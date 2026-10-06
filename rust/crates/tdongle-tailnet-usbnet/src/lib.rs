//! The USB side of the T-Dongle tailnet gateway without lwIP: Ethernet/ARP, a DHCP server and NAPT, as pure sans-IO code.
//!
//! In the C gateway the USB side is an lwIP netif (192.168.77.1/24; the host gets .2 to .101 from lwIP's DHCP server) and the USB host's ordinary
//! Internet traffic is NATed over Wi-Fi by lwIP NAPT. In no_std Rust there is no lwIP; this crate is what replaces it. It does **not** redo what the
//! other crates already cover: the alias NAT towards the tailnet is `tdongle-tailnet-router` (this crate only tells which packets are its:
//! [`HostRx::Router`]), DNS answers are `tdongle-tailnet-dns`.
//!
//! | module | replaces | entry point |
//! |---|---|---|
//! | [`eth`] | `ethernet_input` | [`eth::EthIngress::ingress`] |
//! | [`arp`] | `etharp.c` | [`arp::Neighbors::handle`], [`arp::Neighbors::resolve`] |
//! | [`dhcp`] | `dhcpserver.c` | [`dhcp::DhcpServer::handle_frame`] |
//! | [`napt`] | `ip4_napt.c` and the NAT-relevant parts of `ip4_forward` | [`napt::Napt::outbound`], [`napt::Napt::inbound`], [`napt::Napt::expire`] |
//! | [`reply`] | the ICMP errors and RSTs lwIP originates | [`reply::build_icmp_error`], [`reply::RstNotice`] |
//!
//! [`UsbNet`] composes them in the order the C does (`gateway_host_input` first, lwIP after): one call per frame from the host,
//! one per packet from Wi-Fi, one tick.
//!
//! # Sans-IO contract
//!
//! No clock, socket or entropy source is read: time is [`tdongle_tailnet_types::Millis`], the NAT's port allocator is seeded from an
//! [`tdongle_tailnet_types::Entropy`], frames are slices. Every frame ends as one enum variant and one counter (ADR 0001 rule 2). The NAT works in
//! place on the caller's buffer; ARP and DHCP write their replies into a caller buffer ([`dhcp::REPLY_BUF`], [`arp::ARP_FRAME`] bytes). Nothing
//! allocates and nothing panics on any input (the fuzz targets and the mini-fuzz tests check it).
//!
//! # Not covered (stays with the caller, or is a documented divergence)
//!
//! Wi-Fi L2 framing and the next hop's MAC; the USB host's replies to ICMP echo sent to 192.168.77.1 and the HTTP/DNS servers there (the packet is
//! returned as [`HostRx::Local`]); IPv6 on the USB side; fragmentation of oversize packets; translation of inbound ICMP errors. See each module.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod arp;
pub mod csum;
pub mod dhcp;
pub mod eth;
pub mod napt;
pub mod reply;
pub mod wire;

use arp::{ArpConfig, ArpIgnore, ArpOutcome, Neighbors};
use dhcp::{DhcpConfig, DhcpOutcome, DhcpServer, Silent};
use eth::{EthDrop, EthIngress, Rx};
use napt::{Napt, NaptConfig, Verdict};
use tdongle_tailnet_types::{Entropy, Millis};
use wire::{Mac, USB_IP, USB_MASK, is_alias, rd16, rd32};

/// What one frame from the USB host turned into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum HostRx {
    /// A frame to send back to the host is in the reply buffer (an ARP reply or a DHCP answer).
    Reply {
        /// Length of the frame in the reply buffer.
        len: usize,
    },
    /// The IPv4 packet `frame[offset..offset + len]` is addressed to a tailnet alias (198.18.0.0/15): give it to the router.
    Router {
        /// Offset of the IP header in the frame.
        offset: usize,
        /// IP total length.
        len: usize,
    },
    /// The IPv4 packet `frame[offset..]` was translated in place by the NAT (or refused: see the verdict) for the Wi-Fi interface.
    Napt {
        /// Offset of the IP header in the frame.
        offset: usize,
        /// The NAT's decision; on [`Verdict::Forward`] the first `len` bytes at `offset` go to Wi-Fi.
        verdict: Verdict,
    },
    /// The IPv4 packet `frame[offset..offset + len]` is for the dongle itself (192.168.77.1, the subnet broadcast): the local HTTP, DNS and ICMP.
    Local {
        /// Offset of the IP header in the frame.
        offset: usize,
        /// IP total length.
        len: usize,
    },
    /// An ARP packet that changed the table but needs no answer.
    Learned,
    /// Dropped by the Ethernet layer.
    EthDropped(EthDrop),
    /// ARP ignored.
    ArpIgnored(ArpIgnore),
    /// DHCP ignored.
    DhcpSilent(Silent),
    /// Not an IPv4 packet the dongle can use (header too short or inconsistent).
    BadIpv4,
}

/// The USB side. `FLOWS` is the NAT table size (512 in the C), `LEASES` the DHCP table (8), `NEIGHBORS` the ARP table.
#[derive(Debug)]
pub struct UsbNet<const FLOWS: usize = 512, const LEASES: usize = 8, const NEIGHBORS: usize = 4> {
    /// Receive filter and EtherType dispatch.
    pub eth: EthIngress,
    /// ARP responder and requester.
    pub arp: Neighbors<NEIGHBORS>,
    /// DHCP server.
    pub dhcp: DhcpServer<LEASES>,
    /// NAT of the host's non-alias traffic.
    pub napt: Napt<FLOWS>,
    last_expire: Millis,
}

impl<const FLOWS: usize, const LEASES: usize, const NEIGHBORS: usize> UsbNet<FLOWS, LEASES, NEIGHBORS> {
    /// Bytes of state of this configuration (the ADR figure): the sum of the four parts.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// The C gateway's USB side for a netif with Ethernet address `mac`.
    pub fn new(mac: Mac, entropy: &mut dyn Entropy) -> Self {
        UsbNet {
            eth: EthIngress::new(mac),
            arp: Neighbors::new(ArpConfig { mac, ip: USB_IP, mask: USB_MASK }),
            dhcp: DhcpServer::new(DhcpConfig::c(mac)),
            napt: Napt::new(NaptConfig::C, entropy),
            last_expire: 0,
        }
    }

    /// Handle one Ethernet frame from the USB host. `frame` is modified in place when the NAT translates it; `reply` receives ARP and DHCP answers
    /// (at least [`dhcp::REPLY_BUF`] bytes).
    pub fn host_frame(&mut self, now: Millis, frame: &mut [u8], reply: &mut [u8]) -> HostRx {
        let off = match self.eth.ingress(frame) {
            Rx::Dropped(r) => return HostRx::EthDropped(r),
            Rx::Arp { payload } => {
                // `payload` borrows `frame`; the ARP layer copies what it needs into `reply`.
                return match self.arp.handle(now, payload, reply) {
                    ArpOutcome::Replied { len } => HostRx::Reply { len },
                    ArpOutcome::Learned => HostRx::Learned,
                    ArpOutcome::Ignored(r) => HostRx::ArpIgnored(r),
                };
            }
            Rx::Ipv4 { .. } => 14usize,
        };
        let pkt = &frame[off..];
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return HostRx::BadIpv4;
        }
        let ihl = usize::from(pkt[0] & 15) * 4;
        let total = usize::from(rd16(pkt, 2));
        if ihl < 20 || total < ihl || total > pkt.len() {
            return HostRx::BadIpv4;
        }
        let dst = rd32(pkt, 16);
        if is_alias(dst) {
            return HostRx::Router { offset: off, len: total };
        }
        let for_us = dst == USB_IP || dst == (USB_IP | !USB_MASK) || dst == u32::MAX;
        if for_us {
            let dhcp = pkt[9] == 17 && total >= ihl + 8 && rd16(pkt, ihl + 2) == 67;
            if dhcp {
                return match self.dhcp.handle_frame(now, frame, reply) {
                    DhcpOutcome::Reply { len, .. } => HostRx::Reply { len },
                    DhcpOutcome::Silent(s) => HostRx::DhcpSilent(s),
                };
            }
            return HostRx::Local { offset: off, len: total };
        }
        let verdict = self.napt.outbound(now, &mut frame[off..]);
        HostRx::Napt { offset: off, verdict }
    }

    /// Handle one IPv4 packet that arrived on Wi-Fi: translated in place back to the host when it belongs to a flow.
    pub fn wifi_packet(&mut self, now: Millis, pkt: &mut [u8]) -> Verdict {
        self.napt.inbound(now, pkt)
    }

    /// Run the NAT's timers; call at least every [`napt::EXPIRE_INTERVAL_MS`] (it does nothing if called sooner). Returns flows removed.
    pub fn tick(&mut self, now: Millis) -> usize {
        if now.saturating_sub(self.last_expire) < u64::from(napt::EXPIRE_INTERVAL_MS) {
            return 0;
        }
        self.last_expire = now;
        self.napt.expire(now)
    }
}
