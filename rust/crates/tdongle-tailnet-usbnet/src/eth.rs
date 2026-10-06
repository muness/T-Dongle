//! The Ethernet layer of the USB netif: what `ethernet_input` does for the C gateway, and the dispatch the Rust runtime needs on top.
//!
//! lwIP's `ethernet_input` (ESP-IDF 5.5.5, `ETHARP_SUPPORT_VLAN` off) drops a frame of 14 bytes or fewer, marks link-layer broadcast and
//! multicast, passes EtherType 0x0800 to `ip4_input` and 0x0806 to `etharp_input`, and hands everything else to the unknown-protocol hook (none:
//! dropped). The C build has `CONFIG_LWIP_IPV6=y`, so lwIP also runs IPv6 on this interface (neighbour discovery, its link-local address, ICMPv6
//! echo); it never *forwards* IPv6 (`LWIP_IPV6_FORWARD` is off) and `gateway_host_input` is the IPv4 hook only. **This port does not run IPv6 on the
//! USB side**: such frames are counted ([`EthDrop::Ipv6`]) and dropped, so a host that picks the dongle's link-local address for a service
//! (the C's HTTP server listens dual-stack) no longer gets an answer over IPv6; the IPv4 address 192.168.77.1 is the documented one.
//!
//! One check is added: a unicast frame not addressed to the dongle and a frame whose source is a group address are dropped (lwIP lets the
//! IP layer discard them; the NCM function never delivers such frames from a real host).

use crate::wire::{BROADCAST_MAC, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, Mac, mac_is_group, rd16};
use tdongle_tailnet_types::Counter;

/// How a frame was addressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cast {
    /// To the dongle's own address.
    Unicast,
    /// To ff:ff:ff:ff:ff:ff.
    Broadcast,
    /// To another group address (IPv4 multicast is 01:00:5e).
    Multicast,
}

/// Why a frame was dropped at the Ethernet layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EthDrop {
    /// 14 bytes or fewer (lwIP: `p->len <= SIZEOF_ETH_HDR`).
    Runt,
    /// The source address is a group address.
    BadSource,
    /// A unicast frame for another station.
    NotForUs,
    /// IPv6 (counted, not served; see the module docs).
    Ipv6,
    /// An 802.1Q tag (lwIP is built without VLAN support).
    Vlan,
    /// Any other EtherType.
    OtherType,
}

impl EthDrop {
    /// Number of variants.
    pub const COUNT: usize = 6;
    /// Dense index (exhaustive).
    pub const fn index(self) -> usize {
        match self {
            EthDrop::Runt => 0,
            EthDrop::BadSource => 1,
            EthDrop::NotForUs => 2,
            EthDrop::Ipv6 => 3,
            EthDrop::Vlan => 4,
            EthDrop::OtherType => 5,
        }
    }
}

/// A classified frame. Borrowing the input: nothing is copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Rx<'a> {
    /// An ARP packet (the bytes after the Ethernet header) and the sender's Ethernet address.
    Arp {
        /// The ARP payload.
        payload: &'a [u8],
    },
    /// An IPv4 packet (the bytes after the Ethernet header; may carry Ethernet padding after the IP total length).
    Ipv4 {
        /// How it was addressed.
        cast: Cast,
        /// The sender's Ethernet address.
        src: Mac,
        /// The IP packet.
        packet: &'a [u8],
    },
    /// Dropped here.
    Dropped(EthDrop),
}

/// Counters of the Ethernet layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthStats {
    /// Frames offered.
    pub frames: Counter,
    /// ARP frames passed on.
    pub arp: Counter,
    /// IPv4 frames passed on, by [`Cast`] (unicast, broadcast, multicast).
    pub ipv4: [Counter; 3],
    /// Frames dropped, by [`EthDrop::index`].
    pub dropped: [Counter; EthDrop::COUNT],
}

impl EthStats {
    /// All zero.
    pub const ZERO: EthStats = EthStats { frames: Counter(0), arp: Counter(0), ipv4: [Counter(0); 3], dropped: [Counter(0); EthDrop::COUNT] };
    /// Frames dropped for one reason.
    pub fn dropped(&self, r: EthDrop) -> u32 {
        self.dropped[r.index()].get()
    }
}

/// The receive filter of the USB netif.
#[derive(Debug, Clone)]
pub struct EthIngress {
    local: Mac,
    stats: EthStats,
}

impl EthIngress {
    /// A filter for a netif with Ethernet address `local`.
    pub const fn new(local: Mac) -> Self {
        EthIngress { local, stats: EthStats::ZERO }
    }
    /// The counters.
    pub fn stats(&self) -> &EthStats {
        &self.stats
    }
    /// The netif's Ethernet address.
    pub fn local(&self) -> Mac {
        self.local
    }

    /// Classify one frame from the host.
    pub fn ingress<'a>(&mut self, frame: &'a [u8]) -> Rx<'a> {
        let rx = self.classify(frame);
        self.stats.frames.bump();
        match rx {
            Rx::Arp { .. } => self.stats.arp.bump(),
            Rx::Ipv4 { cast, .. } => self.stats.ipv4[match cast {
                Cast::Unicast => 0,
                Cast::Broadcast => 1,
                Cast::Multicast => 2,
            }]
            .bump(),
            Rx::Dropped(r) => self.stats.dropped[r.index()].bump(),
        }
        rx
    }

    fn classify<'a>(&self, frame: &'a [u8]) -> Rx<'a> {
        if frame.len() <= 14 {
            return Rx::Dropped(EthDrop::Runt);
        }
        let dst: Mac = [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]];
        let src: Mac = [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]];
        if mac_is_group(&src) {
            return Rx::Dropped(EthDrop::BadSource);
        }
        let cast = if dst == BROADCAST_MAC {
            Cast::Broadcast
        } else if mac_is_group(&dst) {
            Cast::Multicast
        } else if dst == self.local {
            Cast::Unicast
        } else {
            return Rx::Dropped(EthDrop::NotForUs);
        };
        let body = &frame[14..];
        match rd16(frame, 12) {
            ETHERTYPE_IPV4 => Rx::Ipv4 { cast, src, packet: body },
            ETHERTYPE_ARP => Rx::Arp { payload: body },
            ETHERTYPE_IPV6 => Rx::Dropped(EthDrop::Ipv6),
            0x8100 => Rx::Dropped(EthDrop::Vlan),
            _ => Rx::Dropped(EthDrop::OtherType),
        }
    }
}
