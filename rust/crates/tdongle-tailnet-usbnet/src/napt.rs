//! NAPT of the USB host's ordinary Internet traffic over the Wi-Fi address: what `CONFIG_LWIP_IPV4_NAPT` (`ip4_napt.c`, `esp_netif_napt_enable(usb)`)
//! does in the C gateway, as sans-IO code on caller buffers.
//!
//! # What lwIP does, and what this crate does about each point
//!
//! | lwIP (ESP-IDF 5.5.5 `ip4_napt.c`, `ip4.c`) | here |
//! |---|---|
//! | `IP_NAPT_MAX` 512 entries, one flat table, linear scan per packet | `Napt<N>` (`N` const generic, 512 in the C), a hash index per direction, the table is a plain array |
//! | TCP, UDP and ICMP echo only; **every other protocol is forwarded un-translated, leaking the private source** | other protocols and ICMP types are dropped and counted ([`DropReason::UnsupportedProtocol`], [`DropReason::IcmpNotEcho`]) |
//! | mapped port = the host's port when it is in 49152..=61439 and unused, else a random free port of that range; ICMP keeps the identifier | the same, from a seeded PRNG; a clashing ICMP identifier is remapped (RFC 1624 patch of the ICMP checksum) |
//! | an entry is keyed by (source address, source port) only; a second destination from the same source port **overwrites** the first | keyed by the full 5-tuple: concurrent flows of one socket each get an entry and their own mapped port |
//! | a new TCP flow only on a SYN without ACK, a new UDP flow on any datagram, both only from a source port of 1024 or more; anything else without a flow gets ICMP port unreachable (UDP and a full table: silent drop) | the same ([`NaptConfig::min_new_flow_port`]) |
//! | timeouts: TCP 30 min established, `TCP_MSL` (60 s) when half open (no SYN-ACK seen), reset, or a FIN was acknowledged; UDP 2 s; ICMP 2 s; scanned every 2 s | the same constants in [`NaptConfig`], applied by [`Napt::expire`] (call it every 2 s); entries are **not** checked for age on lookup, as in lwIP |
//! | table full: free the first expired entry, else the oldest | the same; an evicted live TCP flow (SYN-ACK seen, no FIN/RST) queues a RST for each end ([`Napt::pop_rst`]) |
//! | RST for the Internet end is sent from the private address (never leaves) | built from the Wi-Fi address and the mapped port ([`RstNotice::to_remote`]) |
//! | fragments are translated as if every fragment began with a transport header | **dropped** outbound ([`DropReason::Fragment`]); inbound they go to the local stack ([`LocalReason::Fragment`]) because they may be meant for it |
//! | TTL decremented, ICMP time exceeded (not for ICMP); DF and over the egress MTU: ICMP fragmentation needed; otherwise lwIP fragments | same; over-MTU without DF is dropped ([`DropReason::TooBigNoFragment`]: no fragmenter here) |
//! | ICMP errors from the Internet about a NATed flow are **not** translated (they reach lwIP's own stack and are lost) | the same: [`LocalReason::IcmpNotEchoReply`]. This breaks path-MTU discovery and traceroute for the host; translating them is the first improvement to make if the board shows it matters |
//! | no MSS clamp (the 1360 clamp belongs to the alias router) | none |
//! | IP header checksum verified, TCP/UDP checksums are not | the same; the incremental update preserves a bad L4 checksum as bad |
//! | source address of the host is not checked | must be in the USB subnet and not the dongle's own address ([`DropReason::SpoofedSource`]) |
//!
//! The 2 s UDP timeout and the 30 minute TCP timeout are the C's values, kept as defaults. A reply arriving more than a few seconds after the last
//! datagram of a UDP flow (a long-poll over QUIC, a game server) is lost on the C too; change [`NaptConfig::udp_idle_ms`] if the board shows it.
//!
//! # Layering
//!
//! Everything here is L3: the caller strips the USB Ethernet header (and puts it back with the host's MAC from the neighbour table), and does the
//! Wi-Fi framing with the next hop's MAC. `pkt` is the IPv4 packet starting at its version byte; bytes after the IP total length (Ethernet padding)
//! are ignored and the verdict's `len` says how much to send.
//!
//! # Memory
//!
//! One entry is 32 bytes, plus 4 bytes of hash heads: `Napt<512>` is 19,128 bytes including the counters, the RST queue and the port reservations (see [`Napt::STATE_BYTES`]), against 20.5 KB
//! for lwIP's table. Lookups are O(chain) instead of O(table).

use crate::csum::{header_ok, patch16, patch32};
use crate::reply::{IcmpKind, RstNotice};
use crate::wire::{USB_IP, USB_MASK, rd16, rd32, wr16, wr32};
use tdongle_tailnet_types::{Counter, Entropy, Millis};

const NIL: u16 = 0xffff;
const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;

const F_FIN_REMOTE: u8 = 1; // lwIP fin1: a FIN came from the Internet
const F_FIN_HOST: u8 = 2; // fin2: a FIN came from the host
const F_FINACK_HOST: u8 = 4; // finack1: the host ACKed after the remote FIN
const F_FINACK_REMOTE: u8 = 8; // finack2: the remote ACKed after the host FIN
const F_SYNACK: u8 = 16;
const F_RST: u8 = 32;

const TH_FIN: u8 = 0x01;
const TH_SYN: u8 = 0x02;
const TH_RST: u8 = 0x04;
const TH_ACK: u8 = 0x10;

/// Capacity of the queue of RSTs owed to evicted flows ([`Napt::pop_rst`]).
pub const RST_QUEUE: usize = 8;
/// Number of local ports that can be kept out of the mapped range ([`Napt::reserve_local_port`]).
pub const RESERVED_PORTS: usize = 16;

/// Constants of the translation (defaults: ESP-IDF 5.5.5 `lwip_napt.h` and the C gateway's `sdkconfig.defaults`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NaptConfig {
    /// The USB subnet address (192.168.77.0).
    pub usb_net: u32,
    /// The USB subnet mask.
    pub usb_mask: u32,
    /// The dongle's address on the USB subnet (never a valid source of host traffic).
    pub usb_ip: u32,
    /// First mapped port (`IP_NAPT_PORT_RANGE_START`, 49152).
    pub port_start: u16,
    /// Last mapped port (`IP_NAPT_PORT_RANGE_END`, 61439).
    pub port_end: u16,
    /// Smallest source port that may start a flow (lwIP: 1024). Packets from lower ports belong to an existing flow or are refused.
    pub min_new_flow_port: u16,
    /// TCP flow with a SYN-ACK and no FIN/RST: idle time before it is removed (`IP_NAPT_TIMEOUT_MS_TCP`, 30 min).
    pub tcp_idle_ms: u32,
    /// TCP flow that is half open, reset, or whose FIN was acknowledged: idle time before removal (`IP_NAPT_TIMEOUT_MS_TCP_DISCON` = `TCP_MSL`, 60 s).
    pub tcp_closing_ms: u32,
    /// UDP flow idle time (`IP_NAPT_TIMEOUT_MS_UDP`, 2 s).
    pub udp_idle_ms: u32,
    /// ICMP echo flow idle time (`IP_NAPT_TIMEOUT_MS_ICMP`, 2 s).
    pub icmp_idle_ms: u32,
    /// MTU of the Wi-Fi interface: a larger outbound packet is refused or reported (see the module docs).
    pub wifi_mtu: u16,
    /// MTU of the USB interface (1500) for the inbound direction.
    pub usb_mtu: u16,
}

impl NaptConfig {
    /// The C gateway's values.
    pub const C: NaptConfig = NaptConfig {
        usb_net: USB_IP & USB_MASK,
        usb_mask: USB_MASK,
        usb_ip: USB_IP,
        port_start: 49152,
        port_end: 61439,
        min_new_flow_port: 1024,
        tcp_idle_ms: 30 * 60 * 1000,
        tcp_closing_ms: 60_000,
        udp_idle_ms: 2_000,
        icmp_idle_ms: 2_000,
        wifi_mtu: 1500,
        usb_mtu: 1500,
    };
}

impl Default for NaptConfig {
    fn default() -> Self {
        Self::C
    }
}

/// How often the caller should run [`Napt::expire`] (`NAPT_TMR_INTERVAL`).
pub const EXPIRE_INTERVAL_MS: u32 = 2_000;

/// The Wi-Fi station's address (the NAT's public side).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WifiAddr {
    /// The station's IPv4 address.
    pub ip: u32,
    /// Its netmask (to recognise the directed broadcast of the Wi-Fi subnet).
    pub mask: u32,
}

/// A transport protocol the NAT translates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP echo.
    Icmp,
}

impl Proto {
    const fn number(self) -> u8 {
        match self {
            Proto::Tcp => TCP,
            Proto::Udp => UDP,
            Proto::Icmp => ICMP,
        }
    }
    const fn index(self) -> usize {
        match self {
            Proto::Tcp => 0,
            Proto::Udp => 1,
            Proto::Icmp => 2,
        }
    }
    const fn from_number(n: u8) -> Option<Proto> {
        match n {
            TCP => Some(Proto::Tcp),
            UDP => Some(Proto::Udp),
            ICMP => Some(Proto::Icmp),
            _ => None,
        }
    }
}

/// Why a packet was dropped without a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// Shorter than an IPv4 header (or than the header length says).
    Truncated,
    /// Not IPv4.
    BadVersion,
    /// Header length below 20 bytes.
    BadHeaderLen,
    /// Total length below the header or above the buffer.
    BadTotalLen,
    /// IP header checksum wrong (lwIP drops these too).
    BadIpChecksum,
    /// Transport header length field out of range.
    BadL4Header,
    /// Shorter than its transport header.
    L4Truncated,
    /// A fragment (outbound only; see the module docs).
    Fragment,
    /// Source address not in the USB subnet, a network/broadcast address, or the dongle's own.
    SpoofedSource,
    /// Destination is multicast (lwIP never routes it).
    Multicast,
    /// Destination is a broadcast (limited, or the Wi-Fi subnet's directed broadcast) or in class E.
    Broadcast,
    /// Destination is in 0.0.0.0/8 or 127.0.0.0/8.
    ThisNetOrLoopback,
    /// Destination is link-local (169.254/16): never forwarded (RFC 3927).
    LinkLocal,
    /// Destination is on the USB subnet: not bounced back onto the interface it came from.
    OnLinkDestination,
    /// No Wi-Fi address yet (link down).
    NoWifiAddress,
    /// A protocol other than TCP, UDP and ICMP.
    UnsupportedProtocol,
    /// An ICMP message that is not an echo request.
    IcmpNotEcho,
    /// TTL ran out on an ICMP packet (no error is sent for ICMP).
    TtlExpiredIcmp,
    /// Larger than the egress MTU, DF clear, and there is no fragmenter.
    TooBigNoFragment,
    /// No mapped port or identifier was free for a new UDP or ICMP flow.
    NoPort,
}

impl DropReason {
    /// Number of variants (the length of the counter array).
    pub const COUNT: usize = 20;
    /// Dense index of the variant. Exhaustive on purpose: a new variant does not compile until it has a counter slot.
    pub const fn index(self) -> usize {
        match self {
            DropReason::Truncated => 0,
            DropReason::BadVersion => 1,
            DropReason::BadHeaderLen => 2,
            DropReason::BadTotalLen => 3,
            DropReason::BadIpChecksum => 4,
            DropReason::BadL4Header => 5,
            DropReason::L4Truncated => 6,
            DropReason::Fragment => 7,
            DropReason::SpoofedSource => 8,
            DropReason::Multicast => 9,
            DropReason::Broadcast => 10,
            DropReason::ThisNetOrLoopback => 11,
            DropReason::LinkLocal => 12,
            DropReason::OnLinkDestination => 13,
            DropReason::NoWifiAddress => 14,
            DropReason::UnsupportedProtocol => 15,
            DropReason::IcmpNotEcho => 16,
            DropReason::TtlExpiredIcmp => 17,
            DropReason::TooBigNoFragment => 18,
            DropReason::NoPort => 19,
        }
    }
}

/// Why a packet is not the NAT's business: the caller hands it to the local IP stack (what lwIP does when `ip_napt_recv` finds nothing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalReason {
    /// Outbound packet addressed to the dongle's own Wi-Fi address.
    ToWifiAddress,
    /// Inbound packet not addressed to the Wi-Fi address.
    NotWifiAddress,
    /// No Wi-Fi address configured.
    NoWifiAddress,
    /// Inbound fragment (it may belong to a local socket; the NAT cannot tell).
    Fragment,
    /// Inbound protocol the NAT does not translate.
    Protocol,
    /// Inbound TCP/UDP/ICMP with no flow behind the port or identifier.
    NoMapping,
    /// A flow exists behind the port but for a different remote address or port (an off-path spoof or a stray).
    RemoteMismatch,
    /// Inbound ICMP that is not an echo reply (errors included; see the module docs).
    IcmpNotEchoReply,
}

impl LocalReason {
    /// Number of variants.
    pub const COUNT: usize = 8;
    /// Dense index (exhaustive).
    pub const fn index(self) -> usize {
        match self {
            LocalReason::ToWifiAddress => 0,
            LocalReason::NotWifiAddress => 1,
            LocalReason::NoWifiAddress => 2,
            LocalReason::Fragment => 3,
            LocalReason::Protocol => 4,
            LocalReason::NoMapping => 5,
            LocalReason::RemoteMismatch => 6,
            LocalReason::IcmpNotEchoReply => 7,
        }
    }
}

/// Why a packet was answered with an ICMP error instead of being forwarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// TTL would reach zero.
    TtlExpired,
    /// A TCP segment without a SYN, or a datagram from a port below the new-flow threshold, with no flow.
    NoSession,
    /// A TCP SYN found no free mapped port.
    NoPort,
    /// Over the egress MTU with DF set.
    TooBigDf,
}

impl RejectReason {
    /// Number of variants.
    pub const COUNT: usize = 4;
    /// Dense index (exhaustive).
    pub const fn index(self) -> usize {
        match self {
            RejectReason::TtlExpired => 0,
            RejectReason::NoSession => 1,
            RejectReason::NoPort => 2,
            RejectReason::TooBigDf => 3,
        }
    }
}

/// A packet refused with an ICMP error: build it with [`crate::reply::build_icmp_error`] from the **unmodified** packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reject {
    /// Why.
    pub reason: RejectReason,
    /// The error to send to the packet's source.
    pub icmp: IcmpKind,
}

/// What happened to one packet. Every call to [`Napt::outbound`] / [`Napt::inbound`] ends as exactly one variant, and the counters move in
/// `settle` through a `match` with no wildcard (ADR 0001 rule 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// Translated in place; send the first `len` bytes. `mapped` is the Wi-Fi side port (or ICMP identifier) of the flow.
    Forward {
        /// Bytes to send (the IP total length).
        len: u16,
        /// The mapped port or identifier.
        mapped: u16,
        /// This packet created the flow (or restarted a TCP flow with a new SYN).
        new_flow: bool,
    },
    /// Not the NAT's: hand the unmodified packet to the local stack.
    Local(LocalReason),
    /// Dropped; answer the sender with this ICMP error (the packet is unmodified).
    Reject(Reject),
    /// Dropped.
    Drop(DropReason),
}

/// Counters of one direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirStats {
    /// Packets offered.
    pub packets: Counter,
    /// Packets translated, by [`Proto`] (TCP, UDP, ICMP).
    pub forwarded: [Counter; 3],
    /// Packets handed to the local stack, by [`LocalReason::index`].
    pub local: [Counter; LocalReason::COUNT],
    /// Packets answered with an ICMP error, by [`RejectReason::index`].
    pub rejected: [Counter; RejectReason::COUNT],
    /// Packets dropped, by [`DropReason::index`].
    pub dropped: [Counter; DropReason::COUNT],
}

impl DirStats {
    const ZERO: DirStats = DirStats {
        packets: Counter(0),
        forwarded: [Counter(0); 3],
        local: [Counter(0); LocalReason::COUNT],
        rejected: [Counter(0); RejectReason::COUNT],
        dropped: [Counter(0); DropReason::COUNT],
    };
    /// Packets translated, all protocols.
    pub fn forwarded_total(&self) -> u32 {
        self.forwarded.iter().map(|c| c.get()).sum()
    }
    /// Packets that did not go through, all reasons.
    pub fn refused_total(&self) -> u32 {
        self.local.iter().chain(&self.rejected).chain(&self.dropped).map(|c| c.get()).sum()
    }
    /// The counter of a drop reason.
    pub fn dropped(&self, r: DropReason) -> u32 {
        self.dropped[r.index()].get()
    }
    /// The counter of a local reason.
    pub fn local(&self, r: LocalReason) -> u32 {
        self.local[r.index()].get()
    }
    /// The counter of a reject reason.
    pub fn rejected(&self, r: RejectReason) -> u32 {
        self.rejected[r.index()].get()
    }
    fn settle(&mut self, v: &Verdict, proto: Option<Proto>) {
        self.packets.bump();
        match v {
            Verdict::Forward { .. } => {
                // A forward always has a protocol; the fallback slot keeps the identity (packets = sum of outcomes) without a panic path.
                self.forwarded[proto.map_or(0, Proto::index)].bump();
            }
            Verdict::Local(r) => self.local[r.index()].bump(),
            Verdict::Reject(r) => self.rejected[r.reason.index()].bump(),
            Verdict::Drop(r) => self.dropped[r.index()].bump(),
        }
    }
}

/// Counters of the table and of both directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NaptStats {
    /// USB host to Wi-Fi.
    pub outbound: DirStats,
    /// Wi-Fi to USB host.
    pub inbound: DirStats,
    /// Flows created, by [`Proto`].
    pub created: [Counter; 3],
    /// Flows removed by [`Napt::expire`], by [`Proto`].
    pub expired: [Counter; 3],
    /// Flows evicted because the table was full: an expired one was taken first.
    pub evicted_expired: Counter,
    /// Flows evicted because the table was full and none had expired: the oldest, still live.
    pub evicted_live: Counter,
    /// Flows dropped by a change of the Wi-Fi address.
    pub flushed: Counter,
    /// RSTs queued for evicted TCP flows.
    pub rst_queued: Counter,
    /// RSTs not queued because the queue was full.
    pub rst_lost: Counter,
    /// Most flows ever in the table.
    pub high_water: u16,
}

impl NaptStats {
    const ZERO: NaptStats = NaptStats {
        outbound: DirStats::ZERO,
        inbound: DirStats::ZERO,
        created: [Counter(0); 3],
        expired: [Counter(0); 3],
        evicted_expired: Counter(0),
        evicted_live: Counter(0),
        flushed: Counter(0),
        rst_queued: Counter(0),
        rst_lost: Counter(0),
        high_water: 0,
    };
}

#[derive(Clone, Copy)]
struct Entry {
    last: u32,
    host_ip: u32,
    remote_ip: u32,
    host_seq: u32,
    remote_seq: u32,
    host_port: u16,
    remote_port: u16,
    mport: u16,
    out_next: u16,
    in_next: u16,
    proto: u8, // 0 = free
    flags: u8,
}

impl Entry {
    const EMPTY: Entry = Entry {
        last: 0,
        host_ip: 0,
        remote_ip: 0,
        host_seq: 0,
        remote_seq: 0,
        host_port: 0,
        remote_port: 0,
        mport: 0,
        out_next: NIL,
        in_next: NIL,
        proto: 0,
        flags: 0,
    };
}

struct Hdr {
    ihl: usize,
    total: usize,
    proto: u8,
    src: u32,
    dst: u32,
    ttl: u8,
    df: bool,
    fragment: bool,
}

fn parse_ip(pkt: &[u8]) -> Result<Hdr, DropReason> {
    if pkt.len() < 20 {
        return Err(DropReason::Truncated);
    }
    if pkt[0] >> 4 != 4 {
        return Err(DropReason::BadVersion);
    }
    let ihl = usize::from(pkt[0] & 15) * 4;
    if ihl < 20 {
        return Err(DropReason::BadHeaderLen);
    }
    if ihl > pkt.len() {
        return Err(DropReason::Truncated);
    }
    let total = usize::from(rd16(pkt, 2));
    if total < ihl || total > pkt.len() {
        return Err(DropReason::BadTotalLen);
    }
    if !header_ok(pkt, ihl) {
        return Err(DropReason::BadIpChecksum);
    }
    let frag = rd16(pkt, 6);
    Ok(Hdr { ihl, total, proto: pkt[9], src: rd32(pkt, 12), dst: rd32(pkt, 16), ttl: pkt[8], df: frag & 0x4000 != 0, fragment: frag & 0x3fff != 0 })
}

/// The TCP/UDP/ICMP fields the NAT looks at.
struct L4 {
    sport: u16,
    dport: u16,
    flags: u8,
    seq: u32,
    payload: u32,
}

fn parse_l4(pkt: &[u8], h: &Hdr, proto: Proto) -> Result<L4, DropReason> {
    let l4 = &pkt[h.ihl..h.total];
    match proto {
        Proto::Tcp => {
            if l4.len() < 20 {
                return Err(DropReason::L4Truncated);
            }
            let doff = usize::from(l4[12] >> 4) * 4;
            if doff < 20 || doff > l4.len() {
                return Err(DropReason::BadL4Header);
            }
            Ok(L4 { sport: rd16(l4, 0), dport: rd16(l4, 2), flags: l4[13], seq: rd32(l4, 4), payload: (l4.len() - doff) as u32 })
        }
        Proto::Udp => {
            if l4.len() < 8 {
                return Err(DropReason::L4Truncated);
            }
            let n = usize::from(rd16(l4, 4));
            if n < 8 || n > l4.len() {
                return Err(DropReason::BadL4Header);
            }
            Ok(L4 { sport: rd16(l4, 0), dport: rd16(l4, 2), flags: 0, seq: 0, payload: 0 })
        }
        Proto::Icmp => {
            if l4.len() < 8 {
                return Err(DropReason::L4Truncated);
            }
            // type in `flags`, identifier in both ports (the echo identifier is the flow's "port")
            Ok(L4 { sport: rd16(l4, 4), dport: rd16(l4, 4), flags: l4[0], seq: 0, payload: 0 })
        }
    }
}

/// Offset of the checksum inside the transport header.
const fn l4_csum_at(proto: Proto) -> usize {
    match proto {
        Proto::Tcp => 16,
        Proto::Udp => 6,
        Proto::Icmp => 2,
    }
}

/// Patch the transport checksum for a changed 16-bit word. A UDP datagram without a checksum (0) stays without; a UDP result of 0 is sent as 0xffff.
fn l4_patch16(pkt: &mut [u8], h: &Hdr, proto: Proto, old: u16, new: u16) {
    let at = h.ihl + l4_csum_at(proto);
    if proto == Proto::Udp {
        if rd16(pkt, at) == 0 {
            return;
        }
        patch16(pkt, at, old, new);
        if rd16(pkt, at) == 0 {
            wr16(pkt, at, 0xffff);
        }
    } else {
        patch16(pkt, at, old, new);
    }
}

fn l4_patch32(pkt: &mut [u8], h: &Hdr, proto: Proto, old: u32, new: u32) {
    l4_patch16(pkt, h, proto, (old >> 16) as u16, (new >> 16) as u16);
    l4_patch16(pkt, h, proto, old as u16, new as u16);
}

/// Rewrite the source (`src = true`) or destination address of the packet and the matching port (TCP/UDP), patching every checksum.
fn rewrite_addr_port(pkt: &mut [u8], h: &Hdr, proto: Proto, src: bool, ip: u32, port: u16) {
    let at = if src { 12 } else { 16 };
    let old = rd32(pkt, at);
    wr32(pkt, at, ip);
    patch32(pkt, 10, old, ip);
    if proto != Proto::Icmp {
        l4_patch32(pkt, h, proto, old, ip); // the pseudo header
        let pat = h.ihl + if src { 0 } else { 2 };
        let oldp = rd16(pkt, pat);
        wr16(pkt, pat, port);
        l4_patch16(pkt, h, proto, oldp, port);
    }
}

fn rewrite_icmp_id(pkt: &mut [u8], h: &Hdr, id: u16) {
    let at = h.ihl + 4;
    let old = rd16(pkt, at);
    if old != id {
        wr16(pkt, at, id);
        l4_patch16(pkt, h, Proto::Icmp, old, id);
    }
}

fn decrement_ttl(pkt: &mut [u8]) {
    let old = rd16(pkt, 8);
    let new = old.wrapping_sub(0x0100);
    wr16(pkt, 8, new);
    patch16(pkt, 10, old, new);
}

/// Classify a destination the NAT must never forward. `None` means "forwardable".
fn unforwardable(dst: u32, cfg: &NaptConfig, wifi: &WifiAddr) -> Option<DropReason> {
    if dst >> 28 == 14 {
        return Some(DropReason::Multicast);
    }
    if dst >> 28 == 15 {
        return Some(DropReason::Broadcast); // class E, and 255.255.255.255
    }
    if dst >> 24 == 0 || dst >> 24 == 127 {
        return Some(DropReason::ThisNetOrLoopback);
    }
    if dst >> 16 == 0xa9fe {
        return Some(DropReason::LinkLocal);
    }
    if dst & cfg.usb_mask == cfg.usb_net & cfg.usb_mask {
        return Some(DropReason::OnLinkDestination);
    }
    if wifi.mask != 0 && wifi.mask != u32::MAX && dst & wifi.mask == wifi.ip & wifi.mask && dst | wifi.mask == u32::MAX {
        return Some(DropReason::Broadcast); // the Wi-Fi subnet's directed broadcast
    }
    None
}

#[derive(Clone, Copy)]
struct Reserved {
    proto: u8,
    port: u16,
}

/// The NAT. `N` is the table size (`IP_NAPT_MAX` is 512 in the C).
pub struct Napt<const N: usize> {
    cfg: NaptConfig,
    wifi: Option<WifiAddr>,
    entries: [Entry; N],
    out_heads: [u16; N],
    in_heads: [u16; N],
    free: u16,
    used: u16,
    salt: u32,
    rng: u64,
    reserved: [Option<Reserved>; RESERVED_PORTS],
    rst: [RstNotice; RST_QUEUE],
    rst_head: u8,
    rst_len: u8,
    stats: NaptStats,
}

impl<const N: usize> core::fmt::Debug for Napt<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Napt").field("capacity", &N).field("flows", &self.used).field("wifi", &self.wifi).finish()
    }
}

const EMPTY_RST: RstNotice = RstNotice { host_ip: 0, host_port: 0, remote_ip: 0, remote_port: 0, mapped_port: 0, host_seq: 0, remote_seq: 0 };

impl<const N: usize> Napt<N> {
    /// Size of this table in bytes on the current target (for the ADR; `Napt<512>` is 19,128 bytes on a 64-bit host; the fields are `u32`/`u16`/`u8` except one `u64`, so the
    /// xtensa figure is the same to within a few bytes of padding).
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// An empty table. `entropy` seeds the port allocator and the hash salt (lwIP's `LWIP_RAND`).
    pub fn new(cfg: NaptConfig, entropy: &mut dyn Entropy) -> Self {
        let mut n = Self::new_unseeded(cfg);
        n.seed(entropy);
        n
    }

    /// An empty table with a fixed seed, built entirely at compile time (so a `static` holds it with no 19 KB value ever on a stack). Call [`Napt::seed`]
    /// before it is used.
    pub const fn new_unseeded(cfg: NaptConfig) -> Self {
        const { assert!(N > 0 && N < NIL as usize) };
        let mut entries = [Entry::EMPTY; N];
        let mut i = 0;
        while i < N {
            entries[i].out_next = if i + 1 < N { (i + 1) as u16 } else { NIL };
            i += 1;
        }
        Napt {
            cfg,
            wifi: None,
            entries,
            out_heads: [NIL; N],
            in_heads: [NIL; N],
            free: 0,
            used: 0,
            salt: 0,
            rng: 0x9e37_79b9_7f4a_7c15,
            reserved: [None; RESERVED_PORTS],
            rst: [EMPTY_RST; RST_QUEUE],
            rst_head: 0,
            rst_len: 0,
            stats: NaptStats::ZERO,
        }
    }

    /// Seed the port allocator and the hash salt from `entropy` (what [`Napt::new`] does).
    pub fn seed(&mut self, entropy: &mut dyn Entropy) {
        let mut seed = [0u8; 12];
        entropy.fill(&mut seed);
        let mut rng = u64::from_le_bytes([seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7]]);
        if rng == 0 {
            rng = 0x9e37_79b9_7f4a_7c15;
        }
        self.rng = rng;
        self.salt = u32::from_le_bytes([seed[8], seed[9], seed[10], seed[11]]);
    }

    /// The configuration.
    pub fn config(&self) -> &NaptConfig {
        &self.cfg
    }
    /// The counters.
    pub fn stats(&self) -> &NaptStats {
        &self.stats
    }
    /// The Wi-Fi address in use, if any.
    pub fn wifi(&self) -> Option<WifiAddr> {
        self.wifi
    }
    /// Flows in the table.
    pub fn active(&self) -> usize {
        usize::from(self.used)
    }
    /// Flows of one protocol.
    pub fn active_of(&self, proto: Proto) -> usize {
        self.entries.iter().filter(|e| e.proto == proto.number()).count()
    }
    /// Table capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Set (or clear, on link down) the Wi-Fi address. A different address flushes the table: the old mappings name an identity the Internet no
    /// longer associates with us (lwIP leaves them to time out; they could only deliver stale replies to the host).
    pub fn set_wifi(&mut self, wifi: Option<WifiAddr>) {
        if wifi.map(|w| w.ip) != self.wifi.map(|w| w.ip) {
            self.flush();
        }
        self.wifi = wifi;
    }

    fn flush(&mut self) {
        for i in 0..N {
            if self.entries[i].proto != 0 {
                self.stats.flushed.bump();
            }
            self.entries[i] = Entry::EMPTY;
            self.entries[i].out_next = if i + 1 < N { (i + 1) as u16 } else { NIL };
        }
        self.out_heads = [NIL; N];
        self.in_heads = [NIL; N];
        self.free = 0;
        self.used = 0;
        self.rst_len = 0;
    }

    /// Keep a local socket's port from being handed out as a mapped port (lwIP's `tcp_listening`/`udp_listening` test). Returns false when
    /// [`RESERVED_PORTS`] are taken.
    pub fn reserve_local_port(&mut self, proto: Proto, port: u16) -> bool {
        let r = Reserved { proto: proto.number(), port };
        if self.reserved.iter().flatten().any(|x| x.proto == r.proto && x.port == r.port) {
            return true;
        }
        match self.reserved.iter_mut().find(|s| s.is_none()) {
            Some(slot) => {
                *slot = Some(r);
                true
            }
            None => false,
        }
    }
    /// Undo [`Napt::reserve_local_port`].
    pub fn release_local_port(&mut self, proto: Proto, port: u16) {
        for s in &mut self.reserved {
            if matches!(s, Some(r) if r.proto == proto.number() && r.port == port) {
                *s = None;
            }
        }
    }

    // ---- RST queue ----

    /// Take the next RST owed to an evicted flow (build the packets with [`RstNotice::to_host`] and [`RstNotice::to_remote`]).
    pub fn pop_rst(&mut self) -> Option<RstNotice> {
        if self.rst_len == 0 {
            return None;
        }
        let r = self.rst[usize::from(self.rst_head)];
        self.rst_head = (self.rst_head + 1) % RST_QUEUE as u8;
        self.rst_len -= 1;
        Some(r)
    }

    fn push_rst(&mut self, e: &Entry) {
        if usize::from(self.rst_len) == RST_QUEUE {
            self.stats.rst_lost.bump();
            return;
        }
        let at = (usize::from(self.rst_head) + usize::from(self.rst_len)) % RST_QUEUE;
        self.rst[at] = RstNotice {
            host_ip: e.host_ip,
            host_port: e.host_port,
            remote_ip: e.remote_ip,
            remote_port: e.remote_port,
            mapped_port: e.mport,
            host_seq: e.host_seq,
            remote_seq: e.remote_seq,
        };
        self.rst_len += 1;
        self.stats.rst_queued.bump();
    }

    // ---- randomness ----

    fn rand(&mut self) -> u32 {
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }

    // ---- hashing and chains ----

    fn bucket(&self, h: u32) -> usize {
        ((u64::from(h) * N as u64) >> 32) as usize
    }
    fn mix(a: u32) -> u32 {
        let a = (a ^ (a >> 16)).wrapping_mul(0x7feb_352d);
        let a = (a ^ (a >> 15)).wrapping_mul(0x846c_a68b);
        a ^ (a >> 16)
    }
    fn out_bucket(&self, proto: u8, host_ip: u32, host_port: u16, remote_ip: u32, remote_port: u16) -> usize {
        let a = Self::mix(host_ip ^ self.salt);
        let b = Self::mix(remote_ip ^ a);
        let c = Self::mix(b ^ (u32::from(host_port) << 16 | u32::from(remote_port)) ^ (u32::from(proto) << 8));
        self.bucket(c)
    }
    fn in_bucket(&self, proto: u8, mport: u16) -> usize {
        self.bucket(Self::mix(self.salt ^ u32::from(mport) ^ (u32::from(proto) << 16)))
    }

    fn find_out(&self, proto: u8, host_ip: u32, host_port: u16, remote_ip: u32, remote_port: u16) -> Option<u16> {
        let mut i = self.out_heads[self.out_bucket(proto, host_ip, host_port, remote_ip, remote_port)];
        for _ in 0..N {
            if i == NIL {
                return None;
            }
            let e = &self.entries[usize::from(i)];
            if e.proto == proto && e.host_ip == host_ip && e.host_port == host_port && e.remote_ip == remote_ip && e.remote_port == remote_port {
                return Some(i);
            }
            i = e.out_next;
        }
        None
    }

    /// The flow behind a mapped port (unique per protocol).
    fn find_mport(&self, proto: u8, mport: u16) -> Option<u16> {
        let mut i = self.in_heads[self.in_bucket(proto, mport)];
        for _ in 0..N {
            if i == NIL {
                return None;
            }
            let e = &self.entries[usize::from(i)];
            if e.proto == proto && e.mport == mport {
                return Some(i);
            }
            i = e.in_next;
        }
        None
    }

    fn port_free(&self, proto: u8, port: u16) -> bool {
        !self.reserved.iter().flatten().any(|r| r.proto == proto && r.port == port) && self.find_mport(proto, port).is_none()
    }

    fn alloc_port(&mut self, proto: Proto, preferred: u16) -> Option<u16> {
        let (lo, hi) = if proto == Proto::Icmp { (0u16, u16::MAX) } else { (self.cfg.port_start, self.cfg.port_end) };
        if hi < lo {
            return None;
        }
        let n = proto.number();
        if preferred >= lo && preferred <= hi && self.port_free(n, preferred) {
            return Some(preferred);
        }
        let span = u32::from(hi - lo) + 1;
        for _ in 0..64 {
            let p = lo + (self.rand() % span) as u16;
            if self.port_free(n, p) {
                return Some(p);
            }
        }
        // Dense table: sweep the range once from a random start. Bounded by the span; at most N + RESERVED_PORTS ports are taken.
        let start = self.rand() % span;
        for k in 0..span {
            let p = lo + ((start + k) % span) as u16;
            if self.port_free(n, p) {
                return Some(p);
            }
        }
        None
    }

    fn unlink(&mut self, idx: u16) {
        let e = self.entries[usize::from(idx)];
        let ob = self.out_bucket(e.proto, e.host_ip, e.host_port, e.remote_ip, e.remote_port);
        Self::chain_remove(&mut self.out_heads[ob], &mut self.entries, idx, true);
        let ib = self.in_bucket(e.proto, e.mport);
        Self::chain_remove(&mut self.in_heads[ib], &mut self.entries, idx, false);
    }

    fn chain_remove(head: &mut u16, entries: &mut [Entry; N], idx: u16, out: bool) {
        let next_of = |e: &Entry| if out { e.out_next } else { e.in_next };
        if *head == idx {
            *head = next_of(&entries[usize::from(idx)]);
            return;
        }
        let mut i = *head;
        for _ in 0..N {
            if i == NIL {
                return;
            }
            let n = next_of(&entries[usize::from(i)]);
            if n == idx {
                let after = next_of(&entries[usize::from(idx)]);
                if out {
                    entries[usize::from(i)].out_next = after;
                } else {
                    entries[usize::from(i)].in_next = after;
                }
                return;
            }
            i = n;
        }
    }

    /// Remove a flow (queues the RSTs `ip_napt_free` owes a live TCP connection).
    fn remove(&mut self, idx: u16) {
        let e = self.entries[usize::from(idx)];
        if e.proto == 0 {
            return;
        }
        self.unlink(idx);
        if e.proto == TCP && e.flags & F_SYNACK != 0 && e.flags & (F_FIN_REMOTE | F_FIN_HOST | F_RST) == 0 {
            self.push_rst(&e);
        }
        let slot = &mut self.entries[usize::from(idx)];
        *slot = Entry::EMPTY;
        slot.out_next = self.free;
        self.free = idx;
        self.used -= 1;
    }

    fn timeout_of(&self, e: &Entry) -> Option<u32> {
        // The age after which `e` may go, or None when it may not go on age alone. Mirrors `ip_napt_gc`'s conditions.
        match e.proto {
            TCP => {
                // Idle past TCP_MSL: removable when half open, reset, or a FIN was acknowledged; otherwise only past the 30 minutes.
                if e.flags & (F_FINACK_HOST | F_FINACK_REMOTE | F_RST) != 0 || e.flags & F_SYNACK == 0 {
                    Some(self.cfg.tcp_closing_ms)
                } else {
                    Some(self.cfg.tcp_idle_ms.max(self.cfg.tcp_closing_ms))
                }
            }
            UDP => Some(self.cfg.udp_idle_ms),
            ICMP => Some(self.cfg.icmp_idle_ms),
            _ => None,
        }
    }

    /// Remove every flow that has been idle past its timeout. Call every [`EXPIRE_INTERVAL_MS`]. Returns how many were removed.
    ///
    /// Ages are 32-bit wrapping milliseconds, exact for idle times under 49 days; call this at least that often.
    pub fn expire(&mut self, now: Millis) -> usize {
        let now = now as u32;
        let mut gone = 0;
        for i in 0..N {
            let e = self.entries[i];
            if e.proto == 0 {
                continue;
            }
            if let Some(limit) = self.timeout_of(&e)
                && now.wrapping_sub(e.last) > limit
            {
                if let Some(p) = Proto::from_number(e.proto) {
                    self.stats.expired[p.index()].bump();
                }
                self.remove(i as u16);
                gone += 1;
            }
        }
        gone
    }

    /// Make room in a full table: the first expired flow, else the oldest (`ip_napt_gc(force)`).
    fn make_room(&mut self, now: u32) {
        let mut oldest: Option<(u16, u32)> = None;
        for i in 0..N {
            let e = self.entries[i];
            if e.proto == 0 {
                continue;
            }
            let age = now.wrapping_sub(e.last);
            if self.timeout_of(&e).is_some_and(|limit| age > limit) {
                self.stats.evicted_expired.bump();
                self.remove(i as u16);
                return;
            }
            if oldest.is_none_or(|(_, a)| age > a) {
                oldest = Some((i as u16, age));
            }
        }
        if let Some((i, _)) = oldest {
            self.stats.evicted_live.bump();
            self.remove(i);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn create(&mut self, now: u32, proto: Proto, host_ip: u32, host_port: u16, remote_ip: u32, remote_port: u16, host_seq: u32) -> Option<u16> {
        let mport = self.alloc_port(proto, host_port)?;
        if self.free == NIL {
            self.make_room(now);
        }
        let idx = self.free;
        if idx == NIL {
            return None;
        }
        self.free = self.entries[usize::from(idx)].out_next;
        let ob = self.out_bucket(proto.number(), host_ip, host_port, remote_ip, remote_port);
        let ib = self.in_bucket(proto.number(), mport);
        self.entries[usize::from(idx)] = Entry {
            last: now,
            host_ip,
            remote_ip,
            host_seq,
            remote_seq: 0,
            host_port,
            remote_port,
            mport,
            out_next: self.out_heads[ob],
            in_next: self.in_heads[ib],
            proto: proto.number(),
            flags: 0,
        };
        self.out_heads[ob] = idx;
        self.in_heads[ib] = idx;
        self.used += 1;
        self.stats.high_water = self.stats.high_water.max(self.used);
        self.stats.created[proto.index()].bump();
        Some(idx)
    }

    // ---- the two directions ----

    /// Translate a packet from the USB host towards the Internet, in place.
    pub fn outbound(&mut self, now: Millis, pkt: &mut [u8]) -> Verdict {
        let (v, proto) = self.outbound_inner(now as u32, pkt);
        self.stats.outbound.settle(&v, proto);
        v
    }

    /// Translate a packet that arrived on Wi-Fi back to the USB host, in place, when it belongs to a flow.
    pub fn inbound(&mut self, now: Millis, pkt: &mut [u8]) -> Verdict {
        let (v, proto) = self.inbound_inner(now as u32, pkt);
        self.stats.inbound.settle(&v, proto);
        v
    }

    fn outbound_inner(&mut self, now: u32, pkt: &mut [u8]) -> (Verdict, Option<Proto>) {
        let h = match parse_ip(pkt) {
            Ok(h) => h,
            Err(r) => return (Verdict::Drop(r), None),
        };
        let Some(wifi) = self.wifi else { return (Verdict::Drop(DropReason::NoWifiAddress), None) };
        if h.fragment {
            return (Verdict::Drop(DropReason::Fragment), None);
        }
        let usb_net = self.cfg.usb_net & self.cfg.usb_mask;
        if h.src & self.cfg.usb_mask != usb_net || h.src == self.cfg.usb_ip || h.src == usb_net || h.src | self.cfg.usb_mask == u32::MAX {
            return (Verdict::Drop(DropReason::SpoofedSource), None);
        }
        if h.dst == wifi.ip {
            return (Verdict::Local(LocalReason::ToWifiAddress), None);
        }
        if let Some(r) = unforwardable(h.dst, &self.cfg, &wifi) {
            return (Verdict::Drop(r), None);
        }
        let proto = Proto::from_number(h.proto);
        if h.ttl <= 1 {
            let v = if h.proto == ICMP {
                Verdict::Drop(DropReason::TtlExpiredIcmp)
            } else {
                Verdict::Reject(Reject { reason: RejectReason::TtlExpired, icmp: IcmpKind::TimeExceeded })
            };
            return (v, proto);
        }
        let Some(proto) = proto else { return (Verdict::Drop(DropReason::UnsupportedProtocol), None) };
        let some = Some(proto);
        if h.total > usize::from(self.cfg.wifi_mtu) {
            let v = if h.df {
                Verdict::Reject(Reject { reason: RejectReason::TooBigDf, icmp: IcmpKind::FragNeeded { mtu: self.cfg.wifi_mtu } })
            } else {
                Verdict::Drop(DropReason::TooBigNoFragment)
            };
            return (v, some);
        }
        let l4 = match parse_l4(pkt, &h, proto) {
            Ok(l) => l,
            Err(r) => return (Verdict::Drop(r), some),
        };
        let no_session = Verdict::Reject(Reject { reason: RejectReason::NoSession, icmp: IcmpKind::PortUnreachable });
        let (idx, new_flow) = match proto {
            Proto::Tcp => {
                let existing = self.find_out(TCP, h.src, l4.sport, h.dst, l4.dport);
                let syn = l4.flags & (TH_SYN | TH_ACK) == TH_SYN;
                let seq_next = l4.seq.wrapping_add(l4.payload).wrapping_add(1);
                match (existing, syn) {
                    (Some(i), true) => {
                        // A new SYN on a known 5-tuple: a retransmission, or the port was reused. Either way the connection starts over.
                        let e = &mut self.entries[usize::from(i)];
                        e.flags = 0;
                        e.host_seq = seq_next;
                        e.remote_seq = 0;
                        (i, true)
                    }
                    (None, true) if l4.sport >= self.cfg.min_new_flow_port => match self.create(now, proto, h.src, l4.sport, h.dst, l4.dport, seq_next) {
                        Some(i) => (i, true),
                        None => {
                            return (Verdict::Reject(Reject { reason: RejectReason::NoPort, icmp: IcmpKind::PortUnreachable }), some);
                        }
                    },
                    (Some(i), false) => (i, false),
                    (None, _) => return (no_session, some),
                }
            }
            Proto::Udp => match self.find_out(UDP, h.src, l4.sport, h.dst, l4.dport) {
                Some(i) => (i, false),
                None if l4.sport >= self.cfg.min_new_flow_port => match self.create(now, proto, h.src, l4.sport, h.dst, l4.dport, 0) {
                    Some(i) => (i, true),
                    None => return (Verdict::Drop(DropReason::NoPort), some),
                },
                None => return (no_session, some),
            },
            Proto::Icmp => {
                if l4.flags != 8 {
                    return (Verdict::Drop(DropReason::IcmpNotEcho), some);
                }
                match self.find_out(ICMP, h.src, l4.sport, h.dst, 0) {
                    Some(i) => (i, false),
                    None => match self.create(now, proto, h.src, l4.sport, h.dst, 0, 0) {
                        Some(i) => (i, true),
                        None => return (Verdict::Drop(DropReason::NoPort), some),
                    },
                }
            }
        };
        let e = &mut self.entries[usize::from(idx)];
        e.last = now;
        let mport = e.mport;
        if proto == Proto::Tcp {
            if l4.flags & TH_FIN != 0 {
                e.flags |= F_FIN_HOST;
            }
            if e.flags & F_FIN_REMOTE != 0 && l4.flags & TH_ACK != 0 {
                e.flags |= F_FINACK_HOST;
            }
            if l4.flags & TH_RST != 0 {
                e.flags |= F_RST;
            }
            let next = l4.seq.wrapping_add(l4.payload).wrapping_add(u32::from(l4.flags & TH_SYN != 0)).wrapping_add(u32::from(l4.flags & TH_FIN != 0));
            if next.wrapping_sub(e.host_seq) as i32 >= 0 {
                e.host_seq = next;
            }
        }
        rewrite_addr_port(pkt, &h, proto, true, wifi.ip, mport);
        if proto == Proto::Icmp {
            rewrite_icmp_id(pkt, &h, mport);
        }
        decrement_ttl(pkt);
        (Verdict::Forward { len: h.total as u16, mapped: mport, new_flow }, some)
    }

    fn inbound_inner(&mut self, now: u32, pkt: &mut [u8]) -> (Verdict, Option<Proto>) {
        let h = match parse_ip(pkt) {
            Ok(h) => h,
            Err(r) => return (Verdict::Drop(r), None),
        };
        let Some(wifi) = self.wifi else { return (Verdict::Local(LocalReason::NoWifiAddress), None) };
        if h.dst != wifi.ip {
            return (Verdict::Local(LocalReason::NotWifiAddress), None);
        }
        if h.fragment {
            return (Verdict::Local(LocalReason::Fragment), None);
        }
        let Some(proto) = Proto::from_number(h.proto) else { return (Verdict::Local(LocalReason::Protocol), None) };
        let some = Some(proto);
        let l4 = match parse_l4(pkt, &h, proto) {
            Ok(l) => l,
            Err(r) => return (Verdict::Drop(r), some),
        };
        if proto == Proto::Icmp && l4.flags != 0 {
            return (Verdict::Local(LocalReason::IcmpNotEchoReply), some);
        }
        // For ICMP the identifier is the mapped "port" and the remote has none.
        let (mport, rport) = if proto == Proto::Icmp { (l4.sport, 0) } else { (l4.dport, l4.sport) };
        let Some(idx) = self.find_mport(proto.number(), mport) else { return (Verdict::Local(LocalReason::NoMapping), some) };
        let e = self.entries[usize::from(idx)];
        if e.remote_ip != h.src || e.remote_port != rport {
            return (Verdict::Local(LocalReason::RemoteMismatch), some);
        }
        if h.ttl <= 1 {
            let v = if proto == Proto::Icmp {
                Verdict::Drop(DropReason::TtlExpiredIcmp)
            } else {
                Verdict::Reject(Reject { reason: RejectReason::TtlExpired, icmp: IcmpKind::TimeExceeded })
            };
            return (v, some);
        }
        if h.total > usize::from(self.cfg.usb_mtu) {
            let v = if h.df {
                Verdict::Reject(Reject { reason: RejectReason::TooBigDf, icmp: IcmpKind::FragNeeded { mtu: self.cfg.usb_mtu } })
            } else {
                Verdict::Drop(DropReason::TooBigNoFragment)
            };
            return (v, some);
        }
        let en = &mut self.entries[usize::from(idx)];
        en.last = now;
        if proto == Proto::Tcp {
            if l4.flags & (TH_SYN | TH_ACK) == (TH_SYN | TH_ACK) {
                en.flags |= F_SYNACK;
            }
            if l4.flags & TH_FIN != 0 {
                en.flags |= F_FIN_REMOTE;
            }
            if en.flags & F_FIN_HOST != 0 && l4.flags & TH_ACK != 0 {
                en.flags |= F_FINACK_REMOTE;
            }
            if l4.flags & TH_RST != 0 {
                en.flags |= F_RST;
            }
            let next = l4.seq.wrapping_add(l4.payload).wrapping_add(u32::from(l4.flags & TH_SYN != 0)).wrapping_add(u32::from(l4.flags & TH_FIN != 0));
            if en.remote_seq == 0 || next.wrapping_sub(en.remote_seq) as i32 >= 0 {
                en.remote_seq = next;
            }
        }
        rewrite_addr_port(pkt, &h, proto, false, e.host_ip, e.host_port);
        if proto == Proto::Icmp {
            rewrite_icmp_id(pkt, &h, e.host_port);
        }
        decrement_ttl(pkt);
        (Verdict::Forward { len: h.total as u16, mapped: mport, new_flow: false }, some)
    }

    /// Verify the internal structure: every used flow is on exactly its two chains, the free list and the used flows partition the table, and a
    /// mapped port is unique per protocol. Used by the tests and the fuzzers; cheap enough for a debug assertion in the runtime.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        let mut seen_free = 0usize;
        let mut i = self.free;
        while i != NIL {
            if seen_free > N {
                return Err("free list loops");
            }
            if self.entries[usize::from(i)].proto != 0 {
                return Err("used flow on the free list");
            }
            seen_free += 1;
            i = self.entries[usize::from(i)].out_next;
        }
        let used = self.entries.iter().filter(|e| e.proto != 0).count();
        if used != usize::from(self.used) || used + seen_free != N {
            return Err("used/free count mismatch");
        }
        for (i, e) in self.entries.iter().enumerate() {
            if e.proto == 0 {
                continue;
            }
            if self.find_out(e.proto, e.host_ip, e.host_port, e.remote_ip, e.remote_port) != Some(i as u16) {
                return Err("flow not reachable by its 5-tuple");
            }
            if self.find_mport(e.proto, e.mport) != Some(i as u16) {
                return Err("flow not reachable by its mapped port (or the port is duplicated)");
            }
        }
        Ok(())
    }

    /// The flows as `(proto, host_ip, host_port, remote_ip, remote_port, mapped_port)` (diagnostics and tests).
    pub fn flows(&self) -> impl Iterator<Item = (Proto, u32, u16, u32, u16, u16)> + '_ {
        self.entries.iter().filter_map(|e| Proto::from_number(e.proto).map(|p| (p, e.host_ip, e.host_port, e.remote_ip, e.remote_port, e.mport)))
    }
}
