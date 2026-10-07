//! Packets the NAT *asks* the caller to originate: ICMP errors for a rejected packet and the TCP resets sent when a live flow is evicted.
//!
//! lwIP sends these from inside `ip4_forward`/`ip_napt_free`; sans-IO, the verdict names them and these pure functions build the bytes.

use crate::csum::{fill_header, finish, l4_checksum, sum};
use crate::wire::{rd16, rd32, wr16, wr32};

/// The ICMP error lwIP would send for a rejected packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpKind {
    /// Type 11 code 0: the TTL ran out in transit (`icmp_time_exceeded(ICMP_TE_TTL)`).
    TimeExceeded,
    /// Type 3 code 3: no flow for this packet (`icmp_dest_unreach(ICMP_DUR_PORT)`, which lwIP's NAPT uses for every refusal).
    PortUnreachable,
    /// Type 3 code 4 with the next-hop MTU: DF set and the packet exceeds the egress MTU (`ICMP_DUR_FRAG`).
    FragNeeded {
        /// MTU of the interface the packet could not be sent on.
        mtu: u16,
    },
}

/// Largest ICMP error this module writes: 20 (IP) + 8 (ICMP) + 60 (header with options) + 8 (the quoted payload).
pub const ICMP_ERROR_MAX: usize = 96;

/// TTL of originated packets (`CONFIG_LWIP_IP_DEFAULT_TTL`, 64).
pub const ORIGIN_TTL: u8 = 64;

/// Build the ICMP error for `offending` (a complete IPv4 packet, **unmodified**) with source address `src_ip` (the address of the interface the
/// offender arrived on). Returns the packet length, or `None` when no error may be sent (the offender's source is not a unicast address, the
/// offender is itself an ICMP error, or `out` is shorter than [`ICMP_ERROR_MAX`]).
pub fn build_icmp_error(kind: IcmpKind, offending: &[u8], src_ip: u32, out: &mut [u8]) -> Option<usize> {
    if out.len() < ICMP_ERROR_MAX || offending.len() < 20 {
        return None;
    }
    let ihl = usize::from(offending[0] & 15) * 4;
    if ihl < 20 || offending.len() < ihl {
        return None;
    }
    let dst = rd32(offending, 12);
    // RFC 1122 3.2.2: never answer a broadcast, multicast, or "this host"/loopback source.
    if dst == 0 || dst == u32::MAX || dst >> 28 >= 14 || dst >> 24 == 127 {
        return None;
    }
    // Never answer an ICMP error (RFC 1122 3.2.2).
    if offending[9] == 1 && offending.len() > ihl && !matches!(offending[ihl], 0 | 8) {
        return None;
    }
    // A non-first fragment has no transport header to quote (RFC 1122: send no error for it).
    if rd16(offending, 6) & 0x1fff != 0 {
        return None;
    }
    let quote = (ihl + 8).min(offending.len());
    let total = 20 + 8 + quote;
    out[..total].fill(0);
    out[0] = 0x45;
    wr16(out, 2, total as u16);
    out[8] = ORIGIN_TTL;
    out[9] = 1;
    wr32(out, 12, src_ip);
    wr32(out, 16, dst);
    fill_header(out, 20);
    let (ty, code, rest) = match kind {
        IcmpKind::TimeExceeded => (11, 0, 0),
        IcmpKind::PortUnreachable => (3, 3, 0),
        IcmpKind::FragNeeded { mtu } => (3, 4, u32::from(mtu)),
    };
    out[20] = ty;
    out[21] = code;
    wr32(out, 24, rest);
    out[28..28 + quote].copy_from_slice(&offending[..quote]);
    let c = finish(sum(&out[20..total], 0));
    wr16(out, 22, c);
    Some(total)
}

/// A live TCP flow was evicted (`ip_napt_free`): the two ends are told with a RST each, so neither waits on a connection that no longer exists.
///
/// lwIP sends both from the *private* addresses; the second (towards the Internet) would carry the USB host's RFC 1918 source and be dropped
/// upstream, so here it is built from the Wi-Fi address and the mapped port, the identity the remote end knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RstNotice {
    /// The USB host's address.
    pub host_ip: u32,
    /// The USB host's port.
    pub host_port: u16,
    /// The remote end's address.
    pub remote_ip: u32,
    /// The remote end's port.
    pub remote_port: u16,
    /// The Wi-Fi-side port the remote knows (the mapped port).
    pub mapped_port: u16,
    /// Next sequence number the host would send.
    pub host_seq: u32,
    /// Next sequence number the remote would send.
    pub remote_seq: u32,
}

/// Length of the RSTs built by [`RstNotice`]: 20 (IP) + 20 (TCP).
pub const RST_LEN: usize = 40;

fn rst_packet(src: u32, sport: u16, dst: u32, dport: u16, seq: u32, ack: u32, out: &mut [u8; RST_LEN]) {
    out.fill(0);
    out[0] = 0x45;
    wr16(out, 2, RST_LEN as u16);
    out[8] = ORIGIN_TTL;
    out[9] = 6;
    wr32(out, 12, src);
    wr32(out, 16, dst);
    fill_header(out, 20);
    wr16(out, 20, sport);
    wr16(out, 22, dport);
    wr32(out, 24, seq);
    wr32(out, 28, ack);
    out[32] = 5 << 4;
    out[33] = 0x14; // RST | ACK
    wr16(out, 34, 512); // lwIP's window
    let c = l4_checksum(src, dst, 6, &out[20..]);
    wr16(out, 36, c);
}

impl RstNotice {
    /// The RST for the USB host: from the remote end, to the host's own address and port. Send it on the USB side.
    pub fn to_host(&self, out: &mut [u8; RST_LEN]) {
        rst_packet(self.remote_ip, self.remote_port, self.host_ip, self.host_port, self.remote_seq, self.host_seq, out);
    }
    /// The RST for the remote end: from the Wi-Fi address and the mapped port. Send it on the Wi-Fi side.
    pub fn to_remote(&self, wifi_ip: u32, out: &mut [u8; RST_LEN]) {
        rst_packet(wifi_ip, self.mapped_port, self.remote_ip, self.remote_port, self.host_seq, self.remote_seq, out);
    }
}
