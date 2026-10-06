//! Exhaustive per-packet outcomes. Every packet the router sees ends in exactly one of these; every drop names its reason and maps to the C's
//! counters (`RT_STAT_*`) by [`HostDrop::counters`] / [`TunnelDrop::counters`], which the router bumps itself.

use crate::stats::{Extra, Stat};
use crate::tables::FlowInReject;

/// What to do with a packet that came from the USB host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOutcome {
    /// Not ours (destination outside 198.18.0.0/15, or shorter than an IPv4 header): leave it to the IP stack (Internet NAT, local services).
    PassThrough,
    /// Send `buf[..len]` into the WireGuard tunnel of membership `member`, to the peer with tailnet address `peer`. The packet has been rewritten
    /// in place (source = the membership's address, source port = the flow's mapped port, TTL decremented). Report the emit with
    /// [`crate::Router::tx_result`].
    Forwarded {
        /// Membership whose WireGuard device carries the packet.
        member: u32,
        /// The peer's tailnet address (also the packet's destination).
        peer: u32,
        /// Packet length.
        len: usize,
    },
    /// The packet was copied into the router's bounded hold (waiting for an alias fill); the buffer is free again. Release with
    /// [`crate::Router::hold_service`].
    Held,
    /// `buf[..len]` now holds an ICMP "fragmentation needed" (type 3 code 4, next-hop MTU 1400) for the USB host `host`; send it to the host's
    /// USB netif.
    Reply {
        /// The USB host the reply is addressed to.
        host: u32,
        /// Reply length.
        len: usize,
    },
    /// Dropped, counted.
    Dropped(HostDrop),
}

/// Why a USB-host packet was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostDrop {
    /// The packet was queued for an earlier USB link and the link has been re-attached since (silent in the C).
    StaleGeneration,
    /// Failed validation: not IPv4, bad length, fragment, protocol other than TCP/UDP, bad header checksum or a malformed TCP/UDP header.
    Invalid,
    /// Malformed TCP options on a SYN (the MSS clamp fails closed).
    BadTcpOptions,
    /// TTL below 2: it could not be decremented and forwarded.
    TtlExpired,
    /// Source is not a USB host address (192.168.77.0/24 minus .1 and .255).
    BadSource,
    /// Alias at or beyond the allocation limit: cannot exist, no fill is requested.
    AliasUnknown,
    /// Alias not cached and no fill can be waited for (negative-cached, all four fill slots busy, or already held once).
    AliasMiss,
    /// Alias not cached; a fill is pending but the hold has no slot or bytes left.
    HoldFull,
    /// The alias's membership is not published.
    NoMember,
    /// The membership is published but not ready.
    MemberDown,
    /// No flow slot is free or reclaimable.
    FlowFull,
    /// Larger than the tunnel MTU without DF (the host would only fragment; fragments are rejected).
    OversizeNoDf,
    /// Larger than the tunnel MTU and not a valid packet from a USB host: no ICMP answer.
    OversizeInvalid,
    /// Larger than the tunnel MTU with DF, but the ICMP reply is rate limited (one per 50 ms).
    IcmpSuppressed,
}

impl HostDrop {
    /// The C counters this drop moves (each by one), in the order the C bumps them.
    pub const fn counters(self) -> &'static [Stat] {
        match self {
            HostDrop::StaleGeneration => &[],
            HostDrop::Invalid | HostDrop::BadTcpOptions | HostDrop::TtlExpired | HostDrop::BadSource | HostDrop::OversizeInvalid => &[Stat::BadPacket],
            HostDrop::AliasUnknown => &[Stat::AliasMiss, Stat::AliasUnknown],
            HostDrop::AliasMiss | HostDrop::HoldFull => &[Stat::AliasMiss],
            HostDrop::NoMember => &[Stat::NoMember],
            HostDrop::MemberDown => &[Stat::MemberDown],
            HostDrop::FlowFull => &[Stat::FlowFull],
            HostDrop::OversizeNoDf => &[Stat::OversizeDrop],
            HostDrop::IcmpSuppressed => &[Stat::IcmpSuppressed],
        }
    }
    /// The extra counter this drop moves, if any.
    pub const fn extra(self) -> Option<Extra> {
        match self {
            HostDrop::StaleGeneration => Some(Extra::StaleGeneration),
            HostDrop::HoldFull => Some(Extra::HoldFull),
            _ => None,
        }
    }
}

/// What to do with a packet that came out of a WireGuard tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelOutcome {
    /// Send `buf[..len]` to the USB host `host`: a reply to a flow it opened, rewritten in place (source = the alias, destination = the host,
    /// destination port = the host's own source port). WireGuard padding past `len` is discarded. Report the emit with
    /// [`crate::Router::tx_result`].
    ToHost {
        /// The USB host address.
        host: u32,
        /// Packet length (the IPv4 total length).
        len: usize,
    },
    /// Dropped, counted.
    Dropped(TunnelDrop),
}

/// Why a tunnel packet was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelDrop {
    /// Shorter than an IPv4 header, not IPv4, or the total length is below 20 or beyond the data.
    Malformed,
    /// Failed the USB-side validation (bad header checksum, fragment, protocol, TCP/UDP header) or the MSS clamp.
    Invalid,
    /// The WireGuard device is not a published membership.
    NoMember,
    /// Not addressed to the membership's tailnet address.
    NotUs,
    /// No matching flow, for the given reason.
    Flow(FlowInReject),
}

impl TunnelDrop {
    /// The C counters this drop moves: the specific reason, plus `reply_nomatch` for the membership/flow reasons.
    pub const fn counters(self) -> &'static [Stat] {
        match self {
            TunnelDrop::Malformed => &[Stat::TunnelMalformed],
            TunnelDrop::Invalid => &[Stat::BadPacket],
            TunnelDrop::NoMember => &[Stat::ReplyNoMember, Stat::ReplyNomatch],
            TunnelDrop::NotUs => &[Stat::ReplyNotUs, Stat::ReplyNomatch],
            TunnelDrop::Flow(FlowInReject::Range) => &[Stat::ReplyFlowRange, Stat::ReplyNomatch],
            TunnelDrop::Flow(FlowInReject::NoFlow) => &[Stat::ReplyNoFlow, Stat::ReplyNomatch],
            TunnelDrop::Flow(FlowInReject::Generation) => &[Stat::ReplyGeneration, Stat::ReplyNomatch],
            TunnelDrop::Flow(FlowInReject::Owner) => &[Stat::ReplyOwner, Stat::ReplyNomatch],
            TunnelDrop::Flow(FlowInReject::Idle) => &[Stat::ReplyIdle, Stat::ReplyNomatch],
        }
    }
}

/// Direction of an emit the runtime reports back with [`crate::Router::tx_result`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// Into a WireGuard tunnel (a [`HostOutcome::Forwarded`]).
    ToTunnel,
    /// Out of the USB netif (a [`TunnelOutcome::ToHost`]).
    ToHost,
}
