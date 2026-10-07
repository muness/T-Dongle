//! The router counters: the C's `RT_STAT_*` in the same order with the same names and meanings, plus a few extras for events the C dropped
//! silently.

macro_rules! stats {
    ($( $(#[$doc:meta])* $v:ident = $name:literal ),+ $(,)?) => {
        /// A router counter. Order, names and meaning are those of the C `RT_STAT_*` enum (`route_table.h`, serial command `route`).
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum Stat { $( $(#[$doc])* $v ),+ }
        impl Stat {
            /// Every counter, in index order.
            pub const ALL: [Stat; Stat::COUNT] = [ $( Stat::$v ),+ ];
            /// The name the C prints for this counter.
            pub const fn name(self) -> &'static str {
                match self { $( Stat::$v => $name ),+ }
            }
        }
    };
}

stats! {
    /// Packet handed to the tunnel (counted when the runtime reports the emit succeeded, see `Router::tx_result`).
    ForwardedOut = "forwarded_out",
    /// Reply handed to the USB host (counted when the runtime reports the emit succeeded).
    ForwardedIn = "forwarded_in",
    /// Packet failed validation (malformed, bad header checksum, fragment, unsupported protocol, TTL below 2, bad USB source, bad MSS option).
    BadPacket = "bad_packet",
    /// USB destination alias not in the RAM cache.
    AliasMiss = "alias_miss",
    /// Missed alias at or beyond the allocation limit: cannot exist, no fill requested.
    AliasUnknown = "alias_unknown",
    /// Alias cache filled from the directory.
    AliasFill = "alias_fill",
    /// No free (or reclaimable) flow slot.
    FlowFull = "flow_full",
    /// Alias belongs to a membership that is not published.
    NoMember = "no_member",
    /// Membership published but not ready (not connected, key expired, error).
    MemberDown = "member_down",
    /// Aggregate of the tunnel-to-USB flow/membership refusals.
    ReplyNomatch = "reply_nomatch",
    /// Ingress queue (depth or byte budget) full.
    QueueFull = "queue_full",
    /// ICMP fragmentation-needed sent to the USB host.
    OversizeIcmp = "oversize_icmp",
    /// Oversized packet without DF dropped.
    OversizeDrop = "oversize_drop",
    /// ICMP reply suppressed by the 50 ms rate limit.
    IcmpSuppressed = "icmp_suppressed",
    /// The tunnel refused the packet (runtime reports it).
    TunnelReject = "tunnel_reject",
    /// The USB netif refused a frame (runtime reports it).
    TxFail = "tx_fail",
    /// Packet parked waiting for an alias fill.
    Held = "held",
    /// Held packet released and routed after its fill.
    HeldReleased = "held_released",
    /// Held packet dropped (expired, fill found nothing, USB detached).
    HeldDropped = "held_dropped",
    /// Tunnel packet too short, not IPv4, or inconsistent total length.
    TunnelMalformed = "tunnel_malformed",
    /// No buffer for a tunnel packet (pool exhausted; the runtime reports it).
    TunnelNomem = "tunnel_nomem",
    /// Reply from a WireGuard device that is not a published membership.
    ReplyNoMember = "reply_no_member",
    /// Reply not addressed to the membership's tailnet address.
    ReplyNotUs = "reply_not_us",
    /// Reply destination port outside the mapped-port range.
    ReplyFlowRange = "reply_flow_range",
    /// Reply for a flow slot that is not in use.
    ReplyNoFlow = "reply_no_flow",
    /// Reply for a flow of an earlier USB link generation.
    ReplyGeneration = "reply_generation",
    /// Reply whose tuple, peer, membership or protocol does not own the flow.
    ReplyOwner = "reply_owner",
    /// Reply for a flow idle longer than 120 s.
    ReplyIdle = "reply_idle",
    /// Frame handed to the USB netif transmit (runtime reports it).
    UsbTx = "usb_tx",
    /// Frame the USB transmit refused (runtime reports it).
    UsbTxErr = "usb_tx_err",
}

impl Stat {
    /// Number of counters (30, as the C).
    pub const COUNT: usize = 30;
}

/// Counters the C did not have: events it dropped without a trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Extra {
    /// A packet that had missed the cache could not be held (hold slots or bytes exhausted).
    HoldFull,
    /// A queued packet outlived its USB link generation and was discarded unrouted.
    StaleGeneration,
    /// A packet to the gateway's own management address arriving on a non-USB interface was dropped.
    ManagementDrop,
    /// An alias-range destination arrived on a non-USB interface and was dropped.
    ForeignIngress,
}

impl Extra {
    /// Number of extra counters.
    pub const COUNT: usize = 4;
    /// Name for logs.
    pub const fn name(self) -> &'static str {
        match self {
            Extra::HoldFull => "hold_full",
            Extra::StaleGeneration => "stale_generation",
            Extra::ManagementDrop => "management_drop",
            Extra::ForeignIngress => "foreign_ingress",
        }
    }
}

/// The counter block. Plain integers: the router has a single owner, the runtime exports them (atomics, serial `route`) as it likes. Saturating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stats {
    c: [u32; Stat::COUNT],
    x: [u32; Extra::COUNT],
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    /// All zero.
    pub const fn new() -> Self {
        Self { c: [0; Stat::COUNT], x: [0; Extra::COUNT] }
    }
    /// Value of a counter.
    pub fn get(&self, s: Stat) -> u32 {
        self.c[s as usize]
    }
    /// Value of an extra counter.
    pub fn extra(&self, s: Extra) -> u32 {
        self.x[s as usize]
    }
    /// Count one event.
    pub fn bump(&mut self, s: Stat) {
        let c = &mut self.c[s as usize];
        *c = c.saturating_add(1);
    }
    /// Count one extra event.
    pub fn bump_extra(&mut self, s: Extra) {
        let c = &mut self.x[s as usize];
        *c = c.saturating_add(1);
    }
    /// The raw block, in [`Stat`] order.
    pub fn as_array(&self) -> &[u32; Stat::COUNT] {
        &self.c
    }
}
