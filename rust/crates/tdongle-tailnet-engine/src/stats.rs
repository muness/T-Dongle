//! Outcomes and counters. ADR 0001 rule 2 ("exhaustive outcomes"): every packet the engine is given ends in exactly one variant of exactly one of the
//! enums below, and `Stats::check_counts` plus `Engine::check_identities` (like `tdongle-bridge`'s `Stats::check_identities`) proves the sums.
//!
//! * [`HostFate`]: a packet from the USB host, at ingress. `Forwarded` hands it to the tunnel path, where it ends in a [`TxFate`] (held packets that the
//!   router later releases enter the tunnel path a second time through `hold_service`, counted in `held_released`).
//! * [`TxFate`]: one packet entering the tunnel path (from the host, from the router hold, from the parked queue is NOT a new entry: a parked packet
//!   was already counted `Parked` and ends in a [`ParkEnd`]).
//! * [`RxFate`]: one datagram from a member's UDP socket or one DERP-delivered packet.
//! * [`ParkEnd`]: how a parked (JIT) packet left the queue.

use tdongle_tailnet_types::Counter;

macro_rules! counter_enum {
    ($(#[$m:meta])* $name:ident, $count:ident, { $( $(#[$vm:meta])* $v:ident = $s:literal ),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum $name { $( $(#[$vm])* $v ),+ }
        impl $name {
            /// Every variant.
            pub const ALL: [$name; $count] = [ $( $name::$v ),+ ];
            /// A short stable name for status output.
            pub const fn name(self) -> &'static str { match self { $( $name::$v => $s ),+ } }
        }
        const $count: usize = [ $( $name::$v ),+ ].len();
    };
}

counter_enum! {
    /// What became of a packet from the USB host, at ingress.
    HostFate, HOST_N, {
        /// Not ours (outside 198.18.0.0/15): left to the IP stack.
        PassThrough = "pass_through",
        /// The router answered with ICMP fragmentation-needed (sent to the host).
        Reply = "reply",
        /// The router dropped it (its own counters say why).
        RouterDrop = "router_drop",
        /// The router parked it while an alias is filled.
        Held = "held",
        /// Rewritten and handed to the tunnel path (ends in a [`TxFate`]).
        Forwarded = "forwarded",
    }
}

counter_enum! {
    /// What became of a packet that entered the tunnel path.
    TxFate, TX_N, {
        /// Sealed and sent over a direct UDP path.
        SentDirect = "sent_direct",
        /// Sealed and sent through the DERP relay.
        SentDerp = "sent_derp",
        /// No session yet: parked in the bounded queue (ends in a [`ParkEnd`]).
        Parked = "parked",
        /// The destination is not a peer of the membership's directory.
        NoPeer = "no_peer",
        /// Activation was rejected (own table full of recent peers, or the pool refused to evict).
        Rejected = "rejected",
        /// The pool, the heap gate or the key setup refused a slot.
        NoSlot = "no_slot",
        /// The membership's pending budget is spent.
        JitBudget = "jit_budget",
        /// The heap floor (ADR 0022) or the packet arena refused to park it.
        JitNoMem = "jit_no_mem",
        /// A session exists but neither a direct path nor a ready DERP link does.
        NoRoute = "no_route",
        /// The WireGuard layer could not seal it (counter exhausted, buffer).
        SealFail = "seal_fail",
        /// The output refused the datagram.
        TxRefused = "tx_refused",
        /// The membership is gone or not enabled.
        NoMember = "no_member",
        /// Refused at the DERP transmit heap site (ADR 0022).
        HeapRefused = "heap_refused",
    }
}

counter_enum! {
    /// What became of a datagram that arrived on a member socket or through DERP.
    RxFate, RX_N, {
        /// The membership does not exist (or was removed): counted, nothing else touched.
        NoMember = "no_member",
        /// The membership exists but is disabled.
        MemberDown = "member_down",
        /// Refused at the receive heap site (`WgCopy` / `DerpRx`, ADR 0022).
        HeapRefused = "heap_refused",
        /// Neither STUN, DISCO nor a WireGuard message (or too short/long).
        Garbage = "garbage",
        /// A STUN response that matched a request of ours.
        StunMatched = "stun_matched",
        /// STUN that matched nothing or was malformed.
        StunUnmatched = "stun_unmatched",
        /// A DISCO message that authenticated and was processed.
        DiscoOk = "disco_ok",
        /// A DISCO datagram that was refused (see `DiscoCounters`).
        DiscoDropped = "disco_dropped",
        /// A handshake initiation accepted and answered.
        WgInitiation = "wg_initiation",
        /// A handshake response that completed our handshake.
        WgResponse = "wg_response",
        /// A cookie reply (accepted or not), or a cookie reply we sent in answer to an initiation under load.
        WgCookie = "wg_cookie",
        /// A handshake message refused (mac, unknown peer, flood, replay, ...: `wg_drops` says which).
        WgHandshakeDropped = "wg_handshake_dropped",
        /// An authenticated keepalive.
        WgKeepalive = "wg_keepalive",
        /// Authenticated data delivered to the USB host.
        WgDelivered = "wg_delivered",
        /// Authenticated data the router refused (no flow, not ours, malformed).
        WgRouterDrop = "wg_router_drop",
        /// Authenticated data whose source address is not one the peer may use.
        WgNotAllowed = "wg_not_allowed",
        /// A transport message refused (no session, replay, bad tag, expired).
        WgDataDropped = "wg_data_dropped",
        /// A relayed packet from a DERP sender that is not a known peer (and no trial applies).
        UnknownSender = "unknown_sender",
        /// The output refused the packet for the host.
        HostTxRefused = "host_tx_refused",
    }
}

counter_enum! {
    /// How a parked packet left the queue.
    ParkEnd, PARK_N, {
        /// The session came up and it was sent.
        Sent = "sent",
        /// It waited 5 s.
        Expired = "expired",
        /// The handshake series gave up.
        GaveUp = "gave_up",
        /// The peer left the table (evicted, removed by the netmap).
        PeerGone = "peer_gone",
        /// The membership went away or was disabled.
        MemberGone = "member_gone",
        /// The flush could not send it (no route, seal failure, refused output).
        FlushFailed = "flush_failed",
    }
}

/// An identity that does not hold (a bug, never an input error).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// `host_in` differs from the sum of [`HostFate`].
    Host,
    /// Forwarded plus released packets differ from the sum of [`TxFate`].
    Tx,
    /// `rx_in` differs from the sum of [`RxFate`].
    Rx,
    /// Parked packets differ from ends plus those still queued.
    Park,
    /// The router's hold does not add up.
    Hold,
    /// Two live slots share a receiver index, or a table entry has no slot (or the reverse).
    Pool,
    /// A parked packet refers to a peer that is not resident.
    Orphan,
}

/// Every counter of the engine.
#[derive(Clone, Debug)]
pub struct Stats {
    /// Packets from the host.
    pub host_in: Counter,
    /// Datagrams from member sockets and DERP deliveries.
    pub rx_in: Counter,
    /// Of `rx_in`: those that came through DERP.
    pub rx_in_derp: Counter,
    /// Held packets the router released into the tunnel path.
    pub held_released: Counter,
    /// Held packets that the router's second pass dropped.
    pub held_release_dropped: Counter,
    host: [Counter; HOST_N],
    tx: [Counter; TX_N],
    rx: [Counter; RX_N],
    park: [Counter; PARK_N],
    /// Initiations created.
    pub hs_init_tx: Counter,
    /// Initiations created that had no route to leave on.
    pub hs_init_noroute: Counter,
    /// Responses created.
    pub hs_resp_tx: Counter,
    /// Cookie replies sent.
    pub cookie_tx: Counter,
    /// Keepalives sent.
    pub keepalive_tx: Counter,
    /// DISCO datagrams sent (pings, pongs, call-me-maybe).
    pub disco_tx: Counter,
    /// STUN requests sent.
    pub stun_tx: Counter,
    /// Datagrams handed to the output for UDP.
    pub udp_tx: Counter,
    /// Datagrams handed to the output for DERP.
    pub derp_tx: Counter,
    /// Datagrams or packets the output refused.
    pub out_refused: Counter,
    /// Pool evictions of a peer of the requesting membership.
    pub evict_own: Counter,
    /// Pool evictions of a peer of another membership.
    pub evict_other: Counter,
    /// Wg slots the pool/gate refused at activation.
    pub slot_refused: Counter,
    /// Inputs for a membership that does not exist.
    pub no_member_inputs: Counter,
    /// Netmap events refused (directory staging failure, unknown member).
    pub netmap_refused: Counter,
    /// DNS queries seen / forwarded / answered.
    pub dns_in: Counter,
    /// DNS forwards sent.
    pub dns_forwarded: Counter,
    /// Alias fills served from the directory.
    pub alias_fills: Counter,
    /// Aliases allocated.
    pub alias_allocs: Counter,
    /// Alias allocations the directory refused.
    pub alias_alloc_fail: Counter,
    /// Handshake initiations the under-load rule screened.
    pub under_load_screens: Counter,
    /// Members added / removed over the engine's life.
    pub members_added: Counter,
    /// Members removed.
    pub members_removed: Counter,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! zero {
    () => {
        Counter(0)
    };
}

impl Stats {
    /// All zero.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            host_in: zero!(),
            rx_in: zero!(),
            rx_in_derp: zero!(),
            held_released: zero!(),
            held_release_dropped: zero!(),
            host: [zero!(); HOST_N],
            tx: [zero!(); TX_N],
            rx: [zero!(); RX_N],
            park: [zero!(); PARK_N],
            hs_init_tx: zero!(),
            hs_init_noroute: zero!(),
            hs_resp_tx: zero!(),
            cookie_tx: zero!(),
            keepalive_tx: zero!(),
            disco_tx: zero!(),
            stun_tx: zero!(),
            udp_tx: zero!(),
            derp_tx: zero!(),
            out_refused: zero!(),
            evict_own: zero!(),
            evict_other: zero!(),
            slot_refused: zero!(),
            no_member_inputs: zero!(),
            netmap_refused: zero!(),
            dns_in: zero!(),
            dns_forwarded: zero!(),
            alias_fills: zero!(),
            alias_allocs: zero!(),
            alias_alloc_fail: zero!(),
            under_load_screens: zero!(),
            members_added: zero!(),
            members_removed: zero!(),
        }
    }
    /// Count a host fate.
    pub fn host(&mut self, f: HostFate) {
        self.host[f as usize].bump();
    }
    /// Count a tunnel-path fate.
    pub fn tx(&mut self, f: TxFate) {
        self.tx[f as usize].bump();
    }
    /// Count a receive fate.
    pub fn rx(&mut self, f: RxFate) {
        self.rx[f as usize].bump();
    }
    /// Count the end of a parked packet.
    pub fn park(&mut self, f: ParkEnd) {
        self.park[f as usize].bump();
    }
    /// The count of a host fate.
    pub fn host_count(&self, f: HostFate) -> u32 {
        self.host[f as usize].get()
    }
    /// The count of a tunnel-path fate.
    pub fn tx_count(&self, f: TxFate) -> u32 {
        self.tx[f as usize].get()
    }
    /// The count of a receive fate.
    pub fn rx_count(&self, f: RxFate) -> u32 {
        self.rx[f as usize].get()
    }
    /// The count of a park end.
    pub fn park_count(&self, f: ParkEnd) -> u32 {
        self.park[f as usize].get()
    }
    /// Sum of host fates.
    pub fn host_total(&self) -> u64 {
        self.host.iter().map(|c| u64::from(c.get())).sum()
    }
    /// Sum of tunnel-path fates.
    pub fn tx_total(&self) -> u64 {
        self.tx.iter().map(|c| u64::from(c.get())).sum()
    }
    /// Sum of receive fates.
    pub fn rx_total(&self) -> u64 {
        self.rx.iter().map(|c| u64::from(c.get())).sum()
    }
    /// Sum of park ends.
    pub fn park_total(&self) -> u64 {
        self.park.iter().map(|c| u64::from(c.get())).sum()
    }

    /// The packet identities that need only the counters; `queued` is the number of packets parked now, `held_now` those in the router's hold.
    /// (`Engine::check_identities` adds the structural ones.) Saturated counters (4 billion events) are not checked.
    pub fn check_counts(&self, queued: usize) -> Result<(), IdentityError> {
        let sat = |c: Counter| c.get() == u32::MAX;
        if sat(self.host_in) || sat(self.rx_in) {
            return Ok(());
        }
        if u64::from(self.host_in.get()) != self.host_total() {
            return Err(IdentityError::Host);
        }
        // every packet that entered the tunnel path: forwarded from the host plus those the router released from its hold
        let entered = u64::from(self.host_count(HostFate::Forwarded)) + u64::from(self.held_released.get());
        if entered != self.tx_total() {
            return Err(IdentityError::Tx);
        }
        if u64::from(self.rx_in.get()) != self.rx_total() {
            return Err(IdentityError::Rx);
        }
        if u64::from(self.tx_count(TxFate::Parked)) != self.park_total() + queued as u64 {
            return Err(IdentityError::Park);
        }
        Ok(())
    }
}
