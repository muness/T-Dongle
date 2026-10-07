//! Cumulative counters for the inbound path ahead of WireGuard's own (`ml_rx_stats.h`, ADR 0019).
//!
//! Every place a datagram can be refused, lost or discarded between the UDP socket (or the DERP receive loop) and the WireGuard task is counted,
//! and so is every datagram that makes it, so the layers can be reconciled against each other:
//!
//! ```text
//! udp_rx_wg  ==  q_wg_full + wg_enqueued ;  wg_enqueued + derp_rx_wg == wg_in + (still queued)
//! ```
//!
//! One relaxed atomic add per event on 32-bit words. The names are the C's, in the C's order, because `/status` and `tools/inbound_accounting.py`
//! read them by name.

use core::sync::atomic::{AtomicU32, Ordering};

macro_rules! rx_counters {
    ($( $(#[$m:meta])* $variant:ident => $name:literal ),* $(,)?) => {
        /// `ml_rx_stat_t`: one counter per way an inbound datagram can end (or pass a stage).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[repr(u8)]
        pub enum RxStat { $( $(#[$m])* $variant ),* }
        impl RxStat {
            /// Every counter, in the C's order.
            pub const ALL: [RxStat; RX_STAT_COUNT] = [ $( RxStat::$variant ),* ];
            /// `ml_rx_stat_name`.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $( RxStat::$variant => $name ),* }
            }
        }
    };
}

rx_counters! {
    /// Datagrams read from a membership's DISCO/WireGuard UDP socket.
    UdpRx => "udp_rx",
    /// Of those, zero length: discarded.
    UdpRxEmpty => "udp_rx_empty",
    /// Of those, too short to be WireGuard, DISCO or STUN: discarded.
    UdpUnclassified => "udp_unclassified",
    /// No heap for the copy that crosses to the wg_mgr task: discarded.
    UdpAllocFail => "udp_alloc_fail",
    /// recvfrom failed with something other than "nothing to read".
    UdpRecvErr => "udp_recv_err",
    /// Classified WireGuard, offered to the WireGuard receive queue.
    UdpWg => "udp_wg",
    /// Classified DISCO, offered to the DISCO queue.
    UdpDisco => "udp_disco",
    /// Classified STUN, offered to the STUN queue.
    UdpStun => "udp_stun",
    /// WireGuard queue full when the socket reader offered a packet: dropped.
    QWgFull => "q_wg_full",
    /// DISCO queue full (net_io or DERP): dropped.
    QDiscoFull => "q_disco_full",
    /// STUN queue full: dropped.
    QStunFull => "q_stun_full",
    /// WireGuard datagrams offered to the queue by the DERP loop.
    DerpRxWg => "derp_rx_wg",
    /// ... of which the queue was full: dropped.
    DerpQWgFull => "derp_q_wg_full",
    /// WireGuard datagram refused: it would take the queued bytes past the byte cap, either producer.
    QWgBytes => "q_wg_bytes",
    /// WireGuard datagram refused: it would leave less free internal heap than the floor, either producer.
    QWgHeap => "q_wg_heap",
    /// Times net_io drained a ready socket.
    DrainCalls => "drain_calls",
    /// ... that stopped at the per-call cap with the socket possibly not empty.
    DrainCapped => "drain_capped",
    /// ... that read at least `ML_NET_IO_DEEP` datagrams: the mailbox was nearly full.
    DrainDeep => "drain_deep",
    /// Datagrams taken off the WireGuard queue by wg_mgr.
    WgIn => "wg_in",
    /// DERP source key admitted to no peer slot: dropped before any decryption.
    WgSenderUnknown => "wg_sender_unknown",
    /// Membership has no WireGuard interface (yet or any more): dropped.
    WgNoNetif => "wg_no_netif",
    /// Buffer allocation failed copying the datagram for the WireGuard receive path: dropped.
    WgPbufFail => "wg_pbuf_fail",
    /// Handed to the WireGuard receive path.
    WgToWireguardif => "wg_to_wireguardif",
}

/// `ML_RXS_COUNT`.
pub const RX_STAT_COUNT: usize = 23;

/// `ml_rx_stats_t`: the counters and the `drain_burst_max` gauge.
#[derive(Debug)]
pub struct RxStats {
    c: [AtomicU32; RX_STAT_COUNT],
    drain_burst_max: AtomicU32,
}

impl RxStats {
    /// All zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { c: [const { AtomicU32::new(0) }; RX_STAT_COUNT], drain_burst_max: AtomicU32::new(0) }
    }
    /// `ml_rx_stat_add`.
    pub fn add(&self, which: RxStat, n: u32) {
        self.c[which as usize].fetch_add(n, Ordering::Relaxed);
    }
    /// `ml_rx_stat_get`.
    #[must_use]
    pub fn get(&self, which: RxStat) -> u32 {
        self.c[which as usize].load(Ordering::Relaxed)
    }
    /// `ml_rx_stat_get` by index; out of range reads 0 (the C's rule).
    #[must_use]
    pub fn get_index(&self, which: usize) -> u32 {
        self.c.get(which).map_or(0, |c| c.load(Ordering::Relaxed))
    }
    /// `ml_rx_stat_burst`: the gauge only grows.
    pub fn burst(&self, n: u32) {
        self.drain_burst_max.fetch_max(n, Ordering::Relaxed);
    }
    /// Most datagrams drained from one socket in one call.
    #[must_use]
    pub fn drain_burst_max(&self) -> u32 {
        self.drain_burst_max.load(Ordering::Relaxed)
    }
    /// `ml_rx_stats_reset`.
    pub fn reset(&self) {
        for c in &self.c {
            c.store(0, Ordering::Relaxed);
        }
        self.drain_burst_max.store(0, Ordering::Relaxed);
    }
    /// Size of the state in bytes.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
}

impl Default for RxStats {
    fn default() -> Self {
        Self::new()
    }
}

/// `ml_rx_stat_name` by index; out of range is the empty string (the C's rule).
#[must_use]
pub fn name_of(which: usize) -> &'static str {
    RxStat::ALL.get(which).map_or("", |s| s.name())
}
