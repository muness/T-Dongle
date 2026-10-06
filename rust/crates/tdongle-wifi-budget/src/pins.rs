//! [`WifiPins`]: Wi-Fi driver buffers pinned by the data path, counted at run time and held to the one heap floor.
//!
//! Port of `alternative/tailnet/main/wifi_pin_budget.h` (ADR 0022, amendment 2). The C comment is the design; its content is kept here.
//!
//! # Why
//!
//! A Wi-Fi buffer is heap that nothing in this firmware allocates, so nothing used to check it:
//!
//! * **RX.** The driver copies each received frame into a dynamic RX buffer and hands it to lwIP; the buffer stays pinned until the pbuf that
//!   wraps it is freed, possibly in a socket mailbox, the TCP window or the tcpip mailbox.
//! * **TX.** `esp_wifi_internal_tx()` copies the frame into a dynamic TX buffer, which stays until the frame is sent or dropped.
//!
//! (The transparent bridge, ADR 0023, has no netif and copies each received frame out of the driver buffer at once, so only the TX half
//! applies there: the same counters, callback and floor.) Both are bounded only by the driver's pool sizes (16 dynamic RX and TX buffers,
//! 26.6 KB each), which is far more than the 6 buffers the budget has room for. Here both directions are counted at the one place each
//! starts, and the pool can be as large as the driver supports because the count, not the pool, decides.
//!
//! # The rule, the same for both directions
//!
//! A frame is admitted when
//!
//! * **(a)** it fits the **band**: the Wi-Fi buffers pinned in both directions together are fewer than [`GATEWAY_WIFI_BAND_TOTAL`] (5), and
//!   this direction holds fewer than its maximum (4, so the other direction always keeps one). 5 + 1 (the RX frame being checked) are the 6
//!   buffers [`ML_HB_PIN_BUFFERS`] that the elastic floor leaves room for, so the band is paid for by the floor and needs no heap read: a TCP
//!   ACK, an ARP or DHCP reply, a WireGuard keepalive always finds a buffer, and a one-way flow gets 4 of the 5. Both counts live in one word
//!   (`pins`), so the joint limit has no race between the two directions; or
//! * **(b)** it is **elastic**: the free internal heap stays at or above [`ML_HB_FLOOR`] after the buffer exists, like every other elastic
//!   consumer.
//!
//! Otherwise it is refused and counted: TX returns `ESP_ERR_NO_MEM`, RX frees the frame at once.
//!
//! # Why this bounds the minimum
//!
//! `ML_HB_FLOOR >= ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES`. Elastic frames never take the heap below the floor (TX checks before
//! the driver allocates, RX after: the check includes the buffer itself). Band frames are at most `BAND_TOTAL` buffers in both directions, and
//! the RX frame under check is one more: together `ML_HB_PIN_BUFFERS`. So pins cannot take the heap below `ML_HB_FLOOR - ML_HB_PIN_BYTES`, and
//! the racing checkers take at most `ML_HB_SLACK_BYTES` more.
//!
//! # TX release
//!
//! The driver's tx-done callback calls [`done`](WifiPins::done) once per completed TX descriptor, from the pp task. It does not identify our
//! frame, so the count is a FIFO of charge times: a done pops the oldest. It is not called for every buffer (the driver also recycles queued
//! buffers when it clears a queue), so a charge is also released by
//!
//! * the submitter, when `esp_wifi_internal_tx()` fails ([`abort`](WifiPins::abort); no buffer exists then),
//! * the STA link going down or coming up ([`flush`](WifiPins::flush); the driver cleared its queues), and
//! * a **lease**: a charge older than [`GW_WTX_LEASE_MS`] (3 s) is presumed gone (stale, counted).
//!
//! Missing a callback therefore costs a credit until the flow pauses for a lease; an extra callback can release one credit early. Both are
//! bounded by the pool and visible in the counters (`tx_stale`, `tx_unmatched`). Release is exactly once per charge by construction: only the
//! FIFO's head or tail is ever removed, under one lock.
//!
//! # Locking
//!
//! The TX FIFO is touched from the lwIP/tcpip context (submit), the pp task (done) and the event task (flush): one critical section, a few
//! instructions, supplied by the caller as a [`RawLock`] (a `portMUX` on the target, a mutex on the host). RX is lock free (one atomic word).
//! Everything the tx-done callback calls is inline and, on the target, in IRAM: [`WifiPins::done`] makes no call outside this crate and the
//! lock.

use core::sync::atomic::{
    AtomicU16, AtomicU32,
    Ordering::{AcqRel, Relaxed},
};

use crate::heap_budget::{ML_HB_FLOOR, ML_HB_PIN_BUF_BYTES, ML_HB_PIN_BUFFERS, ML_HB_RESERVE, ML_HB_SLACK_BYTES, hb_ok};

/// The driver's dynamic TX pool (`GATEWAY_WIFI_TX_POOL`, `CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM`, default 16). The pool is a const parameter of
/// [`WifiPins`]; this is its default.
pub const GATEWAY_WIFI_TX_POOL: usize = 16;
/// Capacity of the charge FIFO (`GW_WTX_RING`): one stamp per possible outstanding TX charge.
pub const GW_WTX_RING: usize = 16;
/// The band: pinned buffers the two directions may have together without a heap check (`GATEWAY_WIFI_BAND_TOTAL`). Band + the one RX frame
/// under check = [`ML_HB_PIN_BUFFERS`] (6), the burst the floor was sized for.
pub const GATEWAY_WIFI_BAND_TOTAL: u32 = 5;
/// Most RX buffers one direction may hold in the band (`GATEWAY_WIFI_RX_BAND_MAX`): one below the total, so the other always has one.
pub const GATEWAY_WIFI_RX_BAND_MAX: u32 = 4;
/// Most TX buffers in the band (`GATEWAY_WIFI_TX_BAND_MAX`).
pub const GATEWAY_WIFI_TX_BAND_MAX: u32 = 4;
/// A charge older than this was dropped by the driver without a tx-done (`GW_WTX_LEASE_MS`), milliseconds. It is the LAST fallback (link
/// events flush the queues the driver clears), so it is long: a stall (an off-channel scan dwell, a channel switch, 16 queued frames each
/// retried at 1 Mbit/s: ~85 ms a frame, 1.4 s for the lot) must not read as loss.
pub const GW_WTX_LEASE_MS: u32 = 3000;
/// What a TX buffer costs beyond the frame (`GW_WTX_OVERHEAD`): the driver's descriptor, the 802.11 QoS and LLC headers, the allocator header.
/// Capped at the full-frame cost the budget is sized with.
pub const GW_WTX_OVERHEAD: u32 = 192;
/// The most heap the data path can have pinned in the Wi-Fi driver below the floor (`GATEWAY_WIFI_PIN_BAND_BYTES`): the bands and the RX
/// frame under check; elastic frames never leave the floor.
pub const GATEWAY_WIFI_PIN_BAND_BYTES: usize = (GATEWAY_WIFI_BAND_TOTAL as usize + 1) * ML_HB_PIN_BUF_BYTES;

/// One RX buffer in the `pins` word (`GW_WP_RX_ONE`): bits 0-7.
const RX_ONE: u16 = 1;
/// One TX charge in the `pins` word (`GW_WP_TX_ONE`): bits 8-15.
const TX_ONE: u16 = 0x100;

// The `_Static_assert`s of `wifi_pin_budget.h`.
const _: () = assert!(
    GATEWAY_WIFI_BAND_TOTAL + 1 <= ML_HB_PIN_BUFFERS,
    "the Wi-Fi band and the RX frame under check can pin more buffers than the heap budget allows"
);
const _: () = assert!(
    GATEWAY_WIFI_RX_BAND_MAX + 1 <= GATEWAY_WIFI_BAND_TOTAL && GATEWAY_WIFI_TX_BAND_MAX + 1 <= GATEWAY_WIFI_BAND_TOTAL,
    "each direction must leave the other one band slot, or ACKs and ARP can be starved"
);
const _: () = assert!(GATEWAY_WIFI_BAND_TOTAL <= 127, "the two band counts share one word, 8 bits each");
const _: () = assert!(
    GATEWAY_WIFI_TX_POOL >= GATEWAY_WIFI_TX_BAND_MAX as usize && GATEWAY_WIFI_TX_POOL <= GW_WTX_RING,
    "the TX pool must hold the TX band and fit the FIFO"
);
const _: () = assert!(GW_WTX_OVERHEAD as usize <= ML_HB_PIN_BUF_BYTES, "a TX buffer's overhead cannot exceed a full buffer");
const _: () = assert!(
    ML_HB_RESERVE + GATEWAY_WIFI_PIN_BAND_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR,
    "the Wi-Fi bands, the racing-checker slack and the recovery reserve must fit under the elastic floor"
);
// The 16-bit word: both 8-bit fields can hold a full FIFO.
const _: () = assert!(GW_WTX_RING <= u8::MAX as usize && GATEWAY_WIFI_BAND_TOTAL <= u8::MAX as u32);

/// The critical section the TX FIFO needs (`GW_WP_ENTER`/`GW_WP_EXIT`): `portENTER_CRITICAL_SAFE` on the target (the pp task can run while
/// the flash cache is off, so the implementation must be IRAM-resident there), a mutex on the host. A few instructions; never nested; may be
/// entered from any task including the pp task.
///
/// An implementation that fails to exclude gives wrong counts, never memory unsafety: all state is atomic.
pub trait RawLock {
    /// Enter the critical section.
    fn lock(&self);
    /// Leave it. Called exactly once per `lock`, by the same context.
    fn unlock(&self);
}

/// Leaves the critical section when dropped.
struct Held<'a, L: RawLock>(&'a L);

impl<L: RawLock> Drop for Held<'_, L> {
    fn drop(&mut self) {
        self.0.unlock();
    }
}

/// The verdict of [`WifiPins::admit`] (`gw_wtx_verdict`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxVerdict {
    /// Admitted inside the band (`GW_WTX_BAND`): charged, no heap check was needed.
    Band,
    /// Admitted past the band because the heap stays at or above the floor (`GW_WTX_ELASTIC`): charged.
    Elastic,
    /// Refused: the outstanding charges are at the pool or at `tx_limit` (`GW_WTX_POOL`).
    Pool,
    /// Refused: past the band and the heap would fall below the floor (`GW_WTX_HEAP`).
    Heap,
}

impl TxVerdict {
    /// The frame was charged and the caller must release it exactly once (`gw_wtx_admitted`).
    #[must_use]
    pub const fn admitted(self) -> bool {
        matches!(self, Self::Band | Self::Elastic)
    }
}

/// The heap one TX frame of `len` bytes costs (`gw_wtx_cost`): the frame plus [`GW_WTX_OVERHEAD`], capped at one full buffer.
#[must_use]
pub const fn wtx_cost(len: u32) -> usize {
    let c = len as usize + GW_WTX_OVERHEAD as usize;
    if c > ML_HB_PIN_BUF_BYTES { ML_HB_PIN_BUF_BYTES } else { c }
}

/// RX buffers in a `pins` word (`gw_wp_rx`).
const fn word_rx(word: u16) -> u32 {
    (word & 0xff) as u32
}

/// TX charges in a `pins` word (`gw_wp_tx`).
const fn word_tx(word: u16) -> u32 {
    (word >> 8) as u32
}

/// The band's decision for one more RX frame, from a snapshot of both counts (`gw_wp_rx_in_band`).
const fn rx_in_band(word: u16) -> bool {
    word_rx(word) < GATEWAY_WIFI_RX_BAND_MAX && word_rx(word) + word_tx(word) < GATEWAY_WIFI_BAND_TOTAL
}

/// The band's decision for one more TX frame (`gw_wp_tx_in_band`).
const fn tx_in_band(word: u16) -> bool {
    word_tx(word) < GATEWAY_WIFI_TX_BAND_MAX && word_rx(word) + word_tx(word) < GATEWAY_WIFI_BAND_TOTAL
}

/// A snapshot of the counters (the fields of `gateway_wifi_pins`, named as in the C, plus the two live counts and the limit). Monotonic except
/// the high-water marks and the live counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WifiPinsStats {
    /// TX frames charged.
    pub tx_charged: u32,
    /// Charges released by the driver's tx-done.
    pub tx_done: u32,
    /// Charges released by the submitter after a driver failure.
    pub tx_aborted: u32,
    /// Charges released by a link flush.
    pub tx_flushed: u32,
    /// Charges released by the lease.
    pub tx_stale: u32,
    /// tx-done or abort events with nothing outstanding.
    pub tx_unmatched: u32,
    /// Frames admitted in the band.
    pub tx_band: u32,
    /// Frames admitted past the band by the heap check.
    pub tx_elastic: u32,
    /// Frames refused: the pool or `tx_limit` was full.
    pub tx_refused_pool: u32,
    /// Frames refused: the heap would fall below the floor.
    pub tx_refused_heap: u32,
    /// Most TX charges outstanding at once.
    pub tx_high_water: u32,
    /// RX frames admitted in the band.
    pub rx_band: u32,
    /// RX frames admitted past the band by the heap check.
    pub rx_elastic: u32,
    /// RX frames refused (the caller frees them at once).
    pub rx_dropped: u32,
    /// RX buffers released.
    pub rx_released: u32,
    /// RX releases with nothing in flight.
    pub rx_unmatched: u32,
    /// Most RX buffers in flight at once.
    pub rx_high_water: u32,
    /// TX charges outstanding now (`gw_wtx_outstanding`).
    pub tx_outstanding: u32,
    /// RX buffers delivered to lwIP and not yet freed now (`gw_wrx_inflight`).
    pub rx_inflight: u32,
    /// The TX limit now (0: the pool).
    pub tx_limit: u32,
}

/// The Wi-Fi pin budget (`gateway_wifi_pins`).
///
/// `POOL` is the driver's dynamic TX pool ([`GATEWAY_WIFI_TX_POOL`], 16 by default); the most TX charges outstanding is `POOL` unless
/// [`set_tx_limit`](Self::set_tx_limit) lowers it. Everything is `&self`: share one object between the lwIP task (admit/abort/room), the pp
/// task (done), the event task (flush), the Wi-Fi task and the pbuf free path (RX).
#[derive(Debug)]
pub struct WifiPins<L: RawLock, const POOL: usize = GATEWAY_WIFI_TX_POOL> {
    lock: L,
    /// Ms at which each outstanding TX charge was made, oldest first from `tx_head` (guarded by `lock`).
    tx_stamp: [AtomicU32; GW_WTX_RING],
    tx_head: AtomicU32,
    tx_count: AtomicU32,
    /// 0: the driver's pool; else the most TX charges outstanding (the transparent bridge keeps the radio fed with a few frames, not the whole
    /// pool: every frame beyond that is delay, ADR 0023 amendment 2).
    tx_limit: AtomicU32,
    /// RX buffers delivered to lwIP and not yet freed (bits 0-7) and TX charges outstanding (bits 8-15), one word so the band's joint limit is
    /// decided on both at once. The tx field equals `tx_count`, changed under the lock.
    pins: AtomicU16,
    tx_charged: AtomicU32,
    tx_done: AtomicU32,
    tx_aborted: AtomicU32,
    tx_flushed: AtomicU32,
    tx_stale: AtomicU32,
    tx_unmatched: AtomicU32,
    tx_band: AtomicU32,
    tx_elastic: AtomicU32,
    tx_refused_pool: AtomicU32,
    tx_refused_heap: AtomicU32,
    tx_high_water: AtomicU32,
    rx_band: AtomicU32,
    rx_elastic: AtomicU32,
    rx_dropped: AtomicU32,
    rx_released: AtomicU32,
    rx_unmatched: AtomicU32,
    rx_high_water: AtomicU32,
}

fn bump(counter: &AtomicU32) {
    counter.fetch_add(1, Relaxed);
}

impl<L: RawLock, const POOL: usize> WifiPins<L, POOL> {
    /// The pool must hold the TX band and fit the FIFO (`_Static_assert(GATEWAY_WIFI_TX_POOL >= TX_BAND_MAX && <= GW_WTX_RING)`).
    const POOL_OK: () = assert!(POOL >= GATEWAY_WIFI_TX_BAND_MAX as usize && POOL <= GW_WTX_RING, "the TX pool must hold the TX band and fit the FIFO");

    /// A budget with nothing pinned (`GATEWAY_WIFI_PINS_INIT`). `lock` is the critical section the TX FIFO needs.
    #[must_use]
    pub const fn new(lock: L) -> Self {
        let () = Self::POOL_OK;
        Self {
            lock,
            tx_stamp: [const { AtomicU32::new(0) }; GW_WTX_RING],
            tx_head: AtomicU32::new(0),
            tx_count: AtomicU32::new(0),
            tx_limit: AtomicU32::new(0),
            pins: AtomicU16::new(0),
            tx_charged: AtomicU32::new(0),
            tx_done: AtomicU32::new(0),
            tx_aborted: AtomicU32::new(0),
            tx_flushed: AtomicU32::new(0),
            tx_stale: AtomicU32::new(0),
            tx_unmatched: AtomicU32::new(0),
            tx_band: AtomicU32::new(0),
            tx_elastic: AtomicU32::new(0),
            tx_refused_pool: AtomicU32::new(0),
            tx_refused_heap: AtomicU32::new(0),
            tx_high_water: AtomicU32::new(0),
            rx_band: AtomicU32::new(0),
            rx_elastic: AtomicU32::new(0),
            rx_dropped: AtomicU32::new(0),
            rx_released: AtomicU32::new(0),
            rx_unmatched: AtomicU32::new(0),
            rx_high_water: AtomicU32::new(0),
        }
    }

    /// The critical section (for callers that must hold it across their own steps, and the tests).
    #[must_use]
    pub fn lock(&self) -> &L {
        &self.lock
    }

    fn enter(&self) -> Held<'_, L> {
        self.lock.lock();
        Held(&self.lock)
    }

    /// TX charges outstanding (`gw_wtx_outstanding`): a lock-free reader for status, diagnostics and the heap-low records.
    #[must_use]
    pub fn tx_outstanding(&self) -> u32 {
        word_tx(self.pins.load(Relaxed))
    }

    /// RX buffers delivered to lwIP and not yet freed (`gw_wrx_inflight`).
    #[must_use]
    pub fn rx_inflight(&self) -> u32 {
        word_rx(self.pins.load(Relaxed))
    }

    /// The raw `pins` word: RX count in bits 0-7, TX count in bits 8-15.
    #[must_use]
    pub fn pins_word(&self) -> u16 {
        self.pins.load(Relaxed)
    }

    /// The most TX charges outstanding, 0 for the driver's pool (`wifi_pins_tx_limit_now`).
    #[must_use]
    pub fn tx_limit(&self) -> u32 {
        self.tx_limit.load(Relaxed)
    }

    /// The most frames the radio is given at once, 0 for the driver's pool (`wifi_pins_set_tx_limit`; the bridge sets 6, see
    /// `GATEWAY_BRIDGE_WIFI_TX_INFLIGHT`).
    pub fn set_tx_limit(&self, limit: u32) {
        self.tx_limit.store(limit, Relaxed);
    }

    /// The limit in force: `tx_limit`, or the pool when it is 0.
    fn cap(&self) -> u32 {
        let limit = self.tx_limit.load(Relaxed);
        if limit != 0 { limit } else { POOL as u32 }
    }

    /// Remove the oldest charge. Caller holds the lock and has checked `tx_count` (`gw_wtx_pop_head`).
    fn pop_head_locked(&self) {
        self.tx_head.store((self.tx_head.load(Relaxed) + 1) % GW_WTX_RING as u32, Relaxed);
        self.tx_count.store(self.tx_count.load(Relaxed) - 1, Relaxed);
    }

    /// Expire charges older than the lease. Caller holds the lock; returns how many (the caller counts them). Charges are in order, so only the
    /// head can be the oldest (`gw_wtx_expire_locked`).
    fn expire_locked(&self, now_ms: u32) -> u32 {
        let mut stale = 0u32;
        while self.tx_count.load(Relaxed) != 0 {
            let stamp = self.tx_stamp[self.tx_head.load(Relaxed) as usize].load(Relaxed);
            if now_ms.wrapping_sub(stamp) as i32 <= GW_WTX_LEASE_MS as i32 {
                break;
            }
            self.pop_head_locked();
            stale += 1;
        }
        if stale != 0 {
            self.pins.fetch_sub(stale as u16 * TX_ONE, AcqRel);
        }
        stale
    }

    /// Release the charges whose lease ran out and count them in `tx_stale` (the `gw_wtx_expire_locked` of `gw_wtx_room`, taking the lock
    /// itself). Returns how many were released. Only a charge strictly older than [`GW_WTX_LEASE_MS`] expires, and only from the head; the
    /// clock may wrap.
    pub fn expire(&self, now_ms: u32) -> u32 {
        let stale = {
            let _held = self.enter();
            self.expire_locked(now_ms)
        };
        if stale != 0 {
            self.tx_stale.fetch_add(stale, Relaxed);
        }
        stale
    }

    /// Room for one more charge under the limit now, for a caller that would rather wait than be refused (the bridge's worker) (`gw_wtx_room`).
    /// It must heal a leaked charge exactly as admission does: a caller that never reaches [`admit`](Self::admit) while the allowance LOOKS
    /// full would otherwise keep a full allowance of leaked charges for ever (the lease is only ever applied under the lock). So when the
    /// allowance looks full, expire under the same lock and look again.
    pub fn room(&self, now_ms: u32) -> bool {
        let cap = self.cap();
        if self.tx_outstanding() < cap {
            return true;
        }
        self.expire(now_ms);
        self.tx_outstanding() < cap
    }

    /// TX, before `esp_wifi_internal_tx` (`gw_wtx_admit`). `free_internal` is the free internal heap measured by the caller, `now_ms` a
    /// millisecond clock (wraps are fine). On [`TxVerdict::Band`] or [`TxVerdict::Elastic`] the frame is charged and the caller MUST release
    /// it exactly once: [`abort`](Self::abort) if the driver call fails, otherwise the driver's tx-done ([`done`](Self::done)), a
    /// [`flush`](Self::flush) or the lease does.
    pub fn admit(&self, len: u32, free_internal: usize, now_ms: u32) -> TxVerdict {
        let held = self.enter();
        let stale = self.expire_locked(now_ms);
        let mut word = self.pins.load(Relaxed);
        let v = loop {
            // RX changes the word without our lock: decide on a snapshot, commit with a CAS.
            let v = if self.tx_count.load(Relaxed) >= self.cap() {
                TxVerdict::Pool
            } else if tx_in_band(word) {
                TxVerdict::Band
            } else if hb_ok(free_internal, wtx_cost(len)) {
                TxVerdict::Elastic
            } else {
                TxVerdict::Heap
            };
            if !v.admitted() {
                break v;
            }
            match self.pins.compare_exchange_weak(word, word.wrapping_add(TX_ONE), AcqRel, Relaxed) {
                Ok(_) => break v,
                Err(seen) => word = seen,
            }
        };
        let count = self.tx_count.load(Relaxed);
        let mut count_now = count;
        if v.admitted() {
            let slot = (self.tx_head.load(Relaxed) + count) % GW_WTX_RING as u32;
            self.tx_stamp[slot as usize].store(now_ms, Relaxed);
            count_now = count + 1;
            self.tx_count.store(count_now, Relaxed);
        }
        drop(held);
        if stale != 0 {
            self.tx_stale.fetch_add(stale, Relaxed);
        }
        match v {
            TxVerdict::Band => bump(&self.tx_band),
            TxVerdict::Elastic => bump(&self.tx_elastic),
            TxVerdict::Pool => bump(&self.tx_refused_pool),
            TxVerdict::Heap => bump(&self.tx_refused_heap),
        }
        if v.admitted() {
            bump(&self.tx_charged);
            self.tx_high_water.fetch_max(count_now, Relaxed);
        }
        v
    }

    /// `esp_wifi_internal_tx` failed: no driver buffer exists for the charge just made, so no tx-done will come (`gw_wtx_abort`). The newest
    /// charge goes (the charges are indistinguishable but for their time, and the lease reads only the head). With nothing outstanding it is
    /// counted in `tx_unmatched` and nothing changes.
    pub fn abort(&self) {
        let had = {
            let _held = self.enter();
            let n = self.tx_count.load(Relaxed);
            if n > 0 {
                self.tx_count.store(n - 1, Relaxed);
                self.pins.fetch_sub(TX_ONE, AcqRel);
            }
            n > 0
        };
        bump(if had { &self.tx_aborted } else { &self.tx_unmatched });
    }

    /// The driver's tx-done callback, in the pp task, once per completed frame, sent or failed (`gw_wtx_done`). Pops the oldest charge. With
    /// nothing outstanding it is a frame that was not ours (a management frame) or one a flush or the lease already released: counted in
    /// `tx_unmatched`, and nothing changes.
    pub fn done(&self) {
        let had = {
            let _held = self.enter();
            let had = self.tx_count.load(Relaxed) > 0;
            if had {
                self.pop_head_locked();
                self.pins.fetch_sub(TX_ONE, AcqRel);
            }
            had
        };
        bump(if had { &self.tx_done } else { &self.tx_unmatched });
    }

    /// The STA link went down or came up: the driver cleared its queues without completing the frames in them (`gw_wtx_flush`). Releases
    /// every charge and returns how many.
    pub fn flush(&self) -> u32 {
        let n = {
            let _held = self.enter();
            let n = self.tx_count.load(Relaxed);
            self.tx_count.store(0, Relaxed);
            self.tx_head.store(0, Relaxed);
            if n != 0 {
                self.pins.fetch_sub(n as u16 * TX_ONE, AcqRel);
            }
            n
        };
        if n != 0 {
            self.tx_flushed.fetch_add(n, Relaxed);
        }
        n
    }

    /// RX, in the Wi-Fi task, as the frame is handed to lwIP (`gw_wrx_admit`). `free_after` is the free internal heap NOW, which already
    /// excludes this frame's buffer (the driver allocated it). `true`: counted, and [`rx_release`](Self::rx_release) must follow exactly
    /// once, when the frame's pbuf is freed. `false`: the caller frees the frame at once.
    pub fn rx_admit(&self, free_after: usize) -> bool {
        let mut word = self.pins.load(Relaxed);
        loop {
            let band = rx_in_band(word);
            if !band && !hb_ok(free_after, 0) {
                bump(&self.rx_dropped);
                return false;
            }
            match self.pins.compare_exchange_weak(word, word.wrapping_add(RX_ONE), AcqRel, Relaxed) {
                Ok(_) => {
                    bump(if band { &self.rx_band } else { &self.rx_elastic });
                    self.rx_high_water.fetch_max(word_rx(word) + 1, Relaxed);
                    return true;
                }
                Err(seen) => word = seen,
            }
        }
    }

    /// Any task: the pbuf of an admitted RX frame was freed, so was the driver buffer under it (`gw_wrx_release`). With nothing in flight it is
    /// counted in `rx_unmatched` and nothing changes (no underflow).
    pub fn rx_release(&self) {
        let mut word = self.pins.load(Relaxed);
        loop {
            if word_rx(word) == 0 {
                bump(&self.rx_unmatched);
                return;
            }
            match self.pins.compare_exchange_weak(word, word.wrapping_sub(RX_ONE), AcqRel, Relaxed) {
                Ok(_) => break,
                Err(seen) => word = seen,
            }
        }
        bump(&self.rx_released);
    }

    /// Count a refusal by heap that the caller decided without charging (the degraded path of `wifi_pins_tx`).
    pub(crate) fn note_refused_heap(&self) {
        bump(&self.tx_refused_heap);
    }

    /// Snapshot every counter.
    #[must_use]
    pub fn stats(&self) -> WifiPinsStats {
        let word = self.pins.load(Relaxed);
        let l = |a: &AtomicU32| a.load(Relaxed);
        WifiPinsStats {
            tx_charged: l(&self.tx_charged),
            tx_done: l(&self.tx_done),
            tx_aborted: l(&self.tx_aborted),
            tx_flushed: l(&self.tx_flushed),
            tx_stale: l(&self.tx_stale),
            tx_unmatched: l(&self.tx_unmatched),
            tx_band: l(&self.tx_band),
            tx_elastic: l(&self.tx_elastic),
            tx_refused_pool: l(&self.tx_refused_pool),
            tx_refused_heap: l(&self.tx_refused_heap),
            tx_high_water: l(&self.tx_high_water),
            rx_band: l(&self.rx_band),
            rx_elastic: l(&self.rx_elastic),
            rx_dropped: l(&self.rx_dropped),
            rx_released: l(&self.rx_released),
            rx_unmatched: l(&self.rx_unmatched),
            rx_high_water: l(&self.rx_high_water),
            tx_outstanding: word_tx(word),
            rx_inflight: word_rx(word),
            tx_limit: l(&self.tx_limit),
        }
    }
}
