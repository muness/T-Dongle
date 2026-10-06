//! [`Bridge`], [`Producer`] and [`Worker`]: the port of `l2.c`.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tdongle_aqm::{Codel, EcnClass, INTERVAL_MS_DEFAULT, TARGET_US_DEFAULT, TcpEcnSyn, classify, mark_ce, tcp_ecn_syn};

use crate::env::{Env, RingSend};
use crate::queue::{Slot, Slots};
use crate::stats::{Counters, Stats};
use crate::tuning::{InvalidTuning, Tuning};
use crate::{CODEL_DEFAULT, FRAME_MAX, HOST_QUEUE_LIMIT, HOST_RESUME_DEPTH, SOJOURN_MS};

const ETH_HEADER: usize = 14;

/// What the TinyUSB receive callback should tell the USB class driver about one offered datagram (`tdongle_l2_host`'s `esp_err_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOutcome {
    /// Copied into the queue; the worker was woken.
    Queued,
    /// Source is not the STA MAC: filtered by design (consumed, counted).
    ForeignMac,
    /// Shorter than an Ethernet header or longer than [`FRAME_MAX`]: dropped, counted.
    Invalid,
    /// Wi-Fi is not associated: dropped, counted.
    LinkDown,
    /// The queue is at its limit: **not consumed**. The class driver keeps the datagram and NAKs the host until the worker calls
    /// [`Env::rx_resume`]. Counted as `h2w_held`, not as a frame.
    Hold,
}

impl HostOutcome {
    /// Whether the datagram stays in the class driver (no `tud_network_recv_renew`).
    #[must_use]
    pub const fn is_hold(self) -> bool {
        matches!(self, Self::Hold)
    }
}

/// The bridge's shared state. One instance for the life of the firmware (a `static`); tests build one per case.
///
/// Callbacks that run in other tasks are methods of this type ([`wifi_rx`](Self::wifi_rx), [`link`](Self::link), the stats and tuning
/// accessors); the single TinyUSB-side producer and the single worker are separate handles ([`producer`](Self::producer),
/// [`worker`](Self::worker)) so "one producer, one consumer" is a property of the types.
#[derive(Debug)]
pub struct Bridge<E: Env> {
    env: E,
    identity: [u8; 6],
    slots: Slots,
    /// Free-running: the producer (TinyUSB task) advances `head`, the worker `tail`.
    pub(crate) head: AtomicU32,
    pub(crate) tail: AtomicU32,
    /// The callback refused a datagram at the queue limit and the worker owes the USB layer a resume.
    pub(crate) held: AtomicBool,
    /// Bumped by every link change; a queued frame from an older epoch is stale.
    epoch: AtomicU32,
    linked: AtomicBool,
    // Tuning.
    t_queue_limit: AtomicU32,
    t_resume: AtomicU32,
    t_sojourn_ms: AtomicU32,
    t_codel: AtomicBool,
    t_codel_target_us: AtomicU32,
    t_codel_interval_ms: AtomicU32,
    /// Moves when the AQM parameters change: the worker restarts its controller.
    t_codel_gen: AtomicU32,
    /// The hold-evidenced busy period (see `note_hold`); `last_hold_us == 0`: no period.
    hold_period_start_us: AtomicU32,
    last_hold_us: AtomicU32,
    /// CoDel's signal count in the current dropping state, mirrored by the worker for the stats reader (0 outside it).
    codel_count: AtomicU32,
    c: Counters,
    producer_taken: AtomicBool,
    worker_taken: AtomicBool,
}

/// A link-layer multicast or broadcast frame (the I/G bit) is the neighbours' chatter: it is forwarded like any other but must not pin the
/// clock at its maximum for a hold period (the same rule the tailnet gateway's `gateway_host_input` applies).
fn unicast(frame: &[u8]) -> bool {
    frame[0] & 1 == 0
}

impl<E: Env> Bridge<E> {
    /// Create the bridge for the STA MAC `identity` (the address the host speaks with). Equivalent of `tdongle_l2_start`, minus the allocations:
    /// the queue is part of the value, so a `static Bridge` is the C firmware's permanent 12 KB.
    #[must_use]
    pub const fn new(env: E, identity: [u8; 6]) -> Self {
        Self {
            env,
            identity,
            slots: Slots::new(),
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            held: AtomicBool::new(false),
            epoch: AtomicU32::new(0),
            linked: AtomicBool::new(false),
            t_queue_limit: AtomicU32::new(HOST_QUEUE_LIMIT),
            t_resume: AtomicU32::new(HOST_RESUME_DEPTH),
            t_sojourn_ms: AtomicU32::new(SOJOURN_MS),
            t_codel: AtomicBool::new(CODEL_DEFAULT),
            t_codel_target_us: AtomicU32::new(TARGET_US_DEFAULT),
            t_codel_interval_ms: AtomicU32::new(INTERVAL_MS_DEFAULT),
            t_codel_gen: AtomicU32::new(0),
            hold_period_start_us: AtomicU32::new(0),
            last_hold_us: AtomicU32::new(0),
            codel_count: AtomicU32::new(0),
            c: Counters::new(),
            producer_taken: AtomicBool::new(false),
            worker_taken: AtomicBool::new(false),
        }
    }

    /// The environment (for the firmware glue that owns the bridge).
    pub const fn env(&self) -> &E {
        &self.env
    }

    /// The single host -> Wi-Fi producer handle (the TinyUSB receive callback). `None` while another handle is alive.
    pub fn producer(&self) -> Option<Producer<'_, E>> {
        (!self.producer_taken.swap(true, Ordering::AcqRel)).then_some(Producer { bridge: self })
    }

    /// The single worker handle: the only context that drains the queue, calls [`Env::wifi_tx`] and holds the CoDel controller.
    /// `None` while another handle is alive.
    pub fn worker(&self) -> Option<Worker<'_, E>> {
        (!self.worker_taken.swap(true, Ordering::AcqRel)).then(|| Worker {
            bridge: self,
            codel: Codel::new(TARGET_US_DEFAULT, INTERVAL_MS_DEFAULT * 1000),
            codel_gen_seen: 0,
        })
    }

    // ---- Wi-Fi -> host: the Wi-Fi task -------------------------------------------------------------------------------------------------

    /// The Wi-Fi RX callback. The caller frees the driver's RX buffer after this returns, on every path, exactly once (the driver's pool is not
    /// ours to hold).
    pub fn wifi_rx(&self, frame: &[u8]) {
        // The epoch is read BEFORE the link is looked at: a link change that lands while this frame is being copied is then visible afterwards.
        let epoch = self.epoch.load(Ordering::Acquire);
        Counters::bump(&self.c.w2h_frames);
        if frame.len() < ETH_HEADER || frame.len() > FRAME_MAX {
            Counters::bump(&self.c.w2h_invalid);
        } else if frame[6..12] == self.identity {
            Counters::bump(&self.c.w2h_own_mac);
        } else if !self.linked.load(Ordering::Acquire) {
            Counters::bump(&self.c.w2h_link_down);
        } else {
            // Raise the clock before the copy: the first frame after an idle period finds the CPU at its low frequency, and everything after it
            // (the ring worker, the TinyUSB drain) should not. One atomic load while the hold is active.
            if unicast(frame) {
                self.note_activity();
            }
            if tcp_ecn_syn(frame) == TcpEcnSyn::SynAckEcnAccept {
                Counters::bump(&self.c.w2h_synack_ecn);
            }
            match self.env.usb_ring_send(frame) {
                RingSend::Accepted => {
                    Counters::bump(&self.c.w2h_forwarded);
                    // The window: this frame passed the link check under an association that ended before the ring stamped it, so it carries
                    // the NEW generation and the flush of the change cannot discard it. The epoch moved: flush again. It costs the frames of
                    // the first microseconds of the new association, which is the right side to err on.
                    if self.epoch.load(Ordering::Acquire) != epoch {
                        Counters::bump(&self.c.w2h_raced);
                        self.env.usb_ring_flush();
                    }
                }
                RingSend::Full => Counters::bump(&self.c.w2h_ring_full),
                RingSend::NotReady => Counters::bump(&self.c.w2h_usb_not_ready),
                RingSend::Invalid => Counters::bump(&self.c.w2h_invalid),
            }
        }
    }

    /// `tdongle_pm_note_activity()` with its cost recorded: the first note after an idle period raises the CPU clock inside the caller, and how
    /// long that takes is what the idle-latency question of the first board run is about (ADR 0023, "idle ping").
    fn note_activity(&self) {
        let t0 = self.env.now_us();
        self.env.note_activity();
        let dt = self.env.now_us().wrapping_sub(t0);
        Counters::bump(&self.c.pm_notes);
        Counters::add(&self.c.pm_note_us_sum, dt);
        Counters::note_max(&self.c.pm_note_us_max, dt);
    }

    // ---- link -------------------------------------------------------------------------------------------------------------------------

    /// The STA associated or lost its association (event task). Frames queued toward the host and toward Wi-Fi from the previous association
    /// are discarded (generation), the host sees the carrier change.
    ///
    /// The order is part of the contract (tests pin it): connect = flush the old association's frames, register the RX callback, open the
    /// gate; disconnect = close the gate, unregister, flush; then the held datagram is released and the host told.
    pub fn link(&self, connected: bool) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        Counters::bump(&self.c.link_changes);
        if connected {
            // Everything in the ring was received under the previous association, and nothing of the new one can arrive before the callback is
            // registered: flush first, then open the gate.
            self.env.usb_ring_flush();
            self.env.wifi_rx_register(true);
            self.linked.store(true, Ordering::Release);
        } else {
            self.linked.store(false, Ordering::Release);
            self.env.wifi_rx_register(false);
            self.env.usb_ring_flush(); // frames received before the link dropped must not reach the host after it
        }
        // A datagram held at the queue limit belongs to the old association's backlog: the queue is stale now, so let the USB layer re-offer it.
        self.last_hold_us.store(0, Ordering::Relaxed); // a new association: the old backlog means nothing
        if self.held.swap(false, Ordering::SeqCst) {
            self.resume();
        }
        self.env.usb_link_state(connected);
    }

    fn resume(&self) {
        Counters::bump(&self.c.h2w_resumes);
        self.env.rx_resume();
    }

    // ---- hold-evidenced busy period ---------------------------------------------------------------------------------------------------

    /// The standing-queue clock CoDel is given: the age of the HOLD-EVIDENCED busy period. The only direct evidence the dongle has that the host
    /// has a backlog is that it had to say "not now" ([`HostOutcome::Hold`]: the host is waiting for us). A period starts at the first hold,
    /// continues while holds recur within one CoDel interval, and ends after an interval with no hold; the signal is its age, and zero outside
    /// it. (ADR 0023 amendment 7: the earlier signals, our own queue's busy period and the host's inter-datagram gaps, were wrong in opposite
    /// ways.) A sender below the pipe's rate is never held, so it is never signalled; one that saturates the pipe is held again and again, so it is.
    fn note_hold(&self, now: u32) {
        let last = self.last_hold_us.load(Ordering::Relaxed);
        let interval = self.t_codel_interval_ms.load(Ordering::Relaxed).wrapping_mul(1000);
        if last == 0 || (now.wrapping_sub(last) as i32) > interval as i32 {
            self.hold_period_start_us.store(now, Ordering::Relaxed); // a new period: no hold within the last interval
        }
        self.last_hold_us.store(if now == 0 { 1 } else { now }, Ordering::Relaxed);
    }

    /// The age of the period at `now`, zero when there is none (no hold within the last interval). Worker.
    pub(crate) fn hold_period_age(&self, now: u32) -> u32 {
        let last = self.last_hold_us.load(Ordering::Relaxed);
        let interval = self.t_codel_interval_ms.load(Ordering::Relaxed).wrapping_mul(1000);
        if last == 0 || (now.wrapping_sub(last) as i32) > interval as i32 {
            return 0;
        }
        now.wrapping_sub(self.hold_period_start_us.load(Ordering::Relaxed))
    }

    /// What the ingress counts about ECN and its negotiation, always (whether or not CoDel is on).
    fn count_ecn(&self, frame: &[u8]) {
        let counter = match classify(frame) {
            EcnClass::NotEct => &self.c.h2w_ecn_not_ect,
            EcnClass::Capable => &self.c.h2w_ecn_capable,
            EcnClass::Ce => &self.c.h2w_ecn_ce,
            EcnClass::Exempt => &self.c.h2w_ecn_exempt,
            EcnClass::NotIp => &self.c.h2w_ecn_not_ip,
        };
        Counters::bump(counter);
        if tcp_ecn_syn(frame) == TcpEcnSyn::SynEcnSetup {
            Counters::bump(&self.c.h2w_syn_ecn_setup);
        }
    }

    // ---- tuning and stats -------------------------------------------------------------------------------------------------------------

    /// Apply a tuning set (diagnostics `bridgetune`). Bounds are checked as a whole: a rejected set changes nothing. A lower queue limit may
    /// leave the queue above it: it simply drains; a held datagram is released by the next drain as before.
    ///
    /// # Errors
    /// [`InvalidTuning`] when any field is out of bounds.
    pub fn set_tuning(&self, tuning: &Tuning) -> Result<(), InvalidTuning> {
        if !tuning.is_valid() {
            return Err(InvalidTuning);
        }
        self.t_queue_limit.store(tuning.queue_limit, Ordering::SeqCst);
        self.t_resume.store(tuning.resume_depth, Ordering::SeqCst);
        self.t_sojourn_ms.store(tuning.sojourn_ms, Ordering::SeqCst);
        let changed = self.t_codel_target_us.load(Ordering::SeqCst) != tuning.codel_target_us
            || self.t_codel_interval_ms.load(Ordering::SeqCst) != tuning.codel_interval_ms
            || self.t_codel.load(Ordering::SeqCst) != tuning.codel;
        self.t_codel_target_us.store(tuning.codel_target_us, Ordering::SeqCst);
        self.t_codel_interval_ms.store(tuning.codel_interval_ms, Ordering::SeqCst);
        self.t_codel.store(tuning.codel, Ordering::SeqCst);
        if changed {
            // A controller built under other numbers (or while off) means nothing.
            self.t_codel_gen.fetch_add(1, Ordering::Release);
        }
        Ok(())
    }

    /// The tuning in force.
    #[must_use]
    pub fn tuning(&self) -> Tuning {
        Tuning {
            queue_limit: self.t_queue_limit.load(Ordering::SeqCst),
            resume_depth: self.t_resume.load(Ordering::SeqCst),
            sojourn_ms: self.t_sojourn_ms.load(Ordering::SeqCst),
            codel: self.t_codel.load(Ordering::SeqCst),
            codel_target_us: self.t_codel_target_us.load(Ordering::SeqCst),
            codel_interval_ms: self.t_codel_interval_ms.load(Ordering::SeqCst),
        }
    }

    /// A snapshot of every counter.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let c = &self.c;
        let load = |counter: &AtomicU32| counter.load(Ordering::Relaxed);
        // tail BEFORE head: head only grows, so the difference cannot go negative (and wrap to 4 billion) however the worker interleaves.
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        Stats {
            linked: self.linked.load(Ordering::Acquire),
            link_changes: load(&c.link_changes),
            w2h_frames: load(&c.w2h_frames),
            w2h_forwarded: load(&c.w2h_forwarded),
            w2h_invalid: load(&c.w2h_invalid),
            w2h_own_mac: load(&c.w2h_own_mac),
            w2h_link_down: load(&c.w2h_link_down),
            w2h_usb_not_ready: load(&c.w2h_usb_not_ready),
            w2h_ring_full: load(&c.w2h_ring_full),
            w2h_raced: load(&c.w2h_raced),
            h2w_frames: load(&c.h2w_frames),
            h2w_queued: load(&c.h2w_queued),
            h2w_invalid: load(&c.h2w_invalid),
            h2w_foreign_mac: load(&c.h2w_foreign_mac),
            h2w_link_down: load(&c.h2w_link_down),
            h2w_held: load(&c.h2w_held),
            h2w_resumes: load(&c.h2w_resumes),
            h2w_codel_signals: load(&c.h2w_codel_signals),
            h2w_ce_marked: load(&c.h2w_ce_marked),
            h2w_codel_drop: load(&c.h2w_codel_drop),
            h2w_signal_us_sum: load(&c.h2w_signal_us_sum),
            h2w_signal_us_max: load(&c.h2w_signal_us_max),
            h2w_codel_count: self.codel_count.load(Ordering::Relaxed),
            h2w_ecn_not_ect: load(&c.h2w_ecn_not_ect),
            h2w_ecn_capable: load(&c.h2w_ecn_capable),
            h2w_ecn_ce: load(&c.h2w_ecn_ce),
            h2w_ecn_exempt: load(&c.h2w_ecn_exempt),
            h2w_ecn_not_ip: load(&c.h2w_ecn_not_ip),
            h2w_syn_ecn_setup: load(&c.h2w_syn_ecn_setup),
            w2h_synack_ecn: load(&c.w2h_synack_ecn),
            h2w_room_waits: load(&c.h2w_room_waits),
            h2w_room_wait_us_sum: load(&c.h2w_room_wait_us_sum),
            h2w_room_wait_us_max: load(&c.h2w_room_wait_us_max),
            h2w_sent: load(&c.h2w_sent),
            h2w_stale: load(&c.h2w_stale),
            h2w_sojourn_drop: load(&c.h2w_sojourn_drop),
            h2w_link_down_queued: load(&c.h2w_link_down_queued),
            h2w_tx_failed: load(&c.h2w_tx_failed),
            h2w_tx_retries: load(&c.h2w_tx_retries),
            h2w_last_tx_error: c.h2w_last_tx_error.load(Ordering::Relaxed),
            h2w_queue_depth: head.wrapping_sub(tail),
            h2w_queue_high_water: load(&c.h2w_queue_high_water),
            worker_stack_free: self.env.worker_stack_free(),
            pm_notes: load(&c.pm_notes),
            pm_note_us_sum: load(&c.pm_note_us_sum),
            pm_note_us_max: load(&c.pm_note_us_max),
            h2w_wait_us_sum: load(&c.h2w_wait_us_sum),
            h2w_wait_us_max: load(&c.h2w_wait_us_max),
            h2w_tx_us_sum: load(&c.h2w_tx_us_sum),
            h2w_tx_us_max: load(&c.h2w_tx_us_max),
        }
    }
}

// ---- host -> Wi-Fi: the TinyUSB task ---------------------------------------------------------------------------------------------------

/// The TinyUSB receive callback's handle: the single producer of the host queue. See [`Bridge::producer`].
#[derive(Debug)]
pub struct Producer<'a, E: Env> {
    bridge: &'a Bridge<E>,
}

impl<E: Env> Drop for Producer<'_, E> {
    fn drop(&mut self) {
        self.bridge.producer_taken.store(false, Ordering::Release);
    }
}

impl<E: Env> Producer<'_, E> {
    /// Offer one datagram from the host (`tdongle_l2_host`). Never blocks, allocates or calls into the Wi-Fi driver.
    ///
    /// `h2w_frames` counts frames TAKEN (queued or dropped by name); a held offer comes back and is counted when it is finally taken.
    pub fn host(&mut self, frame: &[u8]) -> HostOutcome {
        let b = self.bridge;
        let c = &b.c;
        if frame.len() < ETH_HEADER || frame.len() > FRAME_MAX {
            Counters::bump(&c.h2w_frames);
            Counters::bump(&c.h2w_invalid);
            return HostOutcome::Invalid;
        }
        if frame[6..12] != b.identity {
            Counters::bump(&c.h2w_frames);
            Counters::bump(&c.h2w_foreign_mac);
            return HostOutcome::ForeignMac;
        }
        if !b.linked.load(Ordering::Acquire) {
            Counters::bump(&c.h2w_frames);
            Counters::bump(&c.h2w_link_down);
            return HostOutcome::LinkDown;
        }
        // tail first, then head: head only grows, so head - tail can never be negative whatever the worker does between the two loads.
        let mut tail = b.tail.load(Ordering::Acquire);
        let head = b.head.load(Ordering::Relaxed);
        let limit = b.t_queue_limit.load(Ordering::Relaxed);
        if head.wrapping_sub(tail) >= limit {
            // Backpressure: say "not now" (the USB class driver keeps the datagram and NAKs the host), and make sure the worker will say "now".
            // The flag is published BEFORE the queue is looked at again, so a worker that drains in between either sees it (and resumes) or
            // this look sees its room.
            b.held.store(true, Ordering::SeqCst);
            tail = b.tail.load(Ordering::SeqCst);
            if head.wrapping_sub(tail) >= limit || !b.held.swap(false, Ordering::SeqCst) {
                // (the second case: the worker already took the flag and owes a resume that re-offers this datagram)
                Counters::bump(&c.h2w_held);
                b.note_hold(b.env.now_us());
                return HostOutcome::Hold;
            }
        }
        if unicast(frame) {
            b.note_activity();
        }
        // SAFETY: SPSC protocol (queue.rs): `Producer` is the only producer (one per bridge, `&mut self`), and head - tail < limit <= SLOTS,
        // so the consumer has released this slot and will not look at it until `head` is published below.
        let slot = unsafe { b.slots.slot(head) };
        slot.len = frame.len() as u16;
        slot.epoch = b.epoch.load(Ordering::Acquire) as u16;
        slot.enq_us = b.env.now_us();
        b.count_ecn(frame);
        slot.bytes[..frame.len()].copy_from_slice(frame);
        b.head.store(head.wrapping_add(1), Ordering::Release);
        Counters::bump(&c.h2w_frames);
        Counters::bump(&c.h2w_queued);
        Counters::note_max(&c.h2w_queue_high_water, head.wrapping_add(1).wrapping_sub(tail));
        b.env.notify_worker(); // never blocks
        HostOutcome::Queued
    }
}

// ---- host -> Wi-Fi: the worker ---------------------------------------------------------------------------------------------------------

/// The worker's handle: the single consumer of the host queue, and the only place the Wi-Fi driver is called from the host side.
/// See [`Bridge::worker`].
#[derive(Debug)]
pub struct Worker<'a, E: Env> {
    bridge: &'a Bridge<E>,
    /// The CoDel controller: worker only.
    codel: Codel,
    codel_gen_seen: u32,
}

impl<E: Env> Drop for Worker<'_, E> {
    fn drop(&mut self) {
        self.bridge.worker_taken.store(false, Ordering::Release);
    }
}

impl<E: Env> Worker<'_, E> {
    /// Everything queued so far; returns how many frames were handled. The worker task is `loop { wait for notify; worker.drain(); }`: a
    /// notification that arrives during `drain` is kept by the RTOS, so no wake-up is lost.
    pub fn drain(&mut self) -> u32 {
        let mut handled = 0;
        while self.drain_one() {
            handled += 1;
        }
        handled
    }

    /// One queued frame, if there is one: deliver it, release its slot, and ask the USB layer to offer a held datagram once the queue is at the
    /// resume depth. Returns whether a frame was handled.
    pub fn drain_one(&mut self) -> bool {
        let b = self.bridge;
        let tail = b.tail.load(Ordering::Relaxed);
        if tail == b.head.load(Ordering::Acquire) {
            return false;
        }
        // SAFETY: SPSC protocol (queue.rs): `Worker` is the only consumer (one per bridge, `&mut self`) and tail != head, so the producer has
        // published this slot and will not write it until `tail` moves.
        let slot = unsafe { b.slots.slot(tail) };
        self.deliver(slot);
        b.tail.store(tail.wrapping_add(1), Ordering::SeqCst); // the slot is the producer's again
        // The queue has room again: if the callback refused a datagram, ask the USB layer to offer it. Below the resume depth, not the limit,
        // so the pipe is refilled while the worker still has frames to send.
        let depth_after = b.head.load(Ordering::Acquire).wrapping_sub(tail.wrapping_add(1));
        if depth_after <= b.t_resume.load(Ordering::Relaxed) && b.held.swap(false, Ordering::SeqCst) {
            b.resume();
        }
        true
    }

    /// CoDel at the hand-to-radio. The signal is what the dongle can see of a standing queue: the larger of this frame's own time in the dongle
    /// (the standard sojourn) and how long the pipe has been continuously full (the age of the hold-evidenced busy period). The first alone
    /// cannot see the host's queue: with backpressure it stays at a few milliseconds while the host's FIFO sits behind our NAKs (board: 2-3 ms in
    /// the dongle, 55-83 ms ping). The second grows for exactly as long as the host has a backlog to push into a full pipe, and falls back to zero
    /// the moment the host finds room without waiting, which is what CoDel's "minimum over an interval" needs. Returns true when the frame was
    /// dropped.
    fn codel_signals(&mut self, slot: &mut Slot, now: u32, own_sojourn: u32) -> bool {
        let b = self.bridge;
        let frame = &mut slot.bytes[..slot.len as usize];
        let class = classify(frame);
        if matches!(class, EcnClass::NotIp | EcnClass::Exempt) {
            return false; // ARP, DHCP, ND, SYN/FIN/RST: never signalled, not measured
        }
        let generation = b.t_codel_gen.load(Ordering::Acquire);
        if generation != self.codel_gen_seen {
            self.codel.retune(b.t_codel_target_us.load(Ordering::Relaxed), b.t_codel_interval_ms.load(Ordering::Relaxed).wrapping_mul(1000));
            self.codel_gen_seen = generation;
            b.codel_count.store(0, Ordering::Relaxed);
        }
        let full = b.hold_period_age(now);
        let signal = full.max(own_sojourn);
        Counters::add(&b.c.h2w_signal_us_sum, signal);
        Counters::note_max(&b.c.h2w_signal_us_max, signal);
        let signalled = self.codel.should_signal(signal, now);
        b.codel_count.store(if self.codel.dropping { self.codel.count } else { 0 }, Ordering::Relaxed);
        if !signalled {
            return false;
        }
        Counters::bump(&b.c.h2w_codel_signals);
        match class {
            EcnClass::Capable => {
                mark_ce(frame);
                Counters::bump(&b.c.h2w_ce_marked);
                false
            }
            EcnClass::Ce => false, // already marked upstream: the signal is satisfied
            _ => {
                Counters::bump(&b.c.h2w_codel_drop);
                true
            }
        }
    }

    fn room_done(&self, since: u32) {
        let dt = self.bridge.env.now_us().wrapping_sub(since);
        Counters::add(&self.bridge.c.h2w_room_wait_us_sum, dt);
        Counters::note_max(&self.bridge.c.h2w_room_wait_us_max, dt);
    }

    /// One queued frame.
    fn deliver(&mut self, slot: &mut Slot) {
        let b = self.bridge;
        let c = &b.c;
        let env = &b.env;
        if !b.linked.load(Ordering::Acquire) {
            Counters::bump(&c.h2w_link_down_queued);
            return;
        }
        if slot.epoch != b.epoch.load(Ordering::Acquire) as u16 {
            Counters::bump(&c.h2w_stale); // queued under an association that has since ended
            return;
        }
        let first = env.now_us();
        let waited = first.wrapping_sub(slot.enq_us);
        let limit = b.t_sojourn_ms.load(Ordering::Relaxed) * 1000;
        if waited >= limit {
            Counters::bump(&c.h2w_sojourn_drop); // a stalled link must not turn the queue into a delay line
            return;
        }
        Counters::add(&c.h2w_wait_us_sum, waited);
        Counters::note_max(&c.h2w_wait_us_max, waited);
        if b.t_codel.load(Ordering::Relaxed) && self.codel_signals(slot, first, waited) {
            return; // dropped by CoDel
        }
        let len = slot.len as usize;
        let mut room_since: Option<u32> = None;
        loop {
            if !env.wifi_room() {
                // The radio has its allowance in flight: that is the bottleneck working, not a failure. Wait for a frame to leave the antenna.
                // The sojourn limit still bounds the wait (a link that never completes anything).
                if room_since.is_none() {
                    room_since = Some(env.now_us());
                    Counters::bump(&c.h2w_room_waits);
                }
                if env.now_us().wrapping_sub(slot.enq_us) >= limit {
                    if let Some(since) = room_since {
                        self.room_done(since);
                    }
                    Counters::bump(&c.h2w_tx_failed);
                    return;
                }
                Counters::bump(&c.h2w_tx_retries);
                env.wait_retry();
                continue;
            }
            if let Some(since) = room_since.take() {
                self.room_done(since);
            }
            // The slot is read in place: only this task frees it (by advancing tail), and the driver copies the frame inside the call.
            let t0 = env.now_us();
            let result = env.wifi_tx(&slot.bytes[..len]);
            let t1 = env.now_us();
            match result {
                Ok(()) => {
                    Counters::bump(&c.h2w_sent);
                    Counters::add(&c.h2w_tx_us_sum, t1.wrapping_sub(t0));
                    Counters::note_max(&c.h2w_tx_us_max, t1.wrapping_sub(t0));
                    return;
                }
                Err(error) => {
                    c.h2w_last_tx_error.store(error.code(), Ordering::Relaxed);
                    // Only "no buffer" can clear by itself. A link change while we wait makes the frame stale, whatever the driver says.
                    if error != crate::TxError::NoMem
                        || !b.linked.load(Ordering::Acquire)
                        || slot.epoch != b.epoch.load(Ordering::Acquire) as u16
                        || t1.wrapping_sub(slot.enq_us) >= limit
                    {
                        Counters::bump(&c.h2w_tx_failed);
                        return;
                    }
                    Counters::bump(&c.h2w_tx_retries);
                    env.wait_retry();
                }
            }
        }
    }
}
