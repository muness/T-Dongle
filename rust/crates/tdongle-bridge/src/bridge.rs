//! [`Bridge`], [`Producer`] and [`Worker`]: the port of `l2.c`, under the design rules of ADR 0001:
//!
//! * **exhaustive outcomes**: every frame that enters a callback or the worker ends as one variant of a `#[must_use]` enum
//!   ([`ToHost`], [`HostOutcome`], [`Delivery`]); the counters are bumped in one `match` per enum with **no wildcard arm**, so an uncounted
//!   drop path does not compile;
//! * **move-only slots**: the host queue is `tdongle-spsc`, whose [`Lease`](tdongle_spsc::Lease) releases its slot exactly once, in `Drop`;
//! * **stale links by type**: a queued frame carries a [`LinkToken`]; the worker needs a [`Fresh`] proof from [`Bridge::validate`] to hand it to
//!   the radio;
//! * **callback context**: blocking environment calls take a [`TaskContext`] that the callbacks never hold.
//!
//! This crate is `#![forbid(unsafe_code)]`.

use tdongle_aqm::{Codel, EcnClass, INTERVAL_MS_DEFAULT, TARGET_US_DEFAULT, TcpEcnSyn, classify, mark_ce, tcp_ecn_syn};
use tdongle_spsc::sync::UnsafeCell;
use tdongle_spsc::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tdongle_spsc::{Consumer, Producer as QueueProducer, Spsc, TaskContext};

use crate::env::{Env, RingSend, TxError};
use crate::stats::{Counters, Stats};
use crate::tuning::{InvalidTuning, Tuning};
use crate::{CODEL_DEFAULT, FRAME_MAX, HOST_QUEUE_LIMIT, HOST_RESUME_DEPTH, HOST_SLOTS, SLOT_BYTES, SOJOURN_MS};

const ETH_HEADER: usize = 14;

/// Identifies one Wi-Fi association (`epoch`, 16 bits as in C). A frame is stamped with the token current when it was queued; a stale token is
/// refused by [`Bridge::validate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkToken(u16);

/// Proof that a [`LinkToken`] was current and the link up at the moment [`Bridge::validate`] looked. Cannot be built any other way.
#[derive(Debug)]
#[must_use]
pub struct Fresh<'a>(core::marker::PhantomData<&'a ()>);

/// Why a token was refused (`validate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The link is down.
    LinkDown,
    /// The frame was queued under an association that has since ended.
    Stale,
}

/// One queued frame: where it came from in time, and under which association.
#[derive(Debug)]
pub(crate) struct Slot {
    len: u16,
    token: LinkToken,
    /// The microsecond clock when the callback queued it.
    enq_us: u32,
    bytes: [u8; FRAME_MAX],
}

// `TDONGLE_L2_SLOT_BYTES` is the size the heap budget is written with (ADR 0023): a slot must not grow past it.
const _: () = assert!(size_of::<Slot>() <= SLOT_BYTES);

pub(crate) type Queue = Spsc<Slot, HOST_SLOTS>;

/// What the TinyUSB receive callback should tell the USB class driver about one offered datagram (`tdongle_l2_host`'s `esp_err_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "every datagram ends as exactly one outcome: the caller decides whether the class driver keeps it (Hold) or not"]
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

/// How one frame from Wi-Fi ended (the Wi-Fi RX callback).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "every frame ends as exactly one outcome: the Wi-Fi task decides what to do with the driver buffer, the bridge has already counted it"]
pub enum ToHost {
    /// Accepted into the USB ring. `raced`: the association changed while the frame was being copied, so the ring was flushed again.
    Forwarded {
        /// The epoch moved during the copy.
        raced: bool,
    },
    /// Shorter than an Ethernet header or longer than [`FRAME_MAX`], or refused by the ring as malformed.
    Invalid,
    /// Source is the bridge's own MAC.
    OwnMac,
    /// The link was marked down.
    LinkDown,
    /// USB not configured, or the ring not started.
    UsbNotReady,
    /// No room in the ring at its elastic cap.
    RingFull,
}

/// How one queued frame ended in the worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "every queued frame ends as exactly one delivery"]
pub enum Delivery {
    /// The Wi-Fi driver took the frame after `tx_us` microseconds in the transmit call.
    Sent {
        /// Duration of the successful transmit call.
        tx_us: u32,
    },
    /// Queued before the link changed.
    Stale,
    /// Older than the sojourn limit when the worker reached it.
    SojournDrop,
    /// The link went down while the frame was queued.
    LinkDownQueued,
    /// Refused until the sojourn limit, or a final error.
    TxFailed,
    /// Dropped by CoDel (a non-ECT frame while the pipe is saturated).
    CodelDrop,
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
    queue: Queue,
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
    pub fn new(env: E, identity: [u8; 6]) -> Self {
        Self {
            env,
            identity,
            queue: Spsc::from_cells(core::array::from_fn(|_| UnsafeCell::new(Slot { len: 0, token: LinkToken(0), enq_us: 0, bytes: [0; FRAME_MAX] }))),
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
        }
    }

    /// The environment (for the firmware glue that owns the bridge).
    pub const fn env(&self) -> &E {
        &self.env
    }

    /// The single host -> Wi-Fi producer handle (the TinyUSB receive callback). `None` while another handle is alive.
    pub fn producer(&self) -> Option<Producer<'_, E>> {
        self.queue.producer().map(|queue| Producer { bridge: self, queue })
    }

    /// The single worker handle: the only context that drains the queue, calls [`Env::wifi_tx`] and holds the CoDel controller.
    /// `None` while another handle is alive.
    pub fn worker(&self) -> Option<Worker<'_, E>> {
        self.queue.consumer().map(|queue| Worker {
            bridge: self,
            context: queue.blocking_context(),
            queue,
            codel: Codel::new(TARGET_US_DEFAULT, INTERVAL_MS_DEFAULT * 1000),
            codel_gen_seen: 0,
        })
    }

    // ---- link tokens ------------------------------------------------------------------------------------------------------------------

    fn token(&self) -> LinkToken {
        LinkToken(self.epoch.load(Ordering::Acquire) as u16)
    }

    /// Accept a frame's token only if the link is up and the token is the current association's.
    ///
    /// # Errors
    /// [`Refused`] says whether the link is down or the frame is from an older association.
    pub fn validate(&self, token: LinkToken) -> Result<Fresh<'static>, Refused> {
        if !self.linked.load(Ordering::Acquire) {
            return Err(Refused::LinkDown);
        }
        if token != self.token() {
            return Err(Refused::Stale);
        }
        Ok(Fresh(core::marker::PhantomData))
    }

    // ---- Wi-Fi -> host: the Wi-Fi task -------------------------------------------------------------------------------------------------

    /// The Wi-Fi RX callback. The caller frees the driver's RX buffer after this returns, on every path, exactly once (the driver's pool is not
    /// ours to hold). It holds no [`TaskContext`]: nothing it calls may block.
    pub fn wifi_rx(&self, frame: &[u8]) -> ToHost {
        // The epoch is read BEFORE the link is looked at: a link change that lands while this frame is being copied is then visible afterwards.
        let epoch = self.epoch.load(Ordering::Acquire);
        let outcome = if frame.len() < ETH_HEADER || frame.len() > FRAME_MAX {
            ToHost::Invalid
        } else if frame[6..12] == self.identity {
            ToHost::OwnMac
        } else if !self.linked.load(Ordering::Acquire) {
            ToHost::LinkDown
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
                    // The window: this frame passed the link check under an association that ended before the ring stamped it, so it carries
                    // the NEW generation and the flush of the change cannot discard it. The epoch moved: flush again. It costs the frames of
                    // the first microseconds of the new association, which is the right side to err on.
                    let raced = self.epoch.load(Ordering::Acquire) != epoch;
                    if raced {
                        self.env.usb_ring_flush();
                    }
                    ToHost::Forwarded { raced }
                }
                RingSend::Full => ToHost::RingFull,
                RingSend::NotReady => ToHost::UsbNotReady,
                RingSend::Invalid => ToHost::Invalid,
            }
        };
        self.settle_to_host(outcome);
        outcome
    }

    /// Count one frame's outcome. The only place `w2h_*` counters move: the match has no wildcard arm.
    fn settle_to_host(&self, outcome: ToHost) {
        let c = &self.c;
        Counters::bump(&c.w2h_frames);
        match outcome {
            ToHost::Forwarded { raced } => {
                Counters::bump(&c.w2h_forwarded);
                if raced {
                    Counters::bump(&c.w2h_raced);
                }
            }
            ToHost::Invalid => Counters::bump(&c.w2h_invalid),
            ToHost::OwnMac => Counters::bump(&c.w2h_own_mac),
            ToHost::LinkDown => Counters::bump(&c.w2h_link_down),
            ToHost::UsbNotReady => Counters::bump(&c.w2h_usb_not_ready),
            ToHost::RingFull => Counters::bump(&c.w2h_ring_full),
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

    /// The STA associated or lost its association (event task, which may block: hence the [`TaskContext`]). Frames queued toward the host and
    /// toward Wi-Fi from the previous association are discarded (generation), the host sees the carrier change.
    ///
    /// The order is part of the contract (tests pin it): connect = flush the old association's frames, register the RX callback, open the
    /// gate; disconnect = close the gate, unregister, flush; then the held datagram is released and the host told.
    pub fn link(&self, connected: bool, context: &TaskContext) {
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
            self.resume(context);
        }
        self.env.usb_link_state(connected);
    }

    fn resume(&self, context: &TaskContext) {
        Counters::bump(&self.c.h2w_resumes);
        self.env.rx_resume(context);
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
            h2w_queue_depth: self.queue.depth(),
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

    /// Test access to the slot counters (the wrap tests).
    #[cfg(test)]
    pub(crate) fn queue(&self) -> &Queue {
        &self.queue
    }
}

// ---- host -> Wi-Fi: the TinyUSB task ---------------------------------------------------------------------------------------------------

/// The TinyUSB receive callback's handle: the single producer of the host queue. See [`Bridge::producer`]. It holds no [`TaskContext`].
#[derive(Debug)]
pub struct Producer<'a, E: Env> {
    bridge: &'a Bridge<E>,
    queue: QueueProducer<'a, Slot, HOST_SLOTS>,
}

impl<E: Env> Producer<'_, E> {
    /// Offer one datagram from the host (`tdongle_l2_host`). Never blocks, allocates or calls into the Wi-Fi driver.
    ///
    /// `h2w_frames` counts frames TAKEN (queued or dropped by name); a held offer comes back and is counted when it is finally taken.
    pub fn host(&mut self, frame: &[u8]) -> HostOutcome {
        let b = self.bridge;
        let outcome = self.admit(frame);
        b.settle_host(outcome);
        outcome
    }

    fn admit(&mut self, frame: &[u8]) -> HostOutcome {
        let b = self.bridge;
        if frame.len() < ETH_HEADER || frame.len() > FRAME_MAX {
            return HostOutcome::Invalid;
        }
        if frame[6..12] != b.identity {
            return HostOutcome::ForeignMac;
        }
        if !b.linked.load(Ordering::Acquire) {
            return HostOutcome::LinkDown;
        }
        let limit = b.t_queue_limit.load(Ordering::Relaxed);
        let reservation = match self.queue.reserve(limit) {
            Ok(reservation) => reservation,
            Err(_) => {
                // Backpressure: say "not now" (the USB class driver keeps the datagram and NAKs the host), and make sure the worker will say
                // "now". The flag is published BEFORE the queue is looked at again, so a worker that drains in between either sees it (and
                // resumes) or this look sees its room.
                b.held.store(true, Ordering::SeqCst);
                let tail = b.queue.tail(Ordering::SeqCst);
                match self.queue.reserve_after(tail, limit) {
                    Ok(reservation) if b.held.swap(false, Ordering::SeqCst) => reservation,
                    // Still full, or the worker already took the flag and owes a resume that re-offers this datagram.
                    Ok(_) | Err(_) => {
                        b.note_hold(b.env.now_us());
                        return HostOutcome::Hold;
                    }
                }
            }
        };
        if unicast(frame) {
            b.note_activity();
        }
        b.count_ecn(frame);
        let token = b.token();
        let now = b.env.now_us();
        let depth = reservation.publish(|slot| {
            slot.len = frame.len() as u16;
            slot.token = token;
            slot.enq_us = now;
            slot.bytes[..frame.len()].copy_from_slice(frame);
        });
        Counters::note_max(&b.c.h2w_queue_high_water, depth);
        b.env.notify_worker(); // never blocks
        HostOutcome::Queued
    }
}

impl<E: Env> Bridge<E> {
    /// Count one offered datagram's outcome. The only place `h2w_frames`, `h2w_queued` and the filter counters move: no wildcard arm.
    fn settle_host(&self, outcome: HostOutcome) {
        let c = &self.c;
        match outcome {
            HostOutcome::Queued => {
                Counters::bump(&c.h2w_frames);
                Counters::bump(&c.h2w_queued);
            }
            HostOutcome::ForeignMac => {
                Counters::bump(&c.h2w_frames);
                Counters::bump(&c.h2w_foreign_mac);
            }
            HostOutcome::Invalid => {
                Counters::bump(&c.h2w_frames);
                Counters::bump(&c.h2w_invalid);
            }
            HostOutcome::LinkDown => {
                Counters::bump(&c.h2w_frames);
                Counters::bump(&c.h2w_link_down);
            }
            // A held offer is not a frame until it is finally taken.
            HostOutcome::Hold => Counters::bump(&c.h2w_held),
        }
    }

    /// Count one delivery's outcome. The only place the worker's counters move: no wildcard arm.
    fn settle_delivery(&self, outcome: Delivery) {
        let c = &self.c;
        match outcome {
            Delivery::Sent { tx_us } => {
                Counters::bump(&c.h2w_sent);
                Counters::add(&c.h2w_tx_us_sum, tx_us);
                Counters::note_max(&c.h2w_tx_us_max, tx_us);
            }
            Delivery::Stale => Counters::bump(&c.h2w_stale),
            Delivery::SojournDrop => Counters::bump(&c.h2w_sojourn_drop),
            Delivery::LinkDownQueued => Counters::bump(&c.h2w_link_down_queued),
            Delivery::TxFailed => Counters::bump(&c.h2w_tx_failed),
            Delivery::CodelDrop => Counters::bump(&c.h2w_codel_drop),
        }
    }
}

// ---- host -> Wi-Fi: the worker ---------------------------------------------------------------------------------------------------------

/// The worker's handle: the single consumer of the host queue, and the only place the Wi-Fi driver is called from the host side.
/// See [`Bridge::worker`]. It owns the [`TaskContext`] the blocking environment calls need.
#[derive(Debug)]
pub struct Worker<'a, E: Env> {
    bridge: &'a Bridge<E>,
    queue: Consumer<'a, Slot, HOST_SLOTS>,
    context: TaskContext,
    /// The CoDel controller: worker only.
    codel: Codel,
    codel_gen_seen: u32,
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

    /// One queued frame, if there is one: deliver it, release its slot (the lease's `Drop`), and ask the USB layer to offer a held datagram once
    /// the queue is at the resume depth. Returns whether a frame was handled.
    pub fn drain_one(&mut self) -> bool {
        let b = self.bridge;
        let Some(mut lease) = self.queue.claim() else { return false };
        // The slot is read in place: only this task frees it (the lease's drop), and the driver copies the frame inside the call.
        let mut slot = LeasedSlot { lease: &mut lease };
        let outcome = slot.with(|s| deliver(b, &self.context, &mut self.codel, &mut self.codel_gen_seen, s));
        b.settle_delivery(outcome);
        drop(lease); // the slot is the producer's again
        // The queue has room again: if the callback refused a datagram, ask the USB layer to offer it. Below the resume depth, not the limit,
        // so the pipe is refilled while the worker still has frames to send.
        if b.queue.depth() <= b.t_resume.load(Ordering::Relaxed) && b.held.swap(false, Ordering::SeqCst) {
            b.resume(&self.context);
        }
        true
    }
}

/// A leased slot, used through a closure so no reference to it escapes the lease.
struct LeasedSlot<'l, 'q> {
    lease: &'l mut tdongle_spsc::Lease<'q, Slot, HOST_SLOTS>,
}

impl LeasedSlot<'_, '_> {
    fn with<R>(&mut self, f: impl FnOnce(&mut Slot) -> R) -> R {
        self.lease.with(f)
    }
}

/// CoDel at the hand-to-radio. The signal is what the dongle can see of a standing queue: the larger of this frame's own time in the dongle
/// (the standard sojourn) and how long the pipe has been continuously full (the age of the hold-evidenced busy period). The first alone cannot
/// see the host's queue: with backpressure it stays at a few milliseconds while the host's FIFO sits behind our NAKs (board: 2-3 ms in the
/// dongle, 55-83 ms ping). The second grows for exactly as long as the host has a backlog to push into a full pipe, and falls back to zero the
/// moment the host finds room without waiting, which is what CoDel's "minimum over an interval" needs. Returns true when the frame was dropped.
fn codel_drops<E: Env>(b: &Bridge<E>, codel: &mut Codel, gen_seen: &mut u32, slot: &mut Slot, now: u32, own_sojourn: u32) -> bool {
    let frame = &mut slot.bytes[..slot.len as usize];
    let class = classify(frame);
    if matches!(class, EcnClass::NotIp | EcnClass::Exempt) {
        return false; // ARP, DHCP, ND, SYN/FIN/RST: never signalled, not measured
    }
    let generation = b.t_codel_gen.load(Ordering::Acquire);
    if generation != *gen_seen {
        codel.retune(b.t_codel_target_us.load(Ordering::Relaxed), b.t_codel_interval_ms.load(Ordering::Relaxed).wrapping_mul(1000));
        *gen_seen = generation;
        b.codel_count.store(0, Ordering::Relaxed);
    }
    let signal = b.hold_period_age(now).max(own_sojourn);
    Counters::add(&b.c.h2w_signal_us_sum, signal);
    Counters::note_max(&b.c.h2w_signal_us_max, signal);
    let signalled = codel.should_signal(signal, now);
    b.codel_count.store(if codel.dropping { codel.count } else { 0 }, Ordering::Relaxed);
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
        EcnClass::NotEct => true,
        // Unreachable (returned above), but spelled out so a new class cannot be forgotten.
        EcnClass::NotIp | EcnClass::Exempt => false,
    }
}

fn room_done<E: Env>(b: &Bridge<E>, since: u32) {
    let dt = b.env.now_us().wrapping_sub(since);
    Counters::add(&b.c.h2w_room_wait_us_sum, dt);
    Counters::note_max(&b.c.h2w_room_wait_us_max, dt);
}

/// One queued frame, in the worker: the only place the Wi-Fi driver is called from the host side.
fn deliver<E: Env>(b: &Bridge<E>, context: &TaskContext, codel: &mut Codel, gen_seen: &mut u32, slot: &mut Slot) -> Delivery {
    let env = &b.env;
    let mut fresh = match b.validate(slot.token) {
        Ok(fresh) => fresh,
        Err(Refused::LinkDown) => return Delivery::LinkDownQueued,
        Err(Refused::Stale) => return Delivery::Stale, // queued under an association that has since ended
    };
    let first = env.now_us();
    let waited = first.wrapping_sub(slot.enq_us);
    let limit = b.t_sojourn_ms.load(Ordering::Relaxed) * 1000;
    if waited >= limit {
        return Delivery::SojournDrop; // a stalled link must not turn the queue into a delay line
    }
    Counters::add(&b.c.h2w_wait_us_sum, waited);
    Counters::note_max(&b.c.h2w_wait_us_max, waited);
    if b.t_codel.load(Ordering::Relaxed) && codel_drops(b, codel, gen_seen, slot, first, waited) {
        return Delivery::CodelDrop;
    }
    let len = slot.len as usize;
    let mut room_since: Option<u32> = None;
    loop {
        if !env.wifi_room() {
            // The radio has its allowance in flight: that is the bottleneck working, not a failure. Wait for a frame to leave the antenna.
            // The sojourn limit still bounds the wait (a link that never completes anything).
            if room_since.is_none() {
                room_since = Some(env.now_us());
                Counters::bump(&b.c.h2w_room_waits);
            }
            if env.now_us().wrapping_sub(slot.enq_us) >= limit {
                if let Some(since) = room_since {
                    room_done(b, since);
                }
                return Delivery::TxFailed;
            }
            Counters::bump(&b.c.h2w_tx_retries);
            env.wait_retry(context);
            continue;
        }
        if let Some(since) = room_since.take() {
            room_done(b, since);
        }
        let t0 = env.now_us();
        let result = transmit(env, &slot.bytes[..len], context, &fresh);
        let t1 = env.now_us();
        match result {
            Ok(()) => return Delivery::Sent { tx_us: t1.wrapping_sub(t0) },
            Err(error) => {
                b.c.h2w_last_tx_error.store(error.code(), Ordering::Relaxed);
                // Only "no buffer" can clear by itself. A link change while we wait makes the frame stale, whatever the driver says.
                fresh = match (error, b.validate(slot.token)) {
                    (TxError::NoMem, Ok(fresh)) if t1.wrapping_sub(slot.enq_us) < limit => fresh,
                    (TxError::NoMem | TxError::Other(_), _) => return Delivery::TxFailed,
                };
                Counters::bump(&b.c.h2w_tx_retries);
                env.wait_retry(context);
            }
        }
    }
}

/// The one call into the Wi-Fi driver. It needs a [`Fresh`] proof, so a frame of a dead association cannot be sent by construction.
fn transmit<E: Env>(env: &E, frame: &[u8], context: &TaskContext, _proof: &Fresh<'_>) -> Result<(), TxError> {
    env.wifi_tx(frame, context)
}
