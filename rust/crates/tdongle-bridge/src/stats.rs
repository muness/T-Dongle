//! The bridge's counters (`tdongle_l2_stats_t`), and the identities that make every missing frame attributable.
//!
//! Every frame that enters either callback is counted exactly once, as forwarded or as one named drop. The identities hold **at rest** (no
//! callback or worker pass in flight) and are asserted after every operation in the tests:
//!
//! * `w2h_frames  = w2h_forwarded + w2h_invalid + w2h_own_mac + w2h_link_down + w2h_usb_not_ready + w2h_ring_full`
//! * `h2w_frames  = h2w_queued + h2w_invalid + h2w_foreign_mac + h2w_link_down` (a held offer is not a frame until it is finally taken)
//! * `h2w_queued  = h2w_sent + h2w_stale + h2w_sojourn_drop + h2w_link_down_queued + h2w_tx_failed + h2w_codel_drop + h2w_queue_depth`

use tdongle_spsc::sync::atomic::{AtomicI32, AtomicU32, Ordering};

macro_rules! counters {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        /// The live counters: word-sized atomics, relaxed (they are evidence, not synchronisation).
        #[derive(Debug)]
        pub(crate) struct Counters {
            $($(#[$doc])* pub(crate) $name: AtomicU32,)*
            pub(crate) h2w_last_tx_error: AtomicI32,
        }

        impl Counters {
            pub(crate) fn new() -> Self {
                Self { $($name: AtomicU32::new(0),)* h2w_last_tx_error: AtomicI32::new(0) }
            }
        }
    };
}

counters! {
    link_changes,
    w2h_frames, w2h_forwarded, w2h_invalid, w2h_own_mac, w2h_link_down, w2h_usb_not_ready, w2h_ring_full, w2h_raced,
    h2w_frames, h2w_queued, h2w_invalid, h2w_foreign_mac, h2w_link_down, h2w_held, h2w_resumes,
    h2w_sent, h2w_stale, h2w_sojourn_drop, h2w_link_down_queued, h2w_tx_failed, h2w_tx_retries, h2w_queue_high_water,
    h2w_codel_signals, h2w_ce_marked, h2w_codel_drop, h2w_signal_us_sum, h2w_signal_us_max,
    h2w_ecn_not_ect, h2w_ecn_capable, h2w_ecn_ce, h2w_ecn_exempt, h2w_ecn_not_ip, h2w_syn_ecn_setup, w2h_synack_ecn,
    h2w_room_waits, h2w_room_wait_us_sum, h2w_room_wait_us_max,
    pm_notes, pm_note_us_sum, pm_note_us_max, h2w_wait_us_sum, h2w_wait_us_max, h2w_tx_us_sum, h2w_tx_us_max,
}

impl Counters {
    #[inline]
    pub(crate) fn bump(counter: &AtomicU32) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub(crate) fn add(counter: &AtomicU32, value: u32) {
        counter.fetch_add(value, Ordering::Relaxed);
    }

    /// Raise a high-water mark (a lock-free maximum).
    #[inline]
    pub(crate) fn note_max(mark: &AtomicU32, value: u32) {
        mark.fetch_max(value, Ordering::Relaxed);
    }
}

/// A snapshot of every counter, in the field names and meanings of the C `tdongle_l2_stats_t`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// The Wi-Fi link is up (associated) and the RX callback registered.
    pub linked: bool,
    /// Associations gained and lost.
    pub link_changes: u32,
    // ---- Wi-Fi -> host ----
    /// Frames the driver handed to the RX callback.
    pub w2h_frames: u32,
    /// Accepted into the USB transmit ring (its own counters say what USB then did).
    pub w2h_forwarded: u32,
    /// Shorter than an Ethernet header or longer than [`FRAME_MAX`](crate::FRAME_MAX), or refused by the ring as malformed.
    pub w2h_invalid: u32,
    /// Source is the bridge's own (STA) MAC: a frame the host sent that came back; filtered by design.
    pub w2h_own_mac: u32,
    /// The Wi-Fi link was marked down: the callback was racing the disconnect.
    pub w2h_link_down: u32,
    /// USB not configured (cable out, host asleep) or the ring not started.
    pub w2h_usb_not_ready: u32,
    /// No room in the USB transmit ring at its elastic cap: backpressure drop.
    pub w2h_ring_full: u32,
    /// A frame was in the RX callback while the link changed: the ring was flushed again so it cannot outlive the change.
    pub w2h_raced: u32,
    // ---- host -> Wi-Fi ----
    /// Frames the TinyUSB receive callback took (a held offer is not a frame until it is taken).
    pub h2w_frames: u32,
    /// Accepted into the host queue.
    pub h2w_queued: u32,
    /// Shorter than an Ethernet header or longer than the frame maximum.
    pub h2w_invalid: u32,
    /// Source is not the STA MAC: the bridge speaks for the STA address only; filtered by design.
    pub h2w_foreign_mac: u32,
    /// Wi-Fi not connected when the frame arrived.
    pub h2w_link_down: u32,
    /// Offers refused with HOLD at the queue limit: USB backpressure, nothing dropped.
    pub h2w_held: u32,
    /// Times the worker asked for held datagrams again.
    pub h2w_resumes: u32,
    // ---- CoDel (only when enabled) ----
    /// Eligible frames CoDel signalled (marked, already CE, or dropped).
    pub h2w_codel_signals: u32,
    /// ECT frames that left with CE set.
    pub h2w_ce_marked: u32,
    /// Non-ECT frames dropped by CoDel.
    pub h2w_codel_drop: u32,
    /// Sum of the signal CoDel saw per eligible frame: max(its own time in the dongle, time the pipe has been continuously full).
    pub h2w_signal_us_sum: u32,
    /// Largest such signal.
    pub h2w_signal_us_max: u32,
    /// CoDel's signal count in the current dropping state (0 outside it).
    pub h2w_codel_count: u32,
    // ---- ECN as it crosses the bridge, always counted ----
    /// Host frames that are IP and not ECN-capable.
    pub h2w_ecn_not_ect: u32,
    /// Host frames carrying ECT(0) or ECT(1).
    pub h2w_ecn_capable: u32,
    /// Host frames already marked CE.
    pub h2w_ecn_ce: u32,
    /// Host frames that are never signalled (setup/teardown, DHCP, ICMPv6, ...).
    pub h2w_ecn_exempt: u32,
    /// Host frames that are not IP (ARP, ...) or malformed.
    pub h2w_ecn_not_ip: u32,
    /// SYN+ECE+CWR from the host: it asked for ECN.
    pub h2w_syn_ecn_setup: u32,
    /// SYN+ACK+ECE to the host: the server accepted.
    pub w2h_synack_ecn: u32,
    /// Frames that had to wait for the radio's allowance.
    pub h2w_room_waits: u32,
    /// Sum of those waits (microseconds, wraps at 71 minutes: take differences).
    pub h2w_room_wait_us_sum: u32,
    /// Longest such wait.
    pub h2w_room_wait_us_max: u32,
    // ---- the worker ----
    /// The Wi-Fi driver took the frame.
    pub h2w_sent: u32,
    /// Queued before the link changed: dropped without sending.
    pub h2w_stale: u32,
    /// Older than the sojourn limit when the worker reached it: dropped without sending.
    pub h2w_sojourn_drop: u32,
    /// The link went down while the frame was queued.
    pub h2w_link_down_queued: u32,
    /// Refused until the sojourn limit, or a final error.
    pub h2w_tx_failed: u32,
    /// Retries after a refusal for buffers or for the radio's allowance.
    pub h2w_tx_retries: u32,
    /// `esp_err_t` of the last refusal, 0 if none.
    pub h2w_last_tx_error: i32,
    /// Frames in the queue now, including the one being sent.
    pub h2w_queue_depth: u32,
    /// Most frames ever standing in the queue.
    pub h2w_queue_high_water: u32,
    /// Bytes of the worker's stack never used.
    pub worker_stack_free: u32,
    // ---- where the time goes (microseconds; sums wrap at 71 minutes, take differences) ----
    /// Calls of the clock-raise hook.
    pub pm_notes: u32,
    /// Sum of their cost.
    pub pm_note_us_sum: u32,
    /// Largest cost.
    pub pm_note_us_max: u32,
    /// Callback to the worker's first attempt (queueing), summed over the frames that were attempted.
    pub h2w_wait_us_sum: u32,
    /// Largest such wait.
    pub h2w_wait_us_max: u32,
    /// The Wi-Fi transmit call itself, summed over calls that succeeded.
    pub h2w_tx_us_sum: u32,
    /// Largest such call.
    pub h2w_tx_us_max: u32,
}

/// Which counter identity failed, see the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityFailure {
    /// `w2h_frames` does not add up.
    ToHost,
    /// `h2w_frames` does not add up.
    ToWifi,
    /// `h2w_queued` does not add up.
    Queue,
}

impl Stats {
    /// Check the three identities (valid at rest only: a frame mid-flight is momentarily in neither term).
    ///
    /// # Errors
    /// The first identity that does not hold.
    pub const fn check_identities(&self) -> Result<(), IdentityFailure> {
        // Wrapping adds: the counters are free-running u32 and the identities hold modulo 2^32.
        let to_host = self
            .w2h_forwarded
            .wrapping_add(self.w2h_invalid)
            .wrapping_add(self.w2h_own_mac)
            .wrapping_add(self.w2h_link_down)
            .wrapping_add(self.w2h_usb_not_ready)
            .wrapping_add(self.w2h_ring_full);
        if self.w2h_frames != to_host {
            return Err(IdentityFailure::ToHost);
        }
        let to_wifi = self.h2w_queued.wrapping_add(self.h2w_invalid).wrapping_add(self.h2w_foreign_mac).wrapping_add(self.h2w_link_down);
        if self.h2w_frames != to_wifi {
            return Err(IdentityFailure::ToWifi);
        }
        let queue = self
            .h2w_sent
            .wrapping_add(self.h2w_stale)
            .wrapping_add(self.h2w_sojourn_drop)
            .wrapping_add(self.h2w_link_down_queued)
            .wrapping_add(self.h2w_tx_failed)
            .wrapping_add(self.h2w_codel_drop)
            .wrapping_add(self.h2w_queue_depth);
        if self.h2w_queued != queue {
            return Err(IdentityFailure::Queue);
        }
        Ok(())
    }
}
