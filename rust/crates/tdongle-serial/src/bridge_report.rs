//! The `bridge_*` lines of serial `status` in bridge mode: the port of `main/bridge_status.inc` (`bridge_visit`, `bridge_line_emit`,
//! `bridge_line_flush`, `bridge_status_lines`).
//!
//! One visitor ([`visit`]) lists every counter as `(section, name, value)` in a fixed order; one renderer ([`LineWriter`]) turns the
//! sequence into one line per section. Android parses the first status lines with end-anchored patterns, so these lines are *new lines
//! only* and nothing is ever appended to a line that existed before.
//!
//! # Line rule
//!
//! A line is `bridge_<section>` followed by ` name=value` fields (`value` printed as a signed 64 bit integer) in one 448 byte buffer
//! ([`LINE_MAX`]): two bytes of it are the CRLF and one the terminator, so the text stops at 445 bytes. **A field that would not fit is
//! left out whole** (never cut), and a later, shorter field may still fit. A section ends when the next field names a different
//! section, and at the end of the report.
//!
//! # Identities that hold at rest
//!
//! (`tests/test_bridge_path.c` checks them on the real code; see also [`tdongle_bridge::Stats::check_identities`].)
//! `to_host.frames = forwarded + invalid + own_mac + link_down + usb_not_ready + ring_full`;
//! `to_wifi.frames = queued + invalid + foreign_mac + link_down`;
//! `to_wifi.queued = sent + stale + sojourn_drop + link_down_queued + tx_failed + codel_drop + queue_depth`;
//! `wifi_tx.charged = done + aborted + flushed + stale + inflight`.

use core::fmt;
use tdongle_bridge::Stats;

/// `BRIDGE_LINE_MAX`: the line buffer, terminator and CRLF included.
pub const LINE_MAX: usize = 448;

/// The USB transmit ring counters the visitor prints (the fields of `tinyusb_net_tx_stats_t` it reads).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingReport {
    /// Capacity now: permanent slabs plus live elastic chunks.
    pub ring_bytes: u32,
    /// Most slabs ever in the queue at once.
    pub high_water_slabs: u32,
    /// Frames accepted into the ring.
    pub enqueued_frames: u32,
    /// Frames handed to an NTB.
    pub sent_frames: u32,
    /// No free slab and no room in the open one: backpressure, frame dropped.
    pub dropped_full: u32,
    /// Refused because USB was not ready.
    pub dropped_link_down: u32,
    /// Queued frames discarded when USB went away.
    pub flushed_link_down: u32,
    /// Elastic chunks added.
    pub grow_events: u32,
    /// Elastic chunks freed after sitting idle.
    pub shrink_events: u32,
    /// Growth refused: free heap would fall below the floor.
    pub grow_denied_heap: u32,
    /// Growth refused: largest free block below the floor.
    pub grow_denied_largest: u32,
    /// Capacity with every elastic chunk present: the cap (printed as `ring_max_bytes`).
    pub max_bytes: u32,
    /// Empty to non-empty transitions that were later handed to an NTB.
    pub cold_starts: u32,
    /// Commit of the first frame to its hand-over, summed (us; wraps at 71 minutes).
    pub cold_us_sum: u32,
    /// Largest such wait.
    pub cold_us_max: u32,
}

/// The receive-side counters of the class driver (`tinyusb_net_rx_stats_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxClassReport {
    /// OUT NTBs completed.
    pub ntbs: u32,
    /// Their bytes.
    pub ntb_bytes: u32,
    /// The largest.
    pub ntb_max_bytes: u32,
    /// Datagrams offered to the receive callback (a held one is offered again).
    pub datagrams: u32,
    /// Per offer: time since the newest OUT NTB completed, summed.
    pub dwell_us_sum: u32,
    /// Largest such time.
    pub dwell_us_max: u32,
    /// Hold episodes.
    pub holds: u32,
    /// How long the holds kept the host waiting for room, summed.
    pub hold_us_sum: u32,
    /// Longest hold.
    pub hold_us_max: u32,
}

/// The Wi-Fi transmit budget (`wifi_pins`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WifiTxReport {
    /// The budget hook is installed (`wifi_pins_installed`).
    pub installed: bool,
    /// The tx-done callback is registered: charges are released by the driver (`wifi_pins_tx_done_ok`).
    pub tx_done_cb: bool,
    /// Frames charged to the budget.
    pub charged: u32,
    /// Charges released by the driver's tx-done.
    pub done: u32,
    /// Charges released because the transmit was aborted.
    pub aborted: u32,
    /// Charges flushed (link change).
    pub flushed: u32,
    /// Charges released as stale.
    pub stale: u32,
    /// tx-done events that matched no charge.
    pub unmatched: u32,
    /// Charges outstanding now (`wifi_pins_tx_outstanding()`).
    pub inflight: u32,
    /// Most charges ever outstanding.
    pub high_water: u32,
    /// Frames refused: the driver's pool was exhausted.
    pub refused_pool: u32,
    /// Frames refused: heap too low.
    pub refused_heap: u32,
}

/// The inputs of the report: the l2 counters of [`tdongle_bridge`], the USB ring, the class driver's receive side and the Wi-Fi budget.
#[derive(Clone, Copy, Debug)]
pub struct Report<'a> {
    /// The bridge's counters.
    pub l2: &'a Stats,
    /// The USB transmit ring.
    pub ring: &'a RingReport,
    /// The class driver's OUT side.
    pub rx: &'a RxClassReport,
    /// The Wi-Fi transmit budget.
    pub wifi_tx: &'a WifiTxReport,
}

/// The sections, in the order of the visitor.
pub const SECTIONS: [&str; 8] = ["link", "to_host", "to_wifi", "ecn", "rx_class", "usb_ring", "timing", "wifi_tx"];

/// `bridge_visit`: every counter as `emit(section, name, value)`, in the exact order of the C visitor. `value` is the C `(int64_t)` cast of
/// the counter (`u32` and `bool` widen, `h2w_last_tx_error` keeps its sign).
pub fn visit(report: &Report<'_>, emit: &mut impl FnMut(&str, &str, i64)) {
    let Report { l2, ring, rx, wifi_tx } = report;
    let mut e = |section: &str, name: &str, value: i64| emit(section, name, value);
    let u = |v: u32| i64::from(v);
    e("link", "linked", i64::from(l2.linked));
    e("link", "changes", u(l2.link_changes));
    e("link", "worker_stack_free", u(l2.worker_stack_free));
    e("to_host", "frames", u(l2.w2h_frames));
    e("to_host", "forwarded", u(l2.w2h_forwarded));
    e("to_host", "invalid", u(l2.w2h_invalid));
    e("to_host", "own_mac", u(l2.w2h_own_mac));
    e("to_host", "link_down", u(l2.w2h_link_down));
    e("to_host", "usb_not_ready", u(l2.w2h_usb_not_ready));
    e("to_host", "ring_full", u(l2.w2h_ring_full));
    e("to_host", "raced", u(l2.w2h_raced));
    e("to_wifi", "frames", u(l2.h2w_frames));
    e("to_wifi", "queued", u(l2.h2w_queued));
    e("to_wifi", "invalid", u(l2.h2w_invalid));
    e("to_wifi", "foreign_mac", u(l2.h2w_foreign_mac));
    e("to_wifi", "link_down", u(l2.h2w_link_down));
    e("to_wifi", "held", u(l2.h2w_held));
    e("to_wifi", "resumes", u(l2.h2w_resumes));
    e("to_wifi", "sent", u(l2.h2w_sent));
    e("to_wifi", "stale", u(l2.h2w_stale));
    e("to_wifi", "sojourn_drop", u(l2.h2w_sojourn_drop));
    e("to_wifi", "link_down_queued", u(l2.h2w_link_down_queued));
    e("to_wifi", "tx_failed", u(l2.h2w_tx_failed));
    e("to_wifi", "tx_retries", u(l2.h2w_tx_retries));
    e("to_wifi", "last_tx_error", i64::from(l2.h2w_last_tx_error));
    e("to_wifi", "queue_depth", u(l2.h2w_queue_depth));
    e("to_wifi", "queue_high_water", u(l2.h2w_queue_high_water));
    e("to_wifi", "codel_signals", u(l2.h2w_codel_signals));
    e("to_wifi", "ce_marked", u(l2.h2w_ce_marked));
    e("to_wifi", "codel_drop", u(l2.h2w_codel_drop));
    e("to_wifi", "codel_count", u(l2.h2w_codel_count));
    e("ecn", "not_ect", u(l2.h2w_ecn_not_ect));
    e("ecn", "capable", u(l2.h2w_ecn_capable));
    e("ecn", "ce", u(l2.h2w_ecn_ce));
    e("ecn", "exempt", u(l2.h2w_ecn_exempt));
    e("ecn", "not_ip", u(l2.h2w_ecn_not_ip));
    e("ecn", "syn_setup", u(l2.h2w_syn_ecn_setup));
    e("ecn", "synack_accept", u(l2.w2h_synack_ecn));
    e("rx_class", "ntbs", u(rx.ntbs));
    e("rx_class", "ntb_bytes", u(rx.ntb_bytes));
    e("rx_class", "ntb_max_bytes", u(rx.ntb_max_bytes));
    e("rx_class", "datagrams", u(rx.datagrams));
    e("rx_class", "dwell_us_sum", u(rx.dwell_us_sum));
    e("rx_class", "dwell_us_max", u(rx.dwell_us_max));
    e("rx_class", "holds", u(rx.holds));
    e("rx_class", "hold_us_sum", u(rx.hold_us_sum));
    e("rx_class", "hold_us_max", u(rx.hold_us_max));
    e("usb_ring", "ring_bytes", u(ring.ring_bytes));
    e("usb_ring", "high_water_slabs", u(ring.high_water_slabs));
    e("usb_ring", "enqueued", u(ring.enqueued_frames));
    e("usb_ring", "sent", u(ring.sent_frames));
    e("usb_ring", "dropped_full", u(ring.dropped_full));
    e("usb_ring", "dropped_link_down", u(ring.dropped_link_down));
    e("usb_ring", "flushed_link_down", u(ring.flushed_link_down));
    e("usb_ring", "grow_events", u(ring.grow_events));
    e("usb_ring", "shrink_events", u(ring.shrink_events));
    e("usb_ring", "grow_denied_heap", u(ring.grow_denied_heap));
    e("usb_ring", "grow_denied_largest", u(ring.grow_denied_largest));
    e("usb_ring", "ring_max_bytes", u(ring.max_bytes));
    e("timing", "cold_starts", u(ring.cold_starts));
    e("timing", "cold_us_sum", u(ring.cold_us_sum));
    e("timing", "cold_us_max", u(ring.cold_us_max));
    e("timing", "pm_notes", u(l2.pm_notes));
    e("timing", "pm_note_us_sum", u(l2.pm_note_us_sum));
    e("timing", "pm_note_us_max", u(l2.pm_note_us_max));
    e("timing", "wait_us_sum", u(l2.h2w_wait_us_sum));
    e("timing", "wait_us_max", u(l2.h2w_wait_us_max));
    e("timing", "tx_us_sum", u(l2.h2w_tx_us_sum));
    e("timing", "tx_us_max", u(l2.h2w_tx_us_max));
    e("timing", "signal_us_sum", u(l2.h2w_signal_us_sum));
    e("timing", "signal_us_max", u(l2.h2w_signal_us_max));
    e("timing", "room_waits", u(l2.h2w_room_waits));
    e("timing", "room_wait_us_sum", u(l2.h2w_room_wait_us_sum));
    e("timing", "room_wait_us_max", u(l2.h2w_room_wait_us_max));
    e("wifi_tx", "installed", i64::from(wifi_tx.installed));
    e("wifi_tx", "tx_done_cb", i64::from(wifi_tx.tx_done_cb));
    e("wifi_tx", "charged", u(wifi_tx.charged));
    e("wifi_tx", "done", u(wifi_tx.done));
    e("wifi_tx", "aborted", u(wifi_tx.aborted));
    e("wifi_tx", "flushed", u(wifi_tx.flushed));
    e("wifi_tx", "stale", u(wifi_tx.stale));
    e("wifi_tx", "unmatched", u(wifi_tx.unmatched));
    e("wifi_tx", "inflight", u(wifi_tx.inflight));
    e("wifi_tx", "high_water", u(wifi_tx.high_water));
    e("wifi_tx", "refused_pool", u(wifi_tx.refused_pool));
    e("wifi_tx", "refused_heap", u(wifi_tx.refused_heap));
}

/// `bridge_line_ctx`: assembles one line per section in a [`LINE_MAX`] byte buffer and hands each finished line (CRLF included, one
/// `write_str` per line, like one `mgmt_write`) to the sink.
#[derive(Debug)]
pub struct LineWriter<'w, W: fmt::Write> {
    sink: &'w mut W,
    line: [u8; LINE_MAX],
    used: usize,
    /// Length of the section name of the line in progress (0: no line). The name sits in `line[PREFIX.len()..]`.
    section_len: usize,
}

const PREFIX: &[u8] = b"bridge_";

impl<'w, W: fmt::Write> LineWriter<'w, W> {
    /// A writer with no line in progress.
    pub const fn new(sink: &'w mut W) -> Self {
        Self { sink, line: [0; LINE_MAX], used: 0, section_len: 0 }
    }

    fn section(&self) -> Option<&[u8]> {
        (self.section_len != 0).then(|| &self.line[PREFIX.len()..PREFIX.len() + self.section_len])
    }

    /// `bridge_line_flush`: finish the line in progress (if any) with CRLF and send it.
    ///
    /// # Errors
    /// Whatever the sink returns.
    pub fn flush(&mut self) -> fmt::Result {
        if self.section_len == 0 {
            return Ok(());
        }
        // `emit` always leaves room for these two bytes.
        self.line[self.used..self.used + 2].copy_from_slice(b"\r\n");
        let end = self.used + 2;
        self.section_len = 0;
        self.used = 0;
        // The section names and fields are ASCII; anything else cannot be passed to a `fmt::Write` and is dropped from the line.
        let text = match core::str::from_utf8(&self.line[..end]) {
            Ok(text) => text,
            Err(e) => core::str::from_utf8(&self.line[..e.valid_up_to()]).unwrap_or(""),
        };
        self.sink.write_str(text)
    }

    /// `bridge_line_emit`: add ` name=value` to the line of `section`, first finishing the previous line if it belongs to another section.
    ///
    /// A section name too long to leave room for the line's CRLF is ignored (not reachable with the eight fixed sections).
    ///
    /// # Errors
    /// Whatever the sink returns when a finished line is sent.
    pub fn emit(&mut self, section: &str, name: &str, value: i64) -> fmt::Result {
        if self.section().is_some_and(|s| s != section.as_bytes()) {
            self.flush()?;
        }
        if self.section_len == 0 {
            let header = PREFIX.len() + section.len();
            if section.is_empty() || header > LINE_MAX - 3 {
                return Ok(());
            }
            self.line[..PREFIX.len()].copy_from_slice(PREFIX);
            self.line[PREFIX.len()..header].copy_from_slice(section.as_bytes());
            self.used = header;
            self.section_len = section.len();
        }
        let room = LINE_MAX - self.used - 3;
        // C: `snprintf(line + used, room + 1, " %s=%lld")`; the field is kept only when all of it fits.
        let mut field = crate::text::ByteLine::<LINE_MAX>::new();
        let _ = fmt::Write::write_fmt(&mut field, format_args!(" {name}={value}"));
        let field = field.as_bytes();
        let n = field.len();
        // `field` holds at most LINE_MAX - 1 bytes; a field longer than that cannot fit in `room` either.
        if n > 0 && n <= room {
            self.line[self.used..self.used + n].copy_from_slice(field);
            self.used += n;
        }
        Ok(())
    }
}

/// `bridge_status_lines`: the whole report, one line per section, each ending in CRLF. Not for tailnet mode (every counter would read 0).
///
/// # Errors
/// Whatever the sink returns.
pub fn write_status_lines<W: fmt::Write>(w: &mut W, report: &Report<'_>) -> fmt::Result {
    let mut lines = LineWriter::new(w);
    let mut result = Ok(());
    visit(report, &mut |section, name, value| {
        if result.is_ok() {
            result = lines.emit(section, name, value);
        }
    });
    result?;
    lines.flush()
}
