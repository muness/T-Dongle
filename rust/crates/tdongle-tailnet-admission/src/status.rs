//! The `/status` and serial-report fragments that belong to admission, the negotiation token, the heap budget and the inbound path.
//!
//! Each `write_*` function emits exactly the bytes of the C code it ports (field names, order, separators, including the trailing comma
//! of the fragments the C embeds in a larger object). The golden tests (`tests/golden.rs`) compare them with output of the real C code
//! compiled on the host (`tools/gen_golden.py`). The firmware's `/status` handler calls the fragments in the C's order:
//! `admission`, [shared runtime], `negotiation`, [wg pool], [rng] ... `heap_budget`, `wifi_pins` ...

use crate::adm::{Budget, ML_ADM_PEER_SLOTS};
use crate::heap::{ML_HB_FLOOR, ML_HB_PIN_BUFFERS, ML_HB_RESERVE};
use crate::json::{JsonWriter, Sink};
use crate::ledger::{Ledger, Owner};
use crate::limits::{CONFIG_LWIP_UDP_RECVMBOX_SIZE, ML_NET_IO_DRAIN_CAP, ML_WG_RX_QUEUE_DEPTH};
use crate::negotiation::{Phase, Status as NegStatus};
use crate::rx_stats::{RxStat, RxStats};
use crate::wg_rx::{ML_WG_RX_BATCH, ML_WG_RX_QUEUE_BYTES};

/// The inputs of the `"admission":{...},` fragment besides the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionStatus {
    /// The arithmetic, from [`crate::adm::Params::budget`].
    pub budget: Budget,
    /// `peer_slot_bytes`: the size of one WireGuard peer slot (`ml_wg_slot_bytes()`).
    pub peer_slot_bytes: u32,
}

/// `"admission":{...},` (`runtime_status.inc`).
pub fn write_admission<S: Sink>(w: &mut JsonWriter<S>, a: &AdmissionStatus) {
    let b = &a.budget;
    w.raw("\"admission\":{");
    w.num_field("required_bytes", b.required as u64);
    w.num_field("shared_runtime_bytes", b.shared_runtime as u64);
    w.num_field("member_start_bytes", b.member_start as u64);
    w.num_field("member_growth_bytes", b.member_growth as u64);
    w.num_field("member_steady_bytes", b.member_steady as u64);
    w.num_field("negotiation_reserve_bytes", b.negotiation as u64);
    w.num_field("recovery_reserve_bytes", b.recovery as u64);
    w.num_field("largest_block_required", b.largest_block as u64);
    w.num_field("peer_slots_charged", u64::from(ML_ADM_PEER_SLOTS));
    w.key("peer_slot_bytes");
    w.number(u64::from(a.peer_slot_bytes));
    w.raw("},");
}

/// `"negotiation":{...},` (`runtime_status.inc`). `holder` is the phase name, or `"none"` when the token is free.
pub fn write_negotiation<S: Sink>(w: &mut JsonWriter<S>, s: &NegStatus) {
    w.raw("\"negotiation\":{");
    w.key("holder");
    w.string(if s.holder != 0 { s.phase.name() } else { Phase::None.name() });
    w.ch(b',');
    w.num_field("held_ms", u64::from(s.held_ms));
    w.num_field("waiting", u64::from(s.waiting));
    w.num_field("grants", u64::from(s.grants));
    w.num_field("timeouts", u64::from(s.timeouts));
    w.num_field("lease_expired", u64::from(s.lease_expired));
    w.num_field("stale_dropped", u64::from(s.stale_dropped));
    w.num_field("refused_full", u64::from(s.refused_full));
    w.num_field("max_wait_ms", u64::from(s.max_wait_ms));
    w.key("max_hold_ms");
    w.number(u64::from(s.max_hold_ms));
    w.raw("},");
}

/// The refusal counters of `"heap_budget":{...},` (`gateway_main.c`, ADR 0022).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeapBudgetStatus {
    /// USB receive frames refused for the floor (`usb_rx_budget.dropped_heap`).
    pub refused_usb_rx: u32,
    /// Packets pending a handshake refused.
    pub refused_pending: u32,
    /// Relay transmit queue refusals.
    pub refused_derp_tx: u32,
    /// DISCO/STUN datagrams refused.
    pub refused_rx_ctrl: u32,
    /// Relayed frames refused.
    pub refused_derp_rx: u32,
    /// WireGuard datagram copies refused.
    pub refused_wg_copy: u32,
}

/// `"heap_budget":{...},` (`gateway_main.c`): the one elastic floor and what was refused for it.
pub fn write_heap_budget<S: Sink>(w: &mut JsonWriter<S>, h: &HeapBudgetStatus) {
    w.raw("\"heap_budget\":{");
    w.num_field("floor", ML_HB_FLOOR as u64);
    w.num_field("reserve", ML_HB_RESERVE as u64);
    w.num_field("pin_buffers", u64::from(ML_HB_PIN_BUFFERS));
    w.num_field("refused_usb_rx", u64::from(h.refused_usb_rx));
    w.num_field("refused_pending", u64::from(h.refused_pending));
    w.num_field("refused_derp_tx", u64::from(h.refused_derp_tx));
    w.num_field("refused_rx_ctrl", u64::from(h.refused_rx_ctrl));
    w.num_field("refused_derp_rx", u64::from(h.refused_derp_rx));
    w.key("refused_wg_copy");
    w.number(u64::from(h.refused_wg_copy));
    w.raw("},");
}

/// `verdict_names` of `memory_diagnostics.inc`: the admission attempt's outcome as the serial report spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdmitVerdict {
    /// `ok`.
    Ok = 0,
    /// `refused_budget`.
    RefusedBudget,
    /// `refused_largest`.
    RefusedLargest,
    /// `refused_sockets`.
    RefusedSockets,
    /// `override` (diagnostics only: admitted past the budget).
    Override,
    /// `refused_floor`.
    RefusedFloor,
    /// `start_failed`.
    StartFailed,
}

impl AdmitVerdict {
    /// The name in the report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            AdmitVerdict::Ok => "ok",
            AdmitVerdict::RefusedBudget => "refused_budget",
            AdmitVerdict::RefusedLargest => "refused_largest",
            AdmitVerdict::RefusedSockets => "refused_sockets",
            AdmitVerdict::Override => "override",
            AdmitVerdict::RefusedFloor => "refused_floor",
            AdmitVerdict::StartFailed => "start_failed",
        }
    }
}

/// `tdongle_admission_record`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionRecord {
    /// Uptime of the attempt, ms.
    pub uptime_ms: u32,
    /// The membership id.
    pub member_id: u32,
    /// Free internal heap at the decision.
    pub free_bytes: u32,
    /// Largest free block at the decision.
    pub largest_bytes: u32,
    /// The `required` it was judged against.
    pub budget_bytes: u32,
    /// Sockets open.
    pub sockets_open: u32,
    /// Socket limit.
    pub sockets_limit: u32,
    /// Active memberships.
    pub active: u32,
    /// The outcome.
    pub verdict: AdmitVerdict,
}

/// `report_admission` of `memory_diagnostics.inc`: one JSON line (`\r\n` terminated).
pub fn write_admission_report<S: Sink>(w: &mut JsonWriter<S>, guard_floor: u32, override_on: bool, slot_evictions: u32, attempts: &[AdmissionRecord]) {
    w.raw("{\"schema\":1,\"kind\":");
    w.string("admission");
    w.report_field("guard_floor", u64::from(guard_floor));
    w.raw(",\"override\":");
    w.raw(if override_on { "true" } else { "false" });
    w.report_field("slot_evictions", u64::from(slot_evictions));
    w.raw(",\"attempts\":[");
    for (i, r) in attempts.iter().enumerate() {
        if i != 0 {
            w.ch(b',');
        }
        w.raw("{\"t\":");
        w.number(u64::from(r.uptime_ms));
        w.report_field("member", u64::from(r.member_id));
        w.report_field("free", u64::from(r.free_bytes));
        w.report_field("largest", u64::from(r.largest_bytes));
        w.report_field("budget", u64::from(r.budget_bytes));
        w.report_field("sockets", u64::from(r.sockets_open));
        w.report_field("socket_limit", u64::from(r.sockets_limit));
        w.report_field("active", u64::from(r.active));
        w.raw(",\"verdict\":");
        w.string(r.verdict.name());
        w.ch(b'}');
    }
    w.ch(b']');
    w.raw("}\r\n");
}

/// The gauges of the head of `report_inbound` that this crate does not own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InboundHead {
    /// Bytes waiting in the WireGuard receive queue now.
    pub wg_rx_bytes_queued: u32,
    /// Their high-water mark.
    pub wg_rx_bytes_peak: u32,
    /// The WireGuard replay window size (`ml_wg_replay_window()`).
    pub replay_window: u32,
}

/// The first part of `report_inbound` (no closing brace: the caller appends the `lwip`, `ml`, `wg`, `route` sections), `memory_diagnostics.inc`.
pub fn write_inbound_head<S: Sink>(w: &mut JsonWriter<S>, h: &InboundHead) {
    w.raw("{\"schema\":1,\"kind\":");
    w.string("inbound");
    w.report_field("udp_recvmbox", u64::from(CONFIG_LWIP_UDP_RECVMBOX_SIZE));
    w.report_field("drain_cap", u64::from(ML_NET_IO_DRAIN_CAP));
    w.report_field("wg_rx_queue_depth", ML_WG_RX_QUEUE_DEPTH as u64);
    w.report_field("wg_rx_queue_bytes", u64::from(ML_WG_RX_QUEUE_BYTES));
    w.report_field("wg_rx_bytes_queued", u64::from(h.wg_rx_bytes_queued));
    w.report_field("wg_rx_bytes_peak", u64::from(h.wg_rx_bytes_peak));
    w.report_field("wg_rx_batch", ML_WG_RX_BATCH as u64);
    w.report_field("replay_window", u64::from(h.replay_window));
}

/// The `,"ml":{...}` section of `report_inbound`: every [`RxStat`] by name, then the burst gauge.
pub fn write_inbound_ml<S: Sink>(w: &mut JsonWriter<S>, stats: &RxStats) {
    w.raw(",\"ml\":{");
    for (i, s) in RxStat::ALL.iter().enumerate() {
        if i != 0 {
            w.ch(b',');
        }
        w.key(s.name());
        w.number(u64::from(stats.get(*s)));
    }
    w.raw(",\"drain_burst_max\":");
    w.number(u64::from(stats.drain_burst_max()));
    w.ch(b'}');
}

/// The `,"owners":{...}` section of `report_heap`, from the ledger. Owner names are [`Owner::name`].
pub fn write_owners<S: Sink>(w: &mut JsonWriter<S>, ledger: &Ledger) {
    w.raw(",\"owners\":{");
    for (i, o) in Owner::ALL.iter().enumerate() {
        let s = ledger.owner(*o);
        if i != 0 {
            w.ch(b',');
        }
        w.key(o.name());
        w.raw("{\"live\":");
        w.number(u64::from(s.live));
        w.report_field("peak", u64::from(s.peak));
        w.report_field("allocs", u64::from(s.allocs));
        w.report_field("frees", u64::from(s.frees));
        w.report_field("failed", u64::from(s.failed));
        w.report_field("denied", u64::from(s.denied));
        w.ch(b'}');
    }
    w.ch(b'}');
}
