//! The serial JSON reports of the diagnostics image (`memory_diagnostics.inc`): `memory`, `memory low`, `memory locks`, `route`, `members`, `inbound`,
//! `cpu`, `wgperf`, `wifistats`, ... Each report is one JSON line, `{"schema":1,"kind":"..."...}\r\n`, written through the same bounded [`JsonWriter`].
//!
//! Counters whose names live in another crate (router `RT_STAT_*`, the receive stats of microlink and wireguard) arrive as `(name, value)` slices; the
//! name tables of the C are here as constants ([`RT_STAT_NAMES`], [`ML_RX_NAMES`], [`WGPERF_STAGES`], [`WGPERF_COUNTERS`]) and checked against the C headers by
//! tests.

use crate::jw::JsonWriter;

/// Owners of heap bytes (`owner_names`), in `tdongle_owner` order.
pub const OWNER_NAMES: [&str; 8] = ["other", "tls", "control", "map", "peer", "wg", "packet", "context"];
/// Join phases (`phase_names`), in `tdongle_phase` order.
pub const PHASE_NAMES: [&str; 7] = ["start", "control", "noise", "register", "map", "derp", "steady"];
/// Admission verdicts (`verdict_names`).
pub const VERDICT_NAMES: [&str; 7] = ["ok", "refused_budget", "refused_largest", "refused_sockets", "override", "refused_floor", "start_failed"];
/// Data path drops (`drop_names`), in `tdongle_drop` order.
pub const DROP_NAMES: [&str; 7] = ["derp_tx_evict", "derp_tx_full", "derp_rx_full", "net_disco_full", "net_wg_full", "net_stun_full", "router_ingress"];
/// lwIP core lock sites (`sites`), in `tdongle_lock_site` order.
pub const LOCK_SITES: [&str; 5] = ["wg_other", "wg_periodic", "wg_commit", "wg_output", "wg_peer"];
/// `tdongle_lock_bucket_limit_us`.
pub const LOCK_BUCKET_LIMITS_US: [u32; 8] = [100, 250, 500, 1000, 2000, 5000, 10000, 30000];
/// `TDONGLE_LOCK_BUCKETS`.
pub const LOCK_BUCKETS: usize = 9;
/// `TDONGLE_MEMORY_MEMBERS`.
pub const MEMORY_MEMBERS: usize = 3;
/// `MEMORY_MEMBER_LIMIT`: memberships listed by `memory`.
pub const MEMORY_MEMBER_LIMIT: usize = MEMORY_MEMBERS + 1;
/// `HEAP_LOW_RECORDS`.
pub const HEAP_LOW_RECORDS: usize = 8;
/// `HEAP_LOW_PERIOD_US`.
pub const HEAP_LOW_PERIOD_US: u32 = 10_000;
/// `CPU_REPORT_TASKS`.
pub const CPU_REPORT_TASKS: usize = 32;
/// `RT_STAT_*` names in enum order (route_table.h).
pub const RT_STAT_NAMES: [&str; 30] = [
    "forwarded_out",
    "forwarded_in",
    "bad_packet",
    "alias_miss",
    "alias_unknown",
    "alias_fill",
    "flow_full",
    "no_member",
    "member_down",
    "reply_nomatch",
    "queue_full",
    "oversize_icmp",
    "oversize_drop",
    "icmp_suppressed",
    "tunnel_reject",
    "tx_fail",
    "held",
    "held_released",
    "held_dropped",
    "tunnel_malformed",
    "tunnel_nomem",
    "reply_no_member",
    "reply_not_us",
    "reply_flow_range",
    "reply_no_flow",
    "reply_generation",
    "reply_owner",
    "reply_idle",
    "usb_tx",
    "usb_tx_err",
];
/// The `route` counters of the `inbound` report, as indices into [`RT_STAT_NAMES`], in the order the C lists them.
pub const INBOUND_ROUTE_REASONS: [usize; 14] = [19, 20, 2, 21, 22, 23, 24, 25, 26, 27, 1, 28, 29, 15];
/// The `ml_rx_stats.h` counters (`ML_RX_COUNTERS`), in order.
pub const ML_RX_NAMES: [&str; 23] = [
    "udp_rx",
    "udp_rx_empty",
    "udp_unclassified",
    "udp_alloc_fail",
    "udp_recv_err",
    "udp_wg",
    "udp_disco",
    "udp_stun",
    "q_wg_full",
    "q_disco_full",
    "q_stun_full",
    "derp_rx_wg",
    "derp_q_wg_full",
    "q_wg_bytes",
    "q_wg_heap",
    "drain_calls",
    "drain_capped",
    "drain_deep",
    "wg_in",
    "wg_sender_unknown",
    "wg_no_netif",
    "wg_pbuf_fail",
    "wg_to_wireguardif",
];
/// `TDONGLE_WGPERF_STAGES`: (name, unit).
pub const WGPERF_STAGES: [(&str, &str); 29] = [
    ("q_latency", "us"),
    ("prep", "cy"),
    ("pass", "cy"),
    ("pm", "cy"),
    ("updates", "cy"),
    ("lookup", "cy"),
    ("lock_wait", "cy"),
    ("lock_hold", "cy"),
    ("send", "cy"),
    ("out_lookup", "cy"),
    ("out_seal", "cy"),
    ("out_udp", "cy"),
    ("rx_pkt", "cy"),
    ("rx_prep", "cy"),
    ("rx_begin", "cy"),
    ("rx_decrypt", "cy"),
    ("rx_complete", "cy"),
    ("rx_route", "cy"),
    ("rx_deliver", "cy"),
    ("rx_run", "pkt"),
    ("rx_qdepth", "pkt"),
    ("rt_check", "cy"),
    ("rt_lock_wait", "cy"),
    ("rt_emit", "cy"),
    ("drain_wg", "cy"),
    ("disco_rx", "cy"),
    ("periodic", "cy"),
    ("disco_tick", "cy"),
    ("batch", "pkt"),
];
/// `TDONGLE_WGPERF_COUNTERS`.
pub const WGPERF_COUNTERS: [&str; 13] = [
    "wakes",
    "passes",
    "passes_idle",
    "passes_skipped",
    "out_direct",
    "out_parked",
    "out_flushed",
    "out_discard",
    "in_pkts",
    "rx_runs",
    "rx_runs_full",
    "rx_runs_cut",
    "lookup_scans",
];
/// The route report's constants.
pub const ROUTE_QUEUE_DEPTH: u32 = 16;
/// `ROUTE_QUEUE_BYTES`.
pub const ROUTE_QUEUE_BYTES: u32 = 16 * 1024;
/// `RT_ALIASES`.
pub const RT_ALIASES: u32 = 64;
/// `RT_FLOWS`.
pub const RT_FLOWS: u32 = 64;

// ---------------------------------------------------------------------------------------------------------------------------------------------
// report_begin / report_field / report_end
// ---------------------------------------------------------------------------------------------------------------------------------------------

fn begin(w: &mut JsonWriter<'_>, kind: &str) {
    w.raw(b"{\"schema\":1,\"kind\":");
    w.string(kind.as_bytes());
}

fn end(w: &mut JsonWriter<'_>) {
    w.raw(b"}\r\n");
    w.flush();
}

fn field(w: &mut JsonWriter<'_>, key: &str, v: u64) {
    w.ch(b',');
    w.key(key);
    w.number(v);
}

fn comma_list(w: &mut JsonWriter<'_>, values: &[u32]) {
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            w.ch(b',');
        }
        w.number((*v).into());
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// memory: heap, attribution, lwip, usb
// ---------------------------------------------------------------------------------------------------------------------------------------------

/// `tdongle_owner_stats`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnerStats {
    /// `live`.
    pub live: u32,
    /// `peak`.
    pub peak: u32,
    /// `allocs`.
    pub allocs: u32,
    /// `frees`.
    pub frees: u32,
    /// `failed`.
    pub failed: u32,
    /// `denied`.
    pub denied: u32,
}

/// What `report_heap` reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Heap<'a> {
    /// `esp_timer_get_time() / 1000`.
    pub uptime_ms: u64,
    /// `GATEWAY_VERSION`.
    pub firmware: &'a [u8],
    /// `heap_caps_get_free_size`.
    pub free: u64,
    /// `heap_caps_get_minimum_free_size`.
    pub min: u64,
    /// `heap_caps_get_largest_free_block`.
    pub largest: u64,
    /// `heap_caps_get_total_size`.
    pub total: u64,
    /// `tdongle_heap_guard_floor()`.
    pub guard_floor: u64,
    /// `tdongle_heap_underflows()`.
    pub underflows: u64,
    /// `tdongle_memory_ledger_bytes()`.
    pub ledger_bytes: u64,
    /// `ML_DERP_TX_QUEUE_DEPTH`.
    pub derp_tx_depth: u64,
    /// `ML_DISCO_RX_QUEUE_DEPTH`.
    pub disco_rx_depth: u64,
    /// `ML_WG_RX_QUEUE_DEPTH`.
    pub wg_rx_depth: u64,
    /// `ML_STUN_RX_QUEUE_DEPTH`.
    pub stun_rx_depth: u64,
    /// One entry per owner ([`OWNER_NAMES`]).
    pub owners: [OwnerStats; 8],
    /// One entry per drop point ([`DROP_NAMES`]).
    pub drops: [u32; 7],
}

/// `report_heap`.
pub fn write_heap(w: &mut JsonWriter<'_>, h: &Heap<'_>) {
    begin(w, "heap");
    field(w, "uptime_ms", h.uptime_ms);
    w.ch(b',');
    w.key("firmware");
    w.string(h.firmware);
    field(w, "free", h.free);
    field(w, "min", h.min);
    field(w, "largest", h.largest);
    field(w, "total", h.total);
    field(w, "guard_floor", h.guard_floor);
    field(w, "underflows", h.underflows);
    field(w, "ledger_bytes", h.ledger_bytes);
    w.raw(b",\"queue_depth\":{\"derp_tx\":");
    w.number(h.derp_tx_depth);
    field(w, "disco_rx", h.disco_rx_depth);
    field(w, "wg_rx", h.wg_rx_depth);
    field(w, "stun_rx", h.stun_rx_depth);
    w.ch(b'}');
    w.raw(b",\"owners\":{");
    for (i, name) in OWNER_NAMES.iter().enumerate() {
        let s = &h.owners[i];
        if i > 0 {
            w.ch(b',');
        }
        w.key(name);
        w.raw(b"{\"live\":");
        w.number(s.live.into());
        field(w, "peak", s.peak.into());
        field(w, "allocs", s.allocs.into());
        field(w, "frees", s.frees.into());
        field(w, "failed", s.failed.into());
        field(w, "denied", s.denied.into());
        w.ch(b'}');
    }
    w.ch(b'}');
    w.raw(b",\"drops\":{");
    for (i, name) in DROP_NAMES.iter().enumerate() {
        if i > 0 {
            w.ch(b',');
        }
        w.key(name);
        w.number(h.drops[i].into());
    }
    w.ch(b'}');
    end(w);
}

/// One membership's line of `report_attribution` (`memory_member`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttributionMember {
    /// `id`.
    pub id: u32,
    /// `tasks` (1 when the coord task exists and the stop is complete).
    pub tasks: u32,
    /// `stacks`.
    pub stacks: u32,
    /// `tcbs`.
    pub tcbs: u32,
    /// `h2_acc` (`c->h2_acc_len`).
    pub h2_acc: u32,
    /// `stack_free[4]` (net_io, derp, coord, wg_mgr; `u32::MAX` unknown).
    pub stack_free: [u32; 4],
    /// `lp_acc != NULL`.
    pub lp_acc: bool,
}

/// What `report_attribution` reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attribution<'a> {
    /// `memory_snapshot` failed (the lock was busy): the report is `"error":"memberships busy"`.
    pub busy: bool,
    /// The memberships with clients (at most [`MEMORY_MEMBER_LIMIT`]).
    pub members: &'a [AttributionMember],
    /// Memberships beyond the limit.
    pub omitted: u32,
    /// `tdongle_heap_owner(i).live` summed.
    pub tagged: u64,
    /// `ml_rt_status`: the shared tasks are running.
    pub shared_running: bool,
    /// `ml_rt_status.stack_bytes[]`.
    pub shared_stack_bytes: [u32; 3],
    /// `sizeof(StaticTask_t)`.
    pub task_tcb_bytes: u32,
    /// `member_queue_bytes()`.
    pub member_queue_bytes: u32,
    /// `heap_caps_get_total_size(MALLOC_CAP_INTERNAL)` (a 32-bit `size_t`).
    pub heap_total: u32,
    /// `heap_caps_get_free_size(MALLOC_CAP_INTERNAL)`.
    pub heap_free: u32,
    /// `ML_JSON_BUFFER_SIZE`.
    pub lp_acc_capacity: u32,
    /// `ML_H2_BUFFER_SIZE`.
    pub h2_window_advertised: u32,
    /// `ML_GATEWAY_PLAIN_BYTES`.
    pub gateway_plain_static: u32,
    /// `ML_GATEWAY_JSON_BYTES`.
    pub gateway_json_static: u32,
}

/// `report_attribution`.
pub fn write_attribution(w: &mut JsonWriter<'_>, a: &Attribution<'_>) {
    if a.busy {
        begin(w, "attribution");
        w.raw(b",\"error\":\"memberships busy\"");
        end(w);
        return;
    }
    let (mut shared_tasks, mut shared_stacks, mut shared_tcbs) = (0u32, 0u32, 0u32);
    if a.shared_running {
        for t in 0..3 {
            shared_tasks += 1;
            shared_stacks = shared_stacks.wrapping_add(a.shared_stack_bytes[t]);
            shared_tcbs = shared_tcbs.wrapping_add(a.task_tcb_bytes);
        }
    }
    let mut synthetic = u64::from(shared_stacks) + u64::from(shared_tcbs);
    let mut lp_acc = false;
    let mut h2_acc = 0u32;
    for m in a.members.iter().take(MEMORY_MEMBER_LIMIT) {
        synthetic += u64::from(m.stacks) + u64::from(m.tcbs) + u64::from(a.member_queue_bytes);
        lp_acc |= m.lp_acc;
        h2_acc = h2_acc.max(m.h2_acc);
    }
    // `uint64_t allocated = size_t - size_t`: the subtraction is 32 bits wide on the target.
    let allocated = u64::from(a.heap_total.wrapping_sub(a.heap_free));
    begin(w, "attribution");
    field(w, "allocated", allocated);
    field(w, "tagged", a.tagged);
    field(w, "synthetic", synthetic);
    let accounted = a.tagged + synthetic;
    field(w, "unattributed", allocated.saturating_sub(accounted));
    field(w, "overattributed", accounted.saturating_sub(allocated));
    field(w, "members_omitted", a.omitted.into());
    w.raw(b",\"shared_runtime\":{\"tasks\":");
    w.number(shared_tasks.into());
    field(w, "stacks", shared_stacks.into());
    field(w, "tcbs", shared_tcbs.into());
    w.ch(b'}');
    w.raw(b",\"members\":[");
    for (i, v) in a.members.iter().take(MEMORY_MEMBER_LIMIT).enumerate() {
        if i > 0 {
            w.ch(b',');
        }
        w.raw(b"{\"id\":");
        w.number(v.id.into());
        field(w, "tasks", v.tasks.into());
        field(w, "stacks", v.stacks.into());
        field(w, "tcbs", v.tcbs.into());
        field(w, "queues", a.member_queue_bytes.into());
        w.raw(b",\"stack_free\":[");
        for (t, f) in v.stack_free.iter().enumerate() {
            if t > 0 {
                w.ch(b',');
            }
            if *f == u32::MAX {
                w.raw(b"null");
            } else {
                w.number((*f).into());
            }
        }
        w.raw(b"]}");
    }
    w.raw(b"],\"n2\":{\"lp_acc_capacity\":");
    w.number(a.lp_acc_capacity.into());
    w.raw(b",\"lp_acc_allocated\":");
    w.boolean(lp_acc);
    field(w, "h2_window_advertised", a.h2_window_advertised.into());
    field(w, "h2_acc_live_max", h2_acc.into());
    field(w, "gateway_plain_static", a.gateway_plain_static.into());
    field(w, "gateway_json_static", a.gateway_json_static.into());
    w.ch(b'}');
    end(w);
}

/// The lwIP and Wi-Fi build constants `report_lwip` prints (all compile-time in C).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lwip {
    /// `TCP_WND`.
    pub tcp_wnd: u32,
    /// `TCP_SND_BUF`.
    pub tcp_snd_buf: u32,
    /// `TCP_MSS`.
    pub tcp_mss: u32,
    /// `TCP_SND_QUEUELEN`.
    pub tcp_snd_queuelen: u32,
    /// `LWIP_WND_SCALE`.
    pub wnd_scale: u32,
    /// `PBUF_POOL_SIZE`.
    pub pbuf_pool_size: u32,
    /// `PBUF_POOL_BUFSIZE`.
    pub pbuf_pool_bufsize: u32,
    /// `MEMP_NUM_TCP_PCB`.
    pub memp_tcp_pcb: u32,
    /// `MEMP_NUM_TCP_SEG`.
    pub memp_tcp_seg: u32,
    /// `CONFIG_LWIP_MAX_SOCKETS`.
    pub max_sockets: u32,
    /// `CONFIG_LWIP_TCP_RECVMBOX_SIZE`.
    pub tcp_recvmbox: u32,
    /// `CONFIG_LWIP_UDP_RECVMBOX_SIZE`.
    pub udp_recvmbox: u32,
    /// `CONFIG_LWIP_TCPIP_RECVMBOX_SIZE`.
    pub tcpip_recvmbox: u32,
    /// `CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM`.
    pub wifi_static_rx: u32,
    /// `CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM`.
    pub wifi_dynamic_rx: u32,
    /// `CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM`.
    pub wifi_dynamic_tx: u32,
}

/// `report_lwip`.
pub fn write_lwip(w: &mut JsonWriter<'_>, l: &Lwip) {
    begin(w, "lwip");
    field(w, "tcp_wnd", l.tcp_wnd.into());
    field(w, "tcp_snd_buf", l.tcp_snd_buf.into());
    field(w, "tcp_mss", l.tcp_mss.into());
    field(w, "tcp_snd_queuelen", l.tcp_snd_queuelen.into());
    field(w, "wnd_scale", l.wnd_scale.into());
    field(w, "pbuf_pool_size", l.pbuf_pool_size.into());
    field(w, "pbuf_pool_bufsize", l.pbuf_pool_bufsize.into());
    field(w, "memp_tcp_pcb", l.memp_tcp_pcb.into());
    field(w, "memp_tcp_seg", l.memp_tcp_seg.into());
    field(w, "max_sockets", l.max_sockets.into());
    field(w, "tcp_recvmbox", l.tcp_recvmbox.into());
    field(w, "udp_recvmbox", l.udp_recvmbox.into());
    field(w, "tcpip_recvmbox", l.tcpip_recvmbox.into());
    field(w, "wifi_static_rx", l.wifi_static_rx.into());
    field(w, "wifi_dynamic_rx", l.wifi_dynamic_rx.into());
    field(w, "wifi_dynamic_tx", l.wifi_dynamic_tx.into());
    end(w);
}

/// `tinyusb_net_tx_stats_t` (the fields `report_usb` prints).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsbTx {
    /// `ring_bytes`.
    pub ring_bytes: u32,
    /// `base_bytes`.
    pub base_bytes: u32,
    /// `max_bytes`.
    pub max_bytes: u32,
    /// `elastic_held_bytes`.
    pub elastic_held_bytes: u32,
    /// `chunks`.
    pub chunks: u32,
    /// `grow_events`.
    pub grow_events: u32,
    /// `shrink_events`.
    pub shrink_events: u32,
    /// `reclaim_events`.
    pub reclaim_events: u32,
    /// `reclaimed_chunks`.
    pub reclaimed_chunks: u32,
    /// `grow_denied_gate`.
    pub grow_denied_gate: u32,
    /// `grow_denied_heap`.
    pub grow_denied_heap: u32,
    /// `grow_denied_largest`.
    pub grow_denied_largest: u32,
    /// `grow_denied_nomem`.
    pub grow_denied_nomem: u32,
    /// `grow_raced`.
    pub grow_raced: u32,
    /// `high_water_bytes`.
    pub high_water_bytes: u32,
    /// `high_water_slabs`.
    pub high_water_slabs: u32,
    /// `pm_acquired`.
    pub pm_acquired: u32,
    /// `pm_released`.
    pub pm_released: u32,
    /// `pm_held`.
    pub pm_held: u32,
    /// `enqueued_frames`.
    pub enqueued_frames: u32,
    /// `enqueued_bytes`.
    pub enqueued_bytes: u32,
    /// `sent_frames`.
    pub sent_frames: u32,
    /// `sent_bytes`.
    pub sent_bytes: u32,
    /// `dropped_full`.
    pub dropped_full: u32,
    /// `dropped_link_down`.
    pub dropped_link_down: u32,
    /// `dropped_invalid`.
    pub dropped_invalid: u32,
    /// `flushed_link_down`.
    pub flushed_link_down: u32,
    /// `ntb_blocked`.
    pub ntb_blocked: u32,
    /// `xfer_events`.
    pub xfer_events: u32,
    /// `worker_stack_free`.
    pub worker_stack_free: u32,
    /// `ntb_xfers`.
    pub ntb_xfers: u32,
    /// `ntb_zlp`.
    pub ntb_zlp: u32,
    /// `ntb_bytes`.
    pub ntb_bytes: u32,
    /// `ntb_max_bytes`.
    pub ntb_max_bytes: u32,
    /// `drains_sent[5]`.
    pub drains_sent: [u32; 5],
    /// `gap_hist[5]`.
    pub gap_hist: [u32; 5],
    /// `gap_count`.
    pub gap_count: u32,
    /// `gap_us_sum`.
    pub gap_us_sum: u32,
    /// `gap_us_max`.
    pub gap_us_max: u32,
    /// `cold_starts`.
    pub cold_starts: u32,
    /// `cold_us_sum`.
    pub cold_us_sum: u32,
    /// `cold_us_max`.
    pub cold_us_max: u32,
    /// `worker_demotions`.
    pub worker_demotions: u32,
}

/// The USB receive budget and the build constants beside the transmit stats.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsbRx {
    /// `CONFIG_TINYUSB_NCM_IN_NTB_BUFFS_COUNT`.
    pub tx_ntb_count: u32,
    /// `GATEWAY_USB_RX_INFLIGHT_MAX`.
    pub inflight_max: u32,
    /// `usb_rx_budget.inflight`.
    pub inflight: u32,
    /// `usb_rx_budget.high_water`.
    pub high_water: u32,
    /// `dropped_busy`.
    pub dropped_busy: u32,
    /// `dropped_nomem`.
    pub dropped_nomem: u32,
    /// `dropped_heap`.
    pub dropped_heap: u32,
    /// `dropped_invalid`.
    pub dropped_invalid: u32,
}

/// `report_usb`.
pub fn write_usb(w: &mut JsonWriter<'_>, tx: &UsbTx, rx: &UsbRx) {
    begin(w, "usb");
    field(w, "tx_ring_bytes", tx.ring_bytes.into());
    field(w, "tx_ring_base_bytes", tx.base_bytes.into());
    field(w, "tx_ring_max_bytes", tx.max_bytes.into());
    field(w, "tx_elastic_held_bytes", tx.elastic_held_bytes.into());
    field(w, "tx_elastic_chunks", tx.chunks.into());
    field(w, "tx_grow_events", tx.grow_events.into());
    field(w, "tx_shrink_events", tx.shrink_events.into());
    field(w, "tx_reclaim_events", tx.reclaim_events.into());
    field(w, "tx_reclaimed_chunks", tx.reclaimed_chunks.into());
    field(w, "tx_grow_denied_gate", tx.grow_denied_gate.into());
    field(w, "tx_grow_denied_heap", tx.grow_denied_heap.into());
    field(w, "tx_grow_denied_largest", tx.grow_denied_largest.into());
    field(w, "tx_grow_denied_nomem", tx.grow_denied_nomem.into());
    field(w, "tx_grow_raced", tx.grow_raced.into());
    field(w, "tx_high_water", tx.high_water_bytes.into());
    field(w, "tx_high_water_slabs", tx.high_water_slabs.into());
    field(w, "tx_pm_acquired", tx.pm_acquired.into());
    field(w, "tx_pm_released", tx.pm_released.into());
    field(w, "tx_pm_held", tx.pm_held.into());
    field(w, "tx_enqueued", tx.enqueued_frames.into());
    field(w, "tx_enqueued_bytes", tx.enqueued_bytes.into());
    field(w, "tx_sent", tx.sent_frames.into());
    field(w, "tx_sent_bytes", tx.sent_bytes.into());
    field(w, "tx_dropped_full", tx.dropped_full.into());
    field(w, "tx_dropped_link_down", tx.dropped_link_down.into());
    field(w, "tx_dropped_invalid", tx.dropped_invalid.into());
    field(w, "tx_flushed_link_down", tx.flushed_link_down.into());
    field(w, "tx_ntb_blocked", tx.ntb_blocked.into());
    field(w, "tx_xfer_events", tx.xfer_events.into());
    field(w, "tx_worker_stack_free", tx.worker_stack_free.into());
    field(w, "ntb_xfers", tx.ntb_xfers.into());
    field(w, "ntb_zlp", tx.ntb_zlp.into());
    field(w, "ntb_bytes", tx.ntb_bytes.into());
    field(w, "ntb_max_bytes", tx.ntb_max_bytes.into());
    w.raw(b",\"drains_sent\":[");
    comma_list(w, &tx.drains_sent);
    w.raw(b"],\"gap_hist_ms\":[");
    comma_list(w, &tx.gap_hist);
    w.raw(b"]");
    field(w, "gap_count", tx.gap_count.into());
    field(w, "gap_us_sum", tx.gap_us_sum.into());
    field(w, "gap_us_max", tx.gap_us_max.into());
    field(w, "cold_starts", tx.cold_starts.into());
    field(w, "cold_us_sum", tx.cold_us_sum.into());
    field(w, "cold_us_max", tx.cold_us_max.into());
    field(w, "tx_worker_demotions", tx.worker_demotions.into());
    field(w, "tx_ntb_count", rx.tx_ntb_count.into());
    field(w, "rx_inflight_max", rx.inflight_max.into());
    field(w, "rx_inflight", rx.inflight.into());
    field(w, "rx_high_water", rx.high_water.into());
    field(w, "rx_dropped_busy", rx.dropped_busy.into());
    field(w, "rx_dropped_nomem", rx.dropped_nomem.into());
    field(w, "rx_dropped_heap", rx.dropped_heap.into());
    field(w, "rx_dropped_invalid", rx.dropped_invalid.into());
    end(w);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// memory low: the heap low-water ring
// ---------------------------------------------------------------------------------------------------------------------------------------------

/// `heap_low_rec_t`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeapLowRecord {
    /// `uptime_ms`.
    pub uptime_ms: u32,
    /// `min_free`.
    pub min_free: u32,
    /// `free_now`.
    pub free_now: u32,
    /// `free_hi`.
    pub free_hi: u32,
    /// `largest`.
    pub largest: u32,
    /// `tx_ring_bytes`.
    pub tx_ring_bytes: u32,
    /// `tx_elastic_bytes`.
    pub tx_elastic_bytes: u32,
    /// `wgq_bytes`.
    pub wgq_bytes: u32,
    /// `rx_inflight`.
    pub rx_inflight: u32,
    /// `packet_live`.
    pub packet_live: u32,
    /// `wifi_rx_pins`.
    pub wifi_rx_pins: u32,
    /// `wifi_tx_inflight`.
    pub wifi_tx_inflight: u32,
}

/// The sampler's state (`heap_low_rec[]`, `heap_low_count`, `heap_low_last_min`, `heap_low_free_hi`) and its recording rule (`heap_low_note`).
#[derive(Clone, Copy, Debug)]
pub struct HeapLow {
    rec: [HeapLowRecord; HEAP_LOW_RECORDS],
    count: u32,
    last_min: u32,
    free_hi: u32,
}

impl Default for HeapLow {
    fn default() -> Self {
        Self::new()
    }
}

impl HeapLow {
    /// Bytes of state (the ADR's per-feature cost).
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// Nothing seen yet.
    pub const fn new() -> Self {
        HeapLow {
            rec: [HeapLowRecord {
                uptime_ms: 0,
                min_free: 0,
                free_now: 0,
                free_hi: 0,
                largest: 0,
                tx_ring_bytes: 0,
                tx_elastic_bytes: 0,
                wgq_bytes: 0,
                rx_inflight: 0,
                packet_live: 0,
                wifi_rx_pins: 0,
                wifi_tx_inflight: 0,
            }; HEAP_LOW_RECORDS],
            count: 0,
            last_min: u32::MAX,
            free_hi: 0,
        }
    }
    /// `heap_low_note`: take a snapshot; true when it was recorded (a new heap-wide minimum below `floor`). Slot 0 keeps the first record, the rest wrap.
    pub fn note(&mut self, input: &HeapLowRecord, floor: u32) -> bool {
        let mut recorded = false;
        if input.free_now > self.free_hi {
            self.free_hi = input.free_now;
        }
        if input.min_free < self.last_min {
            self.last_min = input.min_free;
            if input.min_free < floor {
                let mut r = *input;
                r.free_hi = self.free_hi;
                let n = self.count as usize;
                let slot = if n < HEAP_LOW_RECORDS { n } else { 1 + (n - 1) % (HEAP_LOW_RECORDS - 1) };
                self.rec[slot] = r;
                self.count += 1;
                recorded = true;
            }
        }
        recorded
    }
    /// `heap_low_tick`'s cheap test: whether a tick that read `min_now` may skip the expensive reads (`min_now >= last_min || min_now >= floor`).
    pub fn quiet(&self, min_now: u32, floor: u32) -> bool {
        min_now >= self.last_min || min_now >= floor
    }
    /// Records ever written.
    pub fn events(&self) -> u32 {
        self.count
    }
    /// `report_heap_low`.
    pub fn write_report(&self, w: &mut JsonWriter<'_>, floor: u32, reserve: u32) {
        let n = (self.count as usize).min(HEAP_LOW_RECORDS);
        begin(w, "heap_low");
        field(w, "floor", floor.into());
        field(w, "reserve", reserve.into());
        field(w, "period_ms", (HEAP_LOW_PERIOD_US / 1000).into());
        field(w, "free_hi", self.free_hi.into());
        field(w, "events", self.count.into());
        w.raw(b",\"records\":[");
        for (i, r) in self.rec.iter().take(n).enumerate() {
            if i > 0 {
                w.ch(b',');
            }
            w.raw(b"{\"uptime_ms\":");
            w.number(r.uptime_ms.into());
            field(w, "min", r.min_free.into());
            field(w, "free", r.free_now.into());
            field(w, "largest", r.largest.into());
            field(w, "tx_ring", r.tx_ring_bytes.into());
            field(w, "tx_elastic", r.tx_elastic_bytes.into());
            field(w, "wgq", r.wgq_bytes.into());
            field(w, "rx_inflight", r.rx_inflight.into());
            field(w, "packet_live", r.packet_live.into());
            field(w, "wifi_rx_pins", r.wifi_rx_pins.into());
            field(w, "wifi_tx_inflight", r.wifi_tx_inflight.into());
            w.ch(b'}');
        }
        w.ch(b']');
        end(w);
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// memory locks, route, inbound, members (phases, admission)
// ---------------------------------------------------------------------------------------------------------------------------------------------

/// `tdongle_lock_stats`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockStats {
    /// `count`.
    pub count: u32,
    /// `max_us`.
    pub max_us: u32,
    /// `over_1ms`.
    pub over_1ms: u32,
    /// `bucket[9]`.
    pub bucket: [u32; LOCK_BUCKETS],
    /// `total_us` (printed as its low 32 bits, like the C's `(uint32_t)s.total_us`).
    pub total_us: u64,
}

/// `report_locks`.
pub fn write_locks(w: &mut JsonWriter<'_>, sites: &[LockStats; 5]) {
    begin(w, "locks");
    w.raw(b",\"bucket_limits_us\":[");
    comma_list(w, &LOCK_BUCKET_LIMITS_US);
    w.raw(b"],\"sites\":{");
    for (i, name) in LOCK_SITES.iter().enumerate() {
        let s = &sites[i];
        if i > 0 {
            w.ch(b',');
        }
        w.key(name);
        w.raw(b"{\"count\":");
        w.number(s.count.into());
        field(w, "max_us", s.max_us.into());
        field(w, "over_1ms", s.over_1ms.into());
        field(w, "total_us", u64::from(s.total_us as u32));
        w.raw(b",\"buckets\":[");
        comma_list(w, &s.bucket);
        w.raw(b"]}");
    }
    w.ch(b'}');
    end(w);
}

/// `report_router` (`route`): the 30 router counters in [`RT_STAT_NAMES`] order, then the bounds they are read against.
pub fn write_route(w: &mut JsonWriter<'_>, stats: &[u32; 30]) {
    begin(w, "route");
    for (name, v) in RT_STAT_NAMES.iter().zip(stats) {
        field(w, name, (*v).into());
    }
    field(w, "queue_depth", ROUTE_QUEUE_DEPTH.into());
    field(w, "queue_bytes", ROUTE_QUEUE_BYTES.into());
    field(w, "alias_cache", RT_ALIASES.into());
    field(w, "flow_slots", RT_FLOWS.into());
    end(w);
}

/// One phase capture (`tdongle_phase_record`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PhaseRecord {
    /// `valid`.
    pub valid: bool,
    /// `uptime_ms`.
    pub uptime_ms: u32,
    /// `free_bytes`.
    pub free_bytes: u32,
    /// `minimum_bytes`.
    pub minimum_bytes: u32,
    /// `largest_bytes`.
    pub largest_bytes: u32,
    /// `exact`.
    pub exact: bool,
    /// `owner_peak[8]`.
    pub owner_peak: [u32; 8],
}

/// `tdongle_member_phases`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberPhases {
    /// `member_id`.
    pub member_id: u32,
    /// `attempt`.
    pub attempt: u32,
    /// `phase[7]`.
    pub phase: [PhaseRecord; 7],
}

/// `report_phases`: one line per member slot that has a capture (`slots` is the used ones, [`MEMORY_MEMBERS`] at most).
pub fn write_phases(w: &mut JsonWriter<'_>, slots: &[MemberPhases]) {
    for m in slots.iter().take(MEMORY_MEMBERS) {
        begin(w, "phases");
        field(w, "member", m.member_id.into());
        field(w, "attempt", m.attempt.into());
        w.raw(b",\"owner_order\":[");
        for (i, n) in OWNER_NAMES.iter().enumerate() {
            if i > 0 {
                w.ch(b',');
            }
            w.string(n.as_bytes());
        }
        w.raw(b"],\"phases\":{");
        let mut first = true;
        for (p, r) in m.phase.iter().enumerate() {
            if !r.valid {
                continue;
            }
            if !first {
                w.ch(b',');
            }
            first = false;
            w.key(PHASE_NAMES[p]);
            w.raw(b"{\"t\":");
            w.number(r.uptime_ms.into());
            field(w, "free", r.free_bytes.into());
            field(w, "min", r.minimum_bytes.into());
            field(w, "largest", r.largest_bytes.into());
            field(w, "exact", u64::from(r.exact));
            w.ch(b',');
            w.key("peak");
            w.ch(b'[');
            comma_list(w, &r.owner_peak);
            w.ch(b']');
            w.ch(b'}');
        }
        w.ch(b'}');
        end(w);
    }
}

/// `tdongle_admission_record`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AdmissionRecord {
    /// `uptime_ms`.
    pub uptime_ms: u32,
    /// `member_id`.
    pub member_id: u32,
    /// `free_bytes`.
    pub free_bytes: u32,
    /// `largest_bytes`.
    pub largest_bytes: u32,
    /// `budget_bytes`.
    pub budget_bytes: u32,
    /// `sockets_open`.
    pub sockets_open: u32,
    /// `sockets_limit`.
    pub sockets_limit: u32,
    /// `active`.
    pub active: u32,
    /// `verdict` (index into [`VERDICT_NAMES`]; beyond it prints `unknown`).
    pub verdict: u32,
}

/// `report_admission`.
pub fn write_admission(w: &mut JsonWriter<'_>, guard_floor: u32, override_build: bool, slot_evictions: u32, attempts: &[AdmissionRecord]) {
    begin(w, "admission");
    field(w, "guard_floor", guard_floor.into());
    w.raw(b",\"override\":");
    w.raw(if override_build { b"true" } else { b"false" });
    field(w, "slot_evictions", slot_evictions.into());
    w.raw(b",\"attempts\":[");
    for (i, r) in attempts.iter().enumerate() {
        if i > 0 {
            w.ch(b',');
        }
        w.raw(b"{\"t\":");
        w.number(r.uptime_ms.into());
        field(w, "member", r.member_id.into());
        field(w, "free", r.free_bytes.into());
        field(w, "largest", r.largest_bytes.into());
        field(w, "budget", r.budget_bytes.into());
        field(w, "sockets", r.sockets_open.into());
        field(w, "socket_limit", r.sockets_limit.into());
        field(w, "active", r.active.into());
        w.raw(b",\"verdict\":");
        w.string(VERDICT_NAMES.get(r.verdict as usize).copied().unwrap_or("unknown").as_bytes());
        w.ch(b'}');
    }
    w.ch(b']');
    end(w);
}

/// What `report_inbound` reads. Counter names for the wireguard receive stats come from the wireguard component (`ml_wg_rx_stat_name`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Inbound<'a> {
    /// `CONFIG_LWIP_UDP_RECVMBOX_SIZE`.
    pub udp_recvmbox: u32,
    /// `ML_NET_IO_DRAIN_CAP`.
    pub drain_cap: u32,
    /// `ML_WG_RX_QUEUE_DEPTH`.
    pub wg_rx_queue_depth: u32,
    /// `ML_WG_RX_QUEUE_BYTES`.
    pub wg_rx_queue_bytes: u32,
    /// `ml_wgrx_budget.bytes`.
    pub wg_rx_bytes_queued: u32,
    /// `ml_wgrx_budget.peak`.
    pub wg_rx_bytes_peak: u32,
    /// `ml_wg_rx_batch_size()`.
    pub wg_rx_batch: u32,
    /// `ml_wg_replay_window()`.
    pub replay_window: u32,
    /// `Some((STAT_COUNTER bits, udp.recv, udp.drop, udp.memerr, udp.err))` when `LWIP_STATS && UDP_STATS`.
    pub lwip: Option<(u32, u32, u32, u32, u32)>,
    /// `ml_rx_stat_get(i)` for each [`ML_RX_NAMES`].
    pub ml: [u32; 23],
    /// `ml_rx_stats.drain_burst_max`.
    pub drain_burst_max: u32,
    /// `(ml_wg_rx_stat_name(i), ml_wg_rx_stat(i))`.
    pub wg: &'a [(&'a str, u32)],
    /// `gateway_route_stat(reason)` for each of [`INBOUND_ROUTE_REASONS`].
    pub route: [u32; 14],
}

/// `report_inbound`.
pub fn write_inbound(w: &mut JsonWriter<'_>, i: &Inbound<'_>) {
    begin(w, "inbound");
    field(w, "udp_recvmbox", i.udp_recvmbox.into());
    field(w, "drain_cap", i.drain_cap.into());
    field(w, "wg_rx_queue_depth", i.wg_rx_queue_depth.into());
    field(w, "wg_rx_queue_bytes", i.wg_rx_queue_bytes.into());
    field(w, "wg_rx_bytes_queued", i.wg_rx_bytes_queued.into());
    field(w, "wg_rx_bytes_peak", i.wg_rx_bytes_peak.into());
    field(w, "wg_rx_batch", i.wg_rx_batch.into());
    field(w, "replay_window", i.replay_window.into());
    if let Some((bits, recv, drop, memerr, err)) = i.lwip {
        field(w, "counter_bits", bits.into());
        w.raw(b",\"lwip\":{\"udp_recv\":");
        w.number(recv.into());
        field(w, "udp_drop", drop.into());
        field(w, "udp_memerr", memerr.into());
        field(w, "udp_err", err.into());
        w.ch(b'}');
    }
    w.raw(b",\"ml\":{");
    for (n, name) in ML_RX_NAMES.iter().enumerate() {
        if n > 0 {
            w.ch(b',');
        }
        w.key(name);
        w.number(i.ml[n].into());
    }
    w.raw(b",\"drain_burst_max\":");
    w.number(i.drain_burst_max.into());
    w.raw(b"},\"wg\":{");
    for (n, (name, v)) in i.wg.iter().enumerate() {
        if n > 0 {
            w.ch(b',');
        }
        w.key(name);
        w.number((*v).into());
    }
    w.raw(b"},\"route\":{");
    for (n, reason) in INBOUND_ROUTE_REASONS.iter().enumerate() {
        if n > 0 {
            w.ch(b',');
        }
        w.key(RT_STAT_NAMES[*reason]);
        w.number(i.route[n].into());
    }
    w.ch(b'}');
    end(w);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// cpu, wgperf, bench, logbench, guard, wifi
// ---------------------------------------------------------------------------------------------------------------------------------------------

/// One FreeRTOS task of the `cpu` report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuTask<'a> {
    /// `pcTaskName`.
    pub name: &'a [u8],
    /// `ulRunTimeCounter`.
    pub runtime: u32,
    /// `uxCurrentPriority`.
    pub priority: u32,
    /// `xTaskGetCoreID`: 0..cores, or anything else for "not pinned".
    pub core: i32,
    /// `usStackHighWaterMark`.
    pub stack_free: u32,
}

/// The text `report_cpu` sends when it cannot allocate its task table.
pub const CPU_NO_MEMORY: &str = "ERR no memory for the task table\r\n";

/// `report_cpu` (`tasks_listed` is `tasks.len()`; the C lists none when more than [`CPU_REPORT_TASKS`] exist).
pub fn write_cpu(w: &mut JsonWriter<'_>, uptime_ms: u64, cpu_mhz: u32, total: u32, cores: u32, existing: u32, tasks: &[CpuTask<'_>]) {
    let listed: &[CpuTask<'_>] = if existing as usize <= CPU_REPORT_TASKS { tasks } else { &[] };
    begin(w, "cpu");
    field(w, "uptime_ms", uptime_ms);
    field(w, "cpu_mhz", cpu_mhz.into());
    field(w, "total", total.into());
    field(w, "cores", cores.into());
    field(w, "tasks_listed", listed.len() as u64);
    field(w, "tasks_existing", existing.into());
    w.raw(b",\"tasks\":[");
    for (i, t) in listed.iter().enumerate() {
        if i > 0 {
            w.ch(b',');
        }
        w.raw(b"{\"name\":");
        w.string(t.name);
        field(w, "runtime", t.runtime.into());
        field(w, "priority", t.priority.into());
        w.ch(b',');
        w.key("core");
        if t.core >= 0 && (t.core as u32) < cores {
            w.number(t.core as u64);
        } else {
            w.raw(b"-1");
        }
        field(w, "stack_free", t.stack_free.into());
        w.ch(b'}');
    }
    w.ch(b']');
    end(w);
}

/// `tdongle_wgperf_sample`: [count, total, max].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WgPerfSample {
    /// `count`.
    pub count: u32,
    /// `total`.
    pub total: u64,
    /// `max`.
    pub max: u32,
}

/// `report_wgperf`.
pub fn write_wgperf(w: &mut JsonWriter<'_>, cpu_mhz: u32, elapsed_ms: u32, stages: &[WgPerfSample; 29], counters: &[u32; 13]) {
    begin(w, "wgperf");
    field(w, "cpu_mhz", cpu_mhz.into());
    field(w, "elapsed_ms", elapsed_ms.into());
    w.raw(b",\"stages\":{");
    for (i, (name, _)) in WGPERF_STAGES.iter().enumerate() {
        let s = &stages[i];
        if i > 0 {
            w.ch(b',');
        }
        w.key(name);
        w.ch(b'[');
        w.number(s.count.into());
        w.ch(b',');
        w.number(s.total);
        w.ch(b',');
        w.number(s.max.into());
        w.ch(b']');
    }
    w.raw(b"},\"units\":[");
    for (i, (_, unit)) in WGPERF_STAGES.iter().enumerate() {
        if i > 0 {
            w.ch(b',');
        }
        w.string(unit.as_bytes());
    }
    w.raw(b"],\"counters\":{");
    for (i, name) in WGPERF_COUNTERS.iter().enumerate() {
        if i > 0 {
            w.ch(b',');
        }
        w.key(name);
        w.number(counters[i].into());
    }
    w.ch(b'}');
    end(w);
}

/// `wgperf reset`.
pub fn write_wgperf_reset(w: &mut JsonWriter<'_>) {
    begin(w, "wgperf_reset");
    end(w);
}

/// `report_logbench`.
pub fn write_logbench(w: &mut JsonWriter<'_>, ok: bool, cycles_per_line: u32) {
    begin(w, "logbench");
    field(w, "rounds", 200);
    field(w, "ok", u64::from(ok));
    field(w, "cycles_per_line", cycles_per_line.into());
    end(w);
}

/// The results of `report_bench`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bench {
    /// Microseconds the 256 plain malloc/free pairs took.
    pub plain_us: u64,
    /// Microseconds the 256 tagged pairs took.
    pub tagged_us: u64,
    /// `ml_wg_crypto_bench(1400, 64, ...)`: (aead_ns, copy_ns), or None if it failed.
    pub crypto: Option<(u32, u32)>,
}

/// `report_bench`.
pub fn write_bench(w: &mut JsonWriter<'_>, b: &Bench) {
    const ROUNDS: u64 = 256;
    const PACKET: u64 = 1400;
    begin(w, "bench");
    field(w, "rounds", ROUNDS);
    field(w, "plain_ns_per_pair", b.plain_us.wrapping_mul(1000) / ROUNDS);
    field(w, "tagged_ns_per_pair", b.tagged_us.wrapping_mul(1000) / ROUNDS);
    if let Some((aead_ns, copy_ns)) = b.crypto {
        field(w, "packet_bytes", PACKET);
        field(w, "chacha20poly1305_ns_per_packet", aead_ns.into());
        field(w, "copy_ns_per_packet", copy_ns.into());
        field(w, "cipher_ceiling_kbit_s", if aead_ns != 0 { PACKET * 8 * 1_000_000 / u64::from(aead_ns) } else { 0 });
    }
    end(w);
}

/// `memory guard N` reply.
pub fn write_guard(w: &mut JsonWriter<'_>, guard_floor: u32) {
    begin(w, "guard");
    field(w, "guard_floor", guard_floor.into());
    end(w);
}

/// `report_bridge`: `emit` is called for each `(section, name, value)` of `bridge_visit`; keys are `<section>_<name>`, a negative value prints `-` and its magnitude.
pub fn write_bridge(w: &mut JsonWriter<'_>, active: bool, counters: &[(&str, &str, i64)]) {
    begin(w, "bridge");
    w.raw(b",\"active\":");
    w.boolean(active);
    for (section, name, value) in counters {
        // `char key[48]; snprintf(key, 48, "%s_%s", ...)`: cut at 47 bytes.
        let mut key = [0u8; 47];
        let mut n = 0;
        for part in [section.as_bytes(), b"_", name.as_bytes()] {
            for &b in part {
                if n < key.len() {
                    key[n] = b;
                    n += 1;
                }
            }
        }
        w.ch(b',');
        w.string(&key[..n]);
        w.ch(b':');
        let mut v = *value;
        if v < 0 {
            w.ch(b'-');
            v = v.wrapping_neg();
        }
        w.number(v as u64);
    }
    end(w);
}

/// `report_wifi_link`: the link JSON is `wifi_link_json`'s text, when it fit.
pub fn write_wifi_link(w: &mut JsonWriter<'_>, uptime_ms: u32, link_json: Option<&[u8]>) {
    begin(w, "wifi_link");
    field(w, "uptime_ms", uptime_ms.into());
    w.ch(b',');
    w.key("driver_counters");
    w.string(b"not_exposed");
    if let Some(body) = link_json {
        w.ch(b',');
        w.key("link");
        w.raw(body);
    }
    end(w);
}

/// `report_wifi_reset`.
pub fn write_wifi_reset(w: &mut JsonWriter<'_>, uptime_ms: u32, lwip_reset: bool) {
    begin(w, "wifi_stats_reset");
    field(w, "uptime_ms", uptime_ms.into());
    field(w, "events_reset", 1);
    field(w, "lwip_reset", u64::from(lwip_reset));
    end(w);
}

/// `report_wifi_dump`.
pub fn write_wifi_dump(w: &mut JsonWriter<'_>, uptime_ms: u32, esp_err: u32) {
    begin(w, "wifi_driver_dump");
    field(w, "uptime_ms", uptime_ms.into());
    field(w, "esp_err", esp_err.into());
    w.ch(b',');
    w.key("output");
    w.string(b"rom_console_not_this_port");
    end(w);
}

/// `report_wifi_lwip`'s JSON line: `bits` is `sizeof(STAT_COUNTER) * 8` when `LWIP_STATS` is on (the C then follows it with the per-protocol and per-pool text
/// lines of `wifi_stats.h`, which are not ported), `None` when it is off.
pub fn write_lwip_stats(w: &mut JsonWriter<'_>, uptime_ms: u32, bits: Option<u32>) {
    begin(w, "lwip_stats");
    field(w, "uptime_ms", uptime_ms.into());
    match bits {
        Some(b) => {
            field(w, "enabled", 1);
            field(w, "counter_bits", b.into());
        }
        None => field(w, "enabled", 0),
    }
    end(w);
}

/// `elapsed_ms` of `report_wgperf`: `(uint32_t)((uint32_t)now_us - since_us) / 1000`.
pub fn wgperf_elapsed_ms(now_us: u64, since_us: u32) -> u32 {
    (now_us as u32).wrapping_sub(since_us) / 1000
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// The command dispatcher of gateway_memory_command
// ---------------------------------------------------------------------------------------------------------------------------------------------

/// The reply of `memory guard` for a bad argument.
pub const GUARD_USAGE: &str = "ERR memory guard takes 0-65536 bytes\r\n";

/// A diagnostics command (`gateway_memory_command`'s dispatch, in its order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// `memory`: heap, attribution, lwip, usb.
    Memory,
    /// `bridge`.
    Bridge,
    /// `bridgetune ARGS` (the rest of the line after `bridgetune`).
    BridgeTune,
    /// `memory low`.
    MemoryLow,
    /// `wifistats`.
    WifiStats,
    /// `wifistats reset`.
    WifiStatsReset,
    /// `wifistats dump`.
    WifiStatsDump,
    /// `cpu`.
    Cpu,
    /// `wgperf`.
    WgPerf,
    /// `wgperf reset`.
    WgPerfReset,
    /// `wgperf logbench`.
    WgPerfLogbench,
    /// `route`.
    Route,
    /// `inbound`.
    Inbound,
    /// `members`: phases then admission.
    Members,
    /// `memory locks`.
    Locks,
    /// `memory bench`.
    Bench,
    /// `memory guard N` with N in 0..=65536: set the guard floor, then report it.
    Guard(u32),
    /// `memory guard X` with a bad argument: reply [`GUARD_USAGE`].
    GuardUsage,
}

/// `strtoul(text, &end, 10)` on a 32-bit `unsigned long` (value, bytes consumed; 0 consumed when there are no digits).
fn strtoul(text: &[u8]) -> (u32, usize) {
    let mut i = 0;
    while i < text.len() && matches!(text[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut negative = false;
    let sign_at = i;
    if i < text.len() && (text[i] == b'+' || text[i] == b'-') {
        negative = text[i] == b'-';
        i += 1;
    }
    let digits_at = i;
    let mut value: u64 = 0;
    let mut overflow = false;
    while i < text.len() && text[i].is_ascii_digit() {
        value = value * 10 + u64::from(text[i] - b'0');
        if value > u64::from(u32::MAX) {
            overflow = true;
            value = u64::from(u32::MAX);
        }
        i += 1;
    }
    if i == digits_at {
        let _ = sign_at;
        return (0, 0);
    }
    let v = if overflow {
        u32::MAX
    } else if negative {
        (value as u32).wrapping_neg()
    } else {
        value as u32
    };
    (v, i)
}

impl Command {
    /// Which diagnostics command `line` is, or None (the C returns false and the control task goes on to its own list).
    pub fn parse(line: &[u8]) -> Option<Command> {
        let line = &line[..line.iter().position(|&b| b == 0).unwrap_or(line.len())];
        Some(match line {
            b"memory" => Command::Memory,
            b"bridge" => Command::Bridge,
            b"memory low" => Command::MemoryLow,
            b"wifistats" => Command::WifiStats,
            b"wifistats reset" => Command::WifiStatsReset,
            b"wifistats dump" => Command::WifiStatsDump,
            b"cpu" => Command::Cpu,
            b"wgperf" => Command::WgPerf,
            b"wgperf reset" => Command::WgPerfReset,
            b"wgperf logbench" => Command::WgPerfLogbench,
            b"route" => Command::Route,
            b"inbound" => Command::Inbound,
            b"members" => Command::Members,
            b"memory locks" => Command::Locks,
            b"memory bench" => Command::Bench,
            _ if line.starts_with(b"bridgetune") && (line.len() == 10 || line[10] == b' ') => Command::BridgeTune,
            _ if line.starts_with(b"memory guard") && (line.len() == 12 || line[12] == b' ') => {
                // `bytes = line[12] ? strtoul(line + 13, &end, 10) : 0; if (!line[12] || !line[13] || *end || bytes > 65536) error`
                // The C evaluates `!line[12]` first: with no argument it is an error too.
                if line.len() == 12 || line.len() == 13 {
                    return Some(Command::GuardUsage);
                }
                let (bytes, used) = strtoul(&line[13..]);
                if used == 0 || 13 + used != line.len() || bytes > 65536 { Command::GuardUsage } else { Command::Guard(bytes) }
            }
            _ => return None,
        })
    }
}
