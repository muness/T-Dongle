/* Serial memory diagnostics (CONFIG_TDONGLE_MEMORY_DIAGNOSTICS). Each report is one JSON line:
 * bounded and free of keys, auth keys, URLs and names. Included by
 * gateway_main.c after json_writer.inc. */
#include "lwip/opt.h"
#include "route_table.h"
#include "tdongle_wgperf.h"
#include "ml_rx_stats.h"
#include "ml_net_io_drain.h"
#include "lwip/stats.h"
extern void mgmt_write(const char *s);
static const char *const owner_names[TDONGLE_OWNER_COUNT] = {"other", "tls", "control", "map", "peer", "wg", "packet", "context"};
static const char *const phase_names[TDONGLE_PHASE_COUNT] = {"start", "control", "noise", "register", "map", "derp", "steady"};
static const char *const verdict_names[] = {"ok", "refused_budget", "refused_largest", "refused_sockets", "override", "refused_floor", "start_failed"};
static int memory_sink(void *context, const char *data, size_t length) {
    char part[257];
    while (length) {
        size_t take = length < 256 ? length : 256;
        memcpy(part, data, take);
        part[take] = 0;
        mgmt_write(part);
        data += take;
        length -= take;
    }
    return 0;
}
static void report_begin(jw_writer *w, const char *kind) {
    jw_raw(w, "{\"schema\":1,\"kind\":");
    jw_string(w, kind);
}
static void report_end(jw_writer *w) {
    jw_raw(w, "}\r\n");
    jw_flush(w);
}
static void report_field(jw_writer *w, const char *key, uint64_t value) {
    jw_char(w, ',');
    jw_key(w, key);
    jw_number(w, value);
}
static void report_owner_list(jw_writer *w, const char *key, const uint32_t *values) {
    jw_char(w, ',');
    jw_key(w, key);
    jw_char(w, '[');
    for (unsigned i = 0; i < TDONGLE_OWNER_COUNT; i++) {
        if (i) jw_char(w, ',');
        jw_number(w, values[i]);
    }
    jw_char(w, ']');
}
typedef struct {
    uint32_t id, stacks, tcbs, h2_acc, tasks, stack_free[4];
    bool lp_acc;
} memory_member;
enum { MEMORY_MEMBER_LIMIT = TDONGLE_MEMORY_MEMBERS + 1 };
/* Copies what the report needs under the lifetime lock; returns the number of memberships with clients. */
static bool memory_snapshot(memory_member *out, unsigned *count, unsigned *omitted) {
    if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    *count = *omitted = 0;
    for (membership_t *m = members; m; m = m->next) {
        microlink_t *c = m->client;
        if (!c) continue;
        if (*count == MEMORY_MEMBER_LIMIT) { (*omitted)++; continue; }
        memory_member *v = &out[(*count)++];
        /* A membership owns one task, its control task. net_io, derp and wg_mgr are shared: their headroom is reported
         * under every membership they serve (stack_free keeps its four slots) but their bytes are counted once, in
         * `shared_runtime`. */
        const bool shared = c->rt_attached && !c->stop_incomplete;
        TaskHandle_t tasks[4] = {shared ? ml_rt_task_handle(ML_RT_TASK_NET_IO) : NULL,
                                 shared ? ml_rt_task_handle(ML_RT_TASK_DERP) : NULL,
                                 c->coord_task,
                                 shared ? ml_rt_task_handle(ML_RT_TASK_WG_MGR) : NULL};
        *v = (memory_member){.id = m->id, .h2_acc = c->h2_acc_len, .lp_acc = c->lp_acc != NULL};
        for (unsigned t = 0; t < 4; t++) {
            v->stack_free[t] = UINT32_MAX;
            if (!tasks[t] || c->stop_incomplete) continue;
            v->stack_free[t] = uxTaskGetStackHighWaterMark(tasks[t]);
        }
        if (tasks[2] && !c->stop_incomplete) {
            v->tasks = 1;
            v->stacks = ML_TASK_COORD_STACK;
            v->tcbs = sizeof(StaticTask_t);
        }
    }
    xSemaphoreGive(members_lock);
    return true;
}
static void report_heap(jw_writer *w) {
    report_begin(w, "heap");
    report_field(w, "uptime_ms", esp_timer_get_time() / 1000);
    jw_char(w, ',');
    jw_key(w, "firmware");
    jw_string(w, GATEWAY_VERSION);
    report_field(w, "free", heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    report_field(w, "min", heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    report_field(w, "largest", heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    report_field(w, "total", heap_caps_get_total_size(MALLOC_CAP_INTERNAL));
    report_field(w, "guard_floor", tdongle_heap_guard_floor());
    report_field(w, "underflows", tdongle_heap_underflows());
    report_field(w, "ledger_bytes", tdongle_memory_ledger_bytes());
    jw_raw(w, ",\"queue_depth\":{\"derp_tx\":");
    jw_number(w, ML_DERP_TX_QUEUE_DEPTH);
    report_field(w, "disco_rx", ML_DISCO_RX_QUEUE_DEPTH);
    report_field(w, "wg_rx", ML_WG_RX_QUEUE_DEPTH);
    report_field(w, "stun_rx", ML_STUN_RX_QUEUE_DEPTH);
    jw_char(w, '}');
    jw_raw(w, ",\"owners\":{");
    for (unsigned i = 0; i < TDONGLE_OWNER_COUNT; i++) {
        tdongle_owner_stats s = tdongle_heap_owner((tdongle_owner)i);
        if (i) jw_char(w, ',');
        jw_key(w, owner_names[i]);
        jw_raw(w, "{\"live\":");
        jw_number(w, s.live);
        report_field(w, "peak", s.peak);
        report_field(w, "allocs", s.allocs);
        report_field(w, "frees", s.frees);
        report_field(w, "failed", s.failed);
        report_field(w, "denied", s.denied);
        jw_char(w, '}');
    }
    jw_char(w, '}');
    static const char *const drop_names[TDONGLE_DROP_COUNT] = {"derp_tx_evict", "derp_tx_full", "derp_rx_full", "net_disco_full", "net_wg_full", "net_stun_full", "router_ingress"};
    jw_raw(w, ",\"drops\":{");
    for (unsigned i = 0; i < TDONGLE_DROP_COUNT; i++) {
        if (i) jw_char(w, ',');
        jw_key(w, drop_names[i]);
        jw_number(w, tdongle_memory_drops((tdongle_drop)i));
    }
    jw_char(w, '}');
    report_end(w);
}
static void report_attribution(jw_writer *w) {
    memory_member snapshot[MEMORY_MEMBER_LIMIT];
    unsigned count = 0, omitted = 0;
    if (!memory_snapshot(snapshot, &count, &omitted)) {
        report_begin(w, "attribution");
        jw_raw(w, ",\"error\":\"memberships busy\"");
        report_end(w);
        return;
    }
    uint64_t tagged = 0, synthetic = 0;
    bool lp_acc = false;
    uint32_t h2_acc = 0;
    for (unsigned i = 0; i < TDONGLE_OWNER_COUNT; i++) tagged += tdongle_heap_owner((tdongle_owner)i).live;
    /* The three shared tasks exist once, while any membership is attached. */
    ml_rt_status_t shared_rt;
    ml_rt_status(&shared_rt);
    uint32_t shared_tasks = 0, shared_stacks = 0, shared_tcbs = 0;
    if (shared_rt.running)
        for (unsigned t = 0; t < ML_RT_TASK_COUNT; t++) {
            shared_tasks++;
            shared_stacks += shared_rt.stack_bytes[t];
            shared_tcbs += sizeof(StaticTask_t);
        }
    synthetic += shared_stacks + shared_tcbs;
    for (unsigned i = 0; i < count; i++) {
        synthetic += snapshot[i].stacks + snapshot[i].tcbs + member_queue_bytes();
        lp_acc |= snapshot[i].lp_acc;
        if (snapshot[i].h2_acc > h2_acc) h2_acc = snapshot[i].h2_acc;
    }
    uint64_t allocated = heap_caps_get_total_size(MALLOC_CAP_INTERNAL) - heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    report_begin(w, "attribution");
    report_field(w, "allocated", allocated);
    report_field(w, "tagged", tagged);
    report_field(w, "synthetic", synthetic);
    /* Wi-Fi, lwIP, USB and the HTTP server are the baseline; difference this between ladder steps. */
    /* Tagged bytes can include non-internal memory and synthetic is computed, so never let the unsigned difference wrap. */
    uint64_t accounted = tagged + synthetic;
    report_field(w, "unattributed", allocated > accounted ? allocated - accounted : 0);
    report_field(w, "overattributed", accounted > allocated ? accounted - allocated : 0);
    report_field(w, "members_omitted", omitted);
    jw_raw(w, ",\"shared_runtime\":{\"tasks\":");
    jw_number(w, shared_tasks);
    report_field(w, "stacks", shared_stacks);
    report_field(w, "tcbs", shared_tcbs);
    jw_char(w, '}');
    jw_raw(w, ",\"members\":[");
    for (unsigned i = 0; i < count; i++) {
        memory_member *v = &snapshot[i];
        if (i) jw_char(w, ',');
        jw_raw(w, "{\"id\":");
        jw_number(w, v->id);
        report_field(w, "tasks", v->tasks);
        report_field(w, "stacks", v->stacks);
        report_field(w, "tcbs", v->tcbs);
        report_field(w, "queues", member_queue_bytes());
        jw_raw(w, ",\"stack_free\":[");
        for (unsigned t = 0; t < 4; t++) {
            if (t) jw_char(w, ',');
            if (v->stack_free[t] == UINT32_MAX) jw_raw(w, "null"); else jw_number(w, v->stack_free[t]);
        }
        jw_raw(w, "]}");
    }
    jw_raw(w, "],\"n2\":{\"lp_acc_capacity\":");
    jw_number(w, ML_JSON_BUFFER_SIZE);
    jw_raw(w, ",\"lp_acc_allocated\":");
    jw_bool(w, lp_acc);
    report_field(w, "h2_window_advertised", ML_H2_BUFFER_SIZE);
    report_field(w, "h2_acc_live_max", h2_acc);
    report_field(w, "gateway_plain_static", ML_GATEWAY_PLAIN_BYTES);
    report_field(w, "gateway_json_static", ML_GATEWAY_JSON_BYTES);
    jw_char(w, '}');
    report_end(w);
}
static void report_lwip(jw_writer *w) {
    report_begin(w, "lwip");
    report_field(w, "tcp_wnd", TCP_WND);
    report_field(w, "tcp_snd_buf", TCP_SND_BUF);
    report_field(w, "tcp_mss", TCP_MSS);
    report_field(w, "tcp_snd_queuelen", TCP_SND_QUEUELEN);
    report_field(w, "wnd_scale", LWIP_WND_SCALE);
    report_field(w, "pbuf_pool_size", PBUF_POOL_SIZE);
    report_field(w, "pbuf_pool_bufsize", PBUF_POOL_BUFSIZE);
    report_field(w, "memp_tcp_pcb", MEMP_NUM_TCP_PCB);
    report_field(w, "memp_tcp_seg", MEMP_NUM_TCP_SEG);
    report_field(w, "max_sockets", CONFIG_LWIP_MAX_SOCKETS);
    report_field(w, "tcp_recvmbox", CONFIG_LWIP_TCP_RECVMBOX_SIZE);
    report_field(w, "udp_recvmbox", CONFIG_LWIP_UDP_RECVMBOX_SIZE);
    report_field(w, "tcpip_recvmbox", CONFIG_LWIP_TCPIP_RECVMBOX_SIZE);
    report_field(w, "wifi_static_rx", CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM);
    report_field(w, "wifi_dynamic_rx", CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM);
    report_field(w, "wifi_dynamic_tx", CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM);
    report_end(w);
}
/* USB data path: elastic transmit ring (tunnel to host) and receive budget (host to lwIP). Drops here are
 * backpressure, not faults. tx_ring_bytes is the capacity NOW (permanent plus live elastic chunks); tune the cap
 * (GATEWAY_USB_TX_MAX_CHUNKS) from tx_dropped_full against tx_high_water_slabs, and read tx_grow_denied_* when it
 * does not grow. tx_reclaim_events counts the times admission or a negotiation took the elastic memory back. */
static void report_usb(jw_writer *w) {
    tinyusb_net_tx_stats_t tx;
    tinyusb_net_tx_ring_stats(&tx);
    report_begin(w, "usb");
    report_field(w, "tx_ring_bytes", tx.ring_bytes);
    report_field(w, "tx_ring_base_bytes", tx.base_bytes);
    report_field(w, "tx_ring_max_bytes", tx.max_bytes);
    report_field(w, "tx_elastic_held_bytes", tx.elastic_held_bytes);
    report_field(w, "tx_elastic_chunks", tx.chunks);
    report_field(w, "tx_grow_events", tx.grow_events);
    report_field(w, "tx_shrink_events", tx.shrink_events);
    report_field(w, "tx_reclaim_events", tx.reclaim_events);
    report_field(w, "tx_reclaimed_chunks", tx.reclaimed_chunks);
    report_field(w, "tx_grow_denied_gate", tx.grow_denied_gate);
    report_field(w, "tx_grow_denied_heap", tx.grow_denied_heap);
    report_field(w, "tx_grow_denied_largest", tx.grow_denied_largest);
    report_field(w, "tx_grow_denied_nomem", tx.grow_denied_nomem);
    report_field(w, "tx_grow_raced", tx.grow_raced);
    report_field(w, "tx_high_water", tx.high_water_bytes);
    report_field(w, "tx_high_water_slabs", tx.high_water_slabs);
    report_field(w, "tx_pm_acquired", tx.pm_acquired);
    report_field(w, "tx_pm_released", tx.pm_released);
    report_field(w, "tx_pm_held", tx.pm_held);
    report_field(w, "tx_enqueued", tx.enqueued_frames);
    report_field(w, "tx_enqueued_bytes", tx.enqueued_bytes);
    report_field(w, "tx_sent", tx.sent_frames);
    report_field(w, "tx_sent_bytes", tx.sent_bytes);
    report_field(w, "tx_dropped_full", tx.dropped_full);
    report_field(w, "tx_dropped_link_down", tx.dropped_link_down);
    report_field(w, "tx_dropped_invalid", tx.dropped_invalid);
    report_field(w, "tx_flushed_link_down", tx.flushed_link_down);
    report_field(w, "tx_ntb_blocked", tx.ntb_blocked);
    report_field(w, "tx_xfer_events", tx.xfer_events);
    report_field(w, "tx_worker_stack_free", tx.worker_stack_free);
    report_field(w, "tx_ntb_count", CONFIG_TINYUSB_NCM_IN_NTB_BUFFS_COUNT);
    report_field(w, "rx_inflight_max", GATEWAY_USB_RX_INFLIGHT_MAX);
    report_field(w, "rx_inflight", atomic_load(&usb_rx_budget.inflight));
    report_field(w, "rx_high_water", atomic_load(&usb_rx_budget.high_water));
    report_field(w, "rx_dropped_busy", atomic_load(&usb_rx_budget.dropped_busy));
    report_field(w, "rx_dropped_nomem", atomic_load(&usb_rx_budget.dropped_nomem));
    report_field(w, "rx_dropped_invalid", atomic_load(&usb_rx_budget.dropped_invalid));
    report_end(w);
}
/* How long the lwIP core lock was held by the shared wg_mgr task, by call site: a histogram, so a board run can show whether
 * any single hold exceeds the ~1 ms budget (over_1ms) and how long the worst one was. */
static void report_locks(jw_writer *w) {
    static const char *const sites[TDONGLE_LOCK_SITE_COUNT] = {"wg_other", "wg_periodic", "wg_commit", "wg_output", "wg_peer"};
    report_begin(w, "locks");
    jw_raw(w, ",\"bucket_limits_us\":[");
    for (unsigned b = 0; b < TDONGLE_LOCK_BUCKETS - 1; b++) {
        if (b) jw_char(w, ',');
        jw_number(w, tdongle_lock_bucket_limit_us[b]);
    }
    jw_raw(w, "],\"sites\":{");
    for (unsigned i = 0; i < TDONGLE_LOCK_SITE_COUNT; i++) {
        tdongle_lock_stats s = tdongle_lock_stats_get((tdongle_lock_site)i);
        if (i) jw_char(w, ',');
        jw_key(w, sites[i]);
        jw_raw(w, "{\"count\":");
        jw_number(w, s.count);
        report_field(w, "max_us", s.max_us);
        report_field(w, "over_1ms", s.over_1ms);
        report_field(w, "total_us", (uint32_t)s.total_us);
        jw_raw(w, ",\"buckets\":[");
        for (unsigned b = 0; b < TDONGLE_LOCK_BUCKETS; b++) {
            if (b) jw_char(w, ',');
            jw_number(w, s.bucket[b]);
        }
        jw_raw(w, "]}");
    }
    jw_char(w, '}');
    report_end(w);
}
/* Forwarding counters and the queue/cache bounds they are read against. */
static void report_router(jw_writer *w) {
    report_begin(w, "route");
    for (unsigned i = 0; i < RT_STAT_COUNT; i++)
        report_field(w, rt_stat_name(i), gateway_route_stat(i));
    report_field(w, "queue_depth", ROUTE_QUEUE_DEPTH);
    report_field(w, "queue_bytes", ROUTE_QUEUE_BYTES);
    report_field(w, "alias_cache", RT_ALIASES);
    report_field(w, "flow_slots", RT_FLOWS);
    report_end(w);
}
static void report_phases(jw_writer *w) {
    tdongle_member_phases m;
    for (unsigned slot = 0; slot < TDONGLE_MEMORY_MEMBERS; slot++) {
        if (!tdongle_memory_member_get(slot, &m)) continue;
        report_begin(w, "phases");
        report_field(w, "member", m.member_id);
        report_field(w, "attempt", m.attempt);
        jw_raw(w, ",\"owner_order\":[");
        for (unsigned i = 0; i < TDONGLE_OWNER_COUNT; i++) {
            if (i) jw_char(w, ',');
            jw_string(w, owner_names[i]);
        }
        jw_raw(w, "],\"phases\":{");
        bool first = true;
        for (unsigned p = 0; p < TDONGLE_PHASE_COUNT; p++) {
            const tdongle_phase_record *r = &m.phase[p];
            if (!r->valid) continue;
            if (!first) jw_char(w, ',');
            first = false;
            jw_key(w, phase_names[p]);
            jw_raw(w, "{\"t\":");
            jw_number(w, r->uptime_ms);
            report_field(w, "free", r->free_bytes);
            report_field(w, "min", r->minimum_bytes);
            report_field(w, "largest", r->largest_bytes);
            report_field(w, "exact", r->exact);
            report_owner_list(w, "peak", r->owner_peak);
            jw_char(w, '}');
        }
        jw_char(w, '}');
        report_end(w);
    }
}
static void report_admission(jw_writer *w) {
    report_begin(w, "admission");
    report_field(w, "guard_floor", tdongle_heap_guard_floor());
    jw_raw(w, ",\"override\":");
#if defined(CONFIG_TDONGLE_MEMORY_DIAGNOSTICS) && defined(CONFIG_TDONGLE_MEMORY_ADMISSION_OVERRIDE)
    jw_raw(w, "true");
#else
    jw_raw(w, "false");
#endif
    report_field(w, "slot_evictions", tdongle_memory_slot_evictions());
    jw_raw(w, ",\"attempts\":[");
    for (unsigned i = 0; i < tdongle_memory_admission_count(); i++) {
        tdongle_admission_record r = tdongle_memory_admission_get(i);
        if (i) jw_char(w, ',');
        jw_raw(w, "{\"t\":");
        jw_number(w, r.uptime_ms);
        report_field(w, "member", r.member_id);
        report_field(w, "free", r.free_bytes);
        report_field(w, "largest", r.largest_bytes);
        report_field(w, "budget", r.budget_bytes);
        report_field(w, "sockets", r.sockets_open);
        report_field(w, "socket_limit", r.sockets_limit);
        report_field(w, "active", r.active);
        jw_raw(w, ",\"verdict\":");
        jw_string(w, r.verdict < sizeof(verdict_names) / sizeof(verdict_names[0]) ? verdict_names[r.verdict] : "unknown");
        jw_char(w, '}');
    }
    jw_char(w, ']');
    report_end(w);
}
/* Time the tagged allocator against the plain one, and the WireGuard cipher against a plain copy
 * of a full-size packet (the data path does one of each per packet, plus several more copies). */
static void report_bench(jw_writer *w) {
    enum { ROUNDS = 256 };
    void *volatile block;
    int64_t started = esp_timer_get_time();
    for (unsigned i = 0; i < ROUNDS; i++) { block = malloc(64); free(block); }
    uint64_t plain = esp_timer_get_time() - started;
    started = esp_timer_get_time();
    for (unsigned i = 0; i < ROUNDS; i++) { block = tdongle_heap_tag(TDONGLE_OWNER_OTHER, malloc(64)); tdongle_heap_free(TDONGLE_OWNER_OTHER, block); }
    uint64_t tagged = esp_timer_get_time() - started;
    report_begin(w, "bench");
    report_field(w, "rounds", ROUNDS);
    report_field(w, "plain_ns_per_pair", plain * 1000 / ROUNDS);
    report_field(w, "tagged_ns_per_pair", tagged * 1000 / ROUNDS);
    uint32_t aead_ns, copy_ns;
    enum { PACKET = 1400 };
    if (ml_wg_crypto_bench(PACKET, 64, &aead_ns, &copy_ns)) {
        report_field(w, "packet_bytes", PACKET);
        report_field(w, "chacha20poly1305_ns_per_packet", aead_ns);
        report_field(w, "copy_ns_per_packet", copy_ns);
        /* One core doing nothing but encrypting: the ceiling the cipher alone puts on a tunnel. */
        report_field(w, "cipher_ceiling_kbit_s", aead_ns ? (uint64_t)PACKET * 8 * 1000000 / aead_ns : 0);
    }
    report_end(w);
}
/* `cpu`: one JSON line with the raw, cumulative FreeRTOS run-time counters of every task, so two snapshots around a
 * transfer give each task's share (tools/cpu_profile.py). Needs CONFIG_FREERTOS_USE_TRACE_FACILITY and
 * CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS, which only sdkconfig.diagnostics sets. `total` is the counter's total
 * across both cores (percent of ONE core = task delta / (total delta / 2)); it wraps at 2^32 counts. */
#define CPU_REPORT_TASKS 32
static void report_cpu(jw_writer *w) {
    TaskStatus_t *tasks = malloc(CPU_REPORT_TASKS * sizeof(*tasks));
    if (!tasks) {
        mgmt_write("ERR no memory for the task table\r\n");
        return;
    }
    uint32_t total = 0;
    UBaseType_t existing = uxTaskGetNumberOfTasks();
    /* uxTaskGetSystemState returns 0 and fills nothing when the array is too small: say so rather than print an
     * empty list. */
    UBaseType_t n = existing <= CPU_REPORT_TASKS ? uxTaskGetSystemState(tasks, CPU_REPORT_TASKS, &total) : 0;
    tdongle_pm_status_t pm;
    tdongle_pm_status(&pm);
    report_begin(w, "cpu");
    report_field(w, "uptime_ms", esp_timer_get_time() / 1000);
    report_field(w, "cpu_mhz", pm.cpu_mhz);
    report_field(w, "total", total);
    report_field(w, "cores", portNUM_PROCESSORS);
    report_field(w, "tasks_listed", n);
    report_field(w, "tasks_existing", existing);
    jw_raw(w, ",\"tasks\":[");
    for (UBaseType_t i = 0; i < n; i++) {
        if (i) jw_char(w, ',');
        jw_raw(w, "{\"name\":");
        jw_string(w, tasks[i].pcTaskName);
        report_field(w, "runtime", tasks[i].ulRunTimeCounter);
        report_field(w, "priority", tasks[i].uxCurrentPriority);
        /* core: 0 or 1, or -1 (unpinned) */
        jw_char(w, ',');
        jw_key(w, "core");
        BaseType_t core = xTaskGetCoreID(tasks[i].xHandle);
        if (core >= 0 && core < portNUM_PROCESSORS) jw_number(w, (uint32_t)core);
        else jw_raw(w, "-1");
        report_field(w, "stack_free", tasks[i].usStackHighWaterMark);
        jw_char(w, '}');
    }
    jw_char(w, ']');
    report_end(w);
    free(tasks);
}
/* Every place an inbound datagram can be lost between the Wi-Fi interface and the USB host, as cumulative counters (never
 * reset: diff two samples). Layers, in order (docs/adr/0019-inbound-loss.md has the reconciliation):
 *   lwip   lwIP's own UDP counters. udp_recv counts a datagram BEFORE the socket mailbox, which drops silently when full, so
 *          udp_recv - ml.udp_rx (net_io's reads) is the mailbox loss to date (DNS and other sockets add a little);
 *   ml     net_io -> queues -> wg_mgr: ml_rx_stats.h;  wg  wireguardif receive path: wireguard_stats.h;
 *   route  tunnel -> USB (the `route` report has the rest): reply_* reasons, tunnel_*, usb_tx, usb_tx_err. */
static void report_inbound(jw_writer *w) {
    report_begin(w, "inbound");
    report_field(w, "udp_recvmbox", CONFIG_LWIP_UDP_RECVMBOX_SIZE);
    report_field(w, "drain_cap", ML_NET_IO_DRAIN_CAP);
    report_field(w, "wg_rx_queue_depth", ML_WG_RX_QUEUE_DEPTH);
    report_field(w, "replay_window", ml_wg_replay_window());
#if LWIP_STATS && UDP_STATS
    jw_raw(w, ",\"lwip\":{\"udp_recv\":");
    jw_number(w, lwip_stats.udp.recv);
    report_field(w, "udp_drop", lwip_stats.udp.drop);
    report_field(w, "udp_memerr", lwip_stats.udp.memerr);
    report_field(w, "udp_err", lwip_stats.udp.err);
    jw_char(w, '}');
#endif
    jw_raw(w, ",\"ml\":{");
    for (unsigned i = 0; i < ML_RXS_COUNT; i++) {
        if (i) jw_char(w, ',');
        jw_key(w, ml_rx_stat_name(i));
        jw_number(w, ml_rx_stat_get(i));
    }
    jw_raw(w, ",\"drain_burst_max\":");
    jw_number(w, atomic_load_explicit(&ml_rx_stats.drain_burst_max, memory_order_relaxed));
    jw_raw(w, "},\"wg\":{");
    for (unsigned i = 0; i < ml_wg_rx_stat_count(); i++) {
        if (i) jw_char(w, ',');
        jw_key(w, ml_wg_rx_stat_name(i));
        jw_number(w, ml_wg_rx_stat(i));
    }
    jw_raw(w, "},\"route\":{");
    static const unsigned reasons[] = {RT_STAT_TUNNEL_MALFORMED, RT_STAT_TUNNEL_NOMEM, RT_STAT_BAD_PACKET, RT_STAT_REPLY_NO_MEMBER, RT_STAT_REPLY_NOT_US,
                                       RT_STAT_REPLY_FLOW_RANGE, RT_STAT_REPLY_NO_FLOW, RT_STAT_REPLY_GENERATION, RT_STAT_REPLY_OWNER, RT_STAT_REPLY_IDLE,
                                       RT_STAT_FORWARDED_IN, RT_STAT_USB_TX, RT_STAT_USB_TX_ERR, RT_STAT_TX_FAIL};
    for (unsigned i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
        if (i) jw_char(w, ',');
        jw_key(w, rt_stat_name(reasons[i]));
        jw_number(w, gateway_route_stat(reasons[i]));
    }
    jw_char(w, '}');
    report_end(w);
}
/* wg_mgr packet-path accounting (components/tdongle_runtime/include/tdongle_wgperf.h). Stages are [count,total,max] in the
 * unit named in "units"; "elapsed_ms" is the time since the last `wgperf reset`, so totals divide into rates. */
extern bool ml_wg_log_bench(unsigned rounds, uint32_t *cycles_per_line);
static void report_wgperf(jw_writer *w) {
    static const char *const names[TDONGLE_WGPERF_STAGE_COUNT] = {
#define X(name, unit) #name,
        TDONGLE_WGPERF_STAGES(X)
#undef X
    };
    static const char *const units[TDONGLE_WGPERF_STAGE_COUNT] = {
#define X(name, unit) unit,
        TDONGLE_WGPERF_STAGES(X)
#undef X
    };
    static const char *const counters[TDONGLE_WGPERF_COUNTER_COUNT] = {
#define X(name) #name,
        TDONGLE_WGPERF_COUNTERS(X)
#undef X
    };
    tdongle_pm_status_t pm;
    tdongle_pm_status(&pm);
    report_begin(w, "wgperf");
    report_field(w, "cpu_mhz", pm.cpu_mhz);
    report_field(w, "elapsed_ms", (uint32_t)((uint32_t)esp_timer_get_time() - atomic_load(&tdongle_wgperf.since_us)) / 1000);
    jw_raw(w, ",\"stages\":{");
    for (unsigned i = 0; i < TDONGLE_WGPERF_STAGE_COUNT; i++) {
        tdongle_wgperf_sample s = tdongle_wgperf_get(&tdongle_wgperf, i);
        if (i) jw_char(w, ',');
        jw_key(w, names[i]);
        jw_char(w, '[');
        jw_number(w, s.count);
        jw_char(w, ',');
        jw_number(w, s.total);
        jw_char(w, ',');
        jw_number(w, s.max);
        jw_char(w, ']');
    }
    jw_raw(w, "},\"units\":[");
    for (unsigned i = 0; i < TDONGLE_WGPERF_STAGE_COUNT; i++) {
        if (i) jw_char(w, ',');
        jw_string(w, units[i]);
    }
    jw_raw(w, "],\"counters\":{");
    for (unsigned i = 0; i < TDONGLE_WGPERF_COUNTER_COUNT; i++) {
        if (i) jw_char(w, ',');
        jw_key(w, counters[i]);
        jw_number(w, tdongle_wgperf_counter_get(&tdongle_wgperf, i));
    }
    jw_char(w, '}');
    report_end(w);
}
/* What one per-packet log line cost, measured on the board: the formatting and vprintf path of ESP_LOGI as configured. */
static void report_logbench(jw_writer *w) {
    uint32_t per_line = 0;
    bool ok = ml_wg_log_bench(200, &per_line);
    report_begin(w, "logbench");
    report_field(w, "rounds", 200);
    report_field(w, "ok", ok);
    report_field(w, "cycles_per_line", per_line);
    report_end(w);
}
bool gateway_memory_command(const char *line) {
    jw_writer w = {.sink = memory_sink};
    if (!strcmp(line, "memory")) {
        report_heap(&w);
        report_attribution(&w);
        report_lwip(&w);
        report_usb(&w);
    } else if (!strcmp(line, "cpu")) {
        report_cpu(&w);
    } else if (!strcmp(line, "wgperf")) {
        report_wgperf(&w);
    } else if (!strcmp(line, "wgperf reset")) {
        tdongle_wgperf_reset_now();
        report_begin(&w, "wgperf_reset");
        report_end(&w);
    } else if (!strcmp(line, "wgperf logbench")) {
        report_logbench(&w);
    } else if (!strcmp(line, "route")) {
        report_router(&w);
    } else if (!strcmp(line, "inbound")) {
        report_inbound(&w);
    } else if (!strcmp(line, "members")) {
        report_phases(&w);
        report_admission(&w);
    } else if (!strcmp(line, "memory locks")) {
        report_locks(&w);
    } else if (!strcmp(line, "memory bench"))
        report_bench(&w);
    else if (!strncmp(line, "memory guard", 12) && (!line[12] || line[12] == ' ')) {
        char *end = (char *)line;
        unsigned long bytes = line[12] ? strtoul(line + 13, &end, 10) : 0;
        if (!line[12] || !line[13] || *end || bytes > 65536) {
            mgmt_write("ERR memory guard takes 0-65536 bytes\r\n");
            return true;
        }
        tdongle_heap_set_guard_floor(bytes);
        report_begin(&w, "guard");
        report_field(&w, "guard_floor", tdongle_heap_guard_floor());
        report_end(&w);
    } else
        return false;
    return true;
}
