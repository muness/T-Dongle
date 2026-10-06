/* The transparent bridge's counters (ADR 0023): where every frame went, and what the buffers and the Wi-Fi budget did meanwhile.
 * Included by gateway_main.c after wifi_pins.inc. One visitor lists them, two renderers print them, so the serial `status` lines and the
 * diagnostics `bridge` report cannot drift apart:
 *   serial `status` (bridge mode)  new lines only, one per section: bridge_link, bridge_to_host, bridge_to_wifi, bridge_usb_ring,
 *                                  bridge_timing, bridge_wifi_tx. Android parses the first status lines with end-anchored patterns, so nothing is ever
 *                                  appended to a line that existed before (tools/check-android-status.py holds that line);
 *   `bridge` (diagnostics build)   one JSON line, keys "<section>_<name>".
 * Identities that hold at rest (tests/test_bridge_path.c checks them on the real code):
 *   to_host.frames  = forwarded + invalid + own_mac + link_down + usb_not_ready + ring_full
 *   to_wifi.frames  = queued + invalid + foreign_mac + link_down + queue_full
 *   to_wifi.queued  = sent + stale + sojourn_drop + link_down_queued + tx_failed + queue_depth
 *   wifi_tx.charged = done + aborted + flushed + stale + inflight (wifi_pin_budget.h) */
typedef void (*bridge_emit_fn)(void *ctx, const char *section, const char *name, int64_t value);
static void bridge_visit(bridge_emit_fn emit, void *ctx) {
    tdongle_l2_stats_t l2;
    tdongle_l2_stats(&l2);
    tinyusb_net_tx_stats_t ring;
    tinyusb_net_tx_ring_stats(&ring);
#define E(section, name, value) emit(ctx, section, name, (int64_t)(value))
    E("link", "linked", l2.linked);
    E("link", "changes", l2.link_changes);
    E("link", "worker_stack_free", l2.worker_stack_free);
    E("to_host", "frames", l2.w2h_frames);
    E("to_host", "forwarded", l2.w2h_forwarded);
    E("to_host", "invalid", l2.w2h_invalid);
    E("to_host", "own_mac", l2.w2h_own_mac);
    E("to_host", "link_down", l2.w2h_link_down);
    E("to_host", "usb_not_ready", l2.w2h_usb_not_ready);
    E("to_host", "ring_full", l2.w2h_ring_full);
    E("to_host", "raced", l2.w2h_raced);
    E("to_wifi", "frames", l2.h2w_frames);
    E("to_wifi", "queued", l2.h2w_queued);
    E("to_wifi", "invalid", l2.h2w_invalid);
    E("to_wifi", "foreign_mac", l2.h2w_foreign_mac);
    E("to_wifi", "link_down", l2.h2w_link_down);
    E("to_wifi", "queue_full", l2.h2w_queue_full);
    E("to_wifi", "sent", l2.h2w_sent);
    E("to_wifi", "stale", l2.h2w_stale);
    E("to_wifi", "sojourn_drop", l2.h2w_sojourn_drop);
    E("to_wifi", "link_down_queued", l2.h2w_link_down_queued);
    E("to_wifi", "tx_failed", l2.h2w_tx_failed);
    E("to_wifi", "tx_retries", l2.h2w_tx_retries);
    E("to_wifi", "last_tx_error", l2.h2w_last_tx_error);
    E("to_wifi", "queue_depth", l2.h2w_queue_depth);
    E("to_wifi", "queue_high_water", l2.h2w_queue_high_water);
    E("usb_ring", "ring_bytes", ring.ring_bytes);
    E("usb_ring", "high_water_slabs", ring.high_water_slabs);
    E("usb_ring", "enqueued", ring.enqueued_frames);
    E("usb_ring", "sent", ring.sent_frames);
    E("usb_ring", "dropped_full", ring.dropped_full);
    E("usb_ring", "dropped_link_down", ring.dropped_link_down);
    E("usb_ring", "flushed_link_down", ring.flushed_link_down);
    E("usb_ring", "grow_events", ring.grow_events);
    E("usb_ring", "shrink_events", ring.shrink_events);
    E("usb_ring", "grow_denied_heap", ring.grow_denied_heap);
    E("usb_ring", "grow_denied_largest", ring.grow_denied_largest);
    E("usb_ring", "ring_max_bytes", ring.max_bytes);
    /* Where the time goes, in microseconds (sums wrap at 71 min: take two readings). Wi-Fi to host: the ring's cold start is the wait of the first frame
     * of a burst, commit to NTB (relay wake + deferral + TinyUSB task). Host to Wi-Fi: queueing and the transmit call. pm_note is the cost of the
     * clock raise inside the callback. */
    E("timing", "cold_starts", ring.cold_starts);
    E("timing", "cold_us_sum", ring.cold_us_sum);
    E("timing", "cold_us_max", ring.cold_us_max);
    E("timing", "pm_notes", l2.pm_notes);
    E("timing", "pm_note_us_sum", l2.pm_note_us_sum);
    E("timing", "pm_note_us_max", l2.pm_note_us_max);
    E("timing", "wait_us_sum", l2.h2w_wait_us_sum);
    E("timing", "wait_us_max", l2.h2w_wait_us_max);
    E("timing", "tx_us_sum", l2.h2w_tx_us_sum);
    E("timing", "tx_us_max", l2.h2w_tx_us_max);
    E("wifi_tx", "installed", wifi_pins_installed);
    E("wifi_tx", "tx_done_cb", wifi_pins_tx_done_ok);
    E("wifi_tx", "charged", atomic_load(&wifi_pins.tx_charged));
    E("wifi_tx", "done", atomic_load(&wifi_pins.tx_done));
    E("wifi_tx", "aborted", atomic_load(&wifi_pins.tx_aborted));
    E("wifi_tx", "flushed", atomic_load(&wifi_pins.tx_flushed));
    E("wifi_tx", "stale", atomic_load(&wifi_pins.tx_stale));
    E("wifi_tx", "unmatched", atomic_load(&wifi_pins.tx_unmatched));
    E("wifi_tx", "inflight", wifi_pins_tx_outstanding());
    E("wifi_tx", "high_water", atomic_load(&wifi_pins.tx_high_water));
    E("wifi_tx", "refused_pool", atomic_load(&wifi_pins.tx_refused_pool));
    E("wifi_tx", "refused_heap", atomic_load(&wifi_pins.tx_refused_heap));
#undef E
}

extern void mgmt_write(const char *s);
enum { BRIDGE_LINE_MAX = 384 };
typedef struct {
    char line[BRIDGE_LINE_MAX];
    size_t used;
    const char *section;
} bridge_line_ctx;
static void bridge_line_flush(bridge_line_ctx *c) {
    if (!c->section) return;
    memcpy(c->line + c->used, "\r\n", 3);       /* emit() always leaves room for these */
    mgmt_write(c->line);
    c->section = NULL;
    c->used = 0;
}
static void bridge_line_emit(void *ctx, const char *section, const char *name, int64_t value) {
    bridge_line_ctx *c = ctx;
    if (c->section && strcmp(c->section, section)) bridge_line_flush(c);
    if (!c->section) {
        c->used = (size_t)snprintf(c->line, sizeof(c->line), "bridge_%s", section);
        c->section = section;
    }
    const size_t room = sizeof(c->line) - c->used - 3;
    const int n = snprintf(c->line + c->used, room + 1, " %s=%lld", name, (long long)value);
    if (n > 0 && (size_t)n <= room) c->used += (size_t)n;   /* a field that would not fit is left out whole (the host test pins every line below the limit) */
}
/* The serial `status` lines. Not called in tailnet mode: the counters would all read zero. */
static void bridge_status_lines(void) {
    bridge_line_ctx c = {.used = 0, .section = NULL};
    bridge_visit(bridge_line_emit, &c);
    bridge_line_flush(&c);
}
