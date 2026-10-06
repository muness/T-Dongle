/* The transparent bridge's counters (ADR 0023): where every frame went, and what the buffers and the Wi-Fi budget did meanwhile.
 * Included by gateway_main.c after wifi_pins.inc. One visitor lists them, two renderers print them, so the serial `status` lines and the
 * diagnostics `bridge` report cannot drift apart:
 *   serial `status` (bridge mode)  new lines only, one per section: bridge_link, bridge_to_host, bridge_to_wifi, bridge_ecn, bridge_rx_class, bridge_usb_ring,
 *                                  bridge_timing, bridge_wifi_tx. Android parses the first status lines with end-anchored patterns, so nothing is ever
 *                                  appended to a line that existed before (tools/check-android-status.py holds that line);
 *   `bridge` (diagnostics build)   one JSON line, keys "<section>_<name>".
 * Identities that hold at rest (tests/test_bridge_path.c checks them on the real code):
 *   to_host.frames  = forwarded + invalid + own_mac + link_down + usb_not_ready + ring_full
 *   to_wifi.frames  = queued + invalid + foreign_mac + link_down   (held offers are not frames)
 *   to_wifi.queued  = sent + stale + sojourn_drop + link_down_queued + tx_failed + codel_drop + queue_depth
 *   wifi_tx.charged = done + aborted + flushed + stale + inflight (wifi_pin_budget.h) */
typedef void (*bridge_emit_fn)(void *ctx, const char *section, const char *name, int64_t value);
static void bridge_visit(bridge_emit_fn emit, void *ctx) {
    tdongle_l2_stats_t l2;
    tdongle_l2_stats(&l2);
    tinyusb_net_tx_stats_t ring;
    tinyusb_net_tx_ring_stats(&ring);
    tinyusb_net_rx_stats_t rx;
    tinyusb_net_rx_stats(&rx);
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
    E("to_wifi", "held", l2.h2w_held);
    E("to_wifi", "resumes", l2.h2w_resumes);
    E("to_wifi", "sent", l2.h2w_sent);
    E("to_wifi", "stale", l2.h2w_stale);
    E("to_wifi", "sojourn_drop", l2.h2w_sojourn_drop);
    E("to_wifi", "link_down_queued", l2.h2w_link_down_queued);
    E("to_wifi", "tx_failed", l2.h2w_tx_failed);
    E("to_wifi", "tx_retries", l2.h2w_tx_retries);
    E("to_wifi", "last_tx_error", l2.h2w_last_tx_error);
    E("to_wifi", "queue_depth", l2.h2w_queue_depth);
    E("to_wifi", "queue_high_water", l2.h2w_queue_high_water);
    E("to_wifi", "codel_signals", l2.h2w_codel_signals);
    E("to_wifi", "ce_marked", l2.h2w_ce_marked);
    E("to_wifi", "codel_drop", l2.h2w_codel_drop);
    E("to_wifi", "codel_count", l2.h2w_codel_count);
    /* ECN across the bridge, counted whether or not CoDel is on: what the host's frames carry, and whether a server ever accepted an ECN setup. A CoDel that
     * marks nothing is either not seeing ECT frames (capable stays 0: ECN was not negotiated end to end) or not signalling. */
    E("ecn", "not_ect", l2.h2w_ecn_not_ect);
    E("ecn", "capable", l2.h2w_ecn_capable);
    E("ecn", "ce", l2.h2w_ecn_ce);
    E("ecn", "exempt", l2.h2w_ecn_exempt);
    E("ecn", "not_ip", l2.h2w_ecn_not_ip);
    E("ecn", "syn_setup", l2.h2w_syn_ecn_setup);
    E("ecn", "synack_accept", l2.w2h_synack_ecn);
    /* The host side of the standing queue: the class driver's OUT NTBs. datagrams / ntbs is frames per NTB (how many its 3 buffers can hold); dwell is
     * the time since the newest NTB arrived (a held datagram ages here); hold_us is how long the host was kept waiting for room, per hold episode. */
    E("rx_class", "ntbs", rx.ntbs);
    E("rx_class", "ntb_bytes", rx.ntb_bytes);
    E("rx_class", "ntb_max_bytes", rx.ntb_max_bytes);
    E("rx_class", "datagrams", rx.datagrams);
    E("rx_class", "dwell_us_sum", rx.dwell_us_sum);
    E("rx_class", "dwell_us_max", rx.dwell_us_max);
    E("rx_class", "holds", rx.holds);
    E("rx_class", "hold_us_sum", rx.hold_us_sum);
    E("rx_class", "hold_us_max", rx.hold_us_max);
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
    /* The radio's dwell: frames that found the allowance full, and how long each waited for a tx-done to free a charge. */
    /* The CoDel input per eligible frame: max(its own time in the dongle, time the pipe has been continuously full). */
    E("timing", "signal_us_sum", l2.h2w_signal_us_sum);
    E("timing", "signal_us_max", l2.h2w_signal_us_max);
    E("timing", "room_waits", l2.h2w_room_waits);
    E("timing", "room_wait_us_sum", l2.h2w_room_wait_us_sum);
    E("timing", "room_wait_us_max", l2.h2w_room_wait_us_max);
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
enum { BRIDGE_LINE_MAX = 448 };
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

#ifdef GATEWAY_BRIDGE_TUNE
/* `bridgetune` (diagnostics build only; not persisted): the bridge's queue constants as run-time knobs, so one flashed image can be swept on the board.
 *   bridgetune                                  print the current values and the bounds
 *   bridgetune q=3 resume=1 inflight=6 ring=10 sojourn_ms=100 codel=0 target_us=5000 interval_ms=100     any subset; all bounds are checked first,
 *                                                                                                       a rejected command changes nothing
 *     q          host -> Wi-Fi standing queue limit before the host is NAKed (1..TDONGLE_L2_HOST_SLOTS)
 *     resume     drain to this depth before the held datagram is offered again (0..q-1)
 *     inflight   frames the radio is given at once (GATEWAY_WIFI_TX_BAND_MAX..GATEWAY_WIFI_TX_POOL)
 *     ring       elastic chunks of the Wi-Fi -> host ring, 2 frames each on top of the 8 permanent (0..TINYUSB_NET_TX_MAX_CHUNKS)
 *     sojourn_ms age at which a queued frame is dropped (TDONGLE_L2_SOJOURN_MS_MIN..MAX)
 *     codel      0/1: CoDel at the host -> Wi-Fi ingress: ECT frames are marked CE, others dropped (tdongle_aqm.h; counters codel_*, ce_marked)
 *     target_us  CoDel's target for the standing-queue signal (TDONGLE_L2_CODEL_TARGET_US_MIN..MAX)
 *     interval_ms CoDel's interval (TDONGLE_L2_CODEL_INTERVAL_MS_MIN..MAX)
 *     idle_us    a gap this long between the host's datagrams (none held) ends its busy period: the CoDel signal is the age of that period */
typedef struct { unsigned q, resume, inflight, ring, sojourn_ms, codel, target_us, interval_ms, idle_us; } bridge_tune_t;
static void bridge_tune_get(bridge_tune_t *t) {
    tdongle_l2_tuning_t l;
    tdongle_l2_get_tuning(&l);
    unsigned inflight = wifi_pins_tx_limit_now();
    *t = (bridge_tune_t){.q = l.queue_limit, .resume = l.resume_depth, .inflight = inflight ? inflight : (unsigned)GATEWAY_WIFI_TX_POOL,
                         .ring = tinyusb_net_tx_ring_max_chunks(), .sojourn_ms = l.sojourn_ms, .codel = l.codel, .target_us = l.codel_target_us,
                         .interval_ms = l.codel_interval_ms, .idle_us = l.host_idle_us};
}
static const char *bridge_tune_check(const bridge_tune_t *t) {
    if (t->q < 1 || t->q > TDONGLE_L2_HOST_SLOTS) return "q out of range";
    if (t->resume >= t->q) return "resume must be below q";
    if (t->inflight < GATEWAY_WIFI_TX_BAND_MAX || t->inflight > GATEWAY_WIFI_TX_POOL) return "inflight out of range";
    if (t->ring > TINYUSB_NET_TX_MAX_CHUNKS) return "ring out of range";
    if (t->sojourn_ms < TDONGLE_L2_SOJOURN_MS_MIN || t->sojourn_ms > TDONGLE_L2_SOJOURN_MS_MAX) return "sojourn_ms out of range";
    if (t->codel > 1) return "codel must be 0 or 1";
    if (t->target_us < TDONGLE_L2_CODEL_TARGET_US_MIN || t->target_us > TDONGLE_L2_CODEL_TARGET_US_MAX) return "target_us out of range";
    if (t->interval_ms < TDONGLE_L2_CODEL_INTERVAL_MS_MIN || t->interval_ms > TDONGLE_L2_CODEL_INTERVAL_MS_MAX) return "interval_ms out of range";
    if (t->idle_us < TDONGLE_L2_HOST_IDLE_US_MIN || t->idle_us > TDONGLE_L2_HOST_IDLE_US_MAX) return "idle_us out of range";
    return NULL;
}
/* Parse "key=value ..." over the current values. NULL: ok; else the error text. */
static const char *bridge_tune_parse(const char *args, bridge_tune_t *t) {
    char text[128];
    if (strlcpy(text, args, sizeof(text)) >= sizeof(text)) return "too long";
    char *save = NULL;
    for (char *tok = strtok_r(text, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
        char *eq = strchr(tok, '=');
        if (!eq || eq == tok || !eq[1]) return "expected key=value";
        *eq = 0;
        char *end;
        const unsigned long v = strtoul(eq + 1, &end, 10);
        if (*end || v > 10000000ul) return "value is not a number";
        unsigned *field = !strcmp(tok, "q") ? &t->q : !strcmp(tok, "resume") ? &t->resume : !strcmp(tok, "inflight") ? &t->inflight :
                          !strcmp(tok, "ring") ? &t->ring : !strcmp(tok, "sojourn_ms") ? &t->sojourn_ms : !strcmp(tok, "codel") ? &t->codel :
                          !strcmp(tok, "target_us") ? &t->target_us : !strcmp(tok, "interval_ms") ? &t->interval_ms : !strcmp(tok, "idle_us") ? &t->idle_us : NULL;
        if (!field) return "unknown key";
        *field = (unsigned)v;
    }
    return NULL;
}
/* Check everything, then apply everything. */
static const char *bridge_tune_apply(const bridge_tune_t *t) {
    const char *error = bridge_tune_check(t);
    if (error) return error;
    const tdongle_l2_tuning_t l = {.queue_limit = t->q, .resume_depth = t->resume, .sojourn_ms = t->sojourn_ms, .codel = t->codel != 0,
                                   .codel_target_us = t->target_us, .codel_interval_ms = t->interval_ms, .host_idle_us = t->idle_us};
    if (tdongle_l2_set_tuning(&l) != ESP_OK) return "the bridge is not running";
    wifi_pins_set_tx_limit(t->inflight);
    if (tinyusb_net_tx_ring_set_max_chunks(t->ring) != ESP_OK) return "the ring is not running";
    return NULL;
}
static void bridge_tune_command(const char *args) {
    bridge_tune_t t;
    bridge_tune_get(&t);
    while (*args == ' ') args++;
    if (*args) {
        bridge_tune_t wanted = t;
        const char *error = bridge_tune_parse(args, &wanted);
        if (!error) error = bridge_tune_apply(&wanted);
        if (error) {
            char line[96];
            snprintf(line, sizeof(line), "ERR bridgetune: %s\r\n", error);
            mgmt_write(line);
        }
        bridge_tune_get(&t);
    }
    char line[240];
    snprintf(line, sizeof(line), "bridgetune q=%u resume=%u inflight=%u ring=%u sojourn_ms=%u codel=%u target_us=%u interval_ms=%u idle_us=%u\r\n", t.q, t.resume, t.inflight, t.ring,
             t.sojourn_ms, t.codel, t.target_us, t.interval_ms, t.idle_us);
    mgmt_write(line);
    snprintf(line, sizeof(line), "bridgetune_bounds q=1..%u resume=0..q-1 inflight=%u..%u ring=0..%u sojourn_ms=%u..%u codel=0..1 target_us=%u..%u interval_ms=%u..%u idle_us=%u..%u\r\n",
             (unsigned)TDONGLE_L2_HOST_SLOTS, (unsigned)GATEWAY_WIFI_TX_BAND_MAX, (unsigned)GATEWAY_WIFI_TX_POOL, (unsigned)TINYUSB_NET_TX_MAX_CHUNKS,
             (unsigned)TDONGLE_L2_SOJOURN_MS_MIN, (unsigned)TDONGLE_L2_SOJOURN_MS_MAX, (unsigned)TDONGLE_L2_CODEL_TARGET_US_MIN, (unsigned)TDONGLE_L2_CODEL_TARGET_US_MAX,
             (unsigned)TDONGLE_L2_CODEL_INTERVAL_MS_MIN, (unsigned)TDONGLE_L2_CODEL_INTERVAL_MS_MAX, (unsigned)TDONGLE_L2_HOST_IDLE_US_MIN, (unsigned)TDONGLE_L2_HOST_IDLE_US_MAX);
    mgmt_write(line);
}
#endif
