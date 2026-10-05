// SPDX-License-Identifier: MIT
/* Cases for the non-blocking transmit ring in the real tinyusb_net.c.
 * Each frame carries a sequence number and a length-derived fill pattern, so the USB-side
 * observer can prove every accepted frame is delivered exactly once, in order, uncorrupted. */
#define CAP (3u * 1524u + 4u)   /* the gateway ring: three full frames */
static int free_count_ring;
static void released_ring(void *cookie, void *ctx) { (void)ctx; assert(cookie); free(cookie); free_count++; free_count_ring++; }
static unsigned long long rng = 88172645463325252ull;
static unsigned rnd(unsigned n) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (unsigned)(rng % n); }

static uint32_t next_seq, delivered_seq, delivered_frames;
static void observe(const uint8_t *p, uint16_t n) {
    uint32_t seq;
    memcpy(&seq, p, sizeof(seq));
    assert(seq == delivered_seq);                    /* in order, none skipped, none repeated */
    for (uint16_t i = 4; i < n; i++) assert(p[i] == (uint8_t)(seq + n + i));
    delivered_seq++;
    delivered_frames++;
}
static esp_err_t send_frame(uint16_t n, uint32_t *accepted_seq) {
    uint8_t f[1518];
    memcpy(f, &next_seq, sizeof(next_seq));
    for (uint16_t i = 4; i < n; i++) f[i] = (uint8_t)(next_seq + n + i);
    in_producer = 1;
    esp_err_t e = tinyusb_net_tx_ring_send(f, n);
    in_producer = 0;
    if (e == ESP_OK) { *accepted_seq = next_seq; next_seq++; }
    return e;
}
/* Frames that were refused never reach USB, so they do not consume a sequence number. */
static esp_err_t send_len(uint16_t n) { uint32_t s; return send_frame(n, &s); }
/* One worker wakeup plus every TinyUSB callback it queued. */
static void pump(void) { tx_worker_step(); run_deferred(); }
/* The host took an NTB: TinyUSB's transfer-complete event for the IN endpoint. */
static void in_complete(void) { __wrap_netd_xfer_cb(0, 0x81, 0, 64); }
static uint32_t used_bytes(void) { return s_tx.head >= s_tx.tail ? s_tx.head - s_tx.tail : CAP - s_tx.tail + s_tx.head; }
/* Move both pointers to `off` (ring must be empty) so a case can start at any write position. */
static void park_at(uint32_t off) { assert(s_tx.head == s_tx.tail); s_tx.head = s_tx.tail = off; }
static void reset_counters(void) { delivered_seq = next_seq = delivered_frames = 0; }

static void test_lifecycle(void) {
    tinyusb_net_tx_stats_t st;
    uint8_t f[100] = {0};
    assert(tinyusb_net_tx_ring_send(f, 100) == ESP_ERR_INVALID_STATE);   /* not started */
    assert(tinyusb_net_tx_ring_start(2000, 5) == ESP_ERR_INVALID_ARG);   /* below two frames */
    assert(tinyusb_net_tx_ring_start(2 * 1524, 5) == ESP_ERR_INVALID_ARG);  /* two frames and no spare word */
    task_create_fail = 1;
    assert(tinyusb_net_tx_ring_start(CAP, 5) == ESP_ERR_NO_MEM && s_tx.buf == NULL);
    task_create_fail = 0;
    assert(tinyusb_net_tx_ring_start(CAP, 5) == ESP_OK && task_created == 1 && task_prio == 5);
    assert(task_stack == 1536);
    assert(tinyusb_net_tx_ring_start(CAP, 5) == ESP_OK && task_created == 1);   /* idempotent */
    assert(tinyusb_net_tx_ring_start(CAP + 4096, 5) == ESP_ERR_INVALID_STATE);
    assert(tinyusb_net_tx_ring_send(NULL, 100) == ESP_ERR_INVALID_ARG);
    assert(tinyusb_net_tx_ring_send(f, 13) == ESP_ERR_INVALID_ARG);
    assert(tinyusb_net_tx_ring_send(f, 1519) == ESP_ERR_INVALID_ARG);
    usb_ready = 0;
    assert(tinyusb_net_tx_ring_send(f, 100) == ESP_ERR_INVALID_STATE);
    usb_ready = 1;
    tinyusb_net_tx_ring_stats(&st);
    assert(st.ring_bytes == CAP && st.dropped_invalid == 3 && st.dropped_link_down == 1 && st.enqueued_frames == 0);
    assert(st.worker_stack_free == 777);
    tinyusb_net_deinit();                                                /* stops accepting */
    assert(tinyusb_net_tx_ring_send(f, 100) == ESP_ERR_INVALID_STATE);
    tinyusb_net_config_t cfg = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&cfg) == ESP_OK);            /* deinit cleared the callbacks */
    assert(tinyusb_net_tx_ring_start(CAP, 5) == ESP_OK);
    s_tx.gen = 0; s_tx.down_seen = false;
}

static void test_basic_and_no_blocking(void) {
    reset_counters();
    xmit_hook = observe;
    int pend = pending;
    for (int i = 0; i < 3; i++) assert(send_len(200 + i) == ESP_OK);
    /* The producer only notified the worker: it did not touch TinyUSB's queue and nothing ran yet. */
    assert(pending == pend && delivered_frames == 0 && notify_count == 3);
    pump();
    assert(delivered_frames == 3 && s_tx.tail == s_tx.head && !s_tx.blocked);
    /* The worker only ever sleeps indefinitely: there is no polling timer. */
    assert(last_notify_wait == portMAX_DELAY);
    tinyusb_net_tx_stats_t st;
    tinyusb_net_tx_ring_stats(&st);
    assert(st.enqueued_frames == 3 && st.sent_frames == 3 && st.sent_bytes == 200 + 201 + 202 && st.dropped_full == 0);
    /* Idle worker with an empty ring does not queue a callback. */
    notify_count = 1;
    tx_worker_step();
    assert(pending == 0);
}

/* Exactly three maximum frames fit, wherever the write pointer is, including positions where
 * the third payload straddles the end of the buffer; the fourth is refused. */
static void test_capacity_at_every_position(void) {
    reset_counters();
    xmit_hook = observe;
    for (uint32_t off = 0; off < CAP; off += 4) {
        ntb_credit = -1;
        pump();
        park_at(off);
        ntb_credit = 0;                                 /* hold everything in the ring */
        for (int i = 0; i < 3; i++) assert(send_len(1518) == ESP_OK);
        assert(send_len(1518) == ESP_ERR_NO_MEM);
        assert(used_bytes() == 3 * 1524);
        ntb_credit = -1;
        pump();
        assert(s_tx.head == s_tx.tail);
    }
    assert(delivered_frames == 3 * (CAP / 4));
}

static void test_backpressure_and_drop_accounting(void) {
    reset_counters();
    park_at(0);
    ntb_credit = 0;                                   /* every NTB is in flight */
    unsigned accepted = 0;
    esp_err_t e;
    uint32_t drops_before = s_tx.drop_full;
    for (int i = 0; i < 100; i++) {
        e = send_len(1400);
        if (e != ESP_OK) { assert(e == ESP_ERR_NO_MEM); break; }
        accepted++;
    }
    assert(e == ESP_ERR_NO_MEM);
    /* 1404-byte records in a 4576-byte ring with one word spare: exactly 3 fit. */
    assert(accepted == 3);
    for (int i = 0; i < 10; i++) assert(send_len(1400) == ESP_ERR_NO_MEM);
    assert(s_tx.drop_full == drops_before + 11);
    pump();                                            /* drain stops, frames stay queued */
    assert(delivered_frames == 0 && s_tx.blocked && s_tx.blocked_events >= 1);
    uint32_t ev = s_tx.blocked_events;
    /* Nothing polls: with no new frame and no completion the worker sleeps and nothing moves. */
    notify_count = 0;
    pump(); pump();
    assert(last_notify_wait == portMAX_DELAY && delivered_frames == 0 && s_tx.blocked_events == ev);
    /* The host takes one NTB: its completion event moves exactly one frame, in order. */
    ntb_credit = 1;
    int calls = real_xfer_calls;
    in_complete();
    assert(real_xfer_calls == calls + 1);              /* the real driver ran first */
    assert(delivered_frames == 1 && s_tx.blocked && pending == 0);
    ntb_credit = -1;
    in_complete();
    assert(delivered_frames == 3 && !s_tx.blocked && s_tx.head == s_tx.tail);
    /* Space returns after delivery. */
    assert(send_len(1400) == ESP_OK);
    pump();
    assert(delivered_frames == 4);
}

static void test_xfer_complete_event(void) {
    reset_counters();
    xmit_hook = observe;
    tinyusb_net_tx_stats_t st;
    /* OUT completions are not transmit events: the real handler runs, the ring is left alone. */
    ntb_credit = 0;
    assert(send_len(300) == ESP_OK);
    ntb_credit = -1;
    int calls = real_xfer_calls;
    __wrap_netd_xfer_cb(0, 0x01, 0, 64);
    assert(real_xfer_calls == calls + 1 && delivered_frames == 0);
    /* IN completion drains straight away, no worker, no deferred callback. */
    int pend = pending;
    in_complete();
    assert(delivered_frames == 1 && pending == pend);
    tinyusb_net_tx_ring_stats(&st);
    assert(st.xfer_events >= 1);
    /* Empty ring: a completion is a cheap no-op. */
    in_complete();
    assert(delivered_frames == 1);
    /* Not started or deinitialised: the real handler still runs and nothing else does. */
    tinyusb_net_deinit();
    assert(send_len(300) == ESP_ERR_INVALID_STATE);
    calls = real_xfer_calls;
    uint32_t before = s_tx.xfer_events;
    in_complete();
    assert(real_xfer_calls == calls + 1 && s_tx.xfer_events == before);
    tinyusb_net_config_t cfg = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&cfg) == ESP_OK && tinyusb_net_tx_ring_start(CAP, 5) == ESP_OK);
}

static void test_flush_on_link_loss(void) {
    reset_counters();
    xmit_hook = observe;
    ntb_credit = 0;
    for (int i = 0; i < 3; i++) assert(send_len(500) == ESP_OK);
    pump();
    assert(s_tx.blocked && delivered_frames == 0);
    uint32_t flushed = s_tx.flushed;
    /* Cable pulled and replugged while frames are queued, with no drain in between: the producer
     * notices the outage on its next attempt, and the stale frames never reach the new host. */
    usb_ready = 0;
    assert(send_len(500) == ESP_ERR_INVALID_STATE);
    assert(send_len(500) == ESP_ERR_INVALID_STATE);    /* one generation bump per outage */
    assert(s_tx.gen == 1);
    usb_ready = 1;
    ntb_credit = -1;
    delivered_seq = next_seq;                          /* the 3 stale frames are never observed */
    assert(send_len(500) == ESP_OK);
    pump();
    assert(delivered_frames == 1 && s_tx.flushed == flushed + 3 && s_tx.head == s_tx.tail);
    /* Queued frames are also discarded when a drain runs while USB is down. */
    ntb_credit = 0;
    for (int i = 0; i < 2; i++) assert(send_len(500) == ESP_OK);
    pump();
    flushed = s_tx.flushed;
    usb_ready = 0;
    pump(); in_complete();
    assert(s_tx.flushed == flushed + 2 && s_tx.head == s_tx.tail && !s_tx.blocked);
    usb_ready = 1;
    ntb_credit = -1;
    delivered_seq = next_seq;
    assert(send_len(500) == ESP_OK);
    pump();
    assert(delivered_frames == 2);
    assert(s_tx.gen == 1);                             /* that outage was seen by the drain only */
}

static void test_duplicate_and_stale_callbacks(void) {
    reset_counters();
    xmit_hook = observe;
    for (int i = 0; i < 4; i++) assert(send_len(300) == ESP_OK);
    pump();
    assert(delivered_frames == 4);
    /* Old/duplicate drain callbacks (timed-out wakeups, retries racing a drain) are harmless. */
    for (int i = 0; i < 20; i++) do_drain(NULL);
    for (int i = 0; i < 20; i++) in_complete();
    assert(delivered_frames == 4);
    /* Replay while a new frame is queued: it is delivered once, not once per callback. */
    assert(send_len(300) == ESP_OK);
    for (int i = 0; i < 5; i++) do_drain(NULL);
    assert(delivered_frames == 5);
    /* A worker wakeup after the drain already ran finds nothing and queues nothing. */
    pump();
    assert(pending == 0 && delivered_frames == 5);
    /* Worker defers once per outstanding request, not once per frame. */
    for (int i = 0; i < 3; i++) assert(send_len(300) == ESP_OK);
    tx_worker_step(); tx_worker_step(); tx_worker_step();
    assert(pending == 1);
    run_deferred();
    assert(delivered_frames == 8);
}

static void test_sync_and_ring_share_the_pipe(void) {
    reset_counters();
    int frees = free_count;
    for (int i = 0; i < 20; i++) {
        assert(send_len(150) == ESP_OK);
        uint8_t *p = malloc(100);
        memset(p, 7, 100);
        xmit_hook = NULL;
        schedule = 0; allow_tx = 1;
        esp_err_t e = tinyusb_net_send_sync(p, 100, p, 20);
        assert(e == ESP_OK);                             /* released by the free callback, once */
        xmit_hook = observe;
        pump();
    }
    assert(delivered_frames == 20);
    assert(free_count == frees + 20);                    /* ring frames never call the free callback */
}

/* Randomized soak: random sizes, wrap-around and straddling payloads, random NTB availability,
 * random link flaps, random duplicate callbacks, drains from both triggers.
 * Invariant: accepted == delivered + flushed + queued, in order, bytes intact. */
static void test_soak(void) {
    reset_counters();
    xmit_hook = observe;
    unsigned long accepted = 0, dropped = 0, straddled = 0;
    uint32_t sent0 = s_tx.sent_frames, flushed0 = s_tx.flushed;
    for (int round = 0; round < 300000; round++) {
        unsigned op = rnd(12);
        if (op < 6) {
            uint16_t n = (rnd(4) == 0) ? 14 + rnd(60) : 14 + rnd(1505);
            uint32_t head = s_tx.head;
            esp_err_t e = send_len(n);
            if (e == ESP_OK) { accepted++; if (head + 4 + n > CAP) straddled++; }
            else { assert(e == ESP_ERR_NO_MEM); dropped++; }
        } else if (op < 8) {
            ntb_credit = rnd(3) == 0 ? 0 : (int)rnd(6);
            if (rnd(4) == 0) ntb_credit = -1;
            pump();
        } else if (op == 8) {
            do_drain(NULL);
        } else if (op < 11) {
            if (rnd(3) == 0) ntb_credit = -1;
            in_complete();
        } else if (rnd(40) == 0) {
            /* An outage: the producer sees it (or only a drain does), then USB comes back. */
            usb_ready = 0;
            if (rnd(2)) assert(send_len(100) == ESP_ERR_INVALID_STATE); else pump();
            usb_ready = 1;
            /* Frames queued before the outage that were not drained yet become stale (or are
             * flushed by the drain); either way they are not observed. Resynchronise. */
            ntb_credit = -1;
            if (rnd(2)) { usb_ready = 0; in_complete(); usb_ready = 1; }
            delivered_seq = next_seq;
        }
        uint32_t used = used_bytes();
        assert(used < CAP);                                /* never full to the brim, never overrun */
        assert(s_tx.head < CAP && s_tx.tail < CAP && s_tx.head % 4 == 0 && s_tx.tail % 4 == 0);
    }
    ntb_credit = -1; pump(); do_drain(NULL);
    assert(s_tx.head == s_tx.tail);
    uint32_t sent = s_tx.sent_frames - sent0, flushed = s_tx.flushed - flushed0;
    assert(accepted == sent + flushed);                    /* every accepted frame left the ring once */
    assert(delivered_frames == sent);
    assert(dropped > 0 && sent > 1000 && straddled > 1000);/* the schedule exercised all of it */
    printf("soak: %lu accepted (%lu straddling the ring end), %lu sent, %lu flushed, %lu dropped (ring full)\n",
           accepted, straddled, (unsigned long)sent, (unsigned long)flushed, dropped);
}

int main(void) {
    tinyusb_net_config_t cfg = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&cfg) == ESP_OK);
    test_lifecycle();
    test_basic_and_no_blocking();
    test_capacity_at_every_position();
    test_backpressure_and_drop_accounting();
    test_xfer_complete_event();
    test_flush_on_link_loss();
    test_duplicate_and_stale_callbacks();
    test_sync_and_ring_share_the_pipe();
    test_soak();
    tinyusb_net_tx_stats_t st;
    tinyusb_net_tx_ring_stats(&st);
    assert(st.high_water_bytes > 0 && st.high_water_bytes < CAP);
    printf("PASS: TinyUSB transmit ring: non-blocking producer, byte-exact capacity, exactly-once delivery, event-driven drain, link-generation flush, duplicate callbacks, sync coexistence\n");
}
