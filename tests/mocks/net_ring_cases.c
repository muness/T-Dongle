// SPDX-License-Identifier: MIT
/* Cases for the non-blocking transmit ring in the real tinyusb_net.c.
 * Each frame carries a sequence number and a length-derived fill pattern, so the USB-side
 * observer can prove every accepted frame is delivered exactly once, in order, uncorrupted. */
#define CAP 6144u
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
static void reset_counters(void) { delivered_seq = next_seq = delivered_frames = 0; }

static void test_lifecycle(void) {
    tinyusb_net_tx_stats_t st;
    uint8_t f[100] = {0};
    assert(tinyusb_net_tx_ring_send(f, 100) == ESP_ERR_INVALID_STATE);   /* not started */
    assert(tinyusb_net_tx_ring_start(2000, 5) == ESP_ERR_INVALID_ARG);   /* below two frames */
    task_create_fail = 1;
    assert(tinyusb_net_tx_ring_start(CAP, 5) == ESP_ERR_NO_MEM && s_tx.buf == NULL);
    task_create_fail = 0;
    assert(tinyusb_net_tx_ring_start(CAP, 5) == ESP_OK && task_created == 1 && task_prio == 5);
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
    tinyusb_net_deinit();                                                /* stops accepting */
    assert(tinyusb_net_tx_ring_send(f, 100) == ESP_ERR_INVALID_STATE);
    tinyusb_net_config_t cfg = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&cfg) == ESP_OK);            /* deinit cleared the callbacks */
    assert(tinyusb_net_tx_ring_start(CAP, 5) == ESP_OK);
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
    /* Sleeps indefinitely when idle (no polling, no heat). */
    assert(last_notify_wait == portMAX_DELAY);
    tinyusb_net_tx_stats_t st;
    tinyusb_net_tx_ring_stats(&st);
    assert(st.enqueued_frames == 3 && st.sent_frames == 3 && st.sent_bytes == 200 + 201 + 202 && st.dropped_full == 0);
    /* Idle worker with an empty ring does not queue a callback. */
    notify_count = 1;
    tx_worker_step();
    assert(pending == 0);
}

static void test_backpressure_and_drop_accounting(void) {
    reset_counters();
    /* Capacity depends on where the write pointer sits; start from offset 0 for an exact count. */
    assert(s_tx.head == s_tx.tail);
    s_tx.head = s_tx.tail = 0;
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
    /* 1404-byte records in a 6144-byte ring with one word spare: exactly 4 fit. */
    assert(accepted == 4);
    for (int i = 0; i < 10; i++) assert(send_len(1400) == ESP_ERR_NO_MEM);
    assert(s_tx.drop_full == drops_before + 11);
    pump();                                            /* drain stops, frames stay queued */
    assert(delivered_frames == 0 && s_tx.blocked && s_tx.blocked_events >= 1);
    uint32_t ev = s_tx.blocked_events;
    /* While blocked the worker polls once per tick instead of sleeping forever. */
    notify_count = 0;
    pump();
    assert(last_notify_wait == 1 && delivered_frames == 0 && s_tx.blocked_events == ev);
    pump(); pump();
    assert(delivered_frames == 0);
    /* The host takes one NTB: exactly one frame moves, in order, the rest wait. */
    ntb_credit = 1;
    pump();
    assert(delivered_frames == 1 && s_tx.blocked);
    ntb_credit = -1;
    pump();
    assert(delivered_frames == 4 && !s_tx.blocked);
    /* Space returns after delivery. */
    assert(send_len(1400) == ESP_OK);
    pump();
    assert(delivered_frames == 5);
}

static void test_flush_on_link_loss(void) {
    reset_counters();
    ntb_credit = 0;
    for (int i = 0; i < 3; i++) assert(send_len(500) == ESP_OK);
    pump();
    assert(s_tx.blocked && delivered_frames == 0);
    uint32_t flushed = s_tx.flushed;
    usb_ready = 0;                                     /* cable pulled while frames are queued */
    pump();
    assert(s_tx.flushed == flushed + 3 && s_tx.tail == s_tx.head && delivered_frames == 0 && !s_tx.blocked);
    usb_ready = 1;
    ntb_credit = -1;
    next_seq = delivered_seq = 0;                      /* flushed frames never reach USB */
    assert(send_len(500) == ESP_OK);
    pump();
    assert(delivered_frames == 1);
}

static void test_duplicate_and_stale_callbacks(void) {
    reset_counters();
    for (int i = 0; i < 4; i++) assert(send_len(300) == ESP_OK);
    void (*queued)(void*);
    pump();
    assert(delivered_frames == 4);
    /* Old/duplicate drain callbacks (timed-out wakeups, retries racing a drain) are harmless. */
    for (int i = 0; i < 20; i++) { queued = do_drain; queued(NULL); }
    assert(delivered_frames == 4);
    /* Replay while a new frame is queued: it is delivered once, not once per callback. */
    assert(send_len(300) == ESP_OK);
    for (int i = 0; i < 5; i++) do_drain(NULL);
    assert(delivered_frames == 5);
    /* A worker wakeup after the drain already ran finds nothing and queues nothing. */
    pump();
    assert(pending == 0 && delivered_frames == 5);
    /* Worker defers once per outstanding request, not once per frame. */
    ntb_credit = -1;
    for (int i = 0; i < 4; i++) assert(send_len(300) == ESP_OK);
    tx_worker_step(); tx_worker_step(); tx_worker_step();
    assert(pending == 1);
    run_deferred();
    assert(delivered_frames == 9);
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

/* Randomized soak: random sizes, wrap-around, random NTB availability, random link flaps,
 * random duplicate callbacks. Invariant: accepted == delivered + flushed + queued, in order. */
static void test_soak(void) {
    reset_counters();
    xmit_hook = observe;
    unsigned long accepted = 0, dropped = 0;
    uint32_t sent0 = s_tx.sent_frames, flushed0 = s_tx.flushed;
    for (int round = 0; round < 200000; round++) {
        unsigned op = rnd(10);
        if (op < 6) {
            uint16_t n = (rnd(4) == 0) ? 14 + rnd(60) : 14 + rnd(1505);
            esp_err_t e = send_len(n);
            if (e == ESP_OK) accepted++; else { assert(e == ESP_ERR_NO_MEM); dropped++; }
        } else if (op < 8) {
            ntb_credit = rnd(3) == 0 ? 0 : (int)rnd(6);
            if (rnd(4) == 0) ntb_credit = -1;
            pump();
        } else if (op == 8) {
            do_drain(NULL);
        } else if (rnd(50) == 0) {
            usb_ready = 0; pump(); usb_ready = 1;
            /* flushed frames are never observed: resynchronise the expected sequence */
            delivered_seq = next_seq;
        }
        uint32_t used = (s_tx.head >= s_tx.tail) ? s_tx.head - s_tx.tail : CAP - s_tx.tail + s_tx.head;
        assert(used < CAP);                                /* never full to the brim, never overrun */
        assert(s_tx.head < CAP && s_tx.tail < CAP && s_tx.head % 4 == 0 && s_tx.tail % 4 == 0);
    }
    ntb_credit = -1; pump(); do_drain(NULL);
    assert(s_tx.head == s_tx.tail);
    uint32_t sent = s_tx.sent_frames - sent0, flushed = s_tx.flushed - flushed0;
    assert(accepted == sent + flushed);                    /* every accepted frame left the ring once */
    assert(delivered_frames == sent);
    assert(dropped > 0 && sent > 1000);                    /* the schedule actually exercised both */
    printf("soak: %lu accepted, %lu sent, %lu flushed, %lu dropped (ring full)\n", accepted, (unsigned long)sent, (unsigned long)flushed, dropped);
}

int main(void) {
    tinyusb_net_config_t cfg = {.free_tx_buffer = released_ring};
    assert(tinyusb_net_init(&cfg) == ESP_OK);
    test_lifecycle();
    test_basic_and_no_blocking();
    test_backpressure_and_drop_accounting();
    test_flush_on_link_loss();
    test_duplicate_and_stale_callbacks();
    test_sync_and_ring_share_the_pipe();
    test_soak();
    tinyusb_net_tx_stats_t st;
    tinyusb_net_tx_ring_stats(&st);
    assert(st.high_water_bytes > 0 && st.high_water_bytes < CAP);
    printf("PASS: TinyUSB transmit ring: non-blocking producer, bounded backpressure, exactly-once delivery, link flush, duplicate callbacks, sync coexistence\n");
}
