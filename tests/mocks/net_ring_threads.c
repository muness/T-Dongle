// SPDX-License-Identifier: MIT
/* The elastic ring with four real threads, as on the board: the lwIP core lock holder (producer), the TinyUSB task
 * (consumer: deferred drains and IN completions), the usb_txq worker (growth, idle shrink, CPU-frequency lock) and
 * membership admission (gate closes, reclaim, gate opens), all at once. Built with ThreadSanitizer when the compiler
 * has it, so the critical section, the atomics and the ownership hand-offs are checked for data races on the slab
 * bytes, the chunk table and the pool, not just for the right answer. Every accepted frame must be delivered once,
 * in order, bytes intact; the mocks assert that nothing allocates, frees, waits or calls a task inside the
 * critical section or in the producer. */
#include <sched.h>
#include <unistd.h>
#define FLOOR_FREE 30000u
#define FLOOR_LARGEST 20000u
static _Atomic int producer_done, gate_flag;
static bool gate_cb(void *ctx) { (void)ctx; return atomic_load(&gate_flag); }
static uint32_t delivered_seq, delivered_frames;
static void observe(const uint8_t *p, uint16_t n) {
    uint32_t seq;
    memcpy(&seq, p, sizeof(seq));
    assert(seq == delivered_seq);
    for (uint16_t i = 4; i < n; i++) assert(p[i] == (uint8_t)(seq * 7 + n + i));
    delivered_seq++;
    delivered_frames++;
}
static unsigned long accepted;
static void *producer(void *arg) {
    (void)arg;
    unsigned long long r = 0x9e3779b97f4a7c15ull;
    uint32_t seq = 0;
    uint8_t f[1518];
    in_producer = 1;
    for (int i = 0; i < 300000; i++) {
        r ^= r << 13; r ^= r >> 7; r ^= r << 17;
        uint16_t n = (r & 3) == 0 ? 14 + (r >> 8) % 60 : 14 + (r >> 8) % 1505;
        if ((r >> 50) & 1) n = 1518 - (uint16_t)((r >> 12) & 7);      /* bursts of full-size frames */
        memcpy(f, &seq, 4);
        for (uint16_t k = 4; k < n; k++) f[k] = (uint8_t)(seq * 7 + n + k);
        esp_err_t e = tinyusb_net_tx_ring_send(f, n);
        if (e == ESP_OK) { seq++; accepted++; }
        else if ((r >> 40) & 1) sched_yield();
        if (!((r >> 20) & 63)) { for (int k = 0; k < 20; k++) sched_yield(); }   /* a pause: the ring drains and chunks idle */
    }
    in_producer = 0;
    atomic_store(&producer_done, 1);
    return NULL;
}
static _Atomic int consumer_stop;
static void *consumer(void *arg) {                        /* the TinyUSB task */
    (void)arg;
    unsigned long long r = 0xdeadbeefcafef00dull;
    while (!atomic_load(&consumer_stop)) {
        r ^= r << 13; r ^= r >> 7; r ^= r << 17;
        /* USB drains slower than the producer fills: two frames per NTB, one NTB per wakeup, with periods of catching up. */
        ntb_credit = (r & 63) == 0 ? -1 : (int)(r >> 8) % 3;      /* touched by this thread only */
        run_deferred();
        if ((r >> 20) & 1) do_drain(NULL); else __wrap_netd_xfer_cb(0, 0x81, 0, 64);
        usleep(30);
    }
    return NULL;
}
static void *worker(void *arg) {                          /* usb_txq (the mock take returns at once) */
    (void)arg;
    while (!atomic_load(&consumer_stop)) { tx_worker_step(); atomic_fetch_add(&mock_tick, 1); sched_yield(); }
    return NULL;
}
static unsigned long admissions;
static void admission_delay(void) { usleep(200); }
static void *admission(void *arg) {                       /* a membership starts: token (gate), reclaim, measure, release */
    (void)arg;
    delay_hook = admission_delay;
    while (!atomic_load(&producer_done)) {
        atomic_store(&gate_flag, 1);
        (void)tinyusb_net_tx_elastic_reclaim(20);
        admissions++;
        usleep(300);
        atomic_store(&gate_flag, 0);
        tinyusb_net_tx_elastic_kick();
        usleep(2000);
    }
    return NULL;
}
int main(void) {
    tinyusb_net_config_t cfg = {0};
    assert(tinyusb_net_init(&cfg) == ESP_OK);
    tinyusb_net_tx_config_t c = { .base_frames = 3, .max_chunks = 10, .priority = 5, .core = 0,
                                  .floor_free = FLOOR_FREE, .floor_largest = FLOOR_LARGEST, .idle_ms = 5, .gate = gate_cb };
    assert(tinyusb_net_tx_ring_start(&c) == ESP_OK);
    xmit_hook = observe;
    pthread_t p, c1, w, a;
    pthread_create(&c1, NULL, consumer, NULL);
    pthread_create(&w, NULL, worker, NULL);
    pthread_create(&a, NULL, admission, NULL);
    pthread_create(&p, NULL, producer, NULL);
    pthread_join(p, NULL);
    pthread_join(a, NULL);
    atomic_store(&gate_flag, 0);
    for (int i = 0; i < 200000; i++) {                                  /* the consumer finishes the queue */
        tinyusb_net_tx_stats_t q;
        tinyusb_net_tx_ring_stats(&q);
        if (q.sent_frames == q.enqueued_frames) break;
        sched_yield();
    }
    atomic_store(&consumer_stop, 1);
    pthread_join(c1, NULL);
    pthread_join(w, NULL);
    ntb_credit = -1;
    do_drain(NULL);
    tx_worker_step(); tx_worker_step();
    assert(s_tx.frames_queued == 0);
    tinyusb_net_tx_stats_t st;
    tinyusb_net_tx_ring_stats(&st);
    assert(delivered_frames == accepted && st.sent_frames == accepted && st.flushed_link_down == 0);
    assert(accepted > 10000 && st.grow_events > 0 && st.reclaim_events > 0 && admissions > 5);
#if CONFIG_PM_ENABLE
    assert(pm_acquires == pm_releases && s_tx.pm->held == 0 && pm_acquires > 0);
#endif
    assert(heap_live_blocks == 1 + (long)s_tx.chunks_present && st.chunks <= 10);
    printf("PASS: elastic transmit ring across four threads: %lu frames in order, none lost or repeated; %u dropped (full), %u grown, %u idle-freed, %u reclaim events (%lu admissions), high water %u slabs\n",
           accepted, st.dropped_full, st.grow_events, st.shrink_events, st.reclaim_events, admissions, st.high_water_slabs);
}
