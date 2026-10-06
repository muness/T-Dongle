/* The bridge with real threads, as on the board, under ThreadSanitizer when the compiler has it: the Wi-Fi task (the RX callback), the TinyUSB
 * task (the host receive callback, deferred drains, IN completions), usb_txq (the ring's worker), the host -> Wi-Fi forwarder, the Wi-Fi
 * driver's pp task (tx-done), the event task (link flaps) and the esp_timer task (the forwarding-activity hold), all at once. The mocks assert that
 * neither callback waits, allocates, defers or calls the Wi-Fi driver; TSan checks the ring's critical section, the slot counters and the
 * budget's lock for data races; at the end every frame is accounted for exactly (check_final) and every CPU-frequency lock is paired. */
#include <sched.h>
#include <unistd.h>

static _Atomic int stop_workers;
static _Atomic unsigned wifi_sent, usb_sent;
#define ITERATIONS 120000u
static uint32_t next_rand(unsigned long long *r) { *r ^= *r << 13; *r ^= *r >> 7; *r ^= *r << 17; return (uint32_t)(*r >> 11); }

static void *wifi_task(void *arg) {
    unsigned long long r = 0x9e3779b97f4a7c15ull ^ (unsigned long long)(uintptr_t)arg;
    uint8_t f[TDONGLE_L2_FRAME_MAX];
    uint32_t seq = 1;
    for (unsigned i = 0; i < ITERATIONS; i++) {
        const uint32_t x = next_rand(&r);
        const uint16_t len = (x & 3) == 0 ? (uint16_t)(24 + (x >> 8) % 80) : (uint16_t)(24 + (x >> 8) % 1491);
        build_frame(f, len, false, (x >> 4) % 4 == 0 ? KIND_BCAST : KIND_UNICAST, seq++);
        wifi_rx(f, len);
        atomic_fetch_add(&wifi_sent, 1);
        if (!((x >> 20) & 63)) sched_yield();
    }
    return NULL;
}
static void *usb_task(void *arg) {                         /* TinyUSB: receive callback, deferred calls, IN completions */
    unsigned long long r = 0xdeadbeefcafef00dull ^ (unsigned long long)(uintptr_t)arg;
    uint8_t f[TDONGLE_L2_FRAME_MAX];
    uint32_t seq = 1;
    for (unsigned i = 0; i < ITERATIONS; i++) {
        const uint32_t x = next_rand(&r);
        const uint16_t len = (x & 3) == 0 ? (uint16_t)(24 + (x >> 8) % 80) : (uint16_t)(24 + (x >> 8) % 1491);
        build_frame(f, len, true, KIND_UNICAST, seq++);
        host_tx(f, len);
        atomic_fetch_add(&usb_sent, 1);
        /* USB drains slower than the Wi-Fi side fills: two frames per NTB, one NTB per wake-up, with stretches of catching up. */
        ntb_credit = (x & 63) == 0 ? -1 : (int)((x >> 12) % 3);
        run_deferred();
        if ((x >> 20) & 1) do_drain(NULL); else __wrap_netd_xfer_cb(0, 0x81, 0, 64);
        if (!((x >> 24) & 31)) usleep(20);
    }
    ntb_credit = -1;
    return NULL;
}
static void *ring_worker(void *arg) {                      /* usb_txq */
    (void)arg;
    while (!atomic_load(&stop_workers)) { tx_worker_step(); atomic_fetch_add(&mock_tick, 1); sched_yield(); }
    return NULL;
}
static void *forwarder(void *arg) {                        /* the host -> Wi-Fi worker */
    (void)arg;
    while (!atomic_load(&stop_workers)) if (!drain()) sched_yield();
    return NULL;
}
static void *pp_task(void *arg) {                          /* the Wi-Fi driver completing frames */
    unsigned long long r = 0x1234567890abcdefull ^ (unsigned long long)(uintptr_t)arg;
    while (!atomic_load(&stop_workers)) { drv_complete(1 + next_rand(&r) % 3); sched_yield(); }
    return NULL;
}
static void *event_task(void *arg) {                       /* the association comes and goes */
    unsigned long long r = 0xfeedfacefeedfaceull ^ (unsigned long long)(uintptr_t)arg;
    while (!atomic_load(&stop_workers)) {
        usleep(1500 + next_rand(&r) % 4500);
        wifi_disconnect();
        usleep(100 + next_rand(&r) % 200);
        wifi_connect();
    }
    return NULL;
}
static void *sampler(void *arg) {                          /* a status reader: the depth must never wrap, whatever the worker does between two loads */
    (void)arg;
    while (!atomic_load(&stop_workers)) { const tdongle_l2_stats_t s = l2_stats(); assert(s.h2w_queue_depth < (1u << 16)); sched_yield(); }
    return NULL;
}
static void *timer_task(void *arg) {                       /* esp_timer: the forwarding-activity hold */
    (void)arg;
    while (!atomic_load(&stop_workers)) { atomic_fetch_add(&mock_us, 3000); pm_timer_poll(); usleep(30); }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    tinyusb_net_config_t cfg = {0};
    assert(tinyusb_net_init(&cfg) == ESP_OK);
    world_reset(HEAP_BRIDGE, false);                      /* the PM properties that need a time model are in test_bridge_path.c */
    wifi_connect();
    pthread_t wifi, usb, ring, fwd, pp, ev, tim, smp;
    pthread_create(&ring, NULL, ring_worker, NULL);
    pthread_create(&fwd, NULL, forwarder, NULL);
    pthread_create(&pp, NULL, pp_task, (void *)1);
    pthread_create(&ev, NULL, event_task, (void *)2);
    pthread_create(&tim, NULL, timer_task, NULL);
    pthread_create(&smp, NULL, sampler, NULL);
    pthread_create(&usb, NULL, usb_task, (void *)3);
    pthread_create(&wifi, NULL, wifi_task, (void *)4);
    pthread_join(wifi, NULL);
    pthread_join(usb, NULL);
    atomic_store(&stop_workers, 1);
    pthread_join(ring, NULL); pthread_join(fwd, NULL); pthread_join(pp, NULL); pthread_join(ev, NULL); pthread_join(tim, NULL); pthread_join(smp, NULL);
    if (!wifi_up) wifi_connect();
    settle();
    advance_ms(500);
    pump_ring();
    check_world();
    check_final();
    check_pm_idle();
    const tdongle_l2_stats_t s = l2_stats();
    const tinyusb_net_tx_stats_t t = ring_stats();
    assert(s.w2h_frames > ITERATIONS / 2 && s.h2w_frames <= ITERATIONS && s.w2h_forwarded > 1000 && s.h2w_sent > 1000);
    printf("PASS: transparent bridge across eight threads: to host %u/%u forwarded (%u ring-full, %u flushed, %u link-down), to Wi-Fi %u/%u sent (%u held, %u refused, %u stale, %u link-down), %u link changes, ring grew %u times\n",
           s.w2h_forwarded, s.w2h_frames, s.w2h_ring_full, t.flushed_link_down, s.w2h_link_down, s.h2w_sent, s.h2w_frames, s.h2w_held, s.h2w_tx_failed, s.h2w_stale,
           s.h2w_link_down + s.h2w_link_down_queued, s.link_changes, t.grow_events);
    return 0;
}
