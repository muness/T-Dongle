/* The transparent bridge's forwarding logic (l2.c) against stand-ins for its neighbours: a scripted USB transmit ring, a scripted Wi-Fi
 * transmit, a clock the test moves. The end-to-end behaviour with the real ring, the real Wi-Fi budget and real threads is
 * alternative/tailnet/tests/test_bridge_path.c; this file pins every branch and counter of l2.c itself.
 *
 * Rules checked here for every case:
 *  - the callbacks (the Wi-Fi RX callback and tdongle_l2_host) never wait, allocate or call the Wi-Fi driver: each stand-in asserts it is
 *    not entered while `in_callback` is set;
 *  - every frame that enters either callback is counted exactly once, as forwarded or as one named drop;
 *  - the driver's RX buffer is freed exactly once per call, before the callback returns, on every path. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tdongle_l2.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* ---- the world ---- */
static bool in_callback;                 /* inside tdongle_l2_host or the Wi-Fi RX callback: nothing here may wait or allocate */
static unsigned freed, link_calls, flushes, notifies, note_activity_calls;
static bool fail_alloc, fail_task;
static void *worker_arg;
static esp_err_t ring_result = 0;
static unsigned ring_calls;
static unsigned char ring_seen[2000];
static uint16_t ring_seen_len;
static esp_err_t tx_script[64];          /* results of consecutive wifi_tx calls; past the end: tx_default */
static unsigned tx_calls, tx_script_n;
static esp_err_t tx_default;
static unsigned char tx_seen[2000];
static uint16_t tx_seen_len;
static TickType_t now_ticks;
static unsigned delays;
static void (*delay_hook)(void);
static int cb_registered;                /* 1 = receive registered, 0 = unregistered */
static int order[8], order_n;            /* the order of reg_rxcb / flush / link_state in one tdongle_l2_link call */
static void *allocate(size_t n, size_t size) {
    assert(!in_callback);
    return fail_alloc ? NULL : calloc(n, size);
}
#define calloc allocate
#include "../l2.c"
#undef calloc

bool tud_ready(void) { return true; }
void tud_network_link_state(int i, bool c) { (void)i; (void)c; link_calls++; order[order_n++ % 8] = 3; }
void esp_wifi_internal_free_rx_buffer(void *p) { (void)p; freed++; }
esp_err_t esp_wifi_internal_reg_rxcb(int i, esp_err_t (*f)(void *, uint16_t, void *)) {
    (void)i;
    cb_registered = f == receive;
    assert(f == receive || f == NULL);
    order[order_n++ % 8] = f ? 1 : 0;
    return 0;
}
esp_err_t tinyusb_net_tx_ring_send(const void *b, uint16_t n) {
    ring_calls++;
    if (ring_result == ESP_OK) {
        memcpy(ring_seen, b, n);
        ring_seen_len = n;
    }
    return ring_result;
}
void tinyusb_net_tx_ring_flush(void) { flushes++; order[order_n++ % 8] = 2; }
int xTaskCreatePinnedToCore(void (*f)(void *), const char *n, uint32_t s, void *a, unsigned p, TaskHandle_t *h, int c) {
    (void)f; (void)n; (void)s; (void)p; (void)c;
    if (fail_task) return 0;
    worker_arg = a;
    *h = (TaskHandle_t)&worker_arg;
    return pdPASS;
}
int xTaskNotifyGive(TaskHandle_t h) { assert(h); notifies++; return pdPASS; }   /* allowed in a callback: it never blocks */
uint32_t ulTaskNotifyTake(int c, TickType_t t) { (void)c; (void)t; assert(!in_callback); return 0; }
void vTaskDelay(TickType_t t) { assert(!in_callback); delays++; now_ticks += t; if (delay_hook) delay_hook(); }
TickType_t xTaskGetTickCount(void) { return now_ticks; }
unsigned uxTaskGetStackHighWaterMark(TaskHandle_t h) { (void)h; return 1234; }
void tdongle_pm_note_activity(void) { note_activity_calls++; }
static esp_err_t wifi_tx(void *b, uint16_t n) {
    assert(!in_callback);                /* the Wi-Fi driver is called by the worker only */
    esp_err_t r = tx_calls < tx_script_n ? tx_script[tx_calls] : tx_default;
    tx_calls++;
    if (r == ESP_OK) {
        memcpy(tx_seen, b, n);
        tx_seen_len = n;
    }
    return r;
}

/* ---- helpers ---- */
static const uint8_t mac[6] = {2, 1, 2, 3, 4, 5};
static tdongle_l2_stats_t stats(void) { tdongle_l2_stats_t s; tdongle_l2_stats(&s); return s; }
static void frame(uint8_t *f, size_t len, const uint8_t *dst, const uint8_t *src, unsigned tag) {
    memset(f, 0, len);
    memcpy(f, dst, 6);
    memcpy(f + 6, src, 6);
    for (size_t i = 12; i < len; i++) f[i] = (uint8_t)(tag + i);
}
static const uint8_t unicast_dst[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                     mcast[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, peer[6] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
static esp_err_t wifi_in(const uint8_t *f, uint16_t len) {   /* the driver calls the RX callback in the Wi-Fi task */
    in_callback = true;
    esp_err_t r = receive((void *)f, len, (void *)f);
    in_callback = false;
    return r;
}
static esp_err_t host_in(const uint8_t *f, uint16_t len) {   /* TinyUSB task */
    in_callback = true;
    esp_err_t r = tdongle_l2_host((void *)f, len);
    in_callback = false;
    return r;
}
static unsigned pump(void) { return drain(); }              /* one wake-up of the worker */
static tdongle_l2_config_t config(void) {
    return (tdongle_l2_config_t){.wifi_tx = wifi_tx, .task_priority = 8, .task_core = 1, .task_stack = 3072};
}
static void reset_world(void) {
    freed = link_calls = flushes = notifies = note_activity_calls = ring_calls = tx_calls = tx_script_n = delays = order_n = 0;
    ring_result = ESP_OK; tx_default = ESP_OK; now_ticks = 0; delay_hook = NULL; fail_alloc = fail_task = false;
}
static void start(void) {
    if (l2.slots) { free(l2.slots); l2.slots = NULL; }
    reset_world();
    tdongle_l2_config_t c = config();
    assert(tdongle_l2_start(mac, &c) == ESP_OK);
}
/* The identities the counters keep, at rest. */
static void check_identities(void) {
    tdongle_l2_stats_t s = stats();
    assert(s.w2h_frames == s.w2h_forwarded + s.w2h_invalid + s.w2h_own_mac + s.w2h_link_down + s.w2h_usb_not_ready + s.w2h_ring_full);
    assert(s.h2w_frames == s.h2w_queued + s.h2w_invalid + s.h2w_foreign_mac + s.h2w_link_down + s.h2w_queue_full);
    assert(s.h2w_queued == s.h2w_sent + s.h2w_stale + s.h2w_link_down_queued + s.h2w_tx_failed + s.h2w_queue_depth);
}

static void test_start(void) {
    memset(&l2, 0, sizeof(l2));
    tdongle_l2_config_t c = config();
    assert(tdongle_l2_start(mac, NULL) == ESP_ERR_INVALID_ARG);
    c.wifi_tx = NULL; assert(tdongle_l2_start(mac, &c) == ESP_ERR_INVALID_ARG);
    c = config(); c.task_stack = 0; assert(tdongle_l2_start(mac, &c) == ESP_ERR_INVALID_ARG);
    c = config();
    fail_alloc = true; assert(tdongle_l2_start(mac, &c) == ESP_ERR_NO_MEM && !l2.slots); fail_alloc = false;
    fail_task = true; assert(tdongle_l2_start(mac, &c) == ESP_ERR_NO_MEM && !l2.slots); fail_task = false;   /* the slots are freed again */
    assert(tdongle_l2_host((void *)bcast, 60) == ESP_ERR_INVALID_STATE);    /* not started: nothing to hand over, nothing counted */
    assert(stats().h2w_frames == 0);
    assert(tdongle_l2_start(mac, &c) == ESP_OK && l2.slots && l2.worker);
    assert(tdongle_l2_start(mac, &c) == ESP_ERR_INVALID_STATE);             /* once */
    free(l2.slots); l2.slots = NULL;
}

/* Wi-Fi -> host */
static void test_to_host(void) {
    start();
    uint8_t f[1600];
    /* Before the link is up the callback is not registered; a frame that races the disconnect is counted and its buffer freed. */
    frame(f, 600, unicast_dst, peer, 1);
    assert(wifi_in(f, 600) == ESP_OK && ring_calls == 0 && stats().w2h_link_down == 1 && freed == 1);
    tdongle_l2_link(true);
    assert(cb_registered && link_calls == 1 && flushes == 1);
    /* ARP, IPv4 (DHCP) and IPv6 bytes reach the ring exactly as received: no address rewriting. */
    for (unsigned k = 0; k < 3; k++) {
        const uint16_t len = 100 + 400 * k;
        frame(f, len, k == 0 ? bcast : unicast_dst, peer, 7 * k);
        f[12] = k == 2 ? 0x86 : 0x08; f[13] = k == 0 ? 0x06 : k == 1 ? 0x00 : 0xdd;
        assert(wifi_in(f, len) == ESP_OK && ring_seen_len == len && !memcmp(ring_seen, f, len));
    }
    assert(stats().w2h_forwarded == 3 && freed == 4);
    /* Filters: our own MAC as the source (the host's frame echoed back), a runt, an oversize frame. */
    frame(f, 600, unicast_dst, mac, 3);
    unsigned calls = ring_calls;
    assert(wifi_in(f, 600) == ESP_OK && ring_calls == calls && stats().w2h_own_mac == 1);
    frame(f, 600, unicast_dst, peer, 4);
    assert(wifi_in(f, 13) == ESP_OK && wifi_in(f, TDONGLE_L2_FRAME_MAX + 1) == ESP_OK && wifi_in(f, 0) == ESP_OK && stats().w2h_invalid == 3);
    assert(wifi_in(f, TDONGLE_L2_FRAME_MAX) == ESP_OK && stats().w2h_forwarded == 4 && ring_seen_len == TDONGLE_L2_FRAME_MAX);
    assert(wifi_in(f, 14) == ESP_OK && stats().w2h_forwarded == 5);
    /* Ring refusals are told apart: full (backpressure) and not ready (cable out). */
    ring_result = ESP_ERR_NO_MEM; assert(wifi_in(f, 600) == ESP_OK);
    ring_result = ESP_ERR_INVALID_STATE; assert(wifi_in(f, 600) == ESP_OK && wifi_in(f, 600) == ESP_OK);
    ring_result = ESP_ERR_INVALID_ARG; assert(wifi_in(f, 600) == ESP_OK);
    ring_result = ESP_OK;
    tdongle_l2_stats_t s = stats();
    assert(s.w2h_ring_full == 1 && s.w2h_usb_not_ready == 2 && s.w2h_invalid == 4 && s.w2h_frames == 14);
    check_identities();
    assert(freed == s.w2h_frames);       /* the driver buffer: once per call, whatever happened to the frame */
    /* The link goes down: the callback is unregistered, later frames are counted, and the ring is flushed. */
    tdongle_l2_link(false);
    assert(!cb_registered && flushes == 2 && !stats().linked);
    assert(wifi_in(f, 600) == ESP_OK && stats().w2h_link_down == 2);
    assert(notifies == 0);               /* the receive path never wakes the l2 worker */
    check_identities();
}

/* Which frames raise the clock: a unicast frame that is forwarded, in either direction; never chatter, never a frame that is dropped. */
static void test_pm_notes(void) {
    start();
    uint8_t f[200];
    tdongle_l2_link(true);
    note_activity_calls = 0;
    frame(f, 100, unicast_dst, peer, 1); wifi_in(f, 100);
    assert(note_activity_calls == 1);
    frame(f, 100, bcast, peer, 1); wifi_in(f, 100);
    frame(f, 100, mcast, peer, 1); wifi_in(f, 100);
    assert(note_activity_calls == 1 && stats().w2h_forwarded == 3);      /* forwarded, but not a reason to hold 240 MHz */
    frame(f, 100, unicast_dst, mac, 1); wifi_in(f, 100);                 /* filtered */
    wifi_in(f, 5);                                                       /* invalid */
    assert(note_activity_calls == 1);
    frame(f, 100, peer, mac, 2); host_in(f, 100);
    assert(note_activity_calls == 2 && stats().h2w_queued == 1);
    frame(f, 100, bcast, mac, 2); host_in(f, 100);                       /* DHCP discover, ARP request */
    assert(note_activity_calls == 2 && stats().h2w_queued == 2);
    frame(f, 100, peer, peer, 2); host_in(f, 100);                       /* foreign source */
    host_in(f, 10);                                                      /* runt */
    assert(note_activity_calls == 2);
    tdongle_l2_link(false);
    frame(f, 100, peer, mac, 2); host_in(f, 100);                        /* link down */
    assert(note_activity_calls == 2);
    pump();
    check_identities();
}

/* host -> Wi-Fi */
static void test_to_wifi(void) {
    start();
    uint8_t f[1600];
    frame(f, 600, peer, mac, 1);
    assert(host_in(f, 600) == ESP_ERR_INVALID_STATE && stats().h2w_link_down == 1);          /* Wi-Fi not up yet */
    tdongle_l2_link(true);
    notifies = 0;
    for (unsigned k = 0; k < 3; k++) {                                                          /* ARP, DHCP, IPv6: bytes untouched, source is the STA MAC */
        const uint16_t len = 120 + 500 * k;
        frame(f, len, k == 0 ? bcast : peer, mac, 9 * k);
        assert(host_in(f, len) == ESP_OK && notifies == k + 1);
        assert(pump() == 1 && tx_seen_len == len && !memcmp(tx_seen, f, len));
    }
    assert(stats().h2w_sent == 3 && stats().h2w_queue_depth == 0);
    /* Filters. */
    frame(f, 600, peer, peer, 1);
    assert(host_in(f, 600) == ESP_OK && stats().h2w_foreign_mac == 1);
    assert(host_in(f, 13) == ESP_ERR_INVALID_ARG && host_in(f, TDONGLE_L2_FRAME_MAX + 1) == ESP_ERR_INVALID_ARG && stats().h2w_invalid == 2);
    frame(f, TDONGLE_L2_FRAME_MAX, peer, mac, 5);
    assert(host_in(f, TDONGLE_L2_FRAME_MAX) == ESP_OK && pump() == 1 && tx_seen_len == TDONGLE_L2_FRAME_MAX && !memcmp(tx_seen, f, tx_seen_len));
    assert(tx_calls == 4);                                                                       /* nothing filtered reached the driver */
    /* A full queue drops the new frame, keeps the old ones in order, and never blocks. */
    frame(f, 200, peer, mac, 0);
    for (unsigned i = 0; i < TDONGLE_L2_HOST_SLOTS; i++) { f[20] = (uint8_t)i; assert(host_in(f, 200) == ESP_OK); }
    assert(stats().h2w_queue_depth == TDONGLE_L2_HOST_SLOTS && stats().h2w_queue_high_water == TDONGLE_L2_HOST_SLOTS);
    f[20] = 99;
    assert(host_in(f, 200) == ESP_ERR_NO_MEM && host_in(f, 200) == ESP_ERR_NO_MEM && stats().h2w_queue_full == 2);
    unsigned sent_before = stats().h2w_sent;
    for (unsigned i = 0; i < TDONGLE_L2_HOST_SLOTS; i++) {
        /* one frame at a time: it is the oldest, tx_seen proves the order */
        unsigned tail = atomic_load(&l2.tail);
        assert(l2.slots[tail & SLOT_MASK].bytes[20] == (uint8_t)i);
        deliver(&l2.slots[tail & SLOT_MASK]);
        atomic_store(&l2.tail, tail + 1);
        assert(tx_seen[20] == (uint8_t)i);
    }
    assert(stats().h2w_sent == sent_before + TDONGLE_L2_HOST_SLOTS && stats().h2w_queue_depth == 0);
    check_identities();
    assert(tx_calls == 4 + TDONGLE_L2_HOST_SLOTS);
}

/* The slot counters run free: the queue keeps working across the wrap of the 32-bit counters. */
static void test_counter_wrap(void) {
    start();
    uint8_t f[100];
    tdongle_l2_link(true);
    atomic_store(&l2.head, 0xfffffffcu); atomic_store(&l2.tail, 0xfffffffcu);
    for (unsigned round = 0; round < 6; round++) {
        for (unsigned i = 0; i < 11; i++) { frame(f, 100, peer, mac, round * 11 + i); assert(host_in(f, 100) == ESP_OK); }
        for (unsigned i = 0; i < 11; i++) {
            unsigned tail = atomic_load(&l2.tail);
            deliver(&l2.slots[tail & SLOT_MASK]);
            atomic_store(&l2.tail, tail + 1);
            assert(tx_seen[20] == (uint8_t)(round * 11 + i + 20));
        }
    }
    assert(atomic_load(&l2.head) == 0xfffffffcu + 66 && stats().h2w_sent == 66 && stats().h2w_queue_depth == 0);
    check_identities();
}

/* A link change makes what was queued stale, in both directions; a frame is never sent into the wrong association. */
static void test_link_flap(void) {
    start();
    uint8_t f[200];
    tdongle_l2_link(true);
    frame(f, 200, peer, mac, 1);
    for (unsigned i = 0; i < 5; i++) assert(host_in(f, 200) == ESP_OK);
    tdongle_l2_link(false);                       /* the association ended with five frames queued */
    assert(pump() == 5 && tx_calls == 0 && stats().h2w_link_down_queued == 5);
    for (unsigned i = 0; i < 4; i++) assert(host_in(f, 200) == ESP_ERR_INVALID_STATE);   /* link down: refused, counted */
    assert(stats().h2w_link_down == 4);
    tdongle_l2_link(true);
    for (unsigned i = 0; i < 3; i++) assert(host_in(f, 200) == ESP_OK);
    tdongle_l2_link(false);                       /* a quick flap: down and up again before the worker ran */
    tdongle_l2_link(true);
    assert(pump() == 3 && tx_calls == 0 && stats().h2w_stale == 3);          /* queued under the first association of this link: stale */
    assert(host_in(f, 200) == ESP_OK && pump() == 1 && tx_calls == 1);       /* the new association works */
    check_identities();
    /* tdongle_l2_link orders its steps: stop (or start) the callback, flush the ring, then tell the host. */
    order_n = 0; tdongle_l2_link(false);
    assert(order_n == 3 && order[0] == 0 && order[1] == 2 && order[2] == 3);
    order_n = 0; tdongle_l2_link(true);
    assert(order_n == 3 && order[0] == 1 && order[1] == 2 && order[2] == 3);
    assert(stats().link_changes == 7);
}

static unsigned hook_calls;
static void drop_link_in_delay(void) { if (++hook_calls == 1) tdongle_l2_link(false); }
/* A refused transmit is retried for a bounded time at tick granularity, never forever, and only when retrying can help. */
static void test_retry(void) {
    uint8_t f[200];
    frame(f, 200, peer, mac, 1);
    const TickType_t budget = pdMS_TO_TICKS(TDONGLE_L2_TX_RETRY_MS) ? pdMS_TO_TICKS(TDONGLE_L2_TX_RETRY_MS) : 1;
    /* Refused twice, then taken. */
    start(); tdongle_l2_link(true);
    tx_script[0] = ESP_ERR_NO_MEM; tx_script[1] = ESP_ERR_NO_MEM; tx_script_n = 2;
    assert(host_in(f, 200) == ESP_OK && pump() == 1);
    assert(stats().h2w_sent == 1 && stats().h2w_tx_retries == 2 && delays == 2 && stats().h2w_last_tx_error == ESP_ERR_NO_MEM);
    /* Always refused: it stops after the budget, counts one failure, and the next frame is not held up behind a second budget. */
    start(); tdongle_l2_link(true);
    tx_default = ESP_ERR_NO_MEM;
    assert(host_in(f, 200) == ESP_OK && host_in(f, 200) == ESP_OK && pump() == 2);
    assert(stats().h2w_tx_failed == 2 && stats().h2w_sent == 0);
    assert(now_ticks == 2 * budget && stats().h2w_tx_retries == 2 * budget && tx_calls == 2 * (budget + 1));
    /* A final error is not retried. */
    start(); tdongle_l2_link(true);
    tx_default = -1;    /* ESP_FAIL */
    assert(host_in(f, 200) == ESP_OK && pump() == 1 && tx_calls == 1 && delays == 0 && stats().h2w_tx_failed == 1 && stats().h2w_last_tx_error == -1);
    /* The link drops while the worker waits: the frame is abandoned at once. */
    start(); tdongle_l2_link(true);
    tx_default = ESP_ERR_NO_MEM; hook_calls = 0; delay_hook = drop_link_in_delay;
    assert(host_in(f, 200) == ESP_OK && pump() == 1 && tx_calls == 2 && stats().h2w_tx_failed == 1);
    check_identities();
    /* tdongle_l2.h promises the retry stays below the activity hold. */
    assert((uint64_t)TDONGLE_L2_TX_RETRY_MS * 1000u < TDONGLE_PM_ACTIVITY_HOLD_US);
}

/* The retry window is a time, not a count: with a 1 ms tick it is 20 attempts, with the firmware's 10 ms tick it is 2 (+1). */
static void test_tick_scale(void) {
    printf("  retry budget at a %d ms tick: %u ticks\n", TEST_TICK_MS, (unsigned)pdMS_TO_TICKS(TDONGLE_L2_TX_RETRY_MS));
    assert(TEST_TICK_MS == 1 ? pdMS_TO_TICKS(TDONGLE_L2_TX_RETRY_MS) == 20 : pdMS_TO_TICKS(TDONGLE_L2_TX_RETRY_MS) == 2);
}

int main(void) {
    test_start();
    test_to_host();
    test_pm_notes();
    test_to_wifi();
    test_counter_wrap();
    test_link_flap();
    test_retry();
    test_tick_scale();
    free(l2.slots);
    puts("Bridge l2: filters, both directions, every drop counted once, the driver buffer freed once, queue order and wrap, stale links, bounded retry, clock notes");
    return 0;
}
