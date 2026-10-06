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
#include "esp_timer.h"
/* esp_timer's one-shot API, as l2.c uses it (the shared stub header only has the clock). */
typedef void *esp_timer_handle_t;
typedef struct { void (*callback)(void *); void *arg; const char *name; } esp_timer_create_args_t;
esp_err_t esp_timer_create(const esp_timer_create_args_t *, esp_timer_handle_t *);
esp_err_t esp_timer_start_once(esp_timer_handle_t, uint64_t);
esp_err_t esp_timer_delete(esp_timer_handle_t);

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
static int64_t now_us_v;                  /* the clock, in microseconds */
static unsigned waits;                   /* retry waits the worker made */
static void (*wait_hook)(void);
static bool timer_armed; static uint64_t timer_due; static void (*timer_cb)(void *);
static int cb_registered;                /* 1 = receive registered, 0 = unregistered */
static int order[8], order_n;            /* the order of reg_rxcb / flush / link_state in one tdongle_l2_link call */
static void (*ring_hook)(void);          /* runs inside tinyusb_net_tx_ring_send: "something else happens while the callback copies" */
static bool fail_timer;
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
    if (ring_hook) { void (*h)(void) = ring_hook; ring_hook = NULL; h(); }
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
/* The worker's retry wait: time passes until the armed timer fires (or the timeout), and the test may act meanwhile. */
uint32_t ulTaskNotifyTake(int c, TickType_t t) {
    (void)c;
    assert(!in_callback);
    waits++;
    if (timer_armed) { now_us_v = (int64_t)timer_due; timer_armed = false; timer_cb(NULL); }
    else now_us_v += (int64_t)t * TEST_TICK_MS * 1000;
    if (wait_hook) wait_hook();
    return 1;
}
void vTaskDelay(TickType_t t) { (void)t; assert(0 && "the bridge never sleeps on the RTOS tick"); }
TickType_t xTaskGetTickCount(void) { return 0; }
int64_t esp_timer_get_time(void) { return now_us_v; }
esp_err_t esp_timer_create(const esp_timer_create_args_t *a, esp_timer_handle_t *h) { if (fail_timer) return -1; timer_cb = a->callback; *h = &timer_cb; return 0; }
esp_err_t esp_timer_start_once(esp_timer_handle_t h, uint64_t us) { (void)h; assert(!in_callback); if (timer_armed) return ESP_ERR_INVALID_STATE; timer_armed = true; timer_due = (uint64_t)now_us_v + us; return 0; }
esp_err_t esp_timer_delete(esp_timer_handle_t h) { (void)h; return 0; }
unsigned uxTaskGetStackHighWaterMark(TaskHandle_t h) { (void)h; return 1234; }
void tdongle_pm_note_activity(void) { note_activity_calls++; }
static bool last_sparse;
static esp_err_t wifi_tx(void *b, uint16_t n, bool sparse) {
    last_sparse = sparse;
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
static unsigned resumes;
static bool room = true;
static bool wifi_room(bool sparse) { (void)sparse; assert(!in_callback); return room; }
static void rx_resume(void) { assert(!in_callback); resumes++; }
static tdongle_l2_config_t config(void) {
    return (tdongle_l2_config_t){.wifi_tx = wifi_tx, .wifi_room = wifi_room, .rx_resume = rx_resume, .task_priority = 8, .task_core = 1, .task_stack = 4096};
}
static void reset_world(void) {
    freed = link_calls = flushes = notifies = note_activity_calls = ring_calls = tx_calls = tx_script_n = waits = order_n = 0;
    ring_result = ESP_OK; tx_default = ESP_OK; now_us_v = 1000000; wait_hook = NULL; ring_hook = NULL; timer_armed = false; resumes = 0; room = true; fail_alloc = fail_task = fail_timer = false;
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
    assert(s.h2w_frames == s.h2w_queued + s.h2w_invalid + s.h2w_foreign_mac + s.h2w_link_down);
    assert(s.h2w_queued == s.h2w_sent + s.h2w_stale + s.h2w_sojourn_drop + s.h2w_link_down_queued + s.h2w_tx_failed + s.h2w_queue_depth);
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
    /* A full queue holds the offer (USB backpressure), drops nothing, keeps the old ones in order, and never blocks. */
    frame(f, 200, peer, mac, 0);
    for (unsigned i = 0; i < TDONGLE_L2_HOST_QUEUE_LIMIT; i++) { f[20] = (uint8_t)i; assert(host_in(f, 200) == ESP_OK); }
    assert(stats().h2w_queue_depth == TDONGLE_L2_HOST_QUEUE_LIMIT && stats().h2w_queue_high_water == TDONGLE_L2_HOST_QUEUE_LIMIT);   /* the limit, not the slot count */
    f[20] = 99;
    assert(host_in(f, 200) == TUSB_NET_RX_HOLD && host_in(f, 200) == TUSB_NET_RX_HOLD && stats().h2w_held == 2);
    unsigned sent_before = stats().h2w_sent;
    for (unsigned i = 0; i < TDONGLE_L2_HOST_QUEUE_LIMIT; i++) {
        /* one frame at a time: it is the oldest, tx_seen proves the order */
        unsigned tail = atomic_load(&l2.tail);
        assert(l2.slots[tail & SLOT_MASK].bytes[20] == (uint8_t)i);
        deliver(&l2.slots[tail & SLOT_MASK]);
        atomic_store(&l2.tail, tail + 1);
        assert(tx_seen[20] == (uint8_t)i);
    }
    assert(stats().h2w_sent == sent_before + TDONGLE_L2_HOST_QUEUE_LIMIT && stats().h2w_queue_depth == 0);
    check_identities();
    assert(tx_calls == 4 + TDONGLE_L2_HOST_QUEUE_LIMIT);
}

static unsigned owed_calls;
static void deliver_one_manually(void) { unsigned tail = atomic_load(&l2.tail); deliver(&l2.slots[tail & SLOT_MASK]); atomic_store(&l2.tail, tail + 1); }
/* USB backpressure: hold at the limit, resume exactly once when the worker drains to the resume depth, no wedge on any interleaving. */
static void test_backpressure(void) {
    uint8_t f[200];
    start(); tdongle_l2_link(true);
    frame(f, 200, peer, mac, 1);
    for (unsigned i = 0; i < TDONGLE_L2_HOST_QUEUE_LIMIT; i++) assert(host_in(f, 200) == ESP_OK);
    assert(host_in(f, 200) == TUSB_NET_RX_HOLD && stats().h2w_held == 1 && stats().h2w_frames == TDONGLE_L2_HOST_QUEUE_LIMIT && l2.held);
    assert(host_in(f, 200) == TUSB_NET_RX_HOLD && stats().h2w_held == 2 && resumes == 0);        /* nothing drained: nothing to resume */
    check_identities();
    /* The worker drains: resume is asked for when the depth reaches RESUME_DEPTH, once, not at every frame. */
    assert(pump() == TDONGLE_L2_HOST_QUEUE_LIMIT);
    assert(resumes == 1 && !l2.held && stats().h2w_resumes == 1);
    assert(host_in(f, 200) == ESP_OK && pump() == 1 && resumes == 1);                           /* re-offered datagram accepted; no flag, no resume */
    check_identities();
    /* Interleaving A: the worker drains between the callback's full check and its re-check. The callback must not strand the datagram: it sees the
     * room (and takes it) or the worker's resume covers it. */
    for (unsigned i = 0; i < TDONGLE_L2_HOST_QUEUE_LIMIT; i++) assert(host_in(f, 200) == ESP_OK);
    /* simulate: the callback has set held and the worker finished everything before the callback re-reads the tail */
    atomic_store(&l2.held, true);
    pump();                                                                                     /* the worker sees the flag and resumes */
    assert(resumes == 2 && !l2.held);
    assert(host_in(f, 200) == ESP_OK);                                                          /* the re-offer is accepted */
    pump();
    /* Interleaving B: held is set, the worker has already taken it (resume owed), and the callback's re-check finds room: it must still say HOLD
     * (the owed resume re-offers this datagram) rather than take the room twice. */
    for (unsigned i = 0; i < TDONGLE_L2_HOST_QUEUE_LIMIT; i++) assert(host_in(f, 200) == ESP_OK);
    atomic_store(&l2.held, true);                      /* ... the callback, after storing the flag */
    deliver_one_manually();                            /* the worker consumed one frame meanwhile (depth 2: no resume yet: above the resume depth) */
    assert(host_in(f, 200) == ESP_OK);                 /* room: a normal enqueue (limit 3, depth 2). held was left set by the earlier store */
    pump();
    assert(resumes >= 3 && !l2.held);                  /* the stale flag is released by the next drain: a harmless extra resume, never a missed one */
    /* A link change releases a held datagram (the backlog is stale). */
    start(); tdongle_l2_link(true);
    for (unsigned i = 0; i < TDONGLE_L2_HOST_QUEUE_LIMIT; i++) assert(host_in(f, 200) == ESP_OK);
    assert(host_in(f, 200) == TUSB_NET_RX_HOLD && l2.held);
    tdongle_l2_link(false);
    assert(resumes == 1 && !l2.held);
    pump();
    check_identities();
    /* A wedged Wi-Fi link: frames wait for the radio's allowance, the host stays held, and the sojourn limit frees the queue; the held datagram resumes. */
    start(); tdongle_l2_link(true);
    room = false;
    for (unsigned i = 0; i < TDONGLE_L2_HOST_QUEUE_LIMIT; i++) assert(host_in(f, 200) == ESP_OK);
    assert(host_in(f, 200) == TUSB_NET_RX_HOLD);
    assert(pump() == TDONGLE_L2_HOST_QUEUE_LIMIT);
    assert(tx_calls == 0 && stats().h2w_tx_failed == 1 && stats().h2w_sojourn_drop == TDONGLE_L2_HOST_QUEUE_LIMIT - 1 && resumes == 1);   /* the driver was never called while the allowance was full; the first frame used its window, the rest had aged out behind it */
    room = true;
    assert(host_in(f, 200) == ESP_OK && pump() == 1 && stats().h2w_sent == 1);
    check_identities();
    (void)owed_calls;
}

/* The slot counters run free: the queue keeps working across the wrap of the 32-bit counters. */
static void test_counter_wrap(void) {
    start();
    uint8_t f[100];
    tdongle_l2_link(true);
    atomic_store(&l2.head, 0xfffffffcu); atomic_store(&l2.tail, 0xfffffffcu);
    for (unsigned round = 0; round < 10; round++) {
        for (unsigned i = 0; i < 3; i++) { frame(f, 100, peer, mac, round * 3 + i); assert(host_in(f, 100) == ESP_OK); }
        for (unsigned i = 0; i < 3; i++) {
            unsigned tail = atomic_load(&l2.tail);
            deliver(&l2.slots[tail & SLOT_MASK]);
            atomic_store(&l2.tail, tail + 1);
            assert(tx_seen[20] == (uint8_t)(round * 3 + i + 20));
        }
    }
    assert(atomic_load(&l2.head) == 0xfffffffcu + 30 && stats().h2w_sent == 30 && stats().h2w_queue_depth == 0);
    check_identities();
}

/* A link change makes what was queued stale, in both directions; a frame is never sent into the wrong association. */
static void test_link_flap(void) {
    start();
    uint8_t f[200];
    tdongle_l2_link(true);
    frame(f, 200, peer, mac, 1);
    for (unsigned i = 0; i < 3; i++) assert(host_in(f, 200) == ESP_OK);
    tdongle_l2_link(false);                       /* the association ended with three frames queued */
    assert(pump() == 3 && tx_calls == 0 && stats().h2w_link_down_queued == 3);
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
    assert(order_n == 3 && order[0] == 2 && order[1] == 1 && order[2] == 3);   /* connect: flush the old association's frames, then open the callback */
    assert(stats().link_changes == 7);
}

static unsigned hook_calls;
static void drop_link_in_wait(void) { if (++hook_calls == 1) tdongle_l2_link(false); }
static void advance_us(int64_t us) { now_us_v += us; }
/* A refused transmit is retried on the retry timer (not the RTOS tick) until the frame's sojourn limit, never forever, only when retrying can help. */
static void test_retry(void) {
    uint8_t f[200];
    frame(f, 200, peer, mac, 1);
    const unsigned limit_us = TDONGLE_L2_SOJOURN_MS * 1000u;
    /* Refused twice, then taken: two 500 us waits, not two 10 ms ticks. */
    start(); tdongle_l2_link(true);
    tx_script[0] = ESP_ERR_NO_MEM; tx_script[1] = ESP_ERR_NO_MEM; tx_script_n = 2;
    assert(host_in(f, 200) == ESP_OK);
    const int64_t t0 = now_us_v;
    assert(pump() == 1);
    assert(stats().h2w_sent == 1 && stats().h2w_tx_retries == 2 && waits == 2 && now_us_v - t0 == 2 * TDONGLE_L2_RETRY_US && stats().h2w_last_tx_error == ESP_ERR_NO_MEM);
    /* Always refused: it stops at the sojourn limit measured from the callback, counts one failure, and the frame behind it gets its own full window. */
    start(); tdongle_l2_link(true);
    tx_default = ESP_ERR_NO_MEM;
    assert(host_in(f, 200) == ESP_OK);
    advance_us(5000);                                  /* it already waited 5 ms in the queue: only 15 ms of retries remain */
    assert(pump() == 1);
    assert(stats().h2w_tx_failed == 1 && stats().h2w_tx_retries == (limit_us - 5000) / TDONGLE_L2_RETRY_US && now_us_v - t0 > 0);
    assert(host_in(f, 200) == ESP_OK && pump() == 1 && stats().h2w_tx_failed == 2 && stats().h2w_tx_retries == (limit_us - 5000) / TDONGLE_L2_RETRY_US + limit_us / TDONGLE_L2_RETRY_US);
    /* A final error is not retried. */
    start(); tdongle_l2_link(true);
    tx_default = -1;    /* ESP_FAIL */
    assert(host_in(f, 200) == ESP_OK && pump() == 1 && tx_calls == 1 && waits == 0 && stats().h2w_tx_failed == 1 && stats().h2w_last_tx_error == -1);
    /* The link drops while the worker waits: the frame is abandoned at once. */
    start(); tdongle_l2_link(true);
    tx_default = ESP_ERR_NO_MEM; hook_calls = 0; wait_hook = drop_link_in_wait;
    assert(host_in(f, 200) == ESP_OK && pump() == 1 && tx_calls == 2 && stats().h2w_tx_failed == 1);
    check_identities();
    /* The timer cannot be created: the bridge does not start (nothing half built). */
    memset(&l2, 0, sizeof(l2)); fail_timer = true;
    tdongle_l2_config_t c = config();
    assert(tdongle_l2_start(mac, &c) == ESP_ERR_NO_MEM && !l2.slots);
    fail_timer = false;
}

/* The standing queue is bounded in time too: a frame older than the sojourn limit when the worker reaches it is dropped unsent. */
static void test_sojourn(void) {
    uint8_t f[200];
    frame(f, 200, peer, mac, 1);
    start(); tdongle_l2_link(true);
    for (unsigned i = 0; i < 3; i++) assert(host_in(f, 200) == ESP_OK);
    advance_us(TDONGLE_L2_SOJOURN_MS * 1000u - 1);       /* just inside the limit: sent */
    assert(pump() == 3 && stats().h2w_sent == 3 && stats().h2w_sojourn_drop == 0);
    assert(stats().h2w_wait_us_max == TDONGLE_L2_SOJOURN_MS * 1000u - 1 && stats().h2w_wait_us_sum == 3 * (TDONGLE_L2_SOJOURN_MS * 1000u - 1));
    for (unsigned i = 0; i < 3; i++) assert(host_in(f, 200) == ESP_OK);
    advance_us(TDONGLE_L2_SOJOURN_MS * 1000u);           /* at the limit: dropped, counted, never sent */
    tx_calls = 0;
    assert(pump() == 3 && tx_calls == 0 && stats().h2w_sojourn_drop == 3);
    check_identities();
    assert(host_in(f, 200) == ESP_OK && pump() == 1 && stats().h2w_sent == 4);     /* the queue recovers at once */
    assert(stats().h2w_tx_us_max == 0);                                            /* the stub's call takes no time */
    check_identities();
}

/* tdongle_l2_stats reads tail before head: a worker that finishes frames between the loads cannot make the depth negative. */
static void test_depth_never_wraps(void) {
    start(); tdongle_l2_link(true);
    atomic_store(&l2.head, 7); atomic_store(&l2.tail, 7);
    assert(stats().h2w_queue_depth == 0);
    atomic_store(&l2.head, 9); atomic_store(&l2.tail, 7);
    assert(stats().h2w_queue_depth == 2);
}

static void late_link_down(void) { tdongle_l2_link(false); }
/* A frame in the RX callback while the association ends passes the link check, is stamped with the NEW generation by the ring, and would
 * outlive the change: the callback notices the epoch moved and flushes again. */
static void test_rx_race(void) {
    uint8_t f[200];
    start(); tdongle_l2_link(true);
    frame(f, 200, unicast_dst, peer, 1);
    const unsigned flushes_before = flushes;
    ring_hook = late_link_down;                          /* the event task runs inside the ring send */
    assert(wifi_in(f, 200) == ESP_OK);
    assert(stats().w2h_raced == 1 && stats().w2h_forwarded == 1 && flushes == flushes_before + 2);   /* the change's own flush, and the callback's */
    wifi_in(f, 200);                                     /* link is down now: counted, no race */
    assert(stats().w2h_raced == 1 && stats().w2h_link_down == 1);
    check_identities();
}

static void open_room_after_three(void) { if (++hook_calls == 3) room = true; }

/* Packets for the classifier: Ethernet + IPv4/IPv6 + TCP/UDP/ICMP headers, built by hand. */
static unsigned build_ip(uint8_t *f, unsigned ethertype, unsigned proto, unsigned payload, bool v6, unsigned tcp_doff) {
    memset(f, 0, 400);
    memcpy(f, peer, 6); memcpy(f + 6, mac, 6);
    f[12] = (uint8_t)(ethertype >> 8); f[13] = (uint8_t)ethertype;
    if (!v6) {
        f[14] = 0x45; unsigned total = 20 + payload; f[16] = (uint8_t)(total >> 8); f[17] = (uint8_t)total; f[23] = (uint8_t)proto;
        if (proto == 6) f[14 + 20 + 12] = (uint8_t)(tcp_doff / 4 << 4);
        return 14 + total;
    }
    f[14] = 0x60; f[18] = (uint8_t)(payload >> 8); f[19] = (uint8_t)payload; f[20] = (uint8_t)proto;
    if (proto == 6) f[14 + 40 + 12] = (uint8_t)(tcp_doff / 4 << 4);
    return 14 + 40 + payload;
}
static void test_classifier(void) {
    uint8_t f[400];
    unsigned n = build_ip(f, 0x0800, 6, 20, false, 20); assert(is_sparse(f, n));            /* pure ACK */
    n = build_ip(f, 0x0800, 6, 32, false, 32); assert(is_sparse(f, n));                     /* ACK with options */
    n = build_ip(f, 0x0800, 6, 20 + 100, false, 20); assert(!is_sparse(f, n));              /* TCP data, however small: never reordered ahead of its flow */
    n = build_ip(f, 0x0800, 1, 64, false, 0); assert(is_sparse(f, n));                      /* ICMP echo */
    n = build_ip(f, 0x0800, 17, 60, false, 0); assert(is_sparse(f, n));                     /* DNS-sized UDP */
    n = build_ip(f, 0x0800, 17, 400 - 34, false, 0); assert(!is_sparse(f, 400));            /* bigger than the sparse limit */
    n = build_ip(f, 0x86dd, 58, 32, true, 0); assert(is_sparse(f, n));                      /* ICMPv6 */
    n = build_ip(f, 0x86dd, 6, 20, true, 20); assert(is_sparse(f, n));                      /* IPv6 pure ACK */
    n = build_ip(f, 0x86dd, 6, 20 + 50, true, 20); assert(!is_sparse(f, n));
    n = build_ip(f, 0x0806, 0, 28, false, 0); assert(is_sparse(f, 42));                     /* ARP */
    n = build_ip(f, 0x0800, 47, 20, false, 0); assert(!is_sparse(f, n));                    /* GRE: unknown is bulk */
    f[14] = 0x41; assert(!is_sparse(f, 60));                                                /* a bad header length is bulk, not a crash */
    assert(!is_sparse(f, 13));
}

/* Priority: off by default; on, sparse frames take the priority queue and are served first; data stays in order in the bulk queue. */
static void test_priority(void) {
    uint8_t f[400];
    start(); tdongle_l2_link(true);
    tdongle_l2_tuning_t t; tdongle_l2_get_tuning(&t);
    unsigned n = build_ip(f, 0x0800, 1, 64, false, 0);
    assert(host_in(f, n) == ESP_OK && stats().h2w_sparse == 0 && l2.sp_head == 0);          /* off: an ordinary frame */
    pump();
    t.prio = true; assert(tdongle_l2_set_tuning(&t) == ESP_OK);
    uint8_t d[200]; frame(d, 200, peer, mac, 1);
    for (unsigned i = 0; i < 3; i++) { d[20] = (uint8_t)i; assert(host_in(d, 200) == ESP_OK); }      /* three bulk frames (not sparse: unknown ethertype) */
    n = build_ip(f, 0x0800, 1, 64, false, 0); f[40] = 0xAA;
    assert(host_in(f, n) == ESP_OK && stats().h2w_sparse == 1 && stats().h2w_queue_depth == 4);
    n = build_ip(f, 0x0800, 6, 20, false, 20); f[40] = 0xBB;
    assert(host_in(f, n) == ESP_OK && stats().h2w_sparse == 2);
    n = build_ip(f, 0x0800, 1, 64, false, 0); f[40] = 0xCC;
    assert(host_in(f, n) == TUSB_NET_RX_HOLD && stats().h2w_sparse == 2);   /* the priority queue was full (2): this one is bulk, and the bulk queue is at its limit: held */
    check_identities();
    /* Served: sparse first (in arrival order), then the bulk frames in order. */
    uint8_t order_seen[8]; unsigned k = 0;
    tx_script_n = 0;
    while (stats().h2w_queue_depth) {
        const unsigned sp_before = l2.sp_tail;
        if (l2.sp_tail != l2.sp_head) { deliver_frame(&l2.sp_slots[l2.sp_tail & SPARSE_MASK], true); atomic_store(&l2.sp_tail, sp_before + 1); assert(last_sparse); }
        else { unsigned tail = atomic_load(&l2.tail); deliver(&l2.slots[tail & SLOT_MASK]); atomic_store(&l2.tail, tail + 1); assert(!last_sparse); }
        order_seen[k++] = tx_seen[tx_seen_len > 40 ? 40 : 20];
    }
    assert(k == 5 && order_seen[0] == 0xAA && order_seen[1] == 0xBB);
    check_identities();
    /* Through the real worker pass the same way: sparse before bulk. */
    for (unsigned i = 0; i < 2; i++) { d[20] = (uint8_t)i; assert(host_in(d, 200) == ESP_OK); }
    n = build_ip(f, 0x0800, 1, 64, false, 0); f[40] = 0xDD; assert(host_in(f, n) == ESP_OK);
    assert(pump() == 3 && last_sparse == false && tx_seen[20] == 1);   /* the last frame sent was bulk frame 1; the sparse one went first */
    check_identities();
}

/* Tuning: bounds are checked as a whole, a rejected set changes nothing, a set takes effect at once. */
static void test_tuning(void) {
    start();
    tdongle_l2_tuning_t t, back; tdongle_l2_get_tuning(&t);
    assert(t.queue_limit == TDONGLE_L2_HOST_QUEUE_LIMIT && t.resume_depth == TDONGLE_L2_HOST_RESUME_DEPTH && t.sojourn_ms == TDONGLE_L2_SOJOURN_MS && !t.prio);
    tdongle_l2_tuning_t bad = t;
    bad.queue_limit = 0; assert(tdongle_l2_set_tuning(&bad) == ESP_ERR_INVALID_ARG);
    bad = t; bad.queue_limit = TDONGLE_L2_HOST_SLOTS + 1; assert(tdongle_l2_set_tuning(&bad) == ESP_ERR_INVALID_ARG);
    bad = t; bad.resume_depth = t.queue_limit; assert(tdongle_l2_set_tuning(&bad) == ESP_ERR_INVALID_ARG);
    bad = t; bad.sojourn_ms = TDONGLE_L2_SOJOURN_MS_MIN - 1; assert(tdongle_l2_set_tuning(&bad) == ESP_ERR_INVALID_ARG);
    bad = t; bad.sojourn_ms = TDONGLE_L2_SOJOURN_MS_MAX + 1; assert(tdongle_l2_set_tuning(&bad) == ESP_ERR_INVALID_ARG);
    bad = t; bad.queue_limit = 5; bad.sojourn_ms = 0; assert(tdongle_l2_set_tuning(&bad) == ESP_ERR_INVALID_ARG);   /* one bad field: nothing applied */
    tdongle_l2_get_tuning(&back); assert(!memcmp(&back, &t, sizeof(t)));
    t.queue_limit = 5; t.resume_depth = 2; t.sojourn_ms = 40;
    assert(tdongle_l2_set_tuning(&t) == ESP_OK);
    tdongle_l2_get_tuning(&back); assert(!memcmp(&back, &t, sizeof(t)));
    uint8_t f[200]; frame(f, 200, peer, mac, 1);
    tdongle_l2_link(true);
    for (unsigned i = 0; i < 5; i++) assert(host_in(f, 200) == ESP_OK);
    assert(host_in(f, 200) == TUSB_NET_RX_HOLD);                                         /* the new limit */
    assert(pump() == 5 && resumes == 1);                                                  /* resumed at depth 2 (once) */
    advance_us(40000); assert(host_in(f, 200) == ESP_OK);
    advance_us(40000); tx_calls = 0; assert(pump() == 1 && tx_calls == 0 && stats().h2w_sojourn_drop == 1);   /* the new sojourn limit: 40 ms */
    check_identities();
}

/* The radio's dwell: a frame that waited for room is counted, with how long. */
static void test_room_wait_stats(void) {
    uint8_t f[200]; frame(f, 200, peer, mac, 1);
    start(); tdongle_l2_link(true);
    room = false;
    assert(host_in(f, 200) == ESP_OK);
    hook_calls = 0;
    wait_hook = open_room_after_three;
    assert(pump() == 1);
    wait_hook = NULL;
    tdongle_l2_stats_t s = stats();
    assert(s.h2w_room_waits == 1 && s.h2w_room_wait_us_max == 3 * TDONGLE_L2_RETRY_US && s.h2w_room_wait_us_sum == 3 * TDONGLE_L2_RETRY_US && s.h2w_sent == 1);
    check_identities();
}

static void test_tick_scale(void) {
    printf("  retry period %u us, sojourn limit %u ms, queue limit %u of %u slots (tick %d ms: unused by the worker)\n", TDONGLE_L2_RETRY_US, TDONGLE_L2_SOJOURN_MS,
           TDONGLE_L2_HOST_QUEUE_LIMIT, TDONGLE_L2_HOST_SLOTS, TEST_TICK_MS);
    assert(sizeof(host_slot_t) <= TDONGLE_L2_SLOT_BYTES);
}

int main(void) {
    test_start();
    test_to_host();
    test_pm_notes();
    test_to_wifi();
    test_backpressure();
    test_counter_wrap();
    test_link_flap();
    test_retry();
    test_sojourn();
    test_depth_never_wraps();
    test_rx_race();
    test_classifier();
    test_priority();
    test_tuning();
    test_room_wait_stats();
    test_tick_scale();
    free(l2.slots);
    puts("Bridge l2: filters, both directions, every drop counted once, the driver buffer freed once, queue order and wrap, stale links, bounded retry, clock notes");
    return 0;
}
