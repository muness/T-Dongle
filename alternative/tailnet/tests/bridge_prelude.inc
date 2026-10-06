/* Stand-ins for the neighbours of the transparent bridge's real code, in ONE translation unit with the real sources (assembled by
 * tools/test-bridge-path.py): components/esp_tinyusb/tinyusb_net.c (the USB ring), components/tdongle_runtime/l2.c, main/wifi_pins.inc
 * (the Wi-Fi TX budget), main/bridge_status.inc and the real tdongle_pm_burst.c, over the strict FreeRTOS/TinyUSB mocks of tests/mocks/net.h.
 * This is the part that comes BEFORE those sources: the Wi-Fi driver, the esp_netif/lwIP names wifi_pins.inc mentions, the CPU-frequency locks. */
#include "tdongle_l2.h"
#include "tdongle_pm.h"
#include "tdongle_aqm.h"
#include "wifi_pin_budget.h"
atomic_uint ml_hb_refused[ML_HB_SITE_COUNT];
#define WIFI_IF_STA 0
#define ESP_IF_WIFI_STA 0
#define portTICK_PERIOD_MS TEST_TICK_MS
static const char *esp_err_to_name(int e) { (void)e; return "err"; }

/* ---- the Wi-Fi driver ------------------------------------------------------------------------------------------------------------------ */
/* A TX pool of GATEWAY_WIFI_TX_POOL buffers. A frame the driver accepts is copied into a buffer (heap, like the real one) and leaves it when
 * the test "airs" it (tx-done) or when the driver clears its queues (a link change: no tx-done for those). */
typedef struct { uint32_t cost; uint16_t len; uint8_t bytes[TDONGLE_L2_FRAME_MAX]; } drv_frame;
static pthread_mutex_t drv_lock = PTHREAD_MUTEX_INITIALIZER;
static drv_frame drv_q[GATEWAY_WIFI_TX_POOL + 1];
static unsigned drv_n;                          /* frames queued in the driver, oldest first (under drv_lock) */
static unsigned drv_pool = GATEWAY_WIFI_TX_POOL;
static esp_err_t drv_force_error;               /* esp_wifi_internal_tx fails with this (0: no) */
static unsigned drv_accepted, drv_aired, drv_cleared, drv_refused_pool, drv_calls;
typedef void (*wifi_tx_done_cb_t)(uint8_t ifidx, uint8_t *data, uint16_t *data_len, bool tx_ok);
static wifi_tx_done_cb_t drv_done_cb;
static esp_err_t drv_cb_result;                 /* esp_wifi_set_tx_done_cb result (0: registered) */
static esp_err_t esp_wifi_set_tx_done_cb(wifi_tx_done_cb_t cb) { if (drv_cb_result == ESP_OK) drv_done_cb = cb; return drv_cb_result; }
static void air_observe(const uint8_t *f, uint16_t len);        /* the test's observer of what reaches the air */
static _Atomic bool pm_must_be_max;             /* DFS is on in this world: the clock must be at its maximum whenever a frame is handed over to USB */
static _Atomic bool air_must_be_max;            /* ... and, in the cases that send only unicast frames, to the Wi-Fi driver */
static bool cpu_max(void);
static esp_err_t esp_wifi_internal_tx(int ifx, void *buffer, uint16_t len) {
    assert(ifx == WIFI_IF_STA && !in_producer && !in_crit);     /* the driver is never called from a callback */
    if (atomic_load(&air_must_be_max)) assert(cpu_max());
    esp_err_t r;
    pthread_mutex_lock(&drv_lock);
    drv_calls++;
    if (drv_force_error) r = drv_force_error;
    else if (drv_n >= drv_pool) { drv_refused_pool++; r = ESP_ERR_NO_MEM; }
    else {
        drv_frame *d = &drv_q[drv_n++];
        d->len = len;
        memcpy(d->bytes, buffer, len);
        d->cost = (uint32_t)gw_wtx_cost(len);
        atomic_fetch_add(&heap_live_bytes, (long)d->cost);
        drv_accepted++;
        r = ESP_OK;
    }
    pthread_mutex_unlock(&drv_lock);
    return r;
}
/* The pp task: n frames leave the air in order, each with its tx-done. */
static unsigned drv_complete(unsigned n) {
    unsigned done = 0;
    while (done < n) {
        drv_frame d;
        pthread_mutex_lock(&drv_lock);
        if (!drv_n) { pthread_mutex_unlock(&drv_lock); break; }
        d = drv_q[0];
        memmove(&drv_q[0], &drv_q[1], (drv_n - 1) * sizeof(drv_frame));
        drv_n--;
        atomic_fetch_sub(&heap_live_bytes, (long)d.cost);
        drv_aired++;
        pthread_mutex_unlock(&drv_lock);
        air_observe(d.bytes, d.len);
        if (drv_done_cb) drv_done_cb(0, NULL, NULL, true);
        done++;
    }
    return done;
}
/* The driver clears its queues on a link change and does NOT report those frames through tx-done. */
static void drv_clear(void) {
    pthread_mutex_lock(&drv_lock);
    for (unsigned i = 0; i < drv_n; i++) atomic_fetch_sub(&heap_live_bytes, (long)drv_q[i].cost);
    drv_cleared += drv_n;
    drv_n = 0;
    pthread_mutex_unlock(&drv_lock);
}
static unsigned drv_depth(void) { pthread_mutex_lock(&drv_lock); unsigned n = drv_n; pthread_mutex_unlock(&drv_lock); return n; }

/* RX: the driver calls the callback IDF-style in the Wi-Fi task, and the callback must free the driver buffer before it returns. */
typedef esp_err_t (*rxcb_t)(void *, uint16_t, void *);
static _Atomic(rxcb_t) drv_rxcb;                 /* registered by the event task, called by the Wi-Fi task */
static _Atomic unsigned rx_frees;
static esp_err_t esp_wifi_internal_reg_rxcb(int ifx, rxcb_t f) { assert(ifx == ESP_IF_WIFI_STA); atomic_store(&drv_rxcb, f); return ESP_OK; }
static void esp_wifi_internal_free_rx_buffer(void *p) { assert(p); atomic_fetch_add(&rx_frees, 1); }

/* ---- esp_netif / lwIP names main/wifi_pins.inc mentions (the bridge installs it with no netif; these only have to compile) ---- */
typedef int8_t err_t;
#define ERR_OK 0
#define PBUF_FLAG_IS_CUSTOM 0x02
struct pbuf;
struct netif;
typedef err_t (*netif_input_fn)(struct pbuf *, struct netif *);
typedef void (*pbuf_free_custom_fn)(struct pbuf *);
struct pbuf { struct pbuf *next; void *payload; uint16_t tot_len, len; uint8_t type_internal, flags; uint16_t ref; };
struct pbuf_custom { struct pbuf pbuf; pbuf_free_custom_fn custom_free_function; };
struct netif { netif_input_fn input; };
static void pbuf_free(struct pbuf *p) { (void)p; assert(0 && "the bridge has no lwIP pbufs"); }
typedef struct esp_netif_s esp_netif_t;
typedef void *esp_netif_iodriver_handle;
typedef struct {
    esp_netif_iodriver_handle handle;
    esp_err_t (*transmit)(void *h, void *buffer, size_t len);
    esp_err_t (*transmit_wrap)(void *h, void *buffer, size_t len, void *netstack_buffer);
    void (*driver_free_rx_buffer)(void *h, void *buffer);
} esp_netif_driver_ifconfig_t;
static esp_netif_iodriver_handle esp_netif_get_io_driver(esp_netif_t *n) { (void)n; assert(0 && "bridge mode installs without a netif"); return NULL; }
static void *esp_netif_get_netif_impl(esp_netif_t *n) { (void)n; assert(0); return NULL; }
static esp_err_t esp_netif_set_driver_config(esp_netif_t *n, const esp_netif_driver_ifconfig_t *c) { (void)n; (void)c; assert(0); return ESP_FAIL; }

/* ---- the USB side's carrier, as the host sees it ---- */
static _Atomic int host_carrier;
static _Atomic unsigned host_carrier_changes;
static void tud_network_link_state(int itf, bool up) { (void)itf; atomic_store(&host_carrier, up); atomic_fetch_add(&host_carrier_changes, 1); }

/* ---- CPU-frequency locks: the REAL tdongle_pm_burst/activity code over fake locks that assert strict pairing ---- */
static atomic_int usb_txq_lock, fwd_lock;       /* the backends: 1 while the CPU-max lock is held */
static bool lock_acquire(void *ctx) { atomic_int *h = ctx; const int was = atomic_exchange(h, 1); assert(was == 0); (void)was; return true; }
static void lock_release(void *ctx) { atomic_int *h = ctx; const int was = atomic_exchange(h, 0); assert(was == 1); (void)was; }
static uint32_t pm_now_us(void) { return (uint32_t)atomic_load(&mock_us); }
static const tdongle_pm_ops_t pm_ops = {lock_acquire, lock_release, pm_now_us, NULL};
static tdongle_pm_burst_t usb_tx_pm, fwd_burst;
static tdongle_pm_activity_t fwd_activity;
static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;
static bool timer_armed;
static uint32_t timer_due_us;
static void pm_arm(void *ctx, uint32_t delay_us) {   /* esp_timer_start_once: already armed is a no-op */
    (void)ctx;
    pthread_mutex_lock(&timer_lock);
    if (!timer_armed) { timer_armed = true; timer_due_us = pm_now_us() + delay_us; }
    pthread_mutex_unlock(&timer_lock);
}
void tdongle_pm_note_activity(void) { tdongle_pm_activity_note(&fwd_activity, pm_now_us()); }
static void pm_timer_poll(void) {                    /* esp_timer task */
    pthread_mutex_lock(&timer_lock);
    const bool fire = timer_armed && (int32_t)(pm_now_us() - timer_due_us) >= 0;
    if (fire) timer_armed = false;
    pthread_mutex_unlock(&timer_lock);
    if (fire) tdongle_pm_activity_tick(&fwd_activity, pm_now_us());
}
static void pm_usb_begin(void *ctx) { (void)ctx; tdongle_pm_burst_begin(&usb_tx_pm); }
static void pm_usb_end(void *ctx) { (void)ctx; tdongle_pm_burst_end(&usb_tx_pm); }
static bool cpu_max(void) { return atomic_load(&usb_txq_lock) || atomic_load(&fwd_lock); }

/* ---- the bridge's retry timer and wait (esp_timer + task notification), with time that moves only when the worker waits ---- */
typedef void *esp_timer_handle_t;
typedef struct { void (*callback)(void *); void *arg; const char *name; } esp_timer_create_args_t;
static void (*l2_timer_cb)(void *);
static pthread_mutex_t l2t_lock = PTHREAD_MUTEX_INITIALIZER;
static bool l2_timer_armed;
static uint64_t l2_timer_due;
static void (*wait_hook)(void);                  /* runs inside every retry wait: "the TinyUSB task keeps delivering frames meanwhile" */
static esp_err_t esp_timer_create(const esp_timer_create_args_t *a, esp_timer_handle_t *h) { l2_timer_cb = a->callback; *h = &l2_timer_cb; return ESP_OK; }
static esp_err_t esp_timer_delete(esp_timer_handle_t h) { (void)h; return ESP_OK; }
static esp_err_t esp_timer_start_once(esp_timer_handle_t h, uint64_t us) {
    (void)h;
    assert(!in_producer);
    esp_err_t r = ESP_ERR_INVALID_STATE;
    pthread_mutex_lock(&l2t_lock);
    if (!l2_timer_armed) { l2_timer_armed = true; l2_timer_due = (uint64_t)atomic_load(&mock_us) + us; r = ESP_OK; }
    pthread_mutex_unlock(&l2t_lock);
    return r;
}
/* l2.c's ulTaskNotifyTake: time passes until the armed timer fires (or the timeout), then the test may act. */
static uint32_t l2_notify_take(int clear, TickType_t ticks) {
    (void)clear;
    assert(!in_producer && !in_crit);
    pthread_mutex_lock(&l2t_lock);
    const bool armed = l2_timer_armed;
    const uint64_t due = l2_timer_due;
    l2_timer_armed = false;
    pthread_mutex_unlock(&l2t_lock);
    if (armed) { int64_t now = atomic_load(&mock_us); if ((uint64_t)now < due) atomic_fetch_add(&mock_us, (int64_t)(due - (uint64_t)now)); l2_timer_cb(NULL); }
    else atomic_fetch_add(&mock_us, (int64_t)ticks * TEST_TICK_MS * 1000);
#ifndef BRIDGE_THREADS
    pm_timer_poll();
#endif
    if (wait_hook) wait_hook();
    return 1;
}
