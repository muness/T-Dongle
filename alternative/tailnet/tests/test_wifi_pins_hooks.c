/* main/wifi_pins.inc against stand-ins for the IDF and lwIP calls it makes (the counting itself is tests/test_wifi_pin_budget.c).
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Wall -Wextra -I tests/host_pins \
 *      -I components/microlink/include -I main tests/test_wifi_pins_hooks.c -o build-host/test_wifi_pins_hooks
 *
 * What it pins down:
 *  1. Install order. esp_netif_create_default_wifi_sta() leaves the lwIP netif zeroed (netif_add runs at STA_START), so the TX hooks must
 *     install with netif->input NULL, and the RX hook must follow once the netif is added, survive repeated events, and come back after
 *     the netif is re-added (netif_add resets input).
 *  2. RX: exactly one release per admitted frame through pbuf_free (single, referenced, input error), the driver buffer freed exactly
 *     once on every road including a refusal, uncounted pass-through of a pbuf that is not esp_netif's.
 *  3. TX wrapper: charge, abort on a driver error, release by the tx-done callback, refusal as ESP_ERR_NO_MEM, the degraded path. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ml_heap_budget.h"
atomic_uint ml_hb_refused[ML_HB_SITE_COUNT];

typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL (-1)
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_LOGW(tag, ...) ((void)(tag))
__attribute__((unused)) static const char *esp_err_to_name(esp_err_t e) { (void)e; return "err"; }
#define MALLOC_CAP_INTERNAL 1
static size_t g_free_heap = 1u << 20;
static size_t heap_caps_get_free_size(int caps) { (void)caps; return g_free_heap; }
static uint32_t g_ticks;
static uint32_t xTaskGetTickCount(void) { return g_ticks; }
#define portTICK_PERIOD_MS 1u
#define WIFI_IF_STA 0

/* lwIP */
typedef int8_t err_t;
#define ERR_OK 0
#define ERR_MEM (-1)
#define PBUF_FLAG_IS_CUSTOM 0x02
struct pbuf;
struct netif;
typedef err_t (*netif_input_fn)(struct pbuf *, struct netif *);
typedef void (*pbuf_free_custom_fn)(struct pbuf *);
struct pbuf { struct pbuf *next; void *payload; uint16_t tot_len, len; uint8_t type_internal, flags; uint16_t ref; };
struct pbuf_custom { struct pbuf pbuf; pbuf_free_custom_fn custom_free_function; };
struct netif { netif_input_fn input; };
static void pbuf_free(struct pbuf *p) {         /* lwIP: the last reference of a custom pbuf calls its free function */
    assert(p->ref > 0);
    if (--p->ref) return;
    assert(p->flags & PBUF_FLAG_IS_CUSTOM);
    ((struct pbuf_custom *)p)->custom_free_function(p);
}
static void pbuf_ref(struct pbuf *p) { p->ref++; }

/* esp_netif / the driver */
typedef struct esp_netif_s esp_netif_t;
typedef void *esp_netif_iodriver_handle;
typedef struct {
    esp_netif_iodriver_handle handle;
    esp_err_t (*transmit)(void *h, void *buffer, size_t len);
    esp_err_t (*transmit_wrap)(void *h, void *buffer, size_t len, void *netstack_buffer);
    void (*driver_free_rx_buffer)(void *h, void *buffer);
} esp_netif_driver_ifconfig_t;
struct esp_netif_s { struct netif lwip; void *handle; esp_netif_driver_ifconfig_t cfg; };
static esp_netif_iodriver_handle esp_netif_get_io_driver(esp_netif_t *n) { return n->handle; }
static void *esp_netif_get_netif_impl(esp_netif_t *n) { return &n->lwip; }
static esp_err_t esp_netif_set_driver_config(esp_netif_t *n, const esp_netif_driver_ifconfig_t *c) { n->cfg = *c; return ESP_OK; }
typedef void (*wifi_tx_done_cb_t)(uint8_t ifidx, uint8_t *data, uint16_t *data_len, bool tx_ok);
static wifi_tx_done_cb_t g_done_cb;
static esp_err_t g_cb_result = ESP_OK;
static esp_err_t esp_wifi_set_tx_done_cb(wifi_tx_done_cb_t cb) { if (g_cb_result == ESP_OK) g_done_cb = cb; return g_cb_result; }
static esp_err_t g_tx_result = ESP_OK;
static unsigned g_tx_calls;
static esp_err_t esp_wifi_internal_tx(int ifx, void *buffer, uint16_t len) { (void)ifx; (void)buffer; (void)len; g_tx_calls++; return g_tx_result; }
static unsigned g_driver_frees;
static void esp_wifi_internal_free_rx_buffer(void *buffer) { assert(buffer); g_driver_frees++; }

#include "wifi_pins.inc"

/* esp_netif's RX pbuf (components/esp_netif/lwip/netif/esp_pbuf_ref.c): a custom pbuf over the driver buffer. */
typedef struct { struct pbuf_custom p; void *l2; } esp_custom_pbuf_t;
static unsigned g_esp_frees;
static void esp_pbuf_free(struct pbuf *p) {
    esp_custom_pbuf_t *e = (esp_custom_pbuf_t *)p;
    esp_wifi_internal_free_rx_buffer(e->l2);
    g_esp_frees++;
    free(e);
}
static struct pbuf *esp_rx_pbuf(void) {
    esp_custom_pbuf_t *e = calloc(1, sizeof(*e));
    e->p.custom_free_function = esp_pbuf_free;
    e->l2 = e;
    e->p.pbuf.flags = PBUF_FLAG_IS_CUSTOM;
    e->p.pbuf.ref = 1;
    return &e->p.pbuf;
}

/* lwIP's tcpip_input stand-in: queues the pbuf like the tcpip mailbox, or fails without freeing it (as tcpip_inpkt does). */
static struct pbuf *g_mbox[64];
static unsigned g_mbox_n;
static err_t g_input_result = ERR_OK;
static err_t tcpip_input_stub(struct pbuf *p, struct netif *n) {
    (void)n;
    if (g_input_result != ERR_OK) return g_input_result;
    g_mbox[g_mbox_n++] = p;
    return ERR_OK;
}
/* wlanif_input's tail: netif->input, and on failure the pbuf is freed by the caller (components/esp_netif/lwip/netif/wlanif.c). */
static err_t wlanif_input_stub(esp_netif_t *n, struct pbuf *p) {
    if (n->lwip.input(p, &n->lwip) != ERR_OK) { pbuf_free(p); return ESP_FAIL; }
    return ERR_OK;
}
static void drain_mbox(void) { while (g_mbox_n) pbuf_free(g_mbox[--g_mbox_n]); }
static void *any_handle = (void *)0x1;

int main(void) {
    esp_netif_t sta;
    memset(&sta, 0, sizeof(sta));
    sta.handle = any_handle;
    /* 1. create_default_wifi_sta: the lwIP netif exists but netif_add has not run, input is NULL. */
    wifi_pins_install(&sta);
    assert(wifi_pins_installed);                               /* the TX hooks do not need the netif */
    assert(sta.cfg.transmit_wrap == wifi_pins_transmit_wrap && sta.cfg.transmit == wifi_pins_transmit && sta.cfg.handle == any_handle);
    assert(sta.cfg.driver_free_rx_buffer == wifi_pins_driver_free_rx);
    wifi_pins_hook_rx();
    assert(!wifi_pins_rx_hooked && sta.lwip.input == NULL);    /* nothing to hook yet: no crash, no half state */
    wifi_pins_start();
    assert(wifi_pins_tx_done_ok && g_done_cb == wifi_pins_tx_done);
    /* STA_START: netif_add sets input; the first link event hooks it. */
    sta.lwip.input = tcpip_input_stub;
    wifi_pins_link_changed();
    assert(wifi_pins_rx_hooked && sta.lwip.input == wifi_pins_input && wifi_pins_orig_input == tcpip_input_stub);
    wifi_pins_link_changed(); wifi_pins_hook_rx();             /* idempotent: the original input is never replaced by our own */
    assert(sta.lwip.input == wifi_pins_input && wifi_pins_orig_input == tcpip_input_stub);
    /* esp_wifi_stop/start: netif_remove + netif_add resets input; the next event puts the hook back. */
    sta.lwip.input = tcpip_input_stub;
    wifi_pins_hook_rx();
    assert(sta.lwip.input == wifi_pins_input && wifi_pins_orig_input == tcpip_input_stub);

    /* 2. RX. One admitted frame: counted at input, released once when lwIP frees it. */
    struct pbuf *p = esp_rx_pbuf();
    assert(wlanif_input_stub(&sta, p) == ERR_OK && wifi_pins_rx_inflight() == 1 && g_mbox_n == 1 && g_esp_frees == 0);
    drain_mbox();
    assert(wifi_pins_rx_inflight() == 0 && g_esp_frees == 1 && g_driver_frees == 1);
    assert(atomic_load(&wifi_pins.rx_released) == 1 && atomic_load(&wifi_pins.rx_unmatched) == 0);
    /* The router's hold path (pbuf_ref): the count and the driver buffer go with the LAST reference, once. */
    p = esp_rx_pbuf();
    assert(wlanif_input_stub(&sta, p) == ERR_OK);
    pbuf_ref(p);
    pbuf_free(p);
    assert(wifi_pins_rx_inflight() == 1 && g_esp_frees == 1);
    pbuf_free(g_mbox[--g_mbox_n]);
    assert(wifi_pins_rx_inflight() == 0 && g_esp_frees == 2 && atomic_load(&wifi_pins.rx_unmatched) == 0);
    /* The stack refuses the frame (mailbox full): wlanif frees it, the count returns, the driver buffer is freed once. */
    g_input_result = ERR_MEM;
    p = esp_rx_pbuf();
    assert(wlanif_input_stub(&sta, p) != ERR_OK && wifi_pins_rx_inflight() == 0 && g_esp_frees == 3 && g_driver_frees == 3);
    g_input_result = ERR_OK;
    /* A pbuf that is not esp_netif's custom pbuf (L2_TO_L3_COPY, a PBUF_RAM copy) passes through uncounted. */
    struct pbuf plain = {.ref = 1, .flags = 0};
    assert(wifi_pins_input(&plain, &sta.lwip) == ERR_OK && wifi_pins_rx_inflight() == 0 && g_mbox_n == 1);
    g_mbox_n = 0;
    /* The gate: with the heap at the floor only the band (4 per direction) is admitted; the next frame is dropped and its driver buffer
     * freed at once, wlanif sees ERR_OK, lwIP never sees the frame. */
    g_free_heap = ML_HB_FLOOR - 1;
    struct pbuf *held[8];
    for (unsigned i = 0; i < GATEWAY_WIFI_RX_BAND_MAX; i++) { held[i] = esp_rx_pbuf(); assert(wlanif_input_stub(&sta, held[i]) == ERR_OK); }
    assert(wifi_pins_rx_inflight() == GATEWAY_WIFI_RX_BAND_MAX);
    const unsigned frees = g_esp_frees, mbox = g_mbox_n;
    p = esp_rx_pbuf();
    assert(wlanif_input_stub(&sta, p) == ERR_OK);
    assert(g_esp_frees == frees + 1 && g_mbox_n == mbox && wifi_pins_rx_inflight() == GATEWAY_WIFI_RX_BAND_MAX && atomic_load(&wifi_pins.rx_dropped) == 1);
    g_free_heap = 1u << 20;                                    /* heap above the floor: elastic admits again */
    p = esp_rx_pbuf();
    assert(wlanif_input_stub(&sta, p) == ERR_OK && wifi_pins_rx_inflight() == GATEWAY_WIFI_RX_BAND_MAX + 1);
    drain_mbox();
    assert(wifi_pins_rx_inflight() == 0 && atomic_load(&wifi_pins.rx_unmatched) == 0);
    assert(atomic_load(&wifi_pins.rx_band) + atomic_load(&wifi_pins.rx_elastic) == atomic_load(&wifi_pins.rx_released));
    assert(g_esp_frees == g_driver_frees);                     /* every driver buffer was freed, none twice (the stub would assert on NULL only: counts match) */

    /* 3. TX. A frame is charged, the driver's done releases it. */
    g_tx_calls = 0;
    assert(sta.cfg.transmit_wrap(any_handle, (void *)"x", 1514, NULL) == ESP_OK && wifi_pins_tx_outstanding() == 1 && g_tx_calls == 1);
    g_done_cb(WIFI_IF_STA, NULL, NULL, true);
    assert(wifi_pins_tx_outstanding() == 0 && atomic_load(&wifi_pins.tx_done) == 1);
    /* The driver refuses (no buffer): the charge is aborted, the error is returned, no done will come. */
    g_tx_result = ESP_ERR_NO_MEM;
    assert(sta.cfg.transmit(any_handle, (void *)"x", 1514) == ESP_ERR_NO_MEM && wifi_pins_tx_outstanding() == 0 && atomic_load(&wifi_pins.tx_aborted) == 1);
    g_tx_result = ESP_OK;
    /* The band is four frames; with the heap at the floor the fifth is refused as ESP_ERR_NO_MEM (lwIP: ERR_MEM) and charges nothing. */
    g_free_heap = ML_HB_FLOOR - 1;
    for (unsigned i = 0; i < GATEWAY_WIFI_TX_BAND_MAX; i++) assert(sta.cfg.transmit_wrap(any_handle, (void *)"x", 1514, NULL) == ESP_OK);
    g_tx_calls = 0;
    assert(sta.cfg.transmit_wrap(any_handle, (void *)"x", 1514, NULL) == ESP_ERR_NO_MEM && g_tx_calls == 0);
    assert(wifi_pins_tx_outstanding() == GATEWAY_WIFI_TX_BAND_MAX && atomic_load(&wifi_pins.tx_refused_heap) == 1);
    assert(sta.cfg.transmit_wrap(any_handle, (void *)"x", UINT16_MAX + 1u, NULL) == ESP_ERR_INVALID_ARG);
    /* A link event flushes, a done that follows (nothing outstanding) is counted and changes nothing. */
    wifi_pins_link_changed();
    assert(wifi_pins_tx_outstanding() == 0);
    g_done_cb(WIFI_IF_STA, NULL, NULL, true);
    assert(wifi_pins_tx_outstanding() == 0 && atomic_load(&wifi_pins.tx_unmatched) == 1);
    g_free_heap = 1u << 20;
    /* Degraded: no tx-done callback, nothing is counted, small frames pass at the floor, big frames need the heap. */
    wifi_pins_tx_done_ok = false;
    g_free_heap = ML_HB_FLOOR - 1;
    assert(sta.cfg.transmit_wrap(any_handle, (void *)"x", 66, NULL) == ESP_OK);
    assert(sta.cfg.transmit_wrap(any_handle, (void *)"x", 1514, NULL) == ESP_ERR_NO_MEM && wifi_pins_tx_outstanding() == 0);
    g_free_heap = 1u << 20;
    assert(sta.cfg.transmit_wrap(any_handle, (void *)"x", 1514, NULL) == ESP_OK && wifi_pins_tx_outstanding() == 0);
    /* 4. Bridge mode (ADR 0023): no netif. The budget installs with NULL, the same tx-done callback and counters serve wifi_pins_tx(), the RX hooks
     *    have nothing to attach to and stay out of the way, and a link event still flushes the charges the driver dropped. */
    memset(&wifi_pins, 0, sizeof(wifi_pins));
    pthread_mutex_init(&wifi_pins.lock, NULL);
    wifi_pins_installed = wifi_pins_tx_done_ok = wifi_pins_rx_hooked = false;
    wifi_pins_sta = NULL; wifi_pins_orig_input = NULL; g_done_cb = NULL; g_cb_result = ESP_OK;
    wifi_pins_start();                                         /* before install: nothing registered */
    assert(!wifi_pins_tx_done_ok && g_done_cb == NULL);
    wifi_pins_install(NULL);
    assert(wifi_pins_installed && wifi_pins_sta == NULL);
    wifi_pins_hook_rx();                                       /* no netif: no hook, no crash */
    assert(!wifi_pins_rx_hooked);
    wifi_pins_start();
    assert(wifi_pins_tx_done_ok && g_done_cb == wifi_pins_tx_done);
    g_free_heap = 1u << 20; g_tx_calls = 0; g_tx_result = ESP_OK;
    assert(wifi_pins_tx((void *)"x", 1514) == ESP_OK && wifi_pins_tx_outstanding() == 1 && g_tx_calls == 1);
    g_done_cb(WIFI_IF_STA, NULL, NULL, true);
    assert(wifi_pins_tx_outstanding() == 0 && atomic_load(&wifi_pins.tx_done) == 1);
    g_tx_result = ESP_ERR_NO_MEM;                              /* the driver refuses: aborted, the error comes back */
    assert(wifi_pins_tx((void *)"x", 1514) == ESP_ERR_NO_MEM && wifi_pins_tx_outstanding() == 0 && atomic_load(&wifi_pins.tx_aborted) == 1);
    g_tx_result = ESP_OK;
    g_free_heap = ML_HB_FLOOR - 1;                             /* the band, then the heap floor: the same rule as through the netif */
    for (unsigned i = 0; i < GATEWAY_WIFI_TX_BAND_MAX; i++) assert(wifi_pins_tx((void *)"x", 1514) == ESP_OK);
    g_tx_calls = 0;
    assert(wifi_pins_tx((void *)"x", 1514) == ESP_ERR_NO_MEM && g_tx_calls == 0 && atomic_load(&wifi_pins.tx_refused_heap) == 1);
    wifi_pins_link_changed();                                  /* the driver cleared its queues: the charges go, no netif needed */
    /* The bridge's allowance (ADR 0023 amendment 2): fewer frames in flight than the pool, waited for through wifi_pins_tx_room(), refused as pool-full if asked anyway. */
    g_free_heap = 1u << 20;
    assert(wifi_pins_tx_room());                               /* limit 0: the driver's pool */
    wifi_pins_set_tx_limit(2);
    assert(wifi_pins_tx((void *)"x", 1514) == ESP_OK && wifi_pins_tx_room() && wifi_pins_tx((void *)"x", 1514) == ESP_OK);
    assert(!wifi_pins_tx_room());
    g_tx_calls = 0;
    assert(wifi_pins_tx((void *)"x", 1514) == ESP_ERR_NO_MEM && g_tx_calls == 0 && atomic_load(&wifi_pins.tx_refused_pool) == 1);
    g_done_cb(WIFI_IF_STA, NULL, NULL, true);
    assert(wifi_pins_tx_room() && wifi_pins_tx((void *)"x", 1514) == ESP_OK);
    wifi_pins_set_tx_limit(0);
    wifi_pins_link_changed();
    assert(wifi_pins_tx_outstanding() == 0);
    assert(wifi_pins_tx_outstanding() == 0 && atomic_load(&wifi_pins.tx_flushed) >= GATEWAY_WIFI_TX_BAND_MAX);
    assert(atomic_load(&wifi_pins.tx_charged) == atomic_load(&wifi_pins.tx_done) + atomic_load(&wifi_pins.tx_aborted) +
                                                  atomic_load(&wifi_pins.tx_flushed) + atomic_load(&wifi_pins.tx_stale) + wifi_pins_tx_outstanding());
    (void)g_ticks;
    puts("wifi pins hooks: TX installs before the netif exists (or with none, in bridge mode), the RX hook follows netif_add and survives re-adds; RX/TX release exactly once");
    return 0;
}
