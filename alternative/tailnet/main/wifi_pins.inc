/* The Wi-Fi pin budget (wifi_pin_budget.h, ADR 0022 amendment 2, ADR 0023). Included by gateway_main.c after wifi_link.inc. One mechanism
 * for both modes of the image; what differs is only who submits a frame:
 *   tailnet mode  the STA netif's driver hooks below (lwIP wlanif -> transmit_wrap), plus the RX hooks on its lwIP netif;
 *   bridge mode   there is no netif: the bridge's host -> Wi-Fi worker (tdongle_l2) calls wifi_pins_tx() itself, and a received frame is
 *                 copied out of the driver buffer at once (nothing pins RX), so only the TX half applies. wifi_pins_install(NULL).
 * Both feed the same counters and the same tx-done callback, so the accounting identity (charged = done + aborted + flushed + stale +
 * in flight) and the heap floor hold in either mode.
 *
 * Three hooks, all installed once, before Wi-Fi starts:
 *   TX  wifi_pins_tx(): the same call IDF's wifi_transmit makes, esp_wifi_internal_tx(WIFI_IF_STA, ...), behind gw_wtx_admit. In tailnet
 *       mode it replaces the netif driver's transmit / transmit_wrap (components/esp_wifi/src/wifi_netif.c): lwIP's wlanif calls
 *       transmit_wrap for every frame.
 *   TX  esp_wifi_set_tx_done_cb: one global callback, ours (nothing in IDF 5.5.5 uses it), releases the charge.
 *   RX  (tailnet only) netif->input and the pbuf's custom free function: the driver's RX buffer is wrapped by a custom pbuf
 *       (esp_pbuf_allocate) that lwIP frees exactly once, wherever it ends up (a socket mailbox, the TCP window, the tcpip mailbox), so
 *       counting at input and at that free is exact. A refused frame is freed here, before lwIP sees it.
 * The IDF handlers are left as they are for everything else (the driver handle, the MAC filter, the RX callback IDF registers on
 * every connect, which still ends in esp_netif_receive -> wlanif_input -> netif->input). */
#include "esp_private/wifi.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "wifi_pin_budget.h"

/* 0: leave RX alone (counting and gating are the same code, so this is the one switch if the RX gate has to come out on the board). */
#ifndef GATEWAY_WIFI_RX_GATE
#define GATEWAY_WIFI_RX_GATE 1
#endif

static gateway_wifi_pins wifi_pins = GATEWAY_WIFI_PINS_INIT;
static volatile bool wifi_pins_tx_done_ok;      /* the tx-done callback is registered: charges are released by the driver */
static volatile bool wifi_pins_installed;
static netif_input_fn wifi_pins_orig_input;
static pbuf_free_custom_fn wifi_pins_orig_free;

static unsigned wifi_pins_tx_outstanding(void) { return gw_wtx_outstanding(&wifi_pins); }   /* for /status and the heap-low records */
static unsigned wifi_pins_rx_inflight(void) { return gw_wrx_inflight(&wifi_pins); }
static uint32_t wifi_pins_now_ms(void) { return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS); }

/* A frame no bigger than this is let through when the tx-done callback could not be registered (no counter to hold a band with):
 * ACKs, ARP, DHCP, DNS, keepalives. */
#define WIFI_PINS_SMALL_FRAME 256u

/* Send one frame on the STA interface, charged to the budget. ESP_ERR_NO_MEM: refused for buffers (the bridge retries it for a few
 * milliseconds, lwIP's TCP keeps the segment). Any context that may call esp_wifi_internal_tx. */
static esp_err_t wifi_pins_tx(void *buffer, uint16_t len) {
    const size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (wifi_pins_tx_done_ok) {
        if (!gw_wtx_admitted(gw_wtx_admit(&wifi_pins, (unsigned)len, free_internal, wifi_pins_now_ms())))
            return ESP_ERR_NO_MEM;     /* wlanif: ERR_MEM; tcp_output keeps the segment and retries (no loss, no window cut) */
        const int result = esp_wifi_internal_tx(WIFI_IF_STA, buffer, len);
        if (result != ESP_OK) gw_wtx_abort(&wifi_pins);     /* no driver buffer exists, so no tx-done will come */
        return result;
    }
    /* Degraded (callback not registered): the heap floor alone, small frames exempt. Nothing is counted, nothing can leak. */
    if (len > WIFI_PINS_SMALL_FRAME && !ml_hb_ok(free_internal, gw_wtx_cost((unsigned)len))) {
        atomic_fetch_add_explicit(&wifi_pins.tx_refused_heap, 1, memory_order_relaxed);
        return ESP_ERR_NO_MEM;
    }
    return esp_wifi_internal_tx(WIFI_IF_STA, buffer, len);
}
/* Bridge: the worker waits for a free charge instead of being refused (and counting a refusal) every retry period. */
static bool wifi_pins_tx_room(void) { return gw_wtx_room(&wifi_pins); }
/* Bridge: the most frames the radio is given at once (0: the driver's pool). See GATEWAY_BRIDGE_WIFI_TX_INFLIGHT in gateway_main.c. */
static void wifi_pins_set_tx_limit(unsigned limit) { atomic_store_explicit(&wifi_pins.tx_limit, limit, memory_order_relaxed); }
static esp_err_t wifi_pins_transmit_wrap(void *h, void *buffer, size_t len, void *netstack_buffer) {
    (void)h;
    (void)netstack_buffer;
    if (len > UINT16_MAX) return ESP_ERR_INVALID_ARG;
    return wifi_pins_tx(buffer, (uint16_t)len);
}
static esp_err_t wifi_pins_transmit(void *h, void *buffer, size_t len) { return wifi_pins_transmit_wrap(h, buffer, len, NULL); }
static void wifi_pins_driver_free_rx(void *h, void *buffer) {
    (void)h;
    if (buffer) esp_wifi_internal_free_rx_buffer(buffer);
}

/* pp task: a frame completed (sent, or failed: the flag says which, and either way the buffer is free). Must stay in IRAM and call
 * only IRAM code: this task runs while the flash cache is off. */
static void IRAM_ATTR wifi_pins_tx_done(uint8_t ifidx, uint8_t *data, uint16_t *data_len, bool tx_ok) {
    (void)ifidx;
    (void)data;
    (void)data_len;
    (void)tx_ok;
    gw_wtx_done(&wifi_pins);
}

/* The pbuf of an admitted RX frame is being freed: the driver buffer under it goes with it, and the slot comes back. */
static void wifi_pins_rx_free(struct pbuf *p) {
    gw_wrx_release(&wifi_pins);
    wifi_pins_orig_free(p);
}
/* Wi-Fi task: a received frame on its way to lwIP. `free_after` already excludes the driver buffer under p. */
static err_t wifi_pins_input(struct pbuf *p, struct netif *netif) {
    if (p && (p->flags & PBUF_FLAG_IS_CUSTOM)) {
        struct pbuf_custom *pc = (struct pbuf_custom *)p;
        /* Every RX pbuf of this netif is esp_netif's (one free function). Anything else is passed through uncounted. */
        if (pc->custom_free_function != wifi_pins_rx_free &&
            (!wifi_pins_orig_free || pc->custom_free_function == wifi_pins_orig_free)) {
            if (!gw_wrx_admit(&wifi_pins, heap_caps_get_free_size(MALLOC_CAP_INTERNAL))) {
                pbuf_free(p);          /* frees the driver buffer; wlanif_input sees ERR_OK and reports the frame consumed */
                return ERR_OK;
            }
            wifi_pins_orig_free = pc->custom_free_function;
            pc->custom_free_function = wifi_pins_rx_free;
        }
    }
    return wifi_pins_orig_input(p, netif);
}

/* After esp_netif_create_default_wifi_sta() (or with NULL in bridge mode), before esp_wifi_init(): nothing is in flight, so the TX hooks go in without a lock. Failure
 * leaves IDF's own handlers in place (the budget is then off and the status says so). The RX hook is NOT installed here: the lwIP netif
 * behind `sta` does not exist yet (esp_netif_new() only allocates it zeroed; netif_add(), which sets netif->input = tcpip_input, runs in
 * esp_netif_start_api() on WIFI_EVENT_STA_START), so lwip->input is NULL now. wifi_pins_hook_rx() does it once the netif is added. */
static esp_netif_t *wifi_pins_sta;
static volatile bool wifi_pins_rx_hooked;
static void wifi_pins_install(esp_netif_t *sta) {
    if (!sta) {     /* the transparent bridge: no netif to hook, its worker submits through wifi_pins_tx(); the RX hooks have nothing to attach to */
        wifi_pins_installed = true;
        return;
    }
    esp_netif_iodriver_handle h = esp_netif_get_io_driver(sta);
    if (!h) {
        ESP_LOGW("wifi", "pin budget not installed: STA netif has no driver handle");
        return;
    }
    esp_netif_driver_ifconfig_t driver = {.handle = h,
                                          .transmit = wifi_pins_transmit,
                                          .transmit_wrap = wifi_pins_transmit_wrap,
                                          .driver_free_rx_buffer = wifi_pins_driver_free_rx};
    if (esp_netif_set_driver_config(sta, &driver) != ESP_OK) {
        ESP_LOGW("wifi", "pin budget not installed: esp_netif_set_driver_config failed");
        return;
    }
    wifi_pins_sta = sta;
    wifi_pins_installed = true;
}
/* Put the RX gate in front of the STA netif's input. netif_add() sets netif->input every time the netif is (re)added (every
 * esp_netif_start, so again after an esp_wifi_stop/start), which silently removes the hook: this is idempotent and runs on every link
 * event and on got-IP, all after the netif exists and before the first frame of a new link (the RX callback is registered by IDF's own
 * connect handler). A frame that entered before the hook was in place carries the original free function and is passed through uncounted. */
static void wifi_pins_hook_rx(void) {
#if GATEWAY_WIFI_RX_GATE
    if (!wifi_pins_installed || !wifi_pins_sta) return;
    struct netif *lwip = esp_netif_get_netif_impl(wifi_pins_sta);
    if (!lwip || !lwip->input || lwip->input == wifi_pins_input) {
        wifi_pins_rx_hooked = lwip && lwip->input == wifi_pins_input;
        return;
    }
    wifi_pins_orig_input = lwip->input;     /* before the swap: wifi_pins_input reads it */
    lwip->input = wifi_pins_input;
    wifi_pins_rx_hooked = true;
#endif
}
/* After esp_wifi_start() (the API wants Wi-Fi running). */
static void wifi_pins_start(void) {
    if (!wifi_pins_installed) return;
    const esp_err_t e = esp_wifi_set_tx_done_cb(wifi_pins_tx_done);
    wifi_pins_tx_done_ok = e == ESP_OK;
    if (e != ESP_OK) ESP_LOGW("wifi", "tx-done callback not registered (%s): TX is held to the heap floor with small frames exempt", esp_err_to_name(e));
}
/* The driver clears its queues when the link drops or comes up, without completing the frames in them. */
static void wifi_pins_link_changed(void) {
    if (!wifi_pins_installed) return;
    wifi_pins_hook_rx();
    (void)gw_wtx_flush(&wifi_pins);
}
