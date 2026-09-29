/*
 * SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 *
 * Based on the esp-idf tusb_ncm example; extended into the esp32-usb-eth
 * transparent L2 bridge (see README.md and pico-usb-wifi/esp32_plan.md):
 * reflection filter, host address snooping, and a CDC-ACM management console
 * with runtime credentials in NVS (console.c).
 */

#include "esp_rom_sys.h"
#include "soc/rtc_cntl_reg.h"
#include "app.h"
#include "device/dcd.h"
#include "device/usbd_pvt.h"
#include "esp_attr.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_private/wifi.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_net.h"
#include "tusb.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "bridge";
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static bridge_stats_t s_stats;
static addresses_t s_addr;
static bool s_connected;
static uint8_t s_mac[6];
static uint16_t s_reason;
static uint32_t s_epoch;
static uint32_t s_reconnects, s_usb_resets;
static uint64_t s_connected_ms;

#define COUNT(field)                                                                               \
    do {                                                                                           \
        portENTER_CRITICAL(&s_lock);                                                               \
        s_stats.field++;                                                                           \
        portEXIT_CRITICAL(&s_lock);                                                                \
    } while (0)
/* Crash telemetry. RTC slow memory is not cleared on a warm reset (panic or
 * watchdog), so on recovery these fields still hold the tallies and the
 * counter snapshot from just before the crash; a cold power-on leaves the
 * region indeterminate, which the magic word detects. A 1 s timer refreshes
 * the snapshot while the firmware is healthy. */
#define CRASHLOG_MAGIC                                                                             \
    0x45555748u /* "EUWH": bumped when the layout changes,                                         \
                   so a reflash never misreads stale RTC RAM */
typedef struct {
    uint32_t magic;
    uint32_t boots, hangs, faults;
    uint32_t streak; /* consecutive crashes without 30 s of healthy uptime */
    uint32_t host_to_wifi, wifi_to_host, txdrop, reflected, poolfail, rxdrop;
} crashlog_t;
static RTC_NOINIT_ATTR crashlog_t s_crashlog;
static bridge_crash_info_t s_crash; /* boot-time evaluation, served to the console */
static esp_timer_handle_t s_snapshot_timer;
/* Heartbeat from the TinyUSB task: if it stops (wedged USB stack), restart instead of hanging. */
static volatile int64_t s_usb_alive_us;

static void snapshot_timer_cb(void *arg) {
    portENTER_CRITICAL(&s_lock);
    s_crashlog.host_to_wifi = s_stats.host_to_wifi;
    s_crashlog.wifi_to_host = s_stats.wifi_to_host;
    s_crashlog.txdrop = s_stats.txdrop;
    s_crashlog.reflected = s_stats.reflected;
    s_crashlog.poolfail = s_stats.poolfail;
    s_crashlog.rxdrop = s_stats.rxdrop;
    portEXIT_CRITICAL(&s_lock);
    int64_t now = esp_timer_get_time();
    if (now > 30000000)
        s_crashlog.streak = 0; /* survived long enough: not a crash loop */
    if (s_usb_alive_us && now - s_usb_alive_us > 10000000) {
        s_crashlog.hangs++;
        esp_restart(); /* USB task stalled for 10 s: self-recover */
    }
}

static void crashlog_boot(void) {
    esp_reset_reason_t rr = esp_reset_reason();
    bool warm =
        (rr != ESP_RST_POWERON && rr != ESP_RST_BROWNOUT && s_crashlog.magic == CRASHLOG_MAGIC);
    if (!warm) {
        memset(&s_crashlog, 0, sizeof(s_crashlog));
        s_crashlog.magic = CRASHLOG_MAGIC;
    } else {
        s_crash.pre.host_to_wifi = s_crashlog.host_to_wifi;
        s_crash.pre.wifi_to_host = s_crashlog.wifi_to_host;
        s_crash.pre.txdrop = s_crashlog.txdrop;
        s_crash.pre.reflected = s_crashlog.reflected;
        s_crash.pre.poolfail = s_crashlog.poolfail;
        s_crash.pre.rxdrop = s_crashlog.rxdrop;
        if (rr == ESP_RST_PANIC) {
            s_crashlog.faults++;
            s_crash.recovered = "panic";
        } else if (rr == ESP_RST_TASK_WDT || rr == ESP_RST_INT_WDT || rr == ESP_RST_WDT) {
            s_crashlog.hangs++;
            s_crash.recovered = "watchdog";
        }
        if (s_crash.recovered && ++s_crashlog.streak >= 3) {
            /* Crash loop: drop into the ROM download mode so tools/flash.sh can recover the
             * dongle without the BOOT button. */
            s_crashlog.streak = 0;
            REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
            esp_rom_software_reset_system(); /* see control.c: no RTC watchdog left armed */
        }
    }
    s_crashlog.boots++;
    s_crash.boots = s_crashlog.boots;
    s_crash.hangs = s_crashlog.hangs;
    s_crash.faults = s_crashlog.faults;
    if (s_crash.recovered) {
        ESP_LOGW(TAG, "RECOVERED from %s (boot #%lu, hangs=%lu faults=%lu)", s_crash.recovered,
                 (unsigned long)s_crash.boots, (unsigned long)s_crash.hangs,
                 (unsigned long)s_crash.faults);
    }
}

void bridge_get_crash(bridge_crash_info_t *c) { *c = s_crash; }

void bridge_clear_addresses(void) {
    portENTER_CRITICAL(&s_lock);
    memset(&s_addr, 0, sizeof(s_addr));
    s_epoch++;
    portEXIT_CRITICAL(&s_lock);
}
void bridge_get_stats(bridge_stats_t *s) {
    portENTER_CRITICAL(&s_lock);
    *s = s_stats;
    portEXIT_CRITICAL(&s_lock);
}
void bridge_get_mac(uint8_t mac[6]) { memcpy(mac, s_mac, 6); }
bool bridge_wifi_connected(void) {
    portENTER_CRITICAL(&s_lock);
    bool v = s_connected;
    portEXIT_CRITICAL(&s_lock);
    return v;
}
uint64_t bridge_connected_since_ms(void) {
    portENTER_CRITICAL(&s_lock);
    uint64_t since = s_connected ? s_connected_ms : 0;
    portEXIT_CRITICAL(&s_lock);
    return since;
}
void bridge_snapshot(bridge_snapshot_t *s) {
    portENTER_CRITICAL(&s_lock);
    s->stats = s_stats;
    s->addresses = s_addr;
    s->associated = s_connected;
    s->last_reason = s_reason;
    s->reconnects = s_reconnects;
    s->usb_resets = s_usb_resets;
    s->connected_ms = s_connected_ms;
    s->suspended = tud_suspended();
    portEXIT_CRITICAL(&s_lock);
    s->now_ms = esp_timer_get_time() / 1000;
    s->usb_mounted = tud_mounted();
    s->usb_ready = tud_ready();
    wifi_ap_record_t ap;
    s->rssi = esp_wifi_sta_get_ap_info(&ap) == ESP_OK ? ap.rssi : INT8_MIN;
}
bool bridge_host_ipv4(uint8_t ip[4]) {
    portENTER_CRITICAL(&s_lock);
    bool v = address_fresh(s_addr.valid4, s_addr.seen4, esp_timer_get_time() / 1000);
    if (v)
        memcpy(ip, s_addr.ip4, 4);
    portEXIT_CRITICAL(&s_lock);
    return v;
}
bool bridge_host_ipv6(uint8_t ip[16]) {
    portENTER_CRITICAL(&s_lock);
    bool v = address_fresh(s_addr.valid6, s_addr.seen6, esp_timer_get_time() / 1000);
    if (v)
        memcpy(ip, s_addr.ip6, 16);
    portEXIT_CRITICAL(&s_lock);
    return v;
}
const char *bridge_link_status(void) {
    portENTER_CRITICAL(&s_lock);
    bool up = s_connected;
    unsigned reason = s_reason;
    portEXIT_CRITICAL(&s_lock);
    if (up)
        return "up";
    switch (reason) {
    case WIFI_REASON_NO_AP_FOUND:
        return "AP not found";
    case WIFI_REASON_AUTH_FAIL:
    case WIFI_REASON_AUTH_EXPIRE:
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
        return "auth failed";
    default:
        return "joining";
    }
}
static esp_err_t usb_recv_callback(void *buffer, uint16_t len, void *ctx) {
    if (len < 14 || len > 1514) {
        COUNT(malformed);
        return ESP_OK;
    }
    /* One station MAC only: reject a host trying a different source MAC. */
    if (memcmp((uint8_t *)buffer + 6, s_mac, 6)) {
        COUNT(txdrop);
        return ESP_OK;
    }
    if (!bridge_wifi_connected()) {
        COUNT(txdrop);
        return ESP_OK;
    }
    /* The Wi-Fi driver refuses a frame when its TX queue is full, which is ordinary
     * backpressure under load. Retry briefly rather than drop: this runs inside the TinyUSB
     * task, so waiting here simply delays the host's next OUT transfer. Keep it short so the
     * console and the Wi-Fi-to-host direction, which share the task, are not starved. */
    esp_err_t tx = ESP_FAIL;
    for (int attempt = 0; attempt < 20; attempt++) {
        tx = esp_wifi_internal_tx(ESP_IF_WIFI_STA, buffer, len);
        if (tx == ESP_OK || !bridge_wifi_connected())
            break;
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    if (tx == ESP_OK) {
        portENTER_CRITICAL(&s_lock);
        s_stats.host_to_wifi++;
        s_stats.up_bytes += len;
        if (s_connected)
            observe_packet(&s_addr, buffer, len, esp_timer_get_time() / 1000);
        portEXIT_CRITICAL(&s_lock);
    } else
        COUNT(poolfail);
    return ESP_OK; /* Wi-Fi internal_tx copies; USB owns source buffer. */
}
/* RX callback always releases the driver buffer. Fixed copied frames move to a
 * worker, so USB congestion never blocks the high-priority Wi-Fi task. */
#define RX_SLOTS 32
#define FRAME_MAX 1514
static struct {
    uint16_t len;
    uint32_t epoch;
    uint8_t bytes[FRAME_MAX];
} s_frames[RX_SLOTS];
static QueueHandle_t s_free, s_pending;
static void wifi_pkt_free(void *cookie, void *ctx) {
    unsigned i = (unsigned)(uintptr_t)cookie;
    if (i < RX_SLOTS)
        xQueueSend(s_free, &i, 0);
}
static esp_err_t pkt_wifi2usb(void *buffer, uint16_t len, void *eb) {
    unsigned i;
    if (len < 14 || len > FRAME_MAX)
        COUNT(malformed);
    else if (frame_reflected(buffer, len, s_mac))
        COUNT(reflected);
    else if (!tud_ready() || !bridge_wifi_connected() || xQueueReceive(s_free, &i, 0) != pdTRUE)
        COUNT(rxdrop);
    else {
        portENTER_CRITICAL(&s_lock);
        s_frames[i].epoch = s_epoch;
        portEXIT_CRITICAL(&s_lock);
        s_frames[i].len = len;
        memcpy(s_frames[i].bytes, buffer, len);
        if (xQueueSend(s_pending, &i, 0) != pdTRUE) {
            xQueueSend(s_free, &i, 0);
            COUNT(rxdrop);
        }
    }
    esp_wifi_internal_free_rx_buffer(eb);
    return ESP_OK;
}
bool tud_network_default_link_state_cb(void) { return bridge_wifi_connected(); }
static void update_usb_link(void *arg) {
    s_usb_alive_us = esp_timer_get_time();
    tud_network_link_state(0, bridge_wifi_connected());
}
static void tx_worker(void *arg) {
    unsigned i;
    bool last_link = false;
    int64_t last_beat = 0;
    for (;;) {
        /* Refresh the NCM link state only on a change, plus a 1 s heartbeat. Deferring on every
         * loop pass (one per forwarded frame) competes with ISR transfer-complete events for the
         * 16-entry TinyUSB event queue; an ISR event dropped there leaves an endpoint stuck. */
        bool link = bridge_wifi_connected();
        int64_t now = esp_timer_get_time();
        if (link != last_link || now - last_beat >= 1000000) {
            last_link = link;
            last_beat = now;
            usbd_defer_func(update_usb_link, NULL, false);
        }
        if (xQueueReceive(s_pending, &i, pdMS_TO_TICKS(100)) == pdTRUE) {
            uint16_t len = s_frames[i].len;
            portENTER_CRITICAL(&s_lock);
            bool current = s_frames[i].epoch == s_epoch;
            portEXIT_CRITICAL(&s_lock);
            /* NCM refuses a frame (ESP_FAIL) while every IN transfer block is in flight to the
             * host. That is ordinary backpressure at full-speed USB, not an error: wait a tick
             * and retry for up to ~300 ms before counting a drop. */
            esp_err_t e = ESP_ERR_INVALID_STATE;
            for (int attempt = 0; attempt < 30; attempt++) {
                if (!(current && bridge_wifi_connected() && tud_ready()))
                    break;
                e = tinyusb_net_send_sync(s_frames[i].bytes, len, (void *)(uintptr_t)i,
                                          pdMS_TO_TICKS(20));
                if (e != ESP_FAIL)
                    break;
                vTaskDelay(pdMS_TO_TICKS(10));
            }
            if (e != ESP_OK) {
                COUNT(rxdrop);
                xQueueSend(s_free, &i, 0);
            } else {
                portENTER_CRITICAL(&s_lock);
                s_stats.wifi_to_host++;
                s_stats.down_bytes += len;
                portEXIT_CRITICAL(&s_lock);
            }
        }
    }
}
static void wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *d = data;
        portENTER_CRITICAL(&s_lock);
        s_connected = false;
        s_reason = d->reason;
        s_connected_ms = 0;
        memset(&s_addr, 0, sizeof(s_addr));
        s_epoch++;
        portEXIT_CRITICAL(&s_lock);
        esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA, NULL);
        app_event(2, d->reason);
    } else if (id == WIFI_EVENT_STA_CONNECTED) {
        bridge_clear_addresses();
        esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA, pkt_wifi2usb);
        portENTER_CRITICAL(&s_lock);
        s_connected = true;
        s_connected_ms = esp_timer_get_time() / 1000;
        portEXIT_CRITICAL(&s_lock);
        app_event(1, 0);
    }
}
esp_err_t wifi_apply_creds(const char *ssid, const char *pass) {
    portENTER_CRITICAL(&s_lock);
    s_connected = false;
    s_connected_ms = 0;
    s_reconnects++;
    memset(&s_addr, 0, sizeof(s_addr));
    s_epoch++;
    portEXIT_CRITICAL(&s_lock);
    esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA, NULL);
    esp_wifi_disconnect();
    wifi_config_t c = {0};
    memcpy(c.sta.ssid, ssid, strlen(ssid));
    memcpy(c.sta.password, pass, strlen(pass));
    c.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
    c.sta.pmf_cfg.capable = true;
    c.sta.threshold.authmode = pass[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    /* Same SSID can exist on several APs/nodes. Scan every channel and join the strongest one;
     * the default fast scan takes the first match, which may be a far, weak node. */
    c.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    c.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    esp_err_t e = esp_wifi_set_config(WIFI_IF_STA, &c);
    if (e == ESP_OK && ssid[0])
        e = esp_wifi_connect();
    return e;
}
/* TinyUSB driver owns mount callbacks. Its device event callback is below. */
static void usb_event(tinyusb_event_t *event, void *arg) {
    bridge_clear_addresses();
    app_event(3, event->id);
}
void tud_event_hook_cb(uint8_t rhport, uint32_t eventid, bool in_isr) {
    if (eventid != DCD_EVENT_BUS_RESET && eventid != DCD_EVENT_UNPLUGGED)
        return;
    if (in_isr)
        portENTER_CRITICAL_ISR(&s_lock);
    else
        portENTER_CRITICAL(&s_lock);
    if (eventid == DCD_EVENT_BUS_RESET)
        s_usb_resets++;
    memset(&s_addr, 0, sizeof(s_addr));
    s_epoch++;
    if (in_isr)
        portEXIT_CRITICAL_ISR(&s_lock);
    else
        portEXIT_CRITICAL(&s_lock);
}
void app_main(void) {
    crashlog_boot();
    esp_err_t e = nvs_flash_init();
    /* Never erase credentials automatically on storage trouble. */
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "NVS unavailable: %s; ROM recovery required", esp_err_to_name(e));
        return;
    }
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_read_mac(s_mac, ESP_MAC_WIFI_STA);
    s_free = xQueueCreate(RX_SLOTS, sizeof(unsigned));
    s_pending = xQueueCreate(RX_SLOTS, sizeof(unsigned));
    assert(s_free && s_pending);
    for (unsigned i = 0; i < RX_SLOTS; i++)
        xQueueSend(s_free, &i, 0);
    static char serial[13];
    snprintf(serial, sizeof(serial), "%02X%02X%02X%02X%02X%02X", s_mac[0], s_mac[1], s_mac[2],
             s_mac[3], s_mac[4], s_mac[5]);
    static const char language[] = {0x09, 0x04};
    static const char *strings[] = {language,          "T-Dongle Adapter Project",
                                    "T-Dongle-S3 NCM", serial,
#if CONFIG_TINYUSB_CDC_ENABLED
                                    "Management",
#endif
                                    "USB network",     ""};
    tinyusb_config_t usb = TINYUSB_DEFAULT_CONFIG();
    usb.event_cb = usb_event;
    usb.descriptor.string = strings;
    usb.descriptor.string_count = sizeof(strings) / sizeof(strings[0]);
    ESP_ERROR_CHECK(tinyusb_driver_install(&usb));
    tinyusb_net_config_t net = {.on_recv_callback = usb_recv_callback,
                                .free_tx_buffer = wifi_pkt_free};
    memcpy(net.mac_addr, s_mac, 6);
    ESP_ERROR_CHECK(tinyusb_net_init(&net));
    assert(xTaskCreate(tx_worker, "usb_tx", 3072, NULL, 5, NULL) == pdPASS);
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wc));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE);
    /* 20 MHz is more sensitive than 40 MHz in a crowded 2.4 GHz band; use the highest TX power. */
    esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT20);
    esp_wifi_set_max_tx_power(84);
    s_usb_alive_us = esp_timer_get_time();
    const esp_timer_create_args_t snap = {.callback = snapshot_timer_cb, .name = "crashsnap"};
    ESP_ERROR_CHECK(esp_timer_create(&snap, &s_snapshot_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(s_snapshot_timer, 1000000));
    control_init(setup_requested());
    console_init();
    ui_start();
}
