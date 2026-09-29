// SPDX-License-Identifier: MIT
#include "esp_rom_sys.h"
#include "soc/rtc_cntl_reg.h"
#include "app.h"
#include "cJSON.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
static app_snapshot_t public;
static settings_t cfg;
static QueueHandle_t commands;
static bool in_setup, trial;
static int active = -1, trial_slot;
static profile_t candidate;
static uint64_t attempt_at, trial_at, stable_at, reset_until, last_write;
static uint8_t tried;
static unsigned failures;
static RTC_NOINIT_ATTR uint32_t mode_magic;
static RTC_NOINIT_ATTR uint32_t mode_next;
static uint64_t now_ms(void) { return esp_timer_get_time() / 1000; }
void setup_reboot(bool enter) {
    mode_magic = 0x54444d31;
    mode_next = enter ? 1 : 2;
    esp_restart();
}
bool setup_requested(void) {
    uint32_t mode = 0;
    if (esp_reset_reason() == ESP_RST_SW && mode_magic == 0x54444d31)
        mode = mode_next;
    mode_magic = 0;
    mode_next = 0;
    settings_t s;
    settings_load(&s);
    return mode == 1 || (mode != 2 && policy_next(&s, 0) < 0 && settings_store_ok());
}
void app_snapshot(app_snapshot_t *s) {
    portENTER_CRITICAL(&lock);
    *s = public;
    portEXIT_CRITICAL(&lock);
}
void app_event(unsigned code, unsigned detail) {
    portENTER_CRITICAL(&lock);
    public.events[public.event_count++ % 24] = (event_t){now_ms(), code, detail};
    portEXIT_CRITICAL(&lock);
}
void app_ui_stack(uint32_t n) {
    portENTER_CRITICAL(&lock);
    public.ui_stack = n;
    portEXIT_CRITICAL(&lock);
}
static void error(const char *s) {
    portENTER_CRITICAL(&lock);
    snprintf(public.error, sizeof(public.error), "%s", s);
    portEXIT_CRITICAL(&lock);
    app_event(9, 0);
}
static void publish(void) {
    settings_t safe = cfg;
    for (int i = 0; i < PROFILE_MAX; i++)
        memset(safe.p[i].pass, 0, sizeof(safe.p[i].pass));
    if (trial) {
        safe.p[trial_slot] = candidate;
        memset(safe.p[trial_slot].pass, 0, sizeof(safe.p[trial_slot].pass));
    }
    uint32_t free_heap = esp_get_free_heap_size(), min_heap = esp_get_minimum_free_heap_size();
    uint32_t dma_heap = heap_caps_get_free_size(MALLOC_CAP_DMA),
             stack = uxTaskGetStackHighWaterMark(NULL);
    portENTER_CRITICAL(&lock);
    public.cfg = safe;
    public.active = active;
    public.setup = in_setup;
    public.trial = trial;
    public.free_heap = free_heap;
    public.min_heap = min_heap;
    public.dma_heap = dma_heap;
    public.control_stack = stack;
    portEXIT_CRITICAL(&lock);
}
bool control_submit(const char *line) {
    if (!commands || strlen(line) >= 512)
        return false;
    char b[512] = {0};
    memcpy(b, line, strlen(line));
    return xQueueSend(commands, b, 0) == pdTRUE;
}
static bool persist(void) {
    if (now_ms() - last_write < 2000) {
        error("Wait 2 seconds between saves");
        return false;
    }
    esp_err_t e = settings_save(&cfg);
    if (e != ESP_OK) {
        error("Storage save failed");
        return false;
    }
    last_write = now_ms();
    return true;
}
static void join(int slot) {
    active = slot;
    stable_at = 0;
    attempt_at = now_ms();
    if (slot >= 0) {
        const profile_t *p = trial ? &candidate : &cfg.p[slot];
        esp_err_t e = wifi_apply_creds(p->ssid, p->pass);
        if (e != ESP_OK)
            error("Join start failed; retry pending");
    } else
        wifi_apply_creds("", "");
}
static void status(void) {
    bridge_snapshot_t b;
    bridge_snapshot(&b);
    app_snapshot_t a;
    app_snapshot(&a);
    bridge_crash_info_t c;
    bridge_get_crash(&c);
    char signal[12];
    if (b.associated && b.rssi != INT8_MIN)
        snprintf(signal, sizeof(signal), "%d", b.rssi);
    else
        strcpy(signal, "unknown");
    console_printf("mode=%s trial=%d active=%d wifi=%s rssi=%s usb_enumerated=%d "
                   "usb_transport_ready=%d host_interface_ready=unknown "
                   "internet=not_checked\r\n",
                   in_setup ? "setup" : "adapter", trial, active + 1, bridge_link_status(), signal,
                   b.usb_mounted, b.usb_ready);
    wifi_ap_record_t ap;
    int8_t txp = 0;
    esp_wifi_get_max_tx_power(&txp);
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK)
        console_printf("radio bssid=%02x:%02x:%02x:%02x:%02x:%02x channel=%u rssi=%d txpower_dbm=%.2f "
                       "roams=%" PRIu32 "\r\n",
                       ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4],
                       ap.bssid[5], ap.primary, ap.rssi, txp * 0.25, bridge_roams());
    else
        console_printf("radio not_associated txpower_dbm=%.2f\r\n", txp * 0.25);
    uint8_t ip[16];
    if (bridge_host_ipv4(ip))
        console_printf("observed_ipv4=%u.%u.%u.%u age_ms=%" PRIu64 " (not DHCP proof)\r\n", ip[0],
                       ip[1], ip[2], ip[3], b.now_ms - b.addresses.seen4);
    else
        mgmt_write("observed_ipv4=unknown_or_expired\r\n");
    if (bridge_host_ipv6(ip))
        console_printf("observed_ipv6=%x:%x:%x:%x:%x:%x:%x:%x age_ms=%" PRIu64 "\r\n",
                       ip[0] * 256 + ip[1], ip[2] * 256 + ip[3], ip[4] * 256 + ip[5],
                       ip[6] * 256 + ip[7], ip[8] * 256 + ip[9], ip[10] * 256 + ip[11],
                       ip[12] * 256 + ip[13], ip[14] * 256 + ip[15], b.now_ms - b.addresses.seen6);
    console_printf("download_bytes=%" PRIu64 " upload_bytes=%" PRIu64 " down_frames=%" PRIu32
                   " up_frames=%" PRIu32 " drops_rx=%" PRIu32 " drops_tx=%" PRIu32
                   " poolfail=%" PRIu32 " reflected=%" PRIu32 " malformed=%" PRIu32 "\r\n",
                   b.stats.down_bytes, b.stats.up_bytes, b.stats.wifi_to_host, b.stats.host_to_wifi,
                   b.stats.rxdrop, b.stats.txdrop, b.stats.poolfail, b.stats.reflected,
                   b.stats.malformed);
    console_printf("uptime_ms=%" PRIu64 " association_since_ms=%" PRIu64 " join_attempts=%" PRIu32
                   " disconnect_reason=%u usb_events=%" PRIu32 " heap=%" PRIu32 " min_heap=%" PRIu32
                   " dma=%" PRIu32 " control_stack=%" PRIu32 " ui_stack=%" PRIu32 "\r\n",
                   b.now_ms, b.connected_ms, b.reconnects, b.last_reason, b.usb_resets, a.free_heap,
                   a.min_heap, a.dma_heap, a.control_stack, a.ui_stack);
    console_printf("boots=%" PRIu32 " watchdogs=%" PRIu32 " panics=%" PRIu32
                   " reset=%d error=%s\r\n",
                   c.boots, c.hangs, c.faults, esp_reset_reason(), a.error);
    for (unsigned k = a.event_count > 24 ? a.event_count - 24 : 0; k < a.event_count; k++) {
        event_t *e = &a.events[k % 24];
        console_printf("event ms=%" PRIu64 " code=%u detail=%u\r\n", e->ms, e->code, e->detail);
    }
}
static bool stage_json(const char *json) {
    profile_t p;
    int slot;
    bool ok = profile_parse_json(json, &slot, &p);
    if (!ok) {
        error("Invalid profile fields");
        return false;
    }
    if (in_setup && !cfg.p[slot].ssid[0]) {
        /* Adding to an empty slot risks nothing already saved, so save it now and keep setup
         * open for the next network. A wrong password only means this profile fails to join;
         * the others are untouched. Replacing a saved profile still goes through the trial. */
        settings_t old = cfg;
        cfg.p[slot] = p;
        if (!cfg.p[cfg.preferred].ssid[0])
            cfg.preferred = slot;
        memset(&p, 0, sizeof(p));
        if (!persist()) {
            cfg = old;
            error("Storage save failed");
            return false;
        }
        console_printf("OK saved to slot %d; setup stays open\r\n", slot + 1);
        return true;
    }
    if (settings_stage(slot, &p) != ESP_OK) {
        error("Cannot stage profile");
        return false;
    }
    mgmt_write("OK candidate saved; rebooting for 45s trial. Previous profile "
               "retained.\r\n");
    vTaskDelay(pdMS_TO_TICKS(200));
    setup_reboot(false);
    return true;
}
static bool index_arg(const char *s, int *i) {
    char *end;
    long n = strtol(s, &end, 10);
    if (!*s || *end || n < 1 || n > 8)
        return false;
    *i = n - 1;
    return true;
}
static void handle(char *line) {
    int i;
    if (!strcmp(line, "help"))
        mgmt_write("Commands: status, list, scan, use N, del N, profile "
                   "{\"slot\":1,\"name\":\"Home\",\"ssid\":\"SSID\","
                   "\"password\":\"password\",\"priority\":50}, display "
                   "BRIGHTNESS ROTATION DIM_SECONDS, setup, cancel, reset, "
                   "confirm-reset, reboot, bootloader. Profiles validate by association "
                   "before replacing saved data. No console echo.\r\n");
    else if (!strcmp(line, "status") || !strcmp(line, "show") || !strcmp(line, "diagnostics"))
        status();
    else if (!strcmp(line, "list")) {
        for (i = 0; i < 8; i++)
            if (cfg.p[i].ssid[0])
                console_printf("%d%s name=%s ssid=%s priority=%u\r\n", i + 1,
                               i == active ? "*" : "", cfg.p[i].name, cfg.p[i].ssid,
                               cfg.p[i].priority);
    } else if (!strcmp(line, "scan")) {
        if (in_setup || trial) {
            mgmt_write("ERR scan unavailable in setup/trial\r\n");
            return;
        }
        wifi_scan_config_t sc = {.show_hidden = false};
        esp_err_t e = esp_wifi_scan_start(&sc, true);
        if (e != ESP_OK) {
            mgmt_write("ERR scan busy; retry when association settles\r\n");
            return;
        }
        wifi_ap_record_t *aps = calloc(20, sizeof(*aps));
        uint16_t n = 20;
        if (aps && esp_wifi_scan_get_ap_records(&n, aps) == ESP_OK)
            for (i = 0; i < n; i++) {
                char raw[33] = {0}, safe[33];
                memcpy(raw, aps[i].ssid, 32);
                text_clip(safe, sizeof(safe), raw, 32);
                console_printf("ssid=%s rssi=%d auth=%d\r\n", safe, aps[i].rssi, aps[i].authmode);
            }
        else
            esp_wifi_clear_ap_list();
        free(aps);
    } else if (!strncmp(line, "profile ", 8)) {
        if (trial) {
            mgmt_write("ERR trial in progress\r\n");
            return;
        }
        if (!stage_json(line + 8))
            mgmt_write("ERR invalid profile or storage failure\r\n");
    } else if (!strncmp(line, "use ", 4) && index_arg(line + 4, &i) && cfg.p[i].ssid[0]) {
        if (in_setup || trial) {
            mgmt_write("ERR cancel setup/trial first\r\n");
            return;
        }
        settings_t old = cfg;
        cfg.preferred = i;
        if (persist()) {
            tried = 0;
            failures = 0;
            join(i);
        } else
            cfg = old;
    } else if (!strncmp(line, "del ", 4) && index_arg(line + 4, &i)) {
        if (trial) {
            mgmt_write("ERR trial in progress\r\n");
            return;
        }
        settings_t old = cfg;
        memset(&cfg.p[i], 0, sizeof(profile_t));
        if (persist()) {
            if (i == active && !in_setup)
                join(policy_next(&cfg, 0));
        } else
            cfg = old;
    } else if (!strncmp(line, "display ", 8)) {
        unsigned brightness, rotation, dim;
        char extra;
        if (sscanf(line + 8, "%u %u %u %c", &brightness, &rotation, &dim, &extra) != 3 ||
            brightness < 5 || brightness > 100 || rotation > 1 || dim < 10 || dim > 3600) {
            mgmt_write("ERR display: brightness 5..100 rotation 0|1 dim 10..3600 "
                       "seconds\r\n");
            return;
        }
        settings_t old = cfg;
        cfg.brightness = brightness;
        cfg.rotation = rotation;
        cfg.dim_seconds = dim;
        if (!persist())
            cfg = old;
    } else if (!strcmp(line, "setup")) {
        if (!trial)
            setup_reboot(true);
    } else if (!strcmp(line, "cancel")) {
        setup_reboot(false);
    } else if (!strcmp(line, "reset")) {
        reset_until = now_ms() + 10000;
        mgmt_write("Confirm within 10 seconds: confirm-reset\r\n");
    } else if (!strcmp(line, "confirm-reset")) {
        if (reset_until && now_ms() < reset_until) {
            reset_until = 0;
            if (settings_reset() == ESP_OK)
                setup_reboot(true);
            else
                error("Reset storage failed");
        } else
            mgmt_write("ERR reset confirmation expired\r\n");
    } else if (!strcmp(line, "reboot"))
        esp_restart();
    else if (!strcmp(line, "bootloader")) {
        /* Reboot into the ROM download mode so tools/flash.sh can reflash without BOOT+replug. */
        mgmt_write("OK rebooting into ROM download mode\r\n");
        vTaskDelay(pdMS_TO_TICKS(200));
        /* Not esp_restart(): it arms a 1 s RTC watchdog that then resets the ROM out of
         * download mode mid-flash. A plain ROM software reset leaves no watchdog behind. */
        REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
        esp_rom_software_reset_system();
    }
    else
        mgmt_write("ERR unknown/invalid command; help\r\n");
}
static void task(void *arg) {
    esp_task_wdt_add(NULL);
    settings_load(&cfg);
    if (!settings_store_ok())
        error("Config damaged: explicit reset needed");
    if (in_setup) {
        char ssid[25], pass[17];
        portal_identity(ssid, pass);
        portENTER_CRITICAL(&lock);
        strcpy(public.ap_ssid, ssid);
        strcpy(public.ap_pass, pass);
        public.setup_deadline = now_ms() + 600000;
        portEXIT_CRITICAL(&lock);
        portal_start();
    } else if (settings_take_candidate(&trial_slot, &candidate)) {
        trial = true;
        trial_at = now_ms();
        join(trial_slot);
    } else
        join(policy_next(&cfg, 0));
    char line[512];
    for (;;) {
        esp_task_wdt_reset();
        publish();
        if (xQueueReceive(commands, line, pdMS_TO_TICKS(100)) == pdTRUE) {
            handle(line);
            memset(line, 0, sizeof(line));
            mgmt_write("done>\r\n");
        }
        uint64_t now = now_ms();
        if (in_setup) {
            if (now >= public.setup_deadline)
                setup_reboot(false);
            continue;
        }
        // Use the association event timestamp, not polling duration: a brief
        // disconnect/reconnect between polls must restart candidate validation.
        uint64_t associated_since = bridge_connected_since_ms();
        bool associated = associated_since != 0;
        if (associated)
            stable_at = associated_since;
        int decision = trial ? trial_decision(now, trial_at, stable_at, associated) : 0;
        if (decision < 0) {
            trial = false;
            memset(&candidate, 0, sizeof(candidate));
            error("Trial failed; previous profiles kept");
            app_event(5, 0);
            join(policy_next(&cfg, 0));
            continue;
        }
        if (associated) {
            if (trial && decision == 1) {
                settings_t old = cfg;
                cfg.p[trial_slot] = candidate;
                cfg.preferred = trial_slot;
                if (persist()) {
                    trial = false;
                    memset(&candidate, 0, sizeof(candidate));
                    error("Profile association validated");
                    app_event(4, 0);
                } else {
                    cfg = old;
                    trial = false;
                    join(policy_next(&cfg, 0));
                }
            }
            failures = 0;
            tried = 0;
            attempt_at = now;
            continue; /* Never scan or oscillate a healthy link. */
        }
        stable_at = 0;
        if (trial)
            continue;
        if (active >= 0 && now - attempt_at >= 15000 + retry_delay_ms(failures)) {
            tried |= 1u << active;
            int next = policy_next(&cfg, tried);
            if (next < 0) {
                tried = 0;
                next = policy_next(&cfg, 0);
                if (failures < 32)
                    failures++;
            }
            error(bridge_link_status());
            join(next);
        }
    }
}
void control_init(bool setup) {
    in_setup = setup;
    public.active = -1;
    public.cfg.brightness = 60;
    public.cfg.dim_seconds = 60;
    commands = xQueueCreate(4, 512);
    assert(commands);
    assert(xTaskCreate(task, "control", 6144, NULL, 3, NULL) == pdPASS);
}
