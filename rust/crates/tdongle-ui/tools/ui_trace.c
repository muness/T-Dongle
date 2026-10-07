// SPDX-License-Identifier: MIT
/* Golden-trace harness: the REAL C front panel (main/menu.c, led.c, core.c's button_update, traffic.c, ui_settings.c, setup_boot.c and the UI poll
 * alternative/tailnet/main/device_ui.inc, included verbatim) driven by a scripted scenario, printing what the firmware would do: the commands a
 * gesture chose, the screen draws (backlight, rotation, menu rows or the lcd_state the screen is composed from), the exact bytes clocked to the
 * APA102 (captured from the bit-banged GPIO writes), and setup-leave restarts. The Rust crate replays the same scenario and must print the same lines.
 *
 * Usage: ui_trace scenario.scn > scenario.trace | ui_trace --led-sweep > led_sweep.trace
 * Scenario lines (blank and # lines ignored):
 *   start MS            device clock at boot (64 bit ms); runs ui_start
 *   press A B           the button is down for A <= t < B (absolute ms), may repeat
 *   set KEY VALUE       change what the firmware facts say (see set_key)
 *   traffic DB UB DF UF count frames through the USB side now
 *   setup_start         begin a 10 minute setup session now (and setup_active=1)
 *   setup_stop          setup_active=0, session inactive
 *   tick FROM TO STEP   poll at FROM, FROM+STEP, ... <= TO
 *   fuzz SEED N         N polls with pseudo-random time steps, button, facts and traffic (xorshift32; see fuzz_step)
 */
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "board.h"
#include "core.h"
#include "health.h"
#include "led.h"
#include "lcd_view.h"
#include "menu.h"
#include "setup_boot.h"
#include "traffic.h"
#include "ui_settings.h"

/* ---- ESP-IDF stand-ins ---- */
#define RTC_NOINIT_ATTR
#define ESP_LOGW(...) ((void)0)
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define MALLOC_CAP_INTERNAL 0
#define GATEWAY_VERSION "0.0.0-golden"
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_NO_MEM 1
typedef void *SemaphoreHandle_t;
typedef int StaticSemaphore_t;
typedef struct { uint64_t pin_bit_mask; int mode, pull_up_en; } gpio_config_t;
#define GPIO_MODE_INPUT 1
#define GPIO_MODE_OUTPUT 2
#define GPIO_PULLUP_ENABLE 1
enum { UI_POLL_MS = 20 };

static uint64_t g_now_ms;
static uint64_t esp_timer_get_time(void) { return g_now_ms * 1000; }

static int members_lock_busy;
static char members_lock_token, ui_lock_token;
static SemaphoreHandle_t members_lock = &members_lock_token;
static SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *s) { (void)s; return &ui_lock_token; }
static int xSemaphoreTake(SemaphoreHandle_t h, int ticks) { (void)ticks; return h == members_lock && members_lock_busy ? 0 : pdTRUE; }
static void xSemaphoreGive(SemaphoreHandle_t h) { (void)h; }

/* GPIO: the APA102 bit-bang is captured. A bit is the data level at each clock rising edge; 96 bits are one frame. */
static int g_button_down, g_data_level, g_clk_level;
static uint8_t g_led_bits[12];
static unsigned g_led_nbits;
static char g_led_line[40];
static int g_led_pending;
static esp_err_t gpio_config(const gpio_config_t *c) { (void)c; return ESP_OK; }
static int gpio_get_level(int pin) { return pin == BOARD_BUTTON ? !g_button_down : 1; }
static void gpio_set_level(int pin, int level) {
    if (pin == BOARD_LED_DATA) g_data_level = level;
    else if (pin == BOARD_LED_CLK) {
        if (level && !g_clk_level) {
            if (g_led_nbits < 96) { if (g_data_level) g_led_bits[g_led_nbits / 8] |= (uint8_t)(0x80 >> (g_led_nbits % 8)); else g_led_bits[g_led_nbits / 8] &= (uint8_t)~(0x80 >> (g_led_nbits % 8)); }
            g_led_nbits++;
            if (g_led_nbits == 96) {
                for (unsigned i = 0; i < 12; i++) snprintf(g_led_line + 2 * i, 3, "%02x", g_led_bits[i]);
                g_led_pending = 1;
            }
        }
        g_clk_level = level;
    }
}

/* ---- firmware state the poll reads (what gateway_main.c and the setup/wifi code own) ---- */
static bool setup_active, wifi_ready, online, settings_state_ok = true;
static setup_session setup_clock;
static char setup_ap_name[16] = "TDongle-AB0CF9";
static ui_settings display_settings = {60, 0, 60};
static struct { unsigned count; } wifi_saved;
static struct { struct { char name[25]; } slot[8]; } wifi_meta;
static struct { unsigned connects, last_connect_ms, last_reason; } wifi_link_stats;
typedef struct { bool connected, rssi_valid; int rssi; } wifi_link_info;
static wifi_link_info link_info;
static wifi_link_info wifi_link_read(void) { return link_info; }
static struct {
    bool bridge, wifi, recovery, saved_wifi, installing, usb, usb_configured, usb_suspended;
    unsigned active_slot, saved, enabled, ready, login, failed, usb_resets, heap_free, heap_min, heap_largest;
    char active_name[25], ssid[33];
} fw = {.bridge = true};
static bool tud_ready(void) { return fw.usb; }
static bool tud_mounted(void) { return fw.usb_configured; }
static bool tud_suspended(void) { return fw.usb_suspended; }
static bool gateway_display_is_installing(void) { return fw.installing; }
unsigned gateway_usb_health(unsigned i) { (void)i; return fw.usb_resets; }
static uint32_t esp_get_free_heap_size(void) { return fw.heap_free; }
static uint32_t heap_caps_get_minimum_free_size(int c) { (void)c; return fw.heap_min; }
static uint32_t heap_caps_get_largest_free_block(int c) { (void)c; return fw.heap_largest; }
static void setup_restart(setup_request r, unsigned slot) { (void)slot; printf("t=%llu restart %s\n", (unsigned long long)g_now_ms, r == SETUP_REQUEST_LEAVE ? "leave" : "other"); }
bool gateway_display_state(lcd_state *s) {
    if (!settings_state_ok) return false;
    s->bridge = fw.bridge; s->wifi = fw.wifi; s->recovery = fw.recovery;
    s->saved_wifi = fw.saved_wifi;
    s->active_slot = fw.active_slot;
    strlcpy(s->active_name, fw.active_name, sizeof(s->active_name));
    strlcpy(s->ssid, fw.ssid, sizeof(s->ssid));
    s->saved = fw.saved; s->enabled = fw.enabled; s->ready = fw.ready; s->login = fw.login; s->failed = fw.failed;
    return true;
}

/* ---- the panel: what is drawn is printed ---- */
static char g_status_line[2048];
void lcd_compose(const lcd_state *s, const char *version, lcd_view *view) {
    (void)version;
    int n = snprintf(g_status_line, sizeof(g_status_line),
        "bridge=%d wifi=%d saved_wifi=%d recovery=%d starting=%d installing=%d usb=%d usb_configured=%d usb_suspended=%d saved=%u enabled=%u ready=%u login=%u failed=%u "
        "page=%u rssi_valid=%d rssi=%d ssid=[%s] setup=%d ap_ssid=[%s] setup_seconds_left=%u down_kbps=%u up_kbps=%u down_bytes=%llu up_bytes=%llu down_frames=%llu up_frames=%llu bars=",
        s->bridge, s->wifi, s->saved_wifi, s->recovery, s->starting, s->installing, s->usb, s->usb_configured, s->usb_suspended, s->saved, s->enabled, s->ready, s->login, s->failed,
        s->page, s->rssi_valid, s->rssi, s->ssid, s->setup, s->ap_ssid, s->setup_seconds_left, s->down_kbps, s->up_kbps, (unsigned long long)s->down_bytes,
        (unsigned long long)s->up_bytes, (unsigned long long)s->down_frames, (unsigned long long)s->up_frames);
    for (unsigned i = 0; i < LCD_BARS; i++) n += snprintf(g_status_line + n, sizeof(g_status_line) - (size_t)n, "%02x", s->bars[i]);
    snprintf(g_status_line + n, sizeof(g_status_line) - (size_t)n,
        " uptime_s=%u wifi_up_s=%u connects=%u last_reason=%u usb_resets=%u heap_free=%u heap_min=%u heap_largest=%u reset_reason=%u boots=%u watchdogs=%u panics=%u "
        "health_view=%u active_slot=%u active_name=[%s]",
        s->uptime_s, s->wifi_up_s, s->connects, s->last_reason, s->usb_resets, s->heap_free, s->heap_min, s->heap_largest, s->reset_reason, s->boots, s->watchdogs, s->panics,
        s->health_view, s->active_slot, s->active_name);
    memset(view, 0, sizeof(*view));
    view->layout = LCD_LAYOUT_STATUS;
}
static void gateway_display_apply(unsigned percent, unsigned rotation) { printf("t=%llu apply backlight=%u rotation=%u\n", (unsigned long long)g_now_ms, percent, rotation); }
static void gateway_display_show(const lcd_view *v) {
    if (v->layout == LCD_LAYOUT_ROWS) {
        printf("t=%llu show rows attention=%d", (unsigned long long)g_now_ms, v->attention);
        for (unsigned i = 0; i < LCD_ROWS; i++) printf(" |%s", v->row[i]);
        printf("\n");
    } else {
        static char last[2048];
        if (!strcmp(last, g_status_line)) printf("t=%llu show status same\n", (unsigned long long)g_now_ms);
        else printf("t=%llu show status %s\n", (unsigned long long)g_now_ms, g_status_line);
        strcpy(last, g_status_line);
    }
}

#include DEVICE_UI_INC   /* the verbatim alternative/tailnet/main/device_ui.inc, path given by gen_golden.sh */

/* ---- scenario interpreter ---- */
static struct { uint64_t a, b; } presses[64];
static unsigned npress;
static uint32_t rng_state;
static uint32_t rnd(void) { uint32_t x = rng_state; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return rng_state = x; }
static void poll(void) {
    g_button_down = 0;
    for (unsigned i = 0; i < npress; i++) if (g_now_ms >= presses[i].a && g_now_ms < presses[i].b) g_button_down = 1;
    gateway_display_tick();
    if (g_led_pending) { printf("t=%llu led %s\n", (unsigned long long)g_now_ms, g_led_line); g_led_pending = 0; g_led_nbits = 0; }
    char command[64];
    if (gateway_ui_take_command(command, sizeof(command))) printf("t=%llu cmd %s\n", (unsigned long long)g_now_ms, command);
}
static void set_key(const char *k, const char *v) {
    unsigned long n = strtoul(v, NULL, 10);
#define U(name, var) if (!strcmp(k, name)) { var = (__typeof__(var))n; return; }
#define S(name, var) if (!strcmp(k, name)) { strlcpy(var, v, sizeof(var)); return; }
    U("saved", wifi_saved.count) U("setup", setup_active) U("wifi_ready", wifi_ready) U("online", online) U("state_ok", settings_state_ok)
    U("bridge", fw.bridge) U("wifi", fw.wifi) U("recovery", fw.recovery) U("saved_wifi", fw.saved_wifi) U("installing", fw.installing) U("usb", fw.usb)
    U("usb_configured", fw.usb_configured) U("usb_suspended", fw.usb_suspended) U("active_slot", fw.active_slot) U("tn_saved", fw.saved) U("enabled", fw.enabled)
    U("ready", fw.ready) U("login", fw.login) U("failed", fw.failed) U("usb_resets", fw.usb_resets) U("heap_free", fw.heap_free) U("heap_min", fw.heap_min)
    U("heap_largest", fw.heap_largest) U("reset_reason", reset_reason_at_boot) U("link_connected", link_info.connected) U("link_rssi_valid", link_info.rssi_valid)
    U("connects", wifi_link_stats.connects) U("last_connect_ms", wifi_link_stats.last_connect_ms) U("last_reason", wifi_link_stats.last_reason)
    U("brightness", display_settings.brightness) U("rotation", display_settings.rotation) U("dim_seconds", display_settings.dim_seconds)
    U("lock_busy", members_lock_busy)
    if (!strcmp(k, "link_rssi")) { link_info.rssi = atoi(v); return; }
    S("active_name", fw.active_name) S("ssid", fw.ssid) S("ap_name", setup_ap_name)
    if (!strncmp(k, "name", 4) && k[4] >= '1' && k[4] <= '8' && !k[5]) { strlcpy(wifi_meta.slot[k[4] - '1'].name, v, sizeof(wifi_meta.slot[0].name)); return; }
    if (!strcmp(k, "boots")) { health_rtc.boots = (uint32_t)n; return; }
    if (!strcmp(k, "watchdogs")) { health_rtc.watchdogs = (uint32_t)n; return; }
    if (!strcmp(k, "panics")) { health_rtc.panics = (uint32_t)n; return; }
    fprintf(stderr, "unknown key %s\n", k);
    exit(2);
}
static void fuzz_mutate(unsigned k, uint32_t v) {
    static const unsigned reasons[5] = {0, 8, 15, 201, 202}, dims[3] = {10, 20, 60};
    switch (k) {
    case 0: wifi_saved.count = v % 9; break;
    case 1:
        if (setup_active) { setup_active = false; memset(&setup_clock, 0, sizeof(setup_clock)); }
        else { setup_active = true; setup_session_start(&setup_clock, (uint32_t)g_now_ms); }
        break;
    case 2: settings_state_ok = v % 8 != 0; break;
    case 3: fw.wifi = v & 1; online = v & 1; break;
    case 4: fw.usb = v & 1; break;
    case 5: fw.recovery = v % 8 == 0; break;
    case 6: fw.bridge = v & 1; break;
    case 7: fw.ready = v % 3; fw.failed = (v >> 4) % 2; fw.login = (v >> 8) % 2; break;
    case 8: wifi_link_stats.last_reason = reasons[v % 5]; break;
    case 9: display_settings.dim_seconds = (uint16_t)dims[v % 3]; break;
    case 10: fw.saved_wifi = v % 8 != 0; break;
    default: wifi_ready = v % 4 != 0; break;
    }
}
static void fuzz(uint32_t seed, unsigned n) {
    rng_state = seed ? seed : 1;
    uint64_t next_toggle = g_now_ms;
    int down = 0;
    for (unsigned i = 0; i < n; i++) {
        g_now_ms += 10 + rnd() % 30;
        if (g_now_ms >= next_toggle) {
            down = !down;
            uint32_t a = rnd(), b = rnd();
            uint32_t dur = down ? (a % 4 == 0 ? 1600 + b % 900 : 20 + b % 80) : (a % 8 == 0 ? 12000 : 40 + b % 800);
            next_toggle = g_now_ms + dur;
        }
        uint32_t r = rnd();
        if (r % 48 == 0) { uint32_t k = rnd() % 12, v = rnd(); fuzz_mutate(k, v); }
        uint32_t a = rnd(), b = rnd(), c = rnd();
        if (c % 4 == 0) { traffic_count_down(a % 3000); traffic_count_up(b % 800); }
        npress = 1;
        presses[0].a = down ? 0 : 1; presses[0].b = down ? ~0ull : 0;   /* the button level is `down` */
        poll();
    }
}
static void led_sweep(void) {
    static const char *names[] = {"JOIN", "SETUP", "UP", "FAIL", "ATTENTION", "LOGIN"};
    for (unsigned m = 0; m < 6; m++)
        for (uint32_t since = 0; since < 3; since++) {
            uint32_t s0 = since == 0 ? 500 : since == 1 ? 0xffffff00u : 123456789u;
            for (uint32_t d = 0; d < 6000; d += 37) {
                uint32_t now = s0 + d;
                led_rgb c = led_color((led_mode)m, now, s0);
                uint8_t f[12];
                led_apa102_frame(c, f);
                printf("%s since=%u now=%u rgb=%u,%u,%u frame=", names[m], s0, now, c.r, c.g, c.b);
                for (unsigned i = 0; i < 12; i++) printf("%02x", f[i]);
                printf("\n");
            }
        }
    /* mode selection over every combination of the inputs */
    for (unsigned bits = 0; bits < 1u << 10; bits++) {
        led_inputs in = {.setup = bits & 1, .no_network = bits >> 1 & 1, .associated = bits >> 2 & 1, .usb_ready = bits >> 3 & 1, .recovery = bits >> 4 & 1,
                         .tailnet = bits >> 5 & 1, .tailnet_ready = bits >> 6 & 1, .tailnet_failed = bits >> 7 & 1, .tailnet_login = bits >> 8 & 1,
                         .last_reason = (uint16_t)((bits >> 9 & 1) ? 201 : 8)};
        printf("select %u -> %s\n", bits, names[led_select(&in)]);
    }
}
int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "--led-sweep")) { led_sweep(); return 0; }
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "r");
    if (!f) return 2;
    for (unsigned i = 0; i < 8; i++) snprintf(wifi_meta.slot[i].name, sizeof(wifi_meta.slot[i].name), "Net%u", i + 1);
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *cmd = strtok(line, " \t\r\n");
        if (!cmd || cmd[0] == '#') continue;
        if (!strcmp(cmd, "start")) { g_now_ms = strtoull(strtok(NULL, " \t\r\n"), NULL, 10); ui_start(); }
        else if (!strcmp(cmd, "press")) { presses[npress].a = strtoull(strtok(NULL, " \t\r\n"), NULL, 10); presses[npress].b = strtoull(strtok(NULL, " \t\r\n"), NULL, 10); npress++; }
        else if (!strcmp(cmd, "set")) { char *k = strtok(NULL, " \t\r\n"); char *v = strtok(NULL, "\r\n"); set_key(k, v ? v : ""); }
        else if (!strcmp(cmd, "traffic")) { uint32_t db = (uint32_t)strtoul(strtok(NULL, " "), NULL, 10), ub = (uint32_t)strtoul(strtok(NULL, " "), NULL, 10);
            uint32_t df = (uint32_t)strtoul(strtok(NULL, " "), NULL, 10), uf = (uint32_t)strtoul(strtok(NULL, " \r\n"), NULL, 10);
            for (uint32_t i = 0; i < df; i++) traffic_count_down(i == 0 ? db : 0);
            for (uint32_t i = 0; i < uf; i++) traffic_count_up(i == 0 ? ub : 0); }
        else if (!strcmp(cmd, "setup_start")) { setup_active = true; setup_session_start(&setup_clock, (uint32_t)g_now_ms); }
        else if (!strcmp(cmd, "setup_stop")) { setup_active = false; memset(&setup_clock, 0, sizeof(setup_clock)); }
        else if (!strcmp(cmd, "tick")) {
            uint64_t from = strtoull(strtok(NULL, " "), NULL, 10), to = strtoull(strtok(NULL, " "), NULL, 10), step = strtoull(strtok(NULL, " \r\n"), NULL, 10);
            for (uint64_t t = from; t <= to; t += step) { g_now_ms = t; poll(); }
        } else if (!strcmp(cmd, "fuzz")) { uint32_t seed = (uint32_t)strtoul(strtok(NULL, " "), NULL, 10); unsigned n = (unsigned)strtoul(strtok(NULL, " \r\n"), NULL, 10); fuzz(seed, n); }
        else { fprintf(stderr, "unknown command %s\n", cmd); return 2; }
    }
    return 0;
}
