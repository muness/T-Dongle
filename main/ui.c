// SPDX-License-Identifier: MIT
// Adapted setup: Lewis He, (c) 2025 ShenZhen XinYuan Electronic Technology Co.,
// Ltd. esp_lcd setup adapted from LILYGO lvgl9.ino (MIT); async completion
// fixed.
#include "app.h"
#include "board.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "view.h"
#include <stdio.h>
#include <string.h>
#if CONFIG_ADAPTER_DISPLAY
#include "esp_heap_caps.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_st7735.h"
#include "freertos/semphr.h"
#include "lvgl.h"
static esp_lcd_panel_handle_t panel;
static lv_display_t *display;
static SemaphoreHandle_t dma_done;
static lv_obj_t *labels[5], *bars[HISTORY_LEN], *signal_label;
static bool screen;
static int big_layout;
static uint8_t *dma_pixels;
static bool transfer_done(esp_lcd_panel_io_handle_t io, esp_lcd_panel_io_event_data_t *e,
                          void *ctx) {
    BaseType_t wake = pdFALSE;
    xSemaphoreGiveFromISR(dma_done, &wake);
    return wake == pdTRUE;
}
static void flush(lv_display_t *d, const lv_area_t *a, uint8_t *pixels) {
    if (screen) {
        size_t count = lv_area_get_size(a);
        memcpy(dma_pixels, pixels, count * 2);
        lv_draw_sw_rgb565_swap(dma_pixels, count);
        if (esp_lcd_panel_draw_bitmap(panel, a->x1, a->y1, a->x2 + 1, a->y2 + 1, dma_pixels) !=
                ESP_OK ||
            xSemaphoreTake(dma_done, pdMS_TO_TICKS(250)) != pdTRUE) {
            // DMA buffer is retained and never reused after failure. LVGL's separate
            // render buffer is safe to release even if the SPI hardware stalls.
            screen = false;
            ESP_LOGE("ui", "LCD failed; rendering disabled, network continues");
        }
    }
    lv_display_flush_ready(d);
}
static uint32_t tick(void) { return esp_timer_get_time() / 1000; }
static bool lcd_init(void) {
    dma_done = xSemaphoreCreateBinary();
    if (!dma_done)
        return false;
    spi_bus_config_t bus =
        ST7735_PANEL_BUS_SPI_CONFIG(BOARD_LCD_CLK, BOARD_LCD_MOSI, BOARD_WIDTH * 16 * 2);
    if (spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO) != ESP_OK)
        return false;
    esp_lcd_panel_io_handle_t io;
    esp_lcd_panel_io_spi_config_t ic =
        ST7735_PANEL_IO_SPI_CONFIG(BOARD_LCD_CS, BOARD_LCD_DC, transfer_done, NULL);
    ic.pclk_hz = 20000000;
    ic.trans_queue_depth = 1;
    if (esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST, &ic, &io) != ESP_OK)
        return false;
    esp_lcd_panel_dev_config_t pc = {.reset_gpio_num = BOARD_LCD_RST,
                                     .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR,
                                     .bits_per_pixel = 16};
    if (esp_lcd_new_panel_st7735(io, &pc, &panel) != ESP_OK ||
        esp_lcd_panel_reset(panel) != ESP_OK || esp_lcd_panel_init(panel) != ESP_OK)
        return false;
    if (esp_lcd_panel_invert_color(panel, true) != ESP_OK ||
        esp_lcd_panel_set_gap(panel, 1, 26) != ESP_OK ||
        esp_lcd_panel_swap_xy(panel, true) != ESP_OK ||
        esp_lcd_panel_mirror(panel, false, true) != ESP_OK ||
        esp_lcd_panel_disp_on_off(panel, true) != ESP_OK)
        return false;
    dma_pixels = heap_caps_malloc(BOARD_WIDTH * 16 * 2, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    void *buf = malloc(BOARD_WIDTH * 16 * 2);
    if (!buf || !dma_pixels)
        return false;
    lv_init();
    lv_tick_set_cb(tick);
    display = lv_display_create(BOARD_WIDTH, BOARD_HEIGHT);
    if (!display)
        return false;
    lv_display_set_color_format(display, LV_COLOR_FORMAT_RGB565);
    lv_display_set_buffers(display, buf, NULL, BOARD_WIDTH * 16 * 2,
                           LV_DISPLAY_RENDER_MODE_PARTIAL);
    lv_display_set_flush_cb(display, flush);

    lv_obj_t *root = lv_screen_active();
    lv_obj_set_style_bg_color(root, lv_color_black(), 0);
    lv_obj_set_style_text_color(root, lv_color_white(), 0);
    lv_obj_set_style_text_font(root, &lv_font_montserrat_10, 0);
    for (int i = 0; i < 5; i++) {
        labels[i] = lv_label_create(root);
        lv_obj_set_pos(labels[i], 2, 2 + i * 15);
        lv_obj_set_size(labels[i], 156, 13);
        lv_label_set_long_mode(labels[i], LV_LABEL_LONG_CLIP);
        lv_label_set_text(labels[i], "");
    }
    signal_label = lv_label_create(root);
    lv_obj_set_pos(signal_label, 108, 2);
    lv_obj_set_size(signal_label, 50, 13);
    lv_label_set_long_mode(signal_label, LV_LABEL_LONG_CLIP);
    lv_obj_set_style_text_align(signal_label, LV_TEXT_ALIGN_RIGHT, 0);
    lv_obj_add_flag(signal_label, LV_OBJ_FLAG_HIDDEN);
    for (int i = 0; i < HISTORY_LEN; i++) {
        bars[i] = lv_obj_create(root);
        lv_obj_remove_style_all(bars[i]);
        lv_obj_set_style_bg_opa(bars[i], LV_OPA_COVER, 0);
        lv_obj_set_style_bg_color(bars[i], lv_color_hex(0x40dfff), 0);
        lv_obj_add_flag(bars[i], LV_OBJ_FLAG_HIDDEN);
    }
    ledc_timer_config_t t = {.speed_mode = LEDC_LOW_SPEED_MODE,
                             .duty_resolution = LEDC_TIMER_8_BIT,
                             .timer_num = LEDC_TIMER_0,
                             .freq_hz = 1000,
                             .clk_cfg = LEDC_AUTO_CLK};
    ledc_channel_config_t c = {.gpio_num = BOARD_LCD_BL,
                               .speed_mode = LEDC_LOW_SPEED_MODE,
                               .channel = LEDC_CHANNEL_0,
                               .timer_sel = LEDC_TIMER_0,
                               .duty = 255};
    if (ledc_timer_config(&t) != ESP_OK || ledc_channel_config(&c) != ESP_OK)
        return false;
    return true;
}
#endif
#if CONFIG_ADAPTER_LED
static void led_byte(uint8_t v) {
    for (int i = 7; i >= 0; i--) {
        gpio_set_level(BOARD_LED_CLK, 0);
        gpio_set_level(BOARD_LED_DATA, (v >> i) & 1);
        gpio_set_level(BOARD_LED_CLK, 1);
    }
}
#endif
typedef enum { LED_JOIN, LED_SETUP, LED_UP, LED_FAIL } led_mode_t;
static led_mode_t led_mode = LED_SETUP;
static uint64_t led_since;
static void led_color(uint8_t r, uint8_t g, uint8_t b) {
#if CONFIG_ADAPTER_LED
    for (int i = 0; i < 4; i++)
        led_byte(0);
    led_byte(0xe2);
    led_byte(b);
    led_byte(g);
    led_byte(r);
    for (int i = 0; i < 4; i++)
        led_byte(255);
#else
    (void)r;
    (void)g;
    (void)b;
#endif
}
/* Slow triangle wave, 0..255, so status reads as "alive" rather than "blinking". */
static uint8_t breathe(uint64_t now, unsigned period_ms) {
    unsigned t = now % period_ms, half = period_ms / 2;
    unsigned up = t < half ? t : period_ms - t;
    return 40 + up * 215 / half;
}
static void led_update(uint64_t now) {
    uint32_t since = now - led_since;
    switch (led_mode) {
    case LED_SETUP: /* blue, slow breathe */
        led_color(0, 0, breathe(now, 3000) * 180 / 255);
        break;
    case LED_UP: /* one bright arrival glow that settles to steady green */
        if (since < 1200) {
            unsigned w = 120 - since * 120 / 1200;
            led_color(w, 180, w);
        } else
            led_color(0, 180, 0);
        break;
    case LED_FAIL: { /* two short red blinks, then a rest: reads as "error" without colour */
        unsigned t = since % 2000;
        led_color(t < 150 || (t >= 300 && t < 450) ? 180 : 0, 0, 0);
        break;
    }
    default: { /* amber, faster breathe while joining or waiting for USB */
        unsigned k = breathe(now, 1600);
        led_color(k * 120 / 255, k * 60 / 255, 0);
    }
    }
}
static void task(void *arg) {
    gpio_config_t button = {.pin_bit_mask = 1ULL << BOARD_BUTTON,
                            .mode = GPIO_MODE_INPUT,
                            .pull_up_en = GPIO_PULLUP_ENABLE};
    gpio_config(&button);
#if CONFIG_ADAPTER_LED
    gpio_config_t led = {.pin_bit_mask = (1ULL << BOARD_LED_DATA) | (1ULL << BOARD_LED_CLK),
                         .mode = GPIO_MODE_OUTPUT};
    gpio_config(&led);
#endif
#if CONFIG_ADAPTER_DISPLAY
    screen = lcd_init();
    if (!screen)
        ESP_LOGW("ui", "Display unavailable; networking continues");
#endif
    button_t btn = {0};
    rates_t rates = {0};
    unsigned page = 0;
    int menu = -1;
    bool confirm = false;
    uint64_t confirm_until = 0, last_touch = 0, last_draw = 0, last_led = 0;
#if CONFIG_ADAPTER_DISPLAY
    unsigned rotation = 0;
#endif
    bool dim = false;
    for (;;) {
        uint64_t now = esp_timer_get_time() / 1000;
        static app_snapshot_t a;
        app_snapshot(&a);
        dim = now - last_touch > (uint64_t)a.cfg.dim_seconds * 1000 && !a.setup;
        button_event_t ev = button_update(&btn, !gpio_get_level(BOARD_BUTTON), dim, now);
        if (ev != BUTTON_NONE) {
            last_touch = now;
            dim = false;
            if (ev == BUTTON_SHORT) {
                if (menu >= 0) {
                    menu = (menu + 1) % 11;
                    confirm = false;
                } else
                    page = (page + 1) % 4;
            }
            if (ev == BUTTON_HOLD) {
                if (menu < 0) {
                    menu = 0;
                    confirm = false;
                } else if (confirm && now < confirm_until) {
                    control_submit("confirm-reset");
                    confirm = false;
                    menu = -1;
                } else if (menu == 0) {
                    control_submit(a.setup ? "cancel" : "setup");
                    menu = -1;
                } else if (menu >= 1 && menu <= 8) {
                    char cmd[20];
                    /* An empty slot opens setup to add a network there; a saved one is used. */
                    snprintf(cmd, sizeof(cmd), a.cfg.p[menu - 1].ssid[0] ? "use %d" : "setup %d", menu);
                    control_submit(cmd);
                    menu = -1;
                } else if (menu == 9) {
                    control_submit("reset");
                    confirm = true;
                    confirm_until = now + 10000;
                } else
                    menu = -1;
            }
        }
        if (confirm && now >= confirm_until)
            confirm = false;
        if (now - last_draw >= 250) {
            last_draw = now;
            bridge_snapshot_t b;
            bridge_snapshot(&b);
            bridge_crash_info_t crash;
            bridge_get_crash(&crash);
            rate_update(&rates, b.stats.down_bytes, b.stats.up_bytes, now * 1000);
            view_t v = {.page = page,
                        .detail = (now / 4000) % 3,
                        .tick = (now / 500) % 4,
                        .setup = a.setup,
                        .trial = a.trial,
                        .associated = b.associated,
                        .usb_mounted = b.usb_mounted,
                        .usb_ready = b.usb_ready,
                        .rssi = b.rssi,
                        .active = a.active,
                        .down_mbps = rates.down_mbps,
                        .up_mbps = rates.up_mbps,
                        .up_bytes = b.stats.up_bytes,
                        .down_bytes = b.stats.down_bytes,
                        .uptime = now / 1000,
                        .connection_uptime = b.associated ? (now - b.connected_ms) / 1000 : 0,
                        .drops =
                            b.stats.rxdrop + b.stats.txdrop + b.stats.poolfail + b.stats.malformed,
                        .forwarded = b.stats.host_to_wifi + b.stats.wifi_to_host,
                        .reconnects = b.reconnects,
                        .reason = b.last_reason,
                        .usb_resets = b.usb_resets,
                        .heap = a.free_heap,
                        .min_heap = a.min_heap,
                        .boots = crash.boots,
                        .watchdogs = crash.hangs,
                        .panics = crash.faults,
                        .reset = esp_reset_reason()};
            if (a.active >= 0) {
                strcpy(v.ssid, a.cfg.p[a.active].ssid);
                strcpy(v.name, a.cfg.p[a.active].name);
            } else
                strcpy(v.ssid, "Unconfigured");
            strcpy(v.error, a.error);
            if (!b.associated && a.active >= 0 && b.last_reason)
                snprintf(v.error, sizeof(v.error), "%s (%u)", bridge_link_status(), b.last_reason);
            strcpy(v.ap_ssid, a.ap_ssid);
            strcpy(v.ap_pass, a.ap_pass);
            v.ip_valid = b.associated && address_fresh(b.addresses.valid4, b.addresses.seen4, now);
            if (v.ip_valid) {
                snprintf(v.ip, sizeof(v.ip), "%u.%u.%u.%u", b.addresses.ip4[0], b.addresses.ip4[1],
                         b.addresses.ip4[2], b.addresses.ip4[3]);
                v.age_ms = now - b.addresses.seen4;
            }
            char lines[5][32];
            view_lines(&v, lines);
            if (menu >= 0) {
                memset(lines, 0, sizeof(lines));
                strcpy(lines[0], confirm ? "CONFIRM FACTORY RESET" : "SETUP MENU");
                if (confirm) {
                    strcpy(lines[1], "Release; hold again <10s");
                    strcpy(lines[2], "Short press cancels");
                } else {
                    if (menu == 0)
                        strcpy(lines[1], a.setup ? "Cancel setup AP" : "Enter setup AP");
                    else if (menu == 9)
                        strcpy(lines[1], "Factory reset...");
                    else if (menu == 10)
                        strcpy(lines[1], "Exit menu");
                    else {
                        char tmp[48];
                        snprintf(tmp, sizeof(tmp), "%d %s", menu,
                                 a.cfg.p[menu - 1].ssid[0] ? a.cfg.p[menu - 1].name : "(empty) add");
                        text_clip(lines[1], 32, tmp, 26);
                    }
                    strcpy(lines[3], "Short: next  Hold: select");
                }
            }
#if CONFIG_ADAPTER_DISPLAY
            if (screen) {
                if (rotation != a.cfg.rotation) {
                    rotation = a.cfg.rotation;
                    esp_lcd_panel_mirror(panel, rotation != 0, rotation == 0);
                }
                unsigned bright = dim ? 5 : a.cfg.brightness;
                ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, 255 - bright * 255 / 100);
                ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0);
                int layout = a.setup && menu < 0 ? (a.ap_pass[0] ? 2 : 1) : 0;
                if (layout != big_layout) {
                    big_layout = layout;
                    for (int i = 0; i < 5; i++) {
                        lv_obj_set_style_text_font(labels[i],
                                                   layout ? &lv_font_montserrat_16
                                                          : &lv_font_montserrat_10,
                                                   0);
                        lv_obj_set_pos(labels[i], 2,
                                       layout == 1   ? 14 + i * 28
                                       : layout == 2 ? 4 + i * 24
                                                     : 2 + i * 15);
                        lv_obj_set_height(labels[i], layout ? 22 : 13);
                    }
                }
                if (page == 0 && a.active >= 0 && !a.setup && menu < 0) {
                    text_clip(lines[0], sizeof(lines[0]), v.ssid, 26);
                    lv_obj_set_width(labels[0], 104);
                    char signal[16];
                    if (v.associated && v.rssi != INT8_MIN)
                        snprintf(signal, sizeof(signal), "%ddBm", v.rssi);
                    else
                        strcpy(signal, "RSSI --");
                    if (strcmp(lv_label_get_text(signal_label), signal))
                        lv_label_set_text(signal_label, signal);
                    lv_obj_remove_flag(signal_label, LV_OBJ_FLAG_HIDDEN);
                } else {
                    lv_obj_set_width(labels[0], 156);
                    lv_obj_add_flag(signal_label, LV_OBJ_FLAG_HIDDEN);
                }
                for (int i = 0; i < 5; i++)
                    if (strcmp(lv_label_get_text(labels[i]), lines[i]))
                        lv_label_set_text(labels[i], lines[i]);
                float max = 1;
                for (int i = 0; i < HISTORY_LEN; i++)
                    if (rates.history[i] > max)
                        max = rates.history[i];
                for (int i = 0; i < HISTORY_LEN; i++) {
                    if (page == 1 && !a.setup && menu < 0) {
                        unsigned idx = (rates.cursor + i) % HISTORY_LEN;
                        int height = (int)(rates.history[idx] / max * 20);
                        lv_obj_remove_flag(bars[i], LV_OBJ_FLAG_HIDDEN);
                        lv_obj_set_pos(bars[i], i * 5, 79 - height);
                        lv_obj_set_size(bars[i], 4, height ? height : 1);
                    } else
                        lv_obj_add_flag(bars[i], LV_OBJ_FLAG_HIDDEN);
                }
            }
#endif
            led_mode_t mode = LED_JOIN;
            if (a.setup || a.active < 0)
                mode = LED_SETUP;
            else if (b.associated && b.usb_ready)
                mode = LED_UP;
            else if (!b.associated &&
                     (b.last_reason == 201 || b.last_reason == 202 || b.last_reason == 15))
                mode = LED_FAIL;
            if (mode != led_mode) {
                led_mode = mode;
                led_since = now;
            }
            app_ui_stack(uxTaskGetStackHighWaterMark(NULL));
        }
        if (now - last_led >= 50) {
            last_led = now;
            led_update(now);
        }
#if CONFIG_ADAPTER_DISPLAY
        if (screen)
            lv_timer_handler();
#endif
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
void ui_start(void) {
    if (xTaskCreate(task, "status_ui", 6144, NULL, 1, NULL) != pdPASS)
        ESP_LOGW("ui", "UI task unavailable; network continues");
}
