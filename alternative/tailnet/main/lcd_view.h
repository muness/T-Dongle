#pragma once
#include <stdbool.h>
#include <stdint.h>
/* The status screen, built from a snapshot of the dongle's state. Pure: no ESP-IDF types, so every screen is host tested
 * (tests/test_lcd.c) and rendered to PPM files for review.
 *
 * Pages (a short button press cycles them, as in v0.1.1): 0 Connection, 1 Traffic, 2 Health, 3 Setup. Page 0 is the status screen
 * of the unified firmware (title, two detail lines, signal line, version and USB state). The overlays STARTING, INSTALLING and
 * RECOVERY (and the setup access point screen while a setup boot runs) replace the page; the button menu replaces everything. */
enum { LCD_PAGES = 4, LCD_BARS = 32, LCD_ROWS = 5 };
typedef struct {
    bool bridge, wifi, saved_wifi, recovery, starting, installing, usb, usb_configured, usb_suspended;
    unsigned saved, enabled, ready, login, failed;
    unsigned page;                                   /* 0 to LCD_PAGES - 1; anything else shows page 0 */
    /* Wi-Fi link */
    bool rssi_valid;
    int rssi;                                        /* dBm */
    char ssid[33];                                   /* the joined network, empty when none */
    /* Setup access point (a setup boot) */
    bool setup;
    char ap_ssid[16];
    unsigned setup_seconds_left;
    /* Traffic page */
    uint32_t down_kbps, up_kbps;
    uint64_t down_bytes, up_bytes, down_frames, up_frames;
    uint8_t bars[LCD_BARS];                          /* 0..20, oldest first */
    /* Health page */
    uint32_t uptime_s, wifi_up_s, connects, last_reason, usb_resets, heap_free, heap_min, heap_largest, reset_reason, boots, watchdogs, panics;
    unsigned health_view;                            /* which of the three Health views (0 to 2) */
    /* Setup page */
    unsigned active_slot;                            /* saved network in use, 1-based, 0 none */
    char active_name[25];
} lcd_state;
typedef enum { LCD_LAYOUT_STATUS = 0, LCD_LAYOUT_ROWS } lcd_layout;
typedef struct {
    union {   /* one layout at a time: the struct is on the control task's stack and in a static copy of what is on the glass */
        struct { char title[14], detail[27], hint[27], extra[27], footer[27]; };   /* LCD_LAYOUT_STATUS */
        char row[LCD_ROWS][27];                                                    /* LCD_LAYOUT_ROWS; row[0] is the heading */
    };
    uint8_t bars[LCD_BARS];
    bool attention;
    uint8_t layout, bar_count;
} lcd_view;
void lcd_compose(const lcd_state *state,const char *version,lcd_view *view);
/* The view of the button menu: rows as menu_render produced them (the first is the heading). */
void lcd_compose_rows(lcd_view *view,const char rows[LCD_ROWS][27],bool attention);
/* "45s", "12m05s", "3h12m", "2d04h": a duration in a few characters. out holds at least 8 bytes. */
void lcd_format_duration(char *out,unsigned size,uint32_t seconds);
/* "123456", "1234k", "1234M": a count in at most 7 characters. out holds at least 8 bytes. */
void lcd_format_count(char *out,unsigned size,uint64_t n);
/* One scanline, RGB565 in host byte order. No allocation or framebuffer. */
void lcd_render_row(const lcd_view *view,unsigned y,uint16_t pixels[160]);
