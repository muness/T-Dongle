// SPDX-License-Identifier: MIT
#pragma once
/* Display settings (v0.1.1 `display BRIGHTNESS ROTATION DIM_SECONDS`): backlight percentage, 180 degree rotation and the idle
 * time after which the backlight drops to UI_DIM_PERCENT. Pure: no ESP-IDF types, host tested (tests/test_ui_settings.c).
 *
 * Persistence: NVS namespace tn_settings, key "display", a fixed 8 byte blob (ui_settings_blob). The v0.1.1 firmware kept the
 * same three values inside its `adapter/config` blob; display_load in the firmware falls back to that blob when no "display"
 * key exists yet, so an upgrade keeps the user's brightness without writing anything (see legacy_import.h). */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { UI_BRIGHTNESS_MIN = 5, UI_BRIGHTNESS_MAX = 100, UI_BRIGHTNESS_DEFAULT = 60,
       UI_DIM_SECONDS_MIN = 10, UI_DIM_SECONDS_MAX = 3600, UI_DIM_SECONDS_DEFAULT = 60,
       UI_DIM_PERCENT = 5,        /* backlight while dimmed: the same floor the brightness setting accepts */
       UI_ROTATION_MAX = 1 };

typedef struct {
    uint8_t brightness;     /* percent, UI_BRIGHTNESS_MIN..UI_BRIGHTNESS_MAX */
    uint8_t rotation;       /* 0, or 1 for 180 degrees */
    uint16_t dim_seconds;   /* UI_DIM_SECONDS_MIN..UI_DIM_SECONDS_MAX */
} ui_settings;

void ui_settings_defaults(ui_settings *s);
bool ui_settings_valid(const ui_settings *s);
/* "BRIGHTNESS ROTATION DIM_SECONDS": three unsigned decimal integers separated by blanks and nothing else. Out of range or
 * malformed input returns false and leaves *out untouched. */
bool ui_settings_parse(const char *args, ui_settings *out);
/* Backlight percentage in force: UI_DIM_PERCENT while dimmed, never above the configured brightness. */
unsigned ui_settings_backlight_percent(const ui_settings *s, bool dimmed);
/* The LEDC duty for an active-low backlight (BOARD_LCD_BL_ACTIVE_LOW) at the given percentage, 8 bit resolution. */
unsigned ui_settings_backlight_duty(unsigned percent);

enum { UI_SETTINGS_SCHEMA = 1 };
typedef struct { uint32_t schema; uint8_t brightness, rotation; uint16_t dim_seconds; } ui_settings_blob;
void ui_settings_encode(const ui_settings *s, ui_settings_blob *out);
/* False (and *out untouched) unless the blob has exactly the right size, schema and in-range values. */
bool ui_settings_decode(const void *data, size_t length, ui_settings *out);
