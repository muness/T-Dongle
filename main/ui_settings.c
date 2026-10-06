// SPDX-License-Identifier: MIT
#include "ui_settings.h"
#include <stdlib.h>
#include <string.h>

void ui_settings_defaults(ui_settings *s) {
    s->brightness = UI_BRIGHTNESS_DEFAULT;
    s->rotation = 0;
    s->dim_seconds = UI_DIM_SECONDS_DEFAULT;
}
bool ui_settings_valid(const ui_settings *s) {
    return s->brightness >= UI_BRIGHTNESS_MIN && s->brightness <= UI_BRIGHTNESS_MAX && s->rotation <= UI_ROTATION_MAX &&
           s->dim_seconds >= UI_DIM_SECONDS_MIN && s->dim_seconds <= UI_DIM_SECONDS_MAX;
}
/* One unsigned decimal token: no sign, no leading blank handled by the caller, at most 5 digits (nothing valid is longer). */
static const char *number(const char *p, unsigned long *out) {
    if (*p < '0' || *p > '9') return NULL;
    unsigned long value = 0;
    unsigned digits = 0;
    while (*p >= '0' && *p <= '9') {
        if (++digits > 5) return NULL;
        value = value * 10 + (unsigned long)(*p - '0');
        p++;
    }
    *out = value;
    return p;
}
bool ui_settings_parse(const char *args, ui_settings *out) {
    unsigned long v[3];
    const char *p = args;
    for (unsigned i = 0; i < 3; i++) {
        while (*p == ' ') p++;
        p = number(p, &v[i]);
        if (!p) return false;
        if (i < 2 && *p != ' ') return false;
    }
    while (*p == ' ') p++;
    if (*p) return false;
    ui_settings candidate = {.brightness = (uint8_t)(v[0] > 255 ? 255 : v[0]), .rotation = (uint8_t)(v[1] > 255 ? 255 : v[1]),
                             .dim_seconds = (uint16_t)(v[2] > 65535 ? 65535 : v[2])};
    if (!ui_settings_valid(&candidate)) return false;
    *out = candidate;
    return true;
}
unsigned ui_settings_backlight_percent(const ui_settings *s, bool dimmed) {
    return dimmed && s->brightness > UI_DIM_PERCENT ? UI_DIM_PERCENT : s->brightness;
}
unsigned ui_settings_backlight_duty(unsigned percent) {
    if (percent > 100) percent = 100;
    return 255 - percent * 255 / 100;
}
void ui_settings_encode(const ui_settings *s, ui_settings_blob *out) {
    memset(out, 0, sizeof(*out));
    out->schema = UI_SETTINGS_SCHEMA;
    out->brightness = s->brightness;
    out->rotation = s->rotation;
    out->dim_seconds = s->dim_seconds;
}
bool ui_settings_decode(const void *data, size_t length, ui_settings *out) {
    ui_settings_blob blob;
    if (!data || length != sizeof(blob)) return false;
    memcpy(&blob, data, sizeof(blob));
    ui_settings candidate = {.brightness = blob.brightness, .rotation = blob.rotation, .dim_seconds = blob.dim_seconds};
    if (blob.schema != UI_SETTINGS_SCHEMA || !ui_settings_valid(&candidate)) return false;
    *out = candidate;
    return true;
}
