// SPDX-License-Identifier: MIT
#include "ui_settings.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void defaults_and_ranges(void) {
    ui_settings s;
    ui_settings_defaults(&s);
    assert(s.brightness == 60 && s.rotation == 0 && s.dim_seconds == 60 && ui_settings_valid(&s));   /* v0.1.1 defaults */
    ui_settings t = s;
    t.brightness = 4; assert(!ui_settings_valid(&t)); t.brightness = 5; assert(ui_settings_valid(&t));
    t.brightness = 100; assert(ui_settings_valid(&t)); t.brightness = 101; assert(!ui_settings_valid(&t));
    t = s; t.rotation = 1; assert(ui_settings_valid(&t)); t.rotation = 2; assert(!ui_settings_valid(&t));
    t = s; t.dim_seconds = 9; assert(!ui_settings_valid(&t)); t.dim_seconds = 10; assert(ui_settings_valid(&t));
    t.dim_seconds = 3600; assert(ui_settings_valid(&t)); t.dim_seconds = 3601; assert(!ui_settings_valid(&t));
}
static void parse(void) {
    ui_settings s = {1, 1, 1};
    assert(ui_settings_parse("60 0 60", &s) && s.brightness == 60 && s.rotation == 0 && s.dim_seconds == 60);
    assert(ui_settings_parse("100 1 3600", &s) && s.brightness == 100 && s.rotation == 1 && s.dim_seconds == 3600);
    assert(ui_settings_parse("  5   0   10  ", &s) && s.brightness == 5 && s.dim_seconds == 10);
    assert(ui_settings_parse("075 1 0100", &s) && s.brightness == 75 && s.dim_seconds == 100);
    ui_settings keep = s;
    /* Every refusal leaves the previous value alone. */
    const char *bad[] = {"", "60", "60 0", "60 0 60 1", "60 0 60 x", "4 0 60", "101 0 60", "60 2 60", "60 0 9", "60 0 3601", "-5 0 60", "+5 0 60",
                         "60,0,60", "60 0 60abc", "x 0 60", "60 0 99999999", "999999 0 60", "6O 0 60", "60\t0 60", "60 0 60\n"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        assert(!ui_settings_parse(bad[i], &s));
        assert(!memcmp(&s, &keep, sizeof(s)));
    }
}
static void backlight(void) {
    ui_settings s = {60, 0, 60};
    assert(ui_settings_backlight_percent(&s, false) == 60 && ui_settings_backlight_percent(&s, true) == UI_DIM_PERCENT);
    s.brightness = 5; assert(ui_settings_backlight_percent(&s, true) == 5);   /* dimming never brightens */
    s.brightness = 100;
    assert(ui_settings_backlight_duty(100) == 0 && ui_settings_backlight_duty(0) == 255);   /* active low: full brightness is duty 0 */
    assert(ui_settings_backlight_duty(60) == 255 - 153 && ui_settings_backlight_duty(200) == 0);
    unsigned previous = 256;
    for (unsigned p = 0; p <= 100; p++) { unsigned d = ui_settings_backlight_duty(p); assert(d <= previous && d <= 255); previous = d; }
}
static void blob(void) {
    ui_settings s = {33, 1, 900}, out = {0};
    ui_settings_blob b;
    ui_settings_encode(&s, &b);
    assert(sizeof(b) == 8 && b.schema == 1);
    assert(ui_settings_decode(&b, sizeof(b), &out) && !memcmp(&s, &out, sizeof(s)));
    ui_settings_blob bad = b; bad.schema = 2;
    out = (ui_settings){1, 1, 1};
    assert(!ui_settings_decode(&bad, sizeof(bad), &out) && out.brightness == 1);
    bad = b; bad.brightness = 1; assert(!ui_settings_decode(&bad, sizeof(bad), &out));
    bad = b; bad.rotation = 2; assert(!ui_settings_decode(&bad, sizeof(bad), &out));
    assert(!ui_settings_decode(&b, sizeof(b) - 1, &out) && !ui_settings_decode(&b, sizeof(b) + 1, &out) && !ui_settings_decode(NULL, sizeof(b), &out));
    /* Padding bytes of an encoded blob are zero (it is compared and stored as raw bytes). */
    unsigned char raw[sizeof(b)];
    memset(&b, 0xaa, sizeof(b)); ui_settings_encode(&s, &b); memcpy(raw, &b, sizeof(b));
    ui_settings_blob again; ui_settings_encode(&s, &again);
    assert(!memcmp(raw, &again, sizeof(raw)));
}
int main(void) {
    defaults_and_ranges(); parse(); backlight(); blob();
    puts("Display settings: v0.1.1 defaults and ranges, strict parsing that never half-applies, active-low backlight duty, blob schema");
    return 0;
}
