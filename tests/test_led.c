// SPDX-License-Identifier: MIT
#include "led.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void states_bridge(void) {
    led_inputs in = {0};
    assert(led_select(&in) == LED_JOIN);                                   /* saved network, joining */
    in.no_network = true; assert(led_select(&in) == LED_SETUP);            /* nothing saved: breathing blue */
    in.no_network = false; in.setup = true; assert(led_select(&in) == LED_SETUP);
    in = (led_inputs){0}; in.associated = true; assert(led_select(&in) == LED_JOIN);   /* joined, waiting for the USB side */
    in.usb_ready = true; assert(led_select(&in) == LED_UP);
    in.associated = false; assert(led_select(&in) == LED_JOIN);
    /* The v0.1.1 failure reasons: network not found, authentication refused, 4-way handshake timeout. */
    unsigned failures[] = {201, 202, 15};
    for (unsigned i = 0; i < 3; i++) { in = (led_inputs){0}; in.last_reason = (uint16_t)failures[i]; assert(led_select(&in) == LED_FAIL && led_reason_is_join_failure(failures[i])); }
    in = (led_inputs){0}; in.last_reason = 8; assert(led_select(&in) == LED_JOIN && !led_reason_is_join_failure(8));   /* an ordinary disconnect */
    in.last_reason = 201; in.associated = true; in.usb_ready = true; assert(led_select(&in) == LED_UP);   /* a stale failure never shows over a good link */
    in.setup = true; assert(led_select(&in) == LED_SETUP);
}
static void states_tailnet_and_recovery(void) {
    led_inputs in = {.tailnet = true};
    in.associated = true; in.usb_ready = true;
    assert(led_select(&in) == LED_JOIN);                                   /* Wi-Fi up, tailnet not ready */
    in.tailnet_ready = 1; assert(led_select(&in) == LED_UP);
    in.usb_ready = false; assert(led_select(&in) == LED_JOIN);
    in.usb_ready = true; in.tailnet_ready = 0; in.tailnet_failed = 1; assert(led_select(&in) == LED_FAIL);
    in.tailnet_login = 1; assert(led_select(&in) == LED_LOGIN);
    in.associated = false; assert(led_select(&in) == LED_JOIN);
    in.recovery = true; in.associated = true; assert(led_select(&in) == LED_ATTENTION);   /* recovery outranks everything, setup too */
    in.setup = true; assert(led_select(&in) == LED_ATTENTION);
}
static void colours(void) {
    led_rgb c;
    /* Setup is blue only, breathing between a dim and a bright value. */
    unsigned low = 255, high = 0;
    for (uint32_t t = 0; t < 3000; t += 10) { c = led_color(LED_SETUP, t, 0); assert(!c.r && !c.g && c.b <= 180); if (c.b < low) low = c.b; if (c.b > high) high = c.b; }
    assert(low < 40 && high > 170);
    /* Up: one arrival glow (white added to green) that settles to steady green. */
    c = led_color(LED_UP, 1000, 1000); assert(c.g == 180 && c.r == 120 && c.b == 120);
    c = led_color(LED_UP, 1600, 1000); assert(c.g == 180 && c.r == 60 && c.b == 60);
    c = led_color(LED_UP, 2200, 1000); assert(c.r == 0 && c.g == 180 && c.b == 0);
    c = led_color(LED_UP, 900000, 1000); assert(c.r == 0 && c.g == 180 && c.b == 0);
    c = led_color(LED_UP, 5, 0xfffffff0u); assert(c.g == 180);              /* the clock wrapped during the glow */
    /* Fail: two short red blinks then a rest, repeating every 2 s. */
    unsigned on_ms = 0;
    for (uint32_t t = 0; t < 2000; t++) { c = led_color(LED_FAIL, 7000 + t, 7000); assert(!c.g && !c.b); on_ms += c.r ? 1 : 0; assert(!c.r || c.r == 180); }
    assert(on_ms == 300);
    assert(led_color(LED_FAIL, 7000 + 100, 7000).r == 180 && led_color(LED_FAIL, 7000 + 200, 7000).r == 0 && led_color(LED_FAIL, 7000 + 350, 7000).r == 180 && led_color(LED_FAIL, 7000 + 1000, 7000).r == 0);
    assert(led_color(LED_FAIL, 9000 + 100, 7000).r == 180);                 /* the pattern repeats */
    /* Join is amber: red about twice the green, never blue. */
    for (uint32_t t = 0; t < 1600; t += 7) { c = led_color(LED_JOIN, t, 0); assert(!c.b && c.r >= c.g && c.r <= 120 && c.g <= 60); }
    /* Attention is red only and slower; login is cyan. */
    for (uint32_t t = 0; t < 4000; t += 50) { c = led_color(LED_ATTENTION, t, 0); assert(!c.g && !c.b && c.r <= 180); c = led_color(LED_LOGIN, t, 0); assert(!c.r && c.g && c.b); }
}
static void apa102_frame(void) {
    uint8_t f[12];
    led_apa102_frame((led_rgb){1, 2, 3}, f);
    const uint8_t expected[12] = {0, 0, 0, 0, 0xe2, 3, 2, 1, 0xff, 0xff, 0xff, 0xff};   /* the frame v0.1.1 clocked out: BGR order */
    assert(!memcmp(f, expected, 12));
}
int main(void) {
    states_bridge(); states_tailnet_and_recovery(); colours(); apa102_frame();
    puts("LED: v0.1.1 states and failure reasons, tailnet and recovery additions, colour patterns, APA102 frame");
    return 0;
}
