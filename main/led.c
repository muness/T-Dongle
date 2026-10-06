// SPDX-License-Identifier: MIT
#include "led.h"

bool led_reason_is_join_failure(uint16_t reason) { return reason == 201 || reason == 202 || reason == 15; }
led_mode led_select(const led_inputs *in) {
    if (in->recovery) return LED_ATTENTION;
    if (in->setup || in->no_network) return LED_SETUP;
    if (in->tailnet) {
        if (in->associated && in->tailnet_login) return LED_LOGIN;
        if (in->associated && in->tailnet_ready && in->usb_ready) return LED_UP;
        if (in->associated && in->tailnet_failed) return LED_FAIL;
    } else if (in->associated && in->usb_ready) return LED_UP;
    if (!in->associated && led_reason_is_join_failure(in->last_reason)) return LED_FAIL;
    return LED_JOIN;
}
/* A slow triangle wave, 40..255, so the status reads as "alive" rather than "blinking". */
static unsigned breathe(uint32_t now, unsigned period_ms) {
    unsigned t = now % period_ms, half = period_ms / 2;
    unsigned up = t < half ? t : period_ms - t;
    return 40 + up * 215 / half;
}
led_rgb led_color(led_mode mode, uint32_t now_ms, uint32_t since_ms) {
    uint32_t since = (uint32_t)(now_ms - since_ms);
    switch (mode) {
    case LED_SETUP: return (led_rgb){0, 0, (uint8_t)(breathe(now_ms, 3000) * 180 / 255)};
    case LED_UP:
        if (since < 1200) {
            unsigned w = 120 - since * 120 / 1200;
            return (led_rgb){(uint8_t)w, 180, (uint8_t)w};
        }
        return (led_rgb){0, 180, 0};
    case LED_FAIL: {
        unsigned t = since % 2000;
        return (led_rgb){(t < 150 || (t >= 300 && t < 450)) ? 180 : 0, 0, 0};
    }
    case LED_ATTENTION: return (led_rgb){(uint8_t)(breathe(now_ms, 4000) * 180 / 255), 0, 0};
    case LED_LOGIN: {
        unsigned k = breathe(now_ms, 2400);
        return (led_rgb){0, (uint8_t)(k * 150 / 255), (uint8_t)(k * 180 / 255)};
    }
    case LED_JOIN:
    default: {
        unsigned k = breathe(now_ms, 1600);
        return (led_rgb){(uint8_t)(k * 120 / 255), (uint8_t)(k * 60 / 255), 0};
    }
    }
}
void led_apa102_frame(led_rgb c, uint8_t out[12]) {
    for (unsigned i = 0; i < 4; i++) out[i] = 0;
    out[4] = 0xe2;
    out[5] = c.b;
    out[6] = c.g;
    out[7] = c.r;
    for (unsigned i = 8; i < 12; i++) out[i] = 0xff;
}
