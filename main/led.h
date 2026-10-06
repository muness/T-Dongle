// SPDX-License-Identifier: MIT
#pragma once
/* The APA102 status light (one pixel on GPIO39 clock / GPIO40 data, original T-Dongle-S3).
 *
 * States, as documented for v0.1.1 plus the ones the unified firmware adds:
 *   SETUP      breathing blue    setup access point running, or no Wi-Fi network saved yet
 *   JOIN       breathing amber   joining Wi-Fi, waiting for the USB side, or (tailnet mode) waiting for the tailnet
 *   UP         green             one bright arrival glow, then steady: Wi-Fi joined and the USB link ready
 *                                (tailnet mode: Wi-Fi joined, a tailnet ready, USB ready)
 *   FAIL       two red blinks    the network was not found or the password was refused (v0.1.1), or a tailnet failed to connect
 *   ATTENTION  slow red breathing recovery mode: services are off after repeated crashes (see boot_health)
 *   LOGIN      breathing cyan    tailnet mode: waiting for the sign-in to be approved in a browser
 * Pure C, host tested (tests/test_led.c). The bit-banging lives in alternative/tailnet/main/ui_poll.inc. */
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum { LED_JOIN, LED_SETUP, LED_UP, LED_FAIL, LED_ATTENTION, LED_LOGIN } led_mode;
typedef struct { uint8_t r, g, b; } led_rgb;
typedef struct {
    bool setup;             /* setup access point running */
    bool no_network;        /* no Wi-Fi network saved */
    bool associated;        /* joined Wi-Fi */
    bool usb_ready;
    bool recovery;
    bool tailnet;           /* tailnet gateway mode */
    unsigned tailnet_ready, tailnet_failed, tailnet_login;
    uint16_t last_reason;   /* wifi_err_reason_t of the last disconnect */
} led_inputs;

/* Disconnect reasons that mean "wrong network or password" (wifi_err_reason_t: NO_AP_FOUND, AUTH_FAIL, 4WAY_HANDSHAKE_TIMEOUT). */
bool led_reason_is_join_failure(uint16_t reason);
led_mode led_select(const led_inputs *in);
/* The colour to show at now_ms; since_ms is when the current mode began (for the arrival glow and the blink phase). */
led_rgb led_color(led_mode mode, uint32_t now_ms, uint32_t since_ms);
/* The 12 byte APA102 frame for one pixel: start frame, brightness header 0xE2, blue, green, red, end frame. */
void led_apa102_frame(led_rgb color, uint8_t out[12]);
