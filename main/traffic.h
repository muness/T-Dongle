// SPDX-License-Identifier: MIT
#pragma once
/* Traffic through the dongle's USB side, for the Traffic screen page and the serial `status` report.
 *
 * Counters: traffic_count_down / traffic_count_up are called for every frame that crosses the USB network interface (to the host,
 * from the host), in both modes, by the link-time wrappers of the two TinyUSB NCM callbacks (alternative/tailnet/main/
 * traffic_hooks.c). They are relaxed atomics on 32 bit words (Xtensa has no 64 bit atomics); a reader takes differences modulo 2^32.
 *
 * Sampler: traffic_sample turns two readings into rates and totals. It is only ever called from one task (the UI poll), so it
 * needs no locking. Rates are measured over windows of at least TRAFFIC_WINDOW_MS, in kilobits per second, in integers (no
 * floating point in the firmware's text path). Pure C, host tested (tests/test_traffic.c, including a TSan run of the counters). */
#include <stdbool.h>
#include <stdint.h>

typedef struct { uint32_t down_bytes, up_bytes, down_frames, up_frames; } traffic_counters;
void traffic_count_down(uint32_t bytes);   /* a frame delivered to the USB host */
void traffic_count_up(uint32_t bytes);     /* a frame received from the USB host */
traffic_counters traffic_read(void);

enum { TRAFFIC_HISTORY = 32, TRAFFIC_WINDOW_MS = 1000, TRAFFIC_BAR_MAX = 20 };
typedef struct {
    traffic_counters last;
    uint32_t window_start_ms, window_down, window_up;   /* bytes counted since the window began */
    bool started;
    uint64_t down_total, up_total;                 /* bytes since the first sample */
    uint64_t down_frames_total, up_frames_total;
    uint32_t down_kbps, up_kbps;                   /* the last complete window */
    uint16_t history_kbps[TRAFFIC_HISTORY];        /* down + up per window in kbit/s, saturating at 65535 (the USB link carries 12 Mbit/s at most), ring */
    unsigned cursor;
} traffic_sampler;

/* Feed a reading taken at now_ms. Totals follow every call; rates and history only advance when a window of at least
 * TRAFFIC_WINDOW_MS has passed since the last one. */
void traffic_sample(traffic_sampler *t, const traffic_counters *now, uint32_t now_ms);
/* The history as bar heights 0..TRAFFIC_BAR_MAX, oldest first, scaled to the busiest window shown (never below 1 Mbit/s
 * full scale, so an idle link draws nothing instead of full-height noise). */
void traffic_bars(const traffic_sampler *t, uint8_t out[TRAFFIC_HISTORY]);
/* "1.23" from kilobits per second (two decimals, rounded down). out holds at least 12 bytes. */
void traffic_format_mbps(char *out, unsigned size, uint32_t kbps);
/* "12.3" or "1234" megabytes from a byte total: one decimal below 100 MB, none above. */
void traffic_format_megabytes(char *out, unsigned size, uint64_t bytes);
