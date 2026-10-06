// SPDX-License-Identifier: MIT
#include "traffic.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static atomic_uint down_bytes, up_bytes, down_frames, up_frames;
void traffic_count_down(uint32_t bytes) {
    atomic_fetch_add_explicit(&down_bytes, bytes, memory_order_relaxed);
    atomic_fetch_add_explicit(&down_frames, 1, memory_order_relaxed);
}
void traffic_count_up(uint32_t bytes) {
    atomic_fetch_add_explicit(&up_bytes, bytes, memory_order_relaxed);
    atomic_fetch_add_explicit(&up_frames, 1, memory_order_relaxed);
}
traffic_counters traffic_read(void) {
    return (traffic_counters){atomic_load_explicit(&down_bytes, memory_order_relaxed), atomic_load_explicit(&up_bytes, memory_order_relaxed),
                              atomic_load_explicit(&down_frames, memory_order_relaxed), atomic_load_explicit(&up_frames, memory_order_relaxed)};
}
static uint32_t kbps(uint32_t bytes, uint32_t ms) { return ms ? (uint32_t)((uint64_t)bytes * 8 / ms) : 0; }
void traffic_sample(traffic_sampler *t, const traffic_counters *now, uint32_t now_ms) {
    if (!t->started) {
        t->started = true;
        t->last = *now;
        t->window_start_ms = now_ms;
        return;
    }
    /* Differences modulo 2^32, so a counter that wrapped (4 GB) is not a negative burst. */
    uint32_t down = now->down_bytes - t->last.down_bytes, up = now->up_bytes - t->last.up_bytes;
    t->down_total += down;
    t->up_total += up;
    t->down_frames_total += now->down_frames - t->last.down_frames;
    t->up_frames_total += now->up_frames - t->last.up_frames;
    t->window_down += down;
    t->window_up += up;
    t->last = *now;
    uint32_t elapsed = now_ms - t->window_start_ms;
    if (elapsed < TRAFFIC_WINDOW_MS) return;
    t->down_kbps = kbps(t->window_down, elapsed);
    t->up_kbps = kbps(t->window_up, elapsed);
    uint32_t both = t->down_kbps + t->up_kbps;
    t->history_kbps[t->cursor++ % TRAFFIC_HISTORY] = both > 65535 ? 65535 : (uint16_t)both;
    t->window_down = t->window_up = 0;
    t->window_start_ms = now_ms;
}
void traffic_bars(const traffic_sampler *t, uint8_t out[TRAFFIC_HISTORY]) {
    uint32_t scale = 1000;   /* full scale is at least 1 Mbit/s */
    for (unsigned i = 0; i < TRAFFIC_HISTORY; i++) if (t->history_kbps[i] > scale) scale = t->history_kbps[i];
    for (unsigned i = 0; i < TRAFFIC_HISTORY; i++) {
        uint32_t v = t->history_kbps[(t->cursor + i) % TRAFFIC_HISTORY];   /* the oldest entry sits at the cursor */
        out[i] = (uint8_t)((uint64_t)v * TRAFFIC_BAR_MAX / scale);
    }
}
void traffic_format_mbps(char *out, unsigned size, uint32_t kbps_value) {
    snprintf(out, size, "%u.%02u", (unsigned)(kbps_value / 1000), (unsigned)(kbps_value % 1000 / 10));
}
void traffic_format_megabytes(char *out, unsigned size, uint64_t bytes) {
    uint64_t tenths = bytes / 100000;   /* 0.1 MB steps */
    if (tenths >= 1000) snprintf(out, size, "%u", (unsigned)(tenths / 10));
    else snprintf(out, size, "%u.%u", (unsigned)(tenths / 10), (unsigned)(tenths % 10));
}
