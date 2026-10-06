// SPDX-License-Identifier: MIT
#include "traffic.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static traffic_counters at(uint32_t down, uint32_t up, uint32_t down_f, uint32_t up_f) { return (traffic_counters){down, up, down_f, up_f}; }
static void rates_and_totals(void) {
    traffic_sampler t = {0};
    traffic_counters c = at(0, 0, 0, 0);
    traffic_sample(&t, &c, 5000);                               /* the first reading only sets the baseline */
    assert(t.down_total == 0 && t.down_kbps == 0);
    c = at(62500, 12500, 50, 10); traffic_sample(&t, &c, 5500);   /* half a window: totals move, rates wait */
    assert(t.down_total == 62500 && t.up_total == 12500 && t.down_kbps == 0 && t.cursor == 0);
    c = at(125000, 25000, 100, 20); traffic_sample(&t, &c, 6000);
    assert(t.down_kbps == 1000 && t.up_kbps == 200 && t.cursor == 1 && t.history_kbps[0] == 1200);   /* 125000 B in 1 s = 1 Mbit/s */
    assert(t.down_frames_total == 100 && t.up_frames_total == 20);
    c = at(125000, 25000, 100, 20); traffic_sample(&t, &c, 7000);   /* idle second */
    assert(t.down_kbps == 0 && t.up_kbps == 0 && t.history_kbps[1] == 0);
    c = at(125000 + 250000, 25000, 100, 20); traffic_sample(&t, &c, 9000);   /* a longer window: 2 s, 1 Mbit/s */
    assert(t.down_kbps == 1000 && t.cursor == 3);
}
static void counter_wrap(void) {
    traffic_sampler t = {0};
    traffic_counters c = at(0xffff0000u, 0xfffffff0u, 0xffffffffu, 0);
    traffic_sample(&t, &c, 0);
    c = at(0xffff0000u + 125000u, 0xfffffff0u + 100u, 1, 0);   /* the byte and frame counters wrapped past 2^32 */
    traffic_sample(&t, &c, 1000);
    assert(t.down_total == 125000 && t.up_total == 100 && t.down_kbps == 1000 && t.up_kbps == 0 && t.down_frames_total == 2);
    /* Totals are 64 bit and keep counting past 4 GB. */
    for (unsigned i = 0; i < 40; i++) { c.down_bytes += 0x10000000u; traffic_sample(&t, &c, 2000 + i * 1000); }
    assert(t.down_total > 0xffffffffull);
}
static void bars(void) {
    traffic_sampler t = {0};
    uint8_t b[TRAFFIC_HISTORY];
    traffic_bars(&t, b);
    for (unsigned i = 0; i < TRAFFIC_HISTORY; i++) assert(b[i] == 0);   /* idle draws nothing */
    traffic_counters c = at(0, 0, 0, 0);
    traffic_sample(&t, &c, 0);
    for (unsigned i = 1; i <= 40; i++) { c.down_bytes += i <= 20 ? 31250 : 62500; traffic_sample(&t, &c, i * 1000); }   /* 0.25 then 0.5 Mbit/s */
    traffic_bars(&t, b);
    unsigned max = 0;
    for (unsigned i = 0; i < TRAFFIC_HISTORY; i++) { assert(b[i] <= TRAFFIC_BAR_MAX); if (b[i] > max) max = b[i]; }
    assert(max == 10);   /* full scale is at least 1 Mbit/s: 0.5 Mbit/s is half height, not full */
    assert(b[TRAFFIC_HISTORY - 1] == 10);   /* newest on the right */
    c.down_bytes += 125000u * 8;   /* 8 Mbit/s in one window scales the graph to the busiest second */
    traffic_sample(&t, &c, 41000 + 0);
    traffic_bars(&t, b);
    assert(b[TRAFFIC_HISTORY - 1] == TRAFFIC_BAR_MAX && b[TRAFFIC_HISTORY - 2] == 1);
}
static void formatting(void) {
    char s[16];
    traffic_format_mbps(s, sizeof(s), 0); assert(!strcmp(s, "0.00"));
    traffic_format_mbps(s, sizeof(s), 1234); assert(!strcmp(s, "1.23"));
    traffic_format_mbps(s, sizeof(s), 999); assert(!strcmp(s, "0.99"));
    traffic_format_mbps(s, sizeof(s), 9400); assert(!strcmp(s, "9.40"));
    traffic_format_megabytes(s, sizeof(s), 0); assert(!strcmp(s, "0.0"));
    traffic_format_megabytes(s, sizeof(s), 12345678); assert(!strcmp(s, "12.3"));
    traffic_format_megabytes(s, sizeof(s), 99999999); assert(!strcmp(s, "99.9"));
    traffic_format_megabytes(s, sizeof(s), 100000000); assert(!strcmp(s, "100"));
    traffic_format_megabytes(s, sizeof(s), 5ull * 1000 * 1000 * 1000); assert(!strcmp(s, "5000"));
}
static void *producer(void *arg) {
    int down = *(int *)arg;
    for (unsigned i = 0; i < 100000; i++) { if (down) traffic_count_down(1500); else traffic_count_up(60); }
    return NULL;
}
static void counters_from_two_threads(void) {
    traffic_counters before = traffic_read();
    pthread_t a, b, c;
    int down = 1, up = 0;
    pthread_create(&a, NULL, producer, &down); pthread_create(&b, NULL, producer, &down); pthread_create(&c, NULL, producer, &up);
    traffic_counters live;
    for (unsigned i = 0; i < 100; i++) { live = traffic_read(); (void)live; }   /* a reader racing the writers (TSan) */
    pthread_join(a, NULL); pthread_join(b, NULL); pthread_join(c, NULL);
    traffic_counters after = traffic_read();
    assert(after.down_bytes - before.down_bytes == 2u * 100000u * 1500u && after.up_bytes - before.up_bytes == 100000u * 60u);
    assert(after.down_frames - before.down_frames == 200000u && after.up_frames - before.up_frames == 100000u);
}
int main(void) {
    rates_and_totals(); counter_wrap(); bars(); formatting(); counters_from_two_threads();
    puts("Traffic: windowed integer rates, 32 bit wrap-safe totals, graph scaling, formatting, counters exact under threads");
    return 0;
}
