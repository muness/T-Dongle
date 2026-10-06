// SPDX-License-Identifier: MIT
/* The linker-wrapped NCM callbacks (main/traffic_hooks.c): the real callback runs first and unchanged, and exactly what it accepted is counted. */
#include "traffic.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool __wrap_tud_network_recv_cb(const uint8_t *src, uint16_t size);
uint16_t __wrap_tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg);

static bool take_frames = true;
static unsigned real_recv_calls, real_xmit_calls;
static uint16_t real_xmit_length;
bool __real_tud_network_recv_cb(const uint8_t *src, uint16_t size) { (void)src; (void)size; real_recv_calls++; return take_frames; }
uint16_t __real_tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg) { (void)ref; real_xmit_calls++; memset(dst, 0xab, arg); return real_xmit_length ? real_xmit_length : arg; }

int main(void) {
    traffic_counters before = traffic_read();
    uint8_t frame[1514] = {0};
    /* From the host: counted when the class driver's glue took the datagram. */
    assert(__wrap_tud_network_recv_cb(frame, 60) && __wrap_tud_network_recv_cb(frame, 1514));
    traffic_counters now = traffic_read();
    assert(now.up_bytes - before.up_bytes == 1574 && now.up_frames - before.up_frames == 2 && now.down_bytes == before.down_bytes && real_recv_calls == 2);
    take_frames = false;   /* the real callback could not take it (it is offered again): not counted */
    assert(!__wrap_tud_network_recv_cb(frame, 100));
    now = traffic_read();
    assert(now.up_bytes - before.up_bytes == 1574 && now.up_frames - before.up_frames == 2 && real_recv_calls == 3);
    /* To the host: counted by the length the real callback copied, whatever the class driver asked for. */
    uint8_t block[1600];
    assert(__wrap_tud_network_xmit_cb(block, NULL, 1200) == 1200 && block[0] == 0xab && block[1199] == 0xab);
    real_xmit_length = 800;
    assert(__wrap_tud_network_xmit_cb(block, NULL, 1200) == 800);
    real_xmit_length = 0;
    now = traffic_read();
    assert(now.down_bytes - before.down_bytes == 2000 && now.down_frames - before.down_frames == 2 && real_xmit_calls == 2);
    puts("Traffic hooks: the real NCM callbacks run unchanged and exactly the accepted frames and bytes are counted");
    return 0;
}
