// SPDX-License-Identifier: MIT
#include "health.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    health_counters h;
    memset(&h, 0xaa, sizeof(h));                                  /* power-on RTC contents are indeterminate */
    health_note_boot(&h, HEALTH_RESET_COLD);
    assert(h.magic == HEALTH_MAGIC && h.boots == 1 && !h.watchdogs && !h.panics);
    health_note_boot(&h, HEALTH_RESET_OTHER); assert(h.boots == 2);
    health_note_boot(&h, HEALTH_RESET_PANIC); assert(h.boots == 3 && h.panics == 1 && !h.watchdogs);
    health_note_boot(&h, HEALTH_RESET_WATCHDOG); assert(h.boots == 4 && h.panics == 1 && h.watchdogs == 1);
    health_note_boot(&h, HEALTH_RESET_PANIC); assert(h.panics == 2);
    health_note_boot(&h, HEALTH_RESET_COLD); assert(h.boots == 1 && !h.panics && !h.watchdogs);   /* unplugged: a new session */
    /* A warm reset with garbage RTC contents (no magic) cannot report phantom crashes. */
    memset(&h, 0x55, sizeof(h));
    health_note_boot(&h, HEALTH_RESET_PANIC);
    assert(h.boots == 1 && h.panics == 1 && h.magic == HEALTH_MAGIC);
    puts("Health: boot, panic and watchdog tallies survive warm resets and restart on a cold start or unknown RTC");
    return 0;
}
