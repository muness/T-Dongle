// SPDX-License-Identifier: MIT
#include "health.h"
#include <string.h>

void health_note_boot(health_counters *rtc, health_reset_class reset) {
    if (reset == HEALTH_RESET_COLD || rtc->magic != HEALTH_MAGIC) {
        memset(rtc, 0, sizeof(*rtc));
        rtc->magic = HEALTH_MAGIC;
    }
    rtc->boots++;
    if (reset == HEALTH_RESET_PANIC) rtc->panics++;
    else if (reset == HEALTH_RESET_WATCHDOG) rtc->watchdogs++;
}
