// SPDX-License-Identifier: MIT
#pragma once
/* Boot and crash tallies for the Health screen page (v0.1.1 showed "Session boots / WDT / Panic"). They live in RTC memory, which
 * a panic or watchdog reset keeps and a power cycle does not, so the page answers "has this dongle been crashing since it was
 * plugged in". This is only a display: the crash-loop quarantine is boot_health.c (recovery mode), which replaced v0.1.1's
 * "drop to the ROM loader after three crashes" on purpose. Pure C, host tested (tests/test_health.c). */
#include <stdbool.h>
#include <stdint.h>

enum { HEALTH_MAGIC = 0x48544c31u };
typedef struct { uint32_t magic, boots, watchdogs, panics; } health_counters;
typedef enum { HEALTH_RESET_OTHER, HEALTH_RESET_COLD, HEALTH_RESET_PANIC, HEALTH_RESET_WATCHDOG } health_reset_class;

/* Count this boot. `rtc` is the RTC-resident record. A cold start (power on, brownout) or a record that does not carry the magic
 * starts the tally again. */
void health_note_boot(health_counters *rtc, health_reset_class reset);
