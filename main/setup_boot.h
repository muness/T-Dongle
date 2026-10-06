// SPDX-License-Identifier: MIT
#pragma once
/* The setup access point as a boot mode.
 *
 * Setup is entered by RESTARTING the dongle (button menu, serial `setup`, the first boot with no saved network), exactly as in
 * v0.1.1, never by starting an access point inside a running dongle. A setup boot runs no Wi-Fi bridge and no tailnet memberships:
 * the radio, the heap and the HTTP server belong to setup alone for at most SETUP_SESSION_MS, then the dongle restarts into its
 * normal mode. That is what keeps the access point out of the tailnet heap budget (ADR 0023): the two never coexist, so admission
 * (ml_admission.h, ml_heap_budget.h) never has to account for the access point.
 *
 * The request survives the restart in three RTC words (RTC_NOINIT: not cleared by a software reset, indeterminate after a power
 * cycle, hence the magic). Pure C, host tested (tests/test_setup_boot.c). */
#include <stdbool.h>
#include <stdint.h>

enum { SETUP_BOOT_MAGIC = 0x54444d31u, SETUP_SESSION_MS = 600000u, SETUP_SLOTS = 8 };
typedef enum { SETUP_REQUEST_NONE = 0, SETUP_REQUEST_ENTER = 1, SETUP_REQUEST_LEAVE = 2 } setup_request;

typedef struct {
    bool setup;             /* run this boot as the setup access point */
    unsigned preselect;     /* saved network (1 to 8) to preselect on the page, 0 for "add a new one" */
} setup_boot_decision;

/* Decide this boot. A request left by the previous run counts only after a software reset with the magic intact (a power cycle
 * or crash with stale RTC contents must not open an access point). Without a request, setup starts only when no network is saved
 * and the settings store is readable (the first plug-in), never over a damaged store, and never after a LEAVE request (the
 * restart that closes setup must reach normal mode even though nothing is saved yet). */
setup_boot_decision setup_boot_decide(bool software_reset, uint32_t magic, uint32_t next, uint32_t slot, bool networks_saved, bool store_ok);
/* Fill the RTC words for the next boot. */
void setup_boot_request(uint32_t *magic, uint32_t *next, uint32_t *slot, setup_request request, unsigned preselect);

/* The 10 minute session. Times are esp_timer milliseconds truncated to 32 bits; the comparison is wrap safe. */
typedef struct { uint32_t started_ms; bool active; } setup_session;
void setup_session_start(setup_session *s, uint32_t now_ms);
bool setup_session_expired(const setup_session *s, uint32_t now_ms);
uint32_t setup_session_seconds_left(const setup_session *s, uint32_t now_ms);

/* Access point name: TDongle-XXXXXX from the last three bytes of the station MAC (v0.1.1). out holds at least 15 bytes. */
void setup_ap_ssid(char *out, unsigned size, const uint8_t mac[6]);
