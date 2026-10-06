// SPDX-License-Identifier: MIT
#include "setup_boot.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void decisions(void) {
    const uint32_t M = SETUP_BOOT_MAGIC;
    setup_boot_decision d;
    /* A request survives only a software reset with the magic intact. */
    d = setup_boot_decide(true, M, SETUP_REQUEST_ENTER, 0, true, true); assert(d.setup && d.preselect == 0);
    d = setup_boot_decide(true, M, SETUP_REQUEST_ENTER, 3, true, true); assert(d.setup && d.preselect == 3);
    d = setup_boot_decide(true, M, SETUP_REQUEST_ENTER, 9, true, true); assert(d.setup && d.preselect == 0);   /* slot out of range */
    d = setup_boot_decide(true, M, SETUP_REQUEST_ENTER, 0, true, false); assert(d.setup);                        /* explicit request, even over a bad store */
    d = setup_boot_decide(false, M, SETUP_REQUEST_ENTER, 0, true, true); assert(!d.setup);                       /* a power cycle with stale RTC contents */
    d = setup_boot_decide(true, M ^ 1, SETUP_REQUEST_ENTER, 0, true, true); assert(!d.setup);                    /* no magic */
    d = setup_boot_decide(true, M, 7, 0, true, true); assert(!d.setup);                                          /* garbage request word */
    /* First plug-in: nothing saved opens setup by itself, but never over a store that could not be read. */
    d = setup_boot_decide(false, 0, 0, 0, false, true); assert(d.setup && d.preselect == 0);
    d = setup_boot_decide(false, 0, 0, 0, false, false); assert(!d.setup);
    d = setup_boot_decide(false, 0, 0, 0, true, true); assert(!d.setup);
    /* The restart that closes setup reaches normal mode even with nothing saved (no setup loop), once. */
    d = setup_boot_decide(true, M, SETUP_REQUEST_LEAVE, 0, false, true); assert(!d.setup);
    d = setup_boot_decide(false, M, SETUP_REQUEST_LEAVE, 0, false, true); assert(d.setup);   /* the next cold boot is a first plug-in again */
    d = setup_boot_decide(true, M, SETUP_REQUEST_ENTER, 0, false, true); assert(d.setup);
}
static void request_words(void) {
    uint32_t magic = 0, next = 9, slot = 9;
    setup_boot_request(&magic, &next, &slot, SETUP_REQUEST_ENTER, 4);
    assert(magic == SETUP_BOOT_MAGIC && next == 1 && slot == 4);
    setup_boot_request(&magic, &next, &slot, SETUP_REQUEST_ENTER, 0); assert(slot == 0);
    setup_boot_request(&magic, &next, &slot, SETUP_REQUEST_ENTER, 99); assert(slot == 0);
    setup_boot_request(&magic, &next, &slot, SETUP_REQUEST_LEAVE, 4); assert(next == 2 && slot == 0);
    /* What one boot writes the next boot reads back. */
    setup_boot_request(&magic, &next, &slot, SETUP_REQUEST_ENTER, 6);
    setup_boot_decision d = setup_boot_decide(true, magic, next, slot, true, true);
    assert(d.setup && d.preselect == 6);
}
static void session(void) {
    setup_session s = {0};
    assert(!setup_session_expired(&s, 1000000) && setup_session_seconds_left(&s, 0) == 0);   /* inactive: never expires */
    setup_session_start(&s, 5000);
    assert(SETUP_SESSION_MS == 10 * 60 * 1000);
    assert(!setup_session_expired(&s, 5000) && setup_session_seconds_left(&s, 5000) == 600);
    assert(setup_session_seconds_left(&s, 5001) == 600 && setup_session_seconds_left(&s, 6000) == 599 && setup_session_seconds_left(&s, 5000 + 599000) == 1);
    assert(!setup_session_expired(&s, 5000 + 599999) && setup_session_expired(&s, 5000 + 600000) && setup_session_seconds_left(&s, 5000 + 600000) == 0);
    assert(setup_session_expired(&s, 5000 + 7200000));
    /* esp_timer milliseconds truncated to 32 bits wrap after 49.7 days; a session spanning the wrap still lasts 10 minutes. */
    setup_session_start(&s, 0xffffff00u);
    assert(!setup_session_expired(&s, 0xffffff00u + 599000) && setup_session_expired(&s, 0xffffff00u + 600000));
    assert(setup_session_seconds_left(&s, 0xffffff00u + 1000) == 599);
}
static void access_point_name(void) {
    char ssid[16];
    uint8_t mac[6] = {0x34, 0x85, 0x18, 0xab, 0x0c, 0xf9};
    setup_ap_ssid(ssid, sizeof(ssid), mac);
    assert(!strcmp(ssid, "TDongle-AB0CF9") && strlen(ssid) == 14);
    char small[8];
    setup_ap_ssid(small, sizeof(small), mac);
    assert(strlen(small) == 7);   /* truncated and terminated, never overrun */
}
int main(void) {
    decisions(); request_words(); session(); access_point_name();
    puts("Setup boot: request survives only a software reset, first plug-in opens setup, leaving never loops, 10 minute session wraps safely");
    return 0;
}
