// SPDX-License-Identifier: MIT
#include "setup_boot.h"
#include <stdio.h>

setup_boot_decision setup_boot_decide(bool software_reset, uint32_t magic, uint32_t next, uint32_t slot, bool networks_saved, bool store_ok) {
    setup_boot_decision d = {0};
    uint32_t request = software_reset && magic == SETUP_BOOT_MAGIC ? next : (uint32_t)SETUP_REQUEST_NONE;   /* anything but 1 and 2 is no request */
    if (request == SETUP_REQUEST_ENTER) {
        d.setup = true;
        d.preselect = slot >= 1 && slot <= SETUP_SLOTS ? (unsigned)slot : 0;
    } else if (request != SETUP_REQUEST_LEAVE) {
        d.setup = !networks_saved && store_ok;
    }
    return d;
}
void setup_boot_request(uint32_t *magic, uint32_t *next, uint32_t *slot, setup_request request, unsigned preselect) {
    *magic = SETUP_BOOT_MAGIC;
    *next = (uint32_t)request;
    *slot = request == SETUP_REQUEST_ENTER && preselect >= 1 && preselect <= SETUP_SLOTS ? preselect : 0;
}
void setup_session_start(setup_session *s, uint32_t now_ms) { s->started_ms = now_ms; s->active = true; }
bool setup_session_expired(const setup_session *s, uint32_t now_ms) {
    return s->active && (uint32_t)(now_ms - s->started_ms) >= SETUP_SESSION_MS;
}
bool setup_session_should_end(const setup_session *s, uint32_t now_ms, bool access_point_up) {
    if (!s->active) return false;
    return setup_session_expired(s, now_ms) || (!access_point_up && (uint32_t)(now_ms - s->started_ms) >= SETUP_AP_GRACE_MS);
}
uint32_t setup_session_seconds_left(const setup_session *s, uint32_t now_ms) {
    if (!s->active) return 0;
    uint32_t elapsed = (uint32_t)(now_ms - s->started_ms);
    return elapsed >= SETUP_SESSION_MS ? 0 : (SETUP_SESSION_MS - elapsed + 999) / 1000;
}
void setup_ap_ssid(char *out, unsigned size, const uint8_t mac[6]) {
    snprintf(out, size, "TDongle-%02X%02X%02X", mac[3], mac[4], mac[5]);
}
