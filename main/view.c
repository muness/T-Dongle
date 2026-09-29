// SPDX-License-Identifier: MIT
#include "view.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
void view_lines(const view_t *v, char lines[5][32]) {
    static const char *const dots[4] = {"DOWN", "JOIN.", "JOIN..", "JOIN..."};
    char b[5][128] = {{0}};
    if (v->setup) {
        /* Large font on the LCD: only what is needed to connect. */
        snprintf(b[0], 128, "%s", v->ap_ssid);
        if (v->ap_pass[0]) {
            snprintf(b[1], 128, "%s", v->ap_pass);
            snprintf(b[2], 128, "192.168.4.1");
        } else
            snprintf(b[1], 128, "192.168.4.1");
    } else if (v->page == 0 && v->active < 0) {
        snprintf(b[0], 128, "Welcome to T-Dongle");
        snprintf(b[1], 128, "No Wi-Fi saved yet.");
        snprintf(b[2], 128, "Hold button 1.5s,");
        snprintf(b[3], 128, "pick Enter setup AP,");
        snprintf(b[4], 128, "hold again to start");
    } else if (v->page == 0) {
        if (v->associated && v->rssi != INT8_MIN)
            snprintf(b[0], 128, "%.18s %ddBm", v->ssid, v->rssi);
        else
            snprintf(b[0], 128, "%.18s RSSI --", v->ssid);
        snprintf(b[1], 128, "USB %s WIFI %s",
                 v->usb_ready     ? "ENUM"
                 : v->usb_mounted ? "SUSP"
                                  : "WAIT",
                 v->associated ? "UP" : dots[v->tick % 4]);
        snprintf(b[2], 128, "OBS %s", v->ip_valid ? v->ip : "not seen / stale");
        if (v->ip_valid)
            snprintf(b[3], 128, "Seen %" PRIu64 "s ago; TTL 60s", v->age_ms / 1000);
        else
            snprintf(b[3], 128, "%.26s", v->error);
        snprintf(b[4], 128, "Internet: not checked");
    } else if (v->page == 1) {
        snprintf(b[0], 128, "D %.2f U %.2f Mb/s", v->down_mbps, v->up_mbps);
        snprintf(b[1], 128, "D %.2f U %.2f MB", (double)v->down_bytes / 1e6,
                 (double)v->up_bytes / 1e6);
        snprintf(b[2], 128, "Fwd %" PRIu32 " Drop %" PRIu32, v->forwarded, v->drops);
    } else if (v->page == 2) {
        snprintf(b[0], 128, "HEALTH %u/3", v->detail % 3 + 1);
        if (v->detail % 3 == 0) {
            snprintf(b[1], 128, "Up %" PRIu64 "s WiFi %" PRIu64 "s", v->uptime,
                     v->connection_uptime);
            snprintf(b[2], 128, "Joins %" PRIu32 " Reason %" PRIu32, v->reconnects, v->reason);
            snprintf(b[3], 128, "USB resets %" PRIu32, v->usb_resets);
        } else if (v->detail % 3 == 1) {
            snprintf(b[1], 128, "Heap %" PRIu32, v->heap);
            snprintf(b[2], 128, "Min heap %" PRIu32, v->min_heap);
            snprintf(b[3], 128, "Reset reason %" PRIu32, v->reset);
        } else {
            snprintf(b[1], 128, "Session boots %" PRIu32, v->boots);
            snprintf(b[2], 128, "WDT %" PRIu32 " Panic %" PRIu32, v->watchdogs, v->panics);
            snprintf(b[3], 128, "%s", v->error);
        }
        snprintf(b[4], 128, "Details rotate every 4s");
    } else {
        snprintf(b[0], 128, "SETUP / PROFILES");
        snprintf(b[1], 128, "%d %.21s", v->active + 1, v->name);
        snprintf(b[2], 128, "%s", v->trial ? "Testing candidate..." : "Hold to open menu");
        snprintf(b[3], 128, "USB console: help");
        snprintf(b[4], 128, "Hold BOOT at plug: ROM");
    }
    for (int i = 0; i < 5; i++)
        text_clip(lines[i], 32, b[i], 26);
}
