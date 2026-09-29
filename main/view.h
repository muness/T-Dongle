// SPDX-License-Identifier: MIT
#pragma once
#include "core.h"
typedef struct {
    unsigned page, detail, tick;
    bool setup, trial, associated, usb_ready, usb_mounted, ip_valid;
    char ssid[33], name[25], ip[40], error[48], ap_ssid[25], ap_pass[17];
    int rssi, active;
    uint64_t age_ms, up_bytes, down_bytes, uptime, connection_uptime;
    double down_mbps, up_mbps;
    uint32_t drops, forwarded, reconnects, reason, usb_resets, heap, min_heap, boots, watchdogs,
        panics, reset;
} view_t;
void view_lines(const view_t *v, char lines[5][32]);
