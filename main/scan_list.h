// SPDX-License-Identifier: MIT
#pragma once
/* The "nearby networks" list of the setup page, built from raw Wi-Fi scan records. Pure C, host tested (tests/test_scan_list.c).
 *
 * A scan returns every access point the radio heard, often several for one SSID (a mesh), sometimes hidden (empty SSID), and an SSID
 * is any 0 to 32 bytes. The page needs one entry per network, strongest first, that is safe to put in a JSON string and on a web
 * page: so hidden and duplicate entries are dropped, and an SSID that is not well formed UTF-8 or contains a control character
 * is left out of the list (the user can still type it). */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { SCAN_LIST_MAX = 16, SCAN_SSID_MAX = 32 };
typedef struct { char ssid[SCAN_SSID_MAX + 1]; int8_t rssi; bool secure; } scan_entry;
typedef struct { unsigned count; scan_entry entry[SCAN_LIST_MAX]; } scan_list;

/* Strict UTF-8 (no overlong forms, no surrogates, nothing above U+10FFFF) with no control characters (below 0x20, or 0x7f). */
bool scan_ssid_text_safe(const uint8_t *ssid, size_t length);
void scan_list_init(scan_list *list);
/* Offer one record. ssid is the driver's 32 byte field (NUL terminated only when shorter than 32). Records may arrive in any order:
 * the list keeps the SCAN_LIST_MAX strongest distinct networks, sorted strongest first, and an SSID heard again keeps its strongest
 * signal (and is secure if any of its access points is). */
void scan_list_offer(scan_list *list, const uint8_t ssid[32], int rssi, bool secure);
