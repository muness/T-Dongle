// SPDX-License-Identifier: MIT
#include "scan_list.h"
#include <string.h>

bool scan_ssid_text_safe(const uint8_t *s, size_t n) {
    for (size_t i = 0; i < n;) {
        uint8_t c = s[i];
        if (c < 0x20 || c == 0x7f) return false;
        if (c < 0x80) { i++; continue; }
        unsigned extra;
        uint32_t cp;
        if (c >= 0xc2 && c <= 0xdf) { extra = 1; cp = c & 0x1f; }
        else if (c >= 0xe0 && c <= 0xef) { extra = 2; cp = c & 0x0f; }
        else if (c >= 0xf0 && c <= 0xf4) { extra = 3; cp = c & 0x07; }
        else return false;                                         /* a stray continuation byte, an overlong lead, or beyond U+10FFFF */
        if (i + extra >= n) return false;                          /* truncated sequence */
        for (unsigned k = 1; k <= extra; k++) {
            if ((s[i + k] & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (s[i + k] & 0x3f);
        }
        if ((extra == 2 && cp < 0x800) || (extra == 3 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp <= 0xdfff)) return false;
        i += extra + 1;
    }
    return true;
}
void scan_list_init(scan_list *list) { memset(list, 0, sizeof(*list)); }
void scan_list_offer(scan_list *list, const uint8_t ssid[32], int rssi, bool secure) {
    size_t length = 0;
    while (length < SCAN_SSID_MAX && ssid[length]) length++;
    if (!length || !scan_ssid_text_safe(ssid, length)) return;
    if (rssi > 127) rssi = 127;
    if (rssi < -128) rssi = -128;
    for (unsigned i = 0; i < list->count; i++) {
        if (strlen(list->entry[i].ssid) == length && !memcmp(list->entry[i].ssid, ssid, length)) {
            list->entry[i].secure |= secure;
            if (rssi > list->entry[i].rssi) list->entry[i].rssi = (int8_t)rssi;
            else return;
            /* Louder than it was: bubble it up to its place. */
            for (unsigned j = i; j > 0 && list->entry[j].rssi > list->entry[j - 1].rssi; j--) { scan_entry t = list->entry[j]; list->entry[j] = list->entry[j - 1]; list->entry[j - 1] = t; }
            return;
        }
    }
    unsigned at = list->count;
    if (at == SCAN_LIST_MAX) {
        if (rssi <= list->entry[SCAN_LIST_MAX - 1].rssi) return;      /* weaker than everything kept */
        at = SCAN_LIST_MAX - 1;                                        /* replace the weakest */
    } else list->count++;
    scan_entry e = {.rssi = (int8_t)rssi, .secure = secure};
    memcpy(e.ssid, ssid, length);
    list->entry[at] = e;
    for (unsigned j = at; j > 0 && list->entry[j].rssi > list->entry[j - 1].rssi; j--) { scan_entry t = list->entry[j]; list->entry[j] = list->entry[j - 1]; list->entry[j - 1] = t; }
}
