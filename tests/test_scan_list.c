// SPDX-License-Identifier: MIT
#include "scan_list.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void offer(scan_list *l, const char *ssid, int rssi, bool secure) {
    uint8_t field[32] = {0};
    memcpy(field, ssid, strlen(ssid) > 32 ? 32 : strlen(ssid));
    scan_list_offer(l, field, rssi, secure);
}
static void text_safety(void) {
    assert(scan_ssid_text_safe((const uint8_t *)"HomeNet 5", 9) && scan_ssid_text_safe((const uint8_t *)"caf\xc3\xa9", 5) && scan_ssid_text_safe((const uint8_t *)"\xe6\x97\xa5\xe6\x9c\xac", 6) &&
           scan_ssid_text_safe((const uint8_t *)"\xf0\x9f\x93\xb6 Wi-Fi", 10) && scan_ssid_text_safe((const uint8_t *)"", 0));
    const char *bad[] = {"a\tb", "a\nb", "\x01", "del\x7f", "\x80", "\xc0\x80", "\xc1\xbf", "\xe0\x80\x80", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xc3", "\xe6\x97", "\xf0\x9f\x93",
                         "\xc3\x28", "caf\xe9", "\xff"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) assert(!scan_ssid_text_safe((const uint8_t *)bad[i], strlen(bad[i])));
}
static void dedupe_sort_and_filter(void) {
    scan_list l;
    scan_list_init(&l);
    offer(&l, "Weak", -85, true);
    offer(&l, "Strong", -40, true);
    offer(&l, "Mid", -65, false);
    offer(&l, "", -30, true);                 /* hidden */
    offer(&l, "bad\tname", -20, true);        /* control character */
    offer(&l, "bad\xff", -20, true);          /* not UTF-8 */
    assert(l.count == 3 && !strcmp(l.entry[0].ssid, "Strong") && !strcmp(l.entry[1].ssid, "Mid") && !strcmp(l.entry[2].ssid, "Weak"));
    offer(&l, "Weak", -50, false);            /* another access point of the same network, closer: keeps the best signal, secure if any is */
    assert(l.count == 3 && !strcmp(l.entry[1].ssid, "Weak") && l.entry[1].rssi == -50 && l.entry[1].secure && !strcmp(l.entry[2].ssid, "Mid"));
    offer(&l, "Weak", -90, false);
    assert(l.entry[1].rssi == -50 && l.count == 3);
    offer(&l, "Mid", -65, true); assert(!strcmp(l.entry[2].ssid, "Mid") && l.entry[2].secure);
    offer(&l, "Open", -70, false);
    assert(l.count == 4 && !l.entry[3].secure && !strcmp(l.entry[3].ssid, "Open"));
    for (unsigned i = 1; i < l.count; i++) assert(l.entry[i - 1].rssi >= l.entry[i].rssi);
}
static void a_full_ssid_field(void) {
    scan_list l;
    scan_list_init(&l);
    uint8_t full[32];
    memset(full, 'x', sizeof(full));          /* 32 bytes, no terminator */
    scan_list_offer(&l, full, -50, true);
    assert(l.count == 1 && strlen(l.entry[0].ssid) == 32 && l.entry[0].ssid[32] == 0);
    scan_list_offer(&l, full, -45, true); assert(l.count == 1);
}
static void capacity_keeps_the_strongest(void) {
    scan_list l;
    scan_list_init(&l);
    char name[16];
    for (unsigned i = 0; i < 40; i++) { snprintf(name, sizeof(name), "net%02u", i); offer(&l, name, -100 + (int)i, true); }
    assert(l.count == SCAN_LIST_MAX);
    assert(!strcmp(l.entry[0].ssid, "net39") && l.entry[0].rssi == -61 && !strcmp(l.entry[SCAN_LIST_MAX - 1].ssid, "net24"));
    for (unsigned i = 1; i < l.count; i++) assert(l.entry[i - 1].rssi > l.entry[i].rssi);
    offer(&l, "tooweak", -120, true); assert(l.count == SCAN_LIST_MAX && strcmp(l.entry[SCAN_LIST_MAX - 1].ssid, "tooweak"));
    offer(&l, "newbest", -10, false); assert(!strcmp(l.entry[0].ssid, "newbest") && l.count == SCAN_LIST_MAX);
    scan_list_offer(&l, (const uint8_t *)"x\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 1000, true);   /* absurd rssi is clamped, not wrapped */
    assert(l.entry[0].rssi == 127);
}
int main(void) {
    text_safety(); dedupe_sort_and_filter(); a_full_ssid_field(); capacity_keeps_the_strongest();
    puts("Scan list: strict UTF-8, hidden/duplicate/control SSIDs dropped, strongest-first, best signal kept, capacity bounded");
    return 0;
}
