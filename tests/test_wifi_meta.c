// SPDX-License-Identifier: MIT
#include "wifi_meta.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *const ssids[] = {"Home", "Phone", "Office", "Cafe", "Car", "Hotel", "Lab", "Shed"};
static void fill(wifi_meta_set *s, unsigned count) {
    wifi_meta_defaults(s, ssids, count);
}
static void defaults(void) {
    wifi_meta_set s;
    fill(&s, 3);
    assert(s.preferred == -1 && !strcmp(s.slot[0].name, "Home") && s.slot[2].priority == 50 && s.slot[3].name[0] == 0 && s.slot[3].priority == 0);
    wifi_meta_slot slot;
    wifi_meta_slot_default(&slot, "A very long network name that exceeds twenty-four characters");
    assert(strlen(slot.name) == 24 && !strncmp(slot.name, "A very long network name", 24));
    wifi_meta_slot_default(&slot, "caf\xc3\xa9\x01");
    assert(!strcmp(slot.name, "caf???") && wifi_meta_name_valid(slot.name));   /* the name is printable ASCII whatever the SSID bytes are */
    assert(wifi_meta_name_valid("Home") && wifi_meta_name_valid("a") && wifi_meta_name_valid("123456789012345678901234"));
    assert(!wifi_meta_name_valid("") && !wifi_meta_name_valid("1234567890123456789012345") && !wifi_meta_name_valid("tab\there") && !wifi_meta_name_valid("caf\xc3\xa9"));
}
static void round_trip(void) {
    wifi_meta_set s, out;
    fill(&s, 4);
    strcpy(s.slot[1].name, "Phone hotspot"); s.slot[1].priority = 90; s.slot[3].priority = 0; s.preferred = 2;
    wifi_meta_blob b;
    wifi_meta_encode(&b, ssids, 4, &s);
    assert(b.schema == 1 && b.count == 4 && !strcmp(b.preferred_ssid, "Office"));
    assert(wifi_meta_decode(&b, sizeof(b), ssids, 4, &out));
    assert(out.preferred == 2 && !strcmp(out.slot[1].name, "Phone hotspot") && out.slot[1].priority == 90 && out.slot[3].priority == 0 && out.slot[0].priority == 50);
}
static void keyed_by_ssid_not_slot(void) {
    wifi_meta_set s, out;
    fill(&s, 4);
    s.slot[0].priority = 10; s.slot[1].priority = 20; s.slot[2].priority = 30; s.slot[3].priority = 40; s.preferred = 3;
    wifi_meta_blob b;
    wifi_meta_encode(&b, ssids, 4, &s);
    /* The saved list was edited without the metadata (an older firmware, or a crash between the two writes): Home moved to the
     * end, Office was deleted, and a new network appeared. Each survivor keeps ITS priority; the newcomer gets the default. */
    const char *edited[] = {"Phone", "Cafe", "Home", "Newcomer"};
    assert(wifi_meta_decode(&b, sizeof(b), edited, 4, &out));
    assert(out.slot[0].priority == 20 && out.slot[1].priority == 40 && out.slot[2].priority == 10 && out.slot[3].priority == 50 && !strcmp(out.slot[3].name, "Newcomer"));
    assert(out.preferred == 1);   /* Cafe is still preferred, wherever it now sits */
    const char *without[] = {"Phone", "Home"};
    assert(wifi_meta_decode(&b, sizeof(b), without, 2, &out) && out.preferred == -1);   /* the preferred network is gone */
}
static void removal(void) {
    wifi_meta_set s;
    fill(&s, 4);
    for (unsigned i = 0; i < 4; i++) s.slot[i].priority = (uint8_t)(10 * (i + 1));
    s.preferred = 2;
    wifi_meta_remove(&s, 4, 0);   /* before the preferred one: it moves up and stays preferred */
    assert(s.preferred == 1 && s.slot[0].priority == 20 && s.slot[1].priority == 30 && s.slot[2].priority == 40 && s.slot[3].name[0] == 0 && s.slot[3].priority == 0);
    wifi_meta_remove(&s, 3, 2);   /* after it: untouched */
    assert(s.preferred == 1 && s.slot[2].priority == 0);
    wifi_meta_remove(&s, 2, 1);   /* the preferred one: forgotten */
    assert(s.preferred == -1 && s.slot[0].priority == 20 && s.slot[1].priority == 0);
    wifi_meta_set before = s;
    wifi_meta_remove(&s, 1, 1); wifi_meta_remove(&s, 9, 0);   /* out of range: nothing */
    assert(!memcmp(&before, &s, sizeof(s)));
}
static void hostile_blobs(void) {
    wifi_meta_set s, out, keep;
    fill(&s, 2);
    wifi_meta_blob b;
    wifi_meta_encode(&b, ssids, 2, &s);
    fill(&keep, 2); out = keep;
    wifi_meta_blob bad = b; bad.schema = 2;
    assert(!wifi_meta_decode(&bad, sizeof(bad), ssids, 2, &out) && !memcmp(&out, &keep, sizeof(out)));
    bad = b; bad.count = 9; assert(!wifi_meta_decode(&bad, sizeof(bad), ssids, 2, &out));
    bad = b; bad.entry[0].priority = 101; assert(!wifi_meta_decode(&bad, sizeof(bad), ssids, 2, &out));
    bad = b; memset(bad.entry[1].name, 'x', sizeof(bad.entry[1].name)); assert(!wifi_meta_decode(&bad, sizeof(bad), ssids, 2, &out));
    bad = b; memset(bad.entry[1].ssid, 'x', sizeof(bad.entry[1].ssid)); assert(!wifi_meta_decode(&bad, sizeof(bad), ssids, 2, &out));
    bad = b; memset(bad.preferred_ssid, 'x', sizeof(bad.preferred_ssid)); assert(!wifi_meta_decode(&bad, sizeof(bad), ssids, 2, &out));
    assert(!wifi_meta_decode(&b, sizeof(b) - 1, ssids, 2, &out) && !wifi_meta_decode(NULL, sizeof(b), ssids, 2, &out) && !wifi_meta_decode(&b, sizeof(b), ssids, 9, &out));
    /* An invalid stored name only costs that network its name. */
    bad = b; strcpy(bad.entry[0].name, "bad\tname"); bad.entry[0].priority = 77;
    assert(wifi_meta_decode(&bad, sizeof(bad), ssids, 2, &out) && !strcmp(out.slot[0].name, "Home") && out.slot[0].priority == 77);
    /* Uninitialised bytes after the strings never reach the screen. */
    wifi_meta_encode(&b, ssids, 8, &(wifi_meta_set){.preferred = 7});
    assert(b.count == 8 && !strcmp(b.preferred_ssid, "Shed"));
}
int main(void) {
    defaults(); round_trip(); keyed_by_ssid_not_slot(); removal(); hostile_blobs();
    puts("Wi-Fi metadata: defaults, SSID-keyed round trip that survives reordering, removal, hostile blobs");
    return 0;
}
