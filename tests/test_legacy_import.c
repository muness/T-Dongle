// SPDX-License-Identifier: MIT
#include "legacy_import.h"
#include "core.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static settings_t blank(void) {
    settings_t s;
    memset(&s, 0, sizeof(s));
    s.version = CFG_VERSION;
    s.brightness = 60;
    s.dim_seconds = 60;
    return s;
}
static void set(settings_t *s, unsigned slot, const char *name, const char *ssid, const char *pass, unsigned priority) {
    strcpy(s->p[slot].name, name);
    strcpy(s->p[slot].ssid, ssid);
    strcpy(s->p[slot].pass, pass);
    s->p[slot].priority = (uint8_t)priority;
}
/* What a v0.1.1 flash holds is the raw bytes of this struct: if its layout ever moves, upgrading users lose their networks. */
static void layout_is_the_v011_layout(void) {
    assert(sizeof(settings_t) == 1004 && sizeof(profile_t) == 124 && offsetof(settings_t, p) == 4 && offsetof(settings_t, preferred) == 996 &&
           offsetof(settings_t, brightness) == 997 && offsetof(settings_t, rotation) == 998 && offsetof(settings_t, dim_seconds) == 1000);
    assert(offsetof(profile_t, name) == 0 && offsetof(profile_t, ssid) == 25 && offsetof(profile_t, pass) == 58 && offsetof(profile_t, priority) == 123);
}
static void everything_is_carried(void) {
    settings_t s = blank();
    set(&s, 0, "Home", "HomeNet", "correct-horse", 50);
    set(&s, 1, "Phone", "Pixel hotspot", "", 90);   /* an open network */
    set(&s, 4, "Car", "CarWifi", "12345678", 10);   /* gaps before it: slots 3 to 5 were deleted */
    s.preferred = 4; s.brightness = 85; s.rotation = 1; s.dim_seconds = 300;
    legacy_import in;
    assert(legacy_import_decode(&s, sizeof(s), &in));
    assert(in.count == 3 && in.preferred == 2);
    assert(!strcmp(in.net[0].ssid, "HomeNet") && !strcmp(in.net[0].password, "correct-horse") && !strcmp(in.net[0].meta.name, "Home") && in.net[0].meta.priority == 50);
    assert(!strcmp(in.net[1].ssid, "Pixel hotspot") && !in.net[1].password[0] && !strcmp(in.net[1].meta.name, "Phone") && in.net[1].meta.priority == 90);
    assert(!strcmp(in.net[2].ssid, "CarWifi") && !strcmp(in.net[2].meta.name, "Car") && in.net[2].meta.priority == 10);
    assert(in.display_valid && in.display.brightness == 85 && in.display.rotation == 1 && in.display.dim_seconds == 300);
}
static void v011_defaults(void) {
    /* A v0.1.1 install that never touched anything: preferred is slot 0 (the zeroed default), which is how v0.1.1 chose. */
    settings_t s = blank();
    set(&s, 0, "Home", "HomeNet", "pass1234", 50);
    set(&s, 1, "Work", "WorkNet", "pass5678", 50);
    legacy_import in;
    assert(legacy_import_decode(&s, sizeof(s), &in) && in.count == 2 && in.preferred == 0 && in.display.brightness == 60 && in.display.dim_seconds == 60 && !in.display.rotation);
    /* Nothing saved at all. */
    s = blank();
    assert(legacy_import_decode(&s, sizeof(s), &in) && in.count == 0 && in.preferred == -1);
}
static void preferred_follows_the_network(void) {
    settings_t s = blank();
    set(&s, 0, "A", "same", "aaaaaaaa", 20);
    set(&s, 1, "B", "other", "bbbbbbbb", 30);
    set(&s, 2, "C", "same", "cccccccc", 99);   /* the SSID again: the unified store keys by SSID, the first slot stands */
    s.preferred = 2;
    legacy_import in;
    assert(legacy_import_decode(&s, sizeof(s), &in) && in.count == 2 && in.preferred == 0 && !strcmp(in.net[0].password, "aaaaaaaa") && in.net[0].meta.priority == 20);
    s.preferred = 3;   /* an empty slot */
    assert(legacy_import_decode(&s, sizeof(s), &in) && in.preferred == -1);
    s.preferred = 200;   /* out of range */
    assert(legacy_import_decode(&s, sizeof(s), &in) && in.preferred == -1);
    s = blank();
    set(&s, 0, "Bad", "bad", "x", 50);   /* an unusable first slot (password too short is still imported: validity is the old firmware's job) */
    memset(s.p[0].ssid, 'x', sizeof(s.p[0].ssid));   /* but an unterminated SSID is skipped */
    set(&s, 1, "Good", "good", "gggggggg", 50);
    s.preferred = 0;
    assert(legacy_import_decode(&s, sizeof(s), &in) && in.count == 1 && !strcmp(in.net[0].ssid, "good") && in.preferred == -1);
}
static void eight_networks(void) {
    settings_t s = blank();
    char ssid[16];
    for (unsigned i = 0; i < 8; i++) { snprintf(ssid, sizeof(ssid), "net%u", i); set(&s, i, ssid, ssid, "password", 10 + i); }
    s.preferred = 7;
    legacy_import in;
    assert(legacy_import_decode(&s, sizeof(s), &in) && in.count == 8 && in.preferred == 7 && in.net[7].meta.priority == 17 && !strcmp(in.net[7].ssid, "net7"));
}
static void damaged_fields_do_not_cost_the_network(void) {
    settings_t s = blank();
    set(&s, 0, "bad\tname", "net0", "password", 200);   /* control character in the name, priority out of range */
    set(&s, 1, "", "net1", "password", 50);             /* empty name */
    memset(s.p[2].name, 'n', sizeof(s.p[2].name)); set(&s, 2, "x", "net2", "password", 50); memset(s.p[2].name, 'n', sizeof(s.p[2].name));   /* unterminated name */
    set(&s, 3, "long", "net3", "password", 50); memset(s.p[3].pass, 'p', 64); s.p[3].pass[64] = 0;   /* a 64 character password cannot be used */
    s.brightness = 3; s.rotation = 7; s.dim_seconds = 5;
    legacy_import in;
    assert(legacy_import_decode(&s, sizeof(s), &in));
    assert(in.count == 3 && !strcmp(in.net[0].ssid, "net0") && !strcmp(in.net[0].meta.name, "net0") && in.net[0].meta.priority == 50);
    assert(!strcmp(in.net[1].meta.name, "net1") && !strcmp(in.net[2].meta.name, "net2"));
    assert(!in.display_valid);
}
static void not_a_v011_blob(void) {
    settings_t s = blank();
    set(&s, 0, "Home", "HomeNet", "pass1234", 50);
    legacy_import in;
    assert(!legacy_import_decode(&s, sizeof(s) - 1, &in) && !legacy_import_decode(&s, sizeof(s) + 4, &in) && !legacy_import_decode(NULL, sizeof(s), &in));
    s.version = 2;
    assert(!legacy_import_decode(&s, sizeof(s), &in));
}
int main(void) {
    layout_is_the_v011_layout(); everything_is_carried(); v011_defaults(); preferred_follows_the_network(); eight_networks();
    damaged_fields_do_not_cost_the_network(); not_a_v011_blob();
    puts("Legacy import: v0.1.1 layout pinned; names, priorities, preferred slot and display settings carried; damaged fields never cost a network");
    return 0;
}
