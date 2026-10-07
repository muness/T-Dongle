// SPDX-License-Identifier: MIT
/* Golden-fixture generator for tdongle-nvs-format.
 *
 * Includes the REAL firmware sources (main/wifi_meta.c, main/ui_settings.c, main/legacy_import.c, main/core.c, main/profile_json.c) and dumps
 * the exact bytes the C firmware stores in NVS, plus canonical dumps of what the C decoders return for them. The Rust tests include these
 * files and assert (a) decode(golden) == what C decoded and (b) encode(decode(golden)) == golden byte for byte.
 *
 * Build and run: see regen.sh (it passes the repo root, the output directory and ESP-IDF's cJSON directory). The only function that cannot
 * be compiled from the repo is wifi_load_profiles() (alternative/tailnet/main/wifi_profiles.inc is glued to ESP-IDF statics); its logic is
 * transcribed below as c_load_profiles(), line for line, with the NVS reads replaced by byte buffers.
 *
 * Canonical dumps (little endian, fixed size, no struct padding, so they do not depend on the host ABI):
 *   meta result   : i32 preferred, 8 x { char name[25]; u8 priority }                                   = 4 + 8*26   = 212 bytes
 *   import result : u32 count, i32 preferred, u8 display_valid, u8 brightness, u8 rotation, u8 pad0,
 *                   u16 dim_seconds, u16 pad0, 8 x { char ssid[33]; char password[64]; char name[25]; u8 priority } = 16 + 8*123 = 1000 bytes
 *   load result   : u8 status (0 ok, 1 refused), then if ok: u32 count, 8 x { char ssid[33]; char password[64] } (zero beyond count),
 *                   then the meta result                                                                 = 1 + 4 + 776 + 212 = 993 bytes
 *   json record   : u16 length, bytes, u8 ok, u8 slot (0-based), then 124 bytes of profile_t when ok
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wifi_meta.c"
#include "ui_settings.c"
#include "legacy_import.c"
#include "core.c"
#include "profile_json.c"

/* Host layout must equal the xtensa layout derived by hand: every one of these is natural alignment with 4-byte maximum alignment. */
_Static_assert(sizeof(wifi_meta_blob) == 516, "wifi_meta_blob");
_Static_assert(offsetof(wifi_meta_blob, preferred_ssid) == 8, "wifi_meta_blob.preferred_ssid");
_Static_assert(offsetof(wifi_meta_blob, entry) == 41, "wifi_meta_blob.entry");
_Static_assert(sizeof(ui_settings_blob) == 8 && offsetof(ui_settings_blob, dim_seconds) == 6, "ui_settings_blob");
_Static_assert(sizeof(settings_t) == 1004 && sizeof(profile_t) == 124 && offsetof(settings_t, p) == 4 && offsetof(settings_t, preferred) == 996 &&
               offsetof(settings_t, brightness) == 997 && offsetof(settings_t, rotation) == 998 && offsetof(settings_t, dim_seconds) == 1000, "settings_t");
/* alternative/tailnet/main/wifi_profiles.inc, verbatim. */
typedef struct { char ssid[33], password[64]; } wifi_profile;
typedef struct { uint32_t schema, count; wifi_profile profiles[8]; } wifi_profiles_blob;
_Static_assert(sizeof(wifi_profile) == 97 && offsetof(wifi_profile, password) == 33 && sizeof(wifi_profiles_blob) == 784, "wifi_profiles_blob");

static const char *outdir;
static void put(const char *name, const void *data, size_t n) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", outdir, name);
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(data, 1, n, f) != n) { perror(path); exit(1); }
    fclose(f);
}

/* ---------- canonical dumps ---------- */
static size_t dump_meta(unsigned char *out, const wifi_meta_set *s) {
    unsigned char *p = out;
    int32_t pref = s->preferred;
    memcpy(p, &pref, 4); p += 4;
    for (unsigned i = 0; i < 8; i++) { memcpy(p, s->slot[i].name, 25); p += 25; *p++ = s->slot[i].priority; }
    return (size_t)(p - out);
}
static size_t dump_import(unsigned char *out, const legacy_import *in) {
    unsigned char *p = out;
    uint32_t count = in->count; int32_t pref = in->preferred;
    memset(out, 0, 1000);
    memcpy(p, &count, 4); p += 4;
    memcpy(p, &pref, 4); p += 4;
    *p++ = in->display_valid; *p++ = in->display_valid ? in->display.brightness : 0; *p++ = in->display_valid ? in->display.rotation : 0; *p++ = 0;
    uint16_t dim = in->display_valid ? in->display.dim_seconds : 0;
    memcpy(p, &dim, 2); p += 4;
    for (unsigned i = 0; i < 8; i++, p += 123) {
        if (i >= in->count) continue;
        memcpy(p, in->net[i].ssid, 33); memcpy(p + 33, in->net[i].password, 64); memcpy(p + 97, in->net[i].meta.name, 25); p[122] = in->net[i].meta.priority;
    }
    return 1000;
}

/* ---------- builders ---------- */
static const char *const SSIDS[8] = {"Home", "Phone", "Office", "Cafe", "Car", "Hotel", "Lab", "Shed"};
static void set_slot(settings_t *s, unsigned slot, const char *name, const char *ssid, const char *pass, unsigned priority) {
    strcpy(s->p[slot].name, name); strcpy(s->p[slot].ssid, ssid); strcpy(s->p[slot].pass, pass); s->p[slot].priority = (uint8_t)priority;
}
static settings_t blank(void) {
    settings_t s; memset(&s, 0, sizeof s); s.version = CFG_VERSION; s.brightness = 60; s.dim_seconds = 60; return s;
}
static void meta_file(const char *name, const char *const ssids[], unsigned count, const wifi_meta_set *set) {
    wifi_meta_blob b; wifi_meta_encode(&b, ssids, count, set); put(name, &b, sizeof b);
}
static void meta_result(const char *name, const void *blob, size_t length, const char *const ssids[], unsigned count) {
    wifi_meta_set s; unsigned char out[212];
    wifi_meta_defaults(&s, ssids, count);
    if (!wifi_meta_overlay(blob, length, ssids, count, &s)) { fprintf(stderr, "%s: overlay refused\n", name); exit(1); }
    dump_meta(out, &s); put(name, out, 212);
}
static void import_file(const char *base, const settings_t *s) {
    char n[128]; legacy_import in; unsigned char out[1000];
    snprintf(n, sizeof n, "%s.bin", base); put(n, s, sizeof *s);
    if (legacy_import_decode(s, sizeof *s, &in)) { dump_import(out, &in); snprintf(n, sizeof n, "%s.import.bin", base); put(n, out, sizeof out); }
}
static wifi_profiles_blob profiles_blank(void) { wifi_profiles_blob b; memset(&b, 0, sizeof b); b.schema = 1; return b; }
static void profile_set(wifi_profiles_blob *b, unsigned i, const char *ssid, const char *pass) {
    strcpy(b->profiles[i].ssid, ssid); strcpy(b->profiles[i].password, pass); if (i >= b->count) b->count = i + 1;
}

/* ---------- wifi_load_profiles(), transcribed from alternative/tailnet/main/wifi_profiles.inc ---------- */
typedef struct { uint32_t schema, count; wifi_profile profiles[8]; } saved_t;   /* "wifi_saved" */
typedef struct { const void *data; size_t len; } buf_t;                        /* NULL data == key not found */
static saved_t wifi_saved;
static wifi_meta_set wifi_meta;
static void wifi_ssid_list(const char *ssids[8]) { for (unsigned i = 0; i < 8; i++) ssids[i] = i < wifi_saved.count ? wifi_saved.profiles[i].ssid : ""; }
static bool read_legacy(buf_t legacy, legacy_import *out) { return legacy.data && legacy_import_decode(legacy.data, legacy.len, out); }
static void wifi_apply_legacy_meta(const legacy_import *legacy) {
    for (unsigned i = 0; i < wifi_saved.count; i++) for (unsigned j = 0; j < legacy->count; j++)
        if (!strcmp(wifi_saved.profiles[i].ssid, legacy->net[j].ssid)) { wifi_meta.slot[i] = legacy->net[j].meta; break; }
    if (legacy->preferred >= 0) for (unsigned i = 0; i < wifi_saved.count; i++)
        if (!strcmp(wifi_saved.profiles[i].ssid, legacy->net[legacy->preferred].ssid)) wifi_meta.preferred = (int)i;
}
static void overlay_stored(buf_t meta, const char *const ssids[]) {
    if (meta.data) wifi_meta_overlay(meta.data, meta.len, ssids, wifi_saved.count, &wifi_meta);
}
/* Returns ok. `older` is wifi_config.sta.ssid[32] / password[64] (all zero when there is none). */
static bool c_load_profiles(buf_t profiles, buf_t meta, buf_t legacy_buf, const unsigned char older_ssid[32], const unsigned char older_pass[64]) {
    legacy_import legacy; bool have_legacy = read_legacy(legacy_buf, &legacy);
    const char *ssids[8]; bool ok = true;
    if (!profiles.data) {   /* ESP_ERR_NVS_NOT_FOUND */
        memset(&wifi_saved, 0, sizeof wifi_saved); wifi_saved.schema = 1;
        if (older_ssid[0]) { wifi_saved.count = 1; memcpy(wifi_saved.profiles[0].ssid, older_ssid, 32); memcpy(wifi_saved.profiles[0].password, older_pass, 63); }
        if (have_legacy) for (unsigned i = 0; i < legacy.count && wifi_saved.count < 8; i++) {
            bool duplicate = false; for (unsigned j = 0; j < wifi_saved.count; j++) if (!strcmp(wifi_saved.profiles[j].ssid, legacy.net[i].ssid)) duplicate = true;
            if (!duplicate) { wifi_profile *p = &wifi_saved.profiles[wifi_saved.count++]; snprintf(p->ssid, 33, "%s", legacy.net[i].ssid); snprintf(p->password, 64, "%s", legacy.net[i].password); }
        }
        wifi_ssid_list(ssids); wifi_meta_defaults(&wifi_meta, ssids, wifi_saved.count);
        if (have_legacy) wifi_apply_legacy_meta(&legacy);
        overlay_stored(meta, ssids);
    } else {
        size_t n = profiles.len; memset(&wifi_saved, 0, sizeof wifi_saved); memcpy(&wifi_saved, profiles.data, n < sizeof wifi_saved ? n : sizeof wifi_saved);
        if (n != sizeof(wifi_saved) || wifi_saved.schema != 1 || wifi_saved.count > 8) ok = false;
        for (unsigned i = 0; ok && i < wifi_saved.count; i++) if (!wifi_saved.profiles[i].ssid[0] || wifi_saved.profiles[i].ssid[32] || wifi_saved.profiles[i].password[63]) ok = false;
        if (ok) {
            wifi_ssid_list(ssids); wifi_meta_defaults(&wifi_meta, ssids, wifi_saved.count);
            if (have_legacy) wifi_apply_legacy_meta(&legacy);
            overlay_stored(meta, ssids);
        }
    }
    return ok;
}
static void load_case(const char *name, buf_t profiles, buf_t meta, buf_t legacy, const char *older_ssid, const char *older_pass) {
    unsigned char os[32] = {0}, op[64] = {0}, out[993]; char fn[128];
    if (older_ssid) { memcpy(os, older_ssid, strlen(older_ssid)); memcpy(op, older_pass, strlen(older_pass)); }
    memset(out, 0, sizeof out);
    if (!c_load_profiles(profiles, meta, legacy, os, op)) { out[0] = 1; }
    else {
        unsigned char *p = out + 1; uint32_t count = wifi_saved.count; memcpy(p, &count, 4); p += 4;
        for (unsigned i = 0; i < count; i++) { memcpy(p + i * 97, wifi_saved.profiles[i].ssid, 33); memcpy(p + i * 97 + 33, wifi_saved.profiles[i].password, 64); }
        p += 8 * 97; dump_meta(p, &wifi_meta);
    }
    snprintf(fn, sizeof fn, "load_%s.bin", name); put(fn, out, sizeof out);
}
static buf_t slurp(const char *name) {
    char path[1024]; snprintf(path, sizeof path, "%s/%s", outdir, name);
    FILE *f = fopen(path, "rb"); if (!f) { perror(path); exit(1); }
    unsigned char *d = malloc(4096); size_t n = fread(d, 1, 4096, f); fclose(f);
    return (buf_t){d, n};
}
#define NONE ((buf_t){NULL, 0})

/* ---------- JSON corpus ---------- */
static uint32_t rng_state = 0x9e3779b9u;
static uint32_t rnd(void) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 17; rng_state ^= rng_state << 5; return rng_state; }
static FILE *json_out; static unsigned json_cases;
static void json_case(const char *text) {
    size_t n = strlen(text); profile_t p; int slot = -1;
    bool ok = profile_parse_json(text, &slot, &p);
    uint16_t len = (uint16_t)n; unsigned char okb = ok, sl = ok ? (unsigned char)slot : 0;
    fwrite(&len, 2, 1, json_out); fwrite(text, 1, n, json_out); fwrite(&okb, 1, 1, json_out); fwrite(&sl, 1, 1, json_out);
    if (ok) fwrite(&p, sizeof p, 1, json_out);
    json_cases++;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: gen_golden OUTDIR\n"); return 2; }
    outdir = argv[1];
    printf("host sizes: wifi_meta_blob=%zu ui_settings_blob=%zu settings_t=%zu profile_t=%zu wifi_profile=%zu wifi_profiles_blob=%zu (xtensa, derived by hand: 516 8 1004 124 97 784)\n",
           sizeof(wifi_meta_blob), sizeof(ui_settings_blob), sizeof(settings_t), sizeof(profile_t), sizeof(wifi_profile), sizeof(wifi_profiles_blob));
    printf("offsets: meta.preferred_ssid=%zu meta.entry=%zu entry.stride=%zu settings.p=%zu settings.preferred=%zu settings.dim=%zu profile.ssid=%zu profile.pass=%zu profile.priority=%zu\n",
           offsetof(wifi_meta_blob, preferred_ssid), offsetof(wifi_meta_blob, entry), sizeof(((wifi_meta_blob *)0)->entry[0]), offsetof(settings_t, p),
           offsetof(settings_t, preferred), offsetof(settings_t, dim_seconds), offsetof(profile_t, ssid), offsetof(profile_t, pass), offsetof(profile_t, priority));

    /* ===== wifi_meta ===== */
    wifi_meta_set s;
    wifi_meta_defaults(&s, SSIDS, 0); meta_file("meta_empty.bin", SSIDS, 0, &s);
    wifi_meta_defaults(&s, SSIDS, 1); strcpy(s.slot[0].name, "Home sweet"); s.slot[0].priority = 70; s.preferred = 0; meta_file("meta_one.bin", SSIDS, 1, &s);
    {
        static const char *const eight[8] = {"Home", "Phone", "Office", "Cafe", "Car", "Hotel", "Lab", "Shed"};
        static const char *const names[8] = {"Home", "Phone hotspot", "Office (5 GHz)", "123456789012345678901234", "Car", "a", "Lab bench", "Shed"};
        static const uint8_t prio[8] = {50, 90, 100, 0, 10, 50, 77, 1};
        wifi_meta_defaults(&s, eight, 8);
        for (unsigned i = 0; i < 8; i++) { memset(s.slot[i].name, 0, 25); strcpy(s.slot[i].name, names[i]); s.slot[i].priority = prio[i]; }
        s.preferred = 5; meta_file("meta_eight.bin", eight, 8, &s);
        s.preferred = -1; meta_file("meta_eight_nopref.bin", eight, 8, &s);
    }
    {   /* 32 character SSIDs (the longest an SSID can be) and a name the SSID cannot supply */
        const char *longs[2] = {"abcdefghijklmnopqrstuvwxyz012345", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"};
        wifi_meta_defaults(&s, longs, 2); s.preferred = 1; meta_file("meta_long_ssid.bin", longs, 2, &s);
    }
    {   /* an invalid stored name only costs that network its name; a priority above 100 is refused outright */
        wifi_meta_blob b; wifi_meta_defaults(&s, SSIDS, 2); wifi_meta_encode(&b, SSIDS, 2, &s);
        strcpy(b.entry[0].name, "bad\tname"); b.entry[0].priority = 77; put("meta_badname.bin", &b, sizeof b);
        wifi_meta_encode(&b, SSIDS, 2, &s); b.schema = 2; put("meta_bad_schema.bin", &b, sizeof b);
        wifi_meta_encode(&b, SSIDS, 2, &s); b.count = 9; put("meta_bad_count.bin", &b, sizeof b);
        wifi_meta_encode(&b, SSIDS, 2, &s); b.entry[0].priority = 101; put("meta_bad_priority.bin", &b, sizeof b);
        wifi_meta_encode(&b, SSIDS, 2, &s); memset(b.entry[1].name, 'x', 25); put("meta_name_unterminated.bin", &b, sizeof b);
        wifi_meta_encode(&b, SSIDS, 2, &s); memset(b.entry[1].ssid, 'x', 33); put("meta_ssid_unterminated.bin", &b, sizeof b);
        wifi_meta_encode(&b, SSIDS, 2, &s); memset(b.preferred_ssid, 'x', 33); put("meta_preferred_unterminated.bin", &b, sizeof b);
        /* garbage in entries at or beyond `count` is never looked at, and bytes after a terminator are ignored: this blob is valid */
        wifi_meta_encode(&b, SSIDS, 2, &s); memset(&b.entry[5], 0xAA, sizeof b.entry[5]); memset(b.entry[0].name + 6, 0x55, 18); b.entry[0].priority = 20;
        put("meta_garbage_tail.bin", &b, sizeof b);
        wifi_meta_encode(&b, SSIDS, 2, &s); b.entry[0].priority = 255; put("meta_priority_255.bin", &b, sizeof b);
    }
    {   /* overlay results: the same list; an edited list (the blob is keyed by SSID, not slot); the blob over a longer list */
        static const char *const edited[4] = {"Shed", "Newcomer", "Home", "Lab"};
        buf_t b8 = slurp("meta_eight.bin"), b1 = slurp("meta_one.bin"), be = slurp("meta_empty.bin"), bn = slurp("meta_badname.bin"), bg = slurp("meta_garbage_tail.bin");
        buf_t bl = slurp("meta_long_ssid.bin");
        static const char *const longs[2] = {"abcdefghijklmnopqrstuvwxyz012345", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"};
        meta_result("meta_eight.same.result.bin", b8.data, b8.len, SSIDS, 8);
        meta_result("meta_eight.edited.result.bin", b8.data, b8.len, edited, 4);
        meta_result("meta_eight.two.result.bin", b8.data, b8.len, SSIDS, 2);
        meta_result("meta_one.same.result.bin", b1.data, b1.len, SSIDS, 1);
        meta_result("meta_one.three.result.bin", b1.data, b1.len, SSIDS, 3);
        meta_result("meta_empty.three.result.bin", be.data, be.len, SSIDS, 3);
        meta_result("meta_badname.same.result.bin", bn.data, bn.len, SSIDS, 2);
        meta_result("meta_garbage_tail.same.result.bin", bg.data, bg.len, SSIDS, 2);
        meta_result("meta_long_ssid.same.result.bin", bl.data, bl.len, longs, 2);
    }

    /* ===== display ===== */
    {
        ui_settings d; ui_settings_blob b;
        ui_settings_defaults(&d); ui_settings_encode(&d, &b); put("display_default.bin", &b, sizeof b);
        d = (ui_settings){33, 1, 900}; ui_settings_encode(&d, &b); put("display_custom.bin", &b, sizeof b);
        d = (ui_settings){100, 0, 3600}; ui_settings_encode(&d, &b); put("display_max.bin", &b, sizeof b);
        d = (ui_settings){5, 1, 10}; ui_settings_encode(&d, &b); put("display_min.bin", &b, sizeof b);
        d = (ui_settings){60, 0, 60}; ui_settings_encode(&d, &b); b.schema = 2; put("display_bad_schema.bin", &b, sizeof b);
        ui_settings_encode(&d, &b); b.brightness = 4; put("display_bad_brightness.bin", &b, sizeof b);
        ui_settings_encode(&d, &b); b.rotation = 2; put("display_bad_rotation.bin", &b, sizeof b);
        ui_settings_encode(&d, &b); b.dim_seconds = 9; put("display_bad_dim.bin", &b, sizeof b);
    }

    /* ===== legacy adapter/config ===== */
    {
        settings_t s1 = blank();
        import_file("legacy_empty", &s1);
        set_slot(&s1, 0, "Home", "HomeNet", "correct-horse", 50); set_slot(&s1, 1, "Phone", "Pixel hotspot", "", 90); set_slot(&s1, 4, "Car", "CarWifi", "12345678", 10);
        s1.preferred = 4; s1.brightness = 85; s1.rotation = 1; s1.dim_seconds = 300; import_file("legacy_carried", &s1);

        settings_t one = blank(); set_slot(&one, 0, "Home", "HomeNet", "pass1234", 50); import_file("legacy_one", &one);

        settings_t e = blank(); char nm[16];
        for (unsigned i = 0; i < 8; i++) { snprintf(nm, sizeof nm, "net%u", i); set_slot(&e, i, nm, nm, "password", 10 + i); }
        e.preferred = 7; import_file("legacy_eight", &e);

        settings_t m = blank();
        set_slot(&m, 0, "A", "same", "aaaaaaaa", 20);
        set_slot(&m, 1, "bad\tname", "net1", "password", 200);        /* bad name and priority: kept with the fallbacks */
        set_slot(&m, 2, "C", "same", "cccccccc", 99);                 /* duplicate SSID: skipped, and preferred (2) follows slot 0 */
        set_slot(&m, 3, "", "net3", "short", 50);                     /* empty name; a short password is still imported */
        set_slot(&m, 4, "x", "net4", "password", 50); memset(m.p[4].name, 'n', 25);   /* unterminated name */
        set_slot(&m, 5, "long", "net5", "password", 50); memset(m.p[5].pass, 'p', 64); m.p[5].pass[64] = 0;   /* 64 character password: slot skipped */
        set_slot(&m, 6, "Bad", "bad", "x", 50); memset(m.p[6].ssid, 'x', 33);           /* unterminated SSID: skipped */
        /* slot 7 is empty */
        m.preferred = 2; m.brightness = 3; m.rotation = 7; m.dim_seconds = 5; import_file("legacy_messy", &m);

        settings_t g = m; g.preferred = 6; import_file("legacy_preferred_skipped", &g);          /* preferred points at a slot that was not imported */
        g = m; g.preferred = 200; import_file("legacy_preferred_out_of_range", &g);
        g = e; g.preferred = 0; g.brightness = 100; g.rotation = 1; g.dim_seconds = 3600; import_file("legacy_display_max", &g);
        g = e; g.version = 2; import_file("legacy_bad_version", &g);   /* no .import.bin: refused */
        /* the "in-between build" pair: same networks, different order */
        settings_t ib = blank(); set_slot(&ib, 0, "Home", "HomeNet", "pass1234", 30); set_slot(&ib, 1, "Work", "WorkNet", "pass5678", 80); ib.preferred = 1; import_file("legacy_inbetween", &ib);
    }

    /* ===== wifi_profiles ===== */
    {
        wifi_profiles_blob b = profiles_blank(); put("profiles_empty.bin", &b, sizeof b);
        profile_set(&b, 0, "HomeNet", "pass1234"); put("profiles_one.bin", &b, sizeof b);
        b = profiles_blank(); char a[34], pw[65];
        for (unsigned i = 0; i < 8; i++) { snprintf(a, sizeof a, "network%u", i); snprintf(pw, sizeof pw, "key-%u", i); profile_set(&b, i, a, i == 3 ? "" : pw); }
        put("profiles_eight.bin", &b, sizeof b);
        b = profiles_blank();   /* widest: 32 character SSID, 62 character password (63 is the last byte, which must stay 0) */
        { char w[63]; memset(w, 'p', 62); w[62] = 0; profile_set(&b, 0, "abcdefghijklmnopqrstuvwxyz012345", w); }
        put("profiles_widest.bin", &b, sizeof b);
        b = profiles_blank(); profile_set(&b, 0, "WorkNet", "pass5678"); profile_set(&b, 1, "HomeNet", "pass1234"); put("profiles_inbetween.bin", &b, sizeof b);
        b = profiles_blank(); profile_set(&b, 0, "HomeNet", "pass1234"); memset(&b.profiles[3], 0xA5, sizeof b.profiles[3]); memset(b.profiles[0].ssid + 8, 0x77, 20);
        put("profiles_garbage_tail.bin", &b, sizeof b);   /* valid: unused entries and bytes after a terminator are not looked at */
        b = profiles_blank(); profile_set(&b, 0, "HomeNet", "pass1234"); b.schema = 2; put("profiles_bad_schema.bin", &b, sizeof b);
        b = profiles_blank(); profile_set(&b, 0, "HomeNet", "pass1234"); b.count = 9; put("profiles_bad_count.bin", &b, sizeof b);
        b = profiles_blank(); profile_set(&b, 0, "HomeNet", "pass1234"); memset(b.profiles[0].ssid, 'x', 33); put("profiles_ssid_unterminated.bin", &b, sizeof b);
        b = profiles_blank(); profile_set(&b, 0, "HomeNet", "pass1234"); memset(b.profiles[0].password, 'x', 64); put("profiles_password_unterminated.bin", &b, sizeof b);
        b = profiles_blank(); profile_set(&b, 0, "HomeNet", "pass1234"); profile_set(&b, 1, "", "pass"); put("profiles_empty_ssid.bin", &b, sizeof b);
    }

    /* ===== load cases (Rust tests/golden.rs holds the same table) ===== */
    {
        buf_t p_eight = slurp("profiles_eight.bin"), p_one = slurp("profiles_one.bin"), p_ib = slurp("profiles_inbetween.bin"), p_garb = slurp("profiles_garbage_tail.bin");
        buf_t p_bs = slurp("profiles_bad_schema.bin"), p_bc = slurp("profiles_bad_count.bin"), p_su = slurp("profiles_ssid_unterminated.bin");
        buf_t p_pu = slurp("profiles_password_unterminated.bin"), p_es = slurp("profiles_empty_ssid.bin"), p_empty = slurp("profiles_empty.bin"), p_wide = slurp("profiles_widest.bin");
        buf_t l_carried = slurp("legacy_carried.bin"), l_eight = slurp("legacy_eight.bin"), l_messy = slurp("legacy_messy.bin"), l_ib = slurp("legacy_inbetween.bin");
        buf_t l_empty = slurp("legacy_empty.bin"), l_badver = slurp("legacy_bad_version.bin"), l_one = slurp("legacy_one.bin");
        buf_t m_eight = slurp("meta_eight.bin"), m_one = slurp("meta_one.bin"), m_bad = slurp("meta_bad_schema.bin"), m_empty = slurp("meta_empty.bin");
        load_case("fresh_nothing", NONE, NONE, NONE, NULL, NULL);
        load_case("fresh_older", NONE, NONE, NONE, "legacy", "secret");
        load_case("fresh_legacy_carried", NONE, NONE, l_carried, NULL, NULL);
        load_case("fresh_legacy_messy", NONE, NONE, l_messy, NULL, NULL);
        load_case("fresh_legacy_empty", NONE, NONE, l_empty, NULL, NULL);
        load_case("fresh_older_and_legacy_eight", NONE, NONE, l_eight, "net3", "oldpass1");
        load_case("fresh_legacy_stored_meta", NONE, m_eight, l_eight, NULL, NULL);
        load_case("fresh_stored_meta_names_none", NONE, m_empty, l_carried, NULL, NULL);
        load_case("fresh_stored_meta_over_older", NONE, m_one, NONE, "Home", "pw");
        load_case("fresh_invalid_meta_ignored", NONE, m_bad, l_one, NULL, NULL);
        load_case("fresh_invalid_legacy_ignored", NONE, NONE, l_badver, "legacy", "secret");
        load_case("existing_eight", p_eight, NONE, NONE, NULL, NULL);
        load_case("existing_eight_with_meta", p_eight, m_eight, NONE, NULL, NULL);
        load_case("existing_ignores_older", p_one, NONE, NONE, "other", "pw");
        load_case("existing_legacy_by_ssid", p_ib, NONE, l_ib, NULL, NULL);
        load_case("existing_legacy_then_meta", p_ib, m_one, l_ib, NULL, NULL);
        load_case("existing_garbage_tail", p_garb, NONE, NONE, NULL, NULL);
        load_case("existing_widest", p_wide, NONE, NONE, NULL, NULL);
        load_case("existing_empty_list", p_empty, m_eight, l_carried, NULL, NULL);
        load_case("existing_bad_schema", p_bs, NONE, NONE, NULL, NULL);
        load_case("existing_bad_count", p_bc, NONE, NONE, NULL, NULL);
        load_case("existing_ssid_unterminated", p_su, NONE, NONE, NULL, NULL);
        load_case("existing_password_unterminated", p_pu, NONE, NONE, NULL, NULL);
        load_case("existing_empty_ssid", p_es, NONE, NONE, NULL, NULL);
        load_case("existing_wrong_length", (buf_t){p_one.data, p_one.len - 1}, NONE, NONE, NULL, NULL);
        load_case("existing_empty_blob", (buf_t){p_one.data, 0}, NONE, NONE, NULL, NULL);
    }

    /* ===== profile_parse_json corpus ===== */
    {
        char path[1024]; snprintf(path, sizeof path, "%s/json_corpus.bin", outdir);
        json_out = fopen(path, "wb"); if (!json_out) { perror(path); return 1; }
        static const char *const fixed[] = {
            "{\"slot\":8,\"priority\":100,\"name\":\"Home\",\"ssid\":\"Network\",\"password\":\"12345678\"}",
            "{\"slot\":1,\"priority\":0,\"name\":\"a\",\"ssid\":\"s\",\"password\":\"\"}",
            "", "{}", "[]", "null", "{", "{\"slot\":1}",
            "{\"slot\":1,\"slot\":2,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\\u0000hidden\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"short\"}",
            "{\"slot\":1.5,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\",\"extra\":0}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\\n\",\"password\":\"\"}",
            /* numbers: cJSON takes strtod's prefix */
            "{\"slot\":1.0,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1e0,\"priority\":1E0,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":0.8e1,\"priority\":1000e-1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":+1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":01,\"priority\":001,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1.,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":-0,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":-.0,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":-0.0e5,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1.00000000000000000000001,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":100.0000000000000001,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":101,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":0,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":9,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1e999,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":-1e999,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1e,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1-2,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":0x1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1e+0,\"priority\":2e-0,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":\"1\",\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":true,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":1,\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":null,\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":2147483648,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":4294967297,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            /* whitespace, BOM, trailing */
            " \t\r\n{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"} \t\r\n",
            "\x01\x02{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}\x1f ",
            "\xEF\xBB\xBF{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "\xEF\xBB\xBF",
            "\xEF\xBB{\"slot\":1}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"} trailing",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\",}",
            "{,\"slot\":1}",
            "{ \"slot\" : 1 , \"priority\" : 1 , \"name\" : \"x\" , \"ssid\" : \"x\" , \"password\" : \"\" }",
            "{\"slot\"\t:\t1,\"priority\"\n:1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1 \"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{slot:1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{'slot':1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            /* strings and escapes */
            "{\"slot\":1,\"priority\":1,\"name\":\"a\\\"b\",\"ssid\":\"x\\\\y\",\"password\":\"p\\/q\\/r\\/s\\/t\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"a\\tb\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"a\\bb\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"a\\qb\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"a\\\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"a\\",
            "{\"slot\":1,\"priority\":1,\"name\":\"abc",
            "{\"slot\":1,\"priority\":1,\"name\":\"a\tb\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"caf\xc3\xa9\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"a\x7f\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"a b~\",\"ssid\":\" !\\\"#$%&'()*+,-./\",\"password\":\"        \"}",
            "{\"s\\/ot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"Slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot \":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"password\":\"\",\"ssid\":\"x\",\"name\":\"x\",\"priority\":7,\"slot\":3}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\",\"slot\":1}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":{}}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":[]}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"\",\"ssid\":\"x\",\"password\":\"\"}",
            "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"\",\"password\":\"\"}",
            "\"{}\"", "1", "-", "-1", "\"", "{\"", "{\"a", "{\"a\"", "{\"a\":", "{\"a\":1", "{\"a\":1,", "{\"a\":}",
        };
        for (unsigned i = 0; i < sizeof fixed / sizeof *fixed; i++) json_case(fixed[i]);
        /* length and field-width limits */
        char buf[700], name[40], ssid[40], pass[80];
        static const unsigned nl[] = {23, 24, 25}, sl_[] = {31, 32, 33}, pl[] = {0, 7, 8, 62, 63, 64};
        for (unsigned a = 0; a < 3; a++) for (unsigned b = 0; b < 3; b++) for (unsigned c = 0; c < 6; c++) {
            memset(name, 'n', nl[a]); name[nl[a]] = 0; memset(ssid, 's', sl_[b]); ssid[sl_[b]] = 0; memset(pass, 'p', pl[c]); pass[pl[c]] = 0;
            snprintf(buf, sizeof buf, "{\"slot\":5,\"priority\":9,\"name\":\"%s\",\"ssid\":\"%s\",\"password\":\"%s\"}", name, ssid, pass);
            json_case(buf);
        }
        { /* 500 and 501 characters */
            char big[600]; size_t base = strlen("{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}");
            for (unsigned extra = 495; extra <= 502; extra++) {
                snprintf(big, sizeof big, "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":\"x\",\"password\":\"\"}"); size_t n = base;
                memset(big + n, ' ', extra - n < 600 - n ? extra - n : 0); if (extra > n) n = extra; big[n] = 0; json_case(big);
            }
        }
        /* mutation fuzz of three valid documents; the alphabet is the characters the grammar cares about */
        static const char *const bases[] = {
            "{\"slot\":3,\"priority\":42,\"name\":\"Home\",\"ssid\":\"HomeNet\",\"password\":\"correct-horse\"}",
            "{ \"slot\" : 8 , \"priority\" : 0 , \"name\" : \"A b\" , \"ssid\" : \"open\" , \"password\" : \"\" }",
            "{\"password\":\"p\\\\w\\/d1234\",\"ssid\":\"x\\\"y\",\"name\":\"n\",\"priority\":1e1,\"slot\":1.0}",
        };
        static const char alpha[] = "{}[]\",:\\ \t\n-+.eE0123456789tnfu/xs\x01\x7f\x80\xff";
        for (unsigned k = 0; k < 2400; k++) {
            char m[160]; const char *base = bases[k % 3]; size_t n = strlen(base); memcpy(m, base, n + 1);
            for (unsigned t = 1 + rnd() % 3; t; t--) {
                unsigned op = rnd() % 3, pos = n ? rnd() % n : 0; char c = alpha[rnd() % (sizeof alpha - 1)];
                if (op == 0 && n) m[pos] = c;
                else if (op == 1 && n < 150) { memmove(m + pos + 1, m + pos, n - pos + 1); m[pos] = c; n++; }
                else if (n) { memmove(m + pos, m + pos + 1, n - pos); n--; }
            }
            m[n] = 0; json_case(m);
        }
        fclose(json_out);
        printf("json corpus: %u cases\n", json_cases);
    }
    return 0;
}
