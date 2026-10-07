/* Golden generator of tdongle-setup: runs the REAL C (captive_dns.c, setup_access.c, setup_boot.c, scan_list.c, cJSON) over corpora and
 * writes the expected results as text lines of hex. Nothing here transcribes a rule: every output line is what the C produced.
 * The JSON builders for the scan list and the saved list repeat the cJSON calls of wifi_scan_async / wifi_saved_list
 * (alternative/tailnet/main/gateway_main.c) in the same order. */
#include "captive_dns.h"
#include "setup_access.h"
#include "setup_boot.h"
#include "scan_list.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (uint32_t)(rng >> 16); }
static void hex(FILE *f, const uint8_t *b, size_t n) { if (!n) { fputc('-', f); return; } for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]); }
static FILE *open_out(const char *dir, const char *name) {
    char path[512]; snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w"); if (!f) { perror(path); exit(1); } return f;
}

/* ---------------------------------------------------------------- DNS */
static size_t make_query(uint8_t *q, const char *name, unsigned type, unsigned klass, unsigned flags) {
    memset(q, 0, 12); q[0] = 0x12; q[1] = 0x34; q[2] = (uint8_t)(flags >> 8); q[3] = (uint8_t)flags; q[5] = 1;
    size_t n = 12; const char *p = name;
    while (*p) { const char *dot = strchr(p, '.'); size_t len = dot ? (size_t)(dot - p) : strlen(p); q[n++] = (uint8_t)len; memcpy(q + n, p, len); n += len; p += len; if (*p == '.') p++; }
    q[n++] = 0; q[n++] = (uint8_t)(type >> 8); q[n++] = (uint8_t)type; q[n++] = (uint8_t)(klass >> 8); q[n++] = (uint8_t)klass;
    return n;
}
static void dns_case(FILE *f, const uint8_t *q, size_t n, size_t cap) {
    static const uint8_t dongle[4] = {192, 168, 4, 1};
    uint8_t out[600]; memset(out, 0xaa, sizeof(out));
    if (cap > sizeof(out)) cap = sizeof(out);
    size_t m = captive_dns_reply(q, n, out, cap, dongle);
    fprintf(f, "%zu ", cap); hex(f, q, n); fputc(' ', f); if (m) hex(f, out, m); else fputc('-', f); fputc('\n', f);
}
static void gen_dns(const char *dir) {
    FILE *f = open_out(dir, "dns.golden");
    const char *names[] = {"captive.apple.com", "connectivitycheck.gstatic.com", "www.msftconnecttest.com", "a", "x.y.z.example.org", "detectportal.firefox.com", "Mixed.CASE.Example", ""};
    unsigned types[] = {1, 28, 65, 255, 15, 5, 0}, classes[] = {1, 3, 255, 0};
    uint8_t q[600];
    for (unsigned a = 0; a < 8; a++) for (unsigned t = 0; t < 7; t++) for (unsigned c = 0; c < 4; c++) {
        size_t n = make_query(q, names[a], types[t], classes[c], 0x0100);
        dns_case(f, q, n, 272); dns_case(f, q, n, n + 15); dns_case(f, q, n, n + 16); dns_case(f, q, n, 0);
    }
    uint8_t base[600]; size_t n = make_query(base, "example.com", 1, 1, 0x0100);
    for (size_t cut = 0; cut <= n + 2; cut++) dns_case(f, base, cut, 272);
    /* every header byte set to every interesting value */
    for (unsigned i = 0; i < 12; i++) for (unsigned v = 0; v < 256; v += (v < 4 || v > 250) ? 1 : 51) { memcpy(q, base, n); q[i] = (uint8_t)v; dns_case(f, q, n, 272); }
    /* label bytes: lengths 0..255 at the first label, compression pointers */
    for (unsigned v = 0; v < 256; v++) { memcpy(q, base, n); q[12] = (uint8_t)v; dns_case(f, q, n, 272); }
    /* trailing data of every size up to the 256 byte recv limit and beyond */
    for (unsigned extra = 0; extra < 300; extra += 7) { memcpy(q, base, n); memset(q + n, 0xee, extra); dns_case(f, q, n + extra, 272); }
    /* random packets, and random mutations of a valid one */
    for (unsigned k = 0; k < 3000; k++) {
        size_t len = rnd() % 80; for (size_t i = 0; i < len; i++) q[i] = (uint8_t)rnd();
        if (k & 1 && len >= 17) { q[2] &= 0x07; q[4] = 0; q[5] = 1; }
        dns_case(f, q, len, 272);
        memcpy(q, base, n); for (unsigned m = rnd() % 4; m; m--) q[rnd() % n] = (uint8_t)rnd(); dns_case(f, q, n, 272);
    }
    fclose(f);
}

/* ---------------------------------------------------------------- access */
static const char *hs[] = {NULL, "192.168.4.1", "192.168.4.1:80", "192.168.77.1", "192.168.77.1:80", "evil.example", "192.168.4.1:8080", "", "captive.apple.com", "192.168.4.10"};
static const char *os[] = {NULL, "http://192.168.4.1", "http://192.168.4.1:80", "http://192.168.77.1", "http://192.168.77.1:80", "http://evil.example", "", "https://192.168.4.1", "null"};
#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
static void str_or_dash(FILE *f, const char *s) { if (!s) fputs("~", f); else if (!*s) fputs("-", f); else hex(f, (const uint8_t *)s, strlen(s)); }
static void gen_access(const char *dir) {
    FILE *f = open_out(dir, "access.golden");
    uint32_t peers[] = {IP(192,168,77,2), IP(192,168,4,2), IP(192,168,4,255), IP(10,0,0,1), IP(192,168,5,1), IP(192,168,78,1), 0, IP(192,168,76,255), IP(192,168,77,0), IP(192,168,4,0)};
    uint32_t locals[] = {IP(192,168,77,1), IP(192,168,4,1), IP(192,168,4,77), 0, IP(192,168,77,2), IP(192,168,4,0)};
    static const unsigned kn[3][2] = {{1, 1}, {0, 1}, {1, 0}}, hsel[] = {0, 1, 3, 4, 5, 6, 9}, osel[] = {0, 1, 4, 5, 6};
    for (unsigned p = 0; p < 10; p++) for (unsigned l = 0; l < 6; l++) for (unsigned kk = 0; kk < 3; kk++) for (unsigned s = 0; s < 2; s++)
    for (unsigned hi = 0; hi < 7; hi++) for (unsigned oi = 0; oi < 5; oi++) {
        unsigned pk = kn[kk][0], lk = kn[kk][1], h = hsel[hi], o = osel[oi];
        access_origin r = access_classify(pk, peers[p], lk, locals[l], s, hs[h], os[o]);
        fprintf(f, "C %u %u %u %u %u ", peers[p], locals[l], pk, lk, s); str_or_dash(f, hs[h]); fputc(' ', f); str_or_dash(f, os[o]); fprintf(f, " %d\n", (int)r);
    }
    for (unsigned p = 0; p < 10; p++) fprintf(f, "S %u %d\n", peers[p], access_in_setup_subnet(peers[p]));
    for (int o = 0; o < 3; o++) {
        for (int e = EP_HOME; e <= EP_BOOT_STATUS; e++) fprintf(f, "E %d %d %d\n", o, e, access_endpoint_allowed((access_origin)o, (access_endpoint)e));
        for (int a = ACTION_MODE; a <= ACTION_UNKNOWN; a++) fprintf(f, "A %d %d %d\n", o, a, access_action_allowed((access_origin)o, (access_action)a));
        fprintf(f, "M %d %d %d\n", o, access_may_set_metadata((access_origin)o), access_may_replace((access_origin)o));
    }
    const char *names[] = {"mode", "wifi", "wifi_remove", "add", "remove", "enable", "setup_done", "", "WIFI", "wifi ", "wifi_remove2", "Mode", "setup"};
    for (unsigned i = 0; i < 13; i++) { fputs("P ", f); str_or_dash(f, names[i]); fprintf(f, " %d\n", (int)access_action_parse(names[i])); }
    fprintf(f, "P ~ %d\n", (int)access_action_parse(NULL));
    for (unsigned k = 0; k < 200; k++) {
        uint8_t r[16]; for (int i = 0; i < 16; i++) r[i] = (uint8_t)rnd();
        char t[33]; access_token_format(t, r); fputs("T ", f); hex(f, r, 16); fprintf(f, " %s\n", t);
        char o[33]; strcpy(o, t); unsigned flip = rnd() % 34; if (flip < 32) o[flip] ^= 1; else if (flip == 32) o[31] = 0;
        fprintf(f, "Q %s %s %d\n", t, o, access_token_equal(o, t));
    }
    fclose(f);
}

/* ---------------------------------------------------------------- boot */
static void gen_boot(const char *dir) {
    FILE *f = open_out(dir, "boot.golden");
    uint32_t magics[] = {SETUP_BOOT_MAGIC, SETUP_BOOT_MAGIC ^ 1, 0};
    uint32_t nexts[] = {0, 1, 2, 3, 7, 0xffffffffu};
    uint32_t slots[] = {0, 1, 3, 8, 9, 0xffffffffu};
    for (unsigned sr = 0; sr < 2; sr++) for (unsigned m = 0; m < 3; m++) for (unsigned n = 0; n < 6; n++) for (unsigned s = 0; s < 6; s++) for (unsigned ns = 0; ns < 2; ns++) for (unsigned ok = 0; ok < 2; ok++) {
        setup_boot_decision d = setup_boot_decide(sr, magics[m], nexts[n], slots[s], ns, ok);
        fprintf(f, "D %u %u %u %u %u %u %u %u\n", sr, magics[m], nexts[n], slots[s], ns, ok, d.setup, d.preselect);
    }
    for (unsigned r = 0; r < 3; r++) for (unsigned p = 0; p < 12; p++) {
        uint32_t magic = 9, next = 9, slot = 9; setup_boot_request(&magic, &next, &slot, (setup_request)r, p);
        fprintf(f, "R %u %u %u %u %u\n", r, p, magic, next, slot);
    }
    uint32_t starts[] = {0, 5000, 0xffffff00u, 0xfffffff0u, 1000};
    for (unsigned si = 0; si < 5; si++) {
        setup_session s; setup_session_start(&s, starts[si]);
        uint32_t offs[] = {0, 1, 999, 1000, 1001, 5000, 29999, 30000, 30001, 599000, 599001, 599999, 600000, 600001, 7200000, 0x7fffffffu, 0xffffffffu};
        for (unsigned o = 0; o < 17; o++) for (unsigned up = 0; up < 2; up++) {
            uint32_t now = starts[si] + offs[o];
            fprintf(f, "T %u %u %u %u %u %u %u\n", starts[si], now, up, setup_session_expired(&s, now), setup_session_should_end(&s, now, up), setup_session_seconds_left(&s, now), setup_session_failsafe_delay_ms(&s, now, up));
        }
    }
    {   setup_session s = {0}; uint32_t nows[] = {0, 5, 1000000};
        for (unsigned i = 0; i < 3; i++) for (unsigned up = 0; up < 2; up++) fprintf(f, "I %u %u %u %u %u\n", nows[i], up, setup_session_expired(&s, nows[i]), setup_session_should_end(&s, nows[i], up), setup_session_failsafe_delay_ms(&s, nows[i], up)); }
    for (unsigned k = 0; k < 60; k++) {
        uint8_t mac[6]; for (int i = 0; i < 6; i++) mac[i] = (uint8_t)rnd();
        for (unsigned size = 0; size < 17; size += 4) { char out[32]; memset(out, 'x', sizeof(out)); setup_ap_ssid(out, size, mac); fprintf(f, "N "); hex(f, mac, 6); fprintf(f, " %u ", size); hex(f, (uint8_t *)out, size ? strlen(out) + 1 : 0); fputc('\n', f); }
    }
    fclose(f);
}

/* ---------------------------------------------------------------- scan list */
static void gen_scan(const char *dir) {
    FILE *f = open_out(dir, "scan.golden");
    const char *pool[] = {"home", "Home", "cafe wifi", "caf\xc3\xa9", "\xc3\x28", "bad\x01ctl", "\xe2\x82\xac" "uro", "\xed\xa0\x80", "\xf0\x9f\x98\x80", "\xf4\x90\x80\x80", "\xc0\xaf", "del\x7f", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "x\"q\\y", "tab\there", ""};
    unsigned np = sizeof(pool) / sizeof(pool[0]);
    for (unsigned c = 0; c < 120; c++) {
        scan_list list; scan_list_init(&list);
        unsigned n = 1 + rnd() % 60;
        fprintf(f, "L %u\n", n);
        for (unsigned i = 0; i < n; i++) {
            uint8_t ssid[32]; memset(ssid, 0, 32);
            if (rnd() % 20 == 0) memset(ssid, 'z', 32); else { const char *s = pool[rnd() % np]; strncpy((char *)ssid, s, 32); }
            int rssi = (int)(rnd() % 300) - 150; bool secure = rnd() & 1;
            fputs("O ", f); hex(f, ssid, 32); fprintf(f, " %d %d\n", rssi, secure);
            scan_list_offer(&list, ssid, rssi, secure);
        }
        fprintf(f, "R %u\n", list.count);
        for (unsigned i = 0; i < list.count; i++) { fputs("E ", f); hex(f, (uint8_t *)list.entry[i].ssid, strlen(list.entry[i].ssid)); fprintf(f, " %d %d\n", list.entry[i].rssi, list.entry[i].secure); }
        /* the JSON wifi_scan_async builds from it */
        cJSON *response = cJSON_CreateObject(), *networks = cJSON_CreateArray(); bool busy = rnd() & 1;
        cJSON_AddBoolToObject(response, "ok", true); cJSON_AddBoolToObject(response, "busy", busy); cJSON_AddItemToObject(response, "networks", networks);
        for (unsigned i = 0; i < list.count; i++) {
            cJSON *network = cJSON_CreateObject();
            cJSON_AddStringToObject(network, "ssid", list.entry[i].ssid); cJSON_AddNumberToObject(network, "rssi", list.entry[i].rssi);
            cJSON_AddBoolToObject(network, "secure", list.entry[i].secure); cJSON_AddItemToArray(cJSON_GetObjectItem(response, "networks"), network);
        }
        char *s = cJSON_PrintUnformatted(response); fprintf(f, "J %d ", busy); hex(f, (uint8_t *)s, strlen(s)); fputc('\n', f); free(s); cJSON_Delete(response);
    }
    fclose(f);
}

/* ---------------------------------------------------------------- JSON */
static const char *KEYS[] = {"action", "ssid", "password", "name", "slot", "priority", "mode", "label", "key", "id", "enabled"};
static void json_case(FILE *f, const uint8_t *body, size_t n) {
    char *text = malloc(n + 1); memcpy(text, body, n); text[n] = 0;   /* the handler: body[used] = 0 */
    fputs("B ", f); hex(f, body, n); fputc('\n', f);
    cJSON *j = cJSON_Parse(text);
    if (!j) { fputs("X INVALID\n", f); free(text); return; }
    for (unsigned k = 0; k < 11; k++) {
        cJSON *item = cJSON_GetObjectItem(j, KEYS[k]);
        fprintf(f, "K %s ", KEYS[k]);
        if (!item) fputs("ABSENT", f);
        else if (cJSON_IsString(item)) { fputs("STR ", f); hex(f, (uint8_t *)item->valuestring, strlen(item->valuestring)); }
        else if (cJSON_IsNumber(item)) fprintf(f, "NUM %.17g %d", item->valuedouble, item->valueint);
        else if (cJSON_IsTrue(item)) fputs("TRUE", f);
        else if (cJSON_IsFalse(item)) fputs("FALSE", f);
        else fputs("OTHER", f);
        fputc('\n', f);
    }
    cJSON_Delete(j); free(text);
}
static void gen_json(const char *dir) {
    FILE *f = open_out(dir, "json.golden");
    const char *fixed[] = {
        "{\"action\":\"wifi\",\"ssid\":\"home\",\"password\":\"hunter22\",\"slot\":1}",
        "{\"action\":\"wifi\",\"ssid\":\"home\",\"password\":\"\",\"slot\":2,\"priority\":10,\"name\":\"Home\"}",
        "{\"ACTION\":\"wifi_remove\",\"SSID\":\"x\"}", "{\"action\":5,\"action\":\"wifi\"}", "{\"action\":\"a\",\"Action\":\"b\"}",
        "{\"action\":\"setup_done\"} trailing garbage", "  \t\n{\"action\":\"setup_done\"}", "\xef\xbb\xbf{\"action\":\"setup_done\"}",
        "[{\"action\":\"wifi\"}]", "42", "\"str\"", "null", "true", "", "{", "{}", "{\"a\":}", "{\"action\":\"wifi\",}", "{\"action\" \"wifi\"}",
        "{\"action\":\"w\\u0069fi\"}", "{\"action\":\"wifi\\u0000x\"}", "{\"action\":\"\\ud83d\\ude00\"}", "{\"action\":\"\\ud83d\"}", "{\"action\":\"\\ude00\"}",
        "{\"action\":\"\\q\"}", "{\"action\":\"wifi", "{\"slot\":1.0}", "{\"slot\":1e0}", "{\"slot\":01}", "{\"slot\":-0}", "{\"slot\":1.5}", "{\"slot\":+1}",
        "{\"slot\":1.00000000000000000001}", "{\"slot\":1e400}", "{\"slot\":1.}", "{\"slot\":.5}", "{\"slot\":1e}", "{\"slot\":1ee}", "{\"slot\":--1}", "{\"slot\":\"1\"}",
        "{\"enabled\":true,\"id\":3}", "{\"enabled\":false}", "{\"enabled\":nul}", "{\"enabled\":tru}", "{\"enabled\":truex}", "{\"enabled\":null}", "{\"enabled\":[1,2,{\"a\":[]}]}",
        "{\"x\":{\"action\":\"wifi\"},\"action\":\"mode\"}", "{\"mode\":\"tailnet_gateway\",\"action\":\"mode\"}", "{\"label\":\"a-b\",\"key\":\"tskey\",\"action\":\"add\"}",
        "{\"action\":\"wifi\"\x01}", "{\"action\":\"wi\x01fi\"}", "{\"ssid\":\"\xff\xfe\"}", "{\"a\\u0000b\":1,\"ssid\":\"s\"}", "{\"actio\\u006e\":\"wifi\"}",
        "{\"id\\u0000junk\":7}", "{\"slot\":1,\"slot\":2}", "{ \"slot\" : 3 , \"priority\" : 99 }"};
    for (unsigned i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) json_case(f, (const uint8_t *)fixed[i], strlen(fixed[i]));
    /* nesting limit */
    for (unsigned depth = 995; depth <= 1002; depth++) {
        char *b = malloc(2 * depth + 40); size_t n = 0; b[n++] = '{'; memcpy(b + n, "\"action\":", 9); n += 9;
        for (unsigned i = 0; i < depth - 1; i++) b[n++] = '['; for (unsigned i = 0; i < depth - 1; i++) b[n++] = ']'; b[n++] = '}';
        json_case(f, (uint8_t *)b, n); free(b);
    }
    for (unsigned depth = 998; depth <= 1002; depth++) { char *b = malloc(2 * depth + 4); size_t n = 0; for (unsigned i = 0; i < depth; i++) b[n++] = '['; for (unsigned i = 0; i < depth; i++) b[n++] = ']'; json_case(f, (uint8_t *)b, n); free(b); }
    /* random mutations of valid documents */
    for (unsigned k = 0; k < 4000; k++) {
        const char *base = fixed[rnd() % 6]; size_t n = strlen(base); uint8_t b[256]; memcpy(b, base, n);
        for (unsigned m = rnd() % 4; m; m--) { unsigned at = rnd() % n; switch (rnd() % 3) { case 0: b[at] = (uint8_t)rnd(); break; case 1: b[at] = "{}[]\",:\\ 0-.e"[rnd() % 14]; break; default: if (n > 1) { memmove(b + at, b + at + 1, n - at - 1); n--; } } }
        if (rnd() % 8 == 0) n = rnd() % (n + 1);
        json_case(f, b, n);
    }
    /* printing strings, as CreateString/AddStringToObject does */
    for (unsigned k = 0; k < 300; k++) {
        uint8_t s[40]; size_t n = rnd() % 36; for (size_t i = 0; i < n; i++) s[i] = (uint8_t)(rnd() % 4 ? rnd() % 128 : rnd());
        for (size_t i = 0; i < n; i++) if (!s[i]) s[i] = 1;
        s[n] = 0; cJSON *o = cJSON_CreateObject(); cJSON_AddStringToObject(o, "error", (char *)s); cJSON_AddBoolToObject(o, "ok", false);
        char *p = cJSON_PrintUnformatted(o); fputs("W ", f); hex(f, s, n); fputc(' ', f); hex(f, (uint8_t *)p, strlen(p)); fputc('\n', f); free(p); cJSON_Delete(o);
    }
    fclose(f);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: gen_golden OUTDIR\n"); return 2; }
    gen_dns(argv[1]); gen_access(argv[1]); gen_boot(argv[1]); gen_scan(argv[1]); gen_json(argv[1]);
    return 0;
}
