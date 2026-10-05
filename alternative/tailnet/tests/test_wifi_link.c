/* Wi-Fi link formatting (main/wifi_link.h) and lwIP counter lines (main/wifi_stats.h): exact text, widest values
 * inside their documented bounds, truncation never leaves half an object, and no BSSID/SSID anywhere. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "../main/wifi_link.h"
#include "../main/wifi_stats.h"

static wifi_link_info link_full(void) {
    return (wifi_link_info){.connected = true, .rssi_valid = true, .rssi = -61, .channel = 6, .secondary = 1, .phy = WIFI_LINK_PHY_HT40,
                            .bw_cfg_mhz = 40, .ap_bw_mhz = 40, .ap_modes = WIFI_LINK_AP_B | WIFI_LINK_AP_G | WIFI_LINK_AP_N, .ps = 0,
                            .tx_power_valid = true, .tx_power_qdbm = 78,
                            .selected_slot = 2, .pinned = true};
}
static wifi_link_info link_widest(void) {
    return (wifi_link_info){.connected = true, .rssi_valid = true, .rssi = -128, .channel = 255, .secondary = 2, .phy = WIFI_LINK_PHY_VHT20,
                            .bw_cfg_mhz = 255, .ap_bw_mhz = 255, .ap_modes = 255, .ps = 2, .tx_power_valid = true, .tx_power_qdbm = -128,
                            .selected_slot = 255, .pinned = true, .pin_failed_slot = 255};
}
static char captured[8][WS_LINE_MAX];
static unsigned captured_count;
static void capture(void *context, const char *line) { (void)context; assert(captured_count < 8); strcpy(captured[captured_count++], line); }

static void names(void) {
    assert(!strcmp(wifi_link_phy_name(WIFI_LINK_PHY_11B), "11b") && !strcmp(wifi_link_phy_name(WIFI_LINK_PHY_11G), "11g"));
    assert(!strcmp(wifi_link_phy_name(WIFI_LINK_PHY_HT20), "HT20") && !strcmp(wifi_link_phy_name(WIFI_LINK_PHY_HT40), "HT40"));
    assert(!strcmp(wifi_link_phy_name(WIFI_LINK_PHY_UNKNOWN), "unknown") && !strcmp(wifi_link_phy_name(8), "unknown"));
    assert(!strcmp(wifi_link_secondary_name(0), "none") && !strcmp(wifi_link_secondary_name(1), "above") &&
           !strcmp(wifi_link_secondary_name(2), "below") && !strcmp(wifi_link_secondary_name(3), "unknown"));
    assert(!strcmp(wifi_link_ps_name(0), "none") && !strcmp(wifi_link_ps_name(1), "min_modem") && !strcmp(wifi_link_ps_name(2), "max_modem") &&
           !strcmp(wifi_link_ps_name(WIFI_LINK_PS_UNKNOWN), "unknown"));
    char m[6];
    wifi_link_modes_text(0, m); assert(!strcmp(m, "-"));
    wifi_link_modes_text(WIFI_LINK_AP_B | WIFI_LINK_AP_G | WIFI_LINK_AP_N, m); assert(!strcmp(m, "bgn"));
    wifi_link_modes_text(WIFI_LINK_AP_G | WIFI_LINK_AP_N | WIFI_LINK_AP_AX, m); assert(!strcmp(m, "gnax"));
    wifi_link_modes_text(15, m); assert(!strcmp(m, "bgnax") && strlen(m) == 5);
}
static void rssi_text(void) {
    char b[5];
    wifi_link_info l = link_full();
    assert(!strcmp(wifi_link_rssi_text(&l, b), "-61"));
    l.rssi = -128; assert(!strcmp(wifi_link_rssi_text(&l, b), "-128"));
    l.rssi = 127; assert(!strcmp(wifi_link_rssi_text(&l, b), "127"));   /* very strong signals can read positive */
    l.rssi = 0; assert(!strcmp(wifi_link_rssi_text(&l, b), "0"));
    l.rssi_valid = false; assert(!strcmp(wifi_link_rssi_text(&l, b), "unknown"));
    l = link_full(); l.connected = false; assert(!strcmp(wifi_link_rssi_text(&l, b), "unknown"));
    /* The serial `status` first line's token must keep matching Android's rssi=(?:unknown|-?\d+). */
    for (int r = -128; r <= 127; r++) {
        l = link_full(); l.rssi = (int8_t)r;
        const char *t = wifi_link_rssi_text(&l, b);
        char *end; assert(strtol(t, &end, 10) == r && !*end);
    }
}
static void join_states(void) {
    wifi_link_info l = {0};
    assert(wifi_link_join_state(&l) == WIFI_LINK_JOIN_DISCONNECTED && !strcmp(wifi_link_join_name(wifi_link_join_state(&l)), "disconnected"));
    l.pinned = true; assert(!strcmp(wifi_link_join_name(wifi_link_join_state(&l)), "joining"));
    l.connected = true; assert(!strcmp(wifi_link_join_name(wifi_link_join_state(&l)), "connected"));
    l = (wifi_link_info){.pin_failed_slot = 3}; assert(!strcmp(wifi_link_join_name(wifi_link_join_state(&l)), "failed"));
    char out[WIFI_LINK_JSON_MAX]; wifi_link_events e = {0};
    assert(wifi_link_json(out, sizeof(out), &l, &e) && strstr(out, "\"join\":\"failed\"") && strstr(out, "\"pin_failed_slot\":3"));
    assert(!strcmp(wifi_link_join_name(99), "disconnected"));
}
static void events(void) {
    wifi_link_events e = {0};
    wifi_link_note_connect(&e);
    wifi_link_note_disconnect(&e, 8, -70, 1000);
    assert(e.connects == 1 && e.disconnects == 1 && e.beacon_timeouts == 0 && e.last_reason == 8 && e.last_disconnect_rssi == -70 && e.last_disconnect_ms == 1000);
    wifi_link_note_disconnect(&e, WIFI_LINK_REASON_BEACON_TIMEOUT, -300, 2000);   /* clamped, never wrapped */
    assert(e.disconnects == 2 && e.beacon_timeouts == 1 && e.last_reason == 200 && e.last_disconnect_rssi == -128);
    wifi_link_note_disconnect(&e, 1, 500, 3000);
    assert(e.last_disconnect_rssi == 127 && e.beacon_timeouts == 1);
}
static void json_exact(void) {
    char out[WIFI_LINK_JSON_MAX];
    wifi_link_info l = link_full();
    wifi_link_events e = {.connects = 3, .disconnects = 2, .beacon_timeouts = 1, .last_disconnect_ms = 9000, .last_reason = 200, .last_disconnect_rssi = -85};
    size_t n = wifi_link_json(out, sizeof(out), &l, &e);
    assert(n == strlen(out) && n > 0);
    assert(!strcmp(out, "{\"connected\":true,\"join\":\"connected\",\"selected_slot\":2,\"pinned\":true,\"pin_failed_slot\":0,\"rssi_dbm\":-61,\"channel\":6,\"secondary\":\"above\",\"phy\":\"HT40\",\"bandwidth_cfg_mhz\":40,"
                        "\"ap_bandwidth_mhz\":40,\"ap_modes\":\"bgn\",\"power_save\":\"none\",\"tx_power_qdbm\":78,\"connects\":3,\"disconnects\":2,"
                        "\"beacon_timeouts\":1,\"last_disconnect_reason\":200,\"last_disconnect_rssi_dbm\":-85,\"last_disconnect_uptime_ms\":9000}"));
    l = (wifi_link_info){.phy = WIFI_LINK_PHY_UNKNOWN, .ps = WIFI_LINK_PS_UNKNOWN, .secondary = WIFI_LINK_SECOND_UNKNOWN};
    n = wifi_link_json(out, sizeof(out), &l, &e);
    assert(n && !strcmp(out, "{\"connected\":false,\"join\":\"disconnected\",\"selected_slot\":0,\"pinned\":false,\"pin_failed_slot\":0,\"connects\":3,\"disconnects\":2,\"beacon_timeouts\":1,\"last_disconnect_reason\":200,"
                             "\"last_disconnect_rssi_dbm\":-85,\"last_disconnect_uptime_ms\":9000}"));
    l = link_full(); l.rssi_valid = false; l.tx_power_valid = false; l.phy = WIFI_LINK_PHY_UNKNOWN; l.ps = WIFI_LINK_PS_UNKNOWN;
    n = wifi_link_json(out, sizeof(out), &l, &e);
    assert(n && strstr(out, "\"rssi_dbm\":null,") && strstr(out, "\"phy\":\"unknown\"") && strstr(out, "\"tx_power_qdbm\":null,") && strstr(out, "\"power_save\":\"unknown\""));
    assert(!strstr(out, "ssid") && !strstr(out, "bssid"));
}
static void json_bounds(void) {
    /* Widest possible values must fit WIFI_LINK_JSON_MAX with room to spare, and every shorter buffer must refuse. */
    wifi_link_info l = link_widest();
    wifi_link_events e = {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT16_MAX, -128};
    char big[1024], tight[WIFI_LINK_JSON_MAX];
    size_t n = wifi_link_json(big, sizeof(big), &l, &e);
    assert(n > 0 && n < WIFI_LINK_JSON_MAX && n == strlen(big));
    assert(wifi_link_json(tight, sizeof(tight), &l, &e) == n);
    for (size_t cap = 1; cap <= n; cap++) {       /* too small: nothing returned, always terminated inside the capacity */
        char small[1024];
        memset(small, 'x', sizeof(small));
        assert(wifi_link_json(small, cap, &l, &e) == 0);
        assert(memchr(small, 0, cap) != NULL);
    }
    assert(wifi_link_json(NULL, 10, &l, &e) == 0 && wifi_link_json(big, 0, &l, &e) == 0);
    wifi_link_info down = {0};
    assert(wifi_link_json(big, sizeof(big), &down, &e) < n);
}
static void line_exact(void) {
    char out[WIFI_LINK_LINE_MAX];
    wifi_link_info l = link_full();
    wifi_link_events e = {.connects = 1};
    size_t n = wifi_link_line(out, sizeof(out), &l, &e);
    assert(n == strlen(out));
    assert(!strcmp(out, "wifi_link connected=1 join=connected selected=2 pinned=1 pin_failed=0 rssi_dbm=-61 channel=6 secondary=above phy=HT40 bandwidth_cfg_mhz=40 ap_bandwidth_mhz=40 ap_modes=bgn "
                        "power_save=none tx_power_qdbm=78 connects=1 disconnects=0 beacon_timeouts=0 last_disconnect_reason=0\r\n"));
    /* Must not look like the Android status line (^mode=...) so an extra line never confuses its multiline matcher. */
    assert(strncmp(out, "mode=", 5) != 0);
    wifi_link_info down = {0};
    n = wifi_link_line(out, sizeof(out), &down, &e);
    assert(n && !strcmp(out, "wifi_link connected=0 join=disconnected selected=0 pinned=0 pin_failed=0 connects=1 disconnects=0 beacon_timeouts=0 last_disconnect_reason=0\r\n"));
    l = link_widest();
    e = (wifi_link_events){UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT16_MAX, -128};
    char big[1024];
    n = wifi_link_line(big, sizeof(big), &l, &e);
    assert(n > 0 && n < WIFI_LINK_LINE_MAX);
    assert(wifi_link_line(out, sizeof(out), &l, &e) == n);
    for (size_t cap = 1; cap <= n; cap++) {
        char small[1024];
        memset(small, 'x', sizeof(small));
        assert(wifi_link_line(small, cap, &l, &e) == 0);
        assert(memchr(small, 0, cap) != NULL);
    }
}
static void stats_lines(void) {
    ws_proto p = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    captured_count = 0;
    assert(ws_emit_proto(capture, NULL, "tcp", 16, 77, &p));
    assert(!strcmp(captured[0], "{\"schema\":1,\"kind\":\"lwip_proto\",\"name\":\"tcp\",\"uptime_ms\":77,\"counter_bits\":16,\"xmit\":1,\"recv\":2,\"fw\":3,"
                                "\"drop\":4,\"chkerr\":5,\"lenerr\":6,\"memerr\":7,\"rterr\":8,\"proterr\":9,\"opterr\":10,\"err\":11,\"cachehit\":12}\r\n"));
    ws_pool q = {100, 40, 60, 4, 1};
    assert(ws_emit_pool(capture, NULL, "PBUF_POOL", 78, &q));
    assert(!strcmp(captured[1], "{\"schema\":1,\"kind\":\"lwip_pool\",\"name\":\"PBUF_POOL\",\"uptime_ms\":78,\"avail\":100,\"used\":40,\"max_used\":60,\"err\":4,\"illegal\":1}\r\n"));
    /* Widest counters: still one line inside WS_LINE_MAX (and the 600 byte console budget). */
    ws_proto w = {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX};
    assert(ws_emit_proto(capture, NULL, "0123456789012345678901234567890123456789", 32, UINT32_MAX, &w));
    assert(strlen(captured[2]) < 480 && strchr(captured[2], '\n') == captured[2] + strlen(captured[2]) - 1);
    assert(strstr(captured[2], "\"name\":\"01234567890123456789012\""));   /* names are cut at WS_NAME_MAX - 1 */
    ws_pool wp = {UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX};
    assert(ws_emit_pool(capture, NULL, "x", UINT32_MAX, &wp));
    /* A hostile or corrupt name cannot break the JSON. */
    assert(ws_emit_proto(capture, NULL, "a\"b\\c\n\x01\xff", 16, 1, &p));
    assert(strstr(captured[4], "\"name\":\"a_b_c___\""));
    assert(ws_emit_pool(capture, NULL, NULL, 1, &q));
    assert(strstr(captured[5], "\"name\":\"\""));
    char clean[WS_NAME_MAX];
    ws_clean_name(clean, "PBUF_POOL");
    assert(!strcmp(clean, "PBUF_POOL"));
}
/* Counter copies must keep lwIP's 16-bit counters intact (a counter at 65535 stays 65535, not -1). */
static void copy_macros(void) {
    struct { uint16_t xmit, recv, fw, drop, chkerr, lenerr, memerr, rterr, proterr, opterr, err, cachehit; } src = {1, 65535, 3, 4, 5, 6, 7, 8, 9, 10, 11, 65534};
    ws_proto dst;
    WS_PROTO_FROM(dst, src);
    assert(dst.recv == 65535 && dst.cachehit == 65534 && dst.xmit == 1 && dst.err == 11);
    struct { uint16_t avail, used, max, err, illegal; } m = {5, 4, 3, 65535, 1};
    ws_pool pool;
    WS_POOL_FROM(pool, m);
    assert(pool.err == 65535 && pool.avail == 5 && pool.illegal == 1);
}
int main(void) {
    names(); rssi_text(); join_states(); events(); json_exact(); json_bounds(); line_exact(); stats_lines(); copy_macros();
    puts("wifi_link: names, rssi tokens, event counters, JSON/line exact text, widest-value bounds, truncation and lwIP counter lines passed");
    return 0;
}
