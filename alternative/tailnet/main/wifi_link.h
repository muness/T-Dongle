#pragma once
/* Wi-Fi link visibility for status reports (release and diagnostics images). Pure C: no ESP-IDF types, so the
 * formatting and its bounds are host tested (tests/test_wifi_link.c). The driver reads live in wifi_link.inc.
 *
 * Privacy: nothing here carries the BSSID or the SSID. Both stay out of every report this file produces. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* wifi_phy_mode_t values (esp_wifi_types_generic.h); wifi_link.inc asserts they still match. */
enum { WIFI_LINK_PHY_LR, WIFI_LINK_PHY_11B, WIFI_LINK_PHY_11G, WIFI_LINK_PHY_11A, WIFI_LINK_PHY_HT20,
       WIFI_LINK_PHY_HT40, WIFI_LINK_PHY_HE20, WIFI_LINK_PHY_VHT20, WIFI_LINK_PHY_COUNT };
/* Every field has an explicit "unknown" so a failed driver call is never reported as a real zero. */
enum { WIFI_LINK_PHY_UNKNOWN = 0xff, WIFI_LINK_PS_UNKNOWN = 0xff, WIFI_LINK_SECOND_UNKNOWN = 0xff };
enum { WIFI_LINK_AP_B = 1, WIFI_LINK_AP_G = 2, WIFI_LINK_AP_N = 4, WIFI_LINK_AP_AX = 8 };
/* Reason 200 is WIFI_REASON_BEACON_TIMEOUT: the station stopped hearing the AP (the loss signature we hunt). */
enum { WIFI_LINK_REASON_BEACON_TIMEOUT = 200 };

typedef struct {
    bool connected;          /* an AP record exists: associated */
    bool rssi_valid;
    int8_t rssi;             /* dBm, driver average when available, else the AP record's value */
    uint8_t channel;         /* primary channel */
    uint8_t secondary;       /* 0 none, 1 above, 2 below, WIFI_LINK_SECOND_UNKNOWN */
    uint8_t phy;             /* negotiated wifi_phy_mode_t (HT20/HT40/11G/...) or WIFI_LINK_PHY_UNKNOWN */
    uint8_t bw_cfg_mhz;      /* bandwidth the STA is CONFIGURED to use: 20, 40 or 0 unknown. The negotiated one is phy. */
    uint8_t ap_bw_mhz;       /* bandwidth the AP advertises, 0 unknown */
    uint8_t ap_modes;        /* WIFI_LINK_AP_* capability bits of the AP */
    uint8_t ps;              /* wifi_ps_type_t, or WIFI_LINK_PS_UNKNOWN */
    bool tx_power_valid;
    int8_t tx_power_qdbm;    /* maximum transmit power, quarter dBm */
} wifi_link_info;

/* Cumulative event counters, written by the Wi-Fi event handler (word sized, single writer). */
typedef struct {
    uint32_t connects, disconnects, beacon_timeouts;
    uint32_t last_disconnect_ms;     /* uptime at the last disconnect; meaningful when disconnects != 0 */
    uint16_t last_reason;            /* wifi_err_reason_t of the last disconnect */
    int8_t last_disconnect_rssi;     /* RSSI the driver reported at that disconnect */
} wifi_link_events;

static inline void wifi_link_note_connect(wifi_link_events *e) { e->connects++; }
static inline void wifi_link_note_disconnect(wifi_link_events *e, unsigned reason, int rssi, uint32_t now_ms) {
    e->disconnects++;
    if (reason == WIFI_LINK_REASON_BEACON_TIMEOUT) e->beacon_timeouts++;
    e->last_reason = (uint16_t)reason;
    e->last_disconnect_rssi = (int8_t)(rssi < -128 ? -128 : rssi > 127 ? 127 : rssi);
    e->last_disconnect_ms = now_ms;
}

static inline const char *wifi_link_phy_name(unsigned phy) {
    static const char *const names[WIFI_LINK_PHY_COUNT] = {"lr", "11b", "11g", "11a", "HT20", "HT40", "HE20", "VHT20"};
    return phy < WIFI_LINK_PHY_COUNT ? names[phy] : "unknown";
}
static inline const char *wifi_link_secondary_name(unsigned s) {
    return s == 0 ? "none" : s == 1 ? "above" : s == 2 ? "below" : "unknown";
}
static inline const char *wifi_link_ps_name(unsigned ps) {
    return ps == 0 ? "none" : ps == 1 ? "min_modem" : ps == 2 ? "max_modem" : "unknown";
}
/* AP capability letters in fixed order, e.g. "bgn" or "bgnax"; "-" when none is advertised. 6 bytes. */
static inline void wifi_link_modes_text(unsigned modes, char out[6]) {
    size_t n = 0;
    if (modes & WIFI_LINK_AP_B) out[n++] = 'b';
    if (modes & WIFI_LINK_AP_G) out[n++] = 'g';
    if (modes & WIFI_LINK_AP_N) out[n++] = 'n';
    if (modes & WIFI_LINK_AP_AX) { out[n++] = 'a'; out[n++] = 'x'; }
    if (!n) out[n++] = '-';
    out[n] = 0;
}
/* Serial `status` line one carries rssi=<this>; Android's parser accepts "unknown" or an integer there. */
static inline const char *wifi_link_rssi_text(const wifi_link_info *l, char out[5]) {
    if (!l->connected || !l->rssi_valid) return "unknown";
    snprintf(out, 5, "%d", (int)l->rssi);   /* -128..127: at most 4 characters */
    return out;
}

/* Worst case: every number at its widest. Callers size buffers with these. */
enum { WIFI_LINK_JSON_MAX = 400, WIFI_LINK_LINE_MAX = 300 };

/* The "wifi_link" object body for /status and the diagnostics report: returns the length, or 0 when it did not
 * fit (the caller then omits it; a half object never leaves this function). Includes the surrounding braces. */
static inline size_t wifi_link_json(char *out, size_t cap, const wifi_link_info *l, const wifi_link_events *e) {
    if (!out || !cap) return 0;
    char modes[6];
    wifi_link_modes_text(l->ap_modes, modes);
    int n = snprintf(out, cap, "{\"connected\":%s,", l->connected ? "true" : "false");
    if (n < 0 || (size_t)n >= cap) { out[0] = 0; return 0; }
    size_t used = (size_t)n;
    if (l->connected) {
#define WL_ADD(...) do { n = snprintf(out + used, cap - used, __VA_ARGS__); if (n < 0 || (size_t)n >= cap - used) { out[0] = 0; return 0; } used += (size_t)n; } while (0)
        if (l->rssi_valid) WL_ADD("\"rssi_dbm\":%d,", (int)l->rssi); else WL_ADD("\"rssi_dbm\":null,");
        WL_ADD("\"channel\":%u,\"secondary\":\"%s\",\"phy\":\"%s\",\"bandwidth_cfg_mhz\":%u,\"ap_bandwidth_mhz\":%u,",
               (unsigned)l->channel, wifi_link_secondary_name(l->secondary), wifi_link_phy_name(l->phy),
               (unsigned)l->bw_cfg_mhz, (unsigned)l->ap_bw_mhz);
        WL_ADD("\"ap_modes\":\"%s\",\"power_save\":\"%s\",", modes, wifi_link_ps_name(l->ps));
        if (l->tx_power_valid) WL_ADD("\"tx_power_qdbm\":%d,", (int)l->tx_power_qdbm); else WL_ADD("\"tx_power_qdbm\":null,");
    }
    WL_ADD("\"connects\":%lu,\"disconnects\":%lu,\"beacon_timeouts\":%lu,\"last_disconnect_reason\":%u,"
           "\"last_disconnect_rssi_dbm\":%d,\"last_disconnect_uptime_ms\":%lu}",
           (unsigned long)e->connects, (unsigned long)e->disconnects, (unsigned long)e->beacon_timeouts,
           (unsigned)e->last_reason, (int)e->last_disconnect_rssi, (unsigned long)e->last_disconnect_ms);
    return used;
}

/* Serial `status` second line (no BSSID/SSID). Returns the length or 0 when it did not fit. Ends with CRLF. */
static inline size_t wifi_link_line(char *out, size_t cap, const wifi_link_info *l, const wifi_link_events *e) {
    if (!out || !cap) return 0;
    char modes[6];
    wifi_link_modes_text(l->ap_modes, modes);
    int n;
    if (l->connected) {
        char rssi[5];
        char power[8] = "unknown";
        if (l->tx_power_valid) snprintf(power, sizeof(power), "%d", (int)l->tx_power_qdbm);
        n = snprintf(out, cap, "wifi_link connected=1 rssi_dbm=%s channel=%u secondary=%s phy=%s bandwidth_cfg_mhz=%u ap_bandwidth_mhz=%u "
                     "ap_modes=%s power_save=%s tx_power_qdbm=%s connects=%lu disconnects=%lu beacon_timeouts=%lu last_disconnect_reason=%u\r\n",
                     wifi_link_rssi_text(l, rssi), (unsigned)l->channel, wifi_link_secondary_name(l->secondary),
                     wifi_link_phy_name(l->phy), (unsigned)l->bw_cfg_mhz, (unsigned)l->ap_bw_mhz, modes,
                     wifi_link_ps_name(l->ps), power, (unsigned long)e->connects, (unsigned long)e->disconnects,
                     (unsigned long)e->beacon_timeouts, (unsigned)e->last_reason);
    } else
        n = snprintf(out, cap, "wifi_link connected=0 connects=%lu disconnects=%lu beacon_timeouts=%lu last_disconnect_reason=%u\r\n",
                     (unsigned long)e->connects, (unsigned long)e->disconnects, (unsigned long)e->beacon_timeouts, (unsigned)e->last_reason);
    if (n < 0 || (size_t)n >= cap) { out[0] = 0; return 0; }
    return (size_t)n;
}
