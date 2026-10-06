/* Live Wi-Fi link readings (release and diagnostics images). Included by gateway_main.c after wifi_link.h.
 * Every call is a documented public esp_wifi API; nothing private. The negotiated PHY *rate* is not exposed by
 * ESP-IDF v5.5.5 (only the negotiated PHY mode is), so none is reported. */
#include "esp_wifi.h"
#include "wifi_link.h"
_Static_assert((int)WIFI_PHY_MODE_LR == (int)WIFI_LINK_PHY_LR && (int)WIFI_PHY_MODE_11B == (int)WIFI_LINK_PHY_11B && (int)WIFI_PHY_MODE_11G == (int)WIFI_LINK_PHY_11G &&
               (int)WIFI_PHY_MODE_11A == (int)WIFI_LINK_PHY_11A && (int)WIFI_PHY_MODE_HT20 == (int)WIFI_LINK_PHY_HT20 && (int)WIFI_PHY_MODE_HT40 == (int)WIFI_LINK_PHY_HT40 &&
               (int)WIFI_PHY_MODE_HE20 == (int)WIFI_LINK_PHY_HE20 && (int)WIFI_PHY_MODE_VHT20 == (int)WIFI_LINK_PHY_VHT20,
               "wifi_link.h phy names must follow wifi_phy_mode_t");
_Static_assert((int)WIFI_PS_NONE == (int)0 && (int)WIFI_PS_MIN_MODEM == (int)1 && (int)WIFI_PS_MAX_MODEM == (int)2, "wifi_link.h ps names must follow wifi_ps_type_t");
_Static_assert((int)WIFI_SECOND_CHAN_NONE == (int)0 && (int)WIFI_SECOND_CHAN_ABOVE == (int)1 && (int)WIFI_SECOND_CHAN_BELOW == (int)2, "wifi_link.h secondary names");
_Static_assert((int)WIFI_REASON_BEACON_TIMEOUT == (int)WIFI_LINK_REASON_BEACON_TIMEOUT, "beacon timeout reason code");

static wifi_link_events wifi_link_stats;   /* written only by wifi_event on the event task */

static void wifi_link_event_connected(const wifi_event_sta_connected_t *c) {
    wifi_link_note_association(&wifi_link_stats, c ? c->bssid : NULL, (uint32_t)(esp_timer_get_time() / 1000));
}
static void wifi_link_event_disconnected(const wifi_event_sta_disconnected_t *d) {
    wifi_link_note_disconnect(&wifi_link_stats, d ? d->reason : 0, d ? d->rssi : 0, (uint32_t)(esp_timer_get_time() / 1000));
}

/* Reads the driver; safe from any task. Fields whose call fails stay "unknown" instead of reading as zero. */
static wifi_link_info wifi_link_read(void) {
    wifi_link_info l = {.phy = WIFI_LINK_PHY_UNKNOWN, .ps = WIFI_LINK_PS_UNKNOWN, .secondary = WIFI_LINK_SECOND_UNKNOWN};
    /* Selection state is plain ints written under members_lock; a torn read can only show the previous value. */
    int current = wifi_current;
    l.selected_slot = current >= 0 && current < 8 ? (uint8_t)(current + 1) : 0;
    l.pinned = wifi_pinned.slot >= 0;
    l.pin_failed_slot = (uint8_t)wifi_pinned.failed_slot;
    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) return l;   /* not associated */
    l.connected = true;
    l.rssi = ap.rssi;
    l.rssi_valid = true;
    int average = 0;
    if (esp_wifi_sta_get_rssi(&average) == ESP_OK && average >= -128 && average <= 127) l.rssi = (int8_t)average;
    l.channel = ap.primary;
    l.secondary = (uint8_t)ap.second;
    l.ap_bw_mhz = ap.bandwidth == WIFI_BW_HT40 ? 40 : ap.bandwidth == WIFI_BW_HT20 ? 20 : 0;
    l.ap_modes = (ap.phy_11b ? WIFI_LINK_AP_B : 0) | (ap.phy_11g ? WIFI_LINK_AP_G : 0) | (ap.phy_11n ? WIFI_LINK_AP_N : 0) | (ap.phy_11ax ? WIFI_LINK_AP_AX : 0);
    wifi_phy_mode_t phy;
    if (esp_wifi_sta_get_negotiated_phymode(&phy) == ESP_OK && (unsigned)phy < WIFI_LINK_PHY_COUNT) l.phy = (uint8_t)phy;
    wifi_bandwidth_t bw;
    if (esp_wifi_get_bandwidth(WIFI_IF_STA, &bw) == ESP_OK) l.bw_cfg_mhz = bw == WIFI_BW_HT40 ? 40 : bw == WIFI_BW_HT20 ? 20 : 0;
    wifi_ps_type_t ps;
    if (esp_wifi_get_ps(&ps) == ESP_OK && (unsigned)ps <= WIFI_PS_MAX_MODEM) l.ps = (uint8_t)ps;
    int8_t power;
    if (esp_wifi_get_max_tx_power(&power) == ESP_OK) { l.tx_power_valid = true; l.tx_power_qdbm = power; }
    return l;
}
