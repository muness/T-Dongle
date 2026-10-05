/* Host stand-in for the esp_wifi calls main/wifi_link.inc makes. Behaviour is driven by the host_wifi_* variables. */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
typedef enum { WIFI_PHY_MODE_LR, WIFI_PHY_MODE_11B, WIFI_PHY_MODE_11G, WIFI_PHY_MODE_11A, WIFI_PHY_MODE_HT20, WIFI_PHY_MODE_HT40,
               WIFI_PHY_MODE_HE20, WIFI_PHY_MODE_VHT20 } wifi_phy_mode_t;
typedef enum { WIFI_PS_NONE, WIFI_PS_MIN_MODEM, WIFI_PS_MAX_MODEM } wifi_ps_type_t;
typedef enum { WIFI_SECOND_CHAN_NONE, WIFI_SECOND_CHAN_ABOVE, WIFI_SECOND_CHAN_BELOW } wifi_second_chan_t;
typedef enum { WIFI_BW_HT20 = 1, WIFI_BW_HT40 = 2 } wifi_bandwidth_t;
typedef enum { WIFI_IF_STA } wifi_interface_t;
enum { WIFI_REASON_BEACON_TIMEOUT = 200 };
#define WIFI_STATIS_ALL (-1)
typedef struct {
    uint8_t bssid[6];
    uint8_t ssid[33];
    uint8_t primary;
    wifi_second_chan_t second;
    int8_t rssi;
    uint32_t phy_11b : 1, phy_11g : 1, phy_11n : 1, phy_11ax : 1;
    wifi_bandwidth_t bandwidth;
} wifi_ap_record_t;
typedef struct { uint8_t ssid[32], ssid_len, bssid[6], reason; int8_t rssi; } wifi_event_sta_disconnected_t;
static bool host_wifi_associated = true;
static bool host_wifi_fail_rssi, host_wifi_fail_phy, host_wifi_fail_bw, host_wifi_fail_ps, host_wifi_fail_power;
static wifi_ap_record_t host_wifi_ap;
static int host_wifi_avg_rssi;
static wifi_phy_mode_t host_wifi_phy;
static wifi_bandwidth_t host_wifi_bw;
static wifi_ps_type_t host_wifi_ps;
static int8_t host_wifi_power;
static unsigned host_wifi_dumps;
static esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *ap) { if (!host_wifi_associated) return ESP_FAIL; *ap = host_wifi_ap; return ESP_OK; }
static esp_err_t esp_wifi_sta_get_rssi(int *r) { if (host_wifi_fail_rssi) return ESP_FAIL; *r = host_wifi_avg_rssi; return ESP_OK; }
static esp_err_t esp_wifi_sta_get_negotiated_phymode(wifi_phy_mode_t *m) { if (host_wifi_fail_phy) return ESP_FAIL; *m = host_wifi_phy; return ESP_OK; }
static esp_err_t esp_wifi_get_bandwidth(wifi_interface_t i, wifi_bandwidth_t *b) { (void)i; if (host_wifi_fail_bw) return ESP_FAIL; *b = host_wifi_bw; return ESP_OK; }
static esp_err_t esp_wifi_get_ps(wifi_ps_type_t *p) { if (host_wifi_fail_ps) return ESP_FAIL; *p = host_wifi_ps; return ESP_OK; }
static esp_err_t esp_wifi_get_max_tx_power(int8_t *p) { if (host_wifi_fail_power) return ESP_FAIL; *p = host_wifi_power; return ESP_OK; }
static esp_err_t esp_wifi_statis_dump(uint32_t modules) { (void)modules; host_wifi_dumps++; return ESP_OK; }
