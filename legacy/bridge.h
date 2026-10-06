// Donor interface extended for coherent telemetry. See
// licenses/esp32-usb-wifi-MIT.txt.
#pragma once
#include "core.h"
#include "esp_err.h"
typedef struct {
    uint64_t up_bytes, down_bytes;
    uint32_t host_to_wifi, wifi_to_host, txdrop, reflected, poolfail, rxdrop, malformed;
} bridge_stats_t;
typedef struct {
    uint32_t boots, hangs, faults;
    const char *recovered;
    bridge_stats_t pre;
} bridge_crash_info_t;
typedef struct {
    bridge_stats_t stats;
    addresses_t addresses;
    bool associated, usb_mounted, usb_ready, suspended;
    uint32_t usb_resets, reconnects;
    uint16_t last_reason;
    uint64_t connected_ms, now_ms;
    int8_t rssi;
} bridge_snapshot_t;
void bridge_get_stats(bridge_stats_t *s);
void bridge_snapshot(bridge_snapshot_t *s);
void bridge_get_mac(uint8_t mac[6]);
void bridge_get_crash(bridge_crash_info_t *c);
bool bridge_wifi_connected(void);
uint64_t bridge_connected_since_ms(void);
const char *bridge_link_status(void);
bool bridge_host_ipv4(uint8_t ip[4]);
bool bridge_host_ipv6(uint8_t ip[16]);
esp_err_t wifi_apply_creds(const char *ssid, const char *pass);
void bridge_clear_addresses(void);
uint32_t bridge_roams(void);
