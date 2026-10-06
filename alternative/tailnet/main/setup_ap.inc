/* The setup access point (ADR 0024), compiled into gateway_main.c after the saved-network store.
 *
 * A setup boot is a normal boot that starts none of the dongle's services: no Wi-Fi bridge, no tailnet memberships, no DNS or NAT. It
 * starts the one HTTP server (start_http), the display, and this: an OPEN access point TDongle-XXXXXX on 192.168.4.1 with a DHCP server
 * that names the dongle as DNS and a DNS server that answers every name with the dongle, so a phone's captive-portal probe opens the
 * setup page by itself. The page uses the same /command, /wifi-scan and /wifi-saved handlers as the USB setup page, under the access
 * rules of setup_access.h. After SETUP_SESSION_MS (10 minutes), on `cancel`, or on the page's Done, the dongle restarts into its normal mode.
 *
 * Heap: nothing else runs, so nothing has to be accounted for. The access point, DHCP server, DNS task (3 KB stack) and scan task
 * (4 KB stack, 24 records) cost about 25 KB while the bridge's frame pool (48 KB) and the tailnet runtime (the admission budget of
 * ml_admission.h) are not allocated at all. A tailnet is never active while the access point is: start_member refuses to run in a setup boot. */
#include "esp_attr.h"
#include "lwip/sockets.h"
#include "dhcpserver/dhcpserver.h"
#include "esp_random.h"
#include "bootloader_random.h"

static bool setup_active;                  /* this boot is the setup access point */
static setup_session setup_clock;
static unsigned setup_preselect;           /* saved network (1 to 8) the page offers to replace, 0: add a new one */
static char setup_ap_name[16];
static char setup_ap_password[17];         /* empty: open network (CONFIG_TDONGLE_SETUP_AP_OPEN, the default) */
static char setup_token[ACCESS_TOKEN_LENGTH + 1];
static RTC_NOINIT_ATTR uint32_t setup_rtc[3];   /* SETUP_BOOT_MAGIC, request, preselected slot: survives a software reset only */
bool gateway_setup_active(void) { return setup_active; }

/* Called once, early in app_main (before anything depends on the answer). Consumes the request words. */
static setup_boot_decision setup_boot_early(bool networks_saved, bool store_ok) {
    setup_boot_decision d = setup_boot_decide(esp_reset_reason() == ESP_RST_SW, setup_rtc[0], setup_rtc[1], setup_rtc[2], networks_saved, store_ok);
    memset(setup_rtc, 0, sizeof(setup_rtc));
    return d;
}
/* Restart into setup (ENTER, with an optional preselected network) or out of it into normal mode (LEAVE). Does not return. */
static void setup_restart(setup_request request, unsigned preselect) {
    setup_boot_request(&setup_rtc[0], &setup_rtc[1], &setup_rtc[2], request, preselect);
    esp_restart();
}
/* The failsafe: an esp_timer armed in app_main whenever this boot is setup. It forces the restart even if the control task never ran (USB or console
 * init failed), re-arming itself with setup_session_failsafe_delay_ms until the session is over or the access point proved not to come up. The
 * control task's check (gateway_display_tick) is the fast path; this is the one that cannot be starved. */
static esp_timer_handle_t setup_failsafe;
static void setup_failsafe_fire(void *arg) {
    if (!setup_active) return;   /* recovery cancelled it */
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
    uint32_t next = setup_session_failsafe_delay_ms(&setup_clock, now, wifi_ready);
    if (!next) setup_restart(SETUP_REQUEST_LEAVE, 0);
    else esp_timer_start_once(setup_failsafe, (uint64_t)next * 1000);
}
static void setup_failsafe_arm(void) {
    const esp_timer_create_args_t args = {.callback = setup_failsafe_fire, .name = "setup_failsafe"};
    if (esp_timer_create(&args, &setup_failsafe) == ESP_OK) esp_timer_start_once(setup_failsafe, (uint64_t)SETUP_AP_GRACE_MS * 1000);
}
/* Does the settings store hold at least one saved network? Read the way wifi_load_profiles will read it, before the store is open: the
 * unified list, else the older single network, else the v0.1.x list. `early` is a read-only tn_settings handle, or 0 when that
 * namespace does not exist (an upgrade from v0.1.x). An unreadable store counts as "has networks" and clears *store_ok, so a
 * damaged store never opens an access point by itself. */
static bool setup_early_has_networks(nvs_handle_t early, bool *store_ok) {
    if (early) {
        typeof(wifi_saved) list;   /* 784 B on the main task's stack, which is freed when app_main returns */
        size_t n = sizeof(list);
        esp_err_t e = nvs_get_blob(early, "wifi_profiles", &list, &n);
        if (e == ESP_OK && n == sizeof(list)) {
            if (list.schema != 1 || list.count > WIFI_PROFILE_LIMIT) { *store_ok = false; return true; }   /* a schema this firmware does not know: unreadable, as wifi_load_profiles judges it */
            return list.count > 0;
        }
        if (e != ESP_ERR_NVS_NOT_FOUND) { *store_ok = false; return true; }
        wifi_config_t single;
        size_t m = sizeof(single);
        e = nvs_get_blob(early, "wifi", &single, &m);
        if (e == ESP_OK && m == sizeof(single) && single.sta.ssid[0]) return true;
        if (e != ESP_OK && e != ESP_ERR_NVS_NOT_FOUND) { *store_ok = false; return true; }
    }
    legacy_import *legacy = malloc(sizeof(*legacy));
    bool found = legacy && wifi_read_legacy(legacy) && legacy->count > 0;
    free(legacy);
    return found;
}

/* ---- Nearby networks, scanned off the HTTP task: the page polls /wifi-scan until `busy` clears. A scan takes the radio off the
 * access point's channel for a couple of seconds, exactly while a phone may be joining, so none is started until the page asks. */
static scan_list *setup_nets;              /* the last complete scan (heap, allocated by start_setup: a tailnet boot never pays for it), guarded by setup_nets_lock */
static SemaphoreHandle_t setup_nets_lock;
static volatile bool setup_scanning, setup_scanned;
static void setup_scan_task(void *arg) {
    scan_list *found = malloc(sizeof(*found));
    wifi_ap_record_t *records = calloc(24, sizeof(*records));
    if (found && records) {
        scan_list_init(found);
        if (xSemaphoreTake(wifi_scan_lock, pdMS_TO_TICKS(5000)) == pdTRUE) {
            wifi_scan_config_t config = {.show_hidden = false, .scan_type = WIFI_SCAN_TYPE_ACTIVE, .scan_time.active = {.min = 100, .max = 250}};
            uint16_t count = 24;
            if (esp_wifi_scan_start(&config, true) == ESP_OK && esp_wifi_scan_get_ap_records(&count, records) == ESP_OK)
                for (uint16_t i = 0; i < count; i++) scan_list_offer(found, records[i].ssid, records[i].rssi, records[i].authmode != WIFI_AUTH_OPEN);
            else esp_wifi_clear_ap_list();
            xSemaphoreGive(wifi_scan_lock);
        }
        if (setup_nets && xSemaphoreTake(setup_nets_lock, portMAX_DELAY) == pdTRUE) { *setup_nets = *found; xSemaphoreGive(setup_nets_lock); }
    }
    free(records);
    free(found);
    setup_scanned = true;
    setup_scanning = false;
    vTaskDelete(NULL);
}
/* Start a scan unless one runs; `again` forces a new one even when a result exists. Returns whether one is (now) running. */
static bool setup_scan_kick(bool again) {
    if (setup_scanning) return true;
    if (setup_scanned && !again) return false;
    setup_scanning = true;
    if (xTaskCreate(setup_scan_task, "setup_scan", 4096, NULL, 2, NULL) != pdPASS) { setup_scanning = false; return false; }
    return true;
}
/* A copy of the last scan, and whether one is running. */
static bool setup_scan_result(scan_list *out) {
    memset(out, 0, sizeof(*out));
    if (setup_nets && setup_nets_lock && xSemaphoreTake(setup_nets_lock, pdMS_TO_TICKS(50)) == pdTRUE) { *out = *setup_nets; xSemaphoreGive(setup_nets_lock); }
    return setup_scanning;
}

/* ---- Captive DNS: every name resolves to the dongle (captive_dns.h). Bound to the access point's address only, so it never answers
 * on the USB side. */
static void setup_dns_task(void *arg) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(53)};
    local.sin_addr.s_addr = htonl(0xc0a80401);   /* 192.168.4.1 */
    if (fd < 0 || bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        ESP_LOGE("setup", "captive DNS could not start; the page is still reachable at http://192.168.4.1/");
        if (fd >= 0) close(fd);
        vTaskDelete(NULL);
    }
    static const uint8_t dongle[4] = {192, 168, 4, 1};
    uint8_t query[256], reply[256 + 16];
    for (;;) {
        struct sockaddr_in from;
        socklen_t from_length = sizeof(from);
        int n = recvfrom(fd, query, sizeof(query), 0, (struct sockaddr *)&from, &from_length);
        if (n < 0) continue;
        size_t m = captive_dns_reply(query, (size_t)n, reply, sizeof(reply), dongle);
        if (m) sendto(fd, reply, m, 0, (struct sockaddr *)&from, from_length);
    }
}

/* ---- The access point. */
/* True random bytes before the radio runs: esp_random is a pseudo-random sequence until the RF subsystem is on, and the token (and, with
 * CONFIG_TDONGLE_SETUP_AP_OPEN off, the WPA2 password) must not be guessable. The entropy source is only to be enabled while the RF
 * subsystem is not initialised, so this runs before esp_wifi_init. */
static void setup_random(uint8_t *out, size_t n) {
    bootloader_random_enable();
    esp_fill_random(out, n);
    bootloader_random_disable();
}
static esp_err_t start_setup(void) {
    uint8_t random[16 + 16];
    setup_random(random, sizeof(random));
    access_token_format(setup_token, random);
    esp_netif_t *ap = esp_netif_create_default_wifi_ap();
    if (!ap) return ESP_ERR_NO_MEM;
    setup_nets_lock = xSemaphoreCreateMutex();
    setup_nets = calloc(1, sizeof(*setup_nets));
    if (!setup_nets_lock || !setup_nets) return ESP_ERR_NO_MEM;
    wifi_init_config_t w = WIFI_INIT_CONFIG_DEFAULT();
    START_TRY(esp_wifi_init(&w));
    START_TRY(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    START_TRY(esp_wifi_set_mode(WIFI_MODE_APSTA));   /* the station half is idle: it only scans */
    uint8_t mac[6];
    START_TRY(esp_read_mac(mac, ESP_MAC_WIFI_STA));
    setup_ap_ssid(setup_ap_name, sizeof(setup_ap_name), mac);
    wifi_config_t config = {0};
    memcpy(config.ap.ssid, setup_ap_name, strlen(setup_ap_name));
    config.ap.ssid_len = (uint8_t)strlen(setup_ap_name);
    config.ap.channel = 1;
    config.ap.max_connection = 2;
#if CONFIG_TDONGLE_SETUP_AP_OPEN
    /* Owner decision: setup is an open network (a phone joins it with one tap), for at most 10 minutes. */
    config.ap.authmode = WIFI_AUTH_OPEN;
    setup_ap_password[0] = 0;
#else
    for (unsigned i = 0; i < 16; i++) setup_ap_password[i] = "abcdefghijkmnpqrstuvwxyz23456789"[random[16 + i] % 32];
    setup_ap_password[16] = 0;
    memcpy(config.ap.password, setup_ap_password, 16);
    config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    config.ap.pmf_cfg.capable = true;
#endif
    memset(random, 0, sizeof(random));
    START_TRY(esp_wifi_set_config(WIFI_IF_AP, &config));
    /* Name the dongle as the DNS server in the DHCP offer. The options can only be set while the server is stopped, so they are set BEFORE the radio
     * starts: starting the AP then starts the DHCP server (the default netif handler) with them, and nothing races it. No DHCP option 114
     * (RFC 8910): it must point at an HTTPS API with a valid certificate, which an address like 192.168.4.1 cannot have; the DNS hijack plus the
     * redirect is what opens the page. */
    esp_netif_dhcps_stop(ap);   /* already stopped before the AP starts: ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED is fine */
    esp_netif_dns_info_t dns = {.ip.type = IPADDR_TYPE_V4};
    dns.ip.u_addr.ip4.addr = esp_ip4addr_aton("192.168.4.1");
    esp_netif_set_dns_info(ap, ESP_NETIF_DNS_MAIN, &dns);
    dhcps_offer_t offer = OFFER_DNS;
    esp_netif_dhcps_option(ap, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &offer, sizeof(offer));
    START_TRY(esp_wifi_start());
    wifi_power_save_off();   /* a phone waking from its own power save must not wait for the dongle to wake too */
    esp_err_t dhcp = esp_netif_dhcps_start(ap);   /* normally started by the AP-start event already */
    if (dhcp != ESP_OK && dhcp != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) return dhcp;
    if (xTaskCreate(setup_dns_task, "setup_dns", 3072, NULL, 3, NULL) != pdPASS) return ESP_ERR_NO_MEM;
    wifi_ready = true;   /* the Wi-Fi pages of the HTTP server may scan and save */
    return ESP_OK;
}
