#include "cJSON.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_sntp.h"
#include "esp_wifi.h"
#include "gateway.h"
#include "lwip/inet.h"
#include "lwip/tcpip.h"
#include "nvs_flash.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_net.h"
#include <ctype.h>
#include <strings.h>
#include <time.h>
membership_t *members;
esp_netif_t *usb_interface;
SemaphoreHandle_t members_lock;
static void usb_event(tinyusb_event_t *event, void *arg) {
    if (event->id == TINYUSB_EVENT_DETACHED) {
        extern void gateway_usb_detach(void);
        gateway_usb_detach();
    }
}
static bool online;
static bool route_storage_ok;
bool gateway_online(void) { return online; }
static uint32_t next_id = 1;
static nvs_handle_t store;
static wifi_config_t wifi_config;
extern const char setup_html_start[] asm("_binary_setup_html_start");
extern const char setup_html_end[] asm("_binary_setup_html_end");
static bool save_members(void) {
    cJSON *root = cJSON_CreateObject(),
          *list = cJSON_AddArrayToObject(root, "members");
    cJSON_AddNumberToObject(root, "next_id", next_id);
    for (membership_t *m = members; m; m = m->next) {
        cJSON *j = cJSON_CreateObject();
        cJSON_AddNumberToObject(j, "id", m->id);
        cJSON_AddStringToObject(j, "label", m->label);
        cJSON_AddStringToObject(j, "key", m->key);
        cJSON_AddBoolToObject(j, "enabled", m->enabled);
        cJSON_AddItemToArray(list, j);
    }
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json)
        return false;
    if (strlen(json) >= 16384) {
        free(json);
        return false;
    }
    esp_err_t err = nvs_set_str(store, "members", json);
    free(json);
    if (err != ESP_OK)
        return false;
    return nvs_commit(store) == ESP_OK;
}
static void identify(membership_t *m) {
    snprintf(m->ns, sizeof(m->ns), "tn_%08lx", (unsigned long)m->id);
    snprintf(m->hostname, sizeof(m->hostname), "tdongle-%s-%lx", m->label,
             (unsigned long)m->id);
}
static void load_members(void) {
    size_t n = 0;
    if (nvs_get_str(store, "members", NULL, &n) != ESP_OK || n > 16384)
        return;
    char *s = malloc(n);
    if (!s)
        return;
    if (nvs_get_str(store, "members", s, &n) != ESP_OK) {
        free(s);
        return;
    }
    cJSON *root = cJSON_Parse(s);
    free(s);
    if (!root)
        return;
    cJSON *id = cJSON_GetObjectItem(root, "next_id");
    if (cJSON_IsNumber(id) && id->valuedouble > 0 &&
        id->valuedouble < UINT32_MAX)
        next_id = id->valuedouble;
    cJSON *j;
    cJSON_ArrayForEach(j, cJSON_GetObjectItem(root, "members")) {
        cJSON *label = cJSON_GetObjectItem(j, "label"),
              *key = cJSON_GetObjectItem(j, "key"),
              *mid = cJSON_GetObjectItem(j, "id");
        if (!cJSON_IsString(label) || !cJSON_IsString(key) ||
            !cJSON_IsNumber(mid) || mid->valuedouble <= 0)
            continue;
        membership_t *m = calloc(1, sizeof(*m));
        if (!m)
            break;
        m->id = mid->valuedouble;
        strlcpy(m->label, label->valuestring, sizeof(m->label));
        strlcpy(m->key, key->valuestring, sizeof(m->key));
        m->enabled = cJSON_IsTrue(cJSON_GetObjectItem(j, "enabled"));
        identify(m);
        m->next = members;
        members = m;
    }
    cJSON_Delete(root);
}
static bool stop_member(membership_t *m) {
    extern void gateway_suspend(uint32_t id);
    gateway_suspend(m->id);
    if (!m->client)
        return true;
    microlink_stop(m->client);
    if (m->client->stop_incomplete) {
        strlcpy(m->error, "Shutdown is still running; retry after it finishes",
                sizeof(m->error));
        return false;
    }
    microlink_destroy(m->client);
    m->client = NULL;
    return true;
}
static void start_member(membership_t *m) {
    if (!m->enabled || m->client || !online)
        return;
    if (!route_storage_ok) {
        strlcpy(m->error,
                "Routing storage is damaged; tailnet access is disabled",
                sizeof(m->error));
        return;
    }
    /* The reserve covers the bounded shared control workspace's transient
     * ciphertext/JSON/TLS allocations, networking and recovery HTTP service. */
    if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) < 120000 ||
        heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) < 24000) {
        strlcpy(m->error, "Not enough free memory to activate this membership",
                sizeof(m->error));
        return;
    }
    microlink_config_t config = {.identity_namespace = m->ns,
                                 .auth_key = m->key,
                                 .device_name = m->hostname,
                                 .enable_derp = true,
                                 .enable_stun = true,
                                 .enable_disco = true,
                                 .max_peers = 8};
    m->client = microlink_init(&config);
    if (!m->client) {
        strlcpy(m->error, "Could not allocate or save this identity",
                sizeof(m->error));
        return;
    }
    esp_err_t err = microlink_start(m->client);
    if (err != ESP_OK) {
        if (!stop_member(m)) {
            m->enabled = false;
            save_members();
            return;
        }
        snprintf(m->error, sizeof(m->error), "Start failed: %s",
                 esp_err_to_name(err));
        return;
    }
    m->error[0] = 0;
}
static void manager(void *arg) {
    for (;;) {
        if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
            for (membership_t *m = members; m; m = m->next) {
                if(m->client && m->client->stop_incomplete && !stop_member(m)) continue;
                start_member(m);
                if (m->client && m->client->state == ML_STATE_CONNECTED &&
                    m->key[0]) {
                    memset(m->key, 0, sizeof(m->key));
                    if (!save_members())
                        strlcpy(m->error,
                                "Connected; provisioning-key cleanup could not "
                                "be saved",
                                sizeof(m->error));
                }
            }
            xSemaphoreGive(members_lock);
        }
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
static esp_err_t usb_tx(void *handle, void *buffer, size_t len) {
    void *copy = malloc(len);
    if (!copy)
        return ESP_ERR_NO_MEM;
    memcpy(copy, buffer, len);
    esp_err_t err = tinyusb_net_send_sync(copy, len, copy, pdMS_TO_TICKS(50));
    if (err != ESP_OK)
        free(copy);
    return err;
}
static void usb_free_tx(void *buffer, void *ctx) { free(buffer); }
static void usb_free_rx(void *handle, void *buffer) { free(buffer); }
static esp_err_t usb_rx(void *buffer, uint16_t len, void *ctx) {
    void *copy = malloc(len);
    if (!copy)
        return ESP_ERR_NO_MEM;
    memcpy(copy, buffer, len);
    return esp_netif_receive(usb_interface, copy, len, NULL);
}
static void wifi_event(void *arg, esp_event_base_t base, int32_t event,
                       void *data) {
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_START &&
        wifi_config.sta.ssid[0])
        esp_wifi_connect();
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_DISCONNECTED) {
        online = false;
        if (wifi_config.sta.ssid[0])
            esp_wifi_connect();
    }
    if (base == IP_EVENT && event == IP_EVENT_STA_GOT_IP) {
        online = true;
    }
}
static esp_err_t json_reply(httpd_req_t *req, cJSON *j) {
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Out of memory");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_sendstr(req, s);
    free(s);
    return err;
}
static esp_err_t failure(httpd_req_t *req, const char *message) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddBoolToObject(j, "ok", false);
    cJSON_AddStringToObject(j, "error", message);
    httpd_resp_set_status(req, "400 Bad Request");
    return json_reply(req, j);
}
static bool usb_peer_address(const struct sockaddr *address, socklen_t length) {
    uint32_t ipv4;
    if (address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        ipv4 = ((const struct sockaddr_in *)address)->sin_addr.s_addr;
    } else if (address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        const uint8_t *bytes = (const uint8_t *)&((const struct sockaddr_in6 *)address)->sin6_addr;
        static const uint8_t mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (memcmp(bytes, mapped_prefix, sizeof(mapped_prefix))) return false;
        memcpy(&ipv4, bytes + 12, sizeof(ipv4));
    } else return false;
    return (ntohl(ipv4) & 0xffffff00) == 0xc0a84d00;
}
static bool local_request(httpd_req_t *req) {
    /* HTTPD uses a dual-stack socket: IPv4 clients may be IPv4-mapped IPv6. */
    struct sockaddr_storage peer = {0};
    socklen_t n = sizeof(peer);
    if (getpeername(httpd_req_to_sockfd(req), (struct sockaddr *)&peer, &n) != 0 ||
        !usb_peer_address((const struct sockaddr *)&peer, n)) return false;
    char host[64], origin[96];
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK)
        return false;
    if (strcmp(host, "192.168.77.1") && strcmp(host, "192.168.77.1:80"))
        return false;
    if (httpd_req_get_hdr_value_len(req, "Origin")) {
        if (httpd_req_get_hdr_value_str(req, "Origin", origin,
                                        sizeof(origin)) != ESP_OK)
            return false;
        if (strcmp(origin, "http://192.168.77.1") &&
            strcmp(origin, "http://192.168.77.1:80"))
            return false;
    }
    return true;
}
static esp_err_t home(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(
            req, HTTPD_403_FORBIDDEN,
            "Open this page through USB Ethernet at 192.168.77.1");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Security-Policy",
                       "default-src 'self'; script-src 'unsafe-inline'; "
                       "style-src 'unsafe-inline'; "
                       "connect-src 'self'; frame-ancestors 'none'");
    return httpd_resp_send(req, setup_html_start,
                           setup_html_end - setup_html_start);
}
static esp_err_t status(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                                   "USB access required");
    if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(1000)) != pdTRUE)
        return failure(req, "Memberships are busy; retry shortly");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "wifi", online);
    cJSON_AddBoolToObject(root, "route_storage_ok", route_storage_ok);
    cJSON_AddNumberToObject(root, "free_memory", esp_get_free_heap_size());
    cJSON *list = cJSON_AddArrayToObject(root, "members");
    for (membership_t *m = members; m; m = m->next) {
        cJSON *j = cJSON_CreateObject();
        cJSON_AddNumberToObject(j, "id", m->id);
        cJSON_AddStringToObject(j, "label", m->label);
        cJSON_AddBoolToObject(j, "enabled", m->enabled);
        cJSON_AddStringToObject(j, "error", m->error);
        cJSON_AddNumberToObject(j, "state", m->client ? m->client->state : 0);
        if (m->client) {
            cJSON_AddStringToObject(j, "login_url", m->client->auth_url);
            cJSON_AddStringToObject(j, "protocol_error",
                                    m->client->last_error[0]
                                        ? m->client->last_error
                                        : m->client->transport_error);
            cJSON *peers = cJSON_AddArrayToObject(j, "peers");
            for (int i = 0; i < m->client->peer_count; i++) {
                ml_peer_t *p = &m->client->peers[i];
                if (!p->vpn_ip)
                    continue;
                cJSON *jp = cJSON_CreateObject();
                cJSON_AddStringToObject(jp, "name", p->hostname);
                char short_name[64], qualified[128];
                strlcpy(short_name, p->hostname, sizeof(short_name));
                char *dot = strchr(short_name, '.');
                if (dot)
                    *dot = 0;
                snprintf(qualified, sizeof(qualified), "%s.%s.tailnet",
                         short_name, m->label);
                cJSON_AddStringToObject(jp, "qualifiedName", qualified);
                uint32_t alias = gateway_alias(m->id, p->vpn_ip);
                char ip[16];
                snprintf(ip, sizeof(ip), "%lu.%lu.%lu.%lu",
                         (unsigned long)(alias >> 24),
                         (unsigned long)((alias >> 16) & 255),
                         (unsigned long)((alias >> 8) & 255),
                         (unsigned long)(alias & 255));
                cJSON_AddStringToObject(jp, "address", ip);
                cJSON_AddItemToArray(peers, jp);
            }
        }
        cJSON_AddItemToArray(list, j);
    }
    xSemaphoreGive(members_lock);
    return json_reply(req, root);
}
static esp_err_t command(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                                   "USB access required");
    char type[64];
    if (httpd_req_get_hdr_value_str(req, "Content-Type", type, sizeof(type)) !=
            ESP_OK ||
        strcmp(type, "application/json"))
        return failure(req, "JSON required");
    if (req->content_len <= 0 || req->content_len > 1024)
        return failure(req, "Request is too large");
    char body[1025];
    size_t used = 0;
    while (used < req->content_len) {
        int n = httpd_req_recv(req, body + used, req->content_len - used);
        if (n <= 0)
            return failure(req, "Incomplete request");
        used += n;
    }
    body[used] = 0;
    cJSON *j = cJSON_Parse(body);
    if (!j)
        return failure(req, "Invalid JSON");
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(j, "action"));
    const char *error = NULL;
    if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        cJSON_Delete(j);
        return failure(req, "Memberships are busy; retry shortly");
    }
    if (action && !strcmp(action, "wifi")) {
        const char *ssid = cJSON_GetStringValue(cJSON_GetObjectItem(j, "ssid")),
                   *password =
                       cJSON_GetStringValue(cJSON_GetObjectItem(j, "password"));
        if (!ssid || !password || !strlen(ssid) || strlen(ssid) > 32 ||
            strlen(password) > 63)
            error = "Enter a valid Wi-Fi name and password";
        else {
            wifi_config_t candidate = {0};
            memcpy(candidate.sta.ssid, ssid, strlen(ssid));
            memcpy(candidate.sta.password, password, strlen(password));
            if (nvs_set_blob(store, "wifi", &candidate, sizeof(candidate)) !=
                    ESP_OK ||
                nvs_commit(store) != ESP_OK)
                error = "Wi-Fi could not be saved";
            else {
                wifi_config = candidate;
                esp_wifi_disconnect();
                esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
                esp_wifi_connect();
            }
        }
    } else if (action && !strcmp(action, "add")) {
        const char *label =
                       cJSON_GetStringValue(cJSON_GetObjectItem(j, "label")),
                   *key = cJSON_GetStringValue(cJSON_GetObjectItem(j, "key"));
        if (!key)
            key = "";
        if (!label || !strlen(label) || strlen(label) > 20 ||
            strlen(key) >= 160)
            error = "Use a short label and valid auth key";
        else {
            for (const char *s = label; *s; s++)
                if (!isalnum((unsigned char)*s) && *s != '-')
                    error = "Labels use letters, numbers and hyphens";
            for (membership_t *m = members; m; m = m->next)
                if (!strcasecmp(m->label, label))
                    error = "That label is already saved";
        }
        if (!error) {
            membership_t *m = calloc(1, sizeof(*m));
            if (!m || !next_id || next_id == UINT32_MAX) {
                free(m);
                error = "Cannot allocate another membership";
            } else {
                m->id = next_id++;
                strlcpy(m->label, label, sizeof(m->label));
                strlcpy(m->key, key, sizeof(m->key));
                m->enabled = true;
                identify(m);
                m->next = members;
                members = m;
                if (!save_members()) {
                    members = m->next;
                    next_id--;
                    free(m);
                    error = "Membership could not be saved";
                }
            }
        }
    } else if (action &&
               (!strcmp(action, "remove") || !strcmp(action, "enable"))) {
        cJSON *id = cJSON_GetObjectItem(j, "id");
        membership_t **link = &members;
        while (*link && (!cJSON_IsNumber(id) || (*link)->id != id->valuedouble))
            link = &(*link)->next;
        membership_t *m = *link;
        if (!m)
            error = "Membership not found";
        else if (!strcmp(action, "enable")) {
            bool old = m->enabled;
            m->enabled = cJSON_IsTrue(cJSON_GetObjectItem(j, "enabled"));
            if (!save_members()) {
                m->enabled = old;
                error = "Change could not be saved";
            } else if (!m->enabled && m->client) {
                if (!stop_member(m))
                    error = "Disconnect is still finishing; retry shortly";
                else
                    m->error[0] = 0;
            }
        } else {
            m->enabled = false;
            if (!stop_member(m)) {
                save_members();
                error = "Removal is waiting for shutdown; retry shortly";
            } else {
                *link = m->next;
                if (!save_members()) {
                    *link = m;
                    error = "Removal could not be saved";
                } else {
                    gateway_forget(m->id);
                    nvs_handle_t identity;
                    esp_err_t erase = nvs_open(m->ns, NVS_READWRITE, &identity);
                    if (erase == ESP_OK) {
                        erase = nvs_erase_all(identity);
                        if (erase == ESP_OK)
                            erase = nvs_commit(identity);
                        nvs_close(identity);
                    }
                    if (erase != ESP_OK)
                        error = "Membership removed, but stored identity "
                                "cleanup failed";
                    memset(m->key, 0, sizeof(m->key));
                    free(m);
                }
            }
        }
    } else
        error = "Unknown action";
    xSemaphoreGive(members_lock);
    cJSON_Delete(j);
    memset(body, 0, sizeof(body));
    if (error)
        return failure(req, error);
    cJSON *ok = cJSON_CreateObject();
    cJSON_AddBoolToObject(ok, "ok", true);
    return json_reply(req, ok);
}
void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(nvs_open("tn_settings", NVS_READWRITE, &store));
    members_lock = xSemaphoreCreateMutex();
    load_members();
    extern bool gateway_routes_init(void);
    route_storage_ok = gateway_routes_init();
    size_t n = sizeof(wifi_config);
    nvs_get_blob(store, "wifi", &wifi_config, &n);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t w = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&w));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                               wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                               wifi_event, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_netif_ip_info_t ip = {0};
    IP4_ADDR(&ip.ip, 192, 168, 77, 1);
    ip.gw = ip.ip;
    IP4_ADDR(&ip.netmask, 255, 255, 255, 0);
    esp_netif_inherent_config_t base = ESP_NETIF_INHERENT_DEFAULT_ETH();
    base.flags = ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP;
    base.ip_info = &ip;
    base.if_key = "USB";
    base.if_desc = "usb";
    base.route_prio = 0;
    esp_netif_driver_ifconfig_t driver = {.handle = &usb_interface,
                                          .transmit = usb_tx,
                                          .driver_free_rx_buffer = usb_free_rx};
    esp_netif_config_t config = {.base = &base,
                                 .driver = &driver,
                                 .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH};
    usb_interface = esp_netif_new(&config);
    assert(usb_interface);
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    mac[0] = (mac[0] | 2) & ~1;
    esp_netif_set_mac(usb_interface, mac);
    static char serial[13];
    uint8_t identity_mac[6];
    esp_read_mac(identity_mac, ESP_MAC_WIFI_STA);
    snprintf(serial, sizeof(serial), "%02X%02X%02X%02X%02X%02X",
             identity_mac[0], identity_mac[1], identity_mac[2], identity_mac[3],
             identity_mac[4], identity_mac[5]);
    static const char language[] = {0x09, 0x04};
    static const char *strings[] = {language,
                                    "T-Dongle Adapter Project",
                                    "T-Dongle-S3 tailnet gateway",
                                    serial,
                                    "Management",
                                    "USB network",
                                    ""};
    tinyusb_config_t usb = TINYUSB_DEFAULT_CONFIG();
    usb.event_cb = usb_event;
    usb.descriptor.string = strings;
    usb.descriptor.string_count = sizeof(strings) / sizeof(strings[0]);
    ESP_ERROR_CHECK(tinyusb_driver_install(&usb));
    tinyusb_net_config_t net = {.on_recv_callback = usb_rx,
                                .free_tx_buffer = usb_free_tx};
    memcpy(net.mac_addr, mac, 6);
    ESP_ERROR_CHECK(tinyusb_net_init(&net));
    extern void gateway_console_start(void);
    gateway_console_start();
    esp_netif_dns_info_t dns = {0};
    IP_SET_TYPE_VAL(dns.ip, IPADDR_TYPE_V4);
    IP4_ADDR(ip_2_ip4(&dns.ip), 192, 168, 77, 1);
    ESP_ERROR_CHECK(
        esp_netif_set_dns_info(usb_interface, ESP_NETIF_DNS_MAIN, &dns));
    uint8_t offer = 1;
    ESP_ERROR_CHECK(esp_netif_dhcps_option(usb_interface, ESP_NETIF_OP_SET,
                                           ESP_NETIF_DOMAIN_NAME_SERVER, &offer,
                                           sizeof(offer)));
    esp_netif_action_start(usb_interface, NULL, 0, NULL);
    esp_netif_action_connected(usb_interface, NULL, 0, NULL);
    ESP_ERROR_CHECK(esp_netif_napt_enable(usb_interface));
    extern void gateway_dns_start(void);
    gateway_dns_start();
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();
    httpd_config_t http = HTTPD_DEFAULT_CONFIG();
    http.stack_size = 6144;
    http.max_uri_handlers = 4;
    httpd_handle_t server;
    ESP_ERROR_CHECK(httpd_start(&server, &http));
    httpd_uri_t page = {.uri = "/", .method = HTTP_GET, .handler = home},
                state = {.uri = "/status",
                         .method = HTTP_GET,
                         .handler = status},
                api = {
                    .uri = "/command", .method = HTTP_POST, .handler = command};
    httpd_register_uri_handler(server, &page);
    httpd_register_uri_handler(server, &state);
    httpd_register_uri_handler(server, &api);
    xTaskCreate(manager, "members", 4096, NULL, 4, NULL);
}
