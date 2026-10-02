#include "esp_log.h"
#include "cJSON.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "gateway.h"
#include "socket_budget.h"
#include "esp_system.h"
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
static volatile bool wifi_scan_pauses_reconnect;
static SemaphoreHandle_t wifi_scan_lock;
static bool route_storage_ok;
bool gateway_online(void) { return online; }
static uint32_t next_id = 1;
static nvs_handle_t store;
static nvs_handle_t diag_store;
static SemaphoreHandle_t diag_lock;
enum { DIAG_RING_MAGIC = 0x54444732, DIAG_RING_COUNT = 8 };
typedef struct {
    uint32_t uptime_ms, member_id, event, detail, state, map_attempts;
    uint32_t map_bytes, map_error, h2_error, h2_stream, heap_free, heap_largest;
    char reason[64], h2_debug[49];
    uint32_t stage, noise_error, noise_frame_bytes, reset_reason, wifi;
    uint32_t sockets_open, sockets_peak, socket_failures, socket_errno, socket_operation;
} gateway_diag_record_t;
typedef struct {
    uint32_t magic;
    uint8_t count, next;
    gateway_diag_record_t entries[DIAG_RING_COUNT];
} gateway_diag_ring_t;
/* Import the previous small journal on firmware update without erasing NVS. */
static void gateway_diag_load(gateway_diag_ring_t *ring) {
    memset(ring, 0, sizeof(*ring)); ring->magic = DIAG_RING_MAGIC;
    size_t length = sizeof(*ring);
    if (nvs_get_blob(diag_store, "events2", ring, &length) == ESP_OK &&
        length == sizeof(*ring) && ring->magic == DIAG_RING_MAGIC &&
        ring->count <= DIAG_RING_COUNT && ring->next < DIAG_RING_COUNT) return;
    memset(ring, 0, sizeof(*ring)); ring->magic = DIAG_RING_MAGIC;
    struct { uint32_t magic; uint8_t count, next; uint32_t entries[8][12]; } old;
    length = sizeof(old);
    if (nvs_get_blob(diag_store, "events", &old, &length) == ESP_OK &&
        length == sizeof(old) && old.magic == 0x54444731 && old.count <= 8 && old.next < 8) {
        ring->count = old.count; ring->next = old.next;
        for (unsigned i = 0; i < 8; i++) memcpy(&ring->entries[i], old.entries[i], sizeof(old.entries[i]));
    }
}
static void gateway_diag_write(const microlink_t *ml, uint32_t member_id,
                               uint32_t event, uint32_t detail) {
    if (!diag_lock || xSemaphoreTake(diag_lock, pdMS_TO_TICKS(20)) != pdTRUE) return;
    gateway_diag_ring_t *ring = malloc(sizeof(*ring));
    if (!ring) { xSemaphoreGive(diag_lock); return; }
    gateway_diag_load(ring);
    uint32_t uptime = (uint32_t)(esp_timer_get_time() / 1000);
    for (unsigned i = 0; event != GATEWAY_DIAG_BOOT && event != GATEWAY_DIAG_UPSTREAM && i < ring->count; i++) {
        gateway_diag_record_t *prev = &ring->entries[i];
        if (prev->member_id == member_id && prev->event == event &&
            prev->detail == detail && (uint32_t)(uptime - prev->uptime_ms) < 30000) {
            free(ring); xSemaphoreGive(diag_lock); return;
        }
    }
    gateway_socket_stats sockets = gateway_sockets_snapshot();
    gateway_diag_record_t *entry = &ring->entries[ring->next];
    *entry = (gateway_diag_record_t){
        .uptime_ms = uptime, .member_id = member_id, .event = event, .detail = detail,
        .state = ml ? ml->state : 0, .map_attempts = ml ? ml->map_attempts : 0,
        .map_bytes = ml ? ml->map_bytes : 0, .map_error = ml ? ml->map_error : 0,
        .h2_error = ml ? ml->map_h2_error : 0, .h2_stream = ml ? ml->map_h2_last_stream : 0,
        .stage = ml ? ml->control_stage : 0, .noise_error = ml ? ml->noise_error : 0,
        .noise_frame_bytes = ml ? ml->noise_frame_bytes : 0,
        .heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
        .heap_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
        .reset_reason = esp_reset_reason(), .wifi = online,
        .sockets_open = sockets.open, .sockets_peak = sockets.peak,
        .socket_failures = sockets.failures, .socket_errno = sockets.last_errno,
        .socket_operation = sockets.last_operation};
    if (ml) {
        strlcpy(entry->reason, ml->transport_error, sizeof(entry->reason));
        for (unsigned i=0; entry->reason[i]; i++)
            if (entry->reason[i] == '"' || entry->reason[i] == '\\' || (unsigned char)entry->reason[i] < 32)
                entry->reason[i] = ' ';
        strlcpy(entry->h2_debug, ml->h2_debug, sizeof(entry->h2_debug));
    }
    ring->next = (ring->next + 1) % DIAG_RING_COUNT;
    if (ring->count < DIAG_RING_COUNT) ring->count++;
    if (nvs_set_blob(diag_store, "events2", ring, sizeof(*ring)) == ESP_OK)
        nvs_commit(diag_store);
    free(ring);
    xSemaphoreGive(diag_lock);
}
void gateway_diag_record(const microlink_t *ml, uint32_t event, uint32_t detail) {
    if (ml) gateway_diag_write(ml, ml->config.diagnostic_id, event, detail);
}
void gateway_diag_membership(uint32_t member_id, uint32_t event, uint32_t detail) {
    gateway_diag_write(NULL, member_id, event, detail);
}
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
        cJSON_AddNumberToObject(j,"start_heap_before",m->start_heap_before);cJSON_AddNumberToObject(j,"start_heap_after",m->start_heap_after);
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
/* Account for the allocations requested by microlink_init/start, plus
 * allocator/task bookkeeping and 16 KiB retained for HTTP/control recovery.
 * Shared registration/map byte buffers are static, not charged per member. */
static size_t member_start_budget(void) {
    size_t tasks = ML_TASK_NET_IO_STACK + 2 * ML_TASK_DERP_TX_STACK +
                   ML_TASK_COORD_STACK + ML_TASK_WG_MGR_STACK;
    size_t queues = ML_DERP_TX_QUEUE_DEPTH * sizeof(ml_derp_tx_item_t) +
                    (ML_DISCO_RX_QUEUE_DEPTH + ML_WG_RX_QUEUE_DEPTH +
                     ML_STUN_RX_QUEUE_DEPTH) * sizeof(ml_rx_packet_t) +
                    ML_COORD_CMD_QUEUE_DEPTH * sizeof(ml_coord_cmd_t) +
                    ML_PEER_UPDATE_QUEUE_DEPTH * sizeof(ml_peer_update_t *);
    return sizeof(microlink_t) + tasks + queues + 6 * sizeof(StaticQueue_t) +
           5 * sizeof(StaticTask_t) + 2048 + 16384;
}
static void start_member(membership_t *m) {
    if (!m->enabled || m->client || !online)
        return;
    if (!route_storage_ok) {
        strlcpy(m->error,
                "Routing storage is damaged; tailnet access is disabled",
                sizeof(m->error));
        gateway_diag_membership(m->id, GATEWAY_DIAG_START_BLOCKED, 1);
        return;
    }
    /* Reserve for parsed JSON, networking and recovery HTTP. Shared receive
     * buffers are static. Runtime peak sufficiency needs board qualification. */
    if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) < member_start_budget() ||
        heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL) < 24000) {
        strlcpy(m->error, "Not enough free memory to activate this membership",
                sizeof(m->error));
        gateway_diag_membership(m->id, GATEWAY_DIAG_START_BLOCKED, 2);
        return;
    }
    unsigned active = 0;
    for (membership_t *other = members; other; other = other->next)
        if (other->client) active++;
    gateway_socket_stats sockets = gateway_sockets_snapshot();
    if (!gateway_socket_admit(CONFIG_LWIP_MAX_SOCKETS, active, sockets.open)) {
        strlcpy(m->error, "Socket capacity reserved for USB setup and DNS", sizeof(m->error));
        gateway_diag_membership(m->id, GATEWAY_DIAG_START_BLOCKED, 3);
        return;
    }
    gateway_diag_membership(m->id, GATEWAY_DIAG_START_ATTEMPT, 0);
    microlink_config_t config = {.identity_namespace = m->ns,
                                 .auth_key = m->key,
                                 .device_name = m->hostname,
                                 .enable_derp = true,
                                 .enable_stun = true,
                                 .enable_disco = true,
                                 .max_peers = 8,
                                 .diagnostic_id = m->id};
    m->start_heap_before=heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    m->client = microlink_init(&config);
    if (!m->client) {
        strlcpy(m->error, "Could not allocate or save this identity",
                sizeof(m->error));
        gateway_diag_membership(m->id, GATEWAY_DIAG_START_FAILED, 1);
        return;
    }
    esp_err_t err = microlink_start(m->client);
    m->start_heap_after=heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (err != ESP_OK) {
        gateway_diag_record(m->client, GATEWAY_DIAG_START_FAILED, err);
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
    unsigned last_socket_failures = 0;
    bool last_online = !online;
    for (;;) {
        if (last_online != online) {
            gateway_diag_membership(0, GATEWAY_DIAG_UPSTREAM, online);
            last_online = online;
        }
        gateway_socket_stats sockets = gateway_sockets_snapshot();
        if (sockets.failures != last_socket_failures) {
            gateway_diag_membership(0, GATEWAY_DIAG_SOCKET_FAILURE, sockets.last_errno);
            last_socket_failures = sockets.failures;
        }
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
        if (wifi_config.sta.ssid[0] && !wifi_scan_pauses_reconnect)
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
static bool local_request(httpd_req_t *req);
static void wifi_scan_resume(bool was_connected) {
    wifi_scan_pauses_reconnect = false;
    wifi_ap_record_t current = {0};
    if (wifi_config.sta.ssid[0] &&
        (!was_connected || esp_wifi_sta_get_ap_info(&current) != ESP_OK))
        esp_wifi_connect();
}
static esp_err_t wifi_scan(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                                   "USB access required");
    if (xSemaphoreTake(wifi_scan_lock, 0) != pdTRUE)
        return failure(req, "A Wi-Fi scan is already running");

    wifi_ap_record_t current = {0};
    bool connected = esp_wifi_sta_get_ap_info(&current) == ESP_OK;
    wifi_scan_pauses_reconnect = true;
    if (!connected) {
        /* Stop a failed saved-network reconnect loop so it cannot starve a scan. */
        esp_wifi_disconnect();
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    wifi_scan_config_t config = {
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .show_hidden = false,
        .scan_time.active = {.min = 100, .max = 250},
    };
    esp_err_t result = esp_wifi_scan_start(&config, true);
    if (result != ESP_OK) {
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return failure(req, result == ESP_ERR_WIFI_STATE
                                ? "Wi-Fi is still connecting. Wait a moment, then scan again."
                                : "The dongle could not scan for Wi-Fi. Try again.");
    }

    uint16_t total = 0;
    if (esp_wifi_scan_get_ap_num(&total) != ESP_OK) {
        esp_wifi_clear_ap_list();
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return failure(req, "The Wi-Fi scan finished without readable results. Try again.");
    }

    enum { WIFI_SCAN_RESULT_LIMIT = 12 };
    uint16_t count = total < WIFI_SCAN_RESULT_LIMIT ? total : WIFI_SCAN_RESULT_LIMIT;
    wifi_ap_record_t *records = count ? calloc(count, sizeof(*records)) : NULL;
    if (count && !records) {
        esp_wifi_clear_ap_list();
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return failure(req, "The dongle is low on memory. Try the scan again.");
    }
    if (count && esp_wifi_scan_get_ap_records(&count, records) != ESP_OK) {
        free(records);
        esp_wifi_clear_ap_list();
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return failure(req, "The Wi-Fi scan finished without readable results. Try again.");
    }
    if (!count)
        esp_wifi_clear_ap_list();

    cJSON *response = cJSON_CreateObject();
    cJSON *networks = cJSON_CreateArray();
    if (!response || !networks) {
        cJSON_Delete(response);
        cJSON_Delete(networks);
        free(records);
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Out of memory returning Wi-Fi scan");
    }
    bool json_ok = cJSON_AddBoolToObject(response, "ok", true) &&
                   cJSON_AddNumberToObject(response, "count", count) &&
                   cJSON_AddBoolToObject(response, "truncated", total > count) &&
                   cJSON_AddItemToObject(response, "networks", networks);
    for (uint16_t i = 0; i < count; i++) {
        if (!json_ok)
            break;
        cJSON *network = cJSON_CreateObject();
        json_ok = network &&
                  cJSON_AddStringToObject(network, "ssid",
                                          (const char *)records[i].ssid) &&
                  cJSON_AddNumberToObject(network, "rssi", records[i].rssi) &&
                  cJSON_AddBoolToObject(network, "secure",
                                        records[i].authmode != WIFI_AUTH_OPEN) &&
                  cJSON_AddItemToArray(networks, network);
        if (!json_ok)
            cJSON_Delete(network);
    }
    free(records);
    wifi_scan_resume(connected);
    xSemaphoreGive(wifi_scan_lock);
    if (!json_ok) {
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Out of memory returning Wi-Fi scan");
    }
    return json_reply(req, response);
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
static esp_err_t diagnostics(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "USB access required");
    gateway_diag_ring_t ring = {.magic = DIAG_RING_MAGIC};
    bool available = false;
    if (diag_lock && xSemaphoreTake(diag_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        gateway_diag_load(&ring); available = true;
        xSemaphoreGive(diag_lock);
    }
    httpd_resp_set_type(req, "application/json");
    char prefix[64];
    int prefix_len = snprintf(prefix, sizeof(prefix),
                              "{\"schema\":2,\"available\":%s,\"events\":[",
                              available ? "true" : "false");
    if (prefix_len < 0 || prefix_len >= sizeof(prefix) ||
        httpd_resp_send_chunk(req, prefix, prefix_len) != ESP_OK)
        return ESP_FAIL;
    char row[1024];
    unsigned first = (ring.next + DIAG_RING_COUNT - ring.count) % DIAG_RING_COUNT;
    for (unsigned i = 0; i < ring.count; i++) {
        gateway_diag_record_t *e = &ring.entries[(first + i) % DIAG_RING_COUNT];
        int n = snprintf(row, sizeof(row),
            "%s{\"uptime_ms\":%lu,\"member_id\":%lu,\"event\":%lu,\"detail\":%lu,\"state\":%lu,\"map_attempts\":%lu,\"map_bytes\":%lu,\"map_error\":%lu,\"h2_error\":%lu,\"h2_stream\":%lu,\"free_memory\":%lu,\"largest_free_block\":%lu,\"control_stage\":%lu,\"noise_error\":%lu,\"noise_frame_bytes\":%lu,\"reset_reason\":%lu,\"wifi\":%lu,\"sockets_open\":%lu,\"sockets_peak\":%lu,\"socket_failures\":%lu,\"socket_errno\":%lu,\"socket_operation\":%lu,\"reason\":\"%s\",\"h2_debug\":\"%s\"}",
            i ? "," : "", (unsigned long)e->uptime_ms,
            (unsigned long)e->member_id, (unsigned long)e->event,
            (unsigned long)e->detail, (unsigned long)e->state,
            (unsigned long)e->map_attempts, (unsigned long)e->map_bytes,
            (unsigned long)e->map_error, (unsigned long)e->h2_error,
            (unsigned long)e->h2_stream, (unsigned long)e->heap_free,
            (unsigned long)e->heap_largest, (unsigned long)e->stage,
            (unsigned long)e->noise_error, (unsigned long)e->noise_frame_bytes,
            (unsigned long)e->reset_reason, (unsigned long)e->wifi,
            (unsigned long)e->sockets_open, (unsigned long)e->sockets_peak,
            (unsigned long)e->socket_failures, (unsigned long)e->socket_errno,
            (unsigned long)e->socket_operation, e->reason, e->h2_debug);
        if (n < 0 || n >= sizeof(row) || httpd_resp_send_chunk(req, row, n) != ESP_OK)
            return ESP_FAIL;
    }
    esp_err_t ret = httpd_resp_send_chunk(req, "]}", 2);
    if (ret != ESP_OK) return ret;
    return httpd_resp_send_chunk(req, NULL, 0);
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
#include "json_writer.inc"
typedef struct {
    uint32_t id, state, vpn_ip;
    size_t start_heap_before, start_heap_after;
    bool enabled, has_client, routing_ready;
    char label[24], error[64], dns[128], login[384], protocol_error[64], h2_debug[49];
    unsigned control_stage;
    uint32_t diagnostics[16], stack_free[5];
    unsigned peers, directory_count, peer_offset, page_start;
    uint32_t jit[5];
    struct {
        char name[64];
        uint32_t address;
    } peer[ML_MAX_PEERS];
} status_member;
static int status_chunk(void *context, const char *bytes, size_t length) {
    return httpd_resp_send_chunk(context, bytes, length) == ESP_OK ? 0 : -1;
}
static esp_err_t status_busy(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Retry-After", "1");
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(
        req,
        "{\"ok\":false,\"error\":\"Memberships are busy; retry shortly\"}");
}
static esp_err_t status(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                                   "USB access required");
    /* Allocate outside the lock, then re-count to tolerate add/remove races.
     * No member/client pointers escape the lifetime lock. */
    if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(20)) != pdTRUE)
        return status_busy(req);
    size_t capacity = 0;
    for (membership_t *m = members; m; m = m->next)
        capacity++;
    xSemaphoreGive(members_lock);
    if (capacity > SIZE_MAX / sizeof(status_member))
        return status_busy(req);
    status_member *snapshot =
        capacity ? calloc(capacity, sizeof(*snapshot)) : NULL;
    if (capacity && !snapshot)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Out of memory taking setup snapshot");
    if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(20)) != pdTRUE) {
        free(snapshot);
        return status_busy(req);
    }
    unsigned peer_offset=0,peer_member=0;char query[64]={0},offset_text[16];
    if(httpd_req_get_url_query_str(req,query,sizeof(query))==ESP_OK &&
       httpd_query_key_value(query,"peer_offset",offset_text,sizeof(offset_text))==ESP_OK)
        peer_offset=strtoul(offset_text,NULL,10);
    if(httpd_query_key_value(query,"peer_member",offset_text,sizeof(offset_text))==ESP_OK)
        peer_member=strtoul(offset_text,NULL,10);
    if(peer_offset>100000)peer_offset=0;
    size_t count = 0;
    for (membership_t *m = members; m; m = m->next) {
        if (count == capacity) {
            xSemaphoreGive(members_lock);
            free(snapshot);
            return status_busy(req);
        }
        status_member *v = &snapshot[count++];
        v->id = m->id;
        v->enabled = m->enabled;
        v->start_heap_before = m->start_heap_before;
        v->start_heap_after = m->start_heap_after;
        strlcpy(v->label, m->label, sizeof(v->label));
        strlcpy(v->error, m->error, sizeof(v->error));
        microlink_t *c = m->client;
        if (!c)
            continue;
        v->has_client = true;
        v->state = c->state;
        v->vpn_ip = c->vpn_ip;
        v->routing_ready = m->enabled && c->wg_netif &&
                           c->state == ML_STATE_CONNECTED && !c->key_expired &&
                           !c->last_error[0] && c->directory.session_valid;
        strlcpy(v->dns, c->self_dns_name, sizeof(v->dns));
        strlcpy(v->login, c->auth_url, sizeof(v->login));
        strlcpy(v->protocol_error,
                c->last_error[0] ? c->last_error : c->transport_error,
                sizeof(v->protocol_error));
        strlcpy(v->h2_debug,c->h2_debug,sizeof(v->h2_debug));v->control_stage=c->control_stage;
        v->diagnostics[0] = c->map_attempts;
        v->diagnostics[1] = c->map_failures;
        v->diagnostics[2] = c->map_error;
        v->diagnostics[3] = c->map_bytes;
        v->diagnostics[4] = c->map_declared_bytes;
        v->diagnostics[5] = c->map_projected_bytes;
        v->diagnostics[6] = c->map_heap_before;
        v->diagnostics[7] = c->map_heap_after;
        v->diagnostics[8] = c->map_largest_before;
        v->diagnostics[9] = c->map_stream_id;
        v->diagnostics[10] = c->map_frame_type;
        v->diagnostics[11] = c->noise_error;
        v->diagnostics[12] = c->noise_frame_bytes;
        v->diagnostics[13] = c->map_generation;
        v->diagnostics[14] = c->map_h2_error;
        v->diagnostics[15] = c->map_h2_last_stream;
        TaskHandle_t tasks[5] = {c->net_io_task, c->derp_tx_task,
                                 c->derp_rx_task, c->coord_task,
                                 c->wg_mgr_task};
        for (unsigned t = 0; t < 5; t++) {
            v->stack_free[t]=UINT32_MAX;
            if (tasks[t] && !c->stop_incomplete)
                v->stack_free[t] = uxTaskGetStackHighWaterMark(tasks[t]);
        }
        uint32_t peer_generation=__atomic_load_n(&c->peer_generation,__ATOMIC_ACQUIRE);
        if(peer_generation&1){xSemaphoreGive(members_lock);free(snapshot);return status_busy(req);}
        uint32_t directory_generation=__atomic_load_n(&c->directory.generation,__ATOMIC_ACQUIRE);
        v->jit[0]=c->jit_hits;v->jit[1]=c->jit_misses;v->jit[2]=c->jit_evictions;
        v->jit[3]=c->jit_rejected;v->jit[4]=c->jit_dropped;
        v->directory_count=c->directory.count;v->page_start=peer_member==m->id?peer_offset:0;v->peer_offset=v->page_start;
        for(unsigned i=v->page_start;i<c->directory.count && v->peers<ML_MAX_PEERS;i++) {
            ml_peer_update_t record;
            if(!ml_directory_at(c,i,&record))continue;
            unsigned j=v->peers++;
            strlcpy(v->peer[j].name,record.hostname,sizeof(v->peer[j].name));
            v->peer[j].address=record.vpn_ip;
            v->peer_offset=i+1;
        }
        if(peer_generation!=__atomic_load_n(&c->peer_generation,__ATOMIC_ACQUIRE) || directory_generation!=__atomic_load_n(&c->directory.generation,__ATOMIC_ACQUIRE)){xSemaphoreGive(members_lock);free(snapshot);return status_busy(req);}
        for(unsigned j=0;j<v->peers;j++)v->peer[j].address=gateway_alias(m->id,v->peer[j].address);
    }
    xSemaphoreGive(members_lock);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    jw_writer writer = {.context = req, .sink = status_chunk};
    jw_writer *w = &writer;
    jw_raw(w, "{");
#define NUM(name, value)                                                       \
    do {                                                                       \
        jw_key(w, name);                                                       \
        jw_number(w, value);                                                   \
        jw_char(w, ',');                                                       \
    } while (0)
#define STR(name, value)                                                       \
    do {                                                                       \
        jw_key(w, name);                                                       \
        jw_string(w, value);                                                   \
        jw_char(w, ',');                                                       \
    } while (0)
#define BOOL(name, value)                                                      \
    do {                                                                       \
        jw_key(w, name);                                                       \
        jw_bool(w, value);                                                     \
        jw_char(w, ',');                                                       \
    } while (0)
    STR("firmware", "0.2.11");
    NUM("membership_start_budget", member_start_budget());
    NUM("membership_context_bytes", sizeof(microlink_t));
    gateway_socket_stats sockets = gateway_sockets_snapshot();
    NUM("socket_limit", CONFIG_LWIP_MAX_SOCKETS);
    NUM("socket_recovery_reserve", GATEWAY_SOCKET_RECOVERY);
    NUM("sockets_open", sockets.open);
    NUM("sockets_peak", sockets.peak);
    NUM("socket_failures", sockets.failures);
    NUM("socket_last_errno", sockets.last_errno);
    NUM("socket_last_operation", sockets.last_operation);
    NUM("socket_last_at_ms", sockets.last_at_ms);
    NUM("reset_reason", esp_reset_reason());
    BOOL("wifi", online);
    BOOL("route_storage_ok", route_storage_ok);
    NUM("free_memory", esp_get_free_heap_size());
    NUM("largest_free_block",
        heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    NUM("minimum_free_memory",
        heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    jw_raw(w, "\"members\":[");
    const char *diagnostic_names[] = {
        "map_attempts",      "map_failures",       "map_error",
        "map_bytes",         "map_declared_bytes", "map_projected_bytes",
        "map_heap_before",   "map_heap_after",     "map_largest_before",
        "map_stream_id",     "map_frame_type",     "noise_error",
        "noise_frame_bytes", "map_generation", "h2_error", "h2_last_stream"};
    const char *stack_names[] = {"net_io", "derp_tx", "derp_rx", "coord",
                                 "wg_mgr"};
    for (size_t i = 0; i < count && !w->failed; i++) {
        status_member *v = &snapshot[i];
        if (i)
            jw_char(w, ',');
        jw_char(w, '{');
        NUM("id", v->id);
        NUM("start_heap_before", v->start_heap_before);
        NUM("start_heap_after", v->start_heap_after);
        STR("label", v->label);
        BOOL("enabled", v->enabled);
        STR("error", v->error);
        NUM("state", v->state);
        jw_key(w, "routing_ready");
        jw_bool(w, v->routing_ready);
        if (v->has_client) {
            jw_char(w, ',');
            if (v->vpn_ip) {
                char ip[16];
                microlink_ip_to_str(v->vpn_ip, ip);
                STR("tailnet_ip", ip);
            }
            if (v->dns[0])
                STR("tailnet_dns_name", v->dns);
            jw_raw(w, "\"map_diagnostics\":{");
            for (unsigned d = 0; d < sizeof(diagnostic_names) / sizeof(diagnostic_names[0]); d++) {
                if (d)
                    jw_char(w, ',');
                jw_key(w, diagnostic_names[d]);
                jw_number(w, v->diagnostics[d]);
            }
            jw_raw(w, "},\"stack_free_bytes\":{");
            for (unsigned t = 0; t < 5; t++) {
                if (t)
                    jw_char(w, ',');
                jw_key(w, stack_names[t]);
                if(v->stack_free[t]==UINT32_MAX)jw_raw(w,"null");else jw_number(w, v->stack_free[t]);
            }
            jw_raw(w, "},");
            STR("login_url", v->login);
            STR("protocol_error", v->protocol_error);
            STR("h2_debug", v->h2_debug);
            NUM("control_stage", v->control_stage);
            NUM("jit_hits",v->jit[0]);NUM("jit_misses",v->jit[1]);NUM("jit_evictions",v->jit[2]);
            NUM("jit_rejected",v->jit[3]);NUM("jit_dropped",v->jit[4]);
            NUM("directory_records",v->directory_count);
            NUM("next_peer_offset",v->peer_offset);NUM("peer_page_start",v->page_start);
            jw_raw(w, "\"peers\":[");
            for (unsigned j = 0; j < v->peers && !w->failed; j++) {
                if (j)
                    jw_char(w, ',');
                jw_char(w, '{');
                STR("name", v->peer[j].name);
                char short_name[64], qualified[128], ip[16];
                strlcpy(short_name, v->peer[j].name, sizeof(short_name));
                char *dot = strchr(short_name, '.');
                if (dot)
                    *dot = 0;
                snprintf(qualified, sizeof(qualified), "%s.%s.tailnet",
                         short_name, v->label);
                STR("qualifiedName", qualified);
                microlink_ip_to_str(v->peer[j].address, ip);
                jw_key(w, "address");
                jw_string(w, ip);
                jw_char(w, '}');
            }
            jw_char(w, ']');
        }
        jw_char(w, '}');
    }
    jw_raw(w, "]}");
    bool ok = jw_flush(w);
    free(snapshot);
#undef NUM
#undef STR
#undef BOOL
    if (!ok)
        return ESP_FAIL;
    return httpd_resp_send_chunk(req, NULL, 0);
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
    wifi_scan_lock = xSemaphoreCreateMutex();
    ESP_ERROR_CHECK(members_lock && wifi_scan_lock ? ESP_OK : ESP_ERR_NO_MEM);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
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
    /* Keep CDC recovery reachable before flash formatting, NVS journals or Wi-Fi. */
    if (nvs_open("tn_diag", NVS_READWRITE, &diag_store) == ESP_OK)
        diag_lock = xSemaphoreCreateMutex();
    gateway_diag_membership(0, GATEWAY_DIAG_BOOT, esp_reset_reason());
    if (!ml_directory_mount()) ESP_LOGE("peerstore", "Peer flash storage could not mount");
    load_members();
    extern bool gateway_routes_init(void);
    route_storage_ok = gateway_routes_init();
    size_t n = sizeof(wifi_config);
    nvs_get_blob(store, "wifi", &wifi_config, &n);
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
    http.max_uri_handlers = 5;
    http.max_open_sockets = 2;
    http.lru_purge_enable = true;
    http.recv_wait_timeout = http.send_wait_timeout = 2;
    httpd_handle_t server;
    ESP_ERROR_CHECK(httpd_start(&server, &http));
    httpd_uri_t page = {.uri = "/", .method = HTTP_GET, .handler = home},
                state = {.uri = "/status",
                         .method = HTTP_GET,
                         .handler = status},
                diag = {.uri = "/diagnostics",
                        .method = HTTP_GET,
                        .handler = diagnostics},
                scan = {.uri = "/wifi-scan",
                        .method = HTTP_GET,
                        .handler = wifi_scan},
                api = {
                    .uri = "/command", .method = HTTP_POST, .handler = command};
    httpd_register_uri_handler(server, &page);
    httpd_register_uri_handler(server, &state);
    httpd_register_uri_handler(server, &diag);
    httpd_register_uri_handler(server, &scan);
    httpd_register_uri_handler(server, &api);
    ESP_ERROR_CHECK(xTaskCreate(manager, "members", 4096, NULL, 4, NULL) == pdPASS ? ESP_OK : ESP_ERR_NO_MEM);
}
