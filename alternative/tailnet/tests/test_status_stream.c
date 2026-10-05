#include "../main/boot_health.h"
bool gateway_boot_recovery(void){return false;}
#include "cJSON.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../main/socket_budget.h"
#define CONFIG_LWIP_MAX_SOCKETS 20
gateway_socket_stats gateway_sockets_snapshot(void) {return (gateway_socket_stats){.open=10,.peak=12,.last_errno=23,.failures=1};}
static int esp_reset_reason(void) {return 1;}
#define ML_MAX_PEERS 8
#define ML_STATE_CONNECTED 4
#define pdTRUE 1
#define ESP_OK 0
#define ESP_FAIL -1
#define HTTPD_403_FORBIDDEN 403
#define HTTPD_500_INTERNAL_SERVER_ERROR 500
#define MALLOC_CAP_INTERNAL 1
#define pdMS_TO_TICKS(x) (x)
typedef int esp_err_t, TaskHandle_t;
typedef struct {
    char output[20000];
    size_t used;
    int status;
    unsigned chunks;
    bool fail;
} httpd_req_t;
typedef struct {
    char h2_debug[49]; unsigned control_stage;
    uint32_t map_h2_error, map_h2_last_stream;
    unsigned peer_generation,state, vpn_ip;
    void *wg_netif;
    bool key_expired, stop_incomplete;
    char last_error[64], transport_error[64], self_dns_name[128], auth_url[384];
    unsigned map_attempts, map_failures, map_error, map_bytes,
        map_declared_bytes, map_projected_bytes, map_heap_before,
        map_heap_after, map_largest_before, map_stream_id, map_frame_type,
        noise_error, noise_frame_bytes, map_generation;
    uint32_t read_expected,read_received,read_elapsed_ms,read_errno;int32_t read_tls_result;
    TaskHandle_t net_io_task, derp_tx_task, derp_rx_task, coord_task,
        wg_mgr_task;
    struct {unsigned count,generation;bool session_valid;} directory;
    uint32_t jit_hits,jit_misses,jit_evictions,jit_rejected,jit_dropped;
    int peer_count;
    struct {
        char hostname[64];
        unsigned vpn_ip;
    } peers[8];
} microlink_t;
typedef struct membership {
    struct membership *next;
    unsigned id;
    bool enabled;
    size_t start_heap_before, start_heap_after;
    char label[24], error[64];
    microlink_t *client;
} membership_t;
static membership_t *members;
static int members_lock, held, takes;
static bool busy, grow, release_source, fail_allocation;
static bool online = true, route_storage_ok = true;
static int xSemaphoreTake(int lock, int ticks) {
    assert(!held && ticks <= 20);
    takes++;
    if (busy)
        return 0;
    held = 1;
    if (grow && takes == 2) {
        membership_t *n = calloc(1, sizeof(*n));
        n->next = members;
        members = n;
    }
    return 1;
}
static void xSemaphoreGive(int lock) {
    assert(held);
    held = 0;
    if (release_source && takes == 2) {
        free(members->client);
        members->client = NULL;
        free(members);
        members = NULL;
    }
}

typedef struct {char hostname[64];unsigned vpn_ip;} ml_peer_update_t;
static bool mutate_peer;
static bool ml_directory_at(microlink_t *m,unsigned i,ml_peer_update_t *out) {
    if(i>=m->directory.count)return false;
    strcpy(out->hostname,m->peers[i].hostname);out->vpn_ip=m->peers[i].vpn_ip;
    if(mutate_peer)m->directory.generation++;
    return true;
}
static int httpd_req_get_url_query_str(httpd_req_t *r,char *out,size_t size){return -1;}
static int httpd_query_key_value(const char *q,const char *key,char *out,size_t size){return -1;}
static int local_request(httpd_req_t *r) { return 1; }
static int httpd_resp_send_err(httpd_req_t *r, int code, const char *msg) {
    r->status = code;
    return -1;
}
static int httpd_resp_set_hdr(httpd_req_t *r, const char *k, const char *v) {
    return 0;
}
static int httpd_resp_set_type(httpd_req_t *r, const char *s) { return 0; }
static int httpd_resp_set_status(httpd_req_t *r, const char *s) {
    r->status = atoi(s);
    return 0;
}
static int httpd_resp_sendstr(httpd_req_t *r, const char *s) {
    assert(!held);
    strcpy(r->output, s);
    return 0;
}
static int httpd_resp_send_chunk(httpd_req_t *r, const char *s, size_t n) {
    assert(!held && n <= 256);
    if (r->fail)
        return -1;
    if (!n) {
        r->chunks++;
        return 0;
    }
    assert(r->used + n < sizeof(r->output));
    memcpy(r->output + r->used, s, n);
    r->used += n;
    r->output[r->used] = 0;
    r->chunks++;
    return 0;
}
static unsigned uxTaskGetStackHighWaterMark(int t) {
    assert(held);
    return 100 + t;
}
static unsigned member_start_budget(void) { return 78340; }
static unsigned esp_get_free_heap_size(void) { return 40000; }
static unsigned heap_caps_get_largest_free_block(int x) { return 20000; }
static unsigned heap_caps_get_minimum_free_size(int x) { return 15000; }
static unsigned gateway_alias(unsigned id, unsigned ip) {
    assert(held);
    return 0xc6120001;
}
static void microlink_ip_to_str(unsigned ip, char *out) {
    snprintf(out, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255,
             (ip >> 8) & 255, ip & 255);
}
static void *checked_calloc(size_t n, size_t size) {
    return fail_allocation ? NULL : calloc(n, size);
}
static size_t test_strlcpy(char *out,const char *src,size_t size) {
    size_t length=strlen(src);
    if(size){size_t n=length<size-1?length:size-1;memcpy(out,src,n);out[n]=0;}
    return length;
}
static size_t checked_strlcpy(char *out,const char *src,size_t size){size_t n=test_strlcpy(out,src,size);if(mutate_peer&&members&&members->client&&src==members->client->peers[0].hostname)members->client->peer_generation+=2;return n;}
#define strlcpy checked_strlcpy
#define calloc checked_calloc
static struct {unsigned count;struct {char ssid[33];} profiles[8];} wifi_saved;
#include "../../../components/tdongle_runtime/include/tdongle_mode.h"
#include "../../../components/tdongle_runtime/include/tdongle_temperature.h"
static void tdongle_memory_note(unsigned o,size_t n,int f){}
static void gateway_dns_domains_refresh(void){}
static tdongle_mode runtime_mode=TDONGLE_TAILNET_GATEWAY;
tdongle_temperature tdongle_temperature_snapshot(void){return (tdongle_temperature){.valid=true,.current_tenths=550,.peak_tenths=600,.sampled_at_ms=1000};}
#include "status_stream.inc"
#undef calloc
#undef strlcpy
static void setup(void) {
    takes = held = 0;
    busy = grow = release_source = fail_allocation = false;
    members = calloc(1, sizeof(*members));
    members->id = 1;
    members->enabled = true;
    strcpy(members->label, "work\"\\\n");
    members->client = calloc(1, sizeof(microlink_t));
    microlink_t *c = members->client;
    c->state = 4;
    c->map_h2_error=1;c->map_h2_last_stream=7;
    c->wg_netif = c;
    c->vpn_ip = 0x64010203;
    strcpy(c->self_dns_name, "dongle.ts.net");
    strcpy(c->auth_url, "https://login/?x=\"\\");
    c->directory.count=1;c->directory.session_valid=true;
    c->peer_count = 1;
    strcpy(c->peers[0].hostname, "server.ts.net");
    c->peers[0].vpn_ip = 0x64020304;
    c->net_io_task = 1;
}
static void cleanup(void) {
    while (members) {
        membership_t *n = members->next;
        free(members->client);
        free(members);
        members = n;
    }
    assert(!held);
}
int main(void) {
    setup();
    httpd_req_t r = {0};
    release_source = true;
    assert(status(&r) == 0 && !members);
    cJSON *root = cJSON_Parse(r.output);
    assert(root);
    cJSON *m = cJSON_GetArrayItem(cJSON_GetObjectItem(root, "members"), 0);
    assert(cJSON_IsTrue(cJSON_GetObjectItem(m, "routing_ready")));
    assert(!strcmp(cJSON_GetObjectItem(m, "label")->valuestring, "work\"\\\n"));
    assert(cJSON_GetObjectItem(cJSON_GetObjectItem(m, "stack_free_bytes"),
                               "net_io")
               ->valueint == 101);
    assert(cJSON_GetArraySize(cJSON_GetObjectItem(m, "peers")) == 1);
    cJSON *diagnostics=cJSON_GetObjectItem(m,"map_diagnostics");
    assert(cJSON_GetObjectItem(diagnostics,"h2_error")->valueint==1);
    assert(cJSON_GetObjectItem(diagnostics,"h2_last_stream")->valueint==7);
    assert(cJSON_GetObjectItem(root,"sockets_open")->valueint==10);
    assert(cJSON_GetObjectItem(root,"socket_limit")->valueint==20);
    cJSON_Delete(root);
    setup();
    r = (httpd_req_t){.fail = true};
    assert(status(&r) < 0 && !held && r.chunks == 0);
    cleanup();
    setup();
    busy = true;
    r = (httpd_req_t){0};
    assert(status(&r) == 0 && r.status == 503 && !held);
    cleanup();
    setup();
    grow = true;
    r = (httpd_req_t){0};
    assert(status(&r) == 0 && r.status == 503 && !held);
    cleanup();
    setup();
    fail_allocation = true;
    r = (httpd_req_t){0};
    assert(status(&r) < 0 && r.status == 500 && !held);
    cleanup();
    setup();members->client->peer_generation=1;r=(httpd_req_t){0};assert(status(&r)==0&&r.status==503&&!held);cleanup();
    setup();mutate_peer=true;r=(httpd_req_t){0};assert(status(&r)==0&&r.status==503&&!held);mutate_peer=false;cleanup();
    members = NULL;
    takes = 0;
    r = (httpd_req_t){0};
    fail_allocation = false;
    grow = false;
    assert(status(&r) == 0);
    root = cJSON_Parse(r.output);
    assert(root &&
           cJSON_GetArraySize(cJSON_GetObjectItem(root, "members")) == 0);
    cJSON_Delete(root);
}
