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
#include "../components/microlink/include/ml_published_name.h"
#include "../main/clock_sync.h"
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
    struct {uint32_t tls_verify_failures, tls_deferred; struct {int state; struct {uint32_t frames_rx,frames_tx,rx_timeouts,tx_stalls,alloc_drops,connects;} stats;} link;} derp;
    uint8_t ctrl_key_auth;
    unsigned peer_generation,state, vpn_ip;
    void *wg_netif;
    bool key_expired, stop_incomplete;
    char last_error[64], transport_error[64], auth_url[384];
    ml_published_name_t self_dns_name;
    unsigned map_attempts, map_failures, map_error, map_bytes,
        map_declared_bytes, map_projected_bytes, map_heap_before,
        map_heap_after, map_largest_before, map_stream_id, map_frame_type,
        noise_error, noise_frame_bytes, map_generation;
    uint32_t read_expected,read_received,read_elapsed_ms,read_errno;int32_t read_tls_result;
    TaskHandle_t coord_task;
    bool rt_attached;
    struct { int state; struct {uint32_t frames_rx,frames_tx,rx_timeouts,tx_stalls,alloc_drops,connects;} stats; } derp_link_unused;
    struct {unsigned count,generation;bool session_valid;} directory;
    uint32_t jit_hits,jit_misses,jit_evictions,jit_rejected,jit_dropped;
    int peer_count;
    struct {
        char hostname[64];
        unsigned vpn_ip;
    } peers[8];
} microlink_t;
typedef enum {ML_RT_TASK_NET_IO, ML_RT_TASK_DERP, ML_RT_TASK_WG_MGR, ML_RT_TASK_COUNT} ml_rt_task_t;
typedef int ml_derp_link_state_t;
static const char *ml_derp_link_state_name(ml_derp_link_state_t s) { return s == 9 ? "ready" : "idle"; }
static TaskHandle_t ml_rt_task_handle(ml_rt_task_t t) { return 1 + t; }
typedef struct {size_t required, shared_runtime, member_start, member_growth, member_steady, negotiation, recovery, largest_block;} ml_adm_budget_t;
static ml_adm_budget_t admission_budget(void) { return (ml_adm_budget_t){90000, 23000, 30000, 5000, 35000, 16000, 16384, 24000}; }
#define ML_ADM_PEER_SLOTS 4
static size_t ml_wg_slot_bytes(void) { return 904; }
typedef struct {int holder_unused; unsigned phase; uint32_t held_ms, waiting, grants, timeouts, lease_expired, stale_dropped, refused_full, max_wait_ms, max_hold_ms; uintptr_t holder;} ml_neg_status_t;
typedef struct {bool running; unsigned members; uint32_t starts, stops, attach_failures, detach_failures, stack_bytes[3], stack_free[3], passes[3], max_service_ms[3], slow_services[3], detach_timeouts[3]; ml_neg_status_t negotiation;} ml_rt_status_t;
static void ml_rt_status(ml_rt_status_t *o) { memset(o, 0, sizeof(*o)); o->running = true; o->members = 1; o->stack_free[0] = 4000; o->stack_free[1] = UINT32_MAX; }
static const char *ml_neg_phase_name(unsigned p) { return "derp"; }
typedef struct {uint32_t capacity, used, peak, refused_full, refused_nomem, evictions_own, evictions_other, rejected, refused_largest, largest_low, slot_bytes, device_bytes;} ml_wg_pool_status_t;
static void ml_wg_pool_status(ml_wg_pool_status_t *o) { *o = (ml_wg_pool_status_t){12, 3, 5, 0, 0, 1, 2, 0, 1, 20480, 904, 228}; }
typedef struct {unsigned users, seedings, failures; unsigned long bytes; unsigned bytes_resident;} ml_rng_stats_t;
static void ml_rng_stats(ml_rng_stats_t *o) { memset(o, 0, sizeof(*o)); o->users = 1; o->bytes_resident = 500; }
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
static gw_clock_t sntp_clock;
static bool test_clock_valid = true;
static bool ml_derp_clock_valid(void) { return test_clock_valid; }
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
#include "tdongle_memory.h"
#include "tdongle_pm_burst.h"
typedef struct {bool scaling;int configure_error;uint32_t max_mhz,min_mhz,cpu_mhz,lock_create_failures;unsigned bursts;tdongle_pm_burst_stats_t burst[8];} tdongle_pm_status_t;
static bool pm_scaling=true;
static void tdongle_pm_status(tdongle_pm_status_t *o){memset(o,0,sizeof(*o));o->scaling=pm_scaling;o->configure_error=-1;o->cpu_mhz=pm_scaling?80:240;o->max_mhz=pm_scaling?240:0;o->min_mhz=pm_scaling?80:0;o->bursts=2;
 o->burst[0]=(tdongle_pm_burst_stats_t){.name="ml_derp",.depth=0,.acquires=12,.releases=12,.held_us=3400,.max_depth=1};
 o->burst[1]=(tdongle_pm_burst_stats_t){.name="usb_routes",.depth=1,.acquires=5,.releases=4,.held_us=900,.max_depth=2,.underflows=1,.forced_releases=2,.backend_failures=3,.isr_rejects=4};}
static int wifi_ps_mode(void){return -1;}   /* not readable: must stay -1, not 4294967295 */
void tdongle_memory_note(unsigned o,size_t n,int f){}
static void gateway_dns_domains_refresh(void){}
static tdongle_mode runtime_mode=TDONGLE_TAILNET_GATEWAY;
tdongle_temperature tdongle_temperature_snapshot(void){return (tdongle_temperature){.valid=true,.current_tenths=550,.peak_tenths=600,.sampled_at_ms=1000,.samples=7,.changed_at_ms=500,.age_ms=2500};}
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
    ml_published_name_set(&c->self_dns_name, "dongle.ts.net");
    strcpy(c->auth_url, "https://login/?x=\"\\");
    c->directory.count=1;c->directory.session_valid=true;
    c->peer_count = 1;
    strcpy(c->peers[0].hostname, "server.ts.net");
    c->peers[0].vpn_ip = 0x64020304;
    c->rt_attached = true;
    c->derp.link.state = 9;c->derp.link.stats.frames_rx = 5;
    c->derp.tls_verify_failures=2;c->derp.tls_deferred=3;c->ctrl_key_auth=3;
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
    assert(!strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(m, "derp_link"), "state")->valuestring, "ready"));
    {   /* the shared runtime's decision inputs and the pool are reported */
        cJSON *adm = cJSON_GetObjectItem(root, "admission");
        assert(adm && cJSON_GetObjectItem(adm, "required_bytes")->valueint == 90000 &&
               cJSON_GetObjectItem(adm, "negotiation_reserve_bytes")->valueint == 16000);
        cJSON *rt = cJSON_GetObjectItem(root, "shared_runtime");
        assert(cJSON_IsTrue(cJSON_GetObjectItem(rt, "running")) &&
               cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(rt, "tasks"), "net_io"), "stack_free")->valueint == 4000 &&
               cJSON_IsNull(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(rt, "tasks"), "derp"), "stack_free")));
        assert(cJSON_GetObjectItem(cJSON_GetObjectItem(root, "wg_pool"), "evictions_other")->valueint == 2);
        assert(cJSON_GetObjectItem(cJSON_GetObjectItem(root, "wg_pool"), "refused_largest")->valueint == 1);
        assert(cJSON_GetObjectItem(cJSON_GetObjectItem(root, "wg_pool"), "largest_low")->valueint == 20480);
        assert(cJSON_GetObjectItem(cJSON_GetObjectItem(root, "negotiation"), "holder"));
    }
    {   /* sensor liveness: the reading is re-sampled, so its age and sample count are reported */
        cJSON *t = cJSON_GetObjectItem(root, "chip_temperature");
        assert(cJSON_GetObjectItem(t, "current_tenths_c")->valueint == 550 && cJSON_GetObjectItem(t, "samples")->valueint == 7 &&
               cJSON_GetObjectItem(t, "age_ms")->valueint == 2500 && cJSON_GetObjectItem(t, "changed_at_uptime_ms")->valueint == 500 &&
               cJSON_GetObjectItem(t, "step_tenths_c")->valueint == 10);
    }
    {   /* power: clock, scaling, Wi-Fi power save and every lock's counters */
        cJSON *p = cJSON_GetObjectItem(root, "power");
        assert(cJSON_IsTrue(cJSON_GetObjectItem(p, "scaling")) && cJSON_GetObjectItem(p, "cpu_mhz")->valueint == 80 &&
               cJSON_GetObjectItem(p, "max_mhz")->valueint == 240 && cJSON_GetObjectItem(p, "min_mhz")->valueint == 80 &&
               cJSON_GetObjectItem(p, "wifi_ps")->valueint == -1 &&
               cJSON_GetObjectItem(p, "configure_error")->valueint == -1);
        cJSON *locks = cJSON_GetObjectItem(p, "locks");
        assert(cJSON_GetArraySize(locks) == 2);
        cJSON *d = cJSON_GetObjectItem(locks, "ml_derp"), *u = cJSON_GetObjectItem(locks, "usb_routes");
        assert(cJSON_GetObjectItem(d, "acquires")->valueint == 12 && cJSON_GetObjectItem(d, "held_us")->valueint == 3400 &&
               cJSON_GetObjectItem(u, "depth")->valueint == 1 && cJSON_GetObjectItem(u, "forced_releases")->valueint == 2 &&
               cJSON_GetObjectItem(u, "backend_failures")->valueint == 3 && cJSON_GetObjectItem(u, "isr_rejects")->valueint == 4 &&
               cJSON_GetObjectItem(u, "underflows")->valueint == 1);
    }
    assert(cJSON_GetArraySize(cJSON_GetObjectItem(m, "peers")) == 1);
    cJSON *diagnostics=cJSON_GetObjectItem(m,"map_diagnostics");
    assert(cJSON_GetObjectItem(diagnostics,"h2_error")->valueint==1);
    assert(cJSON_GetObjectItem(diagnostics,"h2_last_stream")->valueint==7);
    assert(cJSON_GetObjectItem(root,"sockets_open")->valueint==10);
    assert(cJSON_GetObjectItem(root,"socket_limit")->valueint==20);
    assert(cJSON_GetObjectItem(m,"derp_tls_verify_failures")->valueint==2);
    assert(cJSON_GetObjectItem(m,"derp_tls_deferred")->valueint==3);
    assert(cJSON_GetObjectItem(m,"control_key_auth")->valueint==3);
    cJSON *clock=cJSON_GetObjectItem(root,"clock");
    assert(!strcmp(cJSON_GetObjectItem(clock,"state")->valuestring,"synced"));
    assert(cJSON_IsTrue(cJSON_GetObjectItem(clock,"valid")));
    cJSON_Delete(root);
    /* A clock that never arrives is visible: state, restarts, server and the next retry. */
    cleanup();setup();
    test_clock_valid=false;online=true;
    sntp_clock=(gw_clock_t){0};
    gw_clock_poll(&sntp_clock,1000,false,true);
    assert(gw_clock_poll(&sntp_clock,1000+GW_CLOCK_FIRST_RETRY_MS,false,true)==GW_CLOCK_RESTART);
    r=(httpd_req_t){0};assert(status(&r)==0);
    root=cJSON_Parse(r.output);assert(root);
    clock=cJSON_GetObjectItem(root,"clock");
    assert(!strcmp(cJSON_GetObjectItem(clock,"state")->valuestring,"failing"));
    assert(!cJSON_IsTrue(cJSON_GetObjectItem(clock,"valid")));
    assert(cJSON_GetObjectItem(clock,"sntp_restarts")->valueint==1);
    assert(cJSON_GetObjectItem(clock,"retry_in_ms")->valueint==2*GW_CLOCK_FIRST_RETRY_MS);
    assert(!strcmp(cJSON_GetObjectItem(clock,"server")->valuestring,"time.cloudflare.com"));
    cJSON_Delete(root);test_clock_valid=true;cleanup();
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
