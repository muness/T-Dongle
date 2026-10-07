/* Host harness: the REAL status() of gateway_main.c, json_writer.inc and runtime_status.inc, compiled with stubs that read a scenario (one JSON
 * line on stdin per run). tools/gen_golden.py cuts status_stream.inc out of gateway_main.c exactly as tools/test-gateway.sh does.
 * Output per scenario:  CONST <sizeof(microlink_t)> <GATEWAY_SOCKET_RECOVERY>\n CHUNKS n,n,..\n BODY <hex>\n  (or STATUS <code>\n). */
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "cJSON.h"
#ifndef __APPLE__
static size_t strlcpy(char *d, const char *s, size_t n){size_t l=strlen(s);if(n){size_t c=l>=n?n-1:l;memcpy(d,s,c);d[c]=0;}return l;}
#endif
static char g_version[64];
#define GATEWAY_VERSION (g_version)
#include "boot_health.h"
static bool g_recovery;
bool gateway_boot_recovery(void){return g_recovery;}
#include "socket_budget.h"
#include "ml_published_name.h"
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
typedef struct { char output[40000]; size_t used; int status; unsigned chunks; unsigned sizes[512]; unsigned fail; } httpd_req_t;
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
    unsigned map_attempts, map_failures, map_error, map_bytes, map_declared_bytes, map_projected_bytes, map_heap_before,
        map_heap_after, map_largest_before, map_stream_id, map_frame_type, noise_error, noise_frame_bytes, map_generation;
    uint32_t read_expected,read_received,read_elapsed_ms,read_errno;int32_t read_tls_result;
    TaskHandle_t coord_task;
    bool rt_attached;
    struct {unsigned count,generation;bool session_valid;} directory;
    uint32_t jit_hits,jit_misses,jit_evictions,jit_rejected,jit_dropped;
    int peer_count;
    struct { char hostname[64]; unsigned vpn_ip; } peers[8];
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
static int members_lock;
static bool online, route_storage_ok;
static bool g_clock_valid;
static char g_clock_state[32], g_clock_server[32];
typedef struct {uint32_t restarts, retry_in_ms; uint8_t server;} gw_clock_t;
static gw_clock_t sntp_clock;
#define GW_CLOCK_SERVERS 1
static const char *gw_clock_server_name[1] = {g_clock_server};
static const char *gw_clock_state(const gw_clock_t *c, bool v, bool up) { return g_clock_state; }
static bool ml_derp_clock_valid(void) { return g_clock_valid; }
static int xSemaphoreTake(int lock, int ticks) { return 1; }
static void xSemaphoreGive(int lock) {}
typedef struct {char hostname[64];unsigned vpn_ip;} ml_peer_update_t;
static bool ml_directory_at(microlink_t *m,unsigned i,ml_peer_update_t *out) {
    if (i >= m->directory.count || (int)i >= m->peer_count) return false;
    strcpy(out->hostname, m->peers[i].hostname); out->vpn_ip = m->peers[i].vpn_ip; return true;
}
static char g_query[128]; static bool g_have_query;
static int httpd_req_get_url_query_str(httpd_req_t *r, char *out, size_t size) {
    if (!g_have_query) return -1;
    size_t n = strlen(g_query);
    if (n >= size) return -2;
    memcpy(out, g_query, n + 1); return 0;
}
static int httpd_query_key_value(const char *qry, const char *key, char *val, size_t val_size) {
    const char *p = qry;
    while (strlen(p)) {
        const char *v = strchr(p, '='); if (!v) break;
        size_t off = v - p;
        if (off != strlen(key) || strncasecmp(p, key, off)) { p = strchr(v, '&'); if (!p) break; p++; continue; }
        p = strchr(++v, '&'); if (!p) p = v + strlen(v);
        size_t len = p - v, copy = len < val_size - 1 ? len : val_size - 1;
        if (copy < len) return -2;
        memcpy(val, v, copy); val[copy] = 0; return 0;
    }
    return -3;
}
static int local_request(httpd_req_t *r) { return 1; }
static int httpd_resp_send_err(httpd_req_t *r, int code, const char *msg) { r->status = code; return -1; }
static int httpd_resp_set_hdr(httpd_req_t *r, const char *k, const char *v) { return 0; }
static int httpd_resp_set_type(httpd_req_t *r, const char *s) { return 0; }
static int httpd_resp_set_status(httpd_req_t *r, const char *s) { r->status = atoi(s); return 0; }
static int httpd_resp_sendstr(httpd_req_t *r, const char *s) { strcpy(r->output, s); return 0; }
static int httpd_resp_send_chunk(httpd_req_t *r, const char *s, size_t n) {
    if (r->fail && n && r->chunks + 1 == r->fail) return -1;
    if (!n) return 0;
    assert(n <= 256 && r->used + n < sizeof(r->output));
    memcpy(r->output + r->used, s, n); r->used += n; r->output[r->used] = 0;
    r->sizes[r->chunks++] = n; return 0;
}
static uint32_t g_stack[5];
static unsigned uxTaskGetStackHighWaterMark(int t) { return g_stack[t == 1 ? 0 : t == 2 ? 1 : t == 3 ? 4 : 3]; }
static uint64_t g_member_start_budget;
#define member_start_budget() g_member_start_budget
static unsigned g_free, g_largest, g_minimum;
static unsigned esp_get_free_heap_size(void) { return g_free; }
static unsigned heap_caps_get_largest_free_block(int x) { return g_largest; }
static unsigned heap_caps_get_minimum_free_size(int x) { return g_minimum; }
static unsigned gateway_alias(unsigned id, unsigned ip) { return ip; }
static void microlink_ip_to_str(unsigned ip, char *out) { snprintf(out, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255); }
#define calloc calloc
static struct {unsigned count;struct {char ssid[33];} profiles[8];} wifi_saved;
#include "tdongle_mode.h"
#include "tdongle_temperature.h"
#include "tdongle_memory.h"
#include "tdongle_pm_burst.h"
static tdongle_temperature g_temp;
tdongle_temperature tdongle_temperature_snapshot(void){return g_temp;}
typedef struct {bool scaling;int configure_error;uint32_t max_mhz,min_mhz,cpu_mhz,lock_create_failures;unsigned bursts;tdongle_pm_burst_stats_t burst[8];} tdongle_pm_status_t;
static tdongle_pm_status_t g_pm; static char g_lock_names[8][64]; static int g_wifi_ps;
static void tdongle_pm_status(tdongle_pm_status_t *o){*o=g_pm;}
static int wifi_ps_mode(void){return g_wifi_ps;}
void tdongle_memory_note(unsigned o,size_t n,int f){}
static void gateway_dns_domains_refresh(void){}
static tdongle_mode runtime_mode;
typedef struct {int dummy;} wifi_link_info; typedef struct {int dummy;} wifi_link_events;
enum { WIFI_LINK_JSON_MAX = 480 };
static wifi_link_events wifi_link_stats; static char g_link_json[480]; static bool g_have_link;
static wifi_link_info wifi_link_read(void){wifi_link_info i={0};return i;}
static size_t wifi_link_json(char *out, size_t cap, const wifi_link_info *l, const wifi_link_events *e) { if (!g_have_link) return 0; size_t n = strlen(g_link_json); memcpy(out, g_link_json, n + 1); return n; }
static unsigned g_hb[5]; static struct {atomic_uint dropped_heap;} usb_rx_budget;
static unsigned g_floor, g_reserve, g_pin;
#define ML_HB_FLOOR g_floor
#define ML_HB_RESERVE g_reserve
#define ML_HB_PIN_BUFFERS g_pin
typedef enum {ML_HB_JIT,ML_HB_DERP_TX,ML_HB_RX_CTRL,ML_HB_DERP_RX,ML_HB_WG_COPY,ML_HB_SITE_COUNT} ml_hb_site_t;
static atomic_uint ml_hb_refused[ML_HB_SITE_COUNT];
static unsigned g_pool, g_band, g_txband, g_rxband, g_txout, g_rxin;
#define GATEWAY_WIFI_TX_POOL g_pool
#define GATEWAY_WIFI_BAND_TOTAL g_band
#define GATEWAY_WIFI_TX_BAND_MAX g_txband
#define GATEWAY_WIFI_RX_BAND_MAX g_rxband
static bool wifi_pins_installed, wifi_pins_tx_done_ok, wifi_pins_rx_hooked;
static struct { atomic_uint tx_high_water, tx_charged, tx_done, tx_aborted, tx_flushed, tx_stale, tx_unmatched, tx_band, tx_elastic,
    tx_refused_pool, tx_refused_heap, rx_high_water, rx_band, rx_elastic, rx_released, rx_unmatched, rx_dropped; } wifi_pins;
static unsigned wifi_pins_tx_outstanding(void){return g_txout;}
static unsigned wifi_pins_rx_inflight(void){return g_rxin;}
typedef struct { uint32_t open, peak, failures, last_errno, last_operation, last_at_ms; } sock_t;
static gateway_socket_stats g_sock; static unsigned g_socket_limit, g_reset_reason;
gateway_socket_stats gateway_sockets_snapshot(void) {return g_sock;}
#define CONFIG_LWIP_MAX_SOCKETS g_socket_limit
static int esp_reset_reason(void) {return g_reset_reason;}
typedef enum {ML_RT_TASK_NET_IO, ML_RT_TASK_DERP, ML_RT_TASK_WG_MGR, ML_RT_TASK_COUNT} ml_rt_task_t;
typedef int ml_derp_link_state_t;
static char g_derp_state[10][32]; static int g_derp_state_n;
static const char *ml_derp_link_state_name(ml_derp_link_state_t s) { return g_derp_state[s]; }
static TaskHandle_t ml_rt_task_handle(ml_rt_task_t t) { return 1 + t; }
typedef struct {size_t required, shared_runtime, member_start, member_growth, member_steady, negotiation, recovery, largest_block;} ml_adm_budget_t;
static ml_adm_budget_t g_adm; static unsigned g_peer_slots, g_peer_slot_bytes;
static ml_adm_budget_t admission_budget(void) { return g_adm; }
#define ML_ADM_PEER_SLOTS g_peer_slots
static size_t ml_wg_slot_bytes(void) { return g_peer_slot_bytes; }
typedef struct {uintptr_t holder; unsigned phase; uint32_t held_ms; unsigned waiting; uint32_t grants, timeouts, lease_expired, stale_dropped, refused_full, max_wait_ms, max_hold_ms;} ml_neg_status_t;
typedef struct {bool running; unsigned members; uint32_t starts, stops, attach_failures, detach_failures, stack_bytes[3], stack_free[3], passes[3], max_service_ms[3], slow_services[3], detach_timeouts[3]; ml_neg_status_t negotiation;} ml_rt_status_t;
static ml_rt_status_t g_rt;
static void ml_rt_status(ml_rt_status_t *o) { *o = g_rt; }
static const char *ml_neg_phase_name(unsigned p) { return p == 1 ? "start" : p == 2 ? "control" : p == 3 ? "derp" : "none"; }
typedef struct {uint32_t capacity, used, peak, refused_full, refused_nomem, evictions_own, evictions_other, rejected, refused_largest, refused_heap, largest_low, slot_bytes, device_bytes;} ml_wg_pool_status_t;
static ml_wg_pool_status_t g_pool_status;
static void ml_wg_pool_status(ml_wg_pool_status_t *o) { *o = g_pool_status; }
typedef struct {unsigned users, seedings, failures; unsigned long bytes; unsigned bytes_resident;} ml_rng_stats_t;
static ml_rng_stats_t g_rng;
static void ml_rng_stats(ml_rng_stats_t *o) { *o = g_rng; }
#include "status_stream.inc"

static double num(cJSON *o, const char *k) { cJSON *i = cJSON_GetObjectItemCaseSensitive(o, k); assert(i && cJSON_IsNumber(i)); return i->valuedouble; }
static unsigned u32(cJSON *o, const char *k) { return (unsigned)(uint32_t)(uint64_t)num(o, k); }
static bool flag(cJSON *o, const char *k) { cJSON *i = cJSON_GetObjectItemCaseSensitive(o, k); assert(i && cJSON_IsBool(i)); return cJSON_IsTrue(i); }
static int unhex(const char *h, char *out, size_t cap) {
    size_t n = strlen(h) / 2; assert(n < cap);
    for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = v; }
    out[n] = 0; return n;
}
static void text(cJSON *o, const char *k, char *out, size_t cap) { cJSON *i = cJSON_GetObjectItemCaseSensitive(o, k); assert(i && cJSON_IsString(i)); unhex(i->valuestring, out, cap); }
static cJSON *obj(cJSON *o, const char *k) { cJSON *i = cJSON_GetObjectItemCaseSensitive(o, k); assert(i); return i; }
static void arr3(cJSON *o, const char *k, uint32_t *out, unsigned n) { cJSON *a = obj(o, k); for (unsigned i = 0; i < n; i++) out[i] = (uint32_t)(uint64_t)cJSON_GetArrayItem(a, i)->valuedouble; }

int main(void) {
    static char line[1 << 20];
    while (fgets(line, sizeof line, stdin)) {
        cJSON *s = cJSON_Parse(line); assert(s);
        memset(g_version, 0, sizeof g_version);
        text(s, "firmware", g_version, sizeof g_version);
        { char m[32]; text(s, "mode", m, sizeof m); runtime_mode = strcmp(m, "wifi_bridge") ? TDONGLE_TAILNET_GATEWAY : TDONGLE_WIFI_BRIDGE; }
        cJSON *t = obj(s, "temperature");
        g_temp = (tdongle_temperature){.valid = flag(t, "valid"), .current_tenths = (int32_t)num(t, "current"), .peak_tenths = (int32_t)num(t, "peak"),
            .sampled_at_ms = u32(t, "sampled"), .errors = u32(t, "errors"), .samples = u32(t, "samples"), .changed_at_ms = u32(t, "changed"), .age_ms = u32(t, "age")};
        g_recovery = flag(s, "recovery");
        g_member_start_budget = (uint64_t)num(s, "member_start_budget");
        cJSON *a = obj(s, "admission");
        g_adm = (ml_adm_budget_t){u32(a, "required"), u32(a, "shared_runtime"), u32(a, "member_start"), u32(a, "member_growth"), u32(a, "member_steady"), u32(a, "negotiation"), u32(a, "recovery"), u32(a, "largest_block")};
        g_peer_slots = u32(a, "peer_slots_charged"); g_peer_slot_bytes = u32(a, "peer_slot_bytes");
        cJSON *r = obj(s, "shared_runtime");
        memset(&g_rt, 0, sizeof g_rt);
        g_rt.running = flag(r, "running"); g_rt.members = u32(r, "members"); g_rt.starts = u32(r, "starts"); g_rt.stops = u32(r, "stops");
        g_rt.attach_failures = u32(r, "attach_failures"); g_rt.detach_failures = u32(r, "detach_failures");
        arr3(r, "stack_bytes", g_rt.stack_bytes, 3); arr3(r, "stack_free", g_rt.stack_free, 3); arr3(r, "passes", g_rt.passes, 3);
        arr3(r, "max_service_ms", g_rt.max_service_ms, 3); arr3(r, "slow_services", g_rt.slow_services, 3); arr3(r, "detach_timeouts", g_rt.detach_timeouts, 3);
        cJSON *n = obj(r, "negotiation");
        { int ph = (int)num(n, "holder"); g_rt.negotiation.holder = ph >= 0; g_rt.negotiation.phase = ph >= 0 ? ph : 0; }
        g_rt.negotiation.held_ms = u32(n, "held_ms"); g_rt.negotiation.waiting = u32(n, "waiting"); g_rt.negotiation.grants = u32(n, "grants");
        g_rt.negotiation.timeouts = u32(n, "timeouts"); g_rt.negotiation.lease_expired = u32(n, "lease_expired"); g_rt.negotiation.stale_dropped = u32(n, "stale_dropped");
        g_rt.negotiation.refused_full = u32(n, "refused_full"); g_rt.negotiation.max_wait_ms = u32(n, "max_wait_ms"); g_rt.negotiation.max_hold_ms = u32(n, "max_hold_ms");
        cJSON *p = obj(s, "wg_pool");
        g_pool_status = (ml_wg_pool_status_t){u32(p, "capacity"), u32(p, "used"), u32(p, "peak"), u32(p, "refused_full"), u32(p, "refused_nomem"), u32(p, "evictions_own"),
            u32(p, "evictions_other"), u32(p, "rejected"), u32(p, "refused_largest"), u32(p, "refused_heap"), u32(p, "largest_low"), u32(p, "slot_bytes"), u32(p, "device_bytes")};
        cJSON *g = obj(s, "shared_rng");
        g_rng = (ml_rng_stats_t){.users = u32(g, "users"), .seedings = u32(g, "seedings"), .failures = u32(g, "failures"), .bytes_resident = u32(g, "bytes_resident")};
        cJSON *pw = obj(s, "power");
        memset(&g_pm, 0, sizeof g_pm);
        g_pm.scaling = flag(pw, "scaling"); g_pm.cpu_mhz = u32(pw, "cpu_mhz"); g_pm.max_mhz = u32(pw, "max_mhz"); g_pm.min_mhz = u32(pw, "min_mhz");
        g_pm.configure_error = (int)num(pw, "configure_error"); g_pm.lock_create_failures = u32(pw, "lock_create_failures"); g_wifi_ps = (int)num(pw, "wifi_ps");
        cJSON *locks = obj(pw, "locks"); g_pm.bursts = cJSON_GetArraySize(locks);
        for (unsigned i = 0; i < g_pm.bursts; i++) {
            cJSON *l = cJSON_GetArrayItem(locks, i);
            text(l, "name", g_lock_names[i], sizeof g_lock_names[i]);
            g_pm.burst[i] = (tdongle_pm_burst_stats_t){.name = g_lock_names[i], .depth = u32(l, "depth"), .acquires = u32(l, "acquires"), .releases = u32(l, "releases"), .held_us = u32(l, "held_us"),
                .max_depth = u32(l, "max_depth"), .underflows = u32(l, "underflows"), .forced_releases = u32(l, "forced_releases"), .backend_failures = u32(l, "backend_failures"), .isr_rejects = u32(l, "isr_rejects")};
        }
        cJSON *k = obj(s, "sockets");
        g_socket_limit = u32(k, "limit");
        g_sock = (gateway_socket_stats){u32(k, "open"), u32(k, "peak"), u32(k, "failures"), u32(k, "last_errno"), u32(k, "last_operation"), u32(k, "last_at_ms")};
        g_reset_reason = u32(s, "reset_reason");
        online = flag(s, "wifi");
        { cJSON *wl = obj(s, "wifi_link"); g_have_link = cJSON_IsString(wl); if (g_have_link) { char tmp[480]; unhex(wl->valuestring, tmp, sizeof tmp); strcpy(g_link_json, tmp); } }
        cJSON *c = obj(s, "clock");
        text(c, "state", g_clock_state, sizeof g_clock_state); text(c, "server", g_clock_server, sizeof g_clock_server);
        g_clock_valid = flag(c, "valid"); sntp_clock.restarts = u32(c, "sntp_restarts"); sntp_clock.retry_in_ms = u32(c, "retry_in_ms");
        { cJSON *w = obj(s, "saved_wifi"); wifi_saved.count = cJSON_GetArraySize(w); for (unsigned i = 0; i < wifi_saved.count; i++) unhex(cJSON_GetArrayItem(w, i)->valuestring, wifi_saved.profiles[i].ssid, 33); }
        route_storage_ok = flag(s, "route_storage_ok");
        g_free = u32(s, "free_memory"); g_largest = u32(s, "largest_free_block"); g_minimum = u32(s, "minimum_free_memory");
        cJSON *h = obj(s, "heap_budget");
        g_floor = u32(h, "floor"); g_reserve = u32(h, "reserve"); g_pin = u32(h, "pin_buffers");
        atomic_store(&usb_rx_budget.dropped_heap, u32(h, "refused_usb_rx"));
        atomic_store(&ml_hb_refused[ML_HB_JIT], u32(h, "refused_pending")); atomic_store(&ml_hb_refused[ML_HB_DERP_TX], u32(h, "refused_derp_tx"));
        atomic_store(&ml_hb_refused[ML_HB_RX_CTRL], u32(h, "refused_rx_ctrl")); atomic_store(&ml_hb_refused[ML_HB_DERP_RX], u32(h, "refused_derp_rx"));
        atomic_store(&ml_hb_refused[ML_HB_WG_COPY], u32(h, "refused_wg_copy"));
        cJSON *wp = obj(s, "wifi_pins");
        wifi_pins_installed = flag(wp, "installed"); wifi_pins_tx_done_ok = flag(wp, "tx_done_cb"); wifi_pins_rx_hooked = flag(wp, "rx_hooked");
        g_pool = u32(wp, "tx_pool"); g_band = u32(wp, "band_total"); g_txband = u32(wp, "tx_band_max"); g_rxband = u32(wp, "rx_band_max");
        g_txout = u32(wp, "tx_inflight"); g_rxin = u32(wp, "rx_inflight");
#define PIN(f) atomic_store(&wifi_pins.f, u32(wp, #f))
        PIN(tx_high_water); PIN(tx_charged); PIN(tx_done); PIN(tx_aborted); PIN(tx_flushed); PIN(tx_stale); PIN(tx_unmatched); PIN(tx_band); PIN(tx_elastic);
        PIN(tx_refused_pool); PIN(tx_refused_heap); PIN(rx_high_water); PIN(rx_band); PIN(rx_elastic); PIN(rx_released); PIN(rx_unmatched); PIN(rx_dropped);
        arr3(s, "stack_values", g_stack, 5);
        { cJSON *q = obj(s, "query"); g_have_query = cJSON_IsString(q); if (g_have_query) unhex(q->valuestring, g_query, sizeof g_query); }
        { cJSON *d = obj(s, "derp_states"); g_derp_state_n = cJSON_GetArraySize(d); for (int i = 0; i < g_derp_state_n; i++) unhex(cJSON_GetArrayItem(d, i)->valuestring, g_derp_state[i], 32); }
        /* members */
        members = NULL; membership_t **tail = &members;
        cJSON *ms = obj(s, "members"), *mj;
        cJSON_ArrayForEach(mj, ms) {
            membership_t *m = calloc(1, sizeof *m); *tail = m; tail = &m->next;
            m->id = u32(mj, "id"); m->enabled = flag(mj, "enabled"); m->start_heap_before = (size_t)num(mj, "start_heap_before"); m->start_heap_after = (size_t)num(mj, "start_heap_after");
            text(mj, "label", m->label, sizeof m->label); text(mj, "error", m->error, sizeof m->error);
            cJSON *cj = obj(mj, "client");
            if (cJSON_IsNull(cj)) continue;
            microlink_t *cl = calloc(1, sizeof *cl); m->client = cl;
            cl->state = u32(cj, "state"); cl->vpn_ip = u32(cj, "vpn_ip"); cl->wg_netif = flag(cj, "wg_netif") ? cl : NULL; cl->key_expired = flag(cj, "key_expired");
            cl->rt_attached = flag(cj, "rt_attached"); cl->stop_incomplete = flag(cj, "stop_incomplete"); cl->coord_task = flag(cj, "coord") ? 4 : 0;
            text(cj, "last_error", cl->last_error, sizeof cl->last_error); text(cj, "transport_error", cl->transport_error, sizeof cl->transport_error);
            text(cj, "auth_url", cl->auth_url, sizeof cl->auth_url); text(cj, "h2_debug", cl->h2_debug, sizeof cl->h2_debug);
            { char dns[128]; text(cj, "dns", dns, sizeof dns); ml_published_name_set(&cl->self_dns_name, dns); }
            cl->control_stage = u32(cj, "control_stage");
            cl->derp.tls_verify_failures = u32(cj, "derp_tls_verify_failures"); cl->derp.tls_deferred = u32(cj, "derp_tls_deferred"); cl->ctrl_key_auth = u32(cj, "control_key_auth");
            cl->derp.link.state = (int)num(cj, "derp_state_index");
            cl->derp.link.stats.frames_rx = u32(cj, "frames_rx"); cl->derp.link.stats.frames_tx = u32(cj, "frames_tx"); cl->derp.link.stats.rx_timeouts = u32(cj, "record_timeouts");
            cl->derp.link.stats.tx_stalls = u32(cj, "write_stalls"); cl->derp.link.stats.alloc_drops = u32(cj, "alloc_drops"); cl->derp.link.stats.connects = u32(cj, "connects");
            cJSON *dg = obj(cj, "diagnostics");
#define D(i, f) (cl->f = (__typeof__(cl->f))(uint32_t)(uint64_t)cJSON_GetArrayItem(dg, i)->valuedouble)
            D(0, map_attempts); D(1, map_failures); D(2, map_error); D(3, map_bytes); D(4, map_declared_bytes); D(5, map_projected_bytes); D(6, map_heap_before);
            D(7, map_heap_after); D(8, map_largest_before); D(9, map_stream_id); D(10, map_frame_type); D(11, noise_error); D(12, noise_frame_bytes); D(13, map_generation);
            D(14, map_h2_error); D(15, map_h2_last_stream); D(16, read_expected); D(17, read_received); D(18, read_elapsed_ms); D(19, read_errno);
            cl->read_tls_result = (int32_t)(uint32_t)(uint64_t)cJSON_GetArrayItem(dg, 20)->valuedouble;
            cl->jit_hits = u32(cj, "jit_hits"); cl->jit_misses = u32(cj, "jit_misses"); cl->jit_evictions = u32(cj, "jit_evictions"); cl->jit_rejected = u32(cj, "jit_rejected"); cl->jit_dropped = u32(cj, "jit_dropped");
            cl->directory.count = u32(cj, "directory_records"); cl->directory.session_valid = flag(cj, "session_valid");
            cJSON *pj = obj(cj, "peers"), *pe; cl->peer_count = 0;
            cJSON_ArrayForEach(pe, pj) { text(pe, "name", cl->peers[cl->peer_count].hostname, 64); cl->peers[cl->peer_count].vpn_ip = u32(pe, "address"); cl->peer_count++; }
        }
        httpd_req_t req; memset(&req, 0, sizeof req);
        { cJSON *f = cJSON_GetObjectItemCaseSensitive(s, "fail_at_chunk"); req.fail = f && cJSON_IsNumber(f) ? (unsigned)f->valuedouble : 0; }
        int rc = status(&req);
        printf("CONST %zu %d\n", sizeof(microlink_t), (int)GATEWAY_SOCKET_RECOVERY);
        printf("RC %d STATUS %d\n", rc, req.status);
        printf("CHUNKS");
        for (unsigned i = 0; i < req.chunks; i++) printf("%c%u", i ? ',' : ' ', req.sizes[i]);
        printf("\nBODY ");
        for (size_t i = 0; i < req.used; i++) printf("%02x", (unsigned char)req.output[i]);
        printf("\n");
        while (members) { membership_t *x = members->next; free(members->client); free(members); members = x; }
        cJSON_Delete(s);
    }
    return 0;
}
