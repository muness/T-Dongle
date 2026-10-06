/* Host harness: the REAL report_* functions and gateway_memory_command of memory_diagnostics.inc (cut out by tools/gen_golden.py; the functions that
 * touch the RTOS are replaced by stubs) driven by a scenario: one JSON line on stdin per run. Numeric inputs are looked up by name in scenario.k.
 * Output per scenario: "RET <0|1>" then "CHUNKS ..." then "OUT <hex>". */
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
#include "sdkconfig.h"
#ifndef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
#define CONFIG_TDONGLE_MEMORY_DIAGNOSTICS 1
#endif
static cJSON *g_s;
static double Kd(const char *n) { cJSON *k = cJSON_GetObjectItemCaseSensitive(g_s, "k"); cJSON *i = k ? cJSON_GetObjectItemCaseSensitive(k, n) : NULL; if (!i) { fprintf(stderr, "missing k.%s\n", n); abort(); } return i->valuedouble; }
#define K(n) ((unsigned)(uint32_t)(uint64_t)Kd(n))
static double KAd(const char *n, unsigned idx) { cJSON *k = cJSON_GetObjectItemCaseSensitive(g_s, "k"); cJSON *a = cJSON_GetObjectItemCaseSensitive(k, n); assert(a); return cJSON_GetArrayItem(a, idx)->valuedouble; }
#define KA(n, i) ((uint32_t)(uint64_t)KAd(n, i))
static char g_version[64];
#define GATEWAY_VERSION (g_version)
typedef int esp_err_t;
#define ESP_OK 0
#define MALLOC_CAP_INTERNAL 1
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define portNUM_PROCESSORS 2
#define TDONGLE_WGPERF_CYCLES() 0u
#define TDONGLE_WGPERF_US() 0u
#include "tdongle_memory.h"
#include "tdongle_wgperf.h"
#include "tdongle_pm_burst.h"
#include "json_writer.inc"
/* ---- stubs ---- */
static int64_t g_timer[8]; static unsigned g_timer_i;
static int64_t esp_timer_get_time(void) { return g_timer[g_timer_i < 8 ? g_timer_i++ : 7]; }
static void mgmt_write(const char *s) { printf("P "); for (; *s; s++) printf("%02x", (unsigned char)*s); printf("\n"); }
static unsigned heap_caps_get_free_size(int c) { return K("heap_free"); }
static unsigned heap_caps_get_minimum_free_size(int c) { return K("heap_min"); }
static unsigned heap_caps_get_largest_free_block(int c) { return K("heap_largest"); }
static unsigned heap_caps_get_total_size(int c) { return K("heap_total"); }
uint32_t tdongle_heap_guard_floor(void) { return K("guard_floor"); }
uint32_t tdongle_heap_underflows(void) { return K("underflows"); }
size_t tdongle_memory_ledger_bytes(void) { return K("ledger_bytes"); }
tdongle_owner_stats tdongle_heap_owner(tdongle_owner o) { return (tdongle_owner_stats){KA("owner_live", o), KA("owner_peak", o), KA("owner_allocs", o), KA("owner_frees", o), KA("owner_failed", o), KA("owner_denied", o)}; }
uint32_t tdongle_memory_drops(tdongle_drop d) { return KA("drops", d); }
#define ML_DERP_TX_QUEUE_DEPTH K("q_derp_tx")
#define ML_DISCO_RX_QUEUE_DEPTH K("q_disco_rx")
#define ML_WG_RX_QUEUE_DEPTH K("q_wg_rx")
#define ML_STUN_RX_QUEUE_DEPTH K("q_stun_rx")
#define ML_TASK_COORD_STACK K("coord_stack")
#define ML_JSON_BUFFER_SIZE K("json_buffer")
#define ML_H2_BUFFER_SIZE K("h2_buffer")
#define ML_GATEWAY_PLAIN_BYTES K("plain_bytes")
#define ML_GATEWAY_JSON_BYTES K("json_bytes")
typedef struct { char b[336]; } StaticTask_t;
typedef int TaskHandle_t;
typedef enum {ML_RT_TASK_NET_IO, ML_RT_TASK_DERP, ML_RT_TASK_WG_MGR, ML_RT_TASK_COUNT} ml_rt_task_t;
typedef struct {bool running; unsigned members; uint32_t starts, stops, attach_failures, detach_failures, stack_bytes[3], stack_free[3], passes[3], max_service_ms[3], slow_services[3], detach_timeouts[3];} ml_rt_status_t;
static void ml_rt_status(ml_rt_status_t *o) { memset(o, 0, sizeof *o); o->running = K("rt_running"); for (int i = 0; i < 3; i++) o->stack_bytes[i] = KA("rt_stack_bytes", i); }
static size_t member_queue_bytes(void) { return K("member_queue_bytes"); }
#define TCP_WND K("TCP_WND")
#define TCP_SND_BUF K("TCP_SND_BUF")
#define TCP_MSS K("TCP_MSS")
#define TCP_SND_QUEUELEN K("TCP_SND_QUEUELEN")
#define LWIP_WND_SCALE K("LWIP_WND_SCALE")
#define PBUF_POOL_SIZE K("PBUF_POOL_SIZE")
#define PBUF_POOL_BUFSIZE K("PBUF_POOL_BUFSIZE")
#define MEMP_NUM_TCP_PCB K("MEMP_NUM_TCP_PCB")
#define MEMP_NUM_TCP_SEG K("MEMP_NUM_TCP_SEG")
#define CONFIG_LWIP_MAX_SOCKETS K("max_sockets")
#define CONFIG_LWIP_TCP_RECVMBOX_SIZE K("tcp_recvmbox")
#define CONFIG_LWIP_UDP_RECVMBOX_SIZE K("udp_recvmbox")
#define CONFIG_LWIP_TCPIP_RECVMBOX_SIZE K("tcpip_recvmbox")
#define CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM K("wifi_static_rx")
#define CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM K("wifi_dynamic_rx")
#define CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM K("wifi_dynamic_tx")
typedef struct {
    uint32_t ring_bytes, base_bytes, max_bytes, elastic_held_bytes, chunks, grow_events, shrink_events, reclaim_events, reclaimed_chunks, grow_denied_gate, grow_denied_heap,
        grow_denied_largest, grow_denied_nomem, grow_raced, high_water_bytes, high_water_slabs, pm_acquired, pm_released, pm_held, enqueued_frames, enqueued_bytes, sent_frames, sent_bytes,
        dropped_full, dropped_link_down, dropped_invalid, flushed_link_down, ntb_blocked, xfer_events, worker_stack_free, ntb_xfers, ntb_zlp, ntb_bytes, ntb_max_bytes, drains_sent[5], gap_count,
        gap_us_sum, gap_us_max, gap_hist[5], cold_starts, cold_us_sum, cold_us_max, worker_demotions;
} tinyusb_net_tx_stats_t;
static const char *const usb_tx_names[] = {"ring_bytes", "base_bytes", "max_bytes", "elastic_held_bytes", "chunks", "grow_events", "shrink_events", "reclaim_events", "reclaimed_chunks", "grow_denied_gate", "grow_denied_heap",
    "grow_denied_largest", "grow_denied_nomem", "grow_raced", "high_water_bytes", "high_water_slabs", "pm_acquired", "pm_released", "pm_held", "enqueued_frames", "enqueued_bytes", "sent_frames", "sent_bytes",
    "dropped_full", "dropped_link_down", "dropped_invalid", "flushed_link_down", "ntb_blocked", "xfer_events", "worker_stack_free", "ntb_xfers", "ntb_zlp", "ntb_bytes", "ntb_max_bytes"};
static void tinyusb_net_tx_ring_stats(tinyusb_net_tx_stats_t *t) {
    memset(t, 0, sizeof *t);
    uint32_t *p = &t->ring_bytes;
    for (unsigned i = 0; i < sizeof usb_tx_names / sizeof *usb_tx_names; i++) p[i] = KA("usb_tx", i);
    for (int i = 0; i < 5; i++) { t->drains_sent[i] = KA("usb_drains", i); t->gap_hist[i] = KA("usb_gap_hist", i); }
    t->gap_count = K("gap_count"); t->gap_us_sum = K("gap_us_sum"); t->gap_us_max = K("gap_us_max"); t->cold_starts = K("cold_starts"); t->cold_us_sum = K("cold_us_sum");
    t->cold_us_max = K("cold_us_max"); t->worker_demotions = K("worker_demotions");
}
#define CONFIG_TINYUSB_NCM_IN_NTB_BUFFS_COUNT K("ntb_count")
#define GATEWAY_USB_RX_INFLIGHT_MAX K("rx_inflight_max")
static struct { atomic_uint inflight, high_water, dropped_busy, dropped_nomem, dropped_heap, dropped_invalid; } usb_rx_budget;
#define ML_HB_FLOOR K("hb_floor")
#define ML_HB_RESERVE K("hb_reserve")
#define portMUX_TYPE int
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(m) ((void)0)
#define portEXIT_CRITICAL(m) ((void)0)
typedef struct { unsigned count; uint32_t recorded; } dummy_t;
/* route / inbound */
#include "route_table_names.h"
static uint32_t gateway_route_stat(unsigned i) { return KA("route_stats", i); }
#define ROUTE_QUEUE_DEPTH 16
#define ROUTE_QUEUE_BYTES (16 * 1024)
#define RT_ALIASES 64
#define RT_FLOWS 64
#define ML_NET_IO_DRAIN_CAP K("drain_cap")
#define ML_WG_RX_QUEUE_BYTES K("wg_rx_queue_bytes")
static struct { atomic_uint bytes, peak; } ml_wgrx_budget;
static unsigned ml_wg_rx_batch_size(void) { return K("wg_rx_batch"); }
static unsigned ml_wg_replay_window(void) { return K("replay_window"); }
static unsigned ml_wg_rx_stat_count(void) { return cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(g_s, "wg_names")); }
static const char *ml_wg_rx_stat_name(unsigned i) { return cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(g_s, "wg_names"), i)->valuestring; }
static uint32_t ml_wg_rx_stat(unsigned i) { return KA("wg_values", i); }
#include "ml_rx_stats_names.h"
static struct { atomic_uint drain_burst_max; } ml_rx_stats_local;
#define ml_rx_stats ml_rx_stats_local
static uint32_t ml_rx_stat_get(unsigned i) { return KA("ml_values", i); }
#ifdef WITH_LWIP
#define LWIP_STATS 1
#define UDP_STATS 1
#define LINK_STATS 0
#define ETHARP_STATS 0
#define IP_STATS 0
#define ICMP_STATS 0
#define TCP_STATS 0
#define MEM_STATS 0
#define MEMP_STATS 0
typedef uint16_t STAT_COUNTER;
static struct { struct { uint16_t recv, drop, memerr, err; } udp; } lwip_stats;
typedef struct { int x; } ws_proto; typedef struct { int x; } ws_pool;
#define WS_PROTO_FROM(p, s) ((void)0)
static void ws_emit_proto(void (*e)(void *, const char *), void *c, const char *label, unsigned bits, uint32_t up, ws_proto *p) { printf("@ws_proto %s %u %u\n", label, bits, up); }
#else
#define LWIP_STATS 0
#endif
/* phases / admission / locks */
bool tdongle_memory_member_get(unsigned slot, tdongle_member_phases *out) {
    cJSON *a = cJSON_GetObjectItemCaseSensitive(g_s, "phases"); if (slot >= (unsigned)cJSON_GetArraySize(a)) return false;
    cJSON *m = cJSON_GetArrayItem(a, slot); memset(out, 0, sizeof *out);
    out->member_id = (uint32_t)cJSON_GetObjectItemCaseSensitive(m, "member")->valuedouble; out->attempt = (uint32_t)cJSON_GetObjectItemCaseSensitive(m, "attempt")->valuedouble;
    cJSON *ph = cJSON_GetObjectItemCaseSensitive(m, "phase");
    for (int p = 0; p < TDONGLE_PHASE_COUNT; p++) {
        cJSON *r = cJSON_GetArrayItem(ph, p);
        out->phase[p].valid = cJSON_GetObjectItemCaseSensitive(r, "valid")->valueint; out->phase[p].exact = cJSON_GetObjectItemCaseSensitive(r, "exact")->valueint;
        out->phase[p].uptime_ms = (uint32_t)cJSON_GetObjectItemCaseSensitive(r, "t")->valuedouble; out->phase[p].free_bytes = (uint32_t)cJSON_GetObjectItemCaseSensitive(r, "free")->valuedouble;
        out->phase[p].minimum_bytes = (uint32_t)cJSON_GetObjectItemCaseSensitive(r, "min")->valuedouble; out->phase[p].largest_bytes = (uint32_t)cJSON_GetObjectItemCaseSensitive(r, "largest")->valuedouble;
        for (int o = 0; o < TDONGLE_OWNER_COUNT; o++) out->phase[p].owner_peak[o] = (uint32_t)cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(r, "peak"), o)->valuedouble;
    }
    return true;
}
uint32_t tdongle_memory_slot_evictions(void) { return K("slot_evictions"); }
unsigned tdongle_memory_admission_count(void) { return cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(g_s, "admissions")); }
tdongle_admission_record tdongle_memory_admission_get(unsigned i) {
    cJSON *a = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(g_s, "admissions"), i); tdongle_admission_record r;
    uint32_t *f = &r.uptime_ms; for (int j = 0; j < 9; j++) f[j] = (uint32_t)cJSON_GetArrayItem(a, j)->valuedouble; return r;
}
tdongle_lock_stats tdongle_lock_stats_get(tdongle_lock_site site) {
    cJSON *a = cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(g_s, "locks"), site); tdongle_lock_stats s; memset(&s, 0, sizeof s);
    s.count = (uint32_t)cJSON_GetArrayItem(a, 0)->valuedouble; s.max_us = (uint32_t)cJSON_GetArrayItem(a, 1)->valuedouble; s.over_1ms = (uint32_t)cJSON_GetArrayItem(a, 2)->valuedouble;
    s.total_us = (uint64_t)cJSON_GetArrayItem(a, 3)->valuedouble; for (int b = 0; b < TDONGLE_LOCK_BUCKETS; b++) s.bucket[b] = (uint32_t)cJSON_GetArrayItem(a, 4 + b)->valuedouble; return s;
}
void *tdongle_heap_note_alloc(tdongle_owner o, void *b) { return b; }
void tdongle_heap_note_free(tdongle_owner o, void *b) {}
void tdongle_heap_adopt(tdongle_owner o, void *b) {}
/* wgperf */
tdongle_wgperf_t tdongle_wgperf;
typedef struct { unsigned cpu_mhz; } tdongle_pm_status_t;
static void tdongle_pm_status(tdongle_pm_status_t *o) { o->cpu_mhz = K("cpu_mhz"); }
void tdongle_wgperf_reset_now(void) { printf("@wgperf_reset\n"); }
static bool ml_wg_log_bench(unsigned rounds, uint32_t *c) { *c = K("cycles_per_line"); return K("logbench_ok"); }
static bool ml_wg_crypto_bench(unsigned bytes, unsigned rounds, uint32_t *aead, uint32_t *copy) { *aead = K("aead_ns"); *copy = K("copy_ns"); return K("crypto_ok"); }
/* cpu */
typedef struct { const char *pcTaskName; uint32_t ulRunTimeCounter; unsigned uxCurrentPriority; int xHandle; unsigned usStackHighWaterMark; } TaskStatus_t;
typedef unsigned UBaseType_t; typedef int BaseType_t;
static UBaseType_t uxTaskGetNumberOfTasks(void) { return K("tasks_existing"); }
static char g_task_names[40][40];
static UBaseType_t uxTaskGetSystemState(TaskStatus_t *t, UBaseType_t cap, uint32_t *total) {
    cJSON *a = cJSON_GetObjectItemCaseSensitive(g_s, "tasks"); unsigned n = cJSON_GetArraySize(a); *total = K("cpu_total");
    for (unsigned i = 0; i < n; i++) { cJSON *e = cJSON_GetArrayItem(a, i); const char *h = cJSON_GetArrayItem(e, 0)->valuestring; size_t len = strlen(h) / 2; for (size_t j = 0; j < len; j++) { unsigned v; sscanf(h + 2 * j, "%2x", &v); g_task_names[i][j] = v; } g_task_names[i][len] = 0;
        t[i] = (TaskStatus_t){g_task_names[i], (uint32_t)cJSON_GetArrayItem(e, 1)->valuedouble, (unsigned)cJSON_GetArrayItem(e, 2)->valuedouble, (int)i, (unsigned)cJSON_GetArrayItem(e, 4)->valuedouble}; }
    return n;
}
static BaseType_t xTaskGetCoreID(int h) { return (BaseType_t)cJSON_GetArrayItem(cJSON_GetArrayItem(cJSON_GetObjectItemCaseSensitive(g_s, "tasks"), h), 3)->valuedouble; }
#define CPU_TASKS_STUB
/* bridge */
typedef void (*bridge_emit_fn)(void *ctx, const char *section, const char *name, int64_t value);
static bool g_bridge_active;
static bool gateway_tailnet_mode(void) { return !g_bridge_active; }
static void bridge_visit(bridge_emit_fn emit, void *ctx) {
    cJSON *a = cJSON_GetObjectItemCaseSensitive(g_s, "bridge"), *e;
    cJSON_ArrayForEach(e, a) emit(ctx, cJSON_GetArrayItem(e, 0)->valuestring, cJSON_GetArrayItem(e, 1)->valuestring, (int64_t)cJSON_GetArrayItem(e, 2)->valuedouble);
}
static void bridge_tune_command(const char *args) { printf("@bridgetune[%s]\n", args); }
void tdongle_heap_set_guard_floor(uint32_t b) { printf("@guard %u\n", b); }
/* wifi */
typedef struct {int d;} wifi_link_info; typedef struct {int d;} wifi_link_events;
enum { WIFI_LINK_JSON_MAX = 480 };
static wifi_link_events wifi_link_stats; static char g_link_json[480]; static bool g_have_link;
static wifi_link_info wifi_link_read(void) { wifi_link_info i = {0}; return i; }
static size_t wifi_link_json(char *out, size_t cap, const wifi_link_info *l, const wifi_link_events *e) { if (!g_have_link) return 0; size_t n = strlen(g_link_json); memcpy(out, g_link_json, n + 1); return n; }
static esp_err_t esp_wifi_statis_dump(int f) { return (esp_err_t)K("wifi_dump_err"); }
#define WIFI_STATIS_ALL 0
typedef int ws_dummy;
#include "diag.inc"
static int unhex(const char *h, char *out) { size_t n = strlen(h) / 2; for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); out[i] = v; } out[n] = 0; return n; }
int main(void) {
    static char line[1 << 20];
    while (fgets(line, sizeof line, stdin)) {
        g_s = cJSON_Parse(line); assert(g_s);
        memset(g_version, 0, sizeof g_version); unhex(cJSON_GetObjectItemCaseSensitive(g_s, "firmware")->valuestring, g_version);
        cJSON *t = cJSON_GetObjectItemCaseSensitive(g_s, "timer"); g_timer_i = 0; for (int i = 0; t && i < cJSON_GetArraySize(t) && i < 8; i++) g_timer[i] = (int64_t)cJSON_GetArrayItem(t, i)->valuedouble;
        g_bridge_active = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(g_s, "bridge_active"));
        { cJSON *wl = cJSON_GetObjectItemCaseSensitive(g_s, "link"); g_have_link = cJSON_IsString(wl); if (g_have_link) unhex(wl->valuestring, g_link_json); }
        atomic_store(&usb_rx_budget.inflight, K("rx_inflight")); atomic_store(&usb_rx_budget.high_water, K("rx_high_water")); atomic_store(&usb_rx_budget.dropped_busy, K("rx_dropped_busy"));
        atomic_store(&usb_rx_budget.dropped_nomem, K("rx_dropped_nomem")); atomic_store(&usb_rx_budget.dropped_heap, K("rx_dropped_heap")); atomic_store(&usb_rx_budget.dropped_invalid, K("rx_dropped_invalid"));
        atomic_store(&ml_wgrx_budget.bytes, K("wg_rx_bytes_queued")); atomic_store(&ml_wgrx_budget.peak, K("wg_rx_bytes_peak")); atomic_store(&ml_rx_stats.drain_burst_max, K("drain_burst_max"));
        cJSON *ws = cJSON_GetObjectItemCaseSensitive(g_s, "wgperf");
        if (ws) {
            for (int i = 0; i < TDONGLE_WGPERF_STAGE_COUNT; i++) { cJSON *e = cJSON_GetArrayItem(ws, i); atomic_store(&tdongle_wgperf.stage[i].count, (uint32_t)cJSON_GetArrayItem(e, 0)->valuedouble);
                atomic_store(&tdongle_wgperf.stage[i].total, (unsigned long long)cJSON_GetArrayItem(e, 1)->valuedouble); atomic_store(&tdongle_wgperf.stage[i].max, (uint32_t)cJSON_GetArrayItem(e, 2)->valuedouble); }
            for (int i = 0; i < TDONGLE_WGPERF_COUNTER_COUNT; i++) atomic_store(&tdongle_wgperf.counter[i], KA("wgperf_counters", i));
            atomic_store(&tdongle_wgperf.since_us, K("since_us"));
        }
        const char *cmd = cJSON_GetObjectItemCaseSensitive(g_s, "command")->valuestring;
        char hexcmd[256]; unhex(cmd, hexcmd);
        bool ret = false;
        if (!strncmp(hexcmd, "@", 1)) {
            jw_writer w = {.sink = memory_sink};
            const char *r = hexcmd + 1;
            if (!strcmp(r, "heap")) report_heap(&w); else if (!strcmp(r, "attribution")) report_attribution(&w); else if (!strcmp(r, "lwip")) report_lwip(&w);
            else if (!strcmp(r, "usb")) report_usb(&w); else if (!strcmp(r, "locks")) report_locks(&w); else if (!strcmp(r, "route")) report_router(&w);
            else if (!strcmp(r, "phases")) report_phases(&w); else if (!strcmp(r, "admission")) report_admission(&w); else if (!strcmp(r, "inbound")) report_inbound(&w);
            else if (!strcmp(r, "wgperf")) report_wgperf(&w); else if (!strcmp(r, "cpu")) report_cpu(&w); else if (!strcmp(r, "bench")) report_bench(&w);
            else if (!strcmp(r, "logbench")) report_logbench(&w); else if (!strcmp(r, "bridge")) report_bridge(&w); else if (!strcmp(r, "wifi_link")) report_wifi_link(&w);
            else if (!strcmp(r, "wifi_reset")) report_wifi_reset(&w); else if (!strcmp(r, "wifi_dump")) report_wifi_dump(&w); else if (!strcmp(r, "lwip_stats")) report_wifi_lwip(&w);
            else if (!strcmp(r, "heap_low")) {
                /* replay the notes through the real heap_low_note, then report */
                cJSON *notes = cJSON_GetObjectItemCaseSensitive(g_s, "notes"), *n;
                cJSON_ArrayForEach(n, notes) { heap_low_rec_t in; uint32_t *f = &in.uptime_ms; for (int j = 0; j < 12; j++) f[j] = (uint32_t)cJSON_GetArrayItem(n, j)->valuedouble; printf("@note %d\n", heap_low_note(&in)); }
                report_heap_low(&w);
            }
            ret = true;
        } else {
            ret = gateway_memory_command(hexcmd);
        }
        printf("@ret %d\n", ret);
        cJSON_Delete(g_s);
    }
    return 0;
}
