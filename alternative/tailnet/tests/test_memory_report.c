/* Prints every diagnostics report the serial console can produce; tools/test-memory-report.py checks the JSON. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "tdongle_memory.h"
#include "ml_gateway_limits.h"
#include "usb_rx_budget.h"
#define CONFIG_TINYUSB_NCM_IN_NTB_BUFFS_COUNT 2
/* The real struct: a field added to the firmware's stats must be filled in here, not silently dropped. */
typedef uint32_t TickType_t;
#define tinyusb_net_tx_ring_stats real_tinyusb_net_tx_ring_stats   /* the header's declaration; the test supplies its own */
#include "../../../components/esp_tinyusb/include/tinyusb_net.h"
#undef tinyusb_net_tx_ring_stats
static void tinyusb_net_tx_ring_stats(tinyusb_net_tx_stats_t *s) {
    *s = (tinyusb_net_tx_stats_t){
        .ring_bytes = 9144, .base_bytes = 4572, .max_bytes = 35052, .elastic_held_bytes = 6096, .chunks = 2,
        .high_water_bytes = 4212, .high_water_slabs = 9, .enqueued_frames = 90, .enqueued_bytes = 120000, .sent_frames = 80,
        .sent_bytes = 100000, .dropped_full = 7, .dropped_link_down = 1, .dropped_invalid = 2, .flushed_link_down = 3,
        .ntb_blocked = 4, .xfer_events = 55, .worker_stack_free = 900, .grow_events = 11, .shrink_events = 12,
        .reclaim_events = 13, .reclaimed_chunks = 14, .grow_denied_gate = 15, .grow_denied_heap = 16,
        .grow_denied_largest = 17, .grow_denied_nomem = 18, .grow_raced = 19, .pm_acquired = 20, .pm_released = 19, .pm_held = 1,
        .ntb_xfers = 40, .ntb_zlp = 2, .ntb_bytes = 100000, .ntb_max_bytes = 3190, .drains_sent = {1, 2, 3, 4, 5},
        .gap_count = 30, .gap_us_sum = 150000, .gap_us_max = 21000, .gap_hist = {6, 7, 8, 9, 10},
        .cold_starts = 21, .cold_us_sum = 42000, .cold_us_max = 9000, .worker_demotions = 22};
}
static gateway_usb_rx_budget usb_rx_budget;
#define GATEWAY_VERSION "0.0.0-test"
#include "route_table.h"
uint32_t gateway_route_stat(unsigned which) { return which * 3; }
#define CONFIG_LWIP_MAX_SOCKETS 20
#define CONFIG_LWIP_TCP_RECVMBOX_SIZE 6
#define CONFIG_LWIP_UDP_RECVMBOX_SIZE 10
#define CONFIG_LWIP_TCPIP_RECVMBOX_SIZE 32
#define CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM 6
#define CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM 16
#define CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM 16
#define CONFIG_TDONGLE_MEMORY_ADMISSION_OVERRIDE 1
#define ML_TASK_NET_IO_STACK 7168
#define ML_TASK_DERP_TX_STACK 7680
#define ML_TASK_COORD_STACK 8704
#define ML_TASK_WG_MGR_STACK 8192
#define ML_JSON_BUFFER_SIZE 65536
#define ML_H2_BUFFER_SIZE 65536
#define ML_DERP_TX_QUEUE_DEPTH 8
#define ML_DISCO_RX_QUEUE_DEPTH 8
#define ML_WG_RX_QUEUE_DEPTH 8
#define ML_STUN_RX_QUEUE_DEPTH 4
#define MALLOC_CAP_8BIT 2
typedef void *TaskHandle_t;
typedef void *SemaphoreHandle_t;
typedef struct { char opaque[336]; } StaticTask_t;
typedef struct { TaskHandle_t coord_task; bool rt_attached, stop_incomplete; size_t h2_acc_len; uint8_t *lp_acc; } microlink_t;
/* The shared runtime: three tasks whose handles are 1000 (net_io), 2000 (derp) and 4000 (wg_mgr) in this test. */
typedef enum { ML_RT_TASK_NET_IO, ML_RT_TASK_DERP, ML_RT_TASK_WG_MGR, ML_RT_TASK_COUNT } ml_rt_task_t;
typedef struct { bool running; uint32_t stack_bytes[ML_RT_TASK_COUNT]; } ml_rt_status_t;
static void *ml_rt_task_handle(ml_rt_task_t t) { static const uintptr_t h[] = {1000, 2000, 4000}; return (void *)h[t]; }
static void ml_rt_status(ml_rt_status_t *out) {
    out->running = true;
    out->stack_bytes[0] = ML_TASK_NET_IO_STACK; out->stack_bytes[1] = ML_TASK_DERP_TX_STACK; out->stack_bytes[2] = ML_TASK_WG_MGR_STACK;
}
typedef struct membership { struct membership *next; uint32_t id; microlink_t *client; } membership_t;
static membership_t *members;
static SemaphoreHandle_t members_lock;
static bool members_busy;
static int xSemaphoreTake(SemaphoreHandle_t s, int ticks) { return members_busy ? 0 : 1; }
static void xSemaphoreGive(SemaphoreHandle_t s) {}
static uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t t) { return (uint32_t)(uintptr_t)t; }
static size_t member_queue_bytes(void) { return 1234; }
static struct { void *block; size_t size; } sizes[16];
int64_t esp_timer_get_time(void) { return 123456000; }
size_t heap_caps_get_free_size(unsigned c) { return 60000; }
size_t heap_caps_get_minimum_free_size(unsigned c) { return 31000; }
size_t heap_caps_get_largest_free_block(unsigned c) { return 24576; }
size_t heap_caps_get_total_size(unsigned c) { return 300000; }
size_t heap_caps_get_allocated_size(void *p) { for (unsigned i = 0; i < 16; i++) if (sizes[i].block == p) return sizes[i].size; return 0; }
bool ml_wg_log_bench(unsigned rounds, uint32_t *c) { *c = 31000; return rounds == 200; }
bool ml_wg_crypto_bench(size_t len, unsigned rounds, uint32_t *aead_ns, uint32_t *copy_ns) { *aead_ns = 2000000; *copy_ns = 20000; return true; }
void mgmt_write(const char *s) { fputs(s, stdout); }
static void *tracked(size_t size) { void *p = malloc(size); for (unsigned i = 0; i < 16; i++) if (!sizes[i].block) { sizes[i] = (typeof(sizes[0])){p, size}; break; } return p; }
/* `cpu`: the FreeRTOS task table (trace facility), pinned to fixed values. */
#include "tdongle_pm_burst.h"
typedef struct {bool scaling;int configure_error;uint32_t max_mhz,min_mhz,cpu_mhz,lock_create_failures;unsigned bursts;tdongle_pm_burst_stats_t burst[8];} tdongle_pm_status_t;
static void tdongle_pm_status(tdongle_pm_status_t *o) { memset(o, 0, sizeof(*o)); o->cpu_mhz = 240; }
#define portNUM_PROCESSORS 2
typedef unsigned UBaseType_t;
typedef int BaseType_t;
typedef struct { TaskHandle_t xHandle; const char *pcTaskName; uint32_t ulRunTimeCounter; UBaseType_t uxCurrentPriority; uint32_t usStackHighWaterMark; } TaskStatus_t;
static UBaseType_t task_count = 3;
static UBaseType_t uxTaskGetNumberOfTasks(void) { return task_count; }
static UBaseType_t uxTaskGetSystemState(TaskStatus_t *t, UBaseType_t n, uint32_t *total) {
    static const char *const names[] = {"IDLE0", "ml_wg_mgr", "tiT"};
    for (UBaseType_t i = 0; i < 3; i++) t[i] = (TaskStatus_t){(TaskHandle_t)(uintptr_t)(i + 1), names[i], 1000 * (i + 1), 5 + i, 700 + i};
    *total = 4294967295u;
    return 3;
}
static BaseType_t xTaskGetCoreID(TaskHandle_t h) { return (uintptr_t)h == 3 ? 0x7fffffff : (int)((uintptr_t)h - 1); }
/* The inbound counters the `inbound` report reads: the real definitions live in ml_net_io.c / wireguard.c and lwIP. */
#include "lwip/stats.h"
#include "ml_rx_stats.h"
#include "wireguard_stats.h"
ml_rx_stats_t ml_rx_stats;
wireguard_rx_stats_t wireguard_rx_stats;
#include "wireguard_replay.h"
unsigned ml_wg_rx_stat_count(void) { return WG_RXS_COUNT; }          /* ml_wg_mgr.c in the firmware */
uint32_t ml_wg_rx_stat(unsigned which) { return wireguard_rx_stat_get(which); }
const char *ml_wg_rx_stat_name(unsigned which) { return wireguard_rx_stat_name(which); }
unsigned ml_wg_replay_window(void) { return WIREGUARD_REPLAY_WINDOW_SIZE; }
unsigned ml_wg_rx_batch_size(void) { return 8; }
#include "ml_wg_rx_budget.h"
ml_wgrx_budget_t ml_wgrx_budget = {.bytes = 4096, .peak = 11000};
#include "wifi_pin_budget.h"
static gateway_wifi_pins wifi_pins = GATEWAY_WIFI_PINS_INIT;
static unsigned wifi_pins_tx_outstanding(void) { return gw_wtx_outstanding(&wifi_pins); }
static unsigned wifi_pins_rx_inflight(void) { return gw_wrx_inflight(&wifi_pins); }
static int wifi_current = 1;   /* slot 2 selected and pinned: the report shows the user's choice */
#include "wifi_policy.h"
static wifi_pin wifi_pinned = {1, 0, 0};
#include "json_writer.inc"
#include "wifi_link.inc"
/* esp_timer's periodic API, for heap_low_start() (never run on the host). */
typedef void *esp_timer_handle_t;
typedef struct { void (*callback)(void *); const char *name; } esp_timer_create_args_t;
static int esp_timer_create(const esp_timer_create_args_t *a, esp_timer_handle_t *h) { (void)a; (void)h; return 0; }
static int esp_timer_start_periodic(esp_timer_handle_t h, uint64_t us) { (void)h; (void)us; return 0; }
/* The bridge's counters (bridge_status.inc), the numbers the `bridge` report must print. */
#include "tdongle_l2.h"
static bool wifi_pins_installed = true, wifi_pins_tx_done_ok = true;
static bool bridge_mode = true;
bool gateway_tailnet_mode(void) { return !bridge_mode; }
void tdongle_l2_stats(tdongle_l2_stats_t *s) {
    *s = (tdongle_l2_stats_t){.linked = true, .link_changes = 5, .worker_stack_free = 1900,
        .w2h_frames = 100, .w2h_forwarded = 90, .w2h_invalid = 2, .w2h_own_mac = 3, .w2h_link_down = 1, .w2h_usb_not_ready = 1, .w2h_ring_full = 3, .w2h_raced = 1, .pm_notes = 50, .pm_note_us_sum = 900, .pm_note_us_max = 400, .h2w_wait_us_sum = 5000, .h2w_wait_us_max = 800, .h2w_tx_us_sum = 3000, .h2w_tx_us_max = 120,
        .h2w_frames = 76, .h2w_queued = 70, .h2w_invalid = 1, .h2w_foreign_mac = 2, .h2w_link_down = 3, .h2w_held = 9, .h2w_resumes = 8,
        .h2w_ecn_not_ect = 11, .h2w_ecn_capable = 22, .h2w_ecn_ce = 3, .h2w_ecn_exempt = 4, .h2w_ecn_not_ip = 5, .h2w_syn_ecn_setup = 2, .w2h_synack_ecn = 1, .h2w_codel_signals = 9, .h2w_ce_marked = 5, .h2w_codel_drop = 4, .h2w_codel_count = 3, .h2w_signal_us_sum = 40000, .h2w_signal_us_max = 12000, .h2w_room_waits = 7, .h2w_room_wait_us_sum = 7000, .h2w_room_wait_us_max = 1500, .h2w_sent = 58, .h2w_stale = 4, .h2w_sojourn_drop = 2, .h2w_link_down_queued = 2, .h2w_tx_failed = 3, .h2w_tx_retries = 11, .h2w_last_tx_error = -1,
        .h2w_queue_depth = 1, .h2w_queue_high_water = 9};
}
/* the run-time knobs (bridgetune): the setters the command calls */
#define GATEWAY_BRIDGE_TUNE 1
static tdongle_l2_tuning_t tuning = {.queue_limit = 3, .resume_depth = 1, .sojourn_ms = 100, .codel = false, .codel_target_us = 5000, .codel_interval_ms = 100, .host_idle_us = 6000};
esp_err_t tdongle_l2_set_tuning(const tdongle_l2_tuning_t *t) { tuning = *t; return ESP_OK; }
void tdongle_l2_get_tuning(tdongle_l2_tuning_t *t) { *t = tuning; }
static unsigned ring_chunks = 10;
esp_err_t tinyusb_net_tx_ring_set_max_chunks(unsigned n) { ring_chunks = n; return ESP_OK; }
unsigned tinyusb_net_tx_ring_max_chunks(void) { return ring_chunks; }
void tinyusb_net_rx_stats(tinyusb_net_rx_stats_t *o) { *o = (tinyusb_net_rx_stats_t){.ntbs = 30, .ntb_bytes = 60000, .ntb_max_bytes = 3190, .datagrams = 55, .dwell_us_sum = 5000, .dwell_us_max = 900, .holds = 4, .hold_us_sum = 3000, .hold_us_max = 1500}; }
static unsigned tx_limit_stub = 6;
static unsigned wifi_pins_tx_limit_now(void) { return tx_limit_stub; }
static void wifi_pins_set_tx_limit(unsigned n) { tx_limit_stub = n; }
#include "bridge_status.inc"
#include "memory_diagnostics.inc"
int main(void) {
    microlink_t client = {(void *)3000, true, false, 0, NULL};
    membership_t second = {NULL, 9, NULL}, first = {&second, 7, &client};
    members = &first;
    tdongle_heap_tag(TDONGLE_OWNER_PACKET, tracked(1500));
    tdongle_heap_tag(TDONGLE_OWNER_MAP, tracked(900));
    tdongle_memory_phase(7, TDONGLE_PHASE_START);
    tdongle_memory_phase(7, TDONGLE_PHASE_CONTROL);
    tdongle_memory_phase(7, TDONGLE_PHASE_STEADY);
    for (int v = 0; v <= TDONGLE_ADMIT_START_FAILED; v++) {
        tdongle_admission_record r = {5000 + v, 7, 50000, 24000, 108000, 11, 20, 1, (uint32_t)v};
        tdongle_memory_admission_note(&r);
    }
    tdongle_memory_drop(TDONGLE_DROP_DERP_TX_FULL);
    tdongle_wgperf_reset_now();
    tdongle_wgperf_add(&tdongle_wgperf, TDONGLE_WGPERF_lock_wait, 100);tdongle_wgperf_add(&tdongle_wgperf, TDONGLE_WGPERF_lock_wait, 250);
    tdongle_wgperf_add(&tdongle_wgperf, TDONGLE_WGPERF_pass, 0xffffffffu);tdongle_wgperf_add(&tdongle_wgperf, TDONGLE_WGPERF_pass, 5);
    tdongle_wgperf_count(&tdongle_wgperf, TDONGLE_WGPERF_C_passes, 2);
    for (unsigned i = 0; i < ML_RXS_COUNT; i++) ml_rx_stat_add((ml_rx_stat_t)i, 100 + i);
    ml_rx_stat_burst(13);
    for (unsigned i = 0; i < WG_RXS_COUNT; i++) for (unsigned k = 0; k < 200 + i; k++) wireguard_rx_stat_add((wireguard_rx_stat_t)i);
    lwip_stats.udp.recv = 5000; lwip_stats.udp.drop = 1; lwip_stats.udp.memerr = 2; lwip_stats.udp.err = 3;
    tdongle_lock_hold(TDONGLE_LOCK_WG_PERIODIC, 700);tdongle_lock_hold(TDONGLE_LOCK_WG_PERIODIC, 42000);
    /* `memory low`: only a NEW minimum below the elastic floor is recorded; the first record is kept when the ring wraps. */
    {
        heap_low_rec_t r = {.uptime_ms = 1000, .min_free = 40000, .free_now = 40000, .largest = 24000};
        assert(!heap_low_note(&r));                                      /* above the floor: nothing */
        r.min_free = 29000; r.free_now = 31000; r.tx_ring_bytes = 7620; r.tx_elastic_bytes = 3048; r.wgq_bytes = 5000; r.rx_inflight = 3; r.packet_live = 5200;
        r.wifi_rx_pins = 4; r.wifi_tx_inflight = 2;
        assert(heap_low_note(&r));
        assert(!heap_low_note(&r));                                      /* the same minimum again: nothing */
        for (uint32_t m = 28000; m > 28000 - 10 * 500; m -= 500) { r.min_free = m; r.uptime_ms++; assert(heap_low_note(&r)); }
        assert(heap_low_count == 11 && heap_low_rec[0].min_free == 29000 && heap_low_rec[0].free_hi == 40000);
        assert(heap_low_rec[1 + (11 - 1 - 1) % 7].min_free == 23500);   /* the newest record is the lowest */
        assert(heap_low_free_hi == 40000);
    }
    atomic_store(&wifi_pins.tx_charged, 10); atomic_store(&wifi_pins.tx_done, 6); atomic_store(&wifi_pins.tx_aborted, 1); atomic_store(&wifi_pins.tx_flushed, 2);
    atomic_store(&wifi_pins.tx_stale, 1); atomic_store(&wifi_pins.tx_refused_heap, 4); atomic_store(&wifi_pins.tx_refused_pool, 5);
    puts("#> bridgetune_show");
    printf("#handled %d\n", gateway_memory_command("bridgetune"));
    puts("#> bridgetune_set");
    printf("#handled %d\n", gateway_memory_command("bridgetune q=2 inflight=8 ring=4 codel=1 target_us=4000"));
    puts("#> bridgetune_bad");
    gateway_memory_command("bridgetune q=99");
    puts("#> bridgetune_bad2");
    gateway_memory_command("bridgetune zz=1");
    puts("#> bridgetune_other");
    printf("#handled %d\n", gateway_memory_command("bridgetunes"));
    puts("#> bridge");
    printf("#handled %d\n", gateway_memory_command("bridge"));
    bridge_mode = false;
    puts("#> bridge_tailnet");
    gateway_memory_command("bridge");
    bridge_mode = true;
    puts("#> bridge_status_lines");
    bridge_status_lines();
    const char *commands[] = {"memory", "memory low", "route", "inbound", "members", "memory bench", "memory locks", "wgperf", "wgperf logbench", "wgperf reset", "wgperf", "cpu", "memory guard 4096", "memory guard", "memory guard 70000", "memory guard 12x", "memory nonsense"};
    for (unsigned i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        printf("#> %s\n", commands[i]);
        printf("#handled %d\n", gateway_memory_command(commands[i]));
    }
    /* Wi-Fi link and lwIP counters: a 16-bit counter near its wrap, a pool with failed allocations, then a reset. */
    host_wifi_ap = (wifi_ap_record_t){.primary = 6, .second = WIFI_SECOND_CHAN_ABOVE, .rssi = -70, .phy_11b = 1, .phy_11g = 1, .phy_11n = 1, .bandwidth = WIFI_BW_HT40,
                                      .bssid = {1, 2, 3, 4, 5, 6}, .ssid = "do-not-print"};
    host_wifi_avg_rssi = -64; host_wifi_phy = WIFI_PHY_MODE_HT40; host_wifi_bw = WIFI_BW_HT40; host_wifi_ps = WIFI_PS_NONE; host_wifi_power = 78;
    wifi_link_note_connect(&wifi_link_stats);
    wifi_link_note_disconnect(&wifi_link_stats, WIFI_REASON_BEACON_TIMEOUT, -88, 4242);
    wifi_link_note_connect(&wifi_link_stats);
    wifi_link_note_disconnect(&wifi_link_stats, 8, -50, 5000);
#if LWIP_STATS
    lwip_stats.link = (struct stats_proto){.xmit = 10, .recv = 65535, .drop = 3, .memerr = 2, .err = 1};
    lwip_stats.tcp = (struct stats_proto){.recv = 500, .drop = 7, .cachehit = 9};
    lwip_stats.mem = (struct stats_mem){.name = "HEAP", .err = 4, .avail = 100, .used = 40, .max = 60, .illegal = 1};
    static struct stats_mem pbuf = {.name = "PBUF", .avail = 16, .used = 2, .max = 9, .err = 5}, pool = {.name = "PBUF_POOL", .avail = 16, .used = 1, .max = 16, .err = 11}, nameless = {.avail = 1};
    lwip_stats.memp[MEMP_PBUF] = &pbuf; lwip_stats.memp[MEMP_PBUF_POOL] = &pool; lwip_stats.memp[MEMP_TCP_SEG] = &nameless;
#endif
    puts("#> wifistats_before");
    printf("#handled %d\n", gateway_memory_command("wifistats"));
    puts("#> wifistats_dump");
    printf("#handled %d\n", gateway_memory_command("wifistats dump"));
    puts("#> wifistats_reset");
    printf("#handled %d\n", gateway_memory_command("wifistats reset"));
    puts("#> wifistats_after");
    gateway_memory_command("wifistats");
    puts("#> wifistats_unknown_arg");
    printf("#handled %d\n", gateway_memory_command("wifistats nonsense"));
    host_wifi_associated = false;
    puts("#> wifistats_down");
    gateway_memory_command("wifistats");
    host_wifi_associated = true; host_wifi_fail_rssi = host_wifi_fail_phy = host_wifi_fail_bw = host_wifi_fail_ps = host_wifi_fail_power = true;
    puts("#> wifistats_partial");
    gateway_memory_command("wifistats");
    printf("#dumps %u\n", host_wifi_dumps);
    task_count = 40;   /* more tasks than the report's table: it must say so, not print an empty list silently */
    puts("#> cpu_many");
    gateway_memory_command("cpu");
    members_busy = true;
    puts("#> busy");
    gateway_memory_command("memory");
    return 0;
}
