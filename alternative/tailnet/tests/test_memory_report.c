/* Prints every diagnostics report the serial console can produce; tools/test-memory-report.py checks the JSON. */
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
        .grow_denied_largest = 17, .grow_denied_nomem = 18, .grow_raced = 19, .pm_acquired = 20, .pm_released = 19, .pm_held = 1};
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
struct stats_ lwip_stats;
#include "wireguard_replay.h"
unsigned ml_wg_rx_stat_count(void) { return WG_RXS_COUNT; }          /* ml_wg_mgr.c in the firmware */
uint32_t ml_wg_rx_stat(unsigned which) { return wireguard_rx_stat_get(which); }
const char *ml_wg_rx_stat_name(unsigned which) { return wireguard_rx_stat_name(which); }
unsigned ml_wg_replay_window(void) { return WIREGUARD_REPLAY_WINDOW_SIZE; }
#include "json_writer.inc"
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
    const char *commands[] = {"memory", "route", "inbound", "members", "memory bench", "memory locks", "wgperf", "wgperf logbench", "wgperf reset", "wgperf", "cpu", "memory guard 4096", "memory guard", "memory guard 70000", "memory guard 12x", "memory nonsense"};
    for (unsigned i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        printf("#> %s\n", commands[i]);
        printf("#handled %d\n", gateway_memory_command(commands[i]));
    }
    task_count = 40;   /* more tasks than the report's table: it must say so, not print an empty list silently */
    puts("#> cpu_many");
    gateway_memory_command("cpu");
    members_busy = true;
    puts("#> busy");
    gateway_memory_command("memory");
    return 0;
}
