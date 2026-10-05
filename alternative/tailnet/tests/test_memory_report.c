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
#define GATEWAY_VERSION "0.0.0-test"
#include "route_table.h"
uint32_t gateway_route_stat(unsigned which) { return which * 3; }
#define CONFIG_LWIP_MAX_SOCKETS 20
#define CONFIG_LWIP_TCP_RECVMBOX_SIZE 6
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
bool ml_wg_crypto_bench(size_t len, unsigned rounds, uint32_t *aead_ns, uint32_t *copy_ns) { *aead_ns = 2000000; *copy_ns = 20000; return true; }
void mgmt_write(const char *s) { fputs(s, stdout); }
static void *tracked(size_t size) { void *p = malloc(size); for (unsigned i = 0; i < 16; i++) if (!sizes[i].block) { sizes[i] = (typeof(sizes[0])){p, size}; break; } return p; }
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
    tdongle_lock_hold(TDONGLE_LOCK_WG_PERIODIC, 700);tdongle_lock_hold(TDONGLE_LOCK_WG_PERIODIC, 42000);
    const char *commands[] = {"memory", "route", "members", "memory bench", "memory locks", "memory guard 4096", "memory guard", "memory guard 70000", "memory guard 12x", "memory nonsense"};
    for (unsigned i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        printf("#> %s\n", commands[i]);
        printf("#handled %d\n", gateway_memory_command(commands[i]));
    }
    members_busy = true;
    puts("#> busy");
    gateway_memory_command("memory");
    return 0;
}
