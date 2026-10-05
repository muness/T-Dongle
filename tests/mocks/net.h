// SPDX-License-Identifier: MIT
/* Host stand-ins for FreeRTOS, TinyUSB and ESP-IDF, so the real tinyusb_net.c (with its #include lines removed)
 * compiles unchanged. The mocks are strict on purpose: the critical section is a real mutex and everything that
 * must never happen inside it (allocation, free, task calls, TinyUSB calls, a log line) or in the producer
 * (waiting, deferring, allocating) is an assert here. */
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <stddef.h>
typedef uint32_t TickType_t;
#include "tinyusb_net.h"
#ifndef TEST_NO_PM
#define CONFIG_PM_ENABLE 1
#else
#define CONFIG_PM_ENABLE 0
#endif
#define pdPASS 1
#define BIT0 1
#define pdTRUE 1
#define portMAX_DELAY ((TickType_t)0xFFFFFFFFu)
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
#define ESP_RETURN_ON_FALSE(a,e,...) do {if(!(a))return e;}while(0)
#define ESP_LOGW(...) do { assert(!in_crit); } while (0)
typedef void *TaskHandle_t;
typedef int EventBits_t;
typedef int *SemaphoreHandle_t;
typedef int *EventGroupHandle_t;
typedef int xfer_result_t;
static int schedule, allow_tx=1, free_count;
static _Atomic int notify_count;
static int real_xfer_calls;

/* ---- who is where ---- */
static _Thread_local int in_crit;          /* inside the TX critical section */
static _Thread_local int in_producer;      /* a case that models the lwIP core lock holder: it may never wait */
static _Thread_local unsigned crit_mine;   /* critical sections entered by this thread */
static _Atomic unsigned long crit_total;
typedef pthread_mutex_t portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED PTHREAD_MUTEX_INITIALIZER
#define portENTER_CRITICAL(m) do { pthread_mutex_lock(m); assert(!in_crit); in_crit = 1; crit_mine++; atomic_fetch_add(&crit_total, 1); } while (0)
#define portEXIT_CRITICAL(m) do { assert(in_crit); in_crit = 0; pthread_mutex_unlock(m); } while (0)

/* ---- scheduler / time ---- */
static int usb_ready=1, ntb_credit=-1, task_create_fail, task_created, task_stack, task_prio, task_core;
static _Atomic uint32_t mock_tick;
static uint32_t last_notify_wait;
static void (*delay_hook)(void);
static void (*xmit_hook)(const uint8_t*,uint16_t);
static void (*pre_copy_hook)(void);        /* runs inside tud_network_xmit, before the NTB copy: "the consumer is mid-copy" */
static pthread_mutex_t defer_lock = PTHREAD_MUTEX_INITIALIZER;
static void (*deferred[8])(void*);static void *args[8];static int pending;
static void run_deferred(void){
    for (;;) {
        pthread_mutex_lock(&defer_lock);
        if (!pending) { pthread_mutex_unlock(&defer_lock); return; }
        void(*f)(void*)=deferred[0];void *arg=args[0];pending--;memmove(deferred,deferred+1,pending*sizeof(*deferred));memmove(args,args+1,pending*sizeof(*args));
        pthread_mutex_unlock(&defer_lock);
        f(arg);
    }
}
static EventGroupHandle_t xEventGroupCreate(void){return calloc(1,sizeof(int));}
static SemaphoreHandle_t xSemaphoreCreateBinary(void){return calloc(1,sizeof(int));}
static void vSemaphoreDelete(SemaphoreHandle_t s){free(s);}
static void vEventGroupDelete(EventGroupHandle_t s){free(s);}
static void xSemaphoreGive(SemaphoreHandle_t s){assert(!*s);*s=1;}
static int xSemaphoreTake(SemaphoreHandle_t s,TickType_t wait){assert(!in_producer);if(wait==portMAX_DELAY && schedule==2){schedule=1;run_deferred();}if(!*s){assert(wait!=portMAX_DELAY);return 0;}*s=0;return 1;}
static void xEventGroupSetBits(EventGroupHandle_t e,int b){*e|=b;}
static void xEventGroupClearBits(EventGroupHandle_t e,int b){*e&=~b;}
static int xEventGroupWaitBits(EventGroupHandle_t e,int b,int clear,int all,int timeout){assert(!in_producer);(void)all;(void)timeout;if(schedule==0)run_deferred();int ret=*e&b;if(clear)*e&=~b;return ret;}
static void usbd_defer_func(void(*f)(void*),void *a,bool isr){assert(!in_producer&&!in_crit);(void)isr;pthread_mutex_lock(&defer_lock);assert(pending<8);deferred[pending]=f;args[pending++]=a;pthread_mutex_unlock(&defer_lock);}
static _Atomic int64_t mock_us;                   /* esp_timer_get_time(): the test moves it */
static int64_t esp_timer_get_time(void){return atomic_load(&mock_us);}
static int prio_sets, prio_cur=-1;
static void vTaskPrioritySet(TaskHandle_t h,unsigned p){assert(h==NULL&&!in_crit&&!in_producer);prio_sets++;prio_cur=(int)p;}
static uint32_t xTaskGetTickCount(void){return atomic_load(&mock_tick);}
static void vTaskDelay(TickType_t ticks){assert(!in_producer&&!in_crit);atomic_fetch_add(&mock_tick,(uint32_t)ticks);if(delay_hook)delay_hook();}

/* ---- TinyUSB ---- */
static bool tud_ready(void){assert(!in_crit);return usb_ready;}
static bool tud_network_can_xmit(uint16_t n){assert(!in_crit&&!in_producer);return allow_tx && n<=1518 && ntb_credit!=0;}
uint16_t tud_network_xmit_cb(uint8_t*,void*,uint16_t);
static void tud_network_xmit(void *ref,uint16_t n){assert(!in_crit&&!in_producer);if(pre_copy_hook)pre_copy_hook();uint8_t dest[1518];uint16_t got=tud_network_xmit_cb(dest,ref,n);assert(got==n);if(xmit_hook)xmit_hook(dest,n);if(ntb_credit>0)ntb_credit--;}
static void tud_network_recv_renew(void){}
static uint8_t tusb_get_mac_string_id(void){return 6;}
static void tinyusb_descriptors_set_string(const char *s,uint8_t id){(void)s;(void)id;}
static int xTaskCreatePinnedToCore(void(*f)(void*),const char *n,int stack,void *a,unsigned prio,TaskHandle_t *h,int core){task_core=core;(void)f;(void)n;(void)a;if(task_create_fail)return 0;task_created++;task_stack=stack;task_prio=(int)prio;*h=(TaskHandle_t)&task_created;return pdPASS;}
static int xTaskNotifyGive(TaskHandle_t h){assert(h&&!in_crit);atomic_fetch_add(&notify_count,1);return pdPASS;}
static int ulTaskNotifyTake(int clear,TickType_t wait){assert(clear==pdTRUE);assert(!in_producer&&!in_crit);last_notify_wait=wait;return atomic_exchange(&notify_count,0);}
static uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t h){(void)h;return 777;}
bool __real_netd_xfer_cb(uint8_t rhport,uint8_t ep,xfer_result_t r,uint32_t n){(void)rhport;(void)ep;(void)r;(void)n;real_xfer_calls++;return true;}

/* ---- heap: free memory is a test-controlled number minus what the code holds ---- */
#define MALLOC_CAP_INTERNAL 1
#define MALLOC_CAP_8BIT 2
static _Atomic long heap_total = 200000, heap_live_bytes, heap_live_blocks;
static _Atomic size_t mock_largest = 100000;   /* largest free block, set by the test */
static size_t frag_next;                       /* the next allocation leaves this as the largest block */
static int malloc_fail;
static _Atomic long malloc_calls;                /* allocation attempts (the cheap refusals must not even try) */
static void (*malloc_hook)(void);              /* runs inside heap_caps_malloc: "something else happens during a growth" */
static size_t heap_caps_get_free_size(int caps){(void)caps;assert(!in_crit);return (size_t)(atomic_load(&heap_total) - atomic_load(&heap_live_bytes));}
static _Atomic long largest_calls;                /* heap walks: the worker must not make them casually */
static size_t heap_caps_get_largest_free_block(int caps){(void)caps;assert(!in_crit);atomic_fetch_add(&largest_calls,1);return atomic_load(&mock_largest);}
static void *heap_caps_malloc(size_t n,int caps){
    (void)caps;assert(!in_crit&&!in_producer);
    if (malloc_hook) { void (*h)(void) = malloc_hook; malloc_hook = NULL; h(); }
    atomic_fetch_add(&malloc_calls,1);
    if (malloc_fail) return NULL;
    size_t *h = malloc(n + 16); assert(h); h[0] = n;
    atomic_fetch_add(&heap_live_bytes,(long)n); atomic_fetch_add(&heap_live_blocks,1);
    if (frag_next) { atomic_store(&mock_largest, frag_next); frag_next = 0; }
    return (uint8_t *)h + 16;
}
static void heap_caps_free(void *p){
    assert(!in_crit&&!in_producer);
    if(!p)return;
    size_t *h=(size_t *)((uint8_t *)p-16);
    atomic_fetch_sub(&heap_live_bytes,(long)h[0]); atomic_fetch_sub(&heap_live_blocks,1);
    memset(p, 0xdd, h[0]);                 /* a read after free sees poison even without ASan */
    free(h);
}

/* ---- power management: the caller's hold; every begin must pair with an end, never twice ---- */
static struct { int held; } mock_pm;
static int pm_acquires, pm_releases;
static void mock_pm_begin(void *ctx){(void)ctx;assert(!in_crit&&!in_producer);assert(!mock_pm.held);mock_pm.held=1;pm_acquires++;}
static void mock_pm_end(void *ctx){(void)ctx;assert(!in_crit&&!in_producer);assert(mock_pm.held);mock_pm.held=0;pm_releases++;}
