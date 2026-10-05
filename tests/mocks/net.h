// SPDX-License-Identifier: MIT
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#include <stddef.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM -2
#define ESP_ERR_TIMEOUT -3
#define ESP_ERR_INVALID_STATE -4
#define ESP_ERR_INVALID_ARG -5
#define pdPASS 1
#define BIT0 1
#define pdTRUE 1
#define portMAX_DELAY -1
#define ESP_RETURN_ON_FALSE(a,e,...) do {if(!(a))return e;}while(0)
#define ESP_LOGW(...) ((void)0)
typedef int TickType_t;
typedef void *TaskHandle_t;
typedef int EventBits_t;
typedef int *SemaphoreHandle_t;
typedef int *EventGroupHandle_t;
typedef esp_err_t (*tusb_net_rx_cb_t)(void*,uint16_t,void*);
typedef void (*tusb_net_free_tx_cb_t)(void*,void*);
typedef void (*tusb_net_init_cb_t)(void*);
typedef struct {tusb_net_rx_cb_t on_recv_callback;tusb_net_free_tx_cb_t free_tx_buffer;tusb_net_init_cb_t on_init_callback;void *user_context;uint8_t mac_addr[6];} tinyusb_net_config_t;
typedef struct {uint32_t ring_bytes,high_water_bytes,enqueued_frames,enqueued_bytes,sent_frames,sent_bytes,dropped_full,dropped_link_down,dropped_invalid,flushed_link_down,ntb_blocked;} tinyusb_net_tx_stats_t;
static int schedule, allow_tx=1, free_count;
/* Ring tests: producer context must never wait (it models the lwIP core lock holder). */
static int in_producer, usb_ready=1, ntb_credit=-1, notify_count, last_notify_wait, task_create_fail, task_created, task_stack, task_prio;
static void (*xmit_hook)(const uint8_t*,uint16_t);
static void (*deferred[8])(void*);static void *args[8];static int pending;
static void run_deferred(void){while(pending){void(*f)(void*)=deferred[0];void *arg=args[0];pending--;memmove(deferred,deferred+1,pending*sizeof(*deferred));memmove(args,args+1,pending*sizeof(*args));f(arg);}}
static EventGroupHandle_t xEventGroupCreate(void){return calloc(1,sizeof(int));}
static SemaphoreHandle_t xSemaphoreCreateBinary(void){return calloc(1,sizeof(int));}
static void vSemaphoreDelete(SemaphoreHandle_t s){free(s);}
static void vEventGroupDelete(EventGroupHandle_t s){free(s);}
static void xSemaphoreGive(SemaphoreHandle_t s){assert(!*s);*s=1;}
static int xSemaphoreTake(SemaphoreHandle_t s,int wait){assert(!in_producer);if(wait==portMAX_DELAY && schedule==2){schedule=1;run_deferred();}if(!*s){assert(wait!=portMAX_DELAY);return 0;}*s=0;return 1;}
static void xEventGroupSetBits(EventGroupHandle_t e,int b){*e|=b;}
static void xEventGroupClearBits(EventGroupHandle_t e,int b){*e&=~b;}
static int xEventGroupWaitBits(EventGroupHandle_t e,int b,int clear,int all,int timeout){assert(!in_producer);(void)all;(void)timeout;if(schedule==0)run_deferred();int ret=*e&b;if(clear)*e&=~b;return ret;}
static void usbd_defer_func(void(*f)(void*),void *a,bool isr){assert(!in_producer);(void)isr;assert(pending<8);deferred[pending]=f;args[pending++]=a;}
static bool tud_ready(void){return usb_ready;}
static bool tud_network_can_xmit(uint16_t n){return allow_tx && n<=1514 && ntb_credit!=0;}
uint16_t tud_network_xmit_cb(uint8_t*,void*,uint16_t);
static void tud_network_xmit(void *ref,uint16_t n){uint8_t dest[1514];uint16_t got=tud_network_xmit_cb(dest,ref,n);assert(got==n);if(xmit_hook)xmit_hook(dest,n);if(ntb_credit>0)ntb_credit--;}
static void tud_network_recv_renew(void){}
static uint8_t tusb_get_mac_string_id(void){return 6;}
static void tinyusb_descriptors_set_string(const char *s,uint8_t id){(void)s;(void)id;}
static int xTaskCreate(void(*f)(void*),const char *n,int stack,void *a,unsigned prio,TaskHandle_t *h){(void)f;(void)n;(void)a;if(task_create_fail)return 0;task_created++;task_stack=stack;task_prio=(int)prio;*h=(TaskHandle_t)&task_created;return pdPASS;}
static int xTaskNotifyGive(TaskHandle_t h){assert(h);notify_count++;return pdPASS;}
static int ulTaskNotifyTake(int clear,int wait){assert(clear==pdTRUE);assert(!in_producer);last_notify_wait=wait;int n=notify_count;notify_count=0;return n;}
