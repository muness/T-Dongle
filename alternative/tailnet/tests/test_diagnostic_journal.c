#include "cJSON.h"
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../main/socket_budget.h"
#define ESP_OK 0
#define ESP_FAIL -1
#define HTTPD_403_FORBIDDEN 403
#define MALLOC_CAP_INTERNAL 1
#define pdTRUE 1
#define pdMS_TO_TICKS(n) (n)
enum {GATEWAY_DIAG_BOOT=11,GATEWAY_DIAG_UPSTREAM=12};
typedef struct {uint32_t state,map_attempts,map_bytes,map_error,map_h2_error,map_h2_last_stream,control_stage,noise_error,noise_frame_bytes;
 char transport_error[64],h2_debug[49];struct {uint32_t diagnostic_id;} config;} microlink_t;
typedef int esp_err_t;
static int diag_store=1,diag_lock=1,held;
static bool online;
static uint64_t time_ms;
static int64_t esp_timer_get_time(void) {return time_ms*1000;}
static unsigned heap_caps_get_free_size(int cap) {return 153000;}
static unsigned heap_caps_get_largest_free_block(int cap) {return 110000;}
static unsigned esp_reset_reason(void) {return 9;}
gateway_socket_stats gateway_sockets_snapshot(void) {return (gateway_socket_stats){.open=5,.peak=16,.failures=1,.last_errno=24,.last_operation=2};}
static int xSemaphoreTake(int lock,int wait) {assert(!held);held=1;return 1;}
static void xSemaphoreGive(int lock) {assert(held);held=0;}
static uint8_t persistent[4096];static size_t persistent_size;static unsigned commits;
static int nvs_get_blob(int store,const char *key,void *out,size_t *length) {
 assert(held);
 if(!strcmp(key,"events2")&&persistent_size&&*length>=persistent_size){memcpy(out,persistent,persistent_size);*length=persistent_size;return 0;}
 if(!strcmp(key,"events")){struct {uint32_t magic;uint8_t count,next;uint32_t entries[8][12];} old={.magic=0x54444731,.count=1,.next=1};old.entries[0][2]=2;old.entries[0][8]=1;old.entries[0][0]=100;
  assert(*length>=sizeof(old));memcpy(out,&old,sizeof(old));*length=sizeof(old);return 0;}
 return -1;
}
static int nvs_set_blob(int store,const char *key,const void *data,size_t length) {assert(held&&!strcmp(key,"events2")&&length<=sizeof(persistent));memcpy(persistent,data,length);persistent_size=length;return 0;}
static int nvs_commit(int store) {assert(held);commits++;return 0;}
static size_t test_strlcpy(char *out,const char *in,size_t n){size_t length=strlen(in);if(n){size_t take=length<n-1?length:n-1;memcpy(out,in,take);out[take]=0;}return length;}
typedef struct {char output[16000];size_t used;} httpd_req_t;
static bool local_request(httpd_req_t *r) {return true;}
static int httpd_resp_send_err(httpd_req_t *r,int code,const char *reason) {return -1;}
static int httpd_resp_set_type(httpd_req_t *r,const char *type) {return 0;}
static int httpd_resp_send_chunk(httpd_req_t *r,const char *data,size_t length){assert(!held&&r->used+length<sizeof(r->output));if(length){memcpy(r->output+r->used,data,length);r->used+=length;r->output[r->used]=0;}return 0;}
#define strlcpy test_strlcpy
static bool fail_journal_allocation;
static void *journal_malloc(size_t n) {return fail_journal_allocation ? NULL : malloc(n);}
#define malloc journal_malloc
#include "diagnostic_journal.inc"
#undef malloc
int main(void) {
 fail_journal_allocation=true;gateway_diag_membership(0,GATEWAY_DIAG_BOOT,9);
 assert(!held && !commits); // Recovery logging must not crash or retain the lock on OOM.
 fail_journal_allocation=false;
 gateway_diag_ring_t ring;held=1;gateway_diag_load(&ring);held=0;
 assert(ring.count==1&&ring.entries[0].h2_error==1); // v1 migrates on firmware update
 time_ms=1000;gateway_diag_membership(8,4,3); // refusal without a live client
 gateway_diag_membership(8,5,0);gateway_diag_membership(8,4,3);assert(commits==2); // coalesce across intervening events
 microlink_t m={.state=1,.map_attempts=1,.map_h2_error=1,.control_stage=4,.noise_error=5,.noise_frame_bytes=100,.config.diagnostic_id=8};
 strcpy(m.transport_error,"Map peer update section exceeds configured capacity");strcpy(m.h2_debug,"too many settings acknowledgements");gateway_diag_record(&m,1,8);
 // Simulate reboot: persistent blob survives independently of runtime client.
 time_ms=0;gateway_diag_membership(0,GATEWAY_DIAG_BOOT,9);
 httpd_req_t report={0};assert(!diagnostics(&report));cJSON *json=cJSON_Parse(report.output);assert(json);
 assert(cJSON_GetObjectItem(json,"schema")->valueint==2);cJSON *events=cJSON_GetObjectItem(json,"events");assert(cJSON_GetArraySize(events)==5);
 cJSON *blocked=cJSON_GetArrayItem(events,1);assert(cJSON_GetObjectItem(blocked,"detail")->valueint==3&&cJSON_GetObjectItem(blocked,"sockets_peak")->valueint==16&&cJSON_GetObjectItem(blocked,"socket_operation")->valueint==2);
 cJSON *failure=cJSON_GetArrayItem(events,3);assert(cJSON_GetObjectItem(failure,"noise_error")->valueint==5&&cJSON_GetObjectItem(failure,"control_stage")->valueint==4);
 assert(!strcmp(cJSON_GetObjectItem(failure,"reason")->valuestring,m.transport_error));cJSON_Delete(json);
 for(unsigned i=0;i<20;i++){time_ms+=31000;gateway_diag_membership(i,5,i);}
 held=1;gateway_diag_load(&ring);held=0;assert(ring.count==8);
 puts("Journal: legacy migration, no-client failures, rate limiting, exact protocol evidence and reboot retention passed");
}
