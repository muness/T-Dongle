unsigned gateway_usb_health(unsigned i){return 0;}
unsigned gateway_dns_count(unsigned i){return 0;}
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../main/boot_health.h"
#include "../main/boot_policy.h"
#define RTC_NOINIT_ATTR
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 1
#define ESP_RST_POWERON 1
#define ESP_RST_BROWNOUT 9
#define ESP_RST_PANIC 4
#define ESP_RST_TASK_WDT 6
#define ESP_RST_INT_WDT 5
#define NVS_READWRITE 1
#define MALLOC_CAP_INTERNAL 1
typedef int esp_err_t;
typedef int esp_reset_reason_t;
typedef int nvs_handle_t;
typedef struct {uint32_t exc_pc;char exc_task[16];uint8_t app_elf_sha256[65];struct {uint32_t depth,bt[16];bool corrupted;} exc_bt_info;struct {uint32_t exc_cause;} ex_info;} esp_core_dump_summary_t;
static esp_core_dump_summary_t raw;
static bool raw_present, storage_fail, allocation_fail;
static int reason=1;
static char build_sha[65];
static uint8_t guard_disk[512],crash_disk[512];static size_t guard_len,crash_len;
static unsigned erases;
unsigned gateway_dns_stack_free(void){return 3000;}
static void esp_app_get_elf_sha256(char *out,size_t n){strlcpy(out,build_sha,n);}
static int esp_reset_reason(void){return reason;}
static int esp_core_dump_image_check(void){return raw_present?0:-1;}
static int esp_core_dump_get_summary(esp_core_dump_summary_t *out){*out=raw;return 0;}
static int esp_core_dump_image_erase(void){raw_present=false;erases++;return 0;}
static unsigned esp_get_free_heap_size(void){return 20000;}
static unsigned heap_caps_get_minimum_free_size(int flags){return 12000;}
static int nvs_open(const char *ns,int access,int *out){if(storage_fail)return -1;*out=1;return 0;}
static int nvs_set_blob(int h,const char *key,const void *data,size_t n){if(storage_fail)return -1;assert(n<=512);if(!strcmp(key,"guard")){memcpy(guard_disk,data,n);guard_len=n;}else{assert(!strcmp(key,"crash"));memcpy(crash_disk,data,n);crash_len=n;}return 0;}
static int nvs_get_blob(int h,const char *key,void *out,size_t *n){const void *data;size_t len;if(!strcmp(key,"guard")){data=guard_disk;len=guard_len;}else{data=crash_disk;len=crash_len;}if(storage_fail||!len||len>*n)return -1;memcpy(out,data,len);*n=len;return 0;}
static int nvs_commit(int h){return storage_fail?-1:0;}
static void *boot_calloc(size_t n,size_t size){return allocation_fail?NULL:calloc(n,size);}
#define calloc boot_calloc
#include "boot_health.inc"
#undef calloc
static void new_boot(int reset){reason=reset;memset(&previous,0,sizeof(previous));memset(&crash,0,sizeof(crash));memset(errors,0,sizeof(errors));recovery=core_present=saved_crash=false;boot_store=0;current_stage=0;gateway_boot_begin();gateway_boot_stage(BOOT_SETTINGS);gateway_boot_storage();}
static char report[4096];static size_t report_used;
static int sink(void *ctx,const char *bytes,size_t n){assert(report_used+n<sizeof(report));memcpy(report+report_used,bytes,n);report_used+=n;report[report_used]=0;return 0;}
int main(void) {
    memset(build_sha,'a',64);build_sha[64]=0;
    new_boot(ESP_RST_POWERON);assert(!recovery);gateway_boot_complete();
    gateway_boot_result(BOOT_DISPLAY,1);assert(!gateway_boot_needs_attention());
    gateway_boot_result(BOOT_DNS,1);assert(gateway_boot_needs_attention());
    gateway_boot_result(BOOT_DNS,0);
    new_boot(ESP_RST_POWERON);assert(!recovery); // normal unplug is not a failed startup
    gateway_boot_stage(BOOT_ROUTES);gateway_route_mark(4,7);
    raw=(esp_core_dump_summary_t){.exc_pc=0x40370000,.exc_task="ml_wg_mgr",.exc_bt_info={.depth=2,.bt={0x40370000,0x40371111}}};strcpy((char*)raw.app_elf_sha256,build_sha);raw_present=true;
    new_boot(ESP_RST_PANIC);assert(recovery && previous.stage==BOOT_ROUTES && previous.route_stage==4 && previous.route_member==7);
    gateway_boot_complete();report_used=0;assert(!gateway_boot_report(NULL,sink));assert(strstr(report,"ml_wg_mgr") && strstr(report,"107734"));
    new_boot(ESP_RST_POWERON);assert(recovery && saved_crash); // survives full power loss
    assert(!gateway_boot_retry() && !raw_present && erases==1);
    new_boot(ESP_RST_POWERON);assert(!recovery && crash.magic==BOOT_MAGIC);gateway_boot_complete(); // retained after retry
    // Same-build crash with failed NVS cannot erase the sole surviving evidence.
    raw_present=true;storage_fail=true;new_boot(ESP_RST_PANIC);assert(recovery);
    assert(gateway_boot_retry()!=0 && raw_present && erases==1);
    storage_fail=false;
    // New image gets a clean attempt; old crash remains available for analysis.
    memset(build_sha,'b',64);new_boot(ESP_RST_POWERON);assert(!recovery && crash.magic==BOOT_MAGIC);gateway_boot_complete();
    // An interrupted startup latches recovery even when no core dump was written.
    raw_present=false;new_boot(ESP_RST_POWERON);gateway_boot_stage(BOOT_WIFI);
    allocation_fail=true;new_boot(ESP_RST_PANIC);assert(recovery && previous.stage==BOOT_WIFI);allocation_fail=false;
    puts("Boot recovery: panic/unfinished-start quarantine, power-loss retention, one explicit retry, new-binary retry, allocation/NVS failure, and crash summary preservation");
}
