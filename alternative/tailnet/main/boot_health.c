#include "boot_health.h"
#include "boot_policy.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_core_dump.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json_writer.inc"
#define BOOT_MAGIC 0x54424232u
typedef struct {
    uint32_t magic, pending, recovery, stage, route_stage, route_member;
    char elf[65];
} boot_marker;
typedef struct {
    uint32_t magic, pc, cause, depth, corrupted, bt[16];
    char task[17], elf[65];
} crash_record;
static RTC_NOINIT_ATTR boot_marker rtc_boot;
static boot_marker previous;
static crash_record crash;
static nvs_handle_t boot_store;
static char elf[65];
static bool recovery, core_present, saved_crash;
static int errors[BOOT_STAGE_COUNT];
static unsigned current_stage;
static const char *stage_name(unsigned s) {
    static const char *const names[] = {"none","usb","settings","network","http",
        "directory","routes","wifi","dns","manager","running","display"};
    return s<BOOT_STAGE_COUNT ? names[s] : "unknown";
}
void gateway_boot_begin(void) {
    esp_app_get_elf_sha256(elf, sizeof(elf));
    esp_reset_reason_t reason=esp_reset_reason();
    /* RTC garbage/old power-on contents cannot create a false boot-loop latch. */
    if (reason != ESP_RST_POWERON && reason != ESP_RST_BROWNOUT &&
        rtc_boot.magic==BOOT_MAGIC) previous=rtc_boot;
    recovery=boot_should_recover(!strcmp(previous.elf,elf),previous.pending,
        reason==ESP_RST_PANIC || reason==ESP_RST_TASK_WDT || reason==ESP_RST_INT_WDT,
        previous.recovery);
    esp_core_dump_summary_t *s=calloc(1,sizeof(*s));
    if(s && esp_core_dump_image_check()==ESP_OK && esp_core_dump_get_summary(s)==ESP_OK) {
        core_present=true;
        crash.magic=BOOT_MAGIC;crash.pc=s->exc_pc;crash.cause=s->ex_info.exc_cause;
        crash.depth=s->exc_bt_info.depth>16?16:s->exc_bt_info.depth;
        crash.corrupted=s->exc_bt_info.corrupted;
        memcpy(crash.bt,s->exc_bt_info.bt,sizeof(crash.bt));
        memcpy(crash.task,s->exc_task,16);crash.task[16]=0;
        /* Only task identifiers and numeric addresses leave the device. */
        for(char *p=crash.task;*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'||*p=='-'))*p='_';
        strlcpy(crash.elf,(char *)s->app_elf_sha256,sizeof(crash.elf));
        /* IDF may store a configured SHA prefix. Require >= 16 hex chars. */
        size_t n=strlen(crash.elf);
        if(n>=16 && !strncmp(crash.elf,elf,n))recovery=true;
    }
    free(s);
    rtc_boot=(boot_marker){.magic=BOOT_MAGIC,.pending=1,.recovery=recovery};
    strlcpy(rtc_boot.elf,elf,sizeof(rtc_boot.elf));
}
void gateway_boot_storage(void) {
    if(nvs_open("tn_boot",NVS_READWRITE,&boot_store)!=ESP_OK)return;
    boot_marker stored={0};size_t n=sizeof(stored);
    if(nvs_get_blob(boot_store,"guard",&stored,&n)==ESP_OK && n==sizeof(stored) && stored.magic==BOOT_MAGIC &&
       boot_should_recover(!memcmp(stored.elf,elf,sizeof(elf)),stored.pending,false,stored.recovery)) {
        recovery=true;
        if(!previous.magic)previous=stored;
    }
    if(core_present) {
        saved_crash=nvs_set_blob(boot_store,"crash",&crash,sizeof(crash))==ESP_OK && nvs_commit(boot_store)==ESP_OK;
    } else {
        n=sizeof(crash);
        if(nvs_get_blob(boot_store,"crash",&crash,&n)!=ESP_OK || n!=sizeof(crash) || crash.magic!=BOOT_MAGIC)
            memset(&crash,0,sizeof(crash));
        else {saved_crash=true;crash.task[16]=0;crash.elf[64]=0;}
    }
    rtc_boot.recovery=recovery;
    nvs_set_blob(boot_store,"guard",&rtc_boot,sizeof(rtc_boot));nvs_commit(boot_store);
}
void gateway_boot_stage(unsigned stage) {
    current_stage=stage;rtc_boot.stage=stage;
    /* No flash writes per stage: RTC identifies the step after a panic. */
}
void gateway_boot_result(unsigned stage,int error) {
    if(stage<BOOT_STAGE_COUNT)errors[stage]=error;
}
bool gateway_boot_recovery(void) {return recovery;}
bool gateway_boot_needs_attention(void) {
    if(recovery)return true;
    for(unsigned i=1;i<BOOT_STAGE_COUNT;i++)if(i!=BOOT_DISPLAY && errors[i])return true;
    return false;
}
void gateway_boot_complete(void) {
    gateway_boot_stage(BOOT_RUNNING);rtc_boot.pending=0;
    if(boot_store){nvs_set_blob(boot_store,"guard",&rtc_boot,sizeof(rtc_boot));nvs_commit(boot_store);}
}
int gateway_boot_retry(void) {
    /* Do not discard the only surviving crash record. */
    if(core_present && !saved_crash)return ESP_ERR_INVALID_STATE;
    if(core_present) {esp_err_t e=esp_core_dump_image_erase();if(e!=ESP_OK)return e;}
    boot_marker cleared=rtc_boot;cleared.pending=0;cleared.recovery=0;
    if(boot_store) {
        esp_err_t e=nvs_set_blob(boot_store,"guard",&cleared,sizeof(cleared));
        if(e==ESP_OK)e=nvs_commit(boot_store);
        if(e!=ESP_OK)return e;
    }
    rtc_boot=cleared;
    return ESP_OK;
}
void gateway_route_mark(unsigned stage,uint32_t member) {
    __atomic_store_n(&rtc_boot.route_member,member,__ATOMIC_RELAXED);
    __atomic_store_n(&rtc_boot.route_stage,stage,__ATOMIC_RELEASE);
}
int gateway_boot_report(void *context,int (*sink)(void *,const char *,size_t)) {
    jw_writer writer={.context=context,.sink=sink};jw_writer *w=&writer;
    jw_raw(w,"{\"schema\":1,\"firmware\":");jw_string(w,GATEWAY_VERSION);
    jw_raw(w,",\"elf\":");jw_string(w,elf);
    jw_raw(w,",\"recovery\":");jw_bool(w,recovery);
    jw_raw(w,",\"stage\":");jw_string(w,stage_name(current_stage));
    jw_raw(w,",\"previous_stage\":");jw_string(w,stage_name(previous.stage));
    jw_raw(w,",\"previous_route_stage\":");jw_number(w,previous.route_stage);
    jw_raw(w,",\"previous_route_member\":");jw_number(w,previous.route_member);
    jw_raw(w,",\"reset_reason\":");jw_number(w,esp_reset_reason());
    jw_raw(w,",\"free_memory\":");jw_number(w,esp_get_free_heap_size());
    jw_raw(w,",\"minimum_free_memory\":");jw_number(w,heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    extern unsigned gateway_dns_stack_free(void);
    jw_raw(w,",\"dns_stack_free_bytes\":");jw_number(w,gateway_dns_stack_free());
    extern unsigned gateway_dns_count(unsigned);
    jw_raw(w,",\"dns\":{");
    const char *dns_keys[]={"queries","cache_hits","lock_failures","temporary_failures","absent_names","upstream_busy_drops","max_lookup_ticks","upstream_forwarded","upstream_replies","upstream_timeouts","upstream_pending_peak"};
    for(unsigned i=0;i<11;i++){if(i)jw_raw(w,",");jw_string(w,dns_keys[i]);jw_raw(w,":");jw_number(w,gateway_dns_count(i));}
    jw_raw(w,"}");
    extern unsigned gateway_usb_health(unsigned);
    jw_raw(w,",\"usb\":{");
    const char *usb_keys[]={"suspend_count","resume_count","last_suspend_uptime_ms","last_resume_uptime_ms","remote_wakeup_enabled","configured","suspended","ready"};
    for(unsigned i=0;i<8;i++){if(i)jw_raw(w,",");jw_string(w,usb_keys[i]);jw_raw(w,":");if(i<4)jw_number(w,gateway_usb_health(i));else jw_bool(w,gateway_usb_health(i)!=0);}
    jw_raw(w,"}");
    jw_raw(w,",\"errors\":[");bool comma=false;
    for(unsigned i=1;i<BOOT_STAGE_COUNT;i++)if(errors[i]) {
        if(comma)jw_char(w,',');
        comma=true;jw_raw(w,"{\"stage\":");jw_string(w,stage_name(i));
        jw_raw(w,",\"code\":");jw_number(w,(uint32_t)errors[i]);jw_char(w,'}');
    }
    jw_raw(w,"],\"crash\":");
    if(crash.magic==BOOT_MAGIC) {
        jw_raw(w,"{\"task\":");jw_string(w,crash.task);jw_raw(w,",\"elf\":");jw_string(w,crash.elf);
        jw_raw(w,",\"pc\":");jw_number(w,crash.pc);jw_raw(w,",\"cause\":");jw_number(w,crash.cause);
        jw_raw(w,",\"corrupted\":");jw_bool(w,crash.corrupted);jw_raw(w,",\"backtrace\":[");
        for(unsigned i=0;i<crash.depth && i<16;i++){if(i)jw_char(w,',');jw_number(w,crash.bt[i]);}
        jw_raw(w,"]}");
    } else jw_raw(w,"null");
    jw_char(w,'}');return jw_flush(w)?0:-1;
}
