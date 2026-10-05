#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "../main/wifi_policy.h"
#include "../../../main/core.h"
typedef int nvs_handle_t;
#define NVS_READONLY 0
static settings_t old_settings;static bool have_old;
static int nvs_open(const char*n,int m,int*h){*h=2;return have_old?0:1;}
static void nvs_close(int h){}
typedef int TaskHandle_t;
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 1
static int store;static bool fail_write;
typedef struct {struct {uint8_t ssid[32],password[64];int scan_method,sort_method;} sta;} wifi_config_t;
static wifi_config_t wifi_config;
static unsigned char disk[2048];static size_t disk_size;

static int nvs_get_blob(int h,const char*k,void*d,size_t*n){if(h==2){assert(*n>=sizeof(old_settings));memcpy(d,&old_settings,sizeof(old_settings));*n=sizeof(old_settings);return 0;}if(!disk_size)return 1;if(*n<disk_size)return 2;memcpy(d,disk,disk_size);*n=disk_size;return 0;}
static int nvs_set_blob(int h,const char*k,const void*d,size_t n){if(fail_write)return 2;memcpy(disk,d,n);disk_size=n;return 0;}
static int nvs_commit(int h){return 0;}
#include "wifi_store.inc"
static bool online,wifi_ready=true,wifi_scan_pauses_reconnect,connected;
static int wifi_scan_lock,members_lock,held,joins;
static int64_t test_time=1000000;
static int64_t esp_timer_get_time(void){return test_time;}
#define pdTRUE 1
#define portMAX_DELAY 0
#define WIFI_IF_STA 0
#define WIFI_ALL_CHANNEL_SCAN 0
#define WIFI_CONNECT_AP_BY_SIGNAL 0
#define WIFI_SCAN_TYPE_ACTIVE 0
static int xSemaphoreTake(int s,int t){return 1;}
static void xSemaphoreGive(int s){}
typedef struct {uint8_t ssid[33];int rssi;} wifi_ap_record_t;
typedef struct {bool show_hidden;int scan_type;struct {struct {int min,max;}active;}scan_time;} wifi_scan_config_t;
static wifi_ap_record_t found[8];static unsigned scan_cursor,scans;static int current_rssi=-80;
static int esp_wifi_sta_get_ap_info(wifi_ap_record_t*a){if(!connected)return 1;memcpy(a->ssid,wifi_config.sta.ssid,32);a->ssid[32]=0;a->rssi=current_rssi;return 0;}
static int esp_wifi_disconnect(void){connected=false;online=false;return 0;}
static int esp_wifi_scan_start(wifi_scan_config_t*c,bool blocking){scan_cursor=0;scans++;return 0;}
static int esp_wifi_scan_get_ap_record(wifi_ap_record_t*a){if(scan_cursor==8)return 1;*a=found[scan_cursor++];return 0;}
static int esp_wifi_clear_ap_list(void){return 0;}
static bool reject_config;
static int esp_wifi_set_config(int i,wifi_config_t*c){if(reject_config)return 1;wifi_config=*c;return 0;}
static int esp_wifi_connect(void){joins++;connected=true;online=true;return 0;}
#include "tdongle_memory.h"
void tdongle_memory_note(unsigned o,size_t n,int f){}
#include "wifi_worker.inc"
int main(void){
 have_old=true;old_settings.version=CFG_VERSION;strcpy(old_settings.p[0].ssid,"bridge");strcpy(old_settings.p[0].pass,"secret");assert(wifi_load_profiles() && wifi_saved.count==1 && !strcmp(wifi_saved.profiles[0].ssid,"bridge"));have_old=false;
 memcpy(wifi_config.sta.ssid,"legacy",6);memcpy(wifi_config.sta.password,"secret",6);assert(wifi_load_profiles());assert(wifi_saved.count==1 && !strcmp(wifi_saved.profiles[0].ssid,"legacy"));
 for(unsigned i=1;i<8;i++){char name[16];snprintf(name,sizeof(name),"network%u",i);assert(wifi_save_profile(name,"key",false));}
 assert(wifi_saved.count==8);assert(!wifi_save_profile("ninth","key",false));assert(wifi_save_profile("legacy","updated",false));
 memset(&wifi_saved,0,sizeof(wifi_saved));assert(wifi_load_profiles() && wifi_saved.count==8 && !strcmp(wifi_saved.profiles[0].password,"updated"));
 fail_write=true;assert(!wifi_save_profile("legacy","lost",false));assert(!strcmp(wifi_saved.profiles[0].password,"updated"));fail_write=false;
 assert(wifi_save_profile("legacy","",true));assert(wifi_saved.count==7 && !strcmp(wifi_saved.profiles[0].ssid,"network1"));assert(wifi_save_profile("ninth","key",false));assert(wifi_saved.count==8);
 for(unsigned i=0;i<8;i++){strlcpy((char*)found[i].ssid,wifi_saved.profiles[i].ssid,33);found[i].rssi=-90+i*5;}
 wifi_rescan=true;wifi_maintain();assert(joins==1 && wifi_current==7); // strongest of all eight, not first saved
 wifi_retry_after[7]=(uint32_t)(test_time/1000)+60000;connected=online=false;wifi_rescan=true;wifi_maintain();assert(joins==2 && wifi_current==6); // failed strongest cannot trap retries
 wifi_rescan=true;wifi_maintain();assert(joins==2); // no oscillation while current scan signal is healthy
 unsigned previous=scans;current_rssi=-55;wifi_rescan=false;test_time+=61000000;wifi_maintain();assert(scans==previous);current_rssi=-85;test_time+=61000000;wifi_maintain();assert(scans==previous+1);
 /* `use N`: deterministic, and the choice sticks against roaming until the user changes it or the join fails. */
 {unsigned count=wifi_saved.count;assert(count==8);
  assert(wifi_use_profile(0)==-1 && wifi_use_profile(9)==-1 && wifi_use_profile(-3)==-1 && wifi_pinned.slot==-1);
  wifi_ready=false;assert(wifi_use_profile(1)==-1);wifi_ready=true;
  unsigned revision_before=wifi_revision,joins_before=joins;
  wifi_retry_after[0]=(uint32_t)(test_time/1000)+60000;
  assert(wifi_use_profile(1)==0 && wifi_current==0 && wifi_pinned.slot==0 && joins==joins_before+1 && wifi_revision==revision_before+1 && wifi_retry_after[0]==0);
  assert(!strcmp((char*)wifi_config.sta.ssid,wifi_saved.profiles[0].ssid) && !strcmp((char*)wifi_config.sta.password,wifi_saved.profiles[0].password));
  assert(!wifi_scan_pauses_reconnect);
  for(unsigned i=0;i<8;i++){strlcpy((char*)found[i].ssid,wifi_saved.profiles[i].ssid,33);found[i].rssi=i==7?-40:-85;}
  /* Weak current network and a far stronger saved one: unpinned selection would roam; the pin must not. */
  current_rssi=-88;connected=online=true;joins_before=joins;
  for(int pass=0;pass<5;pass++){wifi_rescan=true;wifi_maintain();assert(joins==joins_before && wifi_current==0 && wifi_pinned.slot==0);}
  /* Lost link: the worker retries the pinned network (even unseen) a bounded number of times, never another one. */
  for(unsigned i=0;i<8;i++)found[i].ssid[0]=0;
  for(int attempt=1;attempt<=WIFI_PIN_MAX_ATTEMPTS;attempt++){connected=online=false;wifi_rescan=true;wifi_maintain();assert(wifi_current==0 && wifi_pinned.slot==0 && joins==joins_before+attempt);}
  /* Still not joined: the pin is given up, reported, and normal selection resumes. */
  for(unsigned i=0;i<8;i++){strlcpy((char*)found[i].ssid,wifi_saved.profiles[i].ssid,33);found[i].rssi=i==7?-40:-85;}
  connected=online=false;wifi_rescan=true;wifi_maintain();
  assert(wifi_pinned.slot==-1 && wifi_pinned.failed_slot==1 && wifi_current==7);
  /* A fresh `use` clears the failure; editing the saved list drops the pin. */
  assert(wifi_use_profile(3)==0 && wifi_pinned.slot==2 && wifi_pinned.failed_slot==0 && wifi_current==2);
  assert(!wifi_save_profile("another","key",false));   /* list full: refused, pin untouched */
  assert(wifi_pinned.slot==2);
  assert(wifi_save_profile(wifi_saved.profiles[7].ssid,"",true) && wifi_pinned.slot==-1 && wifi_current==-1);
  assert(wifi_use_profile(2)==0);
  /* The driver refusing the config leaves the previous pin alone and says so. */
  reject_config=true;int old_pin=wifi_pinned.slot;assert(wifi_use_profile(1)==-2 && wifi_pinned.slot==old_pin && !wifi_scan_pauses_reconnect);reject_config=false;
 }
 ((uint32_t*)disk)[0]=999;assert(!wifi_load_profiles());
}
