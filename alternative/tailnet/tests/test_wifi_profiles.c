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
static int esp_wifi_set_config(int i,wifi_config_t*c){wifi_config=*c;return 0;}
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
 ((uint32_t*)disk)[0]=999;assert(!wifi_load_profiles());
}
