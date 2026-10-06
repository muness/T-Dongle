/* Host stand-ins for the saved-network store and its worker (wifi_profiles.inc): an in-memory NVS with the v0.1.1 adapter namespace, the Wi-Fi
 * driver calls the worker makes, and the two halves of the file itself (build-host/wifi_store.inc and wifi_worker.inc, cut at the marker by
 * tools/test-gateway.sh). Shared by test_wifi_profiles.c and test_serial_commands.c. */
#pragma once
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../main/wifi_policy.h"
#include "../../../main/core.h"
#include "../../../main/wifi_meta.h"
#include "../../../main/legacy_import.h"
#include "../../../main/ui_settings.h"
typedef int nvs_handle_t;
#define NVS_READONLY 0
#define NVS_READWRITE 1
typedef int TaskHandle_t;
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 1
#define ESP_FAIL 2
/* An in-memory NVS: the unified store (handle 1) as named blobs, and the v0.1.1 adapter namespace (handle 2) with its one `config` key. */
static settings_t old_settings;static bool have_old,old_erased;
enum {KEYS=8};
static struct {char key[24];unsigned char data[2048];size_t size;bool used;} kv[KEYS];
static int store=1;static bool fail_write;static unsigned writes_before_failure=~0u,write_count;static bool fail_erase;
static int nvs_open(const char*n,int m,int*h){if(!strcmp(n,"adapter")){if(!have_old && m==NVS_READONLY)return ESP_ERR_NVS_NOT_FOUND;*h=2;return ESP_OK;}*h=1;return ESP_OK;}
static void nvs_close(int h){(void)h;}
static int find(const char*k){for(int i=0;i<KEYS;i++)if(kv[i].used && !strcmp(kv[i].key,k))return i;return -1;}
static int nvs_get_blob(int h,const char*k,void*d,size_t*n){
 if(h==2){if(!have_old || strcmp(k,"config"))return ESP_ERR_NVS_NOT_FOUND;if(*n<sizeof(old_settings))return ESP_FAIL;memcpy(d,&old_settings,sizeof(old_settings));*n=sizeof(old_settings);return ESP_OK;}
 int i=find(k);if(i<0)return ESP_ERR_NVS_NOT_FOUND;if(*n<kv[i].size)return ESP_FAIL;memcpy(d,kv[i].data,kv[i].size);*n=kv[i].size;return ESP_OK;}
static int nvs_set_blob(int h,const char*k,const void*d,size_t n){
 (void)h;if(fail_write || write_count++>=writes_before_failure)return ESP_FAIL;
 int i=find(k);if(i<0){i=0;while(i<KEYS && kv[i].used)i++;assert(i<KEYS);kv[i].used=true;strcpy(kv[i].key,k);}
 assert(n<=sizeof(kv[i].data));memcpy(kv[i].data,d,n);kv[i].size=n;return ESP_OK;}
static int nvs_erase_key(int h,const char*k){(void)h;if(fail_erase)return ESP_FAIL;int i=find(k);if(i<0)return ESP_ERR_NVS_NOT_FOUND;kv[i].used=false;return ESP_OK;}
static int nvs_erase_all(int h){if(fail_erase)return ESP_FAIL;if(h==2){have_old=false;old_erased=true;memset(&old_settings,0,sizeof(old_settings));}return ESP_OK;}
static int nvs_commit(int h){(void)h;return ESP_OK;}
enum {WIFI_AUTH_OPEN,WIFI_AUTH_WPA2_PSK=3};enum {WPA3_SAE_PWE_BOTH=3};
typedef struct {struct {uint8_t ssid[32],password[64];int scan_method,sort_method,sae_pwe_h2e;struct {bool capable;} pmf_cfg;struct {int authmode;} threshold;unsigned rm_enabled:1,btm_enabled:1;} sta;} wifi_config_t;
static wifi_config_t wifi_config;
static bool roaming=true;static bool wifi_roaming_assist(void){return roaming;}
static unsigned char *unused_disk;
#include "wifi_store.inc"
static bool online,wifi_ready=true,wifi_scan_pauses_reconnect,connected;
static int wifi_scan_lock,members_lock,held,joins;
static int64_t test_time=1000000;
static int64_t esp_timer_get_time(void){return test_time;}
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define portMAX_DELAY 0
#define WIFI_IF_STA 0
#define WIFI_ALL_CHANNEL_SCAN 0
#define WIFI_CONNECT_AP_BY_SIGNAL 0
#define WIFI_SCAN_TYPE_ACTIVE 0
static int xSemaphoreTake(int s,int t){return 1;}
static void xSemaphoreGive(int s){}
typedef struct {uint8_t ssid[33];int rssi;int authmode;} wifi_ap_record_t;
typedef struct {bool show_hidden;int scan_type;struct {struct {int min,max;}active;}scan_time;} wifi_scan_config_t;
static wifi_ap_record_t found[8];static unsigned scan_cursor,scans;static int current_rssi=-80;
static int esp_wifi_sta_get_ap_info(wifi_ap_record_t*a){if(!connected)return 1;memcpy(a->ssid,wifi_config.sta.ssid,32);a->ssid[32]=0;a->rssi=current_rssi;return 0;}
static int esp_wifi_disconnect(void){connected=false;online=false;return 0;}
static void (*during_scan)(void);
static int esp_wifi_scan_start(wifi_scan_config_t*c,bool blocking){scan_cursor=0;scans++;if(during_scan){void (*hook)(void)=during_scan;during_scan=0;hook();}return 0;}
static int esp_wifi_scan_get_ap_record(wifi_ap_record_t*a){if(scan_cursor==8)return 1;*a=found[scan_cursor++];return 0;}
static int esp_wifi_clear_ap_list(void){return 0;}
static bool reject_config;
static int esp_wifi_set_config(int i,wifi_config_t*c){if(reject_config)return 1;wifi_config=*c;return 0;}
static int esp_wifi_connect(void){joins++;connected=true;online=true;return 0;}
#include "tdongle_memory.h"
void tdongle_memory_note(unsigned o,size_t n,int f){}
#include "wifi_worker.inc"

/* Everything back to a fresh dongle: empty store, no v0.1.1 data, nothing joined, driver calls succeed. */
static void reset_world(void){
 memset(kv,0,sizeof(kv));memset(&wifi_saved,0,sizeof(wifi_saved));wifi_saved.schema=1;memset(&wifi_config,0,sizeof(wifi_config));
 const char *none[8]={""};wifi_meta_defaults(&wifi_meta,none,0);ui_settings_defaults(&display_settings);
 have_old=old_erased=false;memset(&old_settings,0,sizeof(old_settings));fail_write=fail_erase=false;writes_before_failure=~0u;write_count=0;
 wifi_pin_clear(&wifi_pinned);wifi_revision=0;wifi_current=-1;memset(wifi_retry_after,0,sizeof(wifi_retry_after));roaming=true;
 connected=online=false;joins=0;scans=0;wifi_ready=true;wifi_rescan=true;reject_config=false;during_scan=0;current_rssi=-80;memset(found,0,sizeof(found));test_time=1000000;
}
/* A restart: the RAM copies are gone, the flash (kv) stays. */
static void forget_ram(void){memset(&wifi_saved,0,sizeof(wifi_saved));const char *none[8]={""};wifi_meta_defaults(&wifi_meta,none,0);ui_settings_defaults(&display_settings);}
