#include <assert.h>
#include <string.h>
#include "../mode_store.c"
static int read_error=ESP_ERR_NVS_NOT_FOUND,members_error=ESP_ERR_NVS_NOT_FOUND,write_error,commit_error,commits,writes;static uint8_t saved=1,pending;static char wifi[]="saved-wifi",identity[]="saved-identity";
esp_err_t nvs_get_u8(nvs_handle_t h,const char*k,uint8_t*v){assert(!strcmp(k,"mode"));if(!read_error)*v=saved;return read_error;}
esp_err_t nvs_get_str(nvs_handle_t h,const char*k,char*v,size_t*n){assert(!strcmp(k,"members") && !v);return members_error;}
esp_err_t nvs_set_u8(nvs_handle_t h,const char*k,uint8_t v){assert(!strcmp(k,"mode"));writes++;pending=v;return write_error;}
esp_err_t nvs_commit(nvs_handle_t h){commits++;if(!commit_error){saved=pending;read_error=0;}return commit_error;}
int main(void){
 tdongle_mode mode=TDONGLE_TAILNET_GATEWAY;
 /* Upgrade from the original bridge firmware or a fresh install: no mode, no memberships -> bridge. */
 assert(tdongle_mode_load(1,&mode)==0 && mode==TDONGLE_WIFI_BRIDGE);
 /* A tailnet install that predates the mode switch keeps running the gateway. */
 members_error=0;assert(tdongle_mode_load(1,&mode)==0 && mode==TDONGLE_TAILNET_GATEWAY);
 /* An unreadable member list is an error, never a guess. */
 mode=TDONGLE_WIFI_BRIDGE;members_error=-5;assert(tdongle_mode_load(1,&mode)==-5 && mode==TDONGLE_WIFI_BRIDGE);members_error=ESP_ERR_NVS_NOT_FOUND;
 read_error=-1;assert(tdongle_mode_load(1,&mode)==-1 && mode==TDONGLE_WIFI_BRIDGE);
 read_error=0;saved=2;assert(tdongle_mode_load(1,&mode)==ESP_ERR_INVALID_STATE && mode==TDONGLE_WIFI_BRIDGE);
 saved=1;mode=TDONGLE_WIFI_BRIDGE;assert(tdongle_mode_load(1,&mode)==0 && mode==TDONGLE_TAILNET_GATEWAY);
 write_error=-1;assert(tdongle_mode_save(1,TDONGLE_WIFI_BRIDGE)==-1 && saved==1 && commits==0);
 write_error=0;commit_error=-1;assert(tdongle_mode_save(1,TDONGLE_WIFI_BRIDGE)==-1 && saved==1);
 commit_error=0;assert(tdongle_mode_save(1,TDONGLE_WIFI_BRIDGE)==0 && saved==0);
 assert(tdongle_mode_load(1,&mode)==0 && mode==TDONGLE_WIFI_BRIDGE);
 assert(tdongle_mode_save(1,(tdongle_mode)7)==ESP_ERR_INVALID_ARG && writes==3);
 /* An explicit saved mode wins over the memberships heuristic. */
 members_error=0;assert(tdongle_mode_load(1,&mode)==0 && mode==TDONGLE_WIFI_BRIDGE);
 assert(!strcmp(wifi,"saved-wifi") && !strcmp(identity,"saved-identity"));return 0;}
