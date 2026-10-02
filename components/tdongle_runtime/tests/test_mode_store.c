#include <assert.h>
#include <string.h>
#include "../mode_store.c"
static int read_error=ESP_ERR_NVS_NOT_FOUND,write_error,commit_error,commits,writes;static uint8_t saved=1,pending;static char wifi[]="saved-wifi",identity[]="saved-identity";
esp_err_t nvs_get_u8(nvs_handle_t h,const char*k,uint8_t*v){assert(!strcmp(k,"mode"));if(!read_error)*v=saved;return read_error;}
esp_err_t nvs_set_u8(nvs_handle_t h,const char*k,uint8_t v){assert(!strcmp(k,"mode"));writes++;pending=v;return write_error;}
esp_err_t nvs_commit(nvs_handle_t h){commits++;if(!commit_error){saved=pending;read_error=0;}return commit_error;}
int main(void){tdongle_mode mode=TDONGLE_WIFI_BRIDGE;assert(tdongle_mode_load(1,&mode)==0 && mode==TDONGLE_TAILNET_GATEWAY);read_error=-1;assert(tdongle_mode_load(1,&mode)==-1 && mode==TDONGLE_TAILNET_GATEWAY);read_error=0;saved=2;assert(tdongle_mode_load(1,&mode)==ESP_ERR_INVALID_STATE && mode==TDONGLE_TAILNET_GATEWAY);saved=1;write_error=-1;assert(tdongle_mode_save(1,TDONGLE_WIFI_BRIDGE)==-1 && saved==1 && commits==0);write_error=0;commit_error=-1;assert(tdongle_mode_save(1,TDONGLE_WIFI_BRIDGE)==-1 && saved==1);commit_error=0;assert(tdongle_mode_save(1,TDONGLE_WIFI_BRIDGE)==0 && saved==0);assert(tdongle_mode_load(1,&mode)==0 && mode==TDONGLE_WIFI_BRIDGE);assert(tdongle_mode_save(1,(tdongle_mode)7)==ESP_ERR_INVALID_ARG && writes==3);assert(!strcmp(wifi,"saved-wifi") && !strcmp(identity,"saved-identity"));return 0;}
