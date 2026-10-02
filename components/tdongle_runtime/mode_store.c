#include "tdongle_mode_store.h"
esp_err_t tdongle_mode_load(nvs_handle_t store,tdongle_mode *mode){
 uint8_t value=1;esp_err_t result=nvs_get_u8(store,"mode",&value);
 if(result==ESP_ERR_NVS_NOT_FOUND){*mode=TDONGLE_TAILNET_GATEWAY;return ESP_OK;}
 if(result!=ESP_OK)return result;
 if(value>1)return ESP_ERR_INVALID_STATE;
 *mode=(tdongle_mode)value;return ESP_OK;
}
esp_err_t tdongle_mode_save(nvs_handle_t store,tdongle_mode mode){
 if(mode!=TDONGLE_WIFI_BRIDGE && mode!=TDONGLE_TAILNET_GATEWAY)return ESP_ERR_INVALID_ARG;
 esp_err_t result=nvs_set_u8(store,"mode",mode);
 return result==ESP_OK?nvs_commit(store):result;
}
