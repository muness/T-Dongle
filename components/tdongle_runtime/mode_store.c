#include "tdongle_mode_store.h"
/* A device that never saved a mode boots in Wi-Fi bridge mode: that is what a fresh install and every upgrade from the
 * original bridge firmware (v0.1.x, which has no tn_settings namespace at all) expect. The one exception is an install
 * that predates the mode switch and already holds tailnet memberships: it was running the gateway, so it keeps doing so
 * until a mode is chosen. Saved Wi-Fi networks are never touched here. */
esp_err_t tdongle_mode_load(nvs_handle_t store,tdongle_mode *mode){
 uint8_t value=0;esp_err_t result=nvs_get_u8(store,"mode",&value);
 if(result==ESP_ERR_NVS_NOT_FOUND){
  size_t length=0;esp_err_t members=nvs_get_str(store,"members",NULL,&length);
  if(members==ESP_OK){*mode=TDONGLE_TAILNET_GATEWAY;return ESP_OK;}
  if(members==ESP_ERR_NVS_NOT_FOUND){*mode=TDONGLE_WIFI_BRIDGE;return ESP_OK;}
  return members;
 }
 if(result!=ESP_OK)return result;
 if(value>1)return ESP_ERR_INVALID_STATE;
 *mode=(tdongle_mode)value;return ESP_OK;
}
esp_err_t tdongle_mode_save(nvs_handle_t store,tdongle_mode mode){
 if(mode!=TDONGLE_WIFI_BRIDGE && mode!=TDONGLE_TAILNET_GATEWAY)return ESP_ERR_INVALID_ARG;
 esp_err_t result=nvs_set_u8(store,"mode",mode);
 return result==ESP_OK?nvs_commit(store):result;
}
