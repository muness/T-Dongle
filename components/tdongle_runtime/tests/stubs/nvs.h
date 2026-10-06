#pragma once
#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>
typedef int nvs_handle_t;
#define ESP_ERR_NVS_NOT_FOUND 3
#define ESP_ERR_INVALID_STATE 4
#define ESP_ERR_INVALID_ARG 5
esp_err_t nvs_get_u8(nvs_handle_t,const char*,uint8_t*);
esp_err_t nvs_set_u8(nvs_handle_t,const char*,uint8_t);
esp_err_t nvs_commit(nvs_handle_t);
esp_err_t nvs_get_str(nvs_handle_t,const char*,char*,size_t*);
