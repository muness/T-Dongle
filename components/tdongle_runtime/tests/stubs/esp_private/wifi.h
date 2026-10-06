#pragma once
#include "esp_err.h"
#include <stdint.h>
#define ESP_IF_WIFI_STA 0
void esp_wifi_internal_free_rx_buffer(void*);
esp_err_t esp_wifi_internal_reg_rxcb(int,esp_err_t(*)(void*,uint16_t,void*));
