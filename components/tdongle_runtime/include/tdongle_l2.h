#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
esp_err_t tdongle_l2_start(const uint8_t mac[6]);
void tdongle_l2_link(bool connected);
esp_err_t tdongle_l2_host(void *buffer,uint16_t len);
void tdongle_l2_release(void *cookie);
