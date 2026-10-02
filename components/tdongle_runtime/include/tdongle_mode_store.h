#pragma once
#include "tdongle_mode.h"
#include "nvs.h"
esp_err_t tdongle_mode_load(nvs_handle_t store,tdongle_mode *mode);
esp_err_t tdongle_mode_save(nvs_handle_t store,tdongle_mode mode);
