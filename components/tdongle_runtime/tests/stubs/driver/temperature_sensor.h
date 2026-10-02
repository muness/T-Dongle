#pragma once
#include "esp_err.h"
typedef void *temperature_sensor_handle_t;
typedef struct {int min,max;} temperature_sensor_config_t;
#define TEMPERATURE_SENSOR_CONFIG_DEFAULT(a,b) ((temperature_sensor_config_t){a,b})
esp_err_t temperature_sensor_install(const temperature_sensor_config_t*,temperature_sensor_handle_t*);
esp_err_t temperature_sensor_enable(temperature_sensor_handle_t);
esp_err_t temperature_sensor_disable(temperature_sensor_handle_t);
esp_err_t temperature_sensor_get_celsius(temperature_sensor_handle_t,float*);
