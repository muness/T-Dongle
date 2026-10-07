#pragma once
#include <stdint.h>
#include "esp_lcd_panel_interface.h"
typedef enum { GPIO_MODE_OUTPUT = 1 } gpio_mode_t;
typedef struct { uint64_t pin_bit_mask; gpio_mode_t mode; } gpio_config_t;
esp_err_t gpio_config(const gpio_config_t *c);
esp_err_t gpio_set_level(int gpio, uint32_t level);
esp_err_t gpio_reset_pin(int gpio);
