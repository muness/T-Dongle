#pragma once
#include "esp_lcd_panel_interface.h"
typedef enum { ESP_LCD_COLOR_SPACE_RGB = 0, ESP_LCD_COLOR_SPACE_BGR = 1 } esp_lcd_color_space_t;
typedef struct {
    int reset_gpio_num;
    esp_lcd_color_space_t color_space;   /* in IDF 5.x a union with rgb_ele_order (LCD_RGB_ELEMENT_ORDER_BGR == 1) */
    unsigned bits_per_pixel;
    struct { unsigned reset_active_high : 1; } flags;
    void *vendor_config;
} esp_lcd_panel_dev_config_t;
