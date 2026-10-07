#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_NOT_SUPPORTED 0x106
typedef struct esp_lcd_panel_t esp_lcd_panel_t;
typedef esp_lcd_panel_t *esp_lcd_panel_handle_t;
typedef struct esp_lcd_panel_io_t *esp_lcd_panel_io_handle_t;
struct esp_lcd_panel_t {
    esp_err_t (*reset)(esp_lcd_panel_t *);
    esp_err_t (*init)(esp_lcd_panel_t *);
    esp_err_t (*del)(esp_lcd_panel_t *);
    esp_err_t (*draw_bitmap)(esp_lcd_panel_t *, int, int, int, int, const void *);
    esp_err_t (*mirror)(esp_lcd_panel_t *, bool, bool);
    esp_err_t (*swap_xy)(esp_lcd_panel_t *, bool);
    esp_err_t (*set_gap)(esp_lcd_panel_t *, int, int);
    esp_err_t (*invert_color)(esp_lcd_panel_t *, bool);
    esp_err_t (*disp_on_off)(esp_lcd_panel_t *, bool);
    esp_err_t (*disp_off)(esp_lcd_panel_t *, bool);
};
