/* Compiles the REAL components/st7735/esp_lcd_st7735.c against stub ESP-IDF headers and prints every wire event for the call sequence of
 * alternative/tailnet/main/lcd.c (gateway_display_start / apply_locked / draw). Output: one event per line. */
#include "esp_lcd_st7735.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "driver/gpio.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static void hexline(const char *tag, int cmd, const uint8_t *p, size_t n) {
    printf("%s %02x", tag, cmd);
    for (size_t i = 0; i < n; i++) printf(" %02x", p[i]);
    printf("\n");
}
esp_err_t esp_lcd_panel_io_tx_param(esp_lcd_panel_io_handle_t io, int cmd, const void *param, size_t n) { (void)io; hexline("CMD", cmd, param, n); return ESP_OK; }
esp_err_t esp_lcd_panel_io_tx_color(esp_lcd_panel_io_handle_t io, int cmd, const void *color, size_t n) {
    (void)io; printf("COLOR %02x %zu\n", cmd, n); (void)color; return ESP_OK;
}
void vTaskDelay(unsigned ticks) { printf("DELAY %u\n", ticks); }
esp_err_t gpio_config(const gpio_config_t *c) { printf("GPIO_OUT mask=%llx\n", (unsigned long long)c->pin_bit_mask); return ESP_OK; }
esp_err_t gpio_set_level(int g, uint32_t l) { printf("GPIO %d %u\n", g, l); return ESP_OK; }
esp_err_t gpio_reset_pin(int g) { (void)g; return ESP_OK; }

/* The panel calls of lcd.c, in the order lcd.c makes them (gateway_display_start, apply_locked); gen_golden.py checks that lcd.c still
 * contains exactly these calls. */
int main(void) {
    esp_lcd_panel_io_handle_t io = (esp_lcd_panel_io_handle_t)1;
    esp_lcd_panel_handle_t panel = NULL;
    esp_lcd_panel_dev_config_t pc = {.reset_gpio_num = 1, .color_space = ESP_LCD_COLOR_SPACE_BGR, .bits_per_pixel = 16};
    esp_err_t e;
    for (int rotation = 0; rotation < 2; rotation++) {
        printf("## start rotation %d\n", rotation);
        if ((e = esp_lcd_new_panel_st7735(io, &pc, &panel)) != ESP_OK || (e = panel->reset(panel)) != ESP_OK ||
            (e = panel->init(panel)) != ESP_OK || (e = panel->invert_color(panel, true)) != ESP_OK ||
            (e = panel->set_gap(panel, 1, 26)) != ESP_OK || (e = panel->swap_xy(panel, true)) != ESP_OK ||
            (e = panel->mirror(panel, false, true)) != ESP_OK || (e = panel->disp_on_off(panel, true)) != ESP_OK) return 1;
        if (rotation == 1) { printf("## apply rotation 1\n"); assert(panel->mirror(panel, 1 != 0, 1 == 0) == ESP_OK); }
        for (int y = 0; y < 80; y += (y < 3 || y > 76) ? 1 : 37) {
            printf("## draw row %d\n", y);
            uint16_t px[160] = {0};
            assert(panel->draw_bitmap(panel, 0, y, 160, y + 1, px) == ESP_OK);
        }
        printf("## draw window 5 7 100 20\n");
        { uint16_t px[160 * 13] = {0}; assert(panel->draw_bitmap(panel, 5, 7, 100, 20, px) == ESP_OK); }
        printf("## draw window 0 0 300 280\n");   /* high address bytes */
        { static uint16_t px[1]; assert(panel->draw_bitmap(panel, 0, 0, 300, 280, px) == ESP_OK); }
        if (rotation == 1) { printf("## apply rotation 0\n"); assert(panel->mirror(panel, 0 != 0, 0 == 0) == ESP_OK); }
        panel->del(panel);
    }
    return 0;
}
