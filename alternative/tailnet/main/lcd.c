// SPDX-License-Identifier: MIT
// Original-board panel configuration follows main/ui.c; no LVGL or extra task.
#include "lcd.h"
#include "lcd_view.h"
#include "gateway.h"
#include "boot_health.h"
#include "board.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_attr.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_st7735.h"
#include "tusb.h"
#include <string.h>
static esp_lcd_panel_handle_t panel;
static SemaphoreHandle_t transfer,lock;
static StaticSemaphore_t transfer_storage,lock_storage;
static DMA_ATTR uint16_t pixels[160];
static lcd_view previous;
static bool available,installing;
extern bool gateway_display_state(lcd_state *state);
static bool done(esp_lcd_panel_io_handle_t io,esp_lcd_panel_io_event_data_t *event,void *context) {
    BaseType_t wake=pdFALSE;xSemaphoreGiveFromISR(transfer,&wake);return wake==pdTRUE;
}
static void draw(const lcd_view *v) {
    if(!available || !memcmp(&previous,v,sizeof(*v)))return;
    for(unsigned y=0;y<80;y++) {
        lcd_render_row(v,y,pixels);
        for(unsigned x=0;x<160;x++)pixels[x]=(pixels[x]<<8)|(pixels[x]>>8);
        if(esp_lcd_panel_draw_bitmap(panel,0,y,160,y+1,pixels)!=ESP_OK ||
           xSemaphoreTake(transfer,pdMS_TO_TICKS(250))!=pdTRUE) {
            available=false;gateway_boot_result(BOOT_DISPLAY,ESP_FAIL);
            return; // Retain the DMA buffer; never reuse it after a timed-out transfer.
        }
    }
    previous=*v;
}
esp_err_t gateway_display_start(void) {
    lock=xSemaphoreCreateMutexStatic(&lock_storage);transfer=xSemaphoreCreateBinaryStatic(&transfer_storage);
    gpio_config_t backlight={.pin_bit_mask=1ULL<<BOARD_LCD_BL,.mode=GPIO_MODE_OUTPUT};
    if(gpio_config(&backlight)!=ESP_OK)return ESP_FAIL;
    gpio_set_level(BOARD_LCD_BL,1);
    spi_bus_config_t bus=ST7735_PANEL_BUS_SPI_CONFIG(BOARD_LCD_CLK,BOARD_LCD_MOSI,sizeof(pixels));
    esp_err_t e=spi_bus_initialize(SPI2_HOST,&bus,SPI_DMA_CH_AUTO);if(e!=ESP_OK)return e;
    esp_lcd_panel_io_handle_t io=NULL;
    esp_lcd_panel_io_spi_config_t cfg=ST7735_PANEL_IO_SPI_CONFIG(BOARD_LCD_CS,BOARD_LCD_DC,done,NULL);
    cfg.pclk_hz=20000000;cfg.trans_queue_depth=1;
    e=esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST,&cfg,&io);if(e!=ESP_OK)goto fail;
    esp_lcd_panel_dev_config_t pc={.reset_gpio_num=BOARD_LCD_RST,.rgb_ele_order=LCD_RGB_ELEMENT_ORDER_BGR,.bits_per_pixel=16};
    if((e=esp_lcd_new_panel_st7735(io,&pc,&panel))!=ESP_OK || (e=esp_lcd_panel_reset(panel))!=ESP_OK ||
       (e=esp_lcd_panel_init(panel))!=ESP_OK || (e=esp_lcd_panel_invert_color(panel,true))!=ESP_OK ||
       (e=esp_lcd_panel_set_gap(panel,1,26))!=ESP_OK || (e=esp_lcd_panel_swap_xy(panel,true))!=ESP_OK ||
       (e=esp_lcd_panel_mirror(panel,false,true))!=ESP_OK || (e=esp_lcd_panel_disp_on_off(panel,true))!=ESP_OK)goto fail;
    available=true;lcd_state state={.starting=true,.usb=tud_ready()};lcd_view view;lcd_compose(&state,GATEWAY_VERSION,&view);draw(&view);
    if(available)gpio_set_level(BOARD_LCD_BL,0);
    return available?ESP_OK:ESP_FAIL;
fail:
    if(panel){esp_lcd_panel_del(panel);panel=NULL;}
    if(io)esp_lcd_panel_io_del(io);
    spi_bus_free(SPI2_HOST);return e;
}
void gateway_display_tick(void) {
    if(!available || !lock || xSemaphoreTake(lock,0)!=pdTRUE)return;
    lcd_state state={0};if(!gateway_display_state(&state)){xSemaphoreGive(lock);return;}state.installing=installing;state.usb=tud_ready();
    lcd_view view;lcd_compose(&state,GATEWAY_VERSION,&view);draw(&view);xSemaphoreGive(lock);
}
void gateway_display_installing(void) {
    if(!available || xSemaphoreTake(lock,pdMS_TO_TICKS(100))!=pdTRUE)return;
    installing=true;lcd_state state={.installing=true,.usb=tud_ready()};lcd_view view;
    lcd_compose(&state,GATEWAY_VERSION,&view);draw(&view);xSemaphoreGive(lock);
}
