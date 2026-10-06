// SPDX-License-Identifier: MIT
// Original-board panel configuration follows main/ui.c; no LVGL or extra task.
#include "lcd.h"
#include "lcd_view.h"
#include "gateway.h"
#include "boot_health.h"
#include "board.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "ui_settings.h"
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
static bool done(esp_lcd_panel_io_handle_t io,esp_lcd_panel_io_event_data_t *event,void *context) {
    BaseType_t wake=pdFALSE;xSemaphoreGiveFromISR(transfer,&wake);return wake==pdTRUE;
}
static void apply_locked(unsigned percent,unsigned rotation);
/* Backlight: LEDC PWM on the active-low backlight pin, 1 kHz, 8 bit. It starts off (duty 255) until the first frame is on the glass. */
static unsigned applied_percent=101,applied_rotation=2;   /* impossible values: the first apply always writes */
static bool backlight_ready;
static esp_err_t backlight_init(void) {
    ledc_timer_config_t timer={.speed_mode=LEDC_LOW_SPEED_MODE,.duty_resolution=LEDC_TIMER_8_BIT,.timer_num=LEDC_TIMER_0,.freq_hz=1000,.clk_cfg=LEDC_AUTO_CLK};
    ledc_channel_config_t channel={.gpio_num=BOARD_LCD_BL,.speed_mode=LEDC_LOW_SPEED_MODE,.channel=LEDC_CHANNEL_0,.timer_sel=LEDC_TIMER_0,.duty=ui_settings_backlight_duty(0)};
    esp_err_t e=ledc_timer_config(&timer);
    if(e==ESP_OK)e=ledc_channel_config(&channel);
    backlight_ready=e==ESP_OK;
    return e;
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
esp_err_t gateway_display_start(unsigned percent,unsigned rotation) {
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
    applied_rotation=0;   /* the mirror just set is rotation 0 */
    if(rotation>UI_ROTATION_MAX)rotation=0;
    // The control task already exists. Publish availability only while holding
    // the same lock used by its refreshes, including this first DMA frame.
    xSemaphoreTake(lock,portMAX_DELAY);
    available=true;lcd_state state={.starting=true,.usb=tud_ready(),.usb_configured=tud_mounted(),.usb_suspended=tud_suspended()};lcd_view view;lcd_compose(&state,GATEWAY_VERSION,&view);draw(&view);
    if(available){
        /* Backlight on at the stored brightness, only now that there is something to see. PWM failing is not fatal: full brightness. */
        if(backlight_init()==ESP_OK)apply_locked(percent,rotation);
        else gpio_set_level(BOARD_LCD_BL,0);
    }
    xSemaphoreGive(lock);
    return available?ESP_OK:ESP_FAIL;
fail:
    if(panel){esp_lcd_panel_del(panel);panel=NULL;}
    if(io)esp_lcd_panel_io_del(io);
    spi_bus_free(SPI2_HOST);return e;
}
static void apply_locked(unsigned percent,unsigned rotation) {
    if(backlight_ready && percent!=applied_percent){
        ledc_set_duty(LEDC_LOW_SPEED_MODE,LEDC_CHANNEL_0,ui_settings_backlight_duty(percent));ledc_update_duty(LEDC_LOW_SPEED_MODE,LEDC_CHANNEL_0);
        applied_percent=percent;
    }
    if(rotation!=applied_rotation && rotation<=1){
        /* 180 degrees: both mirror flags flip. The panel window is symmetric (gap 1,26 inside 132x162), so no gap change. */
        if(esp_lcd_panel_mirror(panel,rotation!=0,rotation==0)==ESP_OK){applied_rotation=rotation;memset(&previous,0xff,sizeof(previous));}   /* repaint */
    }
}
void gateway_display_apply(unsigned percent,unsigned rotation) {
    if(!available || !lock || xSemaphoreTake(lock,pdMS_TO_TICKS(20))!=pdTRUE)return;
    apply_locked(percent,rotation);xSemaphoreGive(lock);
}
bool gateway_display_present(void) {return available;}
void gateway_display_show(const lcd_view *view) {
    if(!available || !lock || xSemaphoreTake(lock,0)!=pdTRUE)return;
    draw(view);xSemaphoreGive(lock);
}
void gateway_display_installing(void) {
    if(!available || xSemaphoreTake(lock,pdMS_TO_TICKS(100))!=pdTRUE)return;
    installing=true;lcd_state state={.installing=true,.usb=tud_ready(),.usb_configured=tud_mounted(),.usb_suspended=tud_suspended()};lcd_view view;
    lcd_compose(&state,GATEWAY_VERSION,&view);draw(&view);xSemaphoreGive(lock);
}
bool gateway_display_is_installing(void) {return installing;}
