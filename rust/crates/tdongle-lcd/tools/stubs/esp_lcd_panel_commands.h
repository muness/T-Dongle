#pragma once
/* Values of ESP-IDF v5.5 components/esp_lcd/include/esp_lcd_panel_commands.h */
#define LCD_CMD_SWRESET 0x01
#define LCD_CMD_SLPOUT 0x11
#define LCD_CMD_INVOFF 0x20
#define LCD_CMD_INVON 0x21
#define LCD_CMD_DISPOFF 0x28
#define LCD_CMD_DISPON 0x29
#define LCD_CMD_CASET 0x2A
#define LCD_CMD_RASET 0x2B
#define LCD_CMD_RAMWR 0x2C
#define LCD_CMD_MADCTL 0x36
#define LCD_CMD_COLMOD 0x3A
#define LCD_CMD_MH_BIT (1 << 2)
#define LCD_CMD_BGR_BIT (1 << 3)
#define LCD_CMD_ML_BIT (1 << 4)
#define LCD_CMD_MV_BIT (1 << 5)
#define LCD_CMD_MX_BIT (1 << 6)
#define LCD_CMD_MY_BIT (1 << 7)
