#pragma once
#include <stdbool.h>
#include <stdint.h>
typedef struct {bool wifi, saved_wifi, recovery, starting, installing, usb;unsigned saved, enabled, ready, login, failed;} lcd_state;
typedef struct {char title[14], detail[27], hint[27], footer[27];bool attention;} lcd_view;
void lcd_compose(const lcd_state *state,const char *version,lcd_view *view);
/* One scanline, RGB565 in host byte order. No allocation or framebuffer. */
void lcd_render_row(const lcd_view *view,unsigned y,uint16_t pixels[160]);
