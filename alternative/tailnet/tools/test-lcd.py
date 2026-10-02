#!/usr/bin/env python3
from pathlib import Path
import subprocess
r=Path(__file__).resolve().parents[1];out=r/'build-host/lcd';out.mkdir(parents=True,exist_ok=True)
source=(r/'main/lcd.c').read_text()
assert 'xTaskCreate' not in source and 'ESP_ERROR_CHECK' not in source
assert 'pixels[160]' in source and 'malloc' not in (r/'main/lcd_view.c').read_text()
subprocess.run(['cc','-std=c11','-g','-fsanitize=address,undefined',str(r/'tests/test_lcd.c'),str(r/'main/lcd_view.c'),'-o',str(out/'test_lcd')],check=True)
subprocess.run([str(out/'test_lcd'),str(out)],check=True)
# Exercise the exact production DMA loop, including a timed-out transfer.
draw=source[source.index('static void draw('):source.index('esp_err_t gateway_display_start(')]
harness='''#include <assert.h>
#include <string.h>
#include <stdint.h>
#include "lcd_view.h"
#define ESP_OK 0
#define ESP_FAIL -1
#define BOOT_DISPLAY 11
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
static int calls,fail_at=-1,timeout,errors;static void *panel,*transfer;
static uint16_t pixels[160];static lcd_view previous;static int available=1;
static int esp_lcd_panel_draw_bitmap(void *p,int x,int y,int w,int end,void *data){calls++;assert(x==0 && w==160 && end==y+1);return calls==fail_at?-1:0;}
static int xSemaphoreTake(void *p,int ticks){assert(ticks==250);return !timeout;}
static void gateway_boot_result(int stage,int error){assert(stage==11 && error==-1);errors++;}
'''+draw+'''
int main(void){lcd_view v={.title="READY"};draw(&v);assert(calls==80);draw(&v);assert(calls==80);
strcpy(v.title,"RECOVERY");timeout=1;draw(&v);assert(calls==81 && !available && errors==1);draw(&v);assert(calls==81);
available=1;timeout=0;fail_at=82;draw(&v);assert(calls==82 && !available && errors==2);draw(&v);assert(calls==82);}
'''
(out/'test_transfer.c').write_text(harness)
subprocess.run(['cc','-std=c11','-g','-fsanitize=address,undefined','-I',str(r/'main'),str(out/'test_transfer.c'),str(r/'main/lcd_view.c'),'-o',str(out/'test_transfer')],check=True)
subprocess.run([str(out/'test_transfer')],check=True)
print('LCD transfer failures disable further DMA buffer reuse; unchanged screens do not redraw')
