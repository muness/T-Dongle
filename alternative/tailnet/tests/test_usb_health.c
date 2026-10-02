#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
static int64_t clock_us;
static bool configured,suspended;
static int64_t esp_timer_get_time(void){return clock_us;}
static bool tud_mounted(void){return configured;}
static bool tud_suspended(void){return suspended;}
static bool tud_ready(void){return configured && !suspended;}
#include "usb_health.inc"
int main(void){
    for(unsigned i=0;i<8;i++)assert(gateway_usb_health(i)==0);
    configured=true;assert(gateway_usb_health(5) && gateway_usb_health(7));
    clock_us=1234000;suspended=true;tud_suspend_cb(true);
    assert(gateway_usb_health(0)==1 && gateway_usb_health(2)==1234 && gateway_usb_health(4)==1 && gateway_usb_health(6)==1 && !gateway_usb_health(7));
    clock_us=5678000;suspended=false;tud_resume_cb();
    assert(gateway_usb_health(1)==1 && gateway_usb_health(3)==5678 && gateway_usb_health(7));
    clock_us=6000000;suspended=true;tud_suspend_cb(false);assert(gateway_usb_health(0)==2 && gateway_usb_health(4)==0);
    for(unsigned i=0;i<10000;i++){tud_resume_cb();tud_suspend_cb(false);}
    assert(gateway_usb_health(0)==10002 && gateway_usb_health(1)==10001 && sizeof(usb_health)==20);
    configured=false;assert(!gateway_usb_health(5) && !gateway_usb_health(7));assert(gateway_usb_health(100)==0);
    puts("USB suspend/resume: counters, uptime, flags and fixed20-byte storage pass");
}
