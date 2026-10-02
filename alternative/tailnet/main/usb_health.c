#include "tusb.h"
#include "esp_timer.h"
#include <stdint.h>
/* TinyUSB task callbacks: fixed counters only, no I/O, allocation or USB reset. */
static uint32_t usb_health[5];
void tud_suspend_cb(bool remote_wakeup_en) {
    __atomic_fetch_add(&usb_health[0],1,__ATOMIC_RELAXED);
    __atomic_store_n(&usb_health[2],(uint32_t)(esp_timer_get_time()/1000),__ATOMIC_RELAXED);
    __atomic_store_n(&usb_health[4],remote_wakeup_en?1:0,__ATOMIC_RELAXED);
}
void tud_resume_cb(void) {
    __atomic_fetch_add(&usb_health[1],1,__ATOMIC_RELAXED);
    __atomic_store_n(&usb_health[3],(uint32_t)(esp_timer_get_time()/1000),__ATOMIC_RELAXED);
}
unsigned gateway_usb_health(unsigned index) {
    if(index<5)return __atomic_load_n(&usb_health[index],__ATOMIC_RELAXED);
    if(index==5)return tud_mounted();
    if(index==6)return tud_suspended();
    if(index==7)return tud_ready();
    return 0;
}
