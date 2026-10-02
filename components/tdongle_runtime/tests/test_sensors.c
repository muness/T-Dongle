#include <assert.h>
#include <math.h>
#include "../temperature.c"
#define lock memory_lock
#include "../memory.c"
#undef lock
#include "tdongle_mode.h"
static int error,installed,enables,disables;static float reading;static uint32_t tick=100,free_heap=40000,min_heap=40000,largest=30000;
int64_t esp_timer_get_time(void){return (int64_t)tick*1000;}
esp_err_t temperature_sensor_install(const temperature_sensor_config_t*c,temperature_sensor_handle_t*h){installed++;assert(c->min==20 && c->max==100);if(error)return -1;*h=(void*)1;return 0;}
esp_err_t temperature_sensor_enable(temperature_sensor_handle_t h){enables++;return error;}
esp_err_t temperature_sensor_disable(temperature_sensor_handle_t h){disables++;return 0;}
esp_err_t temperature_sensor_get_celsius(temperature_sensor_handle_t h,float*v){*v=reading;return error;}
size_t heap_caps_get_free_size(unsigned c){return free_heap;}
size_t heap_caps_get_minimum_free_size(unsigned c){return min_heap;}
size_t heap_caps_get_largest_free_block(unsigned c){return largest;}
int main(void){
 error=-1;tdongle_temperature_sample();assert(!state.valid && state.errors==1);error=0;reading=55.25;tdongle_temperature_sample();assert(state.valid && state.current_tenths==553 && state.peak_tenths==553 && disables==1);tick=200;reading=40;tdongle_temperature_sample();assert(state.peak_tenths==553 && state.current_tenths==400 && state.sampled_at_ms==200);
 reading=NAN;tdongle_temperature_sample();assert(!state.valid && state.sampled_at_ms==200 && state.errors==2);reading=60;tdongle_temperature_sample();assert(state.valid && state.peak_tenths==600 && installed==2 && enables==4);
 tdongle_mode mode=TDONGLE_TAILNET_GATEWAY;assert(!tdongle_mode_parse(NULL,&mode) && !tdongle_mode_parse("wifi_bridge garbage",&mode));assert(tdongle_mode_parse("wifi_bridge",&mode) && mode==TDONGLE_WIFI_BRIDGE);assert(tdongle_mode_parse("tailnet_gateway",&mode) && mode==TDONGLE_TAILNET_GATEWAY);
 tdongle_memory_note(1,512,0);assert(count==1);for(unsigned i=0;i<100;i++)tdongle_memory_note(6,100,0);assert(count==1);min_heap=16000;free_heap=17000;largest=12000;tick=300;tdongle_memory_note(1,8000,0);free_heap=45000;tdongle_memory_note(0,0,0);assert(count==2 && tdongle_memory_get(1).requested==8000 && tdongle_memory_get(1).minimum_bytes==16000);tdongle_memory_note(4,32000,1);assert(count==3 && tdongle_memory_get(2).failed && tdongle_memory_get(2).largest_bytes==12000);
 for(unsigned i=0;i<30;i++)tdongle_memory_note(7,i,1);assert(count==16 && tdongle_memory_get(15).requested==29 && tdongle_memory_get(16).uptime_ms==0);return 0;
}
