#include "tdongle_temperature.h"
#include "driver/temperature_sensor.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include <math.h>
static temperature_sensor_handle_t sensor;
static tdongle_temperature state;
static portMUX_TYPE lock=portMUX_INITIALIZER_UNLOCKED;
void tdongle_temperature_sample(void){
    esp_err_t e=ESP_OK;float c=0;
    if(!sensor){temperature_sensor_config_t config=TEMPERATURE_SENSOR_CONFIG_DEFAULT(20,100);e=temperature_sensor_install(&config,&sensor);}
    if(e==ESP_OK)e=temperature_sensor_enable(sensor);
    if(e==ESP_OK){e=temperature_sensor_get_celsius(sensor,&c);temperature_sensor_disable(sensor);}
    portENTER_CRITICAL(&lock);
    if(e==ESP_OK && isfinite(c)){
        int32_t value=(int32_t)lroundf(c*10);uint32_t now=(uint32_t)(esp_timer_get_time()/1000);
        if(!state.samples || value>state.peak_tenths)state.peak_tenths=value;
        if(!state.samples || value!=state.current_tenths)state.changed_at_ms=now;
        state.valid=true;state.current_tenths=value;state.sampled_at_ms=now;state.samples++;
    }else {state.valid=false;state.errors++;}
    portEXIT_CRITICAL(&lock);
}
tdongle_temperature tdongle_temperature_snapshot(void){
    portENTER_CRITICAL(&lock);tdongle_temperature copy=state;uint32_t now=(uint32_t)(esp_timer_get_time()/1000);portEXIT_CRITICAL(&lock);
    /* `now` is read inside the section: a sample taken between a clock read and the copy would otherwise be newer than
     * `now` and its age would wrap to about 49 days. */
    copy.age_ms=copy.samples?now-copy.sampled_at_ms:UINT32_MAX;
    return copy;
}
