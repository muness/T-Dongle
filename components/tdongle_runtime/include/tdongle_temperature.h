#pragma once
#include <stdbool.h>
#include <stdint.h>
/* The chip temperature sensor.
 *
 * `current_tenths` is re-read by every tdongle_temperature_sample() (the gateway manager calls it every ten
 * seconds); it is never cached or a peak. `peak_tenths` is the highest reading since boot and is a separate field.
 *
 * Resolution: on the ESP32-S3 the driver reports whole degrees minus an eFuse calibration offset
 * (esp_driver_tsens: tsens_raw - deltaT/10), so readings move in steps of 1 degree C and one value (for example
 * 61.9) repeats for as long as the die stays inside the same degree. A repeated value is therefore not evidence of a
 * stale reading; `samples`, `age_ms` and `changed_ms` are: a live sensor has a small age and a rising sample count.
 */
#define TDONGLE_TEMPERATURE_STEP_TENTHS 10
typedef struct {
    bool valid;                       /* the latest sample succeeded */
    int32_t current_tenths, peak_tenths;
    uint32_t sampled_at_ms;           /* uptime of the latest successful sample (0 before any) */
    uint32_t errors;
    uint32_t samples;                 /* successful samples since boot */
    uint32_t changed_at_ms;           /* uptime when `current` last differed from the sample before it */
    uint32_t age_ms;                  /* snapshot time minus sampled_at_ms; UINT32_MAX before the first sample */
} tdongle_temperature;
void tdongle_temperature_sample(void);
tdongle_temperature tdongle_temperature_snapshot(void);
