#pragma once
#include <stdbool.h>
#include <stdint.h>
typedef struct {bool valid;int32_t current_tenths,peak_tenths;uint32_t sampled_at_ms,errors;} tdongle_temperature;
void tdongle_temperature_sample(void);
tdongle_temperature tdongle_temperature_snapshot(void);
