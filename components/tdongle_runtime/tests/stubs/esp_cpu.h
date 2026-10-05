#pragma once
#include <stdint.h>
static inline uint32_t esp_cpu_get_cycle_count(void) { static uint32_t t; return t += 100; }
