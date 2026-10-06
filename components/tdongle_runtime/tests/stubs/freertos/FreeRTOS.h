#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#define pdTRUE 1
#define pdPASS 1
#define portMAX_DELAY 10000
/* The tick the host tests model: 1 ms by default, 10 ms (CONFIG_FREERTOS_HZ=100, the firmware's) with -DTEST_TICK_MS=10. */
#ifndef TEST_TICK_MS
#define TEST_TICK_MS 1
#endif
#define pdMS_TO_TICKS(x) ((uint32_t)(x) / TEST_TICK_MS)
typedef uint32_t TickType_t;
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(x) ((void)(x))
#define portEXIT_CRITICAL(x) ((void)(x))
