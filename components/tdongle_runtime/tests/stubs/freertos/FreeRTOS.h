#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#define pdTRUE 1
#define pdPASS 1
#define portMAX_DELAY 10000
#define pdMS_TO_TICKS(x) (x)
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(x) ((void)(x))
#define portEXIT_CRITICAL(x) ((void)(x))
