#pragma once
#include "FreeRTOS.h"
typedef void *TaskHandle_t;
int xTaskCreatePinnedToCore(void (*)(void *), const char *, uint32_t, void *, unsigned, TaskHandle_t *, int);
int xTaskNotifyGive(TaskHandle_t);
uint32_t ulTaskNotifyTake(int, TickType_t);
void vTaskDelay(TickType_t);
TickType_t xTaskGetTickCount(void);
unsigned uxTaskGetStackHighWaterMark(TaskHandle_t);
