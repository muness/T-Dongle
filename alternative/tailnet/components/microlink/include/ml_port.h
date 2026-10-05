/**
 * @file ml_port.h
 * @brief The few operating-system services the shared-runtime core needs.
 *
 * The shared-runtime modules (ml_mux, ml_derp_link, ml_negotiation, the
 * WireGuard peer pool) hold no FreeRTOS or lwIP types of their own, so the
 * same code runs in the firmware and under ASan/UBSan/TSan on the host. This
 * header is the whole seam: a mutex, a millisecond sleep and a monotonic clock.
 * Everything else a module needs from the platform comes in through an explicit
 * operations table (see ml_derp_link.h) or a plain function argument.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

typedef struct {
    StaticSemaphore_t storage;
    SemaphoreHandle_t handle;
} ml_mutex_t;

static inline void ml_mutex_init(ml_mutex_t *m) { m->handle = xSemaphoreCreateMutexStatic(&m->storage); }
static inline void ml_mutex_destroy(ml_mutex_t *m) { if (m->handle) vSemaphoreDelete(m->handle); m->handle = NULL; }
static inline void ml_mutex_lock(ml_mutex_t *m) { xSemaphoreTake(m->handle, portMAX_DELAY); }
static inline bool ml_mutex_lock_for(ml_mutex_t *m, uint32_t ms) { return xSemaphoreTake(m->handle, pdMS_TO_TICKS(ms)) == pdTRUE; }
static inline void ml_mutex_unlock(ml_mutex_t *m) { xSemaphoreGive(m->handle); }
static inline void ml_sleep_ms(uint32_t ms) { vTaskDelay(pdMS_TO_TICKS(ms) ? pdMS_TO_TICKS(ms) : 1); }

#else /* host */
#include <pthread.h>
#include <time.h>
#include <unistd.h>

typedef struct { pthread_mutex_t m; } ml_mutex_t;

static inline void ml_mutex_init(ml_mutex_t *m) { pthread_mutex_init(&m->m, NULL); }
static inline void ml_mutex_destroy(ml_mutex_t *m) { pthread_mutex_destroy(&m->m); }
static inline void ml_mutex_lock(ml_mutex_t *m) { pthread_mutex_lock(&m->m); }
static inline void ml_mutex_unlock(ml_mutex_t *m) { pthread_mutex_unlock(&m->m); }
static inline void ml_sleep_ms(uint32_t ms) { usleep((useconds_t)ms * 1000u); }
static inline uint64_t ml_port_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
/* macOS has no pthread_mutex_timedlock; poll with trylock (1 ms) instead. */
static inline bool ml_mutex_lock_for(ml_mutex_t *m, uint32_t ms) {
    uint64_t end = ml_port_mono_ms() + ms;
    for (;;) {
        if (pthread_mutex_trylock(&m->m) == 0) return true;
        if (ml_port_mono_ms() >= end) return false;
        usleep(1000);
    }
}
#endif
