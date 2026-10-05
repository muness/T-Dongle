/**
 * @file ml_rt_core.h
 * @brief The lifecycle of the shared tasks, independent of FreeRTOS and of what a membership is.
 *
 * ml_runtime.c supplies the FreeRTOS pieces (task creation, the three loop bodies, what a membership's service slice
 * does); this core owns the part that has to be right: when the shared tasks start and stop, the order a membership is
 * attached and detached, the rollback when attaching fails half way, and the rule that a membership whose detach did not
 * complete is never reported as gone. It runs unchanged on the host (tests/test_rt_lifecycle.c: real threads, members
 * that are freed the moment detach returns, under ASan and TSan).
 *
 *   attach  first member starts the tasks (waiting for a previous shutdown to finish), then attaches to each mux in
 *           `attach_order`; a refusal detaches whatever was attached, stops the tasks if no member remains, and fails
 *   detach  detaches from each mux in `detach_order` (each runs that task's teardown for the member under the mux
 *           lock), and only if ALL succeeded marks the member gone; the last member out stops the tasks. A detach that
 *           times out leaves the member attached, so the caller must not free it, and a later retry is idempotent.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "ml_mux.h"

#define ML_RT_CORE_TASKS 3

struct ml_rt_core;
typedef struct {
    /* Start shared task `index`. Its body loops until ml_rt_core_should_stop(core) and must call
     * ml_rt_core_task_exit(core) as its last act. */
    bool (*spawn)(void *platform, unsigned index, struct ml_rt_core *core);
    void (*sleep_ms)(uint32_t ms);
} ml_rt_platform_t;

typedef struct ml_rt_core {
    ml_mutex_t lock;
    const ml_rt_platform_t *platform;
    void *platform_ctx;
    ml_mux_t mux[ML_RT_CORE_TASKS];
    unsigned attach_order[ML_RT_CORE_TASKS];
    unsigned detach_order[ML_RT_CORE_TASKS];
    uint32_t detach_timeout_ms, stop_wait_ms;
    volatile bool stop;
    volatile int tasks_alive;
    unsigned members;
    uint32_t starts, stops, attach_failures, detach_failures;
} ml_rt_core_t;

void ml_rt_core_init(ml_rt_core_t *core, const ml_rt_platform_t *platform, void *platform_ctx,
                     const ml_mux_ops_t *ops[ML_RT_CORE_TASKS], void *shared[ML_RT_CORE_TASKS],
                     uint64_t (*now_ms)(void), const unsigned attach_order[ML_RT_CORE_TASKS],
                     const unsigned detach_order[ML_RT_CORE_TASKS], uint32_t detach_timeout_ms);

/* Returns false (nothing attached, nothing running) on failure: *why = 1 tasks could not be created, 2 a previous
 * shutdown has not finished, 3 every mux slot is in use. */
bool ml_rt_core_attach(ml_rt_core_t *core, void *member, bool *attached, int *why);
bool ml_rt_core_detach(ml_rt_core_t *core, void *member, bool *attached);

/* For the task bodies. */
static inline bool ml_rt_core_should_stop(const ml_rt_core_t *core) { return __atomic_load_n(&core->stop, __ATOMIC_ACQUIRE); }
void ml_rt_core_task_exit(ml_rt_core_t *core);
bool ml_rt_core_running(ml_rt_core_t *core);
unsigned ml_rt_core_members(ml_rt_core_t *core);
