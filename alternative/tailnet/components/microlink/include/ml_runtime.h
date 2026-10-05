/**
 * @file ml_runtime.h
 * @brief The shared runtime: three tasks that serve every membership (ADR 0013 stage 1).
 *
 * net_io, derp and wg_mgr exist once. The first membership to start creates them, the last to stop deletes them (so
 * a gateway with no membership holds none of their 22 KB of stacks). A membership attaches to each task's ml_mux_t
 * and the tasks visit the attached memberships, one bounded slice each, round robin. coord stays one task per
 * membership (stage 2 is gated on board measurements).
 *
 * Lifetime rule, the one that makes the sharing safe: detach waits for the slice in flight under the task's mux lock,
 * runs the task's teardown hook (derp: close the TLS connection; wg: remove the WireGuard interface) and only then
 * returns. After ml_rt_detach() returns true no shared task will ever touch the membership again, so microlink_destroy
 * can free it. If a task cannot let go within ML_RT_DETACH_TIMEOUT_MS, detach returns false, the membership stays
 * attached, and the caller leaks the context rather than free it under a running task (stop_incomplete).
 *
 * The negotiation token (ml_negotiation.h) lives here too: it is process wide state that outlives memberships.
 */
#pragma once

#include "microlink_internal.h"

#define ML_RT_DETACH_TIMEOUT_MS 3000

typedef enum { ML_RT_TASK_NET_IO, ML_RT_TASK_DERP, ML_RT_TASK_WG_MGR, ML_RT_TASK_COUNT } ml_rt_task_t;

typedef struct {
    bool running;
    unsigned members;
    uint32_t starts, stops, attach_failures, detach_failures;
    uint32_t stack_bytes[ML_RT_TASK_COUNT];       /* configured */
    uint32_t stack_free[ML_RT_TASK_COUNT];        /* high-water mark: bytes never used (UINT32_MAX when not running) */
    uint32_t passes[ML_RT_TASK_COUNT];
    uint32_t max_service_ms[ML_RT_TASK_COUNT];    /* longest single membership slice */
    uint32_t slow_services[ML_RT_TASK_COUNT];     /* slices over ML_MUX_SLOW_SERVICE_MS */
    uint32_t detach_timeouts[ML_RT_TASK_COUNT];
    ml_neg_status_t negotiation;
} ml_rt_status_t;

/* Process-wide negotiation token. Initialises the runtime's static state on first use; safe from any task. */
ml_neg_t *ml_rt_negotiation(void);

/* Heap the shared tasks need before the NEXT membership can attach: their stacks and TCBs when they are not running,
 * zero when they are. Admission charges this once, to the first membership. */
size_t ml_rt_start_bytes(void);

/* Start the shared tasks if this is the first membership, and attach. ESP_OK, or why not (no memory, previous
 * shutdown not finished). On failure nothing stays attached or running. */
esp_err_t ml_rt_attach(microlink_t *ml);

/* Detach from every shared task, tear down their per-membership state, and stop the tasks if this was the last
 * membership. False: a task did not let go in time (the membership stays attached; do not free it). Idempotent. */
bool ml_rt_detach(microlink_t *ml);

/* Visit every membership attached to the wg_mgr task. ONLY from inside a wg_mgr service slice (the mux lock is held). */
void ml_rt_wg_foreach_held(void (*fn)(microlink_t *ml, void *arg), void *arg);

void ml_rt_status(ml_rt_status_t *out);
TaskHandle_t ml_rt_task_handle(ml_rt_task_t which);
