/**
 * @file ml_mux.h
 * @brief One shared task serving every membership: the registry and its lifetime rule.
 *
 * ADR 0013 stage 1 replaces a task per membership with ONE net_io, ONE DERP and ONE
 * wg_mgr task. Each shared task owns an ml_mux_t. A membership attaches to it, the
 * task's loop calls ml_mux_pass() once per iteration, and the mux calls the
 * membership's service function once per pass, round robin, rotating the starting
 * member so no membership is always last.
 *
 * Lifetime (the quiesce protocol). The mux lock is held while a membership is being
 * serviced, attached, detached or torn down. Therefore:
 *   - after ml_mux_detach() returns true, the mux will never touch that context again
 *     and the caller may free it: there is no reference count to leak or to forget;
 *   - the optional teardown hook runs under the same lock, after the context left the
 *     table and before detach returns, so state only the shared task may use (a TLS
 *     context, say) is released while the task cannot be using it;
 *   - a detach waits at most for one bounded service slice of that task. If the slice
 *     does not end within the timeout, detach returns false, the context stays attached
 *     and the caller must not free it; it calls detach again later (the gateway
 *     manager does, every ten seconds), which is idempotent, and the counter says so).
 *
 * A service function must be bounded (no blocking waits), must not call attach or
 * detach on its own mux, and must not take any lock that a thread holding the mux
 * lock can wait for. The lock is never held while a task sleeps between passes, so
 * attach and detach latency is one slice of one membership, not one pass.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "ml_port.h"

#define ML_MUX_MAX 4

typedef struct {
    /* Bounded work for one membership. `shared` is the task's scratch (e.g. a packet buffer). */
    void (*service)(void *ctx, void *shared);
    /* Optional. Runs under the mux lock after `ctx` left the table, from the detaching thread. */
    void (*teardown)(void *ctx, void *shared);
} ml_mux_ops_t;

typedef struct {
    ml_mutex_t lock;
    const ml_mux_ops_t *ops;
    void *shared;
    uint64_t (*now_ms)(void);       /* optional: enables the service-time statistics */
    void *slot[ML_MUX_MAX];
    unsigned start;                 /* rotating first member of the next pass */
    /* Statistics, written under the lock. */
    uint32_t passes, serviced, attached, detached, detach_timeouts, attach_refused;
    uint32_t max_service_ms, slow_services;
    unsigned peak_members;
} ml_mux_t;

#define ML_MUX_SLOW_SERVICE_MS 100

void ml_mux_init(ml_mux_t *mux, const ml_mux_ops_t *ops, void *shared, uint64_t (*now_ms)(void));
void ml_mux_destroy(ml_mux_t *mux);

/* 0 on success, -1 when full, -2 when already attached. Waits for the slice in flight. */
int ml_mux_attach(ml_mux_t *mux, void *ctx);

/* True once `ctx` is out of the table and torn down (or was never attached); false when the
 * timeout expired first, in which case `ctx` is still attached. */
bool ml_mux_detach(ml_mux_t *mux, void *ctx, uint32_t timeout_ms);

/* One fair pass: every attached member is serviced once. Returns how many were serviced. */
unsigned ml_mux_pass(ml_mux_t *mux);

/* Visit every attached member under the lock. For loops whose work is not one slice per member (net_io's single
 * select over all sockets). `fn` must be quick and must not block, attach or detach. */
void ml_mux_foreach(ml_mux_t *mux, void (*fn)(void *ctx, void *arg), void *arg);

/* Same walk for code that is ALREADY running inside a service slice of this mux (so the lock is held by this very
 * thread): the wg_mgr slice reads every membership's peers to choose a pool eviction victim. Calling it from anywhere
 * else is a data race; there is no recursive locking. */
void ml_mux_foreach_held(ml_mux_t *mux, void (*fn)(void *ctx, void *arg), void *arg);

unsigned ml_mux_count(ml_mux_t *mux);
bool ml_mux_contains(ml_mux_t *mux, const void *ctx);
