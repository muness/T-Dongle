#include "ml_mux.h"
#include <string.h>

void ml_mux_init(ml_mux_t *mux, const ml_mux_ops_t *ops, void *shared, uint64_t (*now_ms)(void)) {
    memset(mux, 0, sizeof(*mux));
    ml_mutex_init(&mux->lock);
    mux->ops = ops;
    mux->shared = shared;
    mux->now_ms = now_ms;
}

void ml_mux_destroy(ml_mux_t *mux) {
    ml_mutex_destroy(&mux->lock);
}

static unsigned count_locked(const ml_mux_t *mux) {
    unsigned n = 0;
    for (unsigned i = 0; i < ML_MUX_MAX; i++)
        if (mux->slot[i]) n++;
    return n;
}

int ml_mux_attach(ml_mux_t *mux, void *ctx) {
    if (!ctx) return -1;
    ml_mutex_lock(&mux->lock);
    int result = -1;
    for (unsigned i = 0; i < ML_MUX_MAX; i++) {
        if (mux->slot[i] == ctx) { result = -2; break; }
    }
    if (result == -1) {
        for (unsigned i = 0; i < ML_MUX_MAX; i++) {
            if (!mux->slot[i]) {
                mux->slot[i] = ctx;
                mux->attached++;
                unsigned n = count_locked(mux);
                if (n > mux->peak_members) mux->peak_members = n;
                result = 0;
                break;
            }
        }
    }
    if (result != 0) mux->attach_refused++;
    ml_mutex_unlock(&mux->lock);
    return result;
}

bool ml_mux_detach(ml_mux_t *mux, void *ctx, uint32_t timeout_ms) {
    if (!ctx) return true;
    if (!ml_mutex_lock_for(&mux->lock, timeout_ms)) {
        /* The slice in flight did not end in time. Count it once per attempt; do not free. */
        __atomic_add_fetch(&mux->detach_timeouts, 1, __ATOMIC_RELAXED);
        return false;
    }
    for (unsigned i = 0; i < ML_MUX_MAX; i++) {
        if (mux->slot[i] == ctx) {
            mux->slot[i] = NULL;
            mux->detached++;
            if (mux->ops->teardown) mux->ops->teardown(ctx, mux->shared);
            break;
        }
    }
    ml_mutex_unlock(&mux->lock);
    return true;
}

unsigned ml_mux_pass(ml_mux_t *mux) {
    unsigned serviced = 0;
    /* The rotation index is only used by the task that calls pass; other threads touch the table
     * under the lock, so each slot is read under the lock below. */
    unsigned first = mux->start;
    for (unsigned k = 0; k < ML_MUX_MAX; k++) {
        unsigned i = (first + k) % ML_MUX_MAX;
        ml_mutex_lock(&mux->lock);
        void *ctx = mux->slot[i];
        if (ctx) {
            uint64_t t0 = mux->now_ms ? mux->now_ms() : 0;
            mux->ops->service(ctx, mux->shared);
            if (mux->now_ms) {
                uint64_t dt = mux->now_ms() - t0;
                if (dt > mux->max_service_ms) mux->max_service_ms = (uint32_t)dt;
                if (dt > ML_MUX_SLOW_SERVICE_MS) mux->slow_services++;
            }
            mux->serviced++;
            serviced++;
        }
        ml_mutex_unlock(&mux->lock);
    }
    mux->start = (first + 1) % ML_MUX_MAX;
    mux->passes++;
    return serviced;
}

void ml_mux_foreach(ml_mux_t *mux, void (*fn)(void *ctx, void *arg), void *arg) {
    ml_mutex_lock(&mux->lock);
    for (unsigned i = 0; i < ML_MUX_MAX; i++)
        if (mux->slot[i]) fn(mux->slot[i], arg);
    ml_mutex_unlock(&mux->lock);
}

void ml_mux_foreach_held(ml_mux_t *mux, void (*fn)(void *ctx, void *arg), void *arg) {
    for (unsigned i = 0; i < ML_MUX_MAX; i++)
        if (mux->slot[i]) fn(mux->slot[i], arg);
}

unsigned ml_mux_count(ml_mux_t *mux) {
    ml_mutex_lock(&mux->lock);
    unsigned n = count_locked(mux);
    ml_mutex_unlock(&mux->lock);
    return n;
}

bool ml_mux_contains(ml_mux_t *mux, const void *ctx) {
    bool found = false;
    ml_mutex_lock(&mux->lock);
    for (unsigned i = 0; i < ML_MUX_MAX; i++)
        if (mux->slot[i] == ctx) found = true;
    ml_mutex_unlock(&mux->lock);
    return found;
}
