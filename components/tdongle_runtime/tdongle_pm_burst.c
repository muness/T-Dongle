#include "tdongle_pm_burst.h"
#include <string.h>

static uint32_t now_of(const tdongle_pm_burst_t *b) { return b->ops && b->ops->now_us ? b->ops->now_us() : 0; }

static bool refuse_in_isr(tdongle_pm_burst_t *b) {
    if (b->ops && b->ops->in_isr && b->ops->in_isr()) {
        atomic_fetch_add_explicit(&b->isr_rejects, 1, memory_order_relaxed);
        return true;
    }
    return false;
}

void tdongle_pm_burst_init(tdongle_pm_burst_t *b, const char *name, const tdongle_pm_ops_t *ops, void *ctx) {
    memset(b, 0, sizeof(*b));
    b->name = name;
    b->ops = ops;
    b->ctx = ctx;
}

static void note_max(tdongle_pm_burst_t *b, unsigned depth) {
    unsigned seen = atomic_load_explicit(&b->max_depth, memory_order_relaxed);
    while (depth > seen && !atomic_compare_exchange_weak_explicit(&b->max_depth, &seen, depth, memory_order_relaxed, memory_order_relaxed)) {
    }
}

void tdongle_pm_burst_begin(tdongle_pm_burst_t *b) {
    if (refuse_in_isr(b)) return;
    unsigned previous = atomic_fetch_add_explicit(&b->depth, 1, memory_order_acq_rel);
    note_max(b, previous + 1);
    if (previous != 0) return;
    atomic_store_explicit(&b->since_us, now_of(b), memory_order_relaxed);
    atomic_fetch_add_explicit(&b->acquires, 1, memory_order_relaxed);
    /* A refused acquire leaves nothing held; the matching release is then a harmless error in the backend. */
    if (b->ops && b->ops->acquire && !b->ops->acquire(b->ctx))
        atomic_fetch_add_explicit(&b->backend_failures, 1, memory_order_relaxed);
}

static void leave(tdongle_pm_burst_t *b) {
    uint32_t held = now_of(b) - atomic_load_explicit(&b->since_us, memory_order_relaxed);
    atomic_fetch_add_explicit(&b->held_us, held, memory_order_relaxed);
    atomic_fetch_add_explicit(&b->releases, 1, memory_order_relaxed);
    if (b->ops && b->ops->release) b->ops->release(b->ctx);
}

void tdongle_pm_burst_end(tdongle_pm_burst_t *b) {
    if (refuse_in_isr(b)) return;
    unsigned depth = atomic_load_explicit(&b->depth, memory_order_acquire);
    do {
        if (depth == 0) {
            atomic_fetch_add_explicit(&b->underflows, 1, memory_order_relaxed);
            return;
        }
    } while (!atomic_compare_exchange_weak_explicit(&b->depth, &depth, depth - 1, memory_order_acq_rel, memory_order_acquire));
    if (depth == 1) leave(b);
}

void tdongle_pm_burst_release_all(tdongle_pm_burst_t *b) {
    if (refuse_in_isr(b)) return;
    if (atomic_exchange_explicit(&b->depth, 0, memory_order_acq_rel) == 0) return;
    atomic_fetch_add_explicit(&b->forced_releases, 1, memory_order_relaxed);
    leave(b);
}

void tdongle_pm_burst_stats(const tdongle_pm_burst_t *b, tdongle_pm_burst_stats_t *out) {
#define LOAD(field) atomic_load_explicit(&((tdongle_pm_burst_t *)b)->field, memory_order_relaxed)
    out->name = b->name;
    out->depth = LOAD(depth);
    out->acquires = LOAD(acquires);
    out->releases = LOAD(releases);
    out->held_us = LOAD(held_us);
    out->max_depth = LOAD(max_depth);
    out->underflows = LOAD(underflows);
    out->forced_releases = LOAD(forced_releases);
    out->backend_failures = LOAD(backend_failures);
    out->isr_rejects = LOAD(isr_rejects);
#undef LOAD
}

/* ---- activity hold ------------------------------------------------------------------------------------------- */
void tdongle_pm_activity_init(tdongle_pm_activity_t *a, tdongle_pm_burst_t *burst, uint32_t hold_us,
                              void (*arm)(void *ctx, uint32_t delay_us), void *ctx) {
    memset(a, 0, sizeof(*a));
    a->burst = burst;
    a->hold_us = hold_us;
    a->arm = arm;
    a->ctx = ctx;
}

static void activity_start(tdongle_pm_activity_t *a) {
    if (atomic_exchange_explicit(&a->held, true, memory_order_acq_rel)) return;
    atomic_fetch_add_explicit(&a->starts, 1, memory_order_relaxed);
    tdongle_pm_burst_begin(a->burst);
    if (a->arm) a->arm(a->ctx, a->hold_us);
}

void tdongle_pm_activity_note(tdongle_pm_activity_t *a, uint32_t now_us) {
    if (refuse_in_isr(a->burst)) return;
    atomic_store_explicit(&a->last_us, now_us, memory_order_relaxed);
    if (atomic_load_explicit(&a->held, memory_order_acquire)) return;      /* the common case: one load */
    activity_start(a);
}

void tdongle_pm_activity_tick(tdongle_pm_activity_t *a, uint32_t now_us) {
    if (!atomic_load_explicit(&a->held, memory_order_acquire)) return;
    /* Signed: a note newer than `now_us` (this tick read the clock first) means "just now", not "71 minutes ago". */
    uint32_t last = atomic_load_explicit(&a->last_us, memory_order_relaxed);
    int32_t idle = (int32_t)(now_us - last);
    if (idle < 0) idle = 0;
    if ((uint32_t)idle < a->hold_us) {
        uint32_t left = a->hold_us - (uint32_t)idle;
        if (a->arm) a->arm(a->ctx, left < 1000 ? 1000 : left);
        return;
    }
    if (!atomic_exchange_explicit(&a->held, false, memory_order_acq_rel)) return;
    tdongle_pm_burst_end(a->burst);
    /* A note between the idle test and the exchange saw `held` and returned: take the lock again for it. */
    if (atomic_load_explicit(&a->last_us, memory_order_relaxed) != last) activity_start(a);
}
