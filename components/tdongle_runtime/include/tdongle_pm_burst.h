#pragma once
/* A nesting counter around a power-management lock: the lock is held while work is pending and only then.
 *
 *   begin()  idle -> busy: takes the lock (nested calls only count)
 *   end()    busy -> idle: releases it when the outermost section ends
 *
 * This file is portable C (no ESP-IDF): the backend is a pair of callbacks, so the host tests drive the real
 * counting and error-path logic against a fake lock. tdongle_pm.h binds it to ESP_PM_CPU_FREQ_MAX.
 *
 * Rules the callers keep (docs/adr/0016-dfs-power-management.md):
 *  - task context only. In an interrupt, begin/end do nothing and are counted in isr_rejects.
 *  - a section covers processing, never an indefinite wait: end() runs before the task blocks.
 *  - a task that can exit calls release_all() on the way out, so no exit path leaks the lock.
 *
 * Concurrency: the nesting depth is atomic and the backend lock is itself a counting lock, so an interleaving of
 * begin/end from several tasks always leaves the backend balanced (one acquire per 0->1, one release per 1->0).
 * In practice each object has one owning task. The time accounting is approximate under such interleaving. */
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool (*acquire)(void *ctx);          /* take the lock; false: it could not be taken */
    void (*release)(void *ctx);
    uint32_t (*now_us)(void);            /* optional; without it held_us stays 0 */
    bool (*in_isr)(void);                /* optional; true: refuse (the backend must not run in an interrupt) */
} tdongle_pm_ops_t;

typedef struct {
    const char *name;
    uint32_t depth;
    uint32_t acquires;                   /* idle -> busy transitions */
    uint32_t releases;                   /* busy -> idle transitions, including forced ones */
    uint32_t held_us;                    /* total time busy; wraps at 2^32 us (71.6 min), consumers take differences */
    uint32_t max_depth;
    uint32_t underflows;                 /* end() without begin(): a caller bug, ignored */
    uint32_t forced_releases;            /* release_all() found the section still open: a task exited mid-burst */
    uint32_t backend_failures;           /* the backend refused an acquire */
    uint32_t isr_rejects;
} tdongle_pm_burst_stats_t;

typedef struct {
    const char *name;
    const tdongle_pm_ops_t *ops;
    void *ctx;
    atomic_uint depth, since_us;
    atomic_uint acquires, releases, held_us, max_depth, underflows, forced_releases, backend_failures, isr_rejects;
} tdongle_pm_burst_t;

void tdongle_pm_burst_init(tdongle_pm_burst_t *burst, const char *name, const tdongle_pm_ops_t *ops, void *ctx);
void tdongle_pm_burst_begin(tdongle_pm_burst_t *burst);
void tdongle_pm_burst_end(tdongle_pm_burst_t *burst);
/* Close every open section at once (task exit, membership stop). A no-op when idle. */
void tdongle_pm_burst_release_all(tdongle_pm_burst_t *burst);
void tdongle_pm_burst_stats(const tdongle_pm_burst_t *burst, tdongle_pm_burst_stats_t *out);

/* ---- activity hold ---------------------------------------------------------------------------------------------
 * Some stages of the forwarded data path (the Wi-Fi driver, the lwIP tcpip task, the USB class task) never wait on
 * a queue of ours, so there is no loop of ours to bracket. They call note() when a packet passes. The first note
 * after a quiet spell takes the lock (idle -> active) and arms a one-shot timer; the timer calls tick(), which keeps
 * the lock until `hold_us` have passed without a note and then drops it. A stream therefore pays for one lock
 * acquire, not one per packet, and the CPU returns to its low frequency about hold_us after the last packet.
 *
 * note() runs in the caller's task (any task, many at once); tick() runs in the timer task. Both are safe against
 * each other: `held` is flipped with an exchange and the burst counter absorbs a begin/end that cross. Never from an
 * interrupt (note() then counts an isr_reject and does nothing). */
typedef struct {
    tdongle_pm_burst_t *burst;
    uint32_t hold_us;                    /* must be below 2^31 */
    void (*arm)(void *ctx, uint32_t delay_us);   /* start the one-shot timer; tick() runs from it */
    void *ctx;
    atomic_uint last_us;                 /* time of the latest note */
    atomic_bool held;                    /* this object owns one begin() on `burst` */
    atomic_uint starts;                  /* idle -> active transitions (lock acquires caused by this object) */
} tdongle_pm_activity_t;

void tdongle_pm_activity_init(tdongle_pm_activity_t *a, tdongle_pm_burst_t *burst, uint32_t hold_us,
                              void (*arm)(void *ctx, uint32_t delay_us), void *ctx);
void tdongle_pm_activity_note(tdongle_pm_activity_t *a, uint32_t now_us);
void tdongle_pm_activity_tick(tdongle_pm_activity_t *a, uint32_t now_us);
