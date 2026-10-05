#pragma once
/* Is a wg_mgr membership slice a no-op? Portable (host-tested, tests/test_wg_idle.c).
 *
 * Every producer notifies the task after an enqueue, and ulTaskNotifyTake clears the count in one go, so a burst of N
 * packets can leave one wake-up behind that finds nothing left: a pass of about a dozen clock reads, three queue peeks
 * and the PM lock pair for no work. When nothing is queued, nothing is waiting for a handshake or a trial, no timer is
 * due and no state changed since the last pass, the slice can only re-arm its timers, so it does that and returns. The
 * test is conservative on purpose: any doubt means "not idle", i.e. the full slice as before. */
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    unsigned queued;               /* messages waiting: peer updates + wg rx + disco rx (+ the zero-copy DISCO ring) */
    bool packets_pending;          /* jit_packet_count != 0: an egress packet is queued or parked for a handshake */
    bool trial_pending;            /* an inbound trial slot is held (its deadline is polled) */
    bool directory_stale;          /* the directory generation moved since it was last reconciled */
    bool stun_cmm_due;             /* the one-shot CallMeMaybe broadcast after STUN has not been sent yet and could be */
    bool derp_changed;             /* the DERP connected flag differs from the last pass */
    uint64_t now_ms;
    uint64_t periodic_at_ms;       /* last_wg_periodic + 400 */
    uint64_t probes_at_ms;         /* last_disco_probe + 1000 (the probe test is strictly greater) */
    uint64_t snapshot_at_ms;       /* last_snapshot + 10000 */
    bool wg_ready;                 /* a WireGuard netif exists (the periodic work only runs with one) */
} ml_wg_idle_t;

static inline bool ml_wg_slice_idle(const ml_wg_idle_t *s) {
    if (s->queued || s->packets_pending || s->trial_pending || s->directory_stale || s->stun_cmm_due || s->derp_changed)
        return false;
    if (s->wg_ready && s->now_ms >= s->periodic_at_ms) return false;
    if (s->now_ms >= s->probes_at_ms) return false;        /* the probe test is now - last > 1000; >= is the safe side */
    if (s->now_ms >= s->snapshot_at_ms) return false;
    return true;
}
