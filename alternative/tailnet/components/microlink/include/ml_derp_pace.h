/**
 * @file ml_derp_pace.h
 * @brief When the DERP I/O task may try to connect again (host-testable).
 *
 * A connect attempt that fails for a reason of its own (refused, certificate not
 * authenticated, handshake error) doubles the wait up to a ceiling. A connect
 * that cannot even be tried because the wall clock is not set (certificates
 * cannot be judged) is not a failure of the relay: it neither raises the wait
 * nor counts as a retry, and the first attempt follows the clock at once. Nothing here blocks; the DERP task simply keeps waiting while
 * the control task registers and the other memberships run.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t backoff_ms;
    uint64_t next_ms;       /* 0 = not armed */
    uint32_t deferrals;     /* times a connect was held back for the clock */
    bool waiting_for_clock;
} ml_derp_pace_t;

static inline void ml_derp_pace_reset(ml_derp_pace_t *p, uint32_t min_ms) {
    p->backoff_ms = min_ms;
    p->next_ms = 0;
    p->waiting_for_clock = false;
}

/* True when a connect should be attempted now. */
static inline bool ml_derp_pace_due(ml_derp_pace_t *p, uint64_t now_ms, bool clock_valid,
                                    uint32_t min_ms) {
    if (!clock_valid) {
        if (!p->waiting_for_clock) {
            p->waiting_for_clock = true;
            p->deferrals++;
        }
        p->backoff_ms = min_ms;
        p->next_ms = 0;
        return false;
    }
    if (p->waiting_for_clock) {   /* the clock just arrived: connect now, not after the wait */
        p->waiting_for_clock = false;
        p->next_ms = now_ms;
        return true;
    }
    if (!p->next_ms) {
        p->next_ms = now_ms + p->backoff_ms;
        return false;
    }
    return now_ms >= p->next_ms;
}

/* The attempt made after ml_derp_pace_due() returned true failed. */
static inline void ml_derp_pace_failed(ml_derp_pace_t *p, uint64_t now_ms, uint32_t max_ms) {
    p->backoff_ms = p->backoff_ms > max_ms / 2 ? max_ms : p->backoff_ms * 2;
    p->next_ms = now_ms + p->backoff_ms;
}
