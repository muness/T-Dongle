/**
 * @file ml_negotiation.h
 * @brief The global negotiation token (ADR 0013, S&T steps N1 and N1.2).
 *
 * A membership's join has a memory peak that is far above its steady cost: the Noise handshake, registration and
 * the initial map (control channel), and the DERP TLS handshake (about 16 KB of mbedTLS state while the server
 * certificate is verified). Two joins overlapping add their peaks; that is what took v120 to a 6 KB largest block
 * and a panic. The token serialises them: at most one membership is in a negotiation phase at any moment.
 *
 *   - Phase A (START .. CONTROL): microlink_start's allocations, Noise, registration and the initial map. Taken by
 *     the gateway before microlink_init, handed to the control task, released when the first map is applied or on
 *     any failure path.
 *   - Phase B (DERP): one DERP TLS handshake. Taken by the DERP link, released at READY or on failure.
 *
 * The token is never held across steady-state traffic. Between two phases of one membership it is free, so another
 * membership's negotiation can interleave; their peaks never coexist.
 *
 * Properties, each tested in tests/test_negotiation.c:
 *   - mutual exclusion: one holder;
 *   - ordered: highest priority first, FIFO within a priority, and a waiter older than `aging_ms` is promoted one
 *     priority class per period, so a steady stream of reconnects cannot starve a first join;
 *   - bounded: ml_neg_acquire() gives up after its timeout and leaves no trace in the queue, which makes the
 *     failure retryable;
 *   - self-healing: a holder that never releases loses the token after `lease_ms` (counted), and a waiter that
 *     stops polling (its task died) is dropped from the queue after `stale_ms`, so neither can wedge the gateway;
 *   - cooperative with non-blocking callers: ml_neg_request() never waits, it is the call the DERP task and the
 *     control task poll.
 * Holders are identified by an opaque non-zero key, not by a thread: the token passes from the gateway's start
 * path to the control task without a hand-over.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "ml_port.h"

#define ML_NEG_MAX_WAITERS 6

typedef enum {
    ML_NEG_PRIO_START = 0,     /* first join of a membership */
    ML_NEG_PRIO_REJOIN = 1,    /* the control session dropped: register again */
    ML_NEG_PRIO_RELAY = 2      /* a membership without a relay: DERP handshake */
} ml_neg_prio_t;

typedef enum {
    ML_NEG_PHASE_NONE = 0,
    ML_NEG_PHASE_START,        /* microlink_init / microlink_start allocations */
    ML_NEG_PHASE_CONTROL,      /* Noise, registration, initial map */
    ML_NEG_PHASE_DERP          /* DERP TLS handshake */
} ml_neg_phase_t;

typedef enum { ML_NEG_GRANTED, ML_NEG_QUEUED, ML_NEG_FULL } ml_neg_result_t;

typedef struct {
    ml_mutex_t lock;
    uint64_t (*now_ms)(void);
    uint32_t lease_ms, stale_ms, aging_ms;
    uintptr_t holder;
    ml_neg_phase_t holder_phase;
    uint64_t granted_ms;
    struct {
        uintptr_t key;
        uint8_t prio, phase;
        uint64_t enq_ms, poll_ms;
        uint32_t seq;
    } q[ML_NEG_MAX_WAITERS];
    unsigned nq;
    uint32_t seq;
    /* Statistics. */
    uint32_t grants, releases, timeouts, cancelled, lease_expired, stale_dropped, refused_full;
    uint32_t max_wait_ms, max_hold_ms;
} ml_neg_t;

typedef struct {
    uintptr_t holder;
    ml_neg_phase_t phase;
    uint32_t held_ms;
    unsigned waiting;
    uint32_t grants, timeouts, lease_expired, stale_dropped, refused_full, max_wait_ms, max_hold_ms;
} ml_neg_status_t;

/* Defaults: a negotiation phase is bounded well below 60 s (the DERP attempt ends at 30 s, a control attempt at the
 * control timeouts); a poller polls at least every 100 ms. */
#define ML_NEG_LEASE_MS 90000
#define ML_NEG_STALE_MS 2000
#define ML_NEG_AGING_MS 20000

void ml_neg_init(ml_neg_t *n, uint64_t (*now_ms)(void), uint32_t lease_ms, uint32_t stale_ms, uint32_t aging_ms);

/* Non-blocking, idempotent: call repeatedly until GRANTED (a holder asking again stays the holder). */
ml_neg_result_t ml_neg_request(ml_neg_t *n, uintptr_t key, ml_neg_prio_t prio, ml_neg_phase_t phase);

/* Blocking form for threads that may wait (the gateway manager). False on timeout; the caller is then out of the
 * queue and may simply retry later. */
bool ml_neg_acquire(ml_neg_t *n, uintptr_t key, ml_neg_prio_t prio, ml_neg_phase_t phase, uint32_t timeout_ms);

/* Release the token if `key` holds it, and leave the queue if it waits. Safe to call at any time, any number of
 * times: this is what every error path calls. Returns true when `key` was the holder. */
bool ml_neg_release(ml_neg_t *n, uintptr_t key);

bool ml_neg_holds(ml_neg_t *n, uintptr_t key);
void ml_neg_status(ml_neg_t *n, ml_neg_status_t *out);
const char *ml_neg_phase_name(ml_neg_phase_t p);
