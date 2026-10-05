/**
 * @file ml_coord_state.h
 * @brief The control task's state machine states, and which of them hold the negotiation token.
 *
 * The control task is a loop around `switch (state)`. Every attempt walks STUN_PROBE -> ... -> FETCH_PEERS ->
 * LONG_POLL, and every failure lands in RECONNECTING. The token (ml_negotiation.h) covers exactly the walk from
 * STUN_PROBE through FETCH_PEERS: the Noise handshake, registration and the initial map, the control channel's memory
 * peak. LONG_POLL (steady state), RECONNECTING (backing off) and IDLE do not hold it.
 *
 * "Release on every error path" is therefore not a matter of remembering a call at each failure: one function,
 * coord_token_sync(), runs at the top of every loop iteration and makes the token follow the state. Any path that
 * leaves a negotiation state, however it got there, lets go at the next iteration, and the loop's exit calls it with
 * IDLE. tests/test_coord_token.c walks every state transition (including the ones the real code takes on errors,
 * shutdown and commands) and checks the invariant.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "ml_negotiation.h"

typedef enum {
    COORD_IDLE,
    COORD_STUN_PROBE,
    COORD_DNS_RESOLVE,
    COORD_TCP_CONNECT,
    COORD_NOISE_HANDSHAKE,
    COORD_H2_PREFACE,
    COORD_REGISTER,
    COORD_FETCH_PEERS,
    COORD_LONG_POLL,
    COORD_RECONNECTING,
} coord_state_t;

static inline bool coord_state_negotiates(coord_state_t s) {
    return s >= COORD_STUN_PROBE && s <= COORD_FETCH_PEERS;
}

/* Bring the token in line with `s`. Returns true when the work of state `s` may run now: always for a state that
 * does not negotiate, and for a negotiating state only once the token is granted. `*engaged` records that this task
 * holds the token OR waits in its queue, so a task that gave up waiting (shutdown, a command, a failure) also leaves
 * the queue instead of lingering until it is reaped as stale, and steady states never touch the lock. Idempotent. */
static inline bool coord_token_sync(ml_neg_t *neg, uintptr_t key, coord_state_t s, ml_neg_prio_t prio, bool *engaged) {
    if (coord_state_negotiates(s)) {
        /* Ask every time: for the holder this is a cheap "yes", and it notices a token that was reaped. */
        *engaged = true;
        return ml_neg_request(neg, key, prio, ML_NEG_PHASE_CONTROL) == ML_NEG_GRANTED;
    }
    if (*engaged) {
        ml_neg_release(neg, key);
        *engaged = false;
    }
    return true;
}
