#include "ml_negotiation.h"
#include <string.h>

void ml_neg_init(ml_neg_t *n, uint64_t (*now_ms)(void), uint32_t lease_ms, uint32_t stale_ms, uint32_t aging_ms) {
    memset(n, 0, sizeof(*n));
    ml_mutex_init(&n->lock);
    n->now_ms = now_ms;
    n->lease_ms = lease_ms ? lease_ms : ML_NEG_LEASE_MS;
    n->stale_ms = stale_ms ? stale_ms : ML_NEG_STALE_MS;
    n->aging_ms = aging_ms ? aging_ms : ML_NEG_AGING_MS;
}

const char *ml_neg_phase_name(ml_neg_phase_t p) {
    switch (p) {
    case ML_NEG_PHASE_START: return "start";
    case ML_NEG_PHASE_CONTROL: return "control";
    case ML_NEG_PHASE_DERP: return "derp";
    default: return "none";
    }
}

static void drop_waiter(ml_neg_t *n, unsigned i) {
    for (; i + 1 < n->nq; i++) n->q[i] = n->q[i + 1];
    n->nq--;
}

static int find_waiter(const ml_neg_t *n, uintptr_t key) {
    for (unsigned i = 0; i < n->nq; i++)
        if (n->q[i].key == key) return (int)i;
    return -1;
}

static void end_hold(ml_neg_t *n, uint64_t now) {
    uint32_t held = (uint32_t)(now - n->granted_ms);
    if (held > n->max_hold_ms) n->max_hold_ms = held;
    n->holder = 0;
    n->holder_phase = ML_NEG_PHASE_NONE;
}

/* Effective priority: the class, plus one per aging period spent waiting. */
static uint32_t effective_prio(const ml_neg_t *n, unsigned i, uint64_t now) {
    return n->q[i].prio + (uint32_t)((now - n->q[i].enq_ms) / n->aging_ms);
}

static void reap(ml_neg_t *n, uint64_t now) {
    if (n->holder && now - n->granted_ms > n->lease_ms) {
        /* The holder never released: a bug or a dead task. Free the token (counted) rather than wedge every join. */
        n->lease_expired++;
        end_hold(n, now);
    }
    for (unsigned i = 0; i < n->nq;) {
        if (now - n->q[i].poll_ms > n->stale_ms) {
            n->stale_dropped++;
            drop_waiter(n, i);
        } else {
            i++;
        }
    }
}

ml_neg_result_t ml_neg_request(ml_neg_t *n, uintptr_t key, ml_neg_prio_t prio, ml_neg_phase_t phase) {
    uint64_t now = n->now_ms();
    ml_mutex_lock(&n->lock);
    ml_neg_result_t result;
    if (n->holder == key) {
        result = ML_NEG_GRANTED;
        goto out;
    }
    int idx = find_waiter(n, key);
    if (idx < 0) {
        if (n->nq >= ML_NEG_MAX_WAITERS) {
            n->refused_full++;
            result = ML_NEG_FULL;
            goto out;
        }
        idx = (int)n->nq++;
        n->q[idx].key = key;
        n->q[idx].prio = (uint8_t)prio;
        n->q[idx].phase = (uint8_t)phase;
        n->q[idx].enq_ms = now;
        n->q[idx].seq = n->seq++;
    }
    n->q[idx].poll_ms = now;
    reap(n, now);
    /* `reap` may have dropped waiters: look the caller up again. */
    idx = find_waiter(n, key);
    if (idx < 0) {            /* cannot happen: the caller just polled, so it is not stale */
        result = ML_NEG_QUEUED;
        goto out;
    }
    if (!n->holder) {
        /* The best waiter takes the token: highest effective priority, then oldest. */
        unsigned best = 0;
        for (unsigned i = 1; i < n->nq; i++) {
            uint32_t pi = effective_prio(n, i, now), pb = effective_prio(n, best, now);
            if (pi > pb || (pi == pb && n->q[i].seq < n->q[best].seq)) best = i;
        }
        if (n->q[best].key == key) {
            uint32_t waited = (uint32_t)(now - n->q[best].enq_ms);
            if (waited > n->max_wait_ms) n->max_wait_ms = waited;
            n->holder = key;
            n->holder_phase = (ml_neg_phase_t)n->q[best].phase;
            n->granted_ms = now;
            n->grants++;
            drop_waiter(n, best);
            result = ML_NEG_GRANTED;
            goto out;
        }
    }
    result = ML_NEG_QUEUED;
out:
    ml_mutex_unlock(&n->lock);
    return result;
}

bool ml_neg_acquire(ml_neg_t *n, uintptr_t key, ml_neg_prio_t prio, ml_neg_phase_t phase, uint32_t timeout_ms) {
    uint64_t end = n->now_ms() + timeout_ms;
    for (;;) {
        ml_neg_result_t r = ml_neg_request(n, key, prio, phase);
        if (r == ML_NEG_GRANTED) return true;
        if (r == ML_NEG_FULL || n->now_ms() >= end) {
            ml_mutex_lock(&n->lock);
            int idx = find_waiter(n, key);
            if (idx >= 0) drop_waiter(n, (unsigned)idx);
            n->timeouts++;
            ml_mutex_unlock(&n->lock);
            return false;
        }
        ml_sleep_ms(10);
    }
}

bool ml_neg_release(ml_neg_t *n, uintptr_t key) {
    uint64_t now = n->now_ms();
    bool was_holder = false;
    ml_mutex_lock(&n->lock);
    if (n->holder == key) {
        end_hold(n, now);
        n->releases++;
        was_holder = true;
    }
    int idx = find_waiter(n, key);
    if (idx >= 0) {
        drop_waiter(n, (unsigned)idx);
        n->cancelled++;
    }
    ml_mutex_unlock(&n->lock);
    return was_holder;
}

bool ml_neg_holds(ml_neg_t *n, uintptr_t key) {
    ml_mutex_lock(&n->lock);
    bool held = n->holder == key;
    ml_mutex_unlock(&n->lock);
    return held;
}

void ml_neg_status(ml_neg_t *n, ml_neg_status_t *out) {
    uint64_t now = n->now_ms();
    ml_mutex_lock(&n->lock);
    out->holder = n->holder;
    out->phase = n->holder_phase;
    out->held_ms = n->holder ? (uint32_t)(now - n->granted_ms) : 0;
    out->waiting = n->nq;
    out->grants = n->grants;
    out->timeouts = n->timeouts;
    out->lease_expired = n->lease_expired;
    out->stale_dropped = n->stale_dropped;
    out->refused_full = n->refused_full;
    out->max_wait_ms = n->max_wait_ms;
    out->max_hold_ms = n->max_hold_ms;
    ml_mutex_unlock(&n->lock);
}
