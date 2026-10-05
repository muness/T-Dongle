/* The global negotiation token: exclusion, ordering, bounded waiting, self-healing, and concurrent joins. */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ml_negotiation.h"

static uint64_t vnow;
static uint64_t vclock(void) { return vnow; }

static void basics(void) {
    ml_neg_t n; ml_neg_init(&n, vclock, 0, 0, 0); vnow = 1000;
    assert(ml_neg_request(&n, 1, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_GRANTED);
    assert(ml_neg_request(&n, 1, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_GRANTED);   /* idempotent */
    assert(ml_neg_holds(&n, 1) && !ml_neg_holds(&n, 2));
    assert(ml_neg_request(&n, 2, ML_NEG_PRIO_START, ML_NEG_PHASE_CONTROL) == ML_NEG_QUEUED);
    assert(!ml_neg_release(&n, 99));                       /* not the holder, not queued: harmless */
    assert(ml_neg_release(&n, 1));
    assert(!ml_neg_release(&n, 1));                        /* error paths may release twice */
    assert(ml_neg_request(&n, 2, ML_NEG_PRIO_START, ML_NEG_PHASE_CONTROL) == ML_NEG_GRANTED);
    ml_neg_status_t s; ml_neg_status(&n, &s);
    assert(s.holder == 2 && s.phase == ML_NEG_PHASE_CONTROL && s.waiting == 0 && s.grants == 2);
    ml_neg_release(&n, 2);
    ml_mutex_destroy(&n.lock);
    puts("  basics: exclusive, idempotent for the holder, release is safe to repeat");
}

static void ordering(void) {
    ml_neg_t n; ml_neg_init(&n, vclock, 0, 0, 0); vnow = 1000;
    assert(ml_neg_request(&n, 1, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_GRANTED);
    /* Queue (in this order): start(2), start(3), relay(4), rejoin(5). Poll them as the real tasks would. */
    ml_neg_request(&n, 2, ML_NEG_PRIO_START, ML_NEG_PHASE_START); vnow += 5;
    ml_neg_request(&n, 3, ML_NEG_PRIO_START, ML_NEG_PHASE_START); vnow += 5;
    ml_neg_request(&n, 4, ML_NEG_PRIO_RELAY, ML_NEG_PHASE_DERP); vnow += 5;
    ml_neg_request(&n, 5, ML_NEG_PRIO_REJOIN, ML_NEG_PHASE_CONTROL); vnow += 5;
    uintptr_t expect[] = {4, 5, 2, 3};     /* priority first, FIFO within a class */
    uintptr_t holder = 1;
    for (unsigned i = 0; i < 4; i++) {
        ml_neg_release(&n, holder);
        for (unsigned p = 2; p <= 5; p++) {   /* everyone polls; only the best is granted */
            ml_neg_result_t r = ml_neg_request(&n, p, ML_NEG_PRIO_START, ML_NEG_PHASE_START);
            if (r == ML_NEG_GRANTED) { assert(p == expect[i]); holder = p; }
            vnow++;
        }
        assert(ml_neg_holds(&n, expect[i]));
    }
    ml_neg_release(&n, holder);
    ml_mutex_destroy(&n.lock);
    puts("  ordering: highest priority first, FIFO within a priority");
}

static void aging(void) {
    /* A steady stream of relay reconnects must not starve a first join: it is promoted one class per period. */
    ml_neg_t n; ml_neg_init(&n, vclock, 0, 0, 20000); vnow = 1000;
    ml_neg_request(&n, 1, ML_NEG_PRIO_RELAY, ML_NEG_PHASE_DERP);                 /* holder */
    ml_neg_request(&n, 10, ML_NEG_PRIO_START, ML_NEG_PHASE_START);               /* the old join */
    uintptr_t holder = 1; bool join_ran = false;
    for (unsigned round = 0; round < 8 && !join_ran; round++) {
        for (unsigned step = 0; step < 100; step++) {          /* the holder works for 10 s; the waiters poll every 100 ms */
            vnow += 100;
            ml_neg_request(&n, 10, ML_NEG_PRIO_START, ML_NEG_PHASE_START);
            if (round) ml_neg_request(&n, 20 + round - 1, ML_NEG_PRIO_RELAY, ML_NEG_PHASE_DERP);
        }
        ml_neg_release(&n, holder);
        ml_neg_request(&n, 20 + round, ML_NEG_PRIO_RELAY, ML_NEG_PHASE_DERP);   /* a fresh relay waiter each time */
        for (;;) {
            ml_neg_result_t a = ml_neg_request(&n, 10, ML_NEG_PRIO_START, ML_NEG_PHASE_START);
            ml_neg_result_t b = ml_neg_request(&n, 20 + round, ML_NEG_PRIO_RELAY, ML_NEG_PHASE_DERP);
            if (a == ML_NEG_GRANTED) { join_ran = true; holder = 10; break; }
            if (b == ML_NEG_GRANTED) { holder = 20 + round; break; }
            assert(0);
        }
    }
    assert(join_ran);       /* granted after waiting two aging periods (2 classes up) */
    ml_neg_release(&n, holder);
    ml_mutex_destroy(&n.lock);
    puts("  aging: a first join waiting behind relay reconnects is promoted and runs");
}

static void self_healing(void) {
    ml_neg_t n; ml_neg_init(&n, vclock, 60000, 2000, 20000); vnow = 1000;
    /* A holder that never releases loses the token after the lease; its late release is a no-op. */
    assert(ml_neg_request(&n, 1, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_GRANTED);
    assert(ml_neg_request(&n, 2, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_QUEUED);
    vnow += 59000; assert(ml_neg_request(&n, 2, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_QUEUED);
    vnow += 1100;  assert(ml_neg_request(&n, 2, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_GRANTED);
    assert(!ml_neg_release(&n, 1));                     /* the old holder wakes up and releases: nothing happens */
    assert(ml_neg_holds(&n, 2));
    ml_neg_status_t s; ml_neg_status(&n, &s); assert(s.lease_expired == 1);
    /* A waiter that stops polling (its task died) cannot block the ones behind it. */
    assert(ml_neg_request(&n, 3, ML_NEG_PRIO_RELAY, ML_NEG_PHASE_DERP) == ML_NEG_QUEUED);   /* ahead by priority */
    vnow += 10; assert(ml_neg_request(&n, 4, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_QUEUED);
    ml_neg_release(&n, 2);
    vnow += 2500;                                       /* 3 never polls again */
    assert(ml_neg_request(&n, 4, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_GRANTED);
    ml_neg_status(&n, &s); assert(s.stale_dropped == 1);
    ml_neg_release(&n, 4);
    ml_mutex_destroy(&n.lock);
    puts("  self-healing: lease expiry frees a wedged holder; a dead waiter is dropped");
}

static void bounded(void) {
    /* acquire() times out, leaves no trace, and the failure is retryable. Real clock: it sleeps. */
    ml_neg_t n; ml_neg_init(&n, ml_port_mono_ms, 0, 0, 0);
    assert(ml_neg_request(&n, 1, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_GRANTED);
    uint64_t t0 = ml_port_mono_ms();
    assert(!ml_neg_acquire(&n, 2, ML_NEG_PRIO_START, ML_NEG_PHASE_START, 150));
    uint64_t waited = ml_port_mono_ms() - t0;
    assert(waited >= 150 && waited < 400);
    ml_neg_status_t s; ml_neg_status(&n, &s);
    assert(s.waiting == 0 && s.timeouts == 1);
    ml_neg_release(&n, 1);
    assert(ml_neg_acquire(&n, 2, ML_NEG_PRIO_START, ML_NEG_PHASE_START, 150));       /* retry succeeds at once */
    /* A full queue refuses instead of growing. */
    for (uintptr_t k = 10; k < 10 + ML_NEG_MAX_WAITERS; k++) assert(ml_neg_request(&n, k, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_QUEUED);
    assert(ml_neg_request(&n, 99, ML_NEG_PRIO_START, ML_NEG_PHASE_START) == ML_NEG_FULL);
    assert(!ml_neg_acquire(&n, 98, ML_NEG_PRIO_START, ML_NEG_PHASE_START, 50));
    ml_neg_status(&n, &s); assert(s.refused_full >= 2 && s.waiting == ML_NEG_MAX_WAITERS);
    ml_mutex_destroy(&n.lock);
    puts("  bounded: acquire times out cleanly and can be retried; a full queue refuses");
}

/* ---- three joins at once, real threads ---- */
static ml_neg_t shared;
static atomic_int inside, max_inside;
static atomic_uint order_ticket, completed;
static unsigned order[3 * 40];
#define JOINS 40
static void *joiner(void *arg) {
    uintptr_t key = (uintptr_t)arg;
    unsigned seed = (unsigned)key * 7919u;
    for (unsigned i = 0; i < JOINS; i++) {
        /* Alternate the two calling styles: the blocking one (manager task) and polling (derp/coord tasks). */
        bool ok;
        if (key == 3) {
            ok = false;
            uint64_t end = ml_port_mono_ms() + 20000;
            while (ml_port_mono_ms() < end && !(ok = ml_neg_request(&shared, key, ML_NEG_PRIO_RELAY, ML_NEG_PHASE_DERP) == ML_NEG_GRANTED))
                ml_sleep_ms(2);
        } else {
            ok = ml_neg_acquire(&shared, key, ML_NEG_PRIO_START, ML_NEG_PHASE_START, 20000);
        }
        assert(ok);
        int now = atomic_fetch_add(&inside, 1) + 1;
        int mx = atomic_load(&max_inside);
        while (now > mx && !atomic_compare_exchange_weak(&max_inside, &mx, now)) {}
        assert(now == 1);                                     /* two joins in a negotiation at once: the bug */
        order[atomic_fetch_add(&order_ticket, 1)] = (unsigned)key;
        seed = seed * 1103515245u + 12345u;
        ml_sleep_ms(seed % 4);
        atomic_fetch_sub(&inside, 1);
        assert(ml_neg_release(&shared, key));
        atomic_fetch_add(&completed, 1);
        seed = seed * 1103515245u + 12345u;
        ml_sleep_ms(seed % 3);
    }
    return NULL;
}
static void concurrent(void) {
    ml_neg_init(&shared, ml_port_mono_ms, 0, 0, 0);
    pthread_t t[3];
    for (uintptr_t k = 1; k <= 3; k++) pthread_create(&t[k - 1], NULL, joiner, (void *)k);
    for (int i = 0; i < 3; i++) pthread_join(t[i], NULL);
    assert(atomic_load(&completed) == 3 * JOINS && atomic_load(&max_inside) == 1);
    unsigned per[4] = {0};
    for (unsigned i = 0; i < 3 * JOINS; i++) per[order[i]]++;
    assert(per[1] == JOINS && per[2] == JOINS && per[3] == JOINS);
    ml_neg_status_t s; ml_neg_status(&shared, &s);
    assert(s.holder == 0 && s.waiting == 0 && s.grants == 3 * JOINS && s.lease_expired == 0);
    printf("  concurrent: 3 joiners x %d negotiations, never more than %d inside, max wait %u ms, max hold %u ms\n",
           JOINS, atomic_load(&max_inside), s.max_wait_ms, s.max_hold_ms);
    ml_mutex_destroy(&shared.lock);
}

int main(void) {
    puts("negotiation token");
    basics();
    ordering();
    aging();
    self_healing();
    bounded();
    concurrent();
    puts("negotiation token: exclusive, ordered, bounded, self-healing");
    return 0;
}
