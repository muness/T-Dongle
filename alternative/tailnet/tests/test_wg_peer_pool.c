/* Pool core (wireguard_pool.c): the generic, lwIP-free slot pool shared by every
 * WireGuard device. Compiles only wireguard_pool.c; no stubs needed.
 *   cc -std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -Wall -Wextra \
 *      -I $wg tests/test_wg_peer_pool.c $wg/wireguard_pool.c -o build-host/test_wg_peer_pool */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wireguard_pool.h"

#define SLOT 96

static int live_allocs, total_allocs, fail_after = -1; /* fail_after: allocations left before failing; -1 = never */
static int nonzero_at_free, frees_seen;
static unsigned char poison[SLOT];

static void *hook_alloc(size_t n) {
    if (fail_after == 0) return NULL;
    if (fail_after > 0) fail_after--;
    unsigned char *p = malloc(n);
    assert(p);
    memset(p, 0xA5, n); /* prove acquire() zeroes, rather than relying on calloc */
    live_allocs++; total_allocs++;
    return p;
}
static void hook_free(void *p) {
    const unsigned char *b = p;
    for (size_t i = 0; i < SLOT; i++) if (b[i] != 0) nonzero_at_free++;
    frees_seen++; live_allocs--;
    free(p);
}
static void reset_hooks(void) { live_allocs = total_allocs = nonzero_at_free = frees_seen = 0; fail_after = -1; }

struct visit { int n; const void *owners[WG_POOL_MAX_SLOTS]; void *slots[WG_POOL_MAX_SLOTS]; int stop_after; };
static bool visit_cb(void *slot, const void *owner, void *ctx) {
    struct visit *v = ctx;
    v->slots[v->n] = slot; v->owners[v->n] = owner; v->n++;
    return !(v->stop_after && v->n >= v->stop_after);
}

int main(void) {
    int A = 0, B = 0, C = 0; /* distinct owner tags */
    wg_pool_t pool;
    (void)poison;

    /* --- configuration validation --- */
    assert(!wg_pool_init(&pool, 0, SLOT, NULL, NULL));
    assert(!wg_pool_init(&pool, WG_POOL_MAX_SLOTS + 1, SLOT, NULL, NULL));
    assert(!wg_pool_init(&pool, 4, 0, NULL, NULL));
    assert(!wg_pool_init(&pool, 4, SLOT, hook_alloc, NULL));   /* hooks must come as a pair */
    assert(wg_pool_acquire(&pool, &A) == NULL);                /* failed init leaves it unusable */
    assert(!wg_pool_init(NULL, 4, SLOT, NULL, NULL));

    /* --- capacity cap, zeroed slots, full refusal, tagging --- */
    reset_hooks();
    assert(wg_pool_init(&pool, 4, SLOT, hook_alloc, hook_free));
    assert(wg_pool_capacity(&pool) == 4 && wg_pool_used(&pool) == 0);
    assert(wg_pool_acquire(&pool, NULL) == NULL);              /* NULL owner refused, not counted */
    assert(wg_pool_get_stats(&pool).refused_full == 0 && wg_pool_get_stats(&pool).refused_nomem == 0);
    unsigned char *s[5];
    s[0] = wg_pool_acquire(&pool, &A);
    s[1] = wg_pool_acquire(&pool, &A);
    s[2] = wg_pool_acquire(&pool, &B);
    s[3] = wg_pool_acquire(&pool, &C);
    for (int i = 0; i < 4; i++) {
        assert(s[i]);
        for (size_t j = 0; j < SLOT; j++) assert(s[i][j] == 0);
        for (int k = 0; k < i; k++) assert(s[i] != s[k]);
    }
    assert(wg_pool_used(&pool) == 4 && live_allocs == 4);
    s[4] = wg_pool_acquire(&pool, &A);
    assert(s[4] == NULL && total_allocs == 4);                 /* refused before allocating */
    wg_pool_stats_t st = wg_pool_get_stats(&pool);
    assert(st.refused_full == 1 && st.refused_nomem == 0 && st.acquired == 4 && st.peak_used == 4 && st.used == 4 && st.capacity == 4);
    assert(wg_pool_owner_count(&pool, &A) == 2 && wg_pool_owner_count(&pool, &B) == 1 && wg_pool_owner_count(&pool, &C) == 1);
    assert(wg_pool_owner_of(&pool, s[0]) == &A && wg_pool_owner_of(&pool, s[2]) == &B);
    assert(wg_pool_contains(&pool, s[3]) && !wg_pool_contains(&pool, &st));
    assert(wg_pool_owner_of(&pool, NULL) == NULL && wg_pool_owner_count(&pool, NULL) == 0);

    /* --- each(): visits exactly the live slots, supports early stop --- */
    struct visit v = {0};
    wg_pool_each(&pool, visit_cb, &v);
    assert(v.n == 4);
    for (int i = 0; i < 4; i++) assert(wg_pool_owner_of(&pool, v.slots[i]) == v.owners[i]);
    struct visit v2 = { .stop_after = 2 };
    wg_pool_each(&pool, visit_cb, &v2);
    assert(v2.n == 2);
    wg_pool_each(&pool, NULL, NULL);                           /* NULL callback tolerated */

    /* --- not reconfigurable while slots are live --- */
    assert(!wg_pool_configure(&pool, 8, SLOT, NULL, NULL));
    assert(wg_pool_capacity(&pool) == 4);

    /* --- release: wipes before free, double release harmless, slot reuse --- */
    memset(s[1], 0x5C, SLOT);                                  /* pretend key material */
    nonzero_at_free = 0;
    assert(wg_pool_release(&pool, s[1]));
    assert(nonzero_at_free == 0 && frees_seen == 1);           /* hook saw all-zero bytes */
    assert(!wg_pool_release(&pool, s[1]));                     /* double release: no effect */
    assert(frees_seen == 1 && live_allocs == 3 && wg_pool_used(&pool) == 3);
    assert(!wg_pool_release(&pool, NULL));
    int not_a_slot; assert(!wg_pool_release(&pool, &not_a_slot));
    assert(wg_pool_owner_count(&pool, &A) == 1);
    unsigned char *again = wg_pool_acquire(&pool, &B);         /* freed capacity is reusable */
    assert(again && wg_pool_used(&pool) == 4);
    st = wg_pool_get_stats(&pool);
    assert(st.released == 1 && st.acquired == 5 && st.peak_used == 4);

    /* --- release_owner frees only that owner --- */
    memset(s[0], 0x77, SLOT); memset(s[2], 0x77, SLOT);
    nonzero_at_free = 0;
    assert(wg_pool_release_owner(&pool, &B) == 2);             /* s[2] and `again` */
    assert(nonzero_at_free == 0);
    assert(wg_pool_owner_count(&pool, &B) == 0 && wg_pool_owner_count(&pool, &A) == 1 && wg_pool_owner_count(&pool, &C) == 1);
    assert(wg_pool_used(&pool) == 2 && live_allocs == 2);
    assert(wg_pool_release_owner(&pool, &B) == 0);             /* idempotent */
    assert(wg_pool_release_owner(&pool, NULL) == 0);
    assert(wg_pool_contains(&pool, s[0]) && wg_pool_contains(&pool, s[3]));

    /* --- evictions are only counted --- */
    wg_pool_note_eviction(&pool, &A); wg_pool_note_eviction(&pool, &B);
    assert(wg_pool_get_stats(&pool).evictions == 2 && wg_pool_used(&pool) == 2);

    /* --- peak survives release --- */
    st = wg_pool_get_stats(&pool);
    assert(st.peak_used == 4 && st.used == 2);

    /* --- allocator failure is "nomem", distinct from "full" --- */
    fail_after = 0;
    assert(wg_pool_acquire(&pool, &A) == NULL);
    st = wg_pool_get_stats(&pool);
    assert(st.refused_nomem == 1 && st.refused_full == 1 && st.used == 2);
    fail_after = 1;                                            /* one more succeeds, then fails */
    unsigned char *ok = wg_pool_acquire(&pool, &A);
    assert(ok && wg_pool_acquire(&pool, &A) == NULL);          /* used==3, alloc fails */
    assert(wg_pool_get_stats(&pool).refused_nomem == 2 && wg_pool_used(&pool) == 3);
    fail_after = -1;

    /* --- release everything: no leak, nothing left unwiped --- */
    assert(wg_pool_release_owner(&pool, &A) == 2 && wg_pool_release_owner(&pool, &C) == 1);
    assert(wg_pool_used(&pool) == 0 && live_allocs == 0 && nonzero_at_free == 0);

    /* --- reconfigure when empty (counters kept), hooks swap to default malloc/free --- */
    assert(wg_pool_configure(&pool, 2, 24, NULL, NULL));
    assert(wg_pool_capacity(&pool) == 2);
    assert(wg_pool_get_stats(&pool).acquired == 6);
    void *d1 = wg_pool_acquire(&pool, &A), *d2 = wg_pool_acquire(&pool, &A);
    assert(d1 && d2 && wg_pool_acquire(&pool, &A) == NULL);
    assert(wg_pool_release_owner(&pool, &A) == 2);

    /* --- every capacity up to the maximum is honoured exactly --- */
    for (size_t cap = 1; cap <= WG_POOL_MAX_SLOTS; cap++) {
        reset_hooks();
        assert(wg_pool_init(&pool, cap, SLOT, hook_alloc, hook_free));
        for (size_t i = 0; i < cap; i++) assert(wg_pool_acquire(&pool, &A));
        assert(wg_pool_acquire(&pool, &B) == NULL && wg_pool_used(&pool) == cap);
        assert(wg_pool_get_stats(&pool).refused_full == 1 && wg_pool_get_stats(&pool).peak_used == cap);
        assert(wg_pool_release_owner(&pool, &A) == cap && live_allocs == 0);
    }

    /* --- NULL pool is tolerated everywhere --- */
    assert(wg_pool_acquire(NULL, &A) == NULL && !wg_pool_release(NULL, &A) && wg_pool_release_owner(NULL, &A) == 0);
    assert(wg_pool_used(NULL) == 0 && wg_pool_get_stats(NULL).capacity == 0);
    wg_pool_note_eviction(NULL, &A);

    /* --- secure_zero really clears --- */
    unsigned char buf[16]; memset(buf, 0xEE, sizeof(buf));
    wg_pool_secure_zero(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++) assert(buf[i] == 0);
    wg_pool_secure_zero(NULL, 4);

    puts("wg peer pool core: ok");
    return 0;
}
