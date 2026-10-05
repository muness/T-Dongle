/* The byte and heap bound on datagrams waiting for wg_mgr (ml_wg_rx_budget.h, ADR 0020), against an exact model, and under threads.
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -Wall -Wextra -pthread -I components/microlink/include \
 *      tests/test_wg_rx_budget.c -o build-host/test_wg_rx_budget
 *   cc ... -fsanitize=thread ... (the same file; TSan sees the producers and the consumer race on one counter) */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "ml_wg_rx_budget.h"

ml_wgrx_budget_t ml_wgrx_budget;

static uint32_t rs = 12345;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 17; rs ^= rs << 5; return rs; }

/* ---- the arithmetic ---- */
static void t_model(void) {
    ml_wgrx_budget_t b = {0};
    unsigned model = 0, admitted = 0, bytes_refused = 0, heap_refused = 0;
    unsigned held_len[256]; unsigned held = 0;
    const size_t big_heap = 1u << 20;
    for (unsigned i = 0; i < 400000; i++) {
        if (held && (rnd() % 100) < 48) {                                       /* a pop */
            unsigned k = rnd() % held;
            ml_wgrx_release_to(&b, held_len[k]);
            model -= held_len[k] + ML_WG_RX_OVERHEAD;
            held_len[k] = held_len[--held];
        } else if (held < 256) {                                                /* an offer */
            unsigned len = (rnd() & 3) ? 28 + rnd() % 1300 : 32;
            size_t heap = (rnd() % 10) ? big_heap : ML_WG_RX_FLOOR_FREE + len + ML_WG_RX_OVERHEAD - 1 + rnd() % 3;   /* straddles the heap floor */
            ml_wgrx_verdict_t v = ml_wgrx_admit(&b, len, heap);
            unsigned cost = len + ML_WG_RX_OVERHEAD;
            ml_wgrx_verdict_t want = heap < (size_t)ML_WG_RX_FLOOR_FREE + cost ? ML_WGRX_HEAP : (model + cost > ML_WG_RX_QUEUE_BYTES ? ML_WGRX_BYTES : ML_WGRX_OK);
            assert(v == want);
            if (v == ML_WGRX_OK) { model += cost; held_len[held++] = len; admitted++; }
            else if (v == ML_WGRX_BYTES) bytes_refused++; else heap_refused++;
        }
        assert(atomic_load(&b.bytes) == model && model <= ML_WG_RX_QUEUE_BYTES);
    }
    assert(atomic_load(&b.peak) <= ML_WG_RX_QUEUE_BYTES && atomic_load(&b.peak) > ML_WG_RX_QUEUE_BYTES - 1400);   /* the cap is reachable, never exceeded */
    assert(admitted && bytes_refused && heap_refused);
    while (held) { ml_wgrx_release_to(&b, held_len[--held]); }
    assert(atomic_load(&b.bytes) == 0);
    printf("  model: %u admitted, %u refused for bytes, %u for heap; peak %u of %u\n", admitted, bytes_refused, heap_refused, atomic_load(&b.peak), ML_WG_RX_QUEUE_BYTES);
}
/* ---- one floor (ADR 0022): the queue stops where the USB ring stops, with or without a join, and never asks the negotiation lock ---- */
static bool g_busy; static unsigned g_busy_asked;
static bool busy_fn(void) { g_busy_asked++; return g_busy; }
static void t_one_floor(void) {
    const size_t len = 1264, cost = len + ML_WG_RX_OVERHEAD;
    ml_wgrx_budget_t b = {0};
    assert(ML_WG_RX_FLOOR_FREE == ML_WG_RX_JOIN_FLOOR_FREE && ML_WG_RX_FLOOR_FREE == ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES);
    assert(ML_WG_RX_FLOOR_FREE == 16384 + 13500);
    for (int busy = 0; busy < 2; busy++) {
        g_busy = busy; g_busy_asked = 0;
        atomic_store(&b.bytes, 0);
        assert(ml_wgrx_admit_gated(&b, len, ML_WG_RX_FLOOR_FREE + cost - 1, busy_fn) == ML_WGRX_HEAP && atomic_load(&b.bytes) == 0);   /* nothing reserved */
        assert(ml_wgrx_admit_gated(&b, len, ML_WG_RX_FLOOR_FREE + cost, busy_fn) == ML_WGRX_OK && atomic_load(&b.bytes) == cost);
        assert(g_busy_asked == 0);                                  /* the hot path never takes the negotiation lock */
    }
    /* the old floor (recovery reserve only) no longer admits: that is what let the flood run 13 KB below the ring's floor */
    atomic_store(&b.bytes, 0);
    assert(ml_wgrx_admit(&b, len, (size_t)ML_ADM_RECOVERY_BYTES + cost) == ML_WGRX_HEAP);
    assert(ml_wgrx_admit(&b, 28, ML_WG_RX_FLOOR_FREE + 28 + ML_WG_RX_OVERHEAD) == ML_WGRX_OK);
    /* queued bytes are readable for admission (reclaimable) */
    assert(ml_wgrx_queued(&b) == 28 + ML_WG_RX_OVERHEAD);
    printf("  one floor: %d B with or without a join (was %d B outside a join)\n", ML_WG_RX_FLOOR_FREE, ML_ADM_RECOVERY_BYTES);
}
/* the sizes the design quotes */
static void t_quoted_capacity(void) {
    ml_wgrx_budget_t b = {0};
    unsigned big = 0;
    while (ml_wgrx_admit(&b, 1264, 1u << 20) == ML_WGRX_OK) big++;     /* a 1,200 byte iperf payload: 1,264 byte WireGuard datagram */
    assert(big == 9);                                                     /* 9 full-size datagrams (the old 8 slots held 8) */
    ml_wgrx_budget_t c = {0};
    unsigned small = 0;
    while (small < 1000 && ml_wgrx_admit(&c, 96, 1u << 20) == ML_WGRX_OK) small++;
    assert(small > 12);                                                   /* ML_WG_RX_QUEUE_DEPTH (12): bytes alone never bind for ACK-sized datagrams, the slot count does */
    printf("  capacity: %u full-size datagrams, or %u ACK-sized ones (the 12 slots bind first), in %u bytes\n", big, small, ML_WG_RX_QUEUE_BYTES);
}

/* ---- threads: producers offer, one consumer releases; the total never passes the cap and ends at zero ---- */
#define PRODUCERS 4
#define PER 200000
static ml_wgrx_budget_t tb;
static atomic_uint queue_len;                  /* a stand-in for the queue: lengths waiting, consumed in FIFO order */
static atomic_uint ring[1u << 16];             /* slot -> length + 1 once published, 0 when empty */
static atomic_uint ring_head, ring_tail;
static atomic_bool done;
static atomic_uint over_cap;
static void *producer(void *arg) {
    unsigned seed = (unsigned)(uintptr_t)arg * 2654435761u + 1;
    for (unsigned i = 0; i < PER; i++) {
        seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
        unsigned len = 28 + seed % 1300;
        if (ml_wgrx_admit(&tb, len, 1u << 20) == ML_WGRX_OK) {
            if (atomic_load(&tb.bytes) > ML_WG_RX_QUEUE_BYTES) atomic_fetch_add(&over_cap, 1);
            unsigned slot = atomic_fetch_add(&ring_head, 1);
            atomic_store_explicit(&ring[slot & 0xffff], len + 1, memory_order_release);
            atomic_fetch_add(&queue_len, 1);
        }
    }
    return NULL;
}
static void *consumer(void *arg) {
    (void)arg;
    for (;;) {
        if (atomic_load(&queue_len) == 0) { if (atomic_load(&done)) break; continue; }
        unsigned slot = atomic_fetch_add(&ring_tail, 1);
        unsigned len;
        while ((len = atomic_load_explicit(&ring[slot & 0xffff], memory_order_acquire)) == 0) {}
        atomic_store_explicit(&ring[slot & 0xffff], 0, memory_order_relaxed);
        len -= 1;
        atomic_fetch_sub(&queue_len, 1);
        ml_wgrx_release_to(&tb, len);
    }
    return NULL;
}
static void t_threads(void) {
    pthread_t p[PRODUCERS], c;
    pthread_create(&c, NULL, consumer, NULL);
    for (uintptr_t i = 0; i < PRODUCERS; i++) pthread_create(&p[i], NULL, producer, (void *)(i + 1));
    for (int i = 0; i < PRODUCERS; i++) pthread_join(p[i], NULL);
    atomic_store(&done, true);
    pthread_join(c, NULL);
    assert(atomic_load(&tb.bytes) == 0 && atomic_load(&over_cap) == 0 && atomic_load(&tb.peak) <= ML_WG_RX_QUEUE_BYTES);
    printf("  threads: %d producers x %d offers, peak %u of %u, ended at 0\n", PRODUCERS, PER, atomic_load(&tb.peak), ML_WG_RX_QUEUE_BYTES);
}

int main(void) {
    t_model();
    t_quoted_capacity();
    t_one_floor();
    t_threads();
    printf("wg rx budget ok\n");
    return 0;
}
