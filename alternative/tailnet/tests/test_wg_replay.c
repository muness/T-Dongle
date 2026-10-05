/* WireGuard anti-replay window (wireguard_replay.h): unit, adversarial, exhaustive and differential tests against an exact
 * reference model, plus the reproduction that motivated the change: the arrival patterns the 32-bit RFC 2401 register this
 * replaces would have thrown away.
 *
 *   cc -std=c11 -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined -Wall -Wextra \
 *      -I components/microlink/components/wireguard_lwip/src tests/test_wg_replay.c -o build-host/test_wg_replay
 *   (also with -DWIREGUARD_REPLAY_RING_BITS=64 / 128 / 2048 / 8192: every property below is stated for the compiled size)
 *
 * The reference model is the specification, not a second implementation of the ring: a counter is accepted iff it is below
 * the reject limit, not more than WINDOW below the highest accepted counter, and not accepted before. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wireguard_replay.h"

#define W ((uint64_t)WIREGUARD_REPLAY_WINDOW_SIZE)
#define LIMIT WIREGUARD_REPLAY_LIMIT

/* ---- the model: an exact set of accepted counters and the highest one ---- */
typedef struct { uint64_t *seen; size_t n, cap; uint64_t max; } model_t;
static void model_init(model_t *m) { m->seen = NULL; m->n = m->cap = 0; m->max = 0; }
static void model_free(model_t *m) { free(m->seen); }
static bool model_has(const model_t *m, uint64_t v) {
    for (size_t i = m->n; i-- > 0;) if (m->seen[i] == v) return true;   /* recent first: the interesting ones are near the end */
    return false;
}
static wg_replay_verdict_t model_check(model_t *m, uint64_t v) {
    if (v >= LIMIT) return WG_REPLAY_LIMIT;
    if (v < m->max && m->max - v > W) return WG_REPLAY_TOO_OLD;   /* v + W < max, written without overflow */
    if (model_has(m, v)) return WG_REPLAY_DUPLICATE;
    if (m->n == m->cap) { m->cap = m->cap ? m->cap * 2 : 64; m->seen = realloc(m->seen, m->cap * sizeof(*m->seen)); assert(m->seen); }
    m->seen[m->n++] = v;
    if (v > m->max) m->max = v;
    return WG_REPLAY_OK;
}

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17; return rng_state; }

static void same(struct wireguard_replay *r, model_t *m, uint64_t v) {
    wg_replay_verdict_t a = wireguard_replay_check(r, v), b = model_check(m, v);
    if (a != b) { fprintf(stderr, "MISMATCH counter=%llu ring=%d impl=%d model=%d (max=%llu)\n", (unsigned long long)v, WIREGUARD_REPLAY_RING_BITS, a, b, (unsigned long long)m->max); abort(); }
}

/* ---- the legacy register, verbatim semantics of the code this replaces, to show what it lost ---- */
typedef struct { uint32_t bitmap; uint64_t counter; } legacy_t;
static bool legacy_check(legacy_t *k, uint64_t seq) {
    bool result = false; seq++;
    if (seq != 0) {
        if (seq > k->counter) {
            uint32_t diff = (uint32_t)(seq - k->counter);
            if (diff < 32) { k->bitmap <<= diff; k->bitmap |= 1; } else k->bitmap = 1;
            k->counter = seq; result = true;
        } else {
            uint32_t diff = (uint32_t)(k->counter - seq);
            if (diff < 32) { if (!(k->bitmap & ((uint32_t)1 << diff))) { k->bitmap |= ((uint32_t)1 << diff); result = true; } }
        }
    }
    return result;
}

static void test_basics(void) {
    struct wireguard_replay r; wireguard_replay_reset(&r);
    assert(wireguard_replay_check(&r, 0) == WG_REPLAY_OK);          /* counters start at 0 and 0 is a valid one */
    assert(wireguard_replay_check(&r, 0) == WG_REPLAY_DUPLICATE);
    assert(wireguard_replay_check(&r, 1) == WG_REPLAY_OK);
    assert(wireguard_replay_check(&r, 1) == WG_REPLAY_DUPLICATE);
    assert(wireguard_replay_check(&r, 0) == WG_REPLAY_DUPLICATE);
    /* a gap, then the gap filled out of order, each once */
    assert(wireguard_replay_check(&r, 10) == WG_REPLAY_OK);
    for (int i = 2; i < 10; i++) assert(wireguard_replay_check(&r, (uint64_t)i) == WG_REPLAY_OK);
    for (int i = 0; i <= 10; i++) assert(wireguard_replay_check(&r, (uint64_t)i) == WG_REPLAY_DUPLICATE);
    /* a session that starts at a high counter (first packet lost) */
    wireguard_replay_reset(&r);
    assert(wireguard_replay_check(&r, 12345) == WG_REPLAY_OK && wireguard_replay_check(&r, 12345) == WG_REPLAY_DUPLICATE);
    assert(wireguard_replay_check(&r, 12344) == WG_REPLAY_OK);       /* unseen and inside the window */
    assert(sizeof(struct wireguard_replay) == 8 + WIREGUARD_REPLAY_RING_BITS / 8);
    printf("replay basics ok (ring %d bits, window %d, %zu B per keypair)\n", WIREGUARD_REPLAY_RING_BITS, WIREGUARD_REPLAY_WINDOW_SIZE, sizeof(struct wireguard_replay));
}

static void test_window_edges(void) {
    /* The oldest acceptable counter is exactly W below the highest; one further is refused; the edge slides with the top. */
    for (uint64_t top = W + 1; top < W + 3 * WIREGUARD_REPLAY_RING_BITS; top++) {
        struct wireguard_replay r; wireguard_replay_reset(&r);
        assert(wireguard_replay_check(&r, top) == WG_REPLAY_OK);
        assert(wireguard_replay_check(&r, top - W - 1) == WG_REPLAY_TOO_OLD);
        assert(wireguard_replay_check(&r, top - W) == WG_REPLAY_OK);
        assert(wireguard_replay_check(&r, top - W) == WG_REPLAY_DUPLICATE);
        assert(wireguard_replay_check(&r, top - W + 1) == WG_REPLAY_OK);
        /* advance by one: what was the edge is now too old, and an accepted one stays a duplicate */
        assert(wireguard_replay_check(&r, top + 1) == WG_REPLAY_OK);
        assert(wireguard_replay_check(&r, top - W) == WG_REPLAY_TOO_OLD);
        assert(wireguard_replay_check(&r, top - W + 1) == WG_REPLAY_DUPLICATE);
        assert(wireguard_replay_check(&r, top - W + 2) == WG_REPLAY_OK);
    }
    /* Jumps of exactly one block, the window, the ring and beyond forget everything older, and nothing old comes back. */
    const uint64_t jumps[] = {1, 31, 32, 33, W - 1, W, W + 1, (uint64_t)WIREGUARD_REPLAY_RING_BITS - 1, WIREGUARD_REPLAY_RING_BITS,
                              WIREGUARD_REPLAY_RING_BITS + 1, 2ull * WIREGUARD_REPLAY_RING_BITS, 1ull << 20, 1ull << 40, 1ull << 62};
    for (size_t j = 0; j < sizeof(jumps) / sizeof(jumps[0]); j++) {
        struct wireguard_replay r; wireguard_replay_reset(&r); model_t m; model_init(&m);
        uint64_t base = 5000;
        for (uint64_t i = 0; i < 40; i++) same(&r, &m, base + i * 2);               /* every other counter */
        for (uint64_t i = 0; i < 40; i++) same(&r, &m, base + i * 2);               /* all duplicates */
        same(&r, &m, base + 78 + jumps[j]);
        for (uint64_t i = 0; i < 100; i++) same(&r, &m, base + 78 + jumps[j] - i);  /* the neighbourhood, top down */
        for (uint64_t i = 0; i < 80; i++) same(&r, &m, base + i);                   /* the old region: must follow the model */
        model_free(&m);
    }
}

static void test_limits(void) {
    /* Counters near 2^64. LIMIT is the first refused counter; LIMIT - 1 is the last the session may use. */
    struct wireguard_replay r; wireguard_replay_reset(&r);
    assert(wireguard_replay_check(&r, UINT64_MAX) == WG_REPLAY_LIMIT);
    assert(wireguard_replay_check(&r, UINT64_MAX - 1) == WG_REPLAY_LIMIT);
    assert(wireguard_replay_check(&r, LIMIT) == WG_REPLAY_LIMIT);
    assert(wireguard_replay_check(&r, LIMIT + 1) == WG_REPLAY_LIMIT);
    assert(r.counter == 0);                                                /* a refused counter changes nothing */
    for (int i = 0; i < WIREGUARD_REPLAY_BLOCKS; i++) assert(r.ring[i] == 0);
    assert(wireguard_replay_check(&r, LIMIT - 1) == WG_REPLAY_OK);
    assert(wireguard_replay_check(&r, LIMIT - 1) == WG_REPLAY_DUPLICATE);
    assert(wireguard_replay_check(&r, LIMIT) == WG_REPLAY_LIMIT);
    assert(wireguard_replay_check(&r, LIMIT - 1 - W) == WG_REPLAY_OK);     /* the window edge at the top of the number space: no wrap */
    assert(wireguard_replay_check(&r, LIMIT - 2 - W) == WG_REPLAY_TOO_OLD);
    assert(wireguard_replay_check(&r, 0) == WG_REPLAY_TOO_OLD);            /* a tiny counter must not wrap into the window */
    assert(wireguard_replay_check(&r, 1) == WG_REPLAY_TOO_OLD);
    /* The model agrees on a walk up to the limit in odd strides (stride 3 hits every block offset). */
    wireguard_replay_reset(&r); model_t m; model_init(&m);
    for (uint64_t v = LIMIT - 400; v < LIMIT + 5; v += 3) same(&r, &m, v);
    for (uint64_t v = LIMIT - 400; v < LIMIT + 5; v++) same(&r, &m, v);
    model_free(&m);
    /* and the compile-time relationship the header relies on */
    assert(LIMIT + W < UINT64_MAX && LIMIT == 0xFFFFFFFFFFFFFFFFull - (1ull << 13));
}

static void test_adversarial(void) {
    /* An attacker who can replay any captured authentic datagram, in any order, any number of times, must never get a
     * counter accepted twice, and must not be able to make the filter forget (a replayed counter is a no-op). */
    struct wireguard_replay r; wireguard_replay_reset(&r);
    uint64_t accepted[4096]; size_t na = 0;
    for (uint64_t c = 0; c < 3000; c++) {
        if (wireguard_replay_check(&r, c * 3) == WG_REPLAY_OK) accepted[na++] = c * 3;   /* legitimate stream, gaps of 2 */
        for (int k = 0; k < 4; k++) {                                                   /* the attacker replays random captured ones */
            uint64_t v = accepted[rnd() % na];
            wg_replay_verdict_t verdict = wireguard_replay_check(&r, v);
            assert(verdict == WG_REPLAY_DUPLICATE || verdict == WG_REPLAY_TOO_OLD);
        }
    }
    assert(na == 3000);
    /* replay of the very first and last packets after a long idle jump */
    assert(wireguard_replay_check(&r, 3 * 3000 + (1ull << 33)) == WG_REPLAY_OK);
    for (size_t i = 0; i < na; i++) assert(wireguard_replay_check(&r, accepted[i]) == WG_REPLAY_TOO_OLD);
    /* Fill the whole window with every other counter, then the odd ones in reverse: each exactly once. */
    wireguard_replay_reset(&r);
    uint64_t top = 100000;
    assert(wireguard_replay_check(&r, top) == WG_REPLAY_OK);
    for (uint64_t d = 2; d <= W; d += 2) assert(wireguard_replay_check(&r, top - d) == WG_REPLAY_OK);
    for (uint64_t d = 1; d <= W; d += 2) assert(wireguard_replay_check(&r, top - d) == WG_REPLAY_OK);
    for (uint64_t d = 0; d <= W; d++) assert(wireguard_replay_check(&r, top - d) == WG_REPLAY_DUPLICATE);
    assert(wireguard_replay_check(&r, top - W - 1) == WG_REPLAY_TOO_OLD);
    printf("replay adversarial ok\n");
}

/* Every sequence of up to LEN counters drawn from [0, SPAN): exhaustive against the model. Meaningful for any ring size: the
 * span straddles the window of the small builds; for big rings the random test carries the weight. */
static void exhaust(unsigned span, unsigned len, uint64_t offset) {
    unsigned seq[8] = {0};
    uint64_t total = 1; for (unsigned i = 0; i < len; i++) total *= span;
    for (uint64_t n = 0; n < total; n++) {
        uint64_t x = n; for (unsigned i = 0; i < len; i++) { seq[i] = (unsigned)(x % span); x /= span; }
        struct wireguard_replay r; wireguard_replay_reset(&r); model_t m; model_init(&m);
        for (unsigned i = 0; i < len; i++) same(&r, &m, offset + seq[i]);
        model_free(&m);
    }
}

static uint64_t draw(uint64_t front, int mode) {
    switch (mode) {
    case 0: return front + (rnd() % 8);                                   /* in order with jitter */
    case 1: return front > W + 8 ? front - (rnd() % (W + 8)) : front;     /* reordered around the window edge */
    case 2: return front + (rnd() % (3ull * WIREGUARD_REPLAY_RING_BITS)); /* jumps of a few rings */
    case 3: return rnd() % 64;                                            /* replays from the bottom */
    case 4: return front - (front ? rnd() % (front < 40 ? front + 1 : 40) : 0); /* recent duplicates */
    case 5: return LIMIT - 1 - (rnd() % (2 * WIREGUARD_REPLAY_RING_BITS)); /* top of the number space */
    default: return rnd();                                                /* anything, mostly >= LIMIT */
    }
}

static void test_differential(unsigned iterations) {
    for (unsigned it = 0; it < iterations; it++) {
        struct wireguard_replay r; wireguard_replay_reset(&r); model_t m; model_init(&m);
        uint64_t front = (it & 3) == 0 ? 0 : (it & 3) == 1 ? rnd() % 100000 : (it & 3) == 2 ? (1ull << 32) - 50 + (rnd() % 100) : LIMIT - 5000;
        unsigned len = 200 + (unsigned)(rnd() % 1800);
        for (unsigned i = 0; i < len; i++) {
            int mode = (int)(rnd() % 100);
            mode = mode < 55 ? 0 : mode < 70 ? 1 : mode < 75 ? 2 : mode < 85 ? 3 : mode < 95 ? 4 : mode < 98 ? 5 : 6;
            uint64_t v = draw(front, mode);
            if ((it & 3) == 3 && mode < 5) { v = front + (rnd() % 16); }   /* the near-limit runs advance towards the limit */
            same(&r, &m, v);
            if (m.max > front && m.max < LIMIT) front = m.max;
            else if ((it & 3) == 3 && front + 4 < LIMIT) front += 3;
        }
        model_free(&m);
    }
    printf("replay differential ok (%u sequences against the exact model)\n", iterations);
}

/* The arrival patterns that motivated this: what the 32-bit register lost and the ring keeps. */
static void test_reorder_reproduction(void) {
    /* A peer sends 20000 datagrams in order; the network (a path switch DERP <-> direct, retries, a multi-queue sender) delivers
     * each up to `depth` late. Shuffle within blocks of `depth`: the worst possible lateness is depth - 1. */
    static const unsigned depths[] = {2, 8, 32, 33, 64, 200, 400};
    for (size_t d = 0; d < sizeof(depths) / sizeof(depths[0]); d++) {
        unsigned depth = depths[d], total = 20000;
        uint64_t *order = malloc(total * sizeof(*order)); assert(order);
        for (unsigned i = 0; i < total; i++) order[i] = i;
        for (unsigned base = 0; base + depth <= total; base += depth)
            for (unsigned i = depth; i-- > 1;) { unsigned j = (unsigned)(rnd() % (i + 1)); uint64_t t = order[base + i]; order[base + i] = order[base + j]; order[base + j] = t; }
        struct wireguard_replay r; wireguard_replay_reset(&r); legacy_t k = {0, 0};
        unsigned ring_ok = 0, legacy_ok = 0;
        for (unsigned i = 0; i < total; i++) { ring_ok += wireguard_replay_check(&r, order[i]) == WG_REPLAY_OK; legacy_ok += legacy_check(&k, order[i]); }
        printf("  reorder depth %3u: %u of %u accepted by the %d-bit ring, %u by the 32-bit register (%.1f %% lost)\n",
               depth, ring_ok, total, WIREGUARD_REPLAY_RING_BITS, legacy_ok, 100.0 * (total - legacy_ok) / total);
        if (depth <= W) assert(ring_ok == total);                 /* no loss while the lateness fits the window */
        if (depth > 33) assert(legacy_ok < total);                /* the old register could not */
        free(order);
    }
    /* One burst out of order by more than the window: exactly the packets beyond it are refused, as specified. */
    struct wireguard_replay r; wireguard_replay_reset(&r);
    assert(wireguard_replay_check(&r, 10000) == WG_REPLAY_OK);
    unsigned refused = 0;
    for (uint64_t c = 9000; c < 10000; c++) refused += wireguard_replay_check(&r, c) == WG_REPLAY_TOO_OLD;
    assert(refused == (W < 1000 ? 1000 - W : 0));
}

int main(int argc, char **argv) {
    unsigned iterations = argc > 1 ? (unsigned)atoi(argv[1]) : 3000;
    test_basics();
    test_window_edges();
    test_limits();
    test_adversarial();
    /* exhaustive: all 4-sequences over a span that wraps the small rings; a 5-sequence over a narrower span */
    exhaust(48, 4, 0);
    exhaust(40, 4, 1000);
    exhaust(20, 5, 0xFFFFFFFFull - 8);        /* across the 32-bit counter boundary the legacy code truncated at */
    exhaust(24, 4, LIMIT - 20);               /* against the reject limit */
    printf("replay exhaustive ok\n");
    test_differential(iterations);
    test_reorder_reproduction();
    return 0;
}
