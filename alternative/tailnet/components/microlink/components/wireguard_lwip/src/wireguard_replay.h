#ifndef WIREGUARD_REPLAY_H
#define WIREGUARD_REPLAY_H
/* WireGuard anti-replay window: a sliding bitmap kept as a ring of 32-bit blocks (RFC 6479; the algorithm of the Linux
 * kernel's drivers/net/wireguard/noise.c counter_validate() and of wireguard-go's replay.Filter, adapted to 32-bit blocks).
 *
 * Why not the RFC 2401 shift register this replaces: a 32-bit register accepts a packet only if it is within 32 counters of
 * the highest one seen. Anything that reorders datagrams by more than that (a path switch between DERP and a direct
 * endpoint, Wi-Fi retries, a multi-queue peer) is silently dropped as "too old". The ring costs the same few instructions
 * per packet and a larger window costs memory, not time: an advance clears at most the blocks it passes over.
 *
 * Semantics (identical to the kernel's, and checked against an exact reference model in tests/test_wg_replay.c):
 *   - counters >= REJECT_AFTER_MESSAGES are refused outright (spec section 5.4.6: the session is finished);
 *   - a counter more than WIREGUARD_REPLAY_WINDOW_SIZE below the highest accepted counter is TOO_OLD;
 *   - a counter inside the window that was accepted before is a DUPLICATE; every counter is accepted at most once;
 *   - a counter above the highest slides the window forward, forgetting what falls out of it.
 * Nothing is recorded unless the packet authenticated: call this only after the AEAD tag verified (the caller does).
 *
 * Memory: WIREGUARD_REPLAY_RING_BITS / 8 bytes per keypair, three keypairs per peer slot (current, previous, next), charged
 * to the global peer-slot pool and the admission budget (ml_admission.h reads sizeof(struct wireguard_peer)).
 * Not thread-safe: one writer, under the lwIP core lock (rx complete), exactly like the code it replaces. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifndef WIREGUARD_REPLAY_RING_BITS
#define WIREGUARD_REPLAY_RING_BITS 512   /* 64 B per keypair; window 480. See docs/adr/0019-inbound-loss.md for the sizing. */
#endif
#define WIREGUARD_REPLAY_BLOCK_BITS 32
#define WIREGUARD_REPLAY_BLOCK_LOG 5
#define WIREGUARD_REPLAY_BLOCKS (WIREGUARD_REPLAY_RING_BITS / WIREGUARD_REPLAY_BLOCK_BITS)
/* The newest block may be only partly the window, so one block of the ring is redundant. */
#define WIREGUARD_REPLAY_WINDOW_SIZE (WIREGUARD_REPLAY_RING_BITS - WIREGUARD_REPLAY_BLOCK_BITS)
#define WIREGUARD_REPLAY_LIMIT (0xFFFFFFFFFFFFFFFFULL - (1ULL << 13))   /* == REJECT_AFTER_MESSAGES (wireguard.h asserts it) */

_Static_assert(WIREGUARD_REPLAY_RING_BITS >= 64 && (WIREGUARD_REPLAY_RING_BITS & (WIREGUARD_REPLAY_RING_BITS - 1)) == 0,
               "the replay ring is a power of two blocks, at least two");
_Static_assert(WIREGUARD_REPLAY_RING_BITS <= 8192, "counter + window must not wrap below the reject limit (2^13 of slack)");

typedef enum {
    WG_REPLAY_OK = 0,
    WG_REPLAY_DUPLICATE,   /* inside the window, already accepted */
    WG_REPLAY_TOO_OLD,     /* below the window */
    WG_REPLAY_LIMIT,       /* counter >= REJECT_AFTER_MESSAGES */
} wg_replay_verdict_t;

struct wireguard_replay {
    uint64_t counter;      /* highest counter accepted (0 before the first packet, which is also a valid counter) */
    uint32_t ring[WIREGUARD_REPLAY_BLOCKS];
};

static inline void wireguard_replay_reset(struct wireguard_replay *r) {
    r->counter = 0;
    memset(r->ring, 0, sizeof(r->ring));
}

/* Test and, if acceptable, record `their` in one step. */
static inline wg_replay_verdict_t wireguard_replay_check(struct wireguard_replay *r, uint64_t their) {
    if (their >= WIREGUARD_REPLAY_LIMIT) return WG_REPLAY_LIMIT;
    uint64_t block = their >> WIREGUARD_REPLAY_BLOCK_LOG;
    if (their > r->counter) {
        /* Forward: clear every block the window slides over (at most the whole ring), then take the new top. Only blocks
         * strictly after the current top need clearing; the current one keeps its older bits, which stay in the window. */
        uint64_t current = r->counter >> WIREGUARD_REPLAY_BLOCK_LOG;
        uint64_t advance = block - current;
        if (advance > WIREGUARD_REPLAY_BLOCKS) advance = WIREGUARD_REPLAY_BLOCKS;
        for (uint64_t i = 1; i <= advance; i++) r->ring[(current + i) & (WIREGUARD_REPLAY_BLOCKS - 1)] = 0;
        r->counter = their;
    } else if (their + WIREGUARD_REPLAY_WINDOW_SIZE < r->counter) {
        return WG_REPLAY_TOO_OLD;   /* cannot wrap: their < LIMIT and the window is below 2^13 */
    }
    uint32_t *word = &r->ring[block & (WIREGUARD_REPLAY_BLOCKS - 1)];
    uint32_t bit = (uint32_t)1 << (their & (WIREGUARD_REPLAY_BLOCK_BITS - 1));
    if (*word & bit) return WG_REPLAY_DUPLICATE;
    *word |= bit;
    return WG_REPLAY_OK;
}

#endif /* WIREGUARD_REPLAY_H */
