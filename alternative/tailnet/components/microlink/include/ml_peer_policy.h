/**
 * @file ml_peer_policy.h
 * @brief Which resident peer gives up its WireGuard slot when the global pool is full (ADR 0013, P2).
 *
 * The pool of WireGuard peer slots is shared by every membership. When a membership needs a slot and none is free,
 * one resident peer of ANY membership is evicted; the eviction is not forced on recent traffic (ADR 0012):
 *
 *   - a peer used within `idle_ms` is never evicted (authenticated activation: 10 s; an activation on an
 *     unauthenticated claim: 60 s, so a forged DERP sender cannot push out another membership's warm peers);
 *   - the configured priority peer of its membership is never evicted;
 *   - a peer on trial (activated by an inbound claim nobody has authenticated yet) belongs to the trial machinery of
 *     its membership, which expires or confirms it: it is not a victim;
 *   - among the rest the least recently used goes, so the cost lands on whoever has been quiet longest, across
 *     memberships; on a tie it comes from the membership holding the MOST slots, so one busy membership cannot be
 *     squeezed to nothing by another while a third idles on a pile of them;
 *   - when nothing is eligible the request is REFUSED (counted by the caller): recently used traffic is never evicted
 *     to make room, exactly as the single-membership rule had it.
 *
 * Pure function, no heap, bounded: tests/test_peer_policy.c.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ML_POLICY_MAX_CANDIDATES 32     /* ML_MUX_MAX memberships x 8 resident peers */

typedef struct {
    uint64_t last_used_ms;   /* when the peer last carried (or was activated for) traffic */
    unsigned owner_slots;    /* slots its membership currently holds */
    bool pinned;             /* the membership's priority peer */
    bool trial;              /* activated on an unauthenticated claim and not yet confirmed */
} ml_victim_candidate_t;

/* Index of the victim in c[0..n), or -1 when no candidate may be evicted. */
static inline int ml_policy_pick_victim(const ml_victim_candidate_t *c, size_t n, uint64_t now_ms, uint64_t idle_ms) {
    int best = -1;
    for (size_t i = 0; i < n; i++) {
        if (c[i].pinned || c[i].trial) continue;
        if (now_ms - c[i].last_used_ms < idle_ms) continue;
        if (best < 0 || c[i].last_used_ms < c[best].last_used_ms ||
            (c[i].last_used_ms == c[best].last_used_ms && c[i].owner_slots > c[best].owner_slots))
            best = (int)i;
    }
    return best;
}
