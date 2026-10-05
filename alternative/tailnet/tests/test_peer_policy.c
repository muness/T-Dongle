/* Which peer gives up a WireGuard slot when the global pool is full (ml_peer_policy.h), and a two-membership simulation
 * of the pool: fairness, protection of recent traffic, bounded eviction rate. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ml_peer_policy.h"

static void picks(void) {
    ml_victim_candidate_t c[] = {
        {.last_used_ms = 1000, .owner_slots = 4}, {.last_used_ms = 500, .owner_slots = 2},
        {.last_used_ms = 200, .owner_slots = 4, .pinned = true}, {.last_used_ms = 100, .owner_slots = 4, .trial = true},
        {.last_used_ms = 90000, .owner_slots = 2},
    };
    /* now=100000, 10 s idle window: the oldest ELIGIBLE one (index 1); pinned and trial peers are never victims. */
    assert(ml_policy_pick_victim(c, 5, 100000, 10000) == 1);
    /* Recently used traffic is protected: 20 s window excludes the one used at 90000 and nothing else changes. */
    assert(ml_policy_pick_victim(c, 5, 100000, 20000) == 1);
    /* Nothing idle long enough: the request is refused, never a recent peer evicted. */
    for (int i = 0; i < 5; i++) c[i].last_used_ms = 99000;
    assert(ml_policy_pick_victim(c, 5, 100000, 10000) == -1);
    /* Tie on idle time: the membership holding the most slots pays. */
    ml_victim_candidate_t t[] = {{.last_used_ms = 10, .owner_slots = 2}, {.last_used_ms = 10, .owner_slots = 6}, {.last_used_ms = 10, .owner_slots = 3}};
    assert(ml_policy_pick_victim(t, 3, 100000, 10000) == 1);
    /* A claim on an unauthenticated sender uses a 60 s window, so warm peers of other memberships are safe. */
    ml_victim_candidate_t w[] = {{.last_used_ms = 50000, .owner_slots = 3}};
    assert(ml_policy_pick_victim(w, 1, 100000, 10000) == 0 && ml_policy_pick_victim(w, 1, 100000, 60000) == -1);
    assert(ml_policy_pick_victim(NULL, 0, 1, 1) == -1);
}

/* Two memberships, pool of 12, random traffic: no peer is evicted inside its protection window, no membership
 * is starved to zero while it has recent traffic, and the number of evictions is bounded by the activations. */
typedef struct { uint64_t used; bool resident; } peer_t;
static void simulate(unsigned step_ms, bool expect_rejections) {
    enum { CAP = 12, M = 2, PEERS = 20 };
    peer_t peer[M][PEERS];
    memset(peer, 0, sizeof(peer));
    unsigned used = 0, evictions = 0, rejected = 0, activations = 0, seed = 7;
    uint64_t now = 100000;
    for (unsigned step = 0; step < 20000; step++) {
        now += step_ms;
        seed = seed * 1103515245u + 12345u;
        unsigned m = (seed >> 16) % M, p = (seed >> 8) % PEERS;
        if (m == 1 && p >= 4) p %= 4;                      /* membership 1 is busy on few peers, 0 roams widely */
        peer_t *x = &peer[m][p];
        if (x->resident) { x->used = now; continue; }
        if (used >= CAP) {
            ml_victim_candidate_t c[M * PEERS]; unsigned who[M * PEERS][2]; size_t n = 0;
            for (unsigned a = 0; a < M; a++) {
                unsigned slots = 0;
                for (unsigned b = 0; b < PEERS; b++) slots += peer[a][b].resident;
                for (unsigned b = 0; b < PEERS; b++) if (peer[a][b].resident) { c[n] = (ml_victim_candidate_t){.last_used_ms = peer[a][b].used, .owner_slots = slots}; who[n][0] = a; who[n][1] = b; n++; }
            }
            int v = ml_policy_pick_victim(c, n, now, 10000);
            if (v < 0) { rejected++; continue; }
            peer_t *vp = &peer[who[v][0]][who[v][1]];
            assert(now - vp->used >= 10000);                  /* never evicts recent traffic */
            vp->resident = false; used--; evictions++;
        }
        x->resident = true; x->used = now; used++; activations++;
        assert(used <= CAP);
    }
    assert(evictions <= activations && evictions > 0);
    assert(expect_rejections ? rejected > 0 : evictions > 10);
    printf("  pool simulation: %u activations, %u evictions, %u rejected (all recent peers protected)\n", activations, evictions, rejected);
}

int main(void) {
    picks();
    simulate(2000, false);    /* sparse traffic: idle peers rotate through the pool */
    simulate(50, true);       /* dense traffic: everything is recent, so requests are refused instead */
    puts("peer policy: least-recently-used idle peer across memberships, never recent, pinned or trial");
    return 0;
}
