/* The control task releases the negotiation token on EVERY path out of a negotiation state (ml_coord_state.h). */
#include <assert.h>
#include <stdio.h>
#include "ml_coord_state.h"

static uint64_t now_ms(void) { static uint64_t t; return t += 3; }

int main(void) {
    ml_neg_t neg; ml_neg_init(&neg, now_ms, 0, 0, 0);
    const uintptr_t me = ml_neg_key(1, ML_NEG_PHASE_CONTROL), other = ml_neg_key(2, ML_NEG_PHASE_CONTROL);
    bool holding = false;
    assert(ml_neg_key(1, ML_NEG_PHASE_CONTROL) == ml_neg_key(1, ML_NEG_PHASE_START) && ml_neg_key(1, ML_NEG_PHASE_DERP) != me);
    /* Every state, entered from every state, with the token free: negotiating states hold it, the rest do not. */
    for (int from = COORD_IDLE; from <= COORD_RECONNECTING; from++)
        for (int to = COORD_IDLE; to <= COORD_RECONNECTING; to++) {
            assert(coord_token_sync(&neg, me, (coord_state_t)from, ML_NEG_PRIO_START, &holding) || true);
            assert(coord_token_sync(&neg, me, (coord_state_t)to, ML_NEG_PRIO_START, &holding));
            assert(ml_neg_holds(&neg, me) == coord_state_negotiates((coord_state_t)to));
            assert(holding == coord_state_negotiates((coord_state_t)to));   /* engaged: holds or waits */
            coord_token_sync(&neg, me, COORD_IDLE, ML_NEG_PRIO_START, &holding);   /* loop exit */
            assert(!ml_neg_holds(&neg, me));
        }
    /* An error path that jumps straight from any negotiation state to RECONNECTING lets go at the next iteration. */
    for (int s = COORD_STUN_PROBE; s <= COORD_FETCH_PEERS; s++) {
        assert(coord_token_sync(&neg, me, (coord_state_t)s, ML_NEG_PRIO_START, &holding));
        assert(ml_neg_holds(&neg, me));
        assert(coord_token_sync(&neg, me, COORD_RECONNECTING, ML_NEG_PRIO_REJOIN, &holding) && !ml_neg_holds(&neg, me));
    }
    /* While another membership negotiates, work in a negotiating state must not run, and nothing is leaked. */
    bool other_hold = false;
    assert(coord_token_sync(&neg, other, COORD_NOISE_HANDSHAKE, ML_NEG_PRIO_START, &other_hold));
    assert(!coord_token_sync(&neg, me, COORD_STUN_PROBE, ML_NEG_PRIO_START, &holding) && holding && !ml_neg_holds(&neg, me));   /* waiting */
    assert(coord_token_sync(&neg, me, COORD_LONG_POLL, ML_NEG_PRIO_START, &holding));   /* steady state never waits */
    coord_token_sync(&neg, me, COORD_IDLE, ML_NEG_PRIO_START, &holding);                 /* leaves the queue too */
    coord_token_sync(&neg, other, COORD_LONG_POLL, ML_NEG_PRIO_START, &other_hold);
    ml_neg_status_t st; ml_neg_status(&neg, &st);
    assert(st.holder == 0 && st.waiting == 0);
    puts("coord token: held exactly in STUN_PROBE..FETCH_PEERS, released on every other state, nothing leaks");
    return 0;
}
