/* SNTP supervision and the DERP pacing that waits for it: a missing wall clock
 * is retried with backoff, visible, and never holds anything else up. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../main/clock_sync.h"
#include "../components/microlink/include/ml_derp_pace.h"

int main(void) {
    gw_clock_t c = {0};
    uint64_t t = 5000;

    /* Uplink down: nothing is asked of a server, nothing is armed. */
    assert(gw_clock_poll(&c, t, false, false) == GW_CLOCK_NOTHING);
    assert(!c.next_retry_ms && !strcmp(gw_clock_state(&c, false, false), "waiting_for_network"));

    /* Uplink up: the first request gets time, then restarts back off and rotate servers. */
    assert(gw_clock_poll(&c, t, false, true) == GW_CLOCK_NOTHING);
    assert(!strcmp(gw_clock_state(&c, false, true), "syncing"));
    assert(c.retry_in_ms == GW_CLOCK_FIRST_RETRY_MS);
    assert(gw_clock_poll(&c, t + GW_CLOCK_FIRST_RETRY_MS - 1, false, true) == GW_CLOCK_NOTHING);
    t += GW_CLOCK_FIRST_RETRY_MS;
    assert(gw_clock_poll(&c, t, false, true) == GW_CLOCK_RESTART);
    assert(c.restarts == 1 && c.server == 1 && c.backoff_ms == 2 * GW_CLOCK_FIRST_RETRY_MS);
    assert(!strcmp(gw_clock_state(&c, false, true), "failing"));
    uint32_t previous = c.backoff_ms;
    for (int i = 0; i < 30; i++) {            /* a clock that never comes: bounded, never silent */
        t += c.backoff_ms;
        assert(gw_clock_poll(&c, t - 1, false, true) == GW_CLOCK_NOTHING);
        assert(gw_clock_poll(&c, t, false, true) == GW_CLOCK_RESTART);
        assert(c.backoff_ms >= previous && c.backoff_ms <= GW_CLOCK_MAX_RETRY_MS);
        assert(c.server < GW_CLOCK_SERVERS);
        previous = c.backoff_ms;
    }
    assert(c.backoff_ms == GW_CLOCK_MAX_RETRY_MS && c.restarts == 31);

    /* Losing the uplink disarms the schedule; the backoff restarts from the first step. */
    assert(gw_clock_poll(&c, t + 1, false, false) == GW_CLOCK_NOTHING && !c.next_retry_ms);
    assert(gw_clock_poll(&c, t + 2, false, true) == GW_CLOCK_NOTHING && c.backoff_ms == GW_CLOCK_FIRST_RETRY_MS);

    /* Once the clock is set the supervision stops and says so. */
    assert(gw_clock_poll(&c, t + 3, true, true) == GW_CLOCK_NOTHING);
    assert(c.synced && !c.next_retry_ms && c.retry_in_ms == 0);
    assert(!strcmp(gw_clock_state(&c, true, true), "synced"));

    /* DERP pacing: no clock means no connect attempt, no backoff growth, no failure counted... */
    ml_derp_pace_t p = {0};
    ml_derp_pace_reset(&p, 5000);
    for (uint64_t now = 0; now < 3600 * 1000ull; now += 100)
        assert(!ml_derp_pace_due(&p, now, false, 5000));
    assert(p.deferrals == 1 && p.backoff_ms == 5000 && p.next_ms == 0);
    /* ...and the first attempt follows the clock at once, not after a wait. */
    assert(ml_derp_pace_due(&p, 3600 * 1000ull + 100, true, 5000));
    /* A real failure backs off to the ceiling; a clock that goes away again defers once more. */
    uint64_t now = 3600 * 1000ull + 100;
    for (int i = 0; i < 10; i++) {
        ml_derp_pace_failed(&p, now, 60000);
        assert(p.backoff_ms <= 60000);
        assert(!ml_derp_pace_due(&p, now, true, 5000));
        now = p.next_ms;
        assert(ml_derp_pace_due(&p, now, true, 5000));
    }
    assert(p.backoff_ms == 60000);
    assert(!ml_derp_pace_due(&p, now + 1, false, 5000) && p.deferrals == 2 && p.backoff_ms == 5000);
    puts("clock_sync ok");
    return 0;
}
