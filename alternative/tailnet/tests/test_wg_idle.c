/* ml_wg_slice_idle: a slice may only be skipped when it could not have done anything. Every input that means "work" must
 * defeat the early exit; the timers must agree with the conditions member_service tests (400 ms periodic, > 1000 ms probes,
 * 10 s snapshot). Exhaustive over the boolean inputs and over the timer boundaries. */
#include <assert.h>
#include <stdio.h>
#include "ml_wg_idle.h"

static ml_wg_idle_t quiet(void) {
    return (ml_wg_idle_t){.now_ms = 1000, .periodic_at_ms = 1400, .probes_at_ms = 2000, .snapshot_at_ms = 11000, .wg_ready = true};
}
int main(void) {
    ml_wg_idle_t s = quiet();
    assert(ml_wg_slice_idle(&s));
    /* each blocker alone */
    s = quiet(); s.queued = 1; assert(!ml_wg_slice_idle(&s));
    s = quiet(); s.packets_pending = true; assert(!ml_wg_slice_idle(&s));
    s = quiet(); s.trial_pending = true; assert(!ml_wg_slice_idle(&s));
    s = quiet(); s.directory_stale = true; assert(!ml_wg_slice_idle(&s));
    s = quiet(); s.stun_cmm_due = true; assert(!ml_wg_slice_idle(&s));
    s = quiet(); s.derp_changed = true; assert(!ml_wg_slice_idle(&s));
    /* all 2^6 combinations: idle only for the empty one */
    for (unsigned m = 0; m < 64; m++) {
        s = quiet();
        s.queued = m & 1; s.packets_pending = m & 2; s.trial_pending = m & 4; s.directory_stale = m & 8; s.stun_cmm_due = m & 16; s.derp_changed = m & 32;
        assert(ml_wg_slice_idle(&s) == (m == 0));
    }
    /* timer boundaries: due exactly at the deadline is not idle */
    s = quiet(); s.now_ms = 1399; assert(ml_wg_slice_idle(&s));
    s = quiet(); s.now_ms = 1400; assert(!ml_wg_slice_idle(&s));            /* periodic: now - last >= 400 */
    s = quiet(); s.now_ms = 1400; s.wg_ready = false; assert(ml_wg_slice_idle(&s));   /* ...but only runs with a netif */
    s = quiet(); s.periodic_at_ms = 5000; s.now_ms = 1999; assert(ml_wg_slice_idle(&s));
    s = quiet(); s.periodic_at_ms = 5000; s.now_ms = 2000; assert(!ml_wg_slice_idle(&s));   /* probes: at the deadline, conservatively */
    s = quiet(); s.periodic_at_ms = 50000; s.probes_at_ms = 50000; s.now_ms = 10999; assert(ml_wg_slice_idle(&s));
    s = quiet(); s.periodic_at_ms = 50000; s.probes_at_ms = 50000; s.now_ms = 11000; assert(!ml_wg_slice_idle(&s));   /* snapshot */
    /* 64-bit clock: far from zero, no wrap */
    s = quiet(); s.now_ms = 1ull << 40; s.periodic_at_ms = s.now_ms + 400; s.probes_at_ms = s.now_ms + 1000; s.snapshot_at_ms = s.now_ms + 10000;
    assert(ml_wg_slice_idle(&s));
    puts("wg idle slice: every blocker and timer boundary passed");
    return 0;
}
