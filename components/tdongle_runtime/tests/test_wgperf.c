/* The wg_mgr stage accounting: totals carry past 2^32, the maximum is exact, a reader never sees a torn total while
 * writers run, reset clears everything, the call-site macros measure with the injected clock, and in a release build
 * (no CONFIG_TDONGLE_MEMORY_DIAGNOSTICS) they compile to nothing, including the timestamp variables. */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#ifdef RELEASE_CHECK
#include "tdongle_wgperf.h"
/* -Wall -Wextra -Werror: an unused `t` here would fail the build if WGPERF_T still declared it. */
int main(void) {
    WGPERF_T(t);
    WGPERF_LAP(t, pass);
    WGPERF_CHARGE(t, send);
    WGPERF_RESTART(t);
    WGPERF_ADD(batch, 3);
    WGPERF_COUNT(passes, 1);
    return WGPERF_US_NOW();      /* 0 */
}
#else
#define CONFIG_TDONGLE_MEMORY_DIAGNOSTICS 1
static unsigned fake_cycles, fake_us;
#define TDONGLE_WGPERF_CYCLES() (fake_cycles)
#define TDONGLE_WGPERF_US() (fake_us)
#include "tdongle_wgperf.h"
tdongle_wgperf_t tdongle_wgperf;
void tdongle_wgperf_reset_now(void) { tdongle_wgperf_reset(&tdongle_wgperf, fake_us); }

static void test_basic(void) {
    tdongle_wgperf_t p = {0};
    tdongle_wgperf_add(&p, TDONGLE_WGPERF_send, 10);
    tdongle_wgperf_add(&p, TDONGLE_WGPERF_send, 30);
    tdongle_wgperf_add(&p, TDONGLE_WGPERF_send, 20);
    tdongle_wgperf_sample s = tdongle_wgperf_get(&p, TDONGLE_WGPERF_send);
    assert(s.count == 3 && s.total == 60 && s.max == 30);
    assert(tdongle_wgperf_get(&p, TDONGLE_WGPERF_pass).count == 0);
    tdongle_wgperf_add(&p, 9999, 1);                      /* out of range: ignored, no crash */
    tdongle_wgperf_count(&p, TDONGLE_WGPERF_C_passes, 5);
    tdongle_wgperf_count(&p, 9999, 5);
    assert(tdongle_wgperf_counter_get(&p, TDONGLE_WGPERF_C_passes) == 5 && tdongle_wgperf_counter_get(&p, 9999) == 0);
    tdongle_wgperf_reset(&p, 777);
    s = tdongle_wgperf_get(&p, TDONGLE_WGPERF_send);
    assert(s.count == 0 && s.total == 0 && s.max == 0 && atomic_load(&p.since_us) == 777);
    assert(tdongle_wgperf_counter_get(&p, TDONGLE_WGPERF_C_passes) == 0);
}

static void test_carry(void) {
    tdongle_wgperf_t p = {0};
    for (int i = 0; i < 5; i++) tdongle_wgperf_add(&p, TDONGLE_WGPERF_pass, 0xfffffff0u);
    tdongle_wgperf_sample s = tdongle_wgperf_get(&p, TDONGLE_WGPERF_pass);
    assert(s.total == 5ull * 0xfffffff0u && s.max == 0xfffffff0u && s.count == 5);
    tdongle_wgperf_add(&p, TDONGLE_WGPERF_pass, 0xffffffffu);
    assert(tdongle_wgperf_get(&p, TDONGLE_WGPERF_pass).max == 0xffffffffu);
}

static void test_macros(void) {
    tdongle_wgperf_reset_now();
    fake_cycles = 1000;
    WGPERF_T(t);
    fake_cycles = 1250;
    WGPERF_LAP(t, lookup);                                /* 250, and t restarts at 1250 */
    fake_cycles = 1300;
    WGPERF_LAP(t, send);                                  /* 50: stages chain */
    fake_cycles = 1400;
    WGPERF_CHARGE(t, pass);                               /* 100, t unchanged */
    fake_cycles = 1500;
    WGPERF_CHARGE(t, pass);                               /* 200 */
    WGPERF_ADD(batch, 4);
    WGPERF_COUNT(wakes, 2);
    fake_cycles = 0xffffff00u;                            /* the cycle counter wraps: the difference is still right */
    WGPERF_RESTART(t);
    fake_cycles = 0x00000100u;
    WGPERF_LAP(t, prep);
    fake_us = 42;
    assert(WGPERF_US_NOW() == 42);
    assert(tdongle_wgperf_get(&tdongle_wgperf, TDONGLE_WGPERF_lookup).total == 250);
    assert(tdongle_wgperf_get(&tdongle_wgperf, TDONGLE_WGPERF_send).total == 50);
    tdongle_wgperf_sample pass = tdongle_wgperf_get(&tdongle_wgperf, TDONGLE_WGPERF_pass);
    assert(pass.count == 2 && pass.total == 300 && pass.max == 200);
    assert(tdongle_wgperf_get(&tdongle_wgperf, TDONGLE_WGPERF_batch).total == 4);
    assert(tdongle_wgperf_get(&tdongle_wgperf, TDONGLE_WGPERF_prep).total == 0x200);
    assert(tdongle_wgperf_counter_get(&tdongle_wgperf, TDONGLE_WGPERF_C_wakes) == 2);
}

/* Writers on several threads against a reader: every read is a consistent snapshot (total never goes backwards, never
 * exceeds count * max) and the final totals are exact. */
static tdongle_wgperf_t shared;
#define WRITERS 4
#define ROUNDS 200000
static void *writer(void *arg) {
    uint32_t base = (uint32_t)(uintptr_t)arg;
    for (int i = 0; i < ROUNDS; i++) tdongle_wgperf_add(&shared, TDONGLE_WGPERF_rx_pkt, 0x40000000u + base);
    return NULL;
}
static atomic_bool stop;
static void *reader(void *arg) {
    (void)arg;
    uint64_t last = 0;
    while (!atomic_load(&stop)) {
        tdongle_wgperf_sample s = tdongle_wgperf_get(&shared, TDONGLE_WGPERF_rx_pkt);
        assert(s.total >= last);
        last = s.total;
    }
    return NULL;
}
static void test_threads(void) {
    pthread_t w[WRITERS], r;
    pthread_create(&r, NULL, reader, NULL);
    for (uintptr_t i = 0; i < WRITERS; i++) pthread_create(&w[i], NULL, writer, (void *)i);
    for (int i = 0; i < WRITERS; i++) pthread_join(w[i], NULL);
    atomic_store(&stop, true);
    pthread_join(r, NULL);
    tdongle_wgperf_sample s = tdongle_wgperf_get(&shared, TDONGLE_WGPERF_rx_pkt);
    uint64_t expect = 0;
    for (uint64_t i = 0; i < WRITERS; i++) expect += (uint64_t)ROUNDS * (0x40000000ull + i);
    assert(s.count == WRITERS * ROUNDS && s.total == expect && s.max == 0x40000000u + WRITERS - 1);
}

int main(void) {
    test_basic(); test_carry(); test_macros(); test_threads();
    puts("wgperf: totals, carry, maximum, reset, call-site macros and concurrent writers passed");
    return 0;
}
#endif
