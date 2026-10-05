/* The PM burst counter against a fake counting lock: balance under nesting, error paths, task exit, interrupt
 * refusal, and a randomised comparison with a reference model, then real threads (also run under TSan). */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include "../tdongle_pm_burst.c"

static atomic_int held;                 /* what the fake ESP lock holds right now */
static atomic_int acquire_calls, release_calls, below_zero;
static bool refuse_acquire, in_isr;
static atomic_uint clock_us;
static bool fake_acquire(void *ctx) {
    (void)ctx;
    atomic_fetch_add(&acquire_calls, 1);
    if (refuse_acquire) return false;
    atomic_fetch_add(&held, 1);
    return true;
}
static void fake_release(void *ctx) {
    (void)ctx;
    atomic_fetch_add(&release_calls, 1);
    if (atomic_fetch_sub(&held, 1) <= 0) { atomic_fetch_add(&below_zero, 1); atomic_store(&held, 0); }
}
static uint32_t fake_now(void) { return atomic_load(&clock_us); }
static bool fake_isr(void) { return in_isr; }
static const tdongle_pm_ops_t ops = { fake_acquire, fake_release, fake_now, fake_isr };

static void reset(void) {
    atomic_store(&held, 0); atomic_store(&acquire_calls, 0); atomic_store(&release_calls, 0); atomic_store(&below_zero, 0);
    refuse_acquire = in_isr = false; atomic_store(&clock_us, 1000);
}
static tdongle_pm_burst_stats_t stats(tdongle_pm_burst_t *b) { tdongle_pm_burst_stats_t s; tdongle_pm_burst_stats(b, &s); return s; }

static void test_nesting(void) {
    reset();
    tdongle_pm_burst_t b; tdongle_pm_burst_init(&b, "t", &ops, NULL);
    tdongle_pm_burst_begin(&b); assert(atomic_load(&held) == 1);
    tdongle_pm_burst_begin(&b); tdongle_pm_burst_begin(&b);
    assert(atomic_load(&held) == 1 && atomic_load(&acquire_calls) == 1);        /* nesting only counts */
    tdongle_pm_burst_end(&b); tdongle_pm_burst_end(&b);
    assert(atomic_load(&held) == 1);                                            /* outermost still open */
    atomic_fetch_add(&clock_us, 250);
    tdongle_pm_burst_end(&b);
    assert(atomic_load(&held) == 0 && atomic_load(&release_calls) == 1);
    tdongle_pm_burst_stats_t s = stats(&b);
    assert(s.acquires == 1 && s.releases == 1 && s.max_depth == 3 && s.depth == 0 && s.held_us == 250 && !s.underflows);
    for (int i = 0; i < 100; i++) { tdongle_pm_burst_begin(&b); tdongle_pm_burst_end(&b); }
    s = stats(&b);
    assert(s.acquires == 101 && s.releases == 101 && atomic_load(&held) == 0);
}

static void test_error_paths(void) {
    reset();
    tdongle_pm_burst_t b; tdongle_pm_burst_init(&b, "t", &ops, NULL);
    tdongle_pm_burst_end(&b);                                                   /* end without begin */
    tdongle_pm_burst_end(&b);
    assert(stats(&b).underflows == 2 && atomic_load(&release_calls) == 0 && atomic_load(&held) == 0);
    tdongle_pm_burst_begin(&b); tdongle_pm_burst_end(&b); tdongle_pm_burst_end(&b);  /* extra end after a pair */
    assert(stats(&b).underflows == 3 && atomic_load(&held) == 0 && stats(&b).depth == 0);
    /* the lock is refused: counted, depth still balances, nothing is held, and the object recovers */
    refuse_acquire = true;
    tdongle_pm_burst_begin(&b); assert(stats(&b).backend_failures == 1 && atomic_load(&held) == 0);
    tdongle_pm_burst_end(&b); assert(stats(&b).depth == 0);
    atomic_store(&below_zero, 0);
    refuse_acquire = false;
    tdongle_pm_burst_begin(&b); assert(atomic_load(&held) == 1);
    tdongle_pm_burst_end(&b); assert(atomic_load(&held) == 0 && atomic_load(&below_zero) == 0);
    /* no backend at all: counts, never crashes */
    tdongle_pm_burst_t none; tdongle_pm_burst_init(&none, "n", NULL, NULL);
    tdongle_pm_burst_begin(&none); tdongle_pm_burst_end(&none); tdongle_pm_burst_release_all(&none);
    assert(stats(&none).acquires == 1 && stats(&none).releases == 1);
}

static void test_isr(void) {
    reset();
    tdongle_pm_burst_t b; tdongle_pm_burst_init(&b, "t", &ops, NULL);
    in_isr = true;
    tdongle_pm_burst_begin(&b); tdongle_pm_burst_end(&b); tdongle_pm_burst_release_all(&b);
    tdongle_pm_burst_stats_t s = stats(&b);
    assert(s.isr_rejects == 3 && s.acquires == 0 && s.depth == 0 && atomic_load(&acquire_calls) == 0 && atomic_load(&release_calls) == 0);
    in_isr = false;
    tdongle_pm_burst_begin(&b);
    in_isr = true; tdongle_pm_burst_end(&b); in_isr = false;       /* an end from an interrupt must not release */
    assert(atomic_load(&held) == 1 && stats(&b).depth == 1);
    tdongle_pm_burst_end(&b); assert(atomic_load(&held) == 0);
}

static void test_release_all(void) {
    reset();
    tdongle_pm_burst_t b; tdongle_pm_burst_init(&b, "t", &ops, NULL);
    tdongle_pm_burst_release_all(&b);                                           /* idle: nothing */
    assert(atomic_load(&release_calls) == 0 && stats(&b).forced_releases == 0);
    tdongle_pm_burst_begin(&b); tdongle_pm_burst_begin(&b); tdongle_pm_burst_begin(&b);
    atomic_fetch_add(&clock_us, 40);
    tdongle_pm_burst_release_all(&b);                                           /* the task exits mid-burst */
    assert(atomic_load(&held) == 0 && atomic_load(&release_calls) == 1);
    tdongle_pm_burst_stats_t s = stats(&b);
    assert(s.forced_releases == 1 && s.depth == 0 && s.held_us == 40 && s.releases == 1);
    tdongle_pm_burst_end(&b);                                                   /* a stray end afterwards is an underflow */
    assert(stats(&b).underflows == 1 && atomic_load(&held) == 0);
    tdongle_pm_burst_begin(&b); tdongle_pm_burst_end(&b); assert(atomic_load(&held) == 0);     /* reusable */
}

/* A reference model: the lock is held exactly while the model depth is above zero. */
static void test_model(void) {
    reset();
    tdongle_pm_burst_t b; tdongle_pm_burst_init(&b, "t", &ops, NULL);
    uint32_t x = 12345; unsigned depth = 0;
    for (int i = 0; i < 200000; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        unsigned op = x % 16;
        if (op < 7) { tdongle_pm_burst_begin(&b); depth++; }
        else if (op < 14) { tdongle_pm_burst_end(&b); if (depth) depth--; }
        else if (op == 14) { tdongle_pm_burst_release_all(&b); depth = 0; }
        else { tdongle_pm_burst_end(&b); if (depth) depth--; }
        assert(atomic_load(&held) == (depth > 0 ? 1 : 0));
        assert(stats(&b).depth == depth);
    }
    assert(atomic_load(&below_zero) == 0);
    tdongle_pm_burst_stats_t s = stats(&b);
    assert(s.acquires == s.releases + (depth ? 1 : 0));
}

#define THREADS 4
#define CYCLES 50000
static tdongle_pm_burst_t shared;
static void *worker(void *arg) {
    int exit_mid_burst = (int)(intptr_t)arg;
    for (int i = 0; i < CYCLES; i++) {
        tdongle_pm_burst_begin(&shared);
        if (i % 3 == 0) { tdongle_pm_burst_begin(&shared); tdongle_pm_burst_end(&shared); }
        tdongle_pm_burst_end(&shared);
    }
    if (exit_mid_burst) { tdongle_pm_burst_begin(&shared); /* ... task body fails here ... */ }
    return NULL;
}
static void test_threads(void) {
    reset();
    tdongle_pm_burst_init(&shared, "shared", &ops, NULL);
    pthread_t t[THREADS];
    for (int i = 0; i < THREADS; i++) pthread_create(&t[i], NULL, worker, (void *)(intptr_t)(i == 0));
    for (int i = 0; i < THREADS; i++) pthread_join(t[i], NULL);
    /* thread 0 "exited" with its section open: the owner's exit path closes it. Only its own depth is left. */
    assert(stats(&shared).depth == 1 && atomic_load(&held) == 1);
    tdongle_pm_burst_release_all(&shared);
    tdongle_pm_burst_stats_t s = stats(&shared);
    assert(atomic_load(&held) == 0 && s.depth == 0 && atomic_load(&below_zero) == 0 && s.underflows == 0);
    assert(s.acquires == s.releases && s.acquires == (uint32_t)atomic_load(&acquire_calls));
}

int main(void) {
    test_nesting(); test_error_paths(); test_isr(); test_release_all(); test_model(); test_threads();
    puts("pm burst: nesting, error paths, interrupt refusal, task exit, model and threads passed");
    return 0;
}
