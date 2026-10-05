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

/* ---- activity hold ---- */
static atomic_uint arms, last_arm_delay;
static void fake_arm(void *ctx, uint32_t delay_us) { (void)ctx; atomic_fetch_add(&arms, 1); atomic_store(&last_arm_delay, delay_us); }
static void activity_setup(tdongle_pm_burst_t *b, tdongle_pm_activity_t *a) {
    reset(); atomic_store(&arms, 0);
    tdongle_pm_burst_init(b, "fwd", &ops, NULL);
    tdongle_pm_activity_init(a, b, 200000, fake_arm, NULL);
}
static void test_activity(void) {
    tdongle_pm_burst_t b; tdongle_pm_activity_t a;
    activity_setup(&b, &a);
    tdongle_pm_activity_tick(&a, 5000);                                  /* idle tick: nothing */
    assert(atomic_load(&held) == 0 && atomic_load(&arms) == 0);
    tdongle_pm_activity_note(&a, 1000);                                  /* first packet: one acquire, one timer */
    assert(atomic_load(&held) == 1 && atomic_load(&arms) == 1 && atomic_load(&last_arm_delay) == 200000);
    for (uint32_t t = 1100; t < 150000; t += 100) tdongle_pm_activity_note(&a, t);   /* a stream: no more acquires */
    assert(atomic_load(&acquire_calls) == 1 && atomic_load(&arms) == 1 && a.starts == 1);
    tdongle_pm_activity_tick(&a, 200000);                                /* last note 149,900: 50 ms in, 150 ms left */
    assert(atomic_load(&held) == 1 && atomic_load(&arms) == 2 && atomic_load(&last_arm_delay) == 200000 - (200000 - 149900));
    tdongle_pm_activity_tick(&a, 349899);                                /* one us short */
    assert(atomic_load(&held) == 1 && atomic_load(&release_calls) == 0);
    tdongle_pm_activity_tick(&a, 349900);                                /* hold_us since the last note: released */
    assert(atomic_load(&held) == 0 && atomic_load(&release_calls) == 1 && stats(&b).depth == 0);
    tdongle_pm_activity_tick(&a, 500000);                                /* idle again: nothing to do */
    assert(atomic_load(&release_calls) == 1);
    tdongle_pm_activity_note(&a, 600000);                                /* and it restarts */
    assert(atomic_load(&held) == 1 && a.starts == 2 && atomic_load(&arms) == 4);
    assert(stats(&b).acquires == 2 && stats(&b).underflows == 0);
}
/* A tick that read the clock before a concurrent note (now < last) must treat the note as "just now". */
static void test_activity_stale_clock(void) {
    tdongle_pm_burst_t b; tdongle_pm_activity_t a;
    activity_setup(&b, &a);
    tdongle_pm_activity_note(&a, 1000);
    tdongle_pm_activity_note(&a, 900000);
    tdongle_pm_activity_tick(&a, 800000);                                /* now is 100 ms older than the newest note */
    assert(atomic_load(&held) == 1 && atomic_load(&release_calls) == 0);
    /* wrap: notes and ticks around the 2^32 us rollover */
    activity_setup(&b, &a);
    tdongle_pm_activity_note(&a, 0xffffff00u);
    tdongle_pm_activity_tick(&a, 0x00000100u + 100000);                  /* 100 ms later across the wrap: still held */
    assert(atomic_load(&held) == 1);
    tdongle_pm_activity_tick(&a, 0x00000100u + 250000);
    assert(atomic_load(&held) == 0);
}
static void test_activity_isr(void) {
    tdongle_pm_burst_t b; tdongle_pm_activity_t a;
    activity_setup(&b, &a);
    in_isr = true;
    tdongle_pm_activity_note(&a, 1000);
    in_isr = false;
    assert(atomic_load(&held) == 0 && stats(&b).isr_rejects == 1 && a.starts == 0);
    tdongle_pm_activity_note(&a, 2000);                                  /* the next task-context note works */
    assert(atomic_load(&held) == 1);
}

/* Producers note continuously while a timer thread ticks: the lock is never released under a live stream's feet for
 * long, never leaked, and always balanced. */
static tdongle_pm_burst_t th_burst; static tdongle_pm_activity_t th_act;
static atomic_bool th_stop;
static atomic_uint th_clock;
static void *producer(void *arg) {
    (void)arg;
    for (int i = 0; i < 100000; i++) {
        tdongle_pm_activity_note(&th_act, atomic_fetch_add(&th_clock, 7));
        if (i % 1000 == 0) atomic_fetch_add(&th_clock, 300000);        /* quiet spells: the ticker releases */
    }
    return NULL;
}
static void *ticker(void *arg) {
    (void)arg;
    while (!atomic_load(&th_stop)) tdongle_pm_activity_tick(&th_act, atomic_load(&th_clock));
    return NULL;
}
static void test_activity_threads(void) {
    reset(); atomic_store(&th_stop, false); atomic_store(&th_clock, 1000);
    tdongle_pm_burst_init(&th_burst, "fwd", &ops, NULL);
    tdongle_pm_activity_init(&th_act, &th_burst, 200000, fake_arm, NULL);
    pthread_t p[3], t;
    for (int i = 0; i < 3; i++) pthread_create(&p[i], NULL, producer, NULL);
    pthread_create(&t, NULL, ticker, NULL);
    for (int i = 0; i < 3; i++) pthread_join(p[i], NULL);
    atomic_store(&th_stop, true);
    pthread_join(t, NULL);
    /* drain: far in the future nothing is held any more, and the lock count matches the flag */
    tdongle_pm_activity_tick(&th_act, atomic_load(&th_clock) + 1000000);
    tdongle_pm_burst_stats_t s = stats(&th_burst);
    assert(atomic_load(&held) == 0 && s.depth == 0 && s.underflows == 0 && atomic_load(&below_zero) == 0);
    assert(s.acquires == s.releases && s.acquires <= th_act.starts);   /* a start that crosses a pending end only nests */
}

int main(void) {
    test_activity(); test_activity_stale_clock(); test_activity_isr(); test_activity_threads();
    test_nesting(); test_error_paths(); test_isr(); test_release_all(); test_model(); test_threads();
    puts("pm burst: nesting, error paths, interrupt refusal, task exit, model and threads passed");
    return 0;
}
