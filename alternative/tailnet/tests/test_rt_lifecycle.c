/* The shared runtime's lifecycle (the real ml_rt_core.c + ml_mux.c) with real threads: memberships join and leave while
 * the three shared tasks run, and each is FREED (and poisoned) the moment detach returns. Under ASan any later touch by a
 * shared task is a use-after-free; under TSan any unsynchronised access is a race. */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ml_rt_core.h"

typedef struct {
    atomic_uint serviced[ML_RT_CORE_TASKS], torn_down[ML_RT_CORE_TASKS];
    atomic_int slow_ms;          /* service blocks this long (a stuck slice) */
    bool attached;
    uint32_t canary;
} member_t;

static ml_rt_core_t core;

static atomic_bool fail_spawn_at_1;

static void service0(void *c, void *s) { (void)s; member_t *m = c; assert(m->canary == 0xC0FFEE); atomic_fetch_add(&m->serviced[0], 1); }
static void service1(void *c, void *s) { (void)s; member_t *m = c; assert(m->canary == 0xC0FFEE); atomic_fetch_add(&m->serviced[1], 1); int d = atomic_load(&m->slow_ms); if (d) ml_sleep_ms(d); }
static void service2(void *c, void *s) { (void)s; member_t *m = c; assert(m->canary == 0xC0FFEE); atomic_fetch_add(&m->serviced[2], 1); }
static void teardown0(void *c, void *s) { (void)s; member_t *m = c; assert(m->canary == 0xC0FFEE); atomic_fetch_add(&m->torn_down[0], 1); }
static void teardown1(void *c, void *s) { (void)s; member_t *m = c; atomic_fetch_add(&m->torn_down[1], 1); }
static void teardown2(void *c, void *s) { (void)s; member_t *m = c; atomic_fetch_add(&m->torn_down[2], 1); }
static const ml_mux_ops_t ops0 = {service0, teardown0}, ops1 = {service1, teardown1}, ops2 = {service2, teardown2};

static void *task_body(void *arg) {
    unsigned index = (unsigned)(uintptr_t)arg;
    while (!ml_rt_core_should_stop(&core)) { ml_mux_pass(&core.mux[index]); ml_sleep_ms(1); }
    ml_rt_core_task_exit(&core);
    return NULL;
}
static bool spawn(void *p, unsigned index, ml_rt_core_t *c) {
    (void)p; (void)c;
    if (index == 1 && atomic_load(&fail_spawn_at_1)) return false;
    pthread_t t;
    if (pthread_create(&t, NULL, task_body, (void *)(uintptr_t)index)) return false;
    pthread_detach(t);
    return true;
}
static const ml_rt_platform_t platform = {spawn, ml_sleep_ms};

static member_t *new_member(void) { member_t *m = calloc(1, sizeof(*m)); m->canary = 0xC0FFEE; return m; }
static void free_member(member_t *m) { memset(m, 0xEE, sizeof(*m)); free(m); }

static void basics(void) {
    member_t *a = new_member(), *b = new_member(), *c = new_member();
    assert(!ml_rt_core_running(&core));
    int why = 0;
    assert(ml_rt_core_attach(&core, a, &a->attached, &why) && ml_rt_core_running(&core) && core.starts == 1);
    assert(ml_rt_core_attach(&core, a, &a->attached, &why));              /* idempotent */
    assert(ml_rt_core_attach(&core, b, &b->attached, &why) && ml_rt_core_attach(&core, c, &c->attached, &why));
    assert(ml_rt_core_members(&core) == 3 && core.starts == 1);            /* the tasks start once, with the first */
    ml_sleep_ms(50);
    for (unsigned t = 0; t < 3; t++) assert(atomic_load(&a->serviced[t]) > 0 || t == 0 /* net_io mux here has a service */);
    assert(ml_rt_core_detach(&core, b, &b->attached));
    for (unsigned t = 0; t < 3; t++) assert(atomic_load(&b->torn_down[t]) == 1);   /* teardown ran for every task, exactly once */
    free_member(b);
    ml_sleep_ms(30);                                                        /* the tasks keep serving a and c; b is gone */
    assert(ml_rt_core_detach(&core, a, &a->attached) && ml_rt_core_detach(&core, a, &a->attached));   /* idempotent */
    free_member(a);
    assert(ml_rt_core_running(&core) && ml_rt_core_members(&core) == 1);
    assert(ml_rt_core_detach(&core, c, &c->attached));
    free_member(c);
    assert(!ml_rt_core_running(&core) && __atomic_load_n(&core.tasks_alive, __ATOMIC_SEQ_CST) == 0 && core.stops == 1);   /* the last member out stops the tasks */
    /* ...and they start again. */
    member_t *d = new_member();
    assert(ml_rt_core_attach(&core, d, &d->attached, &why) && core.starts == 2);
    assert(ml_rt_core_detach(&core, d, &d->attached));
    free_member(d);
    puts("  basics: tasks start with the first member, stop with the last, restart; teardown once per task");
}

static void failures(void) {
    int why = 0;
    /* A task that cannot be created leaves nothing running and nothing attached. */
    atomic_store(&fail_spawn_at_1, true);
    member_t *a = new_member();
    assert(!ml_rt_core_attach(&core, a, &a->attached, &why) && why == 1 && !a->attached);
    assert(__atomic_load_n(&core.tasks_alive, __ATOMIC_SEQ_CST) == 0 && ml_rt_core_members(&core) == 0);
    atomic_store(&fail_spawn_at_1, false);
    /* A full table refuses the fifth member and rolls back what was attached. */
    member_t *m[ML_MUX_MAX + 1];
    for (unsigned i = 0; i <= ML_MUX_MAX; i++) m[i] = new_member();
    for (unsigned i = 0; i < ML_MUX_MAX; i++) assert(ml_rt_core_attach(&core, m[i], &m[i]->attached, &why));
    assert(!ml_rt_core_attach(&core, m[ML_MUX_MAX], &m[ML_MUX_MAX]->attached, &why) && why == 3 && !m[ML_MUX_MAX]->attached);
    for (unsigned t = 0; t < 3; t++) assert(!ml_mux_contains(&core.mux[t], m[ML_MUX_MAX]));
    for (unsigned i = 0; i <= ML_MUX_MAX; i++) { assert(ml_rt_core_detach(&core, m[i], &m[i]->attached)); free_member(m[i]); }
    /* A stuck slice: detach times out, the member stays attached and MUST NOT be freed; the retry succeeds. */
    member_t *s = new_member();
    assert(ml_rt_core_attach(&core, s, &s->attached, &why));
    ml_sleep_ms(20);
    atomic_store(&s->slow_ms, 400);
    ml_sleep_ms(30);
    core.detach_timeout_ms = 50;
    assert(!ml_rt_core_detach(&core, s, &s->attached) && s->attached && core.detach_failures == 1);
    assert(s->canary == 0xC0FFEE && ml_rt_core_members(&core) == 1);       /* untouched: still ours */
    atomic_store(&s->slow_ms, 0);
    core.detach_timeout_ms = 3000;
    assert(ml_rt_core_detach(&core, s, &s->attached) && !s->attached);
    free_member(s);
    free_member(a);
    puts("  failures: spawn failure, full table rollback, stuck slice -> detach refuses, retry succeeds");
}

/* ---- churn: four threads join and leave at random while traffic flows ---- */
static atomic_bool stop_churn;
static atomic_uint joins, leaves;
static void *churner(void *arg) {
    unsigned seed = (unsigned)(uintptr_t)arg * 2654435761u;
    while (!atomic_load(&stop_churn)) {
        member_t *m = new_member();
        int why = 0;
        if (ml_rt_core_attach(&core, m, &m->attached, &why)) {
            atomic_fetch_add(&joins, 1);
            seed = seed * 1103515245u + 12345u;
            ml_sleep_ms(seed % 7);
            assert(ml_rt_core_detach(&core, m, &m->attached));
            atomic_fetch_add(&leaves, 1);
            for (unsigned t = 0; t < 3; t++) assert(atomic_load(&m->torn_down[t]) == 1);
        }
        free_member(m);            /* poisoned: a late touch by any shared task is a use-after-free */
        seed = seed * 1103515245u + 12345u;
        ml_sleep_ms(seed % 3);
    }
    return NULL;
}
static void churn(void) {
    pthread_t t[4];
    for (uintptr_t i = 0; i < 4; i++) pthread_create(&t[i], NULL, churner, (void *)(i + 1));
    ml_sleep_ms(2000);
    atomic_store(&stop_churn, true);
    for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
    assert(atomic_load(&joins) == atomic_load(&leaves) && atomic_load(&joins) > 100);
    assert(ml_rt_core_members(&core) == 0 && !ml_rt_core_running(&core) && __atomic_load_n(&core.tasks_alive, __ATOMIC_SEQ_CST) == 0);
    printf("  churn: %u joins and leaves under load, %u task start/stop cycles, no use-after-free\n", atomic_load(&joins), core.starts);
}

int main(void) {
    const ml_mux_ops_t *ops[3] = {&ops0, &ops1, &ops2};
    static const unsigned attach_order[3] = {1, 2, 0}, detach_order[3] = {0, 2, 1};
    ml_rt_core_init(&core, &platform, NULL, ops, NULL, ml_port_mono_ms, attach_order, detach_order, 3000);
    puts("shared runtime lifecycle");
    basics();
    failures();
    churn();
    puts("shared runtime lifecycle: attach/detach/start/stop are safe while the shared tasks run");
    return 0;
}
