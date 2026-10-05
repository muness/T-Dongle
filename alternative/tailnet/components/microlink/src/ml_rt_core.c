#include "ml_rt_core.h"
#include <string.h>

void ml_rt_core_init(ml_rt_core_t *core, const ml_rt_platform_t *platform, void *platform_ctx,
                     const ml_mux_ops_t *ops[ML_RT_CORE_TASKS], void *shared[ML_RT_CORE_TASKS],
                     uint64_t (*now_ms)(void), const unsigned attach_order[ML_RT_CORE_TASKS],
                     const unsigned detach_order[ML_RT_CORE_TASKS], uint32_t detach_timeout_ms) {
    memset(core, 0, sizeof(*core));
    ml_mutex_init(&core->lock);
    core->platform = platform;
    core->platform_ctx = platform_ctx;
    core->detach_timeout_ms = detach_timeout_ms;
    core->stop_wait_ms = 2000;
    for (unsigned i = 0; i < ML_RT_CORE_TASKS; i++) {
        ml_mux_init(&core->mux[i], ops[i], shared ? shared[i] : NULL, now_ms);
        core->attach_order[i] = attach_order[i];
        core->detach_order[i] = detach_order[i];
    }
    __atomic_store_n(&core->stop, true, __ATOMIC_RELEASE);      /* nothing runs yet */
}

void ml_rt_core_task_exit(ml_rt_core_t *core) {
    __atomic_sub_fetch(&core->tasks_alive, 1, __ATOMIC_SEQ_CST);
}

/* Wait for the tasks to be gone, up to stop_wait_ms. */
static bool wait_tasks_gone(ml_rt_core_t *core) {
    for (uint32_t waited = 0; __atomic_load_n(&core->tasks_alive, __ATOMIC_SEQ_CST) > 0; waited += 10) {
        if (waited >= core->stop_wait_ms) return false;
        core->platform->sleep_ms(10);
    }
    return true;
}

static bool stop_tasks(ml_rt_core_t *core) {
    __atomic_store_n(&core->stop, true, __ATOMIC_RELEASE);
    if (!wait_tasks_gone(core)) return false;
    core->stops++;
    return true;
}

static bool start_tasks(ml_rt_core_t *core) {
    __atomic_store_n(&core->stop, false, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < ML_RT_CORE_TASKS; i++) {
        __atomic_add_fetch(&core->tasks_alive, 1, __ATOMIC_SEQ_CST);
        if (!core->platform->spawn(core->platform_ctx, i, core)) {
            __atomic_sub_fetch(&core->tasks_alive, 1, __ATOMIC_SEQ_CST);
            __atomic_store_n(&core->stop, true, __ATOMIC_RELEASE);               /* the ones already running exit on their own */
            wait_tasks_gone(core);
            return false;
        }
    }
    core->starts++;
    return true;
}

bool ml_rt_core_attach(ml_rt_core_t *core, void *member, bool *attached, int *why) {
    ml_mutex_lock(&core->lock);
    bool ok = true;
    int reason = 0;
    if (*attached) goto out;
    if (core->members == 0) {
        if (__atomic_load_n(&core->tasks_alive, __ATOMIC_SEQ_CST) > 0 && !wait_tasks_gone(core)) {
            ok = false; reason = 2; goto fail;
        }
        if (!start_tasks(core)) { ok = false; reason = 1; goto fail; }
    }
    for (unsigned i = 0; i < ML_RT_CORE_TASKS; i++) {
        if (ml_mux_attach(&core->mux[core->attach_order[i]], member) != 0) {
            for (unsigned back = i; back-- > 0;)
                ml_mux_detach(&core->mux[core->attach_order[back]], member, core->detach_timeout_ms);
            if (core->members == 0) stop_tasks(core);
            ok = false; reason = 3; goto fail;
        }
    }
    core->members++;
    *attached = true;
    goto out;
fail:
    core->attach_failures++;
    if (why) *why = reason;
out:
    ml_mutex_unlock(&core->lock);
    return ok;
}

bool ml_rt_core_detach(ml_rt_core_t *core, void *member, bool *attached) {
    ml_mutex_lock(&core->lock);
    bool ok = true;
    if (*attached) {
        for (unsigned i = 0; i < ML_RT_CORE_TASKS; i++)
            if (!ml_mux_detach(&core->mux[core->detach_order[i]], member, core->detach_timeout_ms)) ok = false;
        if (ok) {
            *attached = false;
            if (core->members) core->members--;
            if (core->members == 0) stop_tasks(core);
        } else {
            core->detach_failures++;
        }
    }
    ml_mutex_unlock(&core->lock);
    return ok;
}

bool ml_rt_core_running(ml_rt_core_t *core) {
    return __atomic_load_n(&core->tasks_alive, __ATOMIC_SEQ_CST) > 0 && !__atomic_load_n(&core->stop, __ATOMIC_ACQUIRE);
}

unsigned ml_rt_core_members(ml_rt_core_t *core) {
    ml_mutex_lock(&core->lock);
    unsigned n = core->members;
    ml_mutex_unlock(&core->lock);
    return n;
}
