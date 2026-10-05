#include "ml_runtime.h"
#include "ml_rt_core.h"
#include "esp_log.h"
#include "tdongle_pm.h"
#include <string.h>

/* The FreeRTOS half of the shared runtime. The part that has to be right (when the tasks start and stop, the order a
 * membership attaches and detaches, rollback, "a membership whose detach failed is not gone") is ml_rt_core.c, which
 * the host tests run with real threads. */

static const char *TAG = "ml_runtime";

static struct {
    int ready;                       /* 0 = not built, 1 = building, 2 = ready */
    ml_neg_t neg;
    ml_rt_core_t core;
    ml_wg_pass_t wg_pass;
    ml_derp_pass_t derp_pass;
    TaskHandle_t task[ML_RT_TASK_COUNT];
} rt;

/* A shared task deletes itself when the last membership leaves, and wakers (queue producers on any core) hold nothing
 * that keeps the task alive. rt.task[] is therefore only ever read or written inside this critical section, and a
 * task clears its own entry in it BEFORE it signs off and deletes itself: a waker either notifies a task that cannot
 * yet have been deleted (it is still in vTaskDelete's caller, waiting for this very section) or finds NULL. Without
 * it, a handle read just before the delete was a notify into a freed TCB. */
static portMUX_TYPE rt_task_mux = portMUX_INITIALIZER_UNLOCKED;

/* One CPU-frequency-max lock per shared task (ADR 0016): held for a processing pass, never across the wait for the
 * next one. Each is begun and ended only by its own task, so a lock can never outlive the task (rt_task_exit closes
 * whatever is open). The objects are static and outlive every restart of the tasks. */
static tdongle_pm_burst_t pm_burst[ML_RT_TASK_COUNT];
static const char *const pm_names[ML_RT_TASK_COUNT] = { "ml_net_io", "ml_derp", "ml_wg_mgr" };

void ml_rt_burst_begin(ml_rt_task_t which) {
    if (which < ML_RT_TASK_COUNT) tdongle_pm_burst_begin(&pm_burst[which]);
}
void ml_rt_burst_end(ml_rt_task_t which) {
    if (which < ML_RT_TASK_COUNT) tdongle_pm_burst_end(&pm_burst[which]);
}

static void rt_task_exit(ml_rt_core_t *core, ml_rt_task_t which) {
    tdongle_pm_burst_release_all(&pm_burst[which]);     /* a pass that unwound early must not leave the CPU pinned */
    portENTER_CRITICAL(&rt_task_mux);
    rt.task[which] = NULL;
    portEXIT_CRITICAL(&rt_task_mux);
    ml_rt_core_task_exit(core);     /* after the entry is clear: a restart's spawn can then own the slot */
    vTaskDelete(NULL);
}

static const uint32_t stack_bytes[ML_RT_TASK_COUNT] = {
    ML_TASK_NET_IO_STACK, ML_TASK_DERP_TX_STACK, ML_TASK_WG_MGR_STACK,
};

/* net_io has no per-membership service slice: its single select() covers every membership's sockets. */
static const ml_mux_ops_t net_io_ops = { .service = NULL, .teardown = NULL };

/* ---- the three shared tasks ---- */

static void net_io_task(void *arg) {
    ml_rt_core_t *core = arg;
    ESP_LOGI(TAG, "net_io started (Core %d)", xPortGetCoreID());
    uint8_t scratch[ML_NET_IO_SCRATCH_BYTES];
    while (!ml_rt_core_should_stop(core)) ml_net_io_pass(&core->mux[ML_RT_TASK_NET_IO], scratch);
    rt_task_exit(core, ML_RT_TASK_NET_IO);
}

/* Wait for a wake-up or the computed deadline, whichever is first. A deadline of UINT32_MAX means "nothing is due":
 * the task sleeps until it is woken, but never longer than a second so a stop request is always noticed. */
static void wait_for_work(uint32_t wait_ms) {
    if (wait_ms > 1000) wait_ms = 1000;
    TickType_t ticks = pdMS_TO_TICKS(wait_ms);
    if (ticks == 0) ticks = 1;     /* a deadline already due still yields one tick: lower priorities get the core */
    ulTaskNotifyTake(pdTRUE, ticks);
}

/* The derp task sleeps until the shortest wait any link asks for (ml_derp_link_wait_ms: a retry deadline, a connect
 * step, the 10 ms read of an established relay), or until a producer wakes it: a packet queued for relay, a connect
 * request. With every relay down and nothing wanted it wakes once a second. */
static void derp_task(void *arg) {
    ml_rt_core_t *core = arg;
    ESP_LOGI(TAG, "derp started (Core %d)", xPortGetCoreID());
    while (!ml_rt_core_should_stop(core)) {
        rt.derp_pass.wait_ms = UINT32_MAX;
        ml_rt_burst_begin(ML_RT_TASK_DERP);
        ml_mux_pass(&core->mux[ML_RT_TASK_DERP]);
        ml_rt_burst_end(ML_RT_TASK_DERP);              /* before the wait: an idle relay does not pin 240 MHz */
        wait_for_work(rt.derp_pass.wait_ms);
    }
    rt_task_exit(core, ML_RT_TASK_DERP);
}

/* The wg_mgr task runs when a packet, a peer update or an event arrives (producers call ml_rt_wake), or when the
 * earliest membership timer is due (periodic WireGuard work, DISCO probes, a trial or pending packet deadline), not on
 * a fixed 10 ms tick. A backlog left by the drain budgets (#46) asks for one tick, so the budgets still hand the core
 * to lower priorities between slices. */
static void wg_mgr_task(void *arg) {
    ml_rt_core_t *core = arg;
    ESP_LOGI(TAG, "wg_mgr started (Core %d)", xPortGetCoreID());
    while (!ml_rt_core_should_stop(core)) {
        ml_wg_pass_begin(&rt.wg_pass);
        ml_rt_burst_begin(ML_RT_TASK_WG_MGR);
        ml_mux_pass(&core->mux[ML_RT_TASK_WG_MGR]);
        ml_rt_burst_end(ML_RT_TASK_WG_MGR);
        uint64_t now = ml_get_time_ms();
        wait_for_work(rt.wg_pass.next_due_ms > now ? (uint32_t)(rt.wg_pass.next_due_ms - now) : 0);
    }
    rt_task_exit(core, ML_RT_TASK_WG_MGR);
}

static bool platform_spawn(void *platform, unsigned index, ml_rt_core_t *core) {
    (void)platform;
    static const struct {
        TaskFunction_t fn;
        const char *name;
        UBaseType_t prio;
        BaseType_t core;
    } spec[ML_RT_TASK_COUNT] = {
        [ML_RT_TASK_NET_IO] = { net_io_task, "ml_net_io", ML_TASK_NET_IO_PRIO, ML_TASK_NET_IO_CORE },
        [ML_RT_TASK_DERP] = { derp_task, "ml_derp", ML_TASK_DERP_TX_PRIO, ML_TASK_DERP_TX_CORE },
        [ML_RT_TASK_WG_MGR] = { wg_mgr_task, "ml_wg_mgr", ML_TASK_WG_MGR_PRIO, ML_TASK_WG_MGR_CORE },
    };
    TaskHandle_t handle = NULL;
    if (xTaskCreatePinnedToCore(spec[index].fn, spec[index].name, stack_bytes[index], core, spec[index].prio,
                                &handle, spec[index].core) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create %s", spec[index].name);
        return false;
    }
    /* Published only now, and only by the creator, which holds the core lock: no stop can have been requested, so the
     * task cannot have exited (and cleared its entry) before this store. */
    portENTER_CRITICAL(&rt_task_mux);
    rt.task[index] = handle;
    portEXIT_CRITICAL(&rt_task_mux);
    return true;
}
static void platform_sleep(uint32_t ms) { vTaskDelay(pdMS_TO_TICKS(ms)); }
static void platform_wake_all(void *platform) {
    (void)platform;
    for (int i = 0; i < ML_RT_TASK_COUNT; i++) ml_rt_wake((ml_rt_task_t)i);
}
static const ml_rt_platform_t platform = { .spawn = platform_spawn, .sleep_ms = platform_sleep, .wake_all = platform_wake_all };

/* First use builds the static state exactly once, without a lock to take yet. */
static void rt_init(void) {
    int expected = 0;
    if (__atomic_compare_exchange_n(&rt.ready, &expected, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        ml_neg_init(&rt.neg, ml_get_time_ms, 0, 0, 0);
        for (int i = 0; i < ML_RT_TASK_COUNT; i++) tdongle_pm_burst_register(&pm_burst[i], pm_names[i]);
        const ml_mux_ops_t *ops[ML_RT_CORE_TASKS] = { &net_io_ops, &ml_derp_mux_ops, &ml_wg_mux_ops };
        void *shared[ML_RT_CORE_TASKS] = { NULL, &rt.derp_pass, &rt.wg_pass };
        /* Attach in the order a packet travels; detach in the order that stops intake first, then the WireGuard
         * interface, then the relay. */
        static const unsigned attach_order[ML_RT_CORE_TASKS] = { ML_RT_TASK_DERP, ML_RT_TASK_WG_MGR, ML_RT_TASK_NET_IO };
        static const unsigned detach_order[ML_RT_CORE_TASKS] = { ML_RT_TASK_NET_IO, ML_RT_TASK_WG_MGR, ML_RT_TASK_DERP };
        ml_rt_core_init(&rt.core, &platform, NULL, ops, shared, ml_get_time_ms, attach_order, detach_order,
                        ML_RT_DETACH_TIMEOUT_MS);
        __atomic_store_n(&rt.ready, 2, __ATOMIC_RELEASE);
    } else {
        while (__atomic_load_n(&rt.ready, __ATOMIC_ACQUIRE) != 2) vTaskDelay(1);
    }
}

void ml_rt_wake(ml_rt_task_t which) {
    if (which >= ML_RT_TASK_COUNT) return;
    portENTER_CRITICAL(&rt_task_mux);       /* notify never blocks; the section is what keeps the TCB alive (see above) */
    TaskHandle_t h = rt.task[which];
    if (h) xTaskNotifyGive(h);
    portEXIT_CRITICAL(&rt_task_mux);
}

ml_neg_t *ml_rt_negotiation(void) {
    rt_init();
    return &rt.neg;
}

size_t ml_rt_start_bytes(void) {
    rt_init();
    return ml_rt_core_members(&rt.core) == 0 ? ML_RT_SHARED_STACK_BYTES + 3 * sizeof(StaticTask_t) : 0;
}

esp_err_t ml_rt_attach(microlink_t *ml) {
    rt_init();
    if (!ml) return ESP_ERR_INVALID_ARG;
    int why = 0;
    if (ml_rt_core_attach(&rt.core, ml, &ml->rt_attached, &why)) return ESP_OK;
    ESP_LOGE(TAG, "attach failed (%s)", why == 1 ? "tasks could not be created" : why == 2 ? "previous shutdown not finished" : "no free slot");
    return why == 2 ? ESP_ERR_INVALID_STATE : ESP_ERR_NO_MEM;
}

bool ml_rt_detach(microlink_t *ml) {
    if (!ml) return true;
    rt_init();
    if (ml_rt_core_detach(&rt.core, ml, &ml->rt_attached)) return true;
    ESP_LOGE(TAG, "a shared task did not release the membership in %d ms", ML_RT_DETACH_TIMEOUT_MS);
    ml->stop_incomplete = true;
    return false;
}

void ml_rt_status(ml_rt_status_t *out) {
    rt_init();
    memset(out, 0, sizeof(*out));
    out->running = ml_rt_core_running(&rt.core);
    out->members = ml_rt_core_members(&rt.core);
    out->starts = __atomic_load_n(&rt.core.starts, __ATOMIC_RELAXED);
    out->stops = __atomic_load_n(&rt.core.stops, __ATOMIC_RELAXED);
    out->attach_failures = __atomic_load_n(&rt.core.attach_failures, __ATOMIC_RELAXED);
    out->detach_failures = __atomic_load_n(&rt.core.detach_failures, __ATOMIC_RELAXED);
    for (int i = 0; i < ML_RT_TASK_COUNT; i++) {
        out->stack_bytes[i] = stack_bytes[i];
        TaskHandle_t h = out->running ? ml_rt_task_handle((ml_rt_task_t)i) : NULL;
        out->stack_free[i] = h ? (uint32_t)uxTaskGetStackHighWaterMark(h) : UINT32_MAX;
        out->passes[i] = __atomic_load_n(&rt.core.mux[i].passes, __ATOMIC_RELAXED);
        out->max_service_ms[i] = __atomic_load_n(&rt.core.mux[i].max_service_ms, __ATOMIC_RELAXED);
        out->slow_services[i] = __atomic_load_n(&rt.core.mux[i].slow_services, __ATOMIC_RELAXED);
        out->detach_timeouts[i] = __atomic_load_n(&rt.core.mux[i].detach_timeouts, __ATOMIC_RELAXED);
    }
    ml_neg_status(&rt.neg, &out->negotiation);
}

TaskHandle_t ml_rt_task_handle(ml_rt_task_t which) {
    rt_init();
    if (which >= ML_RT_TASK_COUNT) return NULL;
    portENTER_CRITICAL(&rt_task_mux);
    TaskHandle_t h = rt.task[which];
    portEXIT_CRITICAL(&rt_task_mux);
    return h;       /* a diagnostics reader may still race the task's exit; it never writes through the handle */
}

typedef struct { void (*fn)(microlink_t *, void *); void *arg; } held_call_t;
static void held_thunk(void *ctx, void *arg) {
    held_call_t *c = arg;
    c->fn(ctx, c->arg);
}
void ml_rt_wg_foreach_held(void (*fn)(microlink_t *ml, void *arg), void *arg) {
    held_call_t c = { fn, arg };
    ml_mux_foreach_held(&rt.core.mux[ML_RT_TASK_WG_MGR], held_thunk, &c);
}
