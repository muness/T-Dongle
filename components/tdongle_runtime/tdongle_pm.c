#include "tdongle_pm.h"
#include "esp_log.h"
#include "esp_pm.h"
#include "esp_timer.h"
#include "esp_private/esp_clk.h"
#include "freertos/FreeRTOS.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "tdongle_pm";

static struct {
    bool scaling;
    int configure_error;
    uint32_t lock_create_failures;
    struct {
        tdongle_pm_burst_t *burst;
        esp_pm_lock_handle_t lock;
    } slot[TDONGLE_PM_MAX_BURSTS];
    unsigned used;
} pm;
static portMUX_TYPE pm_mux = portMUX_INITIALIZER_UNLOCKED;

/* Forwarding activity (tdongle_pm.h): the lwIP input hook notes every unicast packet, a one-shot timer drops the
 * lock TDONGLE_PM_ACTIVITY_HOLD_US after the last one. */
static tdongle_pm_burst_t activity_burst;
static tdongle_pm_activity_t activity;
static esp_timer_handle_t activity_timer;
static volatile bool activity_ready;
static void activity_arm(void *ctx, uint32_t delay_us) {
    (void)ctx;
    esp_timer_start_once(activity_timer, delay_us);     /* already armed: ESP_ERR_INVALID_STATE, nothing to do */
}
static void activity_fire(void *arg) {
    (void)arg;
    tdongle_pm_activity_tick(&activity, (uint32_t)esp_timer_get_time());
}

esp_err_t tdongle_pm_start(void) {
    const esp_pm_config_t config = {
        .max_freq_mhz = TDONGLE_PM_MAX_MHZ,
        .min_freq_mhz = TDONGLE_PM_MIN_MHZ,
        .light_sleep_enable = false,        /* USB must stay enumerated: no tickless idle, no light sleep */
    };
    esp_err_t err = esp_pm_configure(&config);
    pm.configure_error = err;
    pm.scaling = err == ESP_OK;
    if (err != ESP_OK)
        ESP_LOGE(TAG, "esp_pm_configure failed (%s): running fixed at the boot frequency, %d MHz", esp_err_to_name(err),
                 (int)(esp_clk_cpu_freq() / 1000000));
    else {
        ESP_LOGI(TAG, "DFS %d..%d MHz, light sleep off", TDONGLE_PM_MIN_MHZ, TDONGLE_PM_MAX_MHZ);
        const esp_timer_create_args_t args = { .callback = activity_fire, .name = "pm_activity" };
        if (tdongle_pm_burst_register(&activity_burst, "fwd_activity") && esp_timer_create(&args, &activity_timer) == ESP_OK) {
            tdongle_pm_activity_init(&activity, &activity_burst, TDONGLE_PM_ACTIVITY_HOLD_US, activity_arm, NULL);
            activity_ready = true;
        } else
            ESP_LOGE(TAG, "forwarding activity hold unavailable: hops outside the shared tasks run at the idle clock");
    }
    return err;
}

/* The backend context is the slot's lock handle. While scaling is off the lock is not taken: there is nothing to
 * hold, the CPU is already fixed. A burst begun before tdongle_pm_start and ended after it would hold nothing at
 * the begin and release nothing at the end only if scaling flips between them, which start-once-before-tasks rules
 * out; the release below is guarded by the same flag for that reason. */
static bool backend_acquire(void *ctx) {
    esp_pm_lock_handle_t lock = *(esp_pm_lock_handle_t *)ctx;
    if (!pm.scaling) return true;
    return lock && esp_pm_lock_acquire(lock) == ESP_OK;
}
static void backend_release(void *ctx) {
    esp_pm_lock_handle_t lock = *(esp_pm_lock_handle_t *)ctx;
    if (pm.scaling && lock) esp_pm_lock_release(lock);
}
static uint32_t backend_now_us(void) { return (uint32_t)esp_timer_get_time(); }
static bool backend_in_isr(void) { return xPortInIsrContext(); }
static const tdongle_pm_ops_t backend = { backend_acquire, backend_release, backend_now_us, backend_in_isr };

bool tdongle_pm_burst_register(tdongle_pm_burst_t *burst, const char *name) {
    int index = -1;
    portENTER_CRITICAL(&pm_mux);
    for (unsigned i = 0; i < pm.used; i++)
        if (pm.slot[i].burst == burst) { portEXIT_CRITICAL(&pm_mux); return true; }
    if (pm.used < TDONGLE_PM_MAX_BURSTS) index = (int)pm.used++;
    portEXIT_CRITICAL(&pm_mux);
    if (index < 0) {
        ESP_LOGE(TAG, "no slot for lock %s", name);
        tdongle_pm_burst_init(burst, name, NULL, NULL);
        return false;
    }
    esp_pm_lock_handle_t lock = NULL;
    esp_err_t err = esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, name, &lock);
    if (err != ESP_OK && err != ESP_ERR_NOT_SUPPORTED) {
        ESP_LOGE(TAG, "lock %s: %s", name, esp_err_to_name(err));
        pm.lock_create_failures++;
    }
    pm.slot[index].lock = lock;
    tdongle_pm_burst_init(burst, name, &backend, &pm.slot[index].lock);
    pm.slot[index].burst = burst;        /* published last: status never sees a half-built slot */
    return lock != NULL || err == ESP_ERR_NOT_SUPPORTED;
}

void tdongle_pm_note_activity(void) {
    if (activity_ready) tdongle_pm_activity_note(&activity, (uint32_t)esp_timer_get_time());
}

void tdongle_pm_status(tdongle_pm_status_t *out) {
    memset(out, 0, sizeof(*out));
    out->scaling = pm.scaling;
    out->configure_error = pm.configure_error;
    out->max_mhz = pm.scaling ? TDONGLE_PM_MAX_MHZ : 0;
    out->min_mhz = pm.scaling ? TDONGLE_PM_MIN_MHZ : 0;
    out->cpu_mhz = esp_clk_cpu_freq() / 1000000;
    out->lock_create_failures = pm.lock_create_failures;
    for (unsigned i = 0; i < pm.used && i < TDONGLE_PM_MAX_BURSTS; i++) {
        if (!pm.slot[i].burst) continue;
        tdongle_pm_burst_stats(pm.slot[i].burst, &out->burst[out->bursts++]);
    }
}

size_t tdongle_pm_dump_locks(char *buf, size_t size) {
    if (!buf || size == 0) return 0;
    buf[0] = 0;
#if CONFIG_PM_ENABLE
    FILE *f = fmemopen(buf, size, "w");
    if (!f) return 0;
    esp_pm_dump_locks(f);
    fclose(f);                           /* NUL terminates when there is room, else the buffer is full */
    buf[size - 1] = 0;
    return strlen(buf);
#else
    return 0;
#endif
}
