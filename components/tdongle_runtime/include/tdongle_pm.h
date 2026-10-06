#pragma once
/* Dynamic frequency scaling for the gateway: 240 MHz while forwarding work is pending, 80 MHz when idle.
 * Design, evidence and the measurement plan: alternative/tailnet/docs/adr/0016-dfs-power-management.md.
 *
 * tdongle_pm_start() configures esp_pm. Each forwarding task owns one tdongle_pm_burst_t registered here: a
 * counted ESP_PM_CPU_FREQ_MAX lock held only while that task has work (see tdongle_pm_burst.h for the rules).
 * Without CONFIG_PM_ENABLE (legacy bridge, host builds) everything still compiles and counts, and holds no lock. */
#include "esp_err.h"
#include "tdongle_pm_burst.h"
#include <stddef.h>

#define TDONGLE_PM_MAX_MHZ 240
/* Never below 80: the APB clock (UART, SPI LCD, the Wi-Fi driver's ESP_PM_APB_FREQ_MAX lock) is 80 MHz and drops
 * with the CPU below that. */
#define TDONGLE_PM_MIN_MHZ 80
#define TDONGLE_PM_MAX_BURSTS 8
/* How long the clock stays at maximum after the last forwarded packet (tdongle_pm_note_activity). Long enough to
 * bridge the gaps inside a stream and the fairness sleeps, short enough that the chip cools within a fraction of a
 * second of the last packet. */
#define TDONGLE_PM_ACTIVITY_HOLD_US 200000

typedef struct {
    bool scaling;                        /* esp_pm_configure succeeded: the CPU moves between min and max */
    bool fixed;                          /* tdongle_pm_set_fixed(true): min = max = 240, scaling kept configured (an A/B switch) */
    int configure_error;                 /* esp_err_t of the last tdongle_pm_start (0 = ESP_OK) */
    uint32_t max_mhz, min_mhz;           /* as configured; 0 when scaling is off */
    uint32_t cpu_mhz;                    /* the clock right now */
    uint32_t lock_create_failures;
    unsigned bursts;
    tdongle_pm_burst_stats_t burst[TDONGLE_PM_MAX_BURSTS];
} tdongle_pm_status_t;

/* Enable scaling (max 240, min 80 MHz, no light sleep). On failure it logs and returns the error: the CPU then stays
 * at its boot frequency (CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ, 240 in the gateway image), i.e. fixed at the maximum.
 * Call once, before the forwarding tasks start. */
esp_err_t tdongle_pm_start(void);

/* A/B switch for latency work (serial `pm fixed` / `pm scale`): re-run esp_pm_configure with the minimum raised to the maximum (the CPU stays
 * at 240 MHz, every lock still counts) or back to 80..240. Not persisted: a reboot is back to scaling. ESP_ERR_INVALID_STATE when scaling
 * never started. */
esp_err_t tdongle_pm_set_fixed(bool fixed);

/* Bind `burst` to a new CPU-frequency-max lock called `name` and list it in the status. Idempotent per object.
 * False: the registry is full or the lock could not be created (the burst then counts but holds nothing). */
bool tdongle_pm_burst_register(tdongle_pm_burst_t *burst, const char *name);

/* A packet is passing through a stage that has no queue of ours to wait on (the lwIP input hook: every forwarded
 * packet, from USB or from Wi-Fi, goes through it). Task context, cheap (one atomic load while active), a no-op while
 * scaling is off. The first call after a quiet spell raises the clock for every core; ADR 0016. */
void tdongle_pm_note_activity(void);

void tdongle_pm_status(tdongle_pm_status_t *out);

/* esp_pm_dump_locks() into `buf`, truncated and NUL terminated. Returns the length. */
size_t tdongle_pm_dump_locks(char *buf, size_t size);
