# ADR 0016: CPU frequency scaling (240/80 MHz) with forwarding PM locks; Wi-Fi power save off

Status: accepted for on-board validation, 2026-10-05 (owner-approved, epic #22). Follows ADR 0013 (shared runtime) and ADR 0015 (data-plane I/O). Nothing here has been measured on the board with scaling on; the plan is at the end.

## Context

Board measurements, 2026-10-05:

| Change | Result |
|---|---|
| CPU fixed at 240 MHz instead of 160 MHz | ping p90 205 -> 149 ms, max 508 -> 222 ms, UDP +14%, TCP unchanged (the board is not CPU-bound for TCP) |
| `WIFI_PS_NONE` instead of the IDF default `WIFI_PS_MIN_MODEM` | ping p50 126 -> 48 ms (waiting for the DTIM beacon adds about 80 ms to the median), throughput unchanged |

Two things follow. The latency tail wants a fast CPU while packets are moving. An idle gateway does not need one: 240 MHz all the time costs heat (the owner's acceptance criterion is a lower idle chip temperature). The gateway never called `esp_wifi_set_ps`, so it ran with modem sleep; the legacy bridge (`main/bridge.c`) already uses `WIFI_PS_NONE`.

## Decision

### A. Dynamic frequency scaling, no light sleep

`alternative/tailnet/sdkconfig.defaults`: `CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240=y`, `CONFIG_PM_ENABLE=y`, `CONFIG_FREERTOS_USE_TICKLESS_IDLE=n`.

`tdongle_pm_start()` (components/tdongle_runtime/tdongle_pm.c, called from `app_main` once the mode is known) runs `esp_pm_configure()` with max 240 MHz, min 80 MHz, `light_sleep_enable = false`.

- **Why 80 is the floor.** 80 MHz is the APB clock. Below it the APB drops with the CPU, which breaks UART and SPI LCD timing and the Wi-Fi driver's own `ESP_PM_APB_FREQ_MAX` lock (esp_wifi/src/wifi_init.c), which on the S3 is satisfied at 80 MHz. So Wi-Fi never forces the CPU above 80.
- **Why no light sleep.** USB must stay enumerated and the CDC/NCM links must answer at any time. Tickless idle and light sleep are off, so DFS is the only power state.
- **Fail safe.** If `esp_pm_configure()` fails, `tdongle_pm_start()` logs, reports the error in `/status` (`power.configure_error`) and the CPU stays at the boot frequency, 240 MHz: fixed at the maximum. The locks then count but take nothing.
- **Transparent bridge mode of the unified image.** Scaling is configured only in tailnet mode. The bridge mode forwards from Wi-Fi and USB callbacks that hold no lock, so it stays fixed at 240 MHz. The archived legacy build (`TDONGLE_LEGACY_BRIDGE`) does not link `tdongle_runtime` and its sdkconfig is untouched.

### B. One helper: `tdongle_pm_burst_t`

`components/tdongle_runtime/tdongle_pm_burst.{h,c}` is portable C (a counter and two callbacks) so the host tests run the real logic against a fake lock. `tdongle_pm.c` binds it to an `ESP_PM_CPU_FREQ_MAX` lock.

```
begin()  depth 0 -> 1 : esp_pm_lock_acquire     (nested calls only count)
end()    depth 1 -> 0 : esp_pm_lock_release
release_all()         : closes whatever is open (task exit)
```

Rules, each enforced in the helper or by where the calls sit:

1. **Task context only.** `begin`/`end` refuse in an interrupt (`xPortInIsrContext`) and count `isr_rejects`. Nothing in an ISR or in a producer (the lwIP hook, the USB callbacks) takes a lock.
2. **Held while work is being processed, never across a wait.** Each loop ends its section before it blocks (`ulTaskNotifyTake`, `select`, `xQueueReceive` on an empty queue, `vTaskDelay`). An idle task therefore holds nothing, whatever the wait length.
3. **No leaks.** An unbalanced `end` is ignored and counted (`underflows`). Every task that can exit calls `release_all` first (`rt_task_exit` for the three shared tasks, which are deleted when the last membership leaves and recreated by the next). The lock objects are static and outlive restarts of the tasks. A refused acquire is counted (`backend_failures`) and leaves the depth balanced.
4. **A counting backend.** `esp_pm_lock` is itself counted, so an interleaving of two tasks on one object still balances the backend (one acquire per 0->1, one release per 1->0). In practice every object has one owning task.

| Task | Lock | Held |
|---|---|---|
| `ml_wg_mgr` (shared) | `ml_wg_mgr` | for each `ml_mux_pass`, not while it waits for a wake-up or the next timer |
| `ml_derp` (shared) | `ml_derp` | for each pass (connect steps, relay read, relay write), not while it waits |
| `ml_net_io` (shared) | `ml_net_io` | while ready UDP sockets are drained, not during the 50 ms `select` |
| `usb_routes` (router.c) | `usb_routes` | from the first dequeued packet until the queue is empty (also across `hold_service` and an alias fill); released before the fairness `vTaskDelay(1)` |
| `usb_txq` (tinyusb_net.c) | by the USB TX ring change | same contract; use `tdongle_pm_burst_register` and `begin`/`end` around the drain |

**Not locked, on purpose.**

- *Console and setup HTTP* (`gateway_control`, the setup server, `/status`): human-paced, a few packets a second at most; the extra latency of 80 MHz is invisible and holding 240 MHz for a page load would only cost heat.
- *`coord` tasks (control plane)*: the Noise handshake and map fetch are seconds-long exchanges bounded by network round trips. At 80 MHz the X25519 and TLS work costs time to join, not forwarding latency. If the time to a connected membership turns out to matter, wrap the connect phase in a burst (one line, same helper).
- *The `manager` task, the display tick, SNTP, DNS*: periodic housekeeping.

**Known gap, to be measured.** The lwIP `tcpip` task (NAT of Wi-Fi to USB, the lwIP hook that feeds `usb_routes`) and the Wi-Fi driver tasks hold no lock of ours. Forwarded traffic that never reaches a shared task (plain NAT) is processed at whatever the clock is, which may be 80 MHz if no forwarding task is busy. The first on-board run must compare NAT throughput and latency with the fixed-240 build; if it regresses, the fix is a burst held from the hook's enqueue to `tcpip` drain, not a higher floor.

**Cost of a section.** `esp_pm_lock_acquire` switches the clock inline (about tens of microseconds, plus a cross-core interrupt so the other core re-bases its tick compare). The `ml_derp` loop wakes every `ML_DERP_POLL_MS` (10 ms) while a relay is up and brackets each pass, so an idle gateway with a relay up takes about 100 acquire/release pairs a second. `power.locks.ml_derp.held_us` shows what that costs in time at 240 MHz. If it is more than a few percent, gate the derp section on the pass having read or written a frame (a follow-up, measured first).

### C. Wi-Fi power save off

`esp_wifi_set_ps(WIFI_PS_NONE)` right after `esp_wifi_start()` in `start_wifi`, for both modes of the unified image, matching the bridge. Failure is logged and not fatal. `power.wifi_ps` in `/status` reports the mode in force (0 = none). It costs radio idle current, not CPU frequency; the two settings are independent.

### D. Diagnostics

- `/status` gains a `power` object: `scaling`, `cpu_mhz` (the clock when the request was served), `max_mhz`, `min_mhz`, `configure_error`, `lock_create_failures`, `wifi_ps`, and per lock `depth`, `acquires`, `releases`, `held_us` (wraps at 71.6 min; difference two readings), `max_depth`, `underflows`, `forced_releases`, `backend_failures`, `isr_rejects`. `underflows`, `forced_releases` and `backend_failures` must stay 0 in normal operation.
- Serial `pm` prints the same, plus IDF's own `esp_pm_dump_locks()` table into a 768 B stack buffer (truncated). The `capabilities` line lists `power_report`.

### E. Temperature sensor semantics

`tdongle_temperature_sample()` runs every ten seconds from the `manager` task and re-reads the sensor each time (the driver is enabled, read and disabled per sample). `current` is a fresh reading, not a cached or peak value; `peak` is a separate field (highest since boot).

The repeated 61.9 is the sensor's resolution. The S3 driver returns whole degrees minus an eFuse offset (`tsens_raw - deltaT/10`, esp_driver_tsens/src/temperature_sensor.c), so readings move in steps of exactly 1 C and 61.9 recurs whenever the die sits in that degree. Changes made: `samples`, `age_ms` (snapshot time minus last sample) and `changed_at_uptime_ms` are reported in `/status` and the serial `status` line, with `step_tenths_c` = 10, so a coordinator can tell a live sensor on a flat temperature (age under 10 s, samples rising) from a stale one. The first-sample test for the peak now uses the sample count instead of `sampled_at_ms == 0`. Because of the 1 C step, idle-versus-load comparisons need a few degrees of difference to show; use the sample series, not single readings.

## Consequences

- Image and heap, release image against its base (cc72801): flash code +5,560 B, flash data +1,432 B, internal RAM (DIRAM) +1,236 B (`.bss` +424, IRAM-resident PM code +764, `.data` +48). Boot free heap therefore falls by about 1.2 KB plus four small lock objects and the IDF PM internals allocated at run time (not measurable without the board; the coordinator should compare `free_heap` at boot). The diagnostics image adds the trace facility and run-time statistics for the `cpu` command (tools/cpu_profile.py); the release image does not.
- A held lock raises the clock for every core, not just the task's: while `usb_routes` is busy on core 1 the whole chip, including Wi-Fi on core 0, runs at 240 MHz. That is the intent.
- Forwarding latency now includes a clock switch when a packet arrives at an idle gateway. It is small against the 48 ms median, but it is the first thing to look at in the p50 under light load.

## Validation

Host: `components/tdongle_runtime/tests/test_pm_burst.c` (nesting, error paths, interrupt refusal, task exit, a 200,000-step randomised comparison with a reference model, four threads under ASan/UBSan and TSan), the temperature sampling assertions in `test_sensors.c`, and the `/status` JSON in `tests/test_status_stream.c`.

On the board (coordinator), each run against the fixed-240 build (`CONFIG_PM_ENABLE` off, or `power.scaling` false) from the same commit:

1. Idle, 10 minutes after the tailnet is up: serial `pm` or `/status` `power.cpu_mhz` reads 80; `ml_derp.held_us` duty (difference over uptime) under a few percent; `forced_releases`, `underflows`, `backend_failures` all 0.
2. Under load (iperf3 through the tunnel, both directions, TCP and UDP): `cpu_mhz` reads 240 during the transfer and returns to 80 within seconds after it; ping p50/p90/max under idle and under load no worse than the fixed-240 build; iperf throughput within noise of fixed 240 (UDP +14% over 160 MHz is the bar).
3. NAT-only traffic (no tailnet peer): the `tcpip` gap above. Compare against fixed 240.
4. Idle chip temperature, sampled every 10 s for 10 minutes after 10 minutes of settle, scaling on against fixed 240, same ambient and orientation; expect a lower plateau of a few degrees, in 1 C steps.
5. Wi-Fi: `power.wifi_ps` is 0; ping p50 near 48 ms idle.
6. USB: unplug and replug, and a 30 minute soak with the display on: the device stays enumerated and `/status` answers (no light sleep).
