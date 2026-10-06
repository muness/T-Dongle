# ADR 0023: The transparent bridge's data plane: non-blocking callbacks, the gateway's USB ring, counted drops, DFS, one task scheme, the Wi-Fi TX budget

Status: accepted for on-board validation, 2026-10-05. Backports ADR 0015 (data-plane I/O), 0016 (DFS), 0022 (USB drain priority, heap budget, amendment 2: Wi-Fi TX budget) to the **transparent bridge mode** of the unified image (`mode wifi_bridge`). Tailnet mode is unchanged. Throughput and latency effects are predictions until the board plan at the end is run.

## Context

The unified image runs either as the tailnet gateway or as the transparent Wi-Fi bridge of the original adapter (`components/tdongle_runtime/l2.c`, derived from `main/bridge.c`). The gateway got a measured data plane in ADR 0015/0016/0022; the bridge still had the first one. Code review of `l2.c` and the bridge branches of `gateway_main.c` found:

1. **Host -> Wi-Fi ran in the TinyUSB receive callback** and called `esp_wifi_internal_tx` up to 20 times with `vTaskDelay(pdMS_TO_TICKS(1))`. The TinyUSB task serves both USB directions, so whatever the Wi-Fi call did, the IN pipe stalled with it. (Measured fact worth keeping: `CONFIG_FREERTOS_HZ` is **100**, so `pdMS_TO_TICKS(1)` is 0 and the "1 ms" delay was a bare yield. The 20 retries were therefore 20 back-to-back calls microseconds apart, which cannot wait out a busy Wi-Fi TX pool: the effective behaviour was "try 20 times at once, drop silently", with the cost of 20 driver calls in the USB task. The design below does not rely on any sub-tick delay.)
2. **Wi-Fi -> host used `tinyusb_net_send_sync`** from a worker with a 20 ms timeout, up to 30 retries, and a 32-frame copy pool (48,768 B, permanent). `send_sync` goes through `usbd_defer_func`, which blocks forever when TinyUSB's event queue is full (the PR #32 finding).
3. **Every drop was silent**: no counter for a full pool, a down link, USB not ready, a refused Wi-Fi TX, the MAC filters.
4. **No DFS**: `tdongle_pm_start()` ran only in tailnet mode, the bridge sat at 240 MHz.
5. **Priorities were not a scheme**: TinyUSB was raised to 9 in tailnet mode only; the bridge's worker was at 5 and its USB task at the default.
6. **No Wi-Fi TX budget**: ADR 0022 amendment 2 installs it on the STA netif, which the bridge does not have; its frames go straight to `esp_wifi_internal_tx`.

## Decisions

### 1. Host -> Wi-Fi: a bounded hand-off to a worker (`l2.c`)

*(Sizes, the retry and the ring cap below are the first-run values; the amendment at the end replaces them after the first board A/B.)* The TinyUSB callback `tdongle_l2_host()` validates the frame, copies it into one of **16 fixed slots** (1,518 B each, 24 KB, allocated once at start) and notifies the worker `l2_wifi`; it returns. The worker calls the Wi-Fi transmit (below) and advances the consumer counter, which gives the slot back. The queue is single producer, single consumer with two free-running 32-bit counters (no lock; the slot count is a power of two so the counters may wrap, tested across the wrap).

Why this and not the alternatives:

* *A single non-blocking attempt in the callback* is the cheapest (no queue, no task, no copy) and is what the ring does for tailnet traffic where the caller holds the lwIP lock and owns no task. Here the caller is the **real-time USB task**, and the call is into a closed-source driver whose worst case nobody here has measured. A queue puts the driver call in a task that may wait without hurting anyone and keeps the TinyUSB task's per-frame cost at one `memcpy` and a task notification (microseconds), whatever the Wi-Fi side does. It also gives the retry (3) somewhere to wait, and it is the same rule as #32 for tailnet: the USB task copies and returns.
* *`malloc` + `usb_rx_budget`* (the tailnet's `usb_rx`) is right where the copy's lifetime is not ours (lwIP holds it for as long as it likes). Here the worker frees the slot within milliseconds, so a fixed array is the simpler bound: no heap lock and no fragmentation in the callback, no floor to compute, 24 KB that exist from boot instead of a pool that can be refused at the worst moment.
* *The IDF ring buffer* would add an API whose host stand-in is a mock; the 40 lines here run unchanged under ASan and TSan.

Sizing: the queue must cover the retry window at the USB OUT limit (875 B/ms): 20 ms is 17.5 KB, 11.6 full frames; 16 slots leave margin. A full queue drops the new frame and counts it (`h2w_queue_full`): the frame is dropped at the dongle exactly where TCP expects a bottleneck to drop it.

**Retry.** A refusal for buffers (`ESP_ERR_NO_MEM`: the budget's, or the driver's own pool) is retried every tick for `TDONGLE_L2_TX_RETRY_MS` = 20 ms of tick time (2 ticks at the firmware's 10 ms tick; 20 attempts at 1 ms), then the frame is dropped and counted (`h2w_tx_failed`). Any other error is final. A link change while waiting abandons the frame at once. 20 ms is below TCP's minimum retransmission timeout, below `TDONGLE_PM_ACTIVITY_HOLD_US` (asserted in `l2.c`, so the clock never drops under a waiting frame) and costs the frames behind it at most one window.

**Wi-Fi -> host** (`receive()`, the Wi-Fi RX callback, the Wi-Fi task) copies into the **ring** and frees the driver's buffer before it returns, on every path (tests count one free per call). It never waits.

### 2. Wi-Fi -> host uses the gateway's USB transmit ring

`tinyusb_net_tx_ring_send()` replaces `send_sync` and the copy pool; `tdongle_l2_release()`, the `free_tx_buffer` callback and `l2.c`'s two queues are gone. The ring is the code of ADR 0015/0022 unchanged (exactly-once hand-over since v122, link-generation flush, IN-completion drain, elastic capacity bounded by the one heap floor, the `usb_txq` CPU lock). Bridge configuration (`gateway_main.c`):

| | tailnet | bridge | why |
|---|---|---|---|
| permanent slabs | 3 (4,572 B) | **8 (12,192 B)** | the bridge's heap is the tailnet's 38 KB plus the ~68 KB the first membership would take; 8 is two full NTBs of burst plus the frames of one worker wake-up |
| elastic chunks | 10 | **12** | cap 32 slabs = 32 full frames, the original bridge's pool and the most the ring can address (`TX_MAX_SLABS`) |
| growth floors | `ML_HB_FLOOR`, `ML_ADM_LARGEST_BLOCK` | the same | one mechanism, one floor |
| gate | negotiation | none | no negotiation runs |

Permanent heap, old against new: copy pool 48,768 B + queues 832 B + worker stack 3,072 B + TCB ~340 B = **53,012 B**; now ring base 12,192 B + ring worker 1,876 B + host queue 24,288 B + forwarder 3,412 B = **41,768 B** (a static assertion in `gateway_main.c` holds the new total at or below the old one). Elastic: up to 36.5 KB more, only while the free heap stays above `ML_HB_FLOOR`.

One addition to the ring, `tinyusb_net_tx_ring_flush()`: bump the link generation and wake the worker, so frames queued under the previous Wi-Fi association are discarded by the next drain (counted `flushed_link_down`) instead of reaching the host after a link change. The same mechanism as a USB detach, requested from the producer's side. `tdongle_l2_link()` calls it after unregistering the RX callback; in-flight frames of the old association therefore cannot outlive the link change by more than the one the callback was already copying. Host -> Wi-Fi frames carry the link epoch they were queued under; the worker drops an older one (`h2w_stale`) or one queued before the link went down (`h2w_link_down_queued`).

### 3. Every drop is counted, in one place each

`tdongle_l2_stats_t` (`tdongle_l2.h`). Each frame that enters a callback ends as exactly one of:

* to the host: `w2h_forwarded`, or `invalid` (runt, over 1,514 B), `own_mac` (our own source address coming back: the host's frame echoed, filtered by design), `link_down`, `usb_not_ready`, `ring_full`;
* to Wi-Fi: `h2w_queued`, or `invalid`, `foreign_mac` (the host speaks for the STA address only; filtered by design), `link_down`, `queue_full`; and every queued frame ends as `sent`, `stale`, `link_down_queued` or `tx_failed` (with `tx_retries`, `last_tx_error`, queue depth and high-water).

The identities `frames = forwarded + the drops` and `queued = sent + stale + link_down_queued + tx_failed + depth` hold at rest and are asserted after every operation of the tests, and again on the numbers the status code prints. The ring's own counters (`dropped_full`, `dropped_link_down`, `flushed_link_down`, growth denials) and the Wi-Fi budget's (`refused_pool`, `refused_heap`, `aborted`, `flushed`, `stale`) are reported beside them.

**Where they appear.** Bridge mode serves no HTTP (`start_http` is tailnet-only), so there is no `/status` to extend: the report is the serial `status` command, as new lines only (`bridge_link`, `bridge_to_host`, `bridge_to_wifi`, `bridge_usb_ring`, `bridge_wifi_tx`, written after the established lines; nothing is appended to a line Android parses, `tools/check-android-status.py` still holds that), and, in the diagnostics build, the `bridge` command (one JSON line, keys `<section>_<name>`). One visitor (`bridge_status.inc`) lists the fields for both, so they cannot drift.

### 4. DFS in bridge mode (ADR 0016)

`tdongle_pm_start()` now runs in both modes (240/80 MHz, no light sleep). The bridge has no forwarding task that owns a lock, so:

* **The clock is raised in the callback**, before any worker runs: both callbacks call `tdongle_pm_note_activity()` (the forwarding-activity hold of #35: one atomic load while held, one lock acquire and one-shot timer after a quiet spell, released `TDONGLE_PM_ACTIVITY_HOLD_US` = 200 ms after the last note) for every frame they are about to forward.
* **Chatter does not pin the clock.** The rule `gateway_host_input` applies is applied here: a link-layer broadcast or multicast frame is forwarded but does not note activity. (The ring's `usb_txq` lock still covers it for the microseconds it is queued.) Frames that are filtered or dropped do not note either.
* **The ring brackets queued frames with `usb_txq`** (`pm_begin`/`pm_end` bound to a `tdongle_pm_burst_t`, worker-only, as in tailnet): a frame is handed to USB with the CPU at its maximum even when it was multicast.
* **The host -> Wi-Fi wait is inside the hold** (asserted at compile time), so no lock of its own is needed.

The test asserts, with the real burst and activity code over fake locks that fail on any unpaired acquire or release: idle is 80 MHz; the first unicast frame has raised the clock when the callback returns; every frame is handed to USB with the clock up; 100 multicast frames 50 ms apart never take the activity lock; a 40-frame stream takes it once; idle returns 200 ms after the last frame; acquires equal releases on both locks in every random run.

### 5. One task scheme (`gateway.h`)

Core 1, both modes, the same constants: `usb_txq` relay 10 > TinyUSB 9 > forwarder 8 > `usb_txq` heap work 6. In the tailnet mode the forwarder is `usb_routes`; in the bridge it is `l2_wifi`, and `GATEWAY_TASK_BRIDGE_PRIO/CORE` are defined as `GATEWAY_TASK_USB_ROUTES_PRIO/CORE`. TinyUSB is now 9 in both modes (it was the default 5 in the bridge): the ADR 0022 argument (the IN pipe must not wait behind forwarding work) is mode-independent, and with the receive callback no longer calling the driver the task is short. `gateway_main.c` asserts the order, the common core, the equality with `usb_routes`, and that all of it stays below the IDF system tasks (esp_timer 22) and the Wi-Fi task (23, core 0). The legacy bridge image is untouched.

### 6. The Wi-Fi TX budget, in both modes, installed once (`wifi_pins.inc`)

`wifi_pins_tx(buffer, len)` is the one transmit that charges the budget (`gw_wtx_admit`, `esp_wifi_internal_tx`, `gw_wtx_abort` on a driver error); the tailnet's netif `transmit`/`transmit_wrap` call it, and so does the bridge's worker (`tdongle_l2_config_t.wifi_tx`). `wifi_pins_install(NULL)` is the bridge's install: there is no netif to hook and no RX pin to count (a received frame is copied and freed in the callback), so the TX counters and the tx-done callback are all that apply. `wifi_pins_start()` registers the callback in both modes; `wifi_pins_link_changed()` (flush: the driver clears its queues on link down and up) now runs on both events in both modes. The accounting identity `charged = done + aborted + flushed + stale + inflight` and the heap-floor bound are those of ADR 0022 amendment 2, not restated: the code is the same code, `gw_wtx_done` stays IRAM-safe (nothing was added to the tx-done path), and the heap check is the same `ML_HB_FLOOR`. The bridge's bound is looser in practice (about 100 KB free against a 30 KB floor), so the band is rarely the limit and the pool of 16 is.

### 7. Preserved

The host speaks with the STA MAC; DHCP, ARP and IPv6 bytes cross untouched (the end-to-end test builds ARP, IPv4 and IPv6 frames of every size from 24 to 1,514 B in both directions and checks every byte and both addresses at the far end); the `mode` command and the setup paths are untouched; `tools/test_net.py` (the shared wrapper's ownership tests) passes unchanged and gains one case for the flush; tailnet-mode behaviour is unchanged (its only edit is the shared `wifi_pins_tx` extraction, covered by the existing `test_wifi_pins_hooks`).

## What the tests prove, and what they do not

`components/tdongle_runtime/tests/test_l2.c` (every branch and counter of `l2.c`, 1 ms and 10 ms ticks), `alternative/tailnet/tests/test_bridge_path.c` (the real ring, `l2.c`, `wifi_pins.inc`, burst/activity code and status counters in one translation unit over the strict mocks of `tests/mocks/net.h`: bytes both ways, ring and driver backpressure with exact capacities, link flaps, USB detach, tight and ample heap, degraded budget, DFS, status lines, then six seeds of 60,000 random operations at three configurations with every identity checked after every operation) and `test_bridge_threads.c` (seven real threads under ThreadSanitizer: the Wi-Fi task, TinyUSB, `usb_txq`, the forwarder, the driver's pp task, link flaps and the timer). The mocks assert that neither callback waits, allocates, defers or calls the Wi-Fi driver. Thirteen deliberate defects were injected into the sources to check the tests notice (a leaked driver buffer, no flush, a blocking callback, no epoch check, no abort, no clock note, an uncounted drop, an endless retry, chatter pinning the clock, a missing MAC filter, a missing flush at connect, ring flush that drops nothing, a missing counter): all are caught.

Not provable on the host: the closed-source driver's real blocking behaviour, the real RX rate, the real cost of a frequency switch, the stack the forwarder needs (it is reported: `bridge_link worker_stack_free`), and whether `esp_wifi_set_tx_done_cb` completes every frame (`wifi_tx stale` and `unmatched` say).

## Consequences

* Idle bridge CPU is 80 MHz (heat), unicast forwarding at 240 MHz; a first frame after an idle period pays the clock switch inside the callback, before the copy.
* Host -> Wi-Fi gains a queue (24 KB permanent) and a worker; the bridge loses 48,768 B of permanent pool. Net permanent heap about 11 KB lower, elastic ring up to 36.5 KB higher.
* Upload under a saturated Wi-Fi pool now drops at the queue (counted), after at most 20 ms of retry, instead of after 20 immediate calls.
* The unified image grows by 3,008 B of flash (see the PR for the table).

## Amendment 1 (2026-10-05): the first board A/B, and what changed

Board, bridge mode, iperf3 to 192.168.1.2 over en19, against main 1e7d767 (no crash):

| | main | first #45 |
|---|---|---|
| TCP up / down, Mbit/s | 4.9-5.6 / 4.0-4.2 | 6.6-6.8 / 6.6-7.2 |
| UDP 4 / 8 Mbit/s loss | 10-11% / 21-28% | 1% / 12% |
| ping avg/max idle, ms | 10 / 38 | **25 / 154** |
| ping avg/max under TCP up, ms | 24 / 63 | **52 / 86** |
| heap minimum | 113.8 KB | **70.6 KB** |

Counters after the run: ring `high_water_slabs` 32, 48,768 B, `dropped_full` 719, grow 60 / shrink 48; host to Wi-Fi `queue_full` 529, `tx_failed` 101, `tx_retries` 590, `refused_pool` 690, `last_tx_error` 257; Wi-Fi TX charged 46,306, done 46,305, aborted 1; `worker_stack_free` 1,812 (of 3,072).

**Reading.** Throughput and loss improved as designed. Load latency and the heap minimum are one finding: *standing queues are delay*. Ping under TCP upload crosses the host-to-Wi-Fi path, which held up to 16 frames (24 KB, 27 ms at the USB OUT limit) on top of the driver's own pool, where main had a bare drop; `high_water_slabs` 32 says the ring ran at its cap (55 ms of USB time) and took 36.5 KB of elastic heap with it, which is the 43 KB heap-minimum difference.

**2. Bounded standing queues (constants in `tdongle_l2.h` / `gateway_main.c`, asserted).**
* Host to Wi-Fi: 8 physical slots, a standing limit of **6 frames** (`TDONGLE_L2_HOST_QUEUE_LIMIT`) and a **sojourn limit of 20 ms** (`TDONGLE_L2_SOJOURN_MS`): a frame older than that when the worker reaches it, or still refused at that age, is dropped (`sojourn_drop`, `tx_failed`). Reasoning: the path's delay product is USB OUT (875 B/ms) times a LAN round trip of 3-10 ms = 2.6-8.8 KB; 6 frames (9 KB, 10 ms) covers the worst case and the frames of one worker wake-up, and the seventh is the sender's cue to slow down. The sojourn limit is CoDel's target reduced to its essence: a stalled link must not turn the queue into a delay line, whatever its depth. Permanent heap -12 KB.
* Wi-Fi to host (USB ring): 8 permanent + **2 elastic chunks = 12 frames** (18 KB, 21 ms of USB time; was 32 frames, 55 ms), asserted at most 25 ms of drain time. The elastic mechanism stays (it still grows from 8 to 12 under a burst and shrinks 10 s later); only its cap is time-based. The 12 frames cover a 6-frame A-MPDU burst arriving while the previous NTB is on the wire.
* Expected: load ping back toward main's 24 ms (the standing delay is now at most 10 ms in the queue plus the driver's own pool, as on main) and heap minimum back near main's, since the elastic ring cannot take 36 KB. TCP throughput has to stay within about 5% of 6.6-7.2: a drop at 6 queued frames is the same signal TCP got from the full 16-slot queue, earlier. If upload loses more than that, raise `TDONGLE_L2_HOST_QUEUE_LIMIT` to 8 (slots allow it) first; if download does, raise `GATEWAY_BRIDGE_TX_MAX_CHUNKS` to 3.

**4. `tx_failed` 101 and `last_tx_error` 257.** 257 is 0x101, `ESP_ERR_NO_MEM`, the budget's refusal (`wifi_pins_tx` returns it when 16 charges are outstanding: `refused_pool` 690, `refused_heap` 0; the driver itself never refused: `aborted` 1). The pool of 16 is full whenever the Wi-Fi link carries less than USB feeds it, which is what upload at 6.7 Mbit/s over this link is. Each refusal is an *attempt*, not a frame: 690 is about 590 retries + 101 final attempts; the 101 are the frames still refused at the end of their window (2 retries each at the 2-tick window: 202 of the 590), the other 388 retries belonged to frames that were then sent. Both are the policy working as designed, but the retry was wrong in one respect: it slept on the RTOS tick, and at `CONFIG_FREERTOS_HZ` 100 that is **10 ms**, longer than the whole 16-buffer pool takes to leave the antenna (16 x 1.5 KB at 25 Mbit/s = 8 ms). A frame refused at 16 in flight therefore left the radio idle for most of a tick, which costs upload throughput, and is consistent with the queue behind it filling (`queue_full` 529). Now: the worker retries on a **500 us esp_timer** (`TDONGLE_L2_RETRY_US`, about one frame of airtime at the Wi-Fi rate), until the frame's sojourn limit (so the retry window is what is left of the 20 ms after the queue wait, not a fresh 20 ms), and wakes early for new frames. The 20 ms window is unchanged in time; it is now 40 attempts instead of 2, each cheap (a budget check against a counter, no driver call while the pool is full). `refused_pool` will therefore be a larger number than before for the same loss: read `tx_failed` and `sojourn_drop` for frames, `refused_pool` for attempts.

**1. Review fixes.** (a) `GATEWAY_BRIDGE_TASK_STACK` 4,096 (board: 1,812 B free of 3,072; the deeper retry path and the timing counters are margin). (b) `tdongle_l2_stats` loads `tail` before `head` (head only grows, so the depth cannot wrap to 4 billion; the TSan test samples it during traffic). (c) `tdongle_l2_link(true)` flushes the ring before registering the callback, and opens `linked` last; `receive()` reads the link epoch before the link check and re-checks it after the ring accepted the frame, and when it moved (a frame that passed the old association's check and was stamped with the new generation) flushes again and counts `w2h_raced`.

**3. Idle ping, 25 ms against 10 (max 154 against 38).** What the host tests can show: the new path adds one task wake (a notification to a core-1 task, microseconds) on host to Wi-Fi, none on Wi-Fi to host (the same relay and deferral as the tailnet's), and nothing waits on the 10 ms tick when the link is idle (the tick was only in the retry path, now gone). The suspects that remain are all on-chip and cannot be separated by reading code: the clock switch inside the first note after idle, an effect of 80 MHz on the Wi-Fi driver's own processing (the Wi-Fi task and the driver run on the same core at the idle clock until the note raises it), and DFS's interaction with the radio. So this change adds the measurements and an A/B switch instead of a guess:
* `bridge_timing` (serial `status`, `bridge` report): `pm_note_us_max/sum/pm_notes` (what the clock raise costs inside the callback), `wait_us_max/sum` (host to Wi-Fi queueing per frame), `tx_us_max/sum` (the Wi-Fi transmit call), and `cold_us_max/sum/cold_starts` (Wi-Fi to host: commit to NTB). If a ping's extra 15 ms is in the dongle it is in one of these; if all stay under a millisecond it is the radio or the host.
* `pm fixed` / `pm scale` (serial, not persisted): re-runs `esp_pm_configure` with min = max = 240 or 80..240, so the same image gives both numbers in one session. Procedure: `pm fixed`, 100 idle pings (1 s apart), `pm scale`, 100 more; read `bridge_timing` between.
* If fixed 240 fixes idle ping, the trade is thermal and power for latency: options in order of preference are a higher floor (`TDONGLE_PM_MIN_MHZ` 160, which ADR 0016 measured as costing p90 205 against 149 ms at 240 on the tailnet, so not free either), a longer activity hold, or fixed 240 for the bridge only. That decision needs the A/B above, not this ADR.

## Amendment 2 (2026-10-05): the second board A/B, and USB backpressure

**Second A/B (ed60322).** Idle ping, alternating `pm fixed` / `pm scale`, 100 pings each: fixed 18.3 / 69 ms (avg / max), scale 18.2 / 128, fixed 10.2 / 165, scale 10.6 / 63; main idle avg 8.7. The mode makes no difference and the spread is airtime noise (it moves between runs, not with the clock); `pm_note_us_max` is 221 us. **Idle ping is not a DFS problem.** DFS stays on in bridge mode; the `pm fixed` / `pm scale` switch was removed again (it answered its question; the `bridge_timing` counters stay, they are cheap and say where time goes). Load: ping during TCP upload 59 ms avg / 116 max against main's 18 / 35 in the same session; TCP up 5.9-6.6 and down 5.4-7.2 against main's 5.1-5.2 and 4.0-4.6. `wait_us_max` 19,995 (frames sat the full sojourn limit), Wi-Fi TX `high_water` 16, `refused_pool` 5,051, `tx_retries` 4,848, `sojourn_drop` 93, `tx_failed` 203. Download: UDP 4 Mbit/s 5% loss (1% at 32 ring frames), 8 Mbit/s 37%, `ring_full` 2,355 at the 12-frame cap.

**Diagnosis.** Amendment 1 shrank the queue and made frames wait less badly; it did not remove the queue. Main's low load latency was largely an accident: it blocked inside the USB OUT callback, the host was NAKed, and the standing queue stayed on the Mac, whose per-flow interface queues let a ping bypass the bulk flow. The bridge now absorbed frames into one FIFO in the dongle (3 to 6 frames of host queue, then the driver's 16 buffers), all of it in front of the ping, and dropping at a sojourn limit only turns that queue into loss. The standing queue has to be where the sender can see it: on the host, by flow control.

**The class driver already supports it.** `managed_components/espressif__tinyusb/src/class/net/ncm_device.c`: `recv_transfer_datagram_to_glue_logic()` offers one datagram to `tud_network_recv_cb()` and advances only if it returns `true`; on `false` the datagram (and the rest of its NTB) stays where it is, and `tud_network_recv_renew()` offers it again. `recv_try_to_start_new_reception()` re-arms the OUT endpoint only while a free receive NTB exists (`CFG_TUD_NCM_OUT_NTB_N` = 3 here), so when held NTBs fill the pool the endpoint stops being re-armed and the host sees NAKs. Our glue (`tinyusb_net.c`) returned `true` always and called renew itself, which is why none of this was in play. So:

* **`tud_network_recv_cb`** returns `false` and does not renew when the receive callback returns `TUSB_NET_RX_HOLD` (0x10C, `ESP_ERR_NOT_FINISHED`); any other result is "consumed or dropped by the callee" as before (the tailnet's `usb_rx` and the legacy bridge never return it: unchanged).
* **`tinyusb_net_rx_resume()`** (any task, coalescing) defers `tud_network_recv_renew()` to the TinyUSB task (`usbd_defer_func`), from the worker that holds no lock.
* **`tdongle_l2_host()`** returns `TUSB_NET_RX_HOLD` when `TDONGLE_L2_HOST_QUEUE_LIMIT` (**3**) frames stand in the queue (4 slots). Held offers are not frames (`h2w_held`, outside the identities); nothing is dropped. The worker asks for the datagram again (`rx_resume`) when it has drained to `TDONGLE_L2_HOST_RESUME_DEPTH` (**1**), one frame of runway, `h2w_resumes`.
* **No lost wake-up.** The callback publishes `held` (seq_cst) and then re-reads the tail: if the worker drained in between, the callback either takes the room (it cleared `held` itself) or finds the worker already took the flag, in which case it still answers HOLD and the owed resume re-offers this datagram. A stale flag costs one harmless resume, never a missed one (unit test, both interleavings).
* **Reset, detach, link flap cannot wedge it.** `netd_reset()` re-initialises the class receive state, so a renew after a reset finds nothing pending and does nothing, and the next `SET_INTERFACE` renews by itself; our `held` may be stale and is released by the next drain. A Wi-Fi link change releases `held` and resumes (the backlog is stale and is dropped by name). A stalled Wi-Fi link: the worker waits for the radio's allowance, the sojourn limit frees the queue frame by frame, and each drain resumes.

**Standing queue in the dongle now** = 3 frames (host queue) + the class driver's NTBs (3 x 3,200 B, the host's NAK point) + the radio's allowance. **`GATEWAY_BRIDGE_WIFI_TX_INFLIGHT` = 6** (was the driver's 16; `tx_limit` in the budget, `GW_WTX_POOL` is now "at the limit"): the Wi-Fi TX block-ack window is 6 (`CONFIG_ESP_WIFI_TX_BA_WIN`), so 6 in flight is one full aggregate and keeps the radio busy; each frame beyond is queueing delay (16 frames at the measured ~6.5 Mbit/s are 30 ms, 6 are 11 ms). It is asserted at least the TX band (4) and the BA window and at most the pool. The worker does not call `wifi_tx` while the allowance is full (`wifi_room`): it waits on the 500 us timer, so a full allowance is waiting, not refusal: `refused_pool` and `sojourn_drop` should read about 0 in steady state, `tx_retries` now counts waits. The sojourn limit (20 ms) remains as the safety net for a stalled link.

**Download ring: 20 frames** (8 + 6 elastic chunks, 30 KB, 35 ms of USB time, asserted at most 36 ms). Evidence: 32 frames cost 55 ms and heap (and, with the 16-slot host queue, ping); 12 lost 5% / 37% at 4 / 8 Mbit/s with `ring_full` 2,355. Nothing can backpressure Wi-Fi, so on this direction the ring is the burst absorber, and its delay exists only while a download runs; it is not in the ping's way during upload (ACKs are small records packed into slabs). 20 absorbs two A-MPDU bursts; tune from `dropped_full` and `high_water_slabs`.

**Expected on the board** (target: load ping at or below main's 18 ms with TCP up at least 6.3): the Mac holds the queue; the dongle holds at most 3 + about 4 (NTBs) + 6 frames, mostly fewer; `sojourn_drop`, `tx_failed` and `refused_pool` about 0; `h2w_held` and `h2w_resumes` large and about equal (they are the backpressure working); `wait_us_max` a few ms. If upload falls short of 6.3, raise the queue limit to 4 (4 slots) or the allowance to 8 before anything else; if ping stays high, `wait_us_*` and `tx_us_*` say whether it is the dongle.

**Tests.** `tests/mocks/net_ring_cases.c`: held datagram, no renew, coalesced resume. `test_l2.c`: hold at the limit, resume exactly once at the resume depth, both interleavings, link-change release, a full allowance waited for without calling the driver. `test_bridge_path.c` models the class driver's receive side (NTBs fill, NAK, held datagram kept, re-entrant renew rule) around the real `tud_network_recv_cb` and runs: nothing drains (the dongle takes exactly 3 + 6 and NAKs the rest, drops nothing); a host that outruns the worker for 1,200 frames (no `sojourn_drop`, no `tx_failed`, no refusal, every acknowledged frame reaches the air once in order, queue never above 3, in-flight never above 6); a link flap while held; a USB reset while held; and the odd-numbered soak seeds send host frames through the class driver. Every counter identity is checked after every operation; the threads test (TSan) is unchanged in shape.

## Board plan (bridge mode; `mode wifi_bridge` over serial, then back to `mode tailnet_gateway`)

Server 192.168.1.2 (`iperf3 -s`), client bound to the bridged interface's IP (en19):

1. Before: serial `status`, `pm` (cpu_mhz, locks), `bridge` (diagnostics build). Record `minimum_free_memory` baseline.
2. TCP up and down, three runs each (`-t 30`; `-R` for down). Expect at least the last bridge numbers (ADR 0022: 4.3-5.0 Mbit/s down, about 6 Mbit/s UDP) and upload not below them. `bridge_to_host ring_full` and `bridge_to_wifi queue_full` should be 0 or small and explained; `bridge_usb_ring grow_events` rises and `shrink_events` follows 10 s after the run.
3. UDP 4 and 8 Mbit/s, both directions (`-u -b 4M`, `-b 8M`, with and without `-R`). Loss should match the counters: lost datagrams = ring_full + queue_full + tx_failed + flushed.
4. Ping latency (idle, then under load): idle p50 against the previous bridge image with DFS off; the first ping after 2 s of idle is the clock-switch cost.
5. During load `pm` must read `cpu_mhz=240`, and 1-2 s after it `80`; `pm_lock name=fwd_activity` acquires small and equal to releases when idle; `usb_txq` the same.
6. After each run: `status` for `bridge_*`, the identities from ADR 0023 section 3 on the printed numbers; `bridge_wifi_tx`: `tx_done_cb=1`, `stale` and `unmatched` near 0, `inflight` 0 at rest, `refused_*` explained; `bridge_link worker_stack_free` above 1,000 (stack 3,072 B); `minimum_free_memory` against the baseline (permanent heap is about 11 KB lower than before).
7. Toggle Wi-Fi (AP off/on) during a transfer: carrier drops and returns, `flushed_link_down` and `link_down_queued` rise, no crash. Unplug and replug USB during a transfer: `usb_not_ready` rises.
8. Crash check: `boot-status` shows no new crash record; then `mode tailnet_gateway` and confirm tailnet mode still passes its own checks (`pm`, `status`).
