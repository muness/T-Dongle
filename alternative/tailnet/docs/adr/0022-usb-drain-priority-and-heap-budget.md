# ADR 0022: USB transmit drain at the bridge's rate (task priority, not NTB size) and one heap budget for everything that grows under traffic

Status: accepted for on-board validation, 2026-10-05. **Nothing here has been measured on the board.** The host work establishes structure (what runs when, what a floor guarantees, what a pipe can carry); every number about the board's behaviour is a prediction with a stated refutation. Follows ADR 0015 (data-plane I/O, elastic ring), 0016 (PM), 0019/0020 (inbound loss and pipeline), 0021 (`ML_ADM_NEG_PEAK_BYTES` 13,500, elastic floor 29,884 B).

## Context: two board measurements

Diagnostics build, UDP `iperf3 -R` tailnet to USB host, `-l 1200`, 10 s.

* **A. The USB side drains 2.6 Mbit/s in tailnet mode.** At 6 Mbit/s offered: `wg.rx_delivered` 5,293, `route.forwarded_in` 2,681, `usb.tx_dropped_full` 2,613 (ring full), `usb_tx` 5,306. The legacy bridge sustains 4.3-5.0 Mbit/s TCP down and ~6 Mbit/s UDP over the same NCM link.
* **B. Minimum free heap 3,040-3,140 B** during the same flood, in release builds before and after the inbound pipeline PR (boot free ~117 KB, steady 36-38 KB). The ring (floor 32,384 B then) and the WireGuard receive queue (floor 16,384 B) both have floors, and still the heap went to the allocator's failure point.

## A. Why the drain is slow

### What the NCM class driver does (managed `espressif/tinyusb` `ncm_device.c`, read in full for this)

* `tud_network_xmit()` copies one datagram into the "glue" NTB and calls `xmit_start_if_possible()`: **if the IN endpoint is idle it ships that NTB at once**, with however many datagrams it holds (often one). While a transfer is in flight, further datagrams join the glue NTB until the next does not fit (`xmit_requested_datagram_fits_into_current_ntb`: size, or 8 datagrams), when it moves to the ready list; with all `CFG_TUD_NCM_IN_NTB_N` = 2 buffers taken `tud_network_can_xmit()` is false.
* The NTB in flight is the only thing on the bus. When it completes, the controller interrupt queues an event; **until the TinyUSB task has run `netd_xfer_cb`, the next NTB is not started and the host's IN polls are NAKed.** `netd_xfer_cb` starts the ready NTB first; our wrapper (`__wrap_netd_xfer_cb`, ADR 0015) then drains the ring into the freed one.
* So the pipe is `cycle = bus time of one NTB + idle time until the TinyUSB task runs`, and `rate = datagrams per NTB / cycle`. Bus time at full speed: 64 B packets, 19 per 1 ms frame; a 2,540 B NTB (two 1,242 B datagrams in a 3,200 B NTB, what `-l 1200` fills) is 2.1 ms. A host behind a transaction translator retries a NAKed bulk IN on the next 1 ms frame, so the idle part is the wake latency rounded up to whole frames.

### Root cause: the TinyUSB task (priority 5) and the `usb_txq` relay (6) were below wg_mgr (7) and usb_routes (8) on the same core

ADR 0015 estimated the endpoint idle between transfers at "about 100-200 us (an estimate, not a measurement)" and sized the NTB on it. That assumed the TinyUSB task runs promptly after the interrupt. On core 1 it cannot while wg_mgr is runnable: at 6 Mbit/s offered wg_mgr spends ~1.3 ms per datagram on ~625 datagrams a second (ADR 0020), i.e. most of the core, in runs of up to eight datagrams (~10 ms). Two consequences, both from priority:

1. Each IN completion waits for the end of a decrypt run before the next NTB starts. `tools/usb_drain_model.py` with 2 datagrams per NTB and a wake latency L: L = 0: 9.4 Mbit/s; L = 1 ms: 6.4; L = 3 ms: 3.9; **L = 6 ms: 2.45 Mbit/s, the board's 2.6** (cycle 2.1 ms bus + ~5-6 ms wait; 270 frames/s = 135 NTBs/s = 7.4 ms per NTB).
2. The first frame of a burst is committed by wg_mgr (7), the worker that must wake the TinyUSB task is at 6: it too runs only when wg_mgr blocks, so a burst of eight frames waits for its own decrypt run to end before the pipe even starts.

The bridge has nothing competing on that core (its frames come from the Wi-Fi task on core 0 and a lightly loaded worker), so L is microseconds and the same 2 x 3,200 B NTBs carry 6 Mbit/s. That is also why NTB size is the wrong first lever: with L = 0 every NTB size from 3,200 to 6,400 B gives 9.4-9.6 Mbit/s.

What ADR 0015's loop already did right and is unchanged: every IN completion drains the ring in the TinyUSB task (no deferral, no worker in the steady state), each drain pass fills the freed NTB with as many queued datagrams as fit (`tx_drain` loops until `can_xmit` is false), exactly-once release, link-generation flush, elastic reclaim and PM hooks.

### Design

| | before | now |
|---|---|---|
| TinyUSB task (tailnet mode only; the legacy bridge keeps 5) | 5 | **9** |
| `usb_txq` relay (notify, then `usbd_defer_func`) | 6 | **10** |
| `usb_txq` growth (the largest-block walks, the allocation, the gate) | 6 | **6** (it drops there with `vTaskPrioritySet` only for a pass that is about to grow, `tinyusb_net_tx_config_t.work_priority`); idle shrink and retire stay at 10 |
| usb_routes / wg_mgr / coord | 8 / 7 / 5 | unchanged |

Order on core 1: usb_txq relay 10 > TinyUSB 9 > usb_routes 8 > wg_mgr 7 > usb_txq heap work 6 > coord 5, asserted at build time (`gateway_main.c`); all below the IDF system tasks (esp_timer 22, ipc 24). Cost to forwarding: the TinyUSB task's own work is an NTB copy per IN event (2-5 datagrams) and, for upload, a `malloc + memcpy` per received datagram: about 3 % of the core at the 12 Mbit/s bus limit. The relay does a notify wake and a defer: a few microseconds per burst edge. Growth stays below wg_mgr because it does up to two `heap_caps_get_largest_free_block()` walks per chunk with the heap lock held, which at 10 would be exactly the delay the change removes. Review (PR #42) narrowed the demotion to a pass that is about to grow: the first version also demoted every pass while an elastic chunk existed (always, during a flood), and a worker that lowers its priority with wg_mgr or usb_routes runnable yields at the call, so the relay was not served again until they blocked, the starvation this ADR removes, to protect work (retire, one idle free) that is microseconds inside a critical section no priority affects. While a growth does run demoted the relay waits for it; the TinyUSB task keeps draining on every IN completion, so only a cold start (empty to non-empty) can wait, and `cold_us_max` shows it. Locks held across the demotion: none (the gate takes `ml_neg_t.lock`, a FreeRTOS mutex with priority inheritance; the router's `rt_lock` is a critical section; `vTaskPrioritySet` on the task itself with no mutex held is the only change).

Instrumentation (always on, `usb` report and `tools/inbound_accounting.py`): NTBs completed, ZLPs, bytes (mean NTB, datagrams per NTB), frames handed per drain pass (1, 2, 3, 4, 5+), the gap between IN completions **while frames were queued** (sum, max, histogram <1/<2/<4/<8/>=8 ms), the wait of the first frame of each burst for its hand-over (relay wake + deferral + TinyUSB task), and worker demotions. The gap minus the bus time of the mean NTB is the wake latency, measured instead of estimated. Cost: two `esp_timer_get_time()` per frame (outside the ring's lock) and a few relaxed atomics per NTB.

### NTB size: quantified, not changed

`tools/usb_drain_model.py` (saturated drain, 1,242 B datagrams as `-l 1200`; 1,514 B in brackets), Mbit/s by NTB size and wake latency:

| NTB (RAM, 2 buffers) | per NTB | L=0 | L=0.3 ms | L=1 | L=3 | L=6 |
|---|---|---|---|---|---|---|
| 3,200 (6,400 B, now) | 2 (2) | 9.4 | 6.4 (6.8) | 6.4 | 3.9 (4.3) | 2.45 (2.8) |
| 3,900 (7,800 B, +1,400) | 3 (2) | 9.4 | 7.2 (6.8) | 7.2 | 4.8 (4.3) | 3.3 (2.8) |
| 4,608 (9,216 B, +2,816) | 3 (3) | 9.4 | 7.2 (7.6) | 7.2 | 4.8 (5.4) | 3.3 (3.7) |
| 6,400 (12,800 B, +6,400) | 5 (4) | 9.5 | 8.0 | 8.0 | 6.1 (6.0) | 4.4 |

A bigger NTB only buys robustness against residual latency, and every kilobyte is boot heap that admission's margin (8,100 B at 107,000 B free) pays for. With the priority fix L should be tens of microseconds, where all rows are within 2 % of each other. **Decision: keep 2 x 3,200 B, spend nothing**; the counters decide. If after this change the gap histogram shows a wake latency above ~1 ms (mean gap minus bus time), raise `CONFIG_TINYUSB_NCM_IN_NTB_BUFF_MAX_SIZE` to 4,608 (+2,816 B static): three full frames per NTB for TCP. The build-time memory assertion in `gateway_main.c` ties the permanent USB buffering to the boot-heap budget and must be updated with it, deliberately.

### Expected board effect, and what refutes it

* The mean of `usb.gap_us_sum / usb.gap_count` falls from ~7 ms to about the bus time of the mean NTB (2-3 ms), the wake latency in the diff (gap minus bus time) under 0.5 ms, the first-frame wait (`cold_us_sum / cold_starts`) under 0.3 ms. UDP `-R` at 3, 4 and 6 Mbit/s: `usb.tx_dropped_full` ~0 and `route.forwarded_in` equal to `wg.rx_delivered` up to what the (also priority-ordered) inbound path itself delivers; with the Wi-Fi and WireGuard path as the limit the ceiling moves to wg_mgr's ~770 datagrams/s (~7.5 Mbit/s at 1,242 B).
* **Refuted if** the gap histogram stays at 4-8 ms with `drains_sent` mostly 2: then the idle is not the TinyUSB task's latency but the host's (turnaround between IN URBs), and the NTB size table above is the lever (bytes per host turnaround). Refuted too if wg_mgr throughput falls (`wgperf` `rx_pkt`, `lock_wait`): then the TinyUSB task's receive work is costing more than 3 %: look at `drains_sent` against the upload rate.

## B. The heap minimum: three claims on the same 20 KB, one of them unchecked

### Where the 3 KB came from

Free internal heap with one membership is 36-38 KB (ADR 0020, 0021); the recovery reserve is 16,384 B, so about **20 KB** is available above it. Under an inbound flood three consumers draw on it:

1. The USB ring's elastic chunks stop at 32,384 B free (`GATEWAY_USB_TX_FLOOR_FREE`, then): about 5 KB.
2. The WireGuard receive queue stopped at **16,384 B** free (`ML_WG_RX_FLOOR_FREE`; the join floor only while a join runs) and holds up to 12,288 B: it fills **below the ring's floor**.
3. **Wi-Fi buffers pinned by sockets, with no heap check anywhere.** A datagram that reached lwIP's UDP socket mailbox pins the driver's RX buffer (a heap block of about the frame, ~1.66 KB with headers) until net_io reads it. `CONFIG_LWIP_UDP_RECVMBOX_SIZE` = 10 allowed ten, ~16.6 KB, arriving within microseconds (one A-MPDU) and before net_io (priority 7, below the Wi-Fi and tcpip tasks of its core) can run. The TCP window (8 segments = 13.3 KB) and the Wi-Fi TX pool (16 buffers, upload) are the same kind of claim.

37 000 - 5 000 (ring) - 12 300 (queue) - 16 600 (pins) = **3 100 B**. The three numbers reproduce the board's 3,040-3,140 B; `tests/test_heap_budget.c` models the schedule with the old constants and lands in the same few KB (and negative with upload, whose 22 USB receive slots had no heap check at all: the 5,884 B minimum after the 0.2.22 iperf runs, `docs/diagnostics/baseline-0.2.22-2026-10-05.md`). Each checked consumer is correct alone ("free now is above my floor"); together they promised the same bytes three times. The things that also grow and had **no** floor: USB receive frames (up to 22 x 1.5 KB), the DERP relay transmit queue (8 x 1.4 KB per membership, internal heap on this board) and, in the Wi-Fi driver, the TX pool.

### The bound (`components/microlink/include/ml_heap_budget.h`)

A consumer that checks the free heap must leave, on top of the recovery reserve, whatever can be taken after its check without a check of its own: the pinned buffers of the largest burst one socket can hold, and the allocations of checkers racing this check (two cores: at most one buffer each beyond the largest).

    ML_HB_FLOOR >= ML_HB_RESERVE + ML_HB_PIN_BUFFERS x 1,664 B + ML_HB_SLACK (2 x 1,664 B)
    29,884   >=   16,384    +   6 x 1,664 = 9,984             +   3,328        (= 29,696)

* **One floor for every elastic consumer**: `ML_HB_FLOOR` = recovery reserve + negotiation peak = `ml_adm_elastic_floor(true)` (29,884 B at `ML_ADM_NEG_PEAK_BYTES` 13,500). The USB ring's growth (already), the WireGuard receive queue (**now always, not only during a join**; that also removes the negotiation-lock take from the receive hot path), the router queue above its two-packet minimum (`ROUTE_HEAP_RESERVE`), pending outbound packets (`ml_gateway_queue_packet`), the DERP relay's transport-data transmit queue (handshakes and DISCO are exempt) and **USB receive frames** (new check; the first two frames in flight are exempt so ARP/DHCP/DNS/ACKs survive, costing at most 3 KB inside the slack). Derived from the `ML_ADM_*` symbols; a smaller negotiation peak shrinks the allowed pin burst, loudly, at build time (`ML_HB_PIN_BUFFERS` >= 4 asserted).
* **The unchecked claimants are held to `ML_HB_PIN_BUFFERS` (6) each, by build assertions**: UDP mailbox 10 -> **6**, TCP window 8 -> **6 segments** (8,640 B), Wi-Fi TX pool 16 -> **6** (`gateway_main.c`, `tcp_window_budget.h`, `tools/test-heap-budget.py`, which also proves each limit live by compiling one past it).
* **Refusals are counted, never silent, never a crash**: `q_wg_heap` (queue), `usb.rx_dropped_heap`, `heap_budget.refused_pending`, `heap_budget.refused_derp_tx` in `/status`, the router's own counters; the sender sees ordinary loss.
* **Test (`tests/test_heap_budget.c`, ASan/UBSan):** an adversarial schedule over free heap 34-44 KB: bursts of pins with no check, partial net_io drains, queue pops, ring growth and shrink, upload frames, pending and relay packets, racing checkers, through the real `ml_wgrx_admit`, `gateway_usb_rx_admit`, `rt_queue_budget`, `ml_hb_ok`. Now: minimum free never below 16,959 B in 66 runs of 400,000 steps. The same schedule on the old constants (queue 16,384, ring 32,384, ten pins): 9 B for a download flood at 37 KB (board 3,040-3,140 B), negative with upload. A floor that omits the pinned buffers is shown to fail (9,728 B).

### The cost, said plainly

The heap is 20 KB above the reserve; 6 pinned buffers (10 KB) + the queue's share (the room above the floor: **6-8 KB at 36-38 KB free = 4-6 full datagrams**, was 9) + ring growth (none at 36-38 KB: its floor is now the same number, so the ring is its three permanent frames plus the NTBs, ~8 frames) is what fits. Concretely:

* **UDP burst absorption falls.** `tests/test_net_io_drain.c` (lwIP's mailbox modelled): a burst of 10 datagrams against a 6-slot mailbox loses 17.7 % of the burst's datagrams (0 % with 10 slots); bursts of 6 or fewer lose none. The loss is lwIP's silent mailbox drop, visible as `lwip udp_recv - ml.udp_rx` in `inbound_accounting.py` (labelled `mailbox loss`).
* **Relay (DERP) TCP window 8 -> 6 segments**: the ceiling is window / RTT, 1.9 Mbit/s at 36 ms, 1.1 at 64 ms (2.6 and 1.4 before). Direct paths (WireGuard over UDP) are unaffected.
* **Wi-Fi TX pool 16 -> 6**: upload is 1-2 Mbit/s; a full pool makes `esp_wifi_internal_tx` fail and lwIP return `ERR_MEM`.
* The A fix lowers the pressure on the ring: with the pipe at line rate the permanent frames plus the NTBs absorb a decrypt run.
* **Not covered, said plainly:** each source is held to 6 buffers on its own; a direct UDP flood and a relayed TCP flood at the same instant could pin 6 more (9,984 B), taking the minimum to about the reserve minus that. The driver's own pool is 16 dynamic buffers. `memory low` (below) records the owner breakdown at every new minimum so the corner is measured, not argued.

### Review of PR #42: what the slack covers, and why the mailbox is not made dynamic

**Racing checkers.** N checkers that pass on the same free value f leave at least `FLOOR - (sum of their costs - the largest)`: the largest one is free, the rest come out of the slack (3,328 B). Three concurrent checkers (a ring chunk, 3,064 B, and two frames, 1,534 B each: 3,068 B) are covered; two cores plus a preemption inside the check-to-allocate window is the design point. A fourth costs 1,534 B more: with the pin burst on top the minimum is 15,298 B (1,086 B under the reserve); with the two exempt USB frames also admitted below the floor, 13,764 B (2,620 B under). These need three racers, two exempt frames and a full pin burst at once and still leave 13 KB; `tests/test_heap_budget.c` states and asserts the numbers. The pin burst and the slack share one 13,500 B band with 188 B to spare, so each added slack buffer costs one pin buffer. Closing the race outright needs a claim counter around every check-and-allocate (claim, allocate, release on every path, ring worker included); a leaked claim would refuse everything forever, so it was not added: the consequence of the open race is a dip to a still-large minimum, the consequence of a claim bug is a dead data path. Revisit if `heap_low` records show the minimum under the reserve with `unexplained` below 6 buffers.

**Why the mailbox and TX pool stay at 6, not runtime-bounded.** A runtime bound has to hold at the moment a burst arrives, and the pin happens in the driver before any of our code runs, so the only place it can act is lwIP's receive path (`SO_RCVBUF`, not built here: `# CONFIG_LWIP_SO_RCVBUF is not set`), per socket, set from outside lwIP's thread. It would also have to be sound against the elastic consumers: they may take the heap down to the floor at any instant, so the headroom a burst can rely on is `floor - reserve - slack`, which is exactly 6 buffers, whatever the free heap was when the limit was last computed (a limit derived from free heap at a net_io pass is stale by the next allocation). A bound that is sound against them must move their floor with the limit, synchronously, from the allocating task: `floor(k) = reserve + slack + k x 1,664` is the same trade fixed in time. The numbers of that trade: k = 6 needs a floor of 29,696 B (have 29,884), k = 8 needs 33,024 B, k = 10 needs 36,352 B, which is the steady free heap (36-38 KB): the queue's room would fall from 7 KB (4 datagrams) to 4 KB (k = 8) or under 1 KB (k = 10), and the ring would never grow. A mailbox slot and a queue byte buy the same thing, buffering in front of wg_mgr; a pinned slot costs 1,664 B for a 1,264 B datagram, a queued one 1,280 B, so converting mailbox slots into queue bytes is at worst neutral for steady load. What a bigger mailbox buys that the queue cannot is absorbing an A-MPDU burst that lands before net_io runs; that is the loss quantified above (`test_net_io_drain.c`: 17.7 % of a 10-datagram burst against 6 slots). It is the cost of the budget and is measured by `mailbox loss` in the A/B. TCP cannot be bounded per socket at all (the window is a compile-time constant), so 6 segments stays whatever happens to UDP. If the board shows mailbox loss that matters, the lever is a smaller negotiation peak (each 1,664 B freed buys one slot everywhere), not a dynamic mailbox.

### Evidence on the board (diagnostics build)

A 10 ms `esp_timer` sampler records, at every NEW heap-wide minimum below `ML_HB_FLOOR`, the free heap, the largest block, the USB ring (capacity and elastic bytes), the WireGuard queue bytes, USB receive frames in flight, and the tagged packet owner; eight records are kept (the first never overwritten; the newest is always the lowest). `tools/inbound_accounting.py` prints the decomposition: drop from the highest free level seen = ring elastic + queue + rx frames + packets + **unexplained (Wi-Fi buffers pinned by sockets and lwIP)**. If the unexplained part at the minimum is near 6 buffers x 1,664 B the model is right; if it is much larger, the pool (16 dynamic RX buffers, 16 TX) is claiming beyond the sockets and the corner above is the real limit.

## Size (ESP-IDF v5.5.5, base = origin/overhaul/multi-tailnet at the merge of #36)

| image | `.bin` | flash code | static DIRAM (`.bss`) |
|---|---|---|---|
| unified (tailnet) | 1,268,944 -> 1,269,936 (+992 B) | 871,188 -> 872,092 (+904 B) | 188,471 -> 188,583 (+112 B, all `.bss`: the evidence counters) |
| diagnostics | 1,296,688 -> 1,299,360 (+2,672 B) | 891,272 -> 893,572 (+2,300 B) | 192,147 -> 192,603 (+456 B: the `memory low` records) |
| legacy bridge (`tdongle_adapter`) | 1,238,784 -> 1,239,232 (+448 B: the shared `tinyusb_net.c` counters) | | |

Boot heap changes by the 112 B of `.bss` (release) against an 8,100 B admission margin. Free heap at steady state is not changed by anything here: the Wi-Fi TX pool and the mailbox are limits, not allocations.

## Tests

`tools/test-gateway.sh`: `tests/test_heap_budget.c`, `tools/test-heap-budget.py`, `tools/test-tcp-window.py` (6 wrong configurations rejected), `tests/test_wg_rx_budget.c` (one floor, no negotiation lock on the hot path), `tests/test_usb_rx_budget.c` (heap floor, exemption, counting, threads), `tests/test_jit_queue.c`, `tests/test_memory_report.c` (new fields, `memory low`), `tools/test-measurement-scripts.py`, `tools/usb_drain_model.py --check`. `tools/test.sh` -> `tools/test_net.py` with `tests/mocks/net_ring_cases.c` (`test_drain_evidence_and_priority`: cold-start latency, frames per drain, NTB sizes and gaps counted only with a backlog, demotion only for a pass that is about to grow and only when the priorities differ; an idle pass with chunks present is not demoted) under ASan/UBSan, and the four-thread ring under TSan.

## Board plan

Flash the diagnostics build of this branch and, for the A/B, of its base (`overhaul/multi-tailnet`). Host: macOS on the USB interface; `$DONGLE` is the dongle's tailnet address, the iperf3 server behind it. For each of 3, 4, 6 Mbit/s UDP and TCP, five runs:

    cd alternative/tailnet
    tools/inbound_accounting.py snapshot before.json --port /dev/cu.usbmodemXXXX --reset-wgperf
    iperf3 -c $DONGLE -u -b 6M -l 1200 -t 10 -R        # sent / received from its summary; -b 3M, 4M, 6M
    tools/inbound_accounting.py snapshot after.json --port /dev/cu.usbmodemXXXX --wgperf
    tools/inbound_accounting.py diff before.json after.json --sent <N> --received <M>
    iperf3 -c $DONGLE -t 10 -R                         # TCP download: Mbit/s and retransmissions; same snapshots around it

Read, in order: `usb.tx_dropped_full` (~0), `route.forwarded_in` against `wg.rx_delivered`, the `USB IN pipe` block (frames per NTB, gap against bus time, wake latency, cold start), `heap minimum since boot` (>= 16,384 B) and its records, `mailbox loss` and `q_wg_heap` (the price of the budget: compare with the base build), `heap_budget.*` in `/status`. Serial: `memory`, `memory low`, `inbound`. A/B of the knobs (each one rebuild): `CONFIG_TINYUSB_NCM_IN_NTB_BUFF_MAX_SIZE` 3200 / 4608 (update the memory assertion), and the priorities in `gateway.h` (the old 5 / 6 order, with the assertion relaxed) to confirm the root cause on the same hardware.
