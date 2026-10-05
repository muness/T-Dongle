# ADR 0022: USB transmit drain at the bridge's rate (task priority, not NTB size) and one heap budget for everything that grows under traffic

Status: accepted for on-board validation, 2026-10-05. **Nothing here has been measured on the board.** The host work establishes structure (what runs when, what a floor guarantees, what a pipe can carry); every number about the board's behaviour is a prediction with a stated refutation. Follows ADR 0015 (data-plane I/O, elastic ring), 0016 (PM), 0019/0020 (inbound loss and pipeline), 0021 (`ML_ADM_NEG_PEAK_BYTES` 13,500, elastic floor 29,884 B). **Amendment 2 (below, 2026-10-06) supersedes the Wi-Fi TX pool of 6 and the "not runtime-bounded" argument: the driver's RX and TX buffers are counted at run time and held to the same floor.**

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
* **Wi-Fi TX pool 16 -> 6** (superseded by amendment 2: pool 16 again, bounded at run time): upload is 1-2 Mbit/s; a full pool makes `esp_wifi_internal_tx` fail and lwIP return `ERR_MEM`.
* The A fix lowers the pressure on the ring: with the pipe at line rate the permanent frames plus the NTBs absorb a decrypt run.
* **Not covered, said plainly (closed by amendment 2):** each source is held to 6 buffers on its own; a direct UDP flood and a relayed TCP flood at the same instant could pin 6 more (9,984 B), taking the minimum to about the reserve minus that. The driver's own pool is 16 dynamic buffers. `memory low` (below) records the owner breakdown at every new minimum so the corner is measured, not argued.

### Review of PR #42: what the slack covers, and why the mailbox is not made dynamic

**Racing checkers.** N checkers that pass on the same free value f leave at least `FLOOR - (sum of their costs - the largest)`: the largest one is free, the rest come out of the slack (3,328 B). Three concurrent checkers (a ring chunk, 3,064 B, and two frames, 1,534 B each: 3,068 B) are covered; two cores plus a preemption inside the check-to-allocate window is the design point. A fourth costs 1,534 B more: with the pin burst on top the minimum is 15,298 B (1,086 B under the reserve); with the two exempt USB frames also admitted below the floor, 13,764 B (2,620 B under). These need three racers, two exempt frames and a full pin burst at once and still leave 13 KB; `tests/test_heap_budget.c` states and asserts the numbers. The pin burst and the slack share one 13,500 B band with 188 B to spare, so each added slack buffer costs one pin buffer. Closing the race outright needs a claim counter around every check-and-allocate (claim, allocate, release on every path, ring worker included); a leaked claim would refuse everything forever, so it was not added: the consequence of the open race is a dip to a still-large minimum, the consequence of a claim bug is a dead data path. Revisit if `heap_low` records show the minimum under the reserve with `unexplained` below 6 buffers.

**Why the mailbox and TX pool stay at 6, not runtime-bounded.** *(Amendment 2 does bound the TX pool and the RX pool at run time, at the one place the argument below leaves open: not per socket and from a stale limit, but by counting every driver buffer where it enters or leaves our code, with the check made synchronously by the allocating task. The argument still holds for the UDP mailbox and the TCP window, which stay at 6.)* A runtime bound has to hold at the moment a burst arrives, and the pin happens in the driver before any of our code runs, so the only place it can act is lwIP's receive path (`SO_RCVBUF`, not built here: `# CONFIG_LWIP_SO_RCVBUF is not set`), per socket, set from outside lwIP's thread. It would also have to be sound against the elastic consumers: they may take the heap down to the floor at any instant, so the headroom a burst can rely on is `floor - reserve - slack`, which is exactly 6 buffers, whatever the free heap was when the limit was last computed (a limit derived from free heap at a net_io pass is stale by the next allocation). A bound that is sound against them must move their floor with the limit, synchronously, from the allocating task: `floor(k) = reserve + slack + k x 1,664` is the same trade fixed in time. The numbers of that trade: k = 6 needs a floor of 29,696 B (have 29,884), k = 8 needs 33,024 B, k = 10 needs 36,352 B, which is the steady free heap (36-38 KB): the queue's room would fall from 7 KB (4 datagrams) to 4 KB (k = 8) or under 1 KB (k = 10), and the ring would never grow. A mailbox slot and a queue byte buy the same thing, buffering in front of wg_mgr; a pinned slot costs 1,664 B for a 1,264 B datagram, a queued one 1,280 B, so converting mailbox slots into queue bytes is at worst neutral for steady load. What a bigger mailbox buys that the queue cannot is absorbing an A-MPDU burst that lands before net_io runs; that is the loss quantified above (`test_net_io_drain.c`: 17.7 % of a 10-datagram burst against 6 slots). It is the cost of the budget and is measured by `mailbox loss` in the A/B. TCP cannot be bounded per socket at all (the window is a compile-time constant), so 6 segments stays whatever happens to UDP. If the board shows mailbox loss that matters, the lever is a smaller negotiation peak (each 1,664 B freed buys one slot everywhere), not a dynamic mailbox.

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

## Amendment 2 (2026-10-06): the Wi-Fi driver's buffers are counted where they start, and every data-path allocation answers to the floor

Status: host-tested (ASan/UBSan, TSan, the three builds), **not measured on the board**. Follows PR #42 (this ADR as merged). Two board findings, both release builds with verified flashes, `iperf3` TCP over the tailnet:

| configuration | TCP up | TCP down | heap minimum |
|---|---|---|---|
| PR #42 as merged (Wi-Fi dynamic TX pool 6) | 2.41-2.51 Mbit/s, 94-118 retransmissions | 1.99-2.41 | 13,312 B |
| same, `CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM=16`, assertion off | 3.02-3.23 Mbit/s, 44-87 retransmissions (+25 %) | | 2,536 B |
| diagnostics build, 6 Mbit/s UDP download then TCP download, `memory low` | | | 5,000 B (largest block 7,680 B) |

The `memory low` records of the last row: `tx_ring` 16,764 B (elastic 12,192), `wgq` 2,560, `packet_live` 10,308 (other records 9,476-12,868 with `rx_inflight` 0), owner `packet` peak 15,428 B, `net_wg_full` 679 drops.

### What the numbers say

Every elastic consumer stops at `ML_HB_FLOOR` (29,884 B), so what they hold together cannot exceed `S - F`, S being the free heap when the flood starts; what takes the heap below the floor is whatever nothing checks. The record gives `S - 5,000 = ring elastic + packet_live + rx frames + pins`, and the wg queue (`wgq`) is a part of `packet_live` (its datagrams are `packet` blocks), not a second term (`tools/inbound_accounting.py` subtracted it twice; fixed). With ring 12,192 + packet 10,308 = 22,500 B of elastic memory:

* if S = 52.4 KB (the elastic consumers then hold exactly their room, `S - F` = 22.5 KB: plausible for a diagnostics run with the DERP TLS session not resident, since a direct-path UDP flood does not need it), the pins are 52,384 - 5,000 - 22,500 = **24.9 KB = 15 buffers of 1,664 B: the driver's 16-buffer RX pool**, held by sockets, the TCP window and the tcpip mailbox together, each of which was bounded to 6 on its own. This is the one reading in which every owner obeys its floor, and it is the one the site audit below supports;
* if S = 37 KB, the elastic memory exceeded its room by 14.4 KB, which would need an unchecked allocation of that size on the data path. The audit finds none (below): every `packet` allocation is one block at a time or already checked.

`heap_low.free_hi` in the record decides between them (board plan, step 1). In both readings the answer is the same: the Wi-Fi buffers must be counted and bounded together, not each source by its own constant.

### 1. Runtime-bounded Wi-Fi TX (`main/wifi_pin_budget.h`, `main/wifi_pins.inc`)

**Where TX starts.** Every frame this firmware sends on the STA interface goes lwIP `wlanif` `low_level_output` -> `esp_netif_transmit_wrap` -> the netif driver's `transmit_wrap` -> `esp_wifi_internal_tx(WIFI_IF_STA, ...)`. IDF's `wifi_netif.c` installs `wifi_transmit_wrap` there; `esp_netif_set_driver_config()` on the netif IDF created replaces it with ours (same call, the same driver handle) after `esp_netif_create_default_wifi_sta()`, before Wi-Fi runs. The RX hook cannot go in then: the lwIP netif behind it is allocated zeroed by `esp_netif_new()` and `netif_add()` (which sets `netif->input`) runs in `esp_netif_start_api()` on `WIFI_EVENT_STA_START`, and again on every `esp_netif_start` after a stop; the first version of this PR tested `lwip->input` at install, found NULL and left the whole budget off. `wifi_pins_hook_rx()` is idempotent and runs on every STA link event and on got-IP (`rx_hooked` in `/status`); `tests/test_wifi_pins_hooks.c` holds that order. The legacy bridge and the transparent L2 mode call `esp_wifi_internal_tx` directly (`main/bridge.c`, `tdongle_l2.c`) and are not touched: they copy each frame out of the driver buffer at once and have no elastic memory to protect.

**The tx-done callback (IDF 5.5.5), read from the sources and `libpp.a` / `libnet80211.a` (`xtensa-esp32s3-elf-objdump -dr`; the driver is closed source):**

* `esp_wifi_set_tx_done_cb(wifi_tx_done_cb_t)` (declared in `esp_private/wifi.h`, defined in `libnet80211.a` `ieee80211_api.o`) checks that Wi-Fi is initialised, then `ic_register_pp_tx_done_cb` -> `ppRegisterTxDoneUserActionCallback` stores the pointer in one global, `g_tx_done_cb_func`. **Nothing in IDF 5.5.5 uses it** (`grep -rn esp_wifi_set_tx_done_cb components`: the declaration only), so there is nothing to collide with. `esp_wifi_internal_reg_txcb`, the other name in the brief, does not exist in this IDF.
* `ppProcTxDone` (`libpp.a` `pp.o`, in `.wifiextrairam`; called by `ppTask` and `lmacTxDone`, so in the driver's pp task or the MAC's completion path, with the flash cache possibly off: the callback must live in IRAM, and does: `wifi_pins_tx_done` is 102 B of IRAM calling only `xPortInIsrContext`, `xPortEnterCriticalTimeout` and `vPortExitCritical`) takes each completed TX descriptor off its done queue and **calls the callback once for each one whose descriptor word has bit 13 set**, with an interface index (0 or 1, from the descriptor), the driver's own copy of the frame (not our buffer), a pointer to its length, and a success flag (descriptor result byte == 1: it is called for failed frames too, `txStatus` false). The buffer is recycled (`esf_buf_recycle`) right after.
* **It is not called for every buffer.** A done record with bit 13 clear gets no callback: with bit 23 set its length is adjusted and processing continues without recycling (an aggregate still being worked), otherwise it is recycled (a record of buffer type 5 is only logged). And TX buffers are recycled with no `ppProcTxDone` at all by `ppClearTxq` (dequeues every entry of a TX queue and recycles it; `pp_stop_sw_txq` calls it), `lmacStopTransmit`, `pp_deattach` and a logged failure path of `ppTxPkt` (the `esf_buf_recycle` call sites in `libpp.a`): the queues clear when the link drops, the channel changes or the interface stops. The callback also does not say which of our frames completed (the pointer is the driver's), and management frames can complete through the same record.
* So tx-done is neither exactly-once for our buffers nor identifying. It is used for what it is good at, the common case, and everything else is covered (design below). **This is read from the disassembly, not measured:** the board counters `tx_stale` and `tx_unmatched` (below) say how often the cases above happen, and are the evidence the fallback is refuted or kept on.

**Design.** `gateway_wifi_pins` counts, in one atomic word, Wi-Fi buffers pinned in both directions (RX in bits 0-7, TX in bits 8-15), and keeps a FIFO of the times of the outstanding TX charges (16 entries, one per pool buffer). A frame is **admitted** (and charged at the call site, before `esp_wifi_internal_tx`) when
(a) it fits the **band**: both directions together hold fewer than `GATEWAY_WIFI_BAND_TOTAL` = 5 and this direction fewer than 4: no heap read, and each direction keeps a slot (an ACK or an ARP reply always has a buffer; a one-way flow gets 4 of the 5, so upload keeps 4 frames in flight with the RX side idle); or
(b) it is **elastic**: the free internal heap stays at or above `ML_HB_FLOOR` once its buffer (TX: `min(len + 192, 1,664)`) exists, like every other elastic consumer.
Otherwise TX returns `ESP_ERR_NO_MEM` and RX frees the frame. A charge is released **exactly once** by: the driver's tx-done (pops the oldest: FIFO), `esp_wifi_internal_tx` returning an error (abort: no buffer exists), the STA link going down or coming up (flush: the driver cleared its queues), or the **lease** (a charge older than 3,000 ms is presumed dropped and counted as `tx_stale`; review of this PR raised it from 1,000 ms: 16 queued frames each retried 7 times at 1 Mbit/s take 1.4 s, a scan dwell or a lower-priority queue behind a busy one adds to that, and expiring a charge whose buffer is still queued admits a replacement above the count). Missing a callback costs a credit until the flow pauses for a lease, never a permanent leak; under steady traffic a systematically missing callback is NOT repaired (dones pop the head, so the surplus charge is always a recent one): a leak of the whole pool heals itself only when the flow slows below pool/lease = ~5 frames/s, which is why `tx_stale` is the first number to read on the board; an extra callback (a management frame) releases a credit early, admitting one more frame than counted for a moment, bounded by the pool. `gw_wtx_done` with nothing outstanding is counted (`tx_unmatched`) and changes nothing. If `esp_wifi_set_tx_done_cb` fails, nothing is counted and TX falls back to the heap floor alone with frames up to 256 B exempt (`tx_done_cb` false in `/status`).

**Refusal: ERR_MEM, not a silent drop.** A refused frame returns `ESP_ERR_NO_MEM`, which `wlanif` maps to `ERR_MEM`. For TCP that is the answer that preserves its behaviour best (lwIP `tcp_out.c`, `tcp_output`: `tcp_output_segment()` returns the error without consuming the segment, which stays on the unsent queue; no loss is inferred, nothing is retransmitted, and the next ACK or segment from the peer (`tcp_input` ends in `tcp_output`) or write sends it. A refusal happens with frames in flight, so that ACK normally comes and the congestion window is untouched. If nothing is in flight (a refusal by heap), the retransmission timer, which `tcp_output_segment()` arms before the failed send, fires and `tcp_slowtmr` treats unsent-without-unacked as a failed send: back-off, ssthresh halved, cwnd one MSS: the ordinary RTO reaction, not worse than loss. `tcp_txnow()` would retry sooner, but nothing in lwIP or IDF calls it). Returning `ERR_OK` and dropping instead makes lwIP believe the frame left: it waits for an ACK that cannot come, retransmits and halves the window, and counts a retransmission, which is how PR #42's pool of 6 reached 94-118 retransmissions on the board. For UDP (WireGuard, which is what forwarded traffic is) `udp_sendto` returns `ERR_MEM` up through `wireguardif_tx_commit`; `gateway_send_packet` discards the result and frees the packet, so the drop is silent for the inner flow (its own TCP reacts) and counted only at the source (`tx_refused_pool`, `tx_refused_heap`): the same loss as before.

**The runtime invariant that replaces the static assertion.** `_Static_assert(CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM <= ML_HB_PIN_BUFFERS)` is gone (and the pool is back at 16: `sdkconfig.defaults`). What is asserted instead, at build time (`wifi_pin_budget.h`, `gateway_main.c`, `tools/test-heap-budget.py`, which also proves it live): the shared band plus the one RX frame under check fit the pin burst the floor was sized for (`GATEWAY_WIFI_BAND_TOTAL + 1 <= ML_HB_PIN_BUFFERS`), each direction leaves the other a slot, the TX pool holds the band and fits the FIFO (4 <= pool <= 16), and `ML_HB_RESERVE + 6 x 1,664 + ML_HB_SLACK_BYTES <= ML_HB_FLOOR` (29,696 <= 29,884). At run time the same inequality is enforced per frame by the admission above, and held by `tests/test_wifi_pin_budget.c` under concurrent TX and RX pins.

### 2. The RX pool (the unchecked allocation behind the board's 5,000 B) and every other data-path allocation

**RX.** The driver copies each received frame into a dynamic RX buffer and passes it up; with `CONFIG_LWIP_L2_TO_L3_COPY` off a custom pbuf (`esp_pbuf_allocate`) wraps it, and lwIP frees that pbuf, once, wherever the frame ends up. `wifi_pins_input` replaces the STA netif's `input` (it calls the original) and counts the frame when it enters lwIP, checking the free heap *after* the driver allocated the buffer (the check includes the buffer itself, so it is synchronous with the allocation, unlike the per-socket limit this ADR ruled out); a refused frame is freed at once (`pbuf_free` of the not-yet-wrapped pbuf frees the driver buffer). An admitted pbuf's `custom_free_function` is wrapped to release the count. The UDP mailbox (6) and the TCP window (6 segments) stay as they are; the pool (16) is no longer the bound. `GATEWAY_WIFI_RX_GATE` 0 takes the RX hook out.

**Sites behind owner `packet`** (`tdongle_heap_tag(TDONGLE_OWNER_PACKET, ...)`, found by grep over `main/` and `components/microlink`), and what each was:

| site | allocation | before | now |
|---|---|---|---|
| `ml_net_io.c` `sock_sink` | copy of each UDP datagram, <= 1,500 B | allocated first, WireGuard admitted after (`ml_wgrx_admit_gated`), DISCO/STUN not checked at all (queues of 8 and 4 per membership, up to 1.5 KB each) | **checked before the copy** (`net_io_admit`): WireGuard by bytes and floor, DISCO/STUN by the floor, small datagram into an empty queue exempt (`ml_hb_rx_ok`); a refused datagram takes no heap; too-short datagrams are dropped without a copy |
| `ml_derp.c` `op_alloc` via `ml_derp_link.c` `rx_next` | receive buffer of each relayed packet, <= 1,564 B, one per link | allocated, then `op_deliver` admitted WireGuard data | `rx_admit` op **before the allocation** (`op_rx_admit`, the floor, small-frame exemption); `op_deliver`'s byte/heap check stays (it reserves the queue bytes); a refusal reads the frame off the wire and drops it, stream in sync (`tests/test_shared_derp.c`) |
| `ml_derp.c` `ml_derp_queue_send` | copy for the relay transmit queue (8 per membership) | floor for WireGuard data, exempt for handshakes and DISCO | unchanged |
| `ml_derp_link.c` (tx) | framed copy of the packet being written, one per link | unchecked | unchanged: one block, built from a queue entry released at once, inside the racing slack |
| `ml_wg_mgr.c` `wg_udp_output_cb` | copy + wrapper for a pbuf chain | unchecked | **floor for transport data** (`ML_HB_WG_COPY`); the one-piece pbuf the firmware builds goes through `wg_udp_output_pbuf_cb`, no copy |
| `ml_wg_mgr.c` `wg_rx_stage` / the run | the datagram blocks of a run of <= 8, popped from the queue (queue bytes released at the pop) | admitted at the queue | unchanged and sound: they were admitted above the floor and allocate nothing more; the router's output pbuf replaces the datagram at once (one transient block, inside the slack) |
| `ml_coord.c` keepalive | 1 byte | | unchanged |

Other data-path allocations not behind `packet`: the USB ring (floor + largest block, before), USB receive frames (floor; first two exempt), the router queue (`rt_queue_budget`), pending packets (`ml_gateway_queue_packet`), the router's output pbufs (transient swap), and now the Wi-Fi buffers in both directions. Refusals: `heap_budget.refused_rx_ctrl`, `refused_derp_rx`, `refused_wg_copy`, `q_wg_heap`/`q_wg_bytes`, `wifi_pins.*` in `/status`.

### 3. The arithmetic, per owner

Steady free heap before the flood S, the floor F = 29,884 B, the reserve 16,384 B, a pinned Wi-Fi buffer 1,664 B. Every elastic consumer checks `free >= F + cost` and so stops at F; the room above it, `S - F`, is shared:

| owner | holds | bound |
|---|---|---|
| USB ring, elastic chunks (not `packet`) | <= 10 x 3,080 B | grows while free >= F + 3,080 and the largest block >= 24,000 before and after |
| `packet`: WireGuard queue + run, DISCO/STUN copies, DERP relay queue and receive buffer | queue <= 12,288 B | each block admitted at free >= F + len + 16 |
| router queue, USB receive frames, pending packets (not `packet`) | <= 16 KB, 22 frames, 4 packets | `rt_queue_budget`, `gateway_usb_rx_admit`, `ml_hb_ok`: all at F |
| Wi-Fi RX and TX, elastic part | whatever fits | free >= F after the buffer exists |
| **sum of the above** | **<= S - F** | = 7,116 B at S = 37,000; = 22,516 B at S = 52,400 |
| Wi-Fi band (RX + TX, below F) | 5 x 1,664 = 8,320 B | counted, 5 shared |
| the RX frame under check | 1,664 B | the driver's buffer exists before the check; a refusal frees it |
| racing checkers | 3,068 B | three concurrent checkers (a ring chunk and two frames: 6,132 - the largest, 3,064) |

    minimum free = F - band - RX frame - racers = 29,884 - 8,320 - 1,664 - 3,068 = 16,832 B  >=  16,384 B (448 B to spare), at any S.

So at S = 52.4 KB, where the board measured 5,000 B, the bound is 16,832 B, and at S = 37 KB the same, because everything that grows with traffic stops at F. `tests/test_wifi_pin_budget.c` writes the worst legal interleaving out with the real functions (three checkers pass on one value, then every pin the budget allows: 16,832 B exactly) and runs the adversarial schedule (RX bursts, partial drains, TX submit/done/flush/missed callbacks, the WireGuard queue, ring, USB frames, pending packets, 1-3 racing checkers drawn from different sites, start levels 34-46 KB, 6 seeds x 400,000 steps): worst 18,006 B. The same schedule on what PR #42 left (RX pool 16, TX pool 6, nothing counting the pins) falls to 271 B (download only 4,038 B: the board's 5,000 B), and each ingredient is shown to matter: an RX band of 10 gives 8,674 B, an elastic floor of reserve + 3 KB gives 10,348 B.

Not covered, as in this ADR before: a fourth concurrent checker costs one more frame (15,298 B), and the two exempt USB frames (3,068 B) and the exempt small DISCO/STUN datagrams (<= 1,584 B per membership) are admitted below the floor; coinciding with a full band and three racers they take the minimum to about 13.8 KB. Quantified in the test, not proved.

### 4. The largest block

The board's largest block fell to 7,680 B. Two facts bound what can be asked of this change. The USB ring's growth already respects `ML_ADM_LARGEST_BLOCK` (24,000 B) **before and after** each 3,048 B chunk and undoes a growth that took the largest block under it (`tinyusb_net.c` `tx_try_grow`, `grow_denied_largest`): at the steady largest block of 24,576 B the ring can take only what the small free blocks hold, so it cannot be what carves the big block. And the largest block follows the total: with free memory at 5,000 B the largest block cannot be above it; the 7,680 B was the same event as the 5,000 B. What does split the big block is anything that allocates below the heap's small holes: the Wi-Fi buffers, the queue, USB frames. They are now held to F - 13,052 = 16,832 B total free; if every byte taken below F came from the big block the largest block would be 24,576 - 13,052 = 11,524 B, and with the small holes (about 5 KB at steady state) absorbing the first allocations it is about 16.5 KB, which is the DERP TLS record buffer (about 16.7 KB). **That last step is an estimate, not a bound**: a DERP reconnect in the middle of a flood can fail for want of a contiguous block and retry (the link paces its retries). `memory low` records `largest` with every record; if it is under 16.7 KB at a minimum the lever is the number of band slots (each 1,664 B freed from the negotiation peak buys one), not a heap walk per frame.

### 5. Kept from PR #42

Exactly-once release (USB receive frames, the TX charges above), the link-generation flush of the USB transmit ring (the Wi-Fi charges flush on the Wi-Fi link events by the same pattern), elastic reclaim, the PM hooks and every priority are untouched; `tests/mocks/net_ring_cases.c`, `tools/test_net.py` and the router suites pass unchanged.

### 6. The cost, said plainly

* **Upload at a full heap.** The TX band is up to 4 frames in flight (RX idle), and more only while the heap is above F: at S = 37 KB with the ring and queue idle that is (37,000 - 29,884) / 1,664 = 4 more, with the elastic consumers full, none. So under a flood at a steady 37 KB (the elastic consumers holding their room) the budget gives 4 frames in flight, against PR #42's 6, and 8 or more only while the ring and queue are idle; **the +25 % of the 16-buffer experiment needs the heap above the floor and is not promised, and upload under a concurrent download flood may fall against PR #42**. What it buys is that it can never again cost the heap (2,536 B). If `tx_refused_heap` is large with `tx_high_water` stuck at 4 and TCP up near 2.4 Mbit/s, the lever is the negotiation peak (each 1,664 B freed is one more band slot), or letting upload reclaim the ring's elastic chunks.
* **RX at the floor.** When the ring and queue hold the room (a sustained flood), RX is held to 4 frames in flight (5 with TX idle) plus whatever the heap above F allows: a 6-slot mailbox and a 6-segment window cannot fill at that moment, and the excess is dropped at the netif (`wifi_pins.rx_dropped`), as lwIP's mailbox drop was. Download throughput under a flood may fall against PR #42, which bought it with the heap (5,000 B minimum); the A/B is on the board plan. Direct-path UDP is unaffected at a steady heap.
* **Code and RAM**: +3.9 KB in the image, +288 B static DRAM/IRAM (the 152 B budget, the 102 B IRAM callback), per image below.

### 7. Tests

`tools/test-gateway.sh` runs, new or changed: `tests/test_wifi_pin_budget.c` (ASan/UBSan and TSan, via `tools/test-heap-budget.py`: rules, the shared band and its two-direction guarantee, the lease with a wrapping clock, abort, flush, unmatched events, exactly-once over 40 seeds x 100,000 random events, six threads, the worst interleaving, the adversarial schedule with its two negative controls and two mutants), `tests/test_heap_budget.c` (the receive-copy exemption), `tests/test_shared_derp.c` (`rx_admit`: refusal drops the packet, the stream stays in sync, control frames are not asked), `tests/test_status_stream.c` (`wifi_pins` and the new `heap_budget` counters in `/status`), `tests/test_memory_report.c` and `tools/test-memory-report.py` (`wifi_rx_pins` and `wifi_tx_inflight` in the `memory low` records), `tools/test-heap-budget.py` (the TX pool must hold the band and fit the FIFO: 0 and 17 are rejected, 16 accepted). Also green: `components/tdongle_runtime/tests/run.sh`, `tools/test.sh` (legacy bridge, ASan/UBSan). `tools/inbound_accounting.py` no longer subtracts `wgq` twice and prints the pin counters beside `unexplained`.

### 8. Size (ESP-IDF v5.5.5, base = `origin/overhaul/multi-tailnet` at af85da3)

| image | `.bin` | flash code | static DIRAM (`.bss` + IRAM) |
|---|---|---|---|
| unified (tailnet) | 1,270,736 -> 1,274,608 (+3,872 B) | 872,028 -> 875,240 (+3,212 B) | 188,607 -> 188,895 (+288 B: the budget's 152 B of `.bss`, the tx-done callback's 102 B of IRAM, the hooks' pointers) |
| diagnostics | 1,299,392 -> 1,303,328 (+3,936 B) | 893,608 -> 896,688 (+3,080 B) | 192,603 -> 192,963 (+360 B: the same, and two fields in each of the eight `memory low` records) |
| legacy bridge (`tdongle_adapter`) | unchanged (1,239,232) | unchanged | unchanged |

Boot heap changes by the 288 B against an 8,100 B admission margin. Free heap at steady state is not changed by anything here: the pool of 16 is the driver's limit on dynamic buffers, not an allocation, and the budget allocates nothing.

### 9. Board plan

Flash the diagnostics build of this branch (and, for the A/B, its base). Host and `$DONGLE` as in the plan above. Per step, 3 runs each; `memory low`, `memory`, `inbound` and `/status` (`wifi_pins`, `heap_budget`) before and after:

1. `iperf3 -c $DONGLE -u -b 6M -l 1200 -t 10 -R` (UDP download) and **`memory low`**: `free_hi` first (S: settles the reading above), then each record's `wifi_rx_pins` and `wifi_tx_inflight` (should be <= 5 + 1 at any record under F) and `unexplained`; **heap minimum >= 16,384 B** (`/status` `minimum_free_memory`, `heap minimum since boot`).
2. `iperf3 -c $DONGLE -t 10 -R` (TCP down) x3: Mbit/s, retransmissions, `wifi_pins.rx_dropped`, `rx_high_water`; against the base's 1.99-2.41.
3. `iperf3 -c $DONGLE -t 10` (TCP up) x3: Mbit/s and retransmissions against 2.41-2.51 (94-118) and the experiment's 3.02-3.23 (44-87); `tx_high_water`, `tx_refused_heap`, `tx_refused_pool`, `tx_band_admits` / `tx_elastic_admits`; heap minimum again.
4. TCP up and TCP down together (`--bidir`): the corner the unchecked pins used to fill.

**Read the tx-done evidence first** (`/status` `wifi_pins`): `tx_charged` should equal `tx_done + tx_aborted + tx_flushed + tx_stale` plus `tx_inflight` at rest, and `tx_stale` and `tx_unmatched` should be about 0. `tx_stale` in the tens means the callback misses frames outside link changes (the lease does the work, at the price of a lease, 3 s, of credit per miss and, under steady traffic, not at all): set the callback aside (the degraded path is the heap floor alone). Many `tx_unmatched` means management frames complete through the same record: harmless below a few per second.

**Refuted if**: the heap minimum is under 16,384 B with records whose `wifi_rx_pins + wifi_tx_inflight` is under 6 (then an owner this audit calls bounded is not: the `unexplained` column names the size), or under it with the pins above 6 while free is under F (a band bug); TCP up under PR #42's 2.4 Mbit/s with `tx_refused_heap` high (the TX band is too small: the lever above); TCP down far under 2 Mbit/s with `rx_dropped` high (the RX gate costs more than the pins were worth: `GATEWAY_WIFI_RX_GATE` 0 for the A/B isolates it); `largest` under 16,700 B at a record (section 4).

