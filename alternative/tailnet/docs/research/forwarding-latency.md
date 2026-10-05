# Forwarding latency and packet pool design (research for PR-B)

Status: research, 2026-10-05. Read-only analysis of branch overhaul/multi-tailnet. Nothing here has been run on the board except the coordinator result in section 0.

## Headline

Throughput is capped by the **egress hand-off, not by crypto or Wi-Fi**. Every USB-to-tunnel packet crosses four queues and three tasks, and one of them (`wg_mgr`) services at most 4 packets per loop and sleeps 10 ms (one 10 ms FreeRTOS tick at the default 100 Hz) per loop. That is a hard ceiling near 4 Mbit/s before any stall, and the wg_mgr loop also runs 30-66 ms jobs under the tcpip core lock, which freezes the whole IP stack and produces the RTT spikes and queue-full drops. Cipher (0.39 ms/pkt) and copies (5.7 us) are noise. Wi-Fi modem sleep was tested and is not the limiter.

## 0. Coordinator result (on board)

`esp_wifi_set_ps(WIFI_PS_NONE)` after `esp_wifi_start` (gateway_main.c:1244): TCP 0.94 up / 0.52 down Mbit/s, 53-135 retransmits, ping 47 ms. Unchanged. PS is demoted to a secondary RTT-tail suspect. Note `ml_net_switch.c:140` already sets PS_NONE, but that path is not used by the gateway; gateway_main.c never calls `esp_wifi_set_ps` (grep: no hits in main/).

## 1. Ranked root causes

### R1. Egress cap: wg_mgr drains the USB packet path 4 packets per ~10-20 ms (confidence high, ~75% of the TCP ceiling)
- `router.c:299` calls `ml_gateway_queue_packet` (ml_wg_mgr.c:1178). It admits at most **4** packets per membership (`jit_packet_count`, :1180-1181), each a `calloc` + copy (:1182-1185), pushed to `peer_update_queue`.
- wg_mgr consumes them in `process_peer_updates` (:1215-1235): each is parked in one of 4 `jit_pending` slots and calls `ml_wg_mgr_trigger_handshake` per packet (:1231). The slot is freed only in `directory_flush_packets` (:1190-1212), which runs **once per loop** (:2605).
- The loop ends with `vTaskDelay(pdMS_TO_TICKS(10))` (:2751). No event wakes it. At the IDF default `CONFIG_FREERTOS_HZ=100` (not set in sdkconfig.defaults) that delay is 10-20 ms of wall time.
- Ceiling: 4 pkt / (10 to 20 ms + loop work) = 200-400 pps = 2.2-4.5 Mbit/s at 1400 B for full-size data, and a TCP window of 4 segments gives cwnd collapse. Observed 1 Mbit/s fits once R2 and R3 stalls are added. Everything past 4 in flight is dropped with `ESP_ERR_NO_MEM` silently (router.c ignores the return), so TCP sees loss: this is the main retransmit source (53-137 per 10 s).
- Each packet also does a per-packet `trigger_handshake` and goes through the JIT pending path even when the session is long established. The pending path was built for the first packet to a cold peer, not as the data path.

### R2. wg_mgr holds the tcpip core lock for 30-66 ms jobs and blocks both directions (confidence high)
- `wireguardif_periodic` under `LOCK_TCPIP_CORE` every 400 ms (:2686-2700); code itself logs "SLOW: 30-66 ms" (comment :2706-2715). `disco_periodic_probes` every 1 s (:2706). Each outbound packet is encrypted and sent under `GATEWAY_WG_CALL` = `LOCK_TCPIP_CORE` (:367, used at :1203), so 0.39 ms x up to 4 per loop is also held lock-side.
- While the lock is held, lwIP's tcpip thread (and therefore `gateway_host_input`, NAPT, Wi-Fi RX delivery, `usb->output`) cannot run. Packets arriving on USB meanwhile fill `route_queue` (R3). This explains the latency spikes (RTT 74 ms up to 583 ms: tail of lock holds plus retransmission timer) better than modem sleep.
- Inbound: `process_wg_packet` runs in wg_mgr after the same 10 ms sleep, so a received WG datagram waits in `wg_rx_queue` (depth 8, ml_net_io.c:97-108 drop counter `net_wg_full`) up to one loop, with a 30 ms drain budget (:2589) per window. At 100 pps of ACK-clocked download 8 slots overflow after one 80 ms stall: 4 `net_wg_full` drops observed.

### R3. `route_queue` depth 4, non-blocking send, low-priority consumer (confidence high for the 62 drops)
- `router.c:41` depth 4; `router.c:383` `xQueueSend(...,0)` drops and counts `router_ingress` on failure. The producer is the lwIP tcpip thread (prio 18 default), the consumer `usb_routes` (router.c:42) runs at **prio 3, unpinned**, below `members` (4), derp_tx/coord (5), wg_mgr and net_io (7), tcpip (18), Wi-Fi (23). Any of those running for a few ms starves it; 4 slots hold 4 packets = under 1 TCP window.
- `route_task` does malloc + copy + `valid()` + try-lock on `members_lock` (:206 `xSemaphoreTake(...,0)` drops the packet if any task, e.g. the manager at gateway_main.c:345/382/698, holds it) + two checksum passes (`checksums`, :133) + another malloc/copy in `ml_gateway_queue_packet`. Per packet: 3 mallocs, 3 memcpys, 2 full checksums. Cheap (~0.1 ms) but each of those lock-try failures silently loses a packet.
- Also at ingress, `p->tot_len > 1400` is dropped unconditionally (router.c:383). A host with MTU 1500 sending UDP (iperf3 UDP default 1448-1470 payload) loses every full-size datagram and counts it as `router_ingress`; this explains part of UDP 8 -> 2 Mbit/s and part of the 62 drops. TCP is protected only by the SYN MSS clamp to 1360 (:150-160).

### R4. Returns path blocks the tcpip/wg thread on USB (confidence medium)
- `gateway_tunnel_input` (router.c:327-365) runs in the context of `process_wg_packet` under tcpip lock, allocs a pbuf, and calls `usb->output` -> `usb_tx` (gateway_main.c:402-410): malloc+copy, then `tinyusb_net_send_sync(..., pdMS_TO_TICKS(50))`. If the NCM IN endpoint is busy (host not polling, `NTB_BUFFS_COUNT=2` of 6400 B in sdkconfig.defaults:17-18) the thread holds the tcpip lock up to 50 ms. Download side is the slower direction (0.52 Mbit/s), consistent. TinyUSB task priority was not verifiable (esp_tinyusb is a managed component not present in the worktree); `TINYUSB_DEFAULT_CONFIG` sets it, check at flash time.
- NCM aggregation: ESP TinyUSB NCM fills an NTB and sends on a short timer/once per `xmit` call; with 2 buffers of 6400 B, ACK-only traffic cannot starve but a busy buffer delays by one USB frame (1 ms) at worst. Low priority.

### R5. Task-structure latency floors (confidence medium, matters for ping)
- net_io `select` timeout 50 ms (ml_net_io.c:131) is not a delay when data arrives (select returns at once), but net_io (prio 7, core 0) and wg_mgr (prio 7, core 1) are separate; the DERP/IP stack tasks (tcpip, wifi, derp_tx 5) are also on core 0 competing with net_io and USB. Core 1 holds wg_mgr + coord + unpinned tcpip/route. There is no core dedicated to the forwarding path.
- Ping variability 47 ms to 1.9 s: 47 ms = good case (wg_mgr loop + one disco hop); 74 ms = one extra 10-20 ms loop on each of 4 hops plus tick quantization; 583 ms / 1.9 s = a packet dropped (R1/R3) and retried by the disco pinger or TCP RTO (min 200 ms, then exponential). The coordinator's PS=NONE run had 47 ms; RTT tails were not re-measured long enough to rule PS out for 100-300 ms spikes.
- Wi-Fi: 6 static RX, 16 dynamic RX/TX is adequate for 2 Mbit/s; not a limiter. Modem sleep (WIFI_PS_MIN_MODEM) remains a risk for tails of 100-300 ms on idle-to-burst transitions; recommended off (PS_NONE) for a USB-powered gateway.

### R6. Measurement artifact: `memory bench` 2.95 ms vs `crypto bench` 0.39 ms (confidence medium)
`report_bench` (memory_diagnostics.inc:258-283) times 64 rounds of `chacha20poly1305_encrypt` with wall-clock `esp_timer_get_time` from the console task, **with interrupts and preemption enabled**, on the diagnostics image, and with the first rounds cold in the flash cache. Higher-priority tasks (Wi-Fi 23, tcpip 18, net_io/wg_mgr 7) and the ISR load steal time from a prio-low console task, so the wall-clock average includes everyone else's CPU. `crypto bench` (wg_crypto_bench_run, control.c:18/56) uses CPU cycle counts with interrupts masked, which isolates cipher cost. 2.95/0.39 = 7.6x is consistent with the console task getting ~13% of the CPU while Wi-Fi/USB/DERP run. Fix: delete the cipher part of `report_bench` and keep the allocator timing; or port the cycle-counter/interrupt-masked method; and print "wall-clock, includes preemption" if kept. Also ADR 0013 says "memory bench" figure was the artifact: correct.

## 2. PR-B design (targets ADR 0013 shared runtime)

### 2.1 Shared prioritized packet pool (`gw_pkt`)
- Static slabs in internal RAM, no malloc on the data path: `N` blocks of 1536 B (1420 MTU + WG header 32 + headroom 16 + descriptor) in a free list guarded by a spinlock/atomic stack. Budget: packet heap peak measured 12.1 KB + WG working +6.4 KB; replace both with a fixed pool. Sizing: bandwidth x latency; 8 Mbit/s x 60 ms = 60 KB is unaffordable, so size to the goal of ~4 Mbit/s x 30 ms = 15 KB = **10 slabs** per direction, **20 slabs total ~ 30 KB** replacing ~18 KB transient + the 3 mallocs per packet; start at 16 and tune with the pool high-water stat. Heap min under traffic is 18 KB, so 16 slabs (24 KB) must come from reclaimed per-packet mallocs and per-membership stacks (ADR 0013 stage 1 saves tens of KB); do not add on top of the current layout.
- Classes: `CTRL` (handshake init/response/cookie, disco, keepalive; guaranteed reserve 4 slabs, never dropped for data), `DATA`. Per-tailnet cap = ceil(N/2) data slabs and reserve 1 each so one member cannot starve others.
- Zero copy chain: `usb_rx` (TinyUSB task) allocates a slab only after cheap checks of length and dest alias on the header already in the NTB buffer (**drop at ingress before copy**), copies once, then the same slab is rewritten in place (NAT, TTL, checksum incremental per RFC 1624 instead of two full passes), handed to wg encrypt (in-place with headroom), and on the return path reversed. Saves 2 mallocs, 2 memcpys, 2 checksum passes per packet.
- When empty: drop and count by class and reason (`pool_empty_data`, `pool_cap_tailnet`). No malloc fallback (ADR D2).

### 2.2 Queues and wakeups (event-driven)
- Replace `vTaskDelay(10)` in wg_mgr with `xTaskNotifyWait`/queue-set wait with a timeout equal to the nearest timer (periodic 400 ms, disco 1 s, jit expiry). Producers (`ml_gateway_queue_packet`, `ml_net_io` push to `wg_rx_queue`, coord updates) call `xTaskNotifyGive`. Removes up to 20 ms per direction per hop.
- Data egress path must not go through `peer_update_queue` / `jit_pending`. Add an `egress_ring` (SPSC, 32 slab pointers) drained fully each wake (budget 3 ms); only a cold peer (no session) falls into the JIT path. Remove the per-packet `trigger_handshake` and the cap of 4 (keep a cap on *cold* pending packets, 4, as now).
- `route_queue` depth 4 -> **16** (16 x 12 B = 192 B), `xQueueSend` timeout 0 stays for tcpip (never block lwIP) but with the pool at ingress, depth equals pool share. `wg_rx_queue` 8 -> 16 (pointers only). Count every drop by site.
- Take the `members_lock` by pointer snapshot: readers use an RCU-style immutable alias/flow table pointer (atomically swapped by manager) instead of try-lock that drops, or at least `xSemaphoreTake(...,pdMS_TO_TICKS(1))`.
- Move WG encrypt/decrypt **out of the tcpip lock**: wg_mgr already holds session keys; only the final UDP send needs `LOCK_TCPIP_CORE` (or use `udp_sendto` via `tcpip_callback`). Move `wireguardif_periodic` work to a short bounded slice (<=5 ms) and never run X25519 handshake inside the lock.
- `usb_tx`: replace malloc+copy and 50 ms blocking send with a TX ring of slabs owned by the TinyUSB task; `tcpip` enqueues and returns immediately (drop-oldest-data when full, count).

### 2.3 Tasks, priorities, cores
- Core 0: Wi-Fi, tcpip (unpinned today) pinned to 0, net_io (7), TinyUSB. Core 1: shared `wg_mgr` (prio 8, above net_io is not needed), route/usb_routes **merged into wg_mgr's egress path** or raised to prio 6 pinned core 1. coord, members, LCD, console, derp_tx at <=4 and never above the forwarding tasks. Console/LCD at prio 1-2 (check `lcd.c`, `console.c` creation; not changed here).
- `CONFIG_FREERTOS_HZ=1000` (cost: ~1% CPU) so any residual timed wait has 1 ms granularity.

### 2.4 Wi-Fi and CPU
- `esp_wifi_set_ps(WIFI_PS_NONE)` after `esp_wifi_start` (gateway_main.c:1244): free for a USB-powered dongle; helps RTT tails.
- CPU 240 MHz: raises all CPU-bound work by 50% (cipher 0.26 ms) for ~+30-40 mA; temperature sensor 32-46 C leaves large headroom; recommend **240 MHz after R1/R2 fixes only if** the pool/egress build still shows the wg_mgr core above ~70% busy under `-P 4`. Not a root-cause fix; do it as an experiment (E7).
- Keep `CONFIG_COMPILER_OPTIMIZATION_SIZE=y` as default, but place `chacha20poly1305`/`poly1305` hot loops in IRAM with `-O2` (`IRAM_ATTR` plus per-file `-O2`); the IRAM test in PR #28 saw no gain, so low priority.

## 3. Experiments for the coordinator (ordered by expected impact)

All with the release build; run `iperf3 -c <peer> -t 20 -P 1` TCP up/down plus `-u -b 3M -l 1200` UDP and `tailscale ping -c 30`, then read `memory` drop counters. Use the drop counters as primary outcome (lost packets), Mbit/s secondary.

E1 (R1, highest impact). In `ml_wg_mgr.c`, change `vTaskDelay(pdMS_TO_TICKS(10))` at :2751 to `vTaskDelay(1)` and set `CONFIG_FREERTOS_HZ=1000` in sdkconfig.defaults; also change the `old>=4` at :1181 to `old>=16` and `jit_pending[4]` loops (:1190, :1224) to 16 entries (array in microlink_internal.h). True if the egress ceiling dominates: TCP up rises roughly 3-8x (to 3-8 Mbit/s), retransmits fall below ~10, `router_ingress` drops fall. False: no change, then R3/R2 dominate.
E2 (R3). `router.c:41`: `xQueueCreate(4,...)` -> 32; `xTaskCreate(route_task,"usb_routes",4096,NULL,3,NULL)` -> priority 6 pinned `xTaskCreatePinnedToCore(...,6,NULL,1)`. True: `router_ingress` drops go to ~0 during TCP; retransmits drop. Do alone first, then with E1.
E3 (R3, MTU). Host side: `networksetup -setMTU` not needed; instead run `iperf3 -u -b 3M -l 1300` vs default `-l 1448`. Router drops `tot_len>1400` (router.c:383). True: the default-length UDP run shows loss near 100% of 1448 B datagrams, the 1300 B run does not. Also count by adding a distinct drop reason `TDONGLE_DROP_ROUTER_OVERSIZE`.
E4 (R2). Temporarily lengthen/shorten the periodic: `last_wg_periodic_ms` threshold 400 -> 5000 (ml_wg_mgr.c:2688) and the disco probe 1000 -> 5000 (:2707) for a 20 s run. True if lock-hold stalls cause the tails: ping max RTT drops from 583-1900 ms to < 100 ms and retransmits fall. (Handshakes still occur by session timers, so keep the test to 30 s.)
E5 (R2/R4 instrumentation, no behavior change). Add `ROUTE_MARK`-style timing: log lock-hold time in `GATEWAY_WG_CALL` (:367) and time inside `usb_tx` including the `tinyusb_net_send_sync` wait, histogram buckets <1, <5, <20, >=20 ms, printed with `memory`. True: any bucket >=20 ms during iperf supports R2/R4. Also log `uxTaskGetStackHighWaterMark`-free CPU: enable `CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS` + `vTaskGetRunTimeStats` to see %CPU of wg_mgr, usb_routes, tcpip, wifi under load (≥90% on one core = CPU bound; <40% = latency/queue bound).
E6 (R4). `usb_tx` (gateway_main.c:407): change timeout `pdMS_TO_TICKS(50)` to `0` and count failures. True: download Mbit/s changes (rises if tcpip lock hold was the stall; drops counted as `usb_tx_busy` instead). Also try `CONFIG_TINYUSB_NCM_IN_NTB_BUFFS_COUNT=4`.
E7 (CPU). `CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_240=y` (or `...160=n`). True if CPU-bound (E5 stats >70%): throughput scales ~1.4x. False: unchanged, so keep 160.
E8 (PS tail). Re-run with `WIFI_PS_NONE` vs default, `tailscale ping -c 200`, compare p99/max rather than mean. Already shows min 47 ms with NONE; need tail distribution.
E9 (R6). Run `crypto bench` and `memory bench` back to back while idle (Wi-Fi disconnected, no traffic) and again while iperf runs. True: idle `memory bench` approaches 0.39-0.5 ms and the loaded one inflates, confirming preemption/wall-clock; if idle is still 2.95 ms, suspect cold flash cache or a different build (check -Os vs diagnostics) and compare the code path of `chacha20poly1305_encrypt` there.
E10 (MSS/MTU). Capture on host: `tcpdump -ni <usb iface> -s 0 tcp` during iperf; verify SYN-ACK MSS <= 1360 both directions, no segments > 1400, no fragmentation (router rejects fragmented IP, `valid()` mask 0x3fff). False expectation: all segments <= 1400 B.

## 4. Open items and uncertainties
- Not verified: TinyUSB task priority and NCM timer behavior (managed component absent from worktree); actual lwIP tcpip task priority in this build (IDF default 18); `LWIP` TCP window/MSS settings; DERP path was not measured (direct UDP path only).
- Percentages in R1 are estimates from loop arithmetic; E1/E2 are designed to confirm them in one flash each.
- Another worker restructures microlink tasks on a different branch; line numbers refer to origin/overhaul/multi-tailnet at the time of reading and the design is expressed against shared net_io / derp / wg_mgr tasks of ADR 0013.

## On-board results (coordinator, 2026-10-05)

| Experiment | Result | Verdict |
|---|---|---|
| Wi-Fi power save off (`WIFI_PS_NONE`) | TCP 0.94 up / 0.52 down / 0.94 Mbit/s, unchanged | Not the throughput limiter. Still a candidate for the RTT tail |
| `route_queue` 4 → 32 | TCP unchanged (~1.0 Mbit/s); UDP 3 Mbit/s offered at `-l 1200` loses 59% | Queue depth alone is not the limiter |
| #1: outbound cap and `jit_pending` 4 → 16, `vTaskDelay(1)`, `FREERTOS_HZ=1000` | TCP up 1.14 Mbit/s (+20%), UDP 1.50 Mbit/s; heap minimum 6.4 KB; **chip temperature 62–65 °C** (was 32–46) | Minor factor. Polling has a thermal cost, so prefer event-driven wakeups |
| #5: per-task CPU during iperf (diagnostics build, 1 kHz tick) | IDLE0 51.0%, IDLE1 46.4%; `ml_wg_mgr` 32.9%; **`usb_routes` 32.0%**; `ipc1` 12.7%; `wifi` 7.8%; `ml_net_io` 6.6%; `ml_derp_tx` 3.5%; `tiT` 3.4%; TinyUSB 2.1% | **Not CPU-bound.** `usb_routes` costs about 1.5 ms per packet at ~1 Mbit/s, more than all of WireGuard. High `ipc1` suggests cross-core IPC on the per-packet path, possibly flash/cache operations (flash-directory or alias lookups) |

**Revised priority for PR-B:**

1. Profile and remove the per-packet cost in `usb_routes`: flash/directory access, linear scans, checksums.
2. Raise the forwarding path's priority and pin it to a core.
3. Event-driven wakeups instead of a faster tick.
4. The shared packet pool.
