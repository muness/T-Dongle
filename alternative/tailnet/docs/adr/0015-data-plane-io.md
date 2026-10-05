# ADR 0015: Data-plane I/O: non-blocking USB transmit, bounded USB receive, DERP TCP window

Status: accepted for on-board validation, 2026-10-05. Numbered 0015 because PR #31 takes 0014. Follows ADR 0013 and `docs/research/forwarding-latency.md` (R4). Nothing here has been measured on the board yet; the plan is at the end.

## Context

Tunnel-to-USB traffic ran at about 0.5 Mbit/s against about 1 Mbit/s the other way, and a relayed (DERP) connection could not exceed about 0.7-1.3 Mbit/s at 36-64 ms round trip.

**USB transmit.** `usb_tx` (gateway_main.c) is the lwIP netif output for the USB interface. It runs in whoever holds the lwIP core lock: the tcpip task, or the WireGuard manager delivering a decrypted packet. It did `malloc` + `memcpy` and then `tinyusb_net_send_sync(..., 50 ms)`, which waits for the TinyUSB task to take the frame. Two waits are hidden in that call:

1. The sync call itself, up to 50 ms, whenever all NCM transmit blocks (NTBs) are in flight to the host.
2. `usbd_defer_func()` from a task is `xQueueSendToBack(..., UINT32_MAX)` in TinyUSB's OSAL (`osal_freertos.h`). When the TinyUSB event queue (16 entries, shared with USB interrupts) is full, it blocks forever, with the core lock held.

The same lock serves Wi-Fi RX delivery, NAT, the router and every socket, so a USB stall is an IP-stack stall.

**USB receive.** `usb_rx` copies each host frame out of the NTB with `malloc`; lwIP frees it later. Nothing bounded the number of copies: they queue behind the tcpip mailbox (32 entries) and the router queue, 1.5 KB each, exactly when the heap is smallest.

**TCP window.** lwIP's receive window is `TCP_WND` = 5,760 B (4 segments of 1,440 B), no window scaling, send buffer the same. One connection can move at most one window per round trip: 5,760 B / 64 ms = 0.72 Mbit/s, 5,760 B / 36 ms = 1.28 Mbit/s. This matches the measured DERP numbers.

## Decision

### A. Transmit ring (`tinyusb_net_tx_ring_send`)

The shared wrapper `components/esp_tinyusb/tinyusb_net.c` gains a second send contract beside `tinyusb_net_send_sync()`. The bridge (`main/bridge.c`) and `tdongle_l2` keep the sync call and their tests; they allocate nothing for the ring (it is created only by `tinyusb_net_tx_ring_start`, which only the gateway calls).

```
lwIP core lock holder                 usb_txq worker (prio 5)        TinyUSB task
tinyusb_net_tx_ring_send()
  copy frame into ring
  publish head (release)
  xTaskNotifyGive(worker) ---------> wake, ring non-empty?
  return ESP_OK / ESP_ERR_NO_MEM       usbd_defer_func(do_drain) ---> tx_drain():
                                       (may block; holds no lock)       tud_network_can_xmit()
                                                                        tud_network_xmit()  (copies to NTB)
                                                                        publish tail (release)
                          every IN transfer completion (__wrap_netd_xfer_cb) ---> tx_drain() again
```

- **No wait, no allocation under the lock.** The producer does a bounded `memcpy` into preallocated memory, two atomic stores and a task notification. The blocking `usbd_defer_func` is done by the worker, which holds no lock.
- **Single producer, single consumer.** `head` is written only by the producer and `tail` only by the TinyUSB task, with release/acquire ordering. No spinlock. Producers must be serialized by the caller, the same contract `send_sync` already had (the gateway sends from `usb_tx`, which lwIP calls under the core lock). `tools/test_net.py` runs the real code with a producer thread and a consumer thread under ThreadSanitizer; weakening the `head` release store to relaxed fails it.
- **Byte ring, variable records, byte-exact capacity** `[len:2][gen:2][payload padded to 4]`. The 4-byte header never straddles the end (offsets and capacity are multiples of 4); the payload may, and is copied in two parts by the producer and by `tud_network_xmit_cb`. One word is always free so `head == tail` means empty. A ring of `n * 1524 + 4` bytes holds `n` full frames at every write position (a test sweeps every position). An earlier draft padded to the end instead, which needs `(n + 1) * 1524 + 4` for the same guarantee.
- **Exactly-once.** A record is consumed once: the copy into the NTB is synchronous inside `tud_network_xmit()`, then `tail` advances. The ring owns its copy, so there is nothing for the caller to free and `free_tx_buffer` is not called for ring frames (a `ring` flag on the packet keeps the sync path's callback contract, including the v122 fix 505b08e, untouched). A stale or duplicate drain finds an empty ring and does nothing.
- **Link loss.** Each record carries the link generation current when it was queued. The producer bumps the generation the first time it finds USB not ready, so the frames queued before a cable pull are discarded by the next drain instead of being delivered to the next host; a drain that finds USB not ready also discards. (The first version flushed only inside a drain, and nothing triggers a drain while the link is down.)
- **Drain triggers, no polling.** The worker sleeps until a producer publishes (`portMAX_DELAY`), then asks TinyUSB to run `do_drain`. When every NTB is in flight the drain stops and the frame stays queued; the NCM driver's IN transfer-complete handler (`netd_xfer_cb`, wrapped with the linker flag `-Wl,--wrap=netd_xfer_cb` in `components/esp_tinyusb/CMakeLists.txt`) then drains again, in the TinyUSB task, right after the finished NTB returned to the free list. An in-flight NTB always completes, so a frame cannot be forgotten, and the refill adds no wakeup latency. The first version polled once per tick while blocked, and read its "blocked" flag before the deferred drain had set it, so the worker could go to sleep with the ring non-empty. That race is gone with the polling. The map file proves the wrap took: `usbd.c.obj` references `__wrap_netd_xfer_cb`, `tinyusb_net.c.obj` references the real `netd_xfer_cb`.
- **Backpressure and drops, all counted** (serial `memory` report, kind `usb`): `tx_dropped_full` (ring full: the new frame is dropped, TCP sees ordinary loss), `tx_dropped_link_down`, `tx_dropped_invalid` (length outside 14..1518), `tx_flushed_link_down`, `tx_ntb_blocked` (a drain stopped because every NTB was in flight), `tx_xfer_events` (completions that drained), `tx_worker_stack_free` (high-water mark of the worker stack, for the board check below), plus `tx_high_water` and `tx_sent`.
- **Why a worker task** and not `usbd_defer_func` from the producer: see wait 2 above. The `in_isr = true` variant is non-blocking but is an ISR-only API (`portYIELD_FROM_ISR` on Xtensa sets a switch flag that only an interrupt exit consumes), so it is not used from a task. Cost: one task, 1,536 B of stack plus a 340 B TCB (`sizeof(TCB_t)`, read from the ELF).
- **Why tail-drop** and not drop-oldest: with one producer and one consumer only the consumer may move `tail`. Tail-drop is also the right signal for TCP (loss of the newest segment) and keeps frames in order.

**Worker stack: 1,536 B.** The worker's deepest path is `tx_worker` (32 B frame) -> `usbd_defer_func` (48) -> `xQueueGenericSend` (64) -> `vTaskPlaceOnEventList` (32) -> `prvAddCurrentTaskToDelayedList` (32), frame sizes read from the linked ELF (`entry a1, N`), about 210 B, plus one Xtensa interrupt frame (`XT_STK_FRMSZ`, under 200 B). That is about 0.4 KB against 1,536 B, and 1,536 is above the IDF IPC task (1,280 B), which makes the same queue calls. Not measured on the board; `tx_worker_stack_free` reports the real number.

### B. Bounded receive (`usb_rx_budget.h`)

`usb_rx` admits at most 12 frames (18 KB) in flight between the NTB copy and lwIP's free (`usb_free_rx`). Over the cap, the frame is dropped and counted (`rx_dropped_busy`). Frames outside 14..1518 bytes are rejected before the allocation (`rx_dropped_invalid`). A slot is released exactly once: from `usb_free_rx`, which esp_netif calls on every path (checked against `ethernetif_input` in IDF v5.5.5: no interface, interface down, `esp_pbuf_allocate` failure and `netif->input` failure each free the buffer through the driver exactly once), or directly when `malloc` fails before the copy is handed over. `tud_network_recv_cb` ignores `usb_rx`'s result and always renews, so a refused frame cannot stall the NCM receive path. This replaces an effectively unbounded queue (tcpip mailbox 32 + router) with a bound that is visible in the report.

### C. NTB size: 3,200 B (was 6,400), count 2, to pay for the ring

Measured on the unified build (esp32s3, IDF 5.5.5), each extra IN NTB cost 6,408 B of DIRAM and the same in flash image (data buffers in `.data`). The first version of this ADR kept the NTBs and added the ring on top. That put about 8.7 KB on the heap before membership admission, whose margin on the release image is only about 4.6 KB (see Memory budget). The ring decouples the producer from the USB endpoint, so the NTBs no longer have to absorb producer bursts; they only have to keep the endpoint fed. So the two NTBs go back to esp_tinyusb's default of 3,200 B (the same size as the three OUT NTBs, two full frames each; Linux requires at least 2,048), and the 6,400 B this frees pays for the ring and its worker.

How big the ring is: it only has to hold what the producer adds between two drains. Drains happen at every IN completion, and an NTB of 3,200 B is on the wire for about 3.7 ms at the observed USB ceiling of 7 Mbit/s (875 B/ms), so one NTB period of a producer running flat out at that ceiling is about 3.2 KB. Three full frames (4,576 B) cover that with one frame to spare; the on-board runs saw 0.5-1 Mbit/s, well below it. Every byte of the ring is therefore justified by "one NTB period at the USB ceiling", and the working total buffering is 3 frames (ring) + 2 x 2 frames (NTBs) = 7 frames, against the previous 8 frames in NTBs alone.

If the board shows `tx_dropped_full` with `tx_high_water` equal to `tx_ring_bytes`, raise the ring before touching the NTBs, and pay for it from the Wi-Fi/TCP side (or after PR #30 frees about 23 KB), never from the admission margin. If `tx_ntb_blocked` climbs while the ring stays below `tx_high_water`, the host is slow to take NTBs and more NTBs would help. `main/gateway_main.c` has `_Static_assert`s that keep `NTB count x size + ring + worker (1,536 + 340)` within `2 x 6,400 + 512` (the previous NTB memory plus 512 B), that an NTB holds two frames and that the ring holds three. This is a decision from the memory cost and the USB arithmetic, not from a throughput measurement; the on-board plan below measures it.

### Memory budget: boot heap minus admission budget, release image

Admission (`start_member`) requires `free >= member_start_budget()` and a 24,000 B largest block. On the release image the board boots with about 107.8 KB free and the budget is 103,176 B, a margin of about 4,624 B. Everything this PR changes before admission, against base `overhaul/multi-tailnet` (9d2bda9), both built with `idf.py size` on IDF v5.5.5:

| Item | Bytes |
|---|---|
| DIRAM static, base 205,287 -> PR 198,975 (two IN NTBs 6,400 -> 3,200: -6,400; `s_tx`, rx budget counters, strings: +88 in `.bss`) | -6,312 |
| Heap at USB start: ring 4,576 + block header | +4,584 |
| Heap at USB start: worker stack 1,536 + block header | +1,544 |
| Heap at USB start: worker TCB 340 + block header | +348 |
| TCP receive mailbox 6 -> 10 entries, 16 B per TCP netconn, at most 4 open at admission | +64 |
| **Net change in boot free heap** | **+228** |
| New margin: 4,624 - 228 | **about 4,396, above the 4,096 bar** |

Assumptions, stated so they can be checked on the board: the 107.8 KB figure is 107,800 B from the release image (the margin moves by the same amount if it is 100 B off); block headers are at most 8 B; no other allocation changes (the TCP window and send buffer do not allocate until a socket uses them). The `largest >= 24,000` condition is not affected by the static shrink, and the 6.5 KB of heap taken at USB start comes out of the large boot region; read `largest` in the `admission` report to confirm. The first version (6,144 B ring, 2,560 B stack, NTBs unchanged) was +8.7 KB heap and no static saving: a margin of about -4.5 KB, i.e. the only membership refused. To get more margin without touching anything else, the ring can be cut to two frames (3,052 B): +1,524 B of margin at the cost of one frame of burst absorption.

Transient, not at admission: the send buffer doubles (5,760 -> 11,520 B), so a socket that uploads at full rate can hold four more queued segments. A queued segment is one `PBUF_RAM` pbuf (16 B header + 54 B link/IP/TCP headroom + 1,440 B payload, about 1.5 KB with the allocator header) plus a 20 B TCP segment record, so up to +6.2 KB per bulk-uploading socket: DERP is one per membership, and the setup HTTP server allows two sockets. Worst case +18.6 KB transient, on a board that has 44-66 KB free after one membership; it comes back when the data is acknowledged.

### D. TCP window: global 11,520 B (8 x MSS), send buffer the same, receive mailbox 10

What the IDF v5.5.5 lwIP supports (read in `components/lwip`):

- **Per-socket window: not available.** `LWIP_TCP_WND_DEFAULT`'s Kconfig help mentions `setsockopt(TCP_WINDOW)` and `TCP_SNDBUF`, but neither exists in the lwIP sources (`sockets.c`, `tcp.h`). `TCP_WND` is a compile-time constant, `TCP_WND_MAX(pcb)` is derived from it and `tcp_recved()` clamps to it, so a pcb cannot be given more. `SO_RCVBUF` is compiled out (`CONFIG_LWIP_SO_RCVBUF` unset) and in any case does not affect the TCP window. Making it per-pcb means patching the pinned IDF lwIP, which we do not carry.
- **Window scaling: not available and not needed.** `CONFIG_LWIP_WND_SCALE` depends on `SPIRAM_TRY_ALLOCATE_WIFI_LWIP`, and this board has no PSRAM. Any window below 65,536 B works without it, and we are far below that.

So the window is global, and the question is how large. Window memory is not reserved: lwIP's receive window is an advertised number. Memory is held only by segments that arrived and have not been read, and the data in flight in the network costs nothing. The real exposure is a stalled reader. With `CONFIG_LWIP_L2_TO_L3_COPY` off, queued TCP segments are pbufs that reference Wi-Fi RX buffers, so a stalled socket pins up to window/MSS of the 16 dynamic RX buffers (`CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM`). We therefore cap the window at half that pool:

| Window | Segments | Ceiling at 36 ms | at 64 ms | Pins at worst (one stalled socket) |
|---|---|---|---|---|
| 5,760 (before) | 4 | 1.28 Mbit/s | 0.72 | 4 of 16 RX buffers |
| **11,520 (chosen)** | **8** | **2.56** | **1.44** | **8 of 16** |
| 17,280 | 12 | 3.84 | 2.16 | 12 of 16: one stuck socket can starve Wi-Fi RX |

Companion changes, all in `sdkconfig.defaults`:

- `CONFIG_LWIP_TCP_RECVMBOX_SIZE` 6 -> 10 (window/MSS + 2, as the Kconfig says). With 6 the mailbox can fill before the window does when segments are small; lwIP then parks the data in `refused_data` and retries on its 250 ms timer instead of delivering it. The 10 entries only bound segments queued for the application, they do not allocate. Cost: 16 B per TCP socket.
- `CONFIG_LWIP_TCP_SND_BUF_DEFAULT` 5,760 -> 11,520. The send buffer holds unacknowledged copies, so this is real heap while a socket uploads at high rate: 8 queued segments per socket instead of 4. IDF builds lwIP with `MEMP_MEM_MALLOC = 1`, so the `MEMP_NUM_TCP_SEG` pool of 16 is only a default, not a limit: nothing caps the segments queued across all sockets except each socket's own send buffer (and `TCP_SND_QUEUELEN` = 4 x buffer/MSS = 32 segments per socket for tiny writes). The worst case is therefore per socket, summed over the sockets that send at once (see Memory budget).
- Setup, HTTP and DNS sockets are not given larger windows (they cannot be), but they do not use them: the HTTP server is limited to 2 open sockets (`max_open_sockets = 2`) and DNS is UDP. A reader that keeps up holds nothing.

Honest cost: no standing heap; transient heap of about 12.3 KB per bulk-uploading socket (6.2 KB more than before), and up to 8 Wi-Fi RX buffers (about 13 KB of dynamic heap, taken from the same 16-buffer cap that already bounds Wi-Fi) per stalled-reader socket. The "half the pool" rule is per socket, not aggregate: lwIP offers no cap across sockets, so four sockets that all stall with full windows (DERP, the control stream and two setup HTTP connections) could pin the whole pool, and the Wi-Fi driver then drops frames (counted, no crash). A reader that keeps up pins nothing, and every long-lived socket here has a task that reads continuously. The ceiling doubles; it does not lift the DERP path to the multi-Mbit/s that the egress changes may reach. Raising it further is a one-line change, but only with a larger Wi-Fi dynamic RX pool (each extra buffer is on-demand heap), and that trade should be made from the on-board numbers below.

`main/tcp_window_budget.h` makes the constraints build-time `_Static_assert`s in `gateway_main.c` (window below 64 KB without scaling, mailbox >= window/MSS + 2, window at most half the RX pool, send buffer within the default segment pool size, at least two segments). The last-but-one is a sanity bound on the lwIP default, not a heap limit (see above). `tools/test-tcp-window.py` compiles the same header against the values parsed from `sdkconfig.defaults` and proves each assertion is live by compiling five wrong configurations and requiring a failure.

## Rejected

- **A larger global window (12+ segments) now.** One stalled socket could pin most of the Wi-Fi RX pool, and the send side grows the same way. Revisit with on-board numbers.
- **Patching lwIP for per-pcb windows** (to give only DERP sockets more). The accounting above shows the cost is in the stalled-reader case, which a per-socket option would not remove for DERP itself; the patch would diverge from the pinned IDF.
- **A static pool of preallocated RX frames** for `usb_rx`. 12 x 1.5 KB of standing memory against a transient bound with the same limit.
- **Drop-oldest transmit** (needs the producer to move `tail`) and **a lock around the ring** (the producer would block the TinyUSB task or take a critical section with interrupts masked for every frame).
- **More or larger NTBs** instead of a ring: 6.4 KB each at the old size, and they do nothing for the producer-side wait.
- **A ring on top of the unchanged 2 x 6,400 B NTBs** (the first version of this PR): +8.7 KB of heap before admission against a 4.6 KB margin.
- **Kicking TinyUSB from the producer** with `usbd_defer_func(..., in_isr = true)`: non-blocking, but an ISR-only API.
- **Polling from the worker while NTBs are busy**: a tick-rate wakeup that was also racy (see A). The IN transfer-complete event replaces it.

## Consequences

- `usb_tx` can no longer hold the core lock, so USB stalls stop being IP-stack stalls. They become counted ring drops.
- The tunnel-to-USB path costs one copy (into the ring) and one copy (into the NTB), and no `malloc`/`free` per packet.
- Standing memory: 4,576 B ring and one task (1,536 B stack + 340 B TCB), paid for by the IN NTBs going from 6,400 to 3,200 B: net +228 B of boot heap (Memory budget). Flash code +1.7 KB, image -4.7 KB (the NTBs were in `.data`).
- Each IN NTB now carries at most two full frames, so one NTB holds less of a burst than before; the ring holds three more.
- The legacy bridge image keeps 4 x 6,400 B NTBs (root `sdkconfig.defaults`) and does not start the ring. It links the same wrapper, so the `--wrap` is present there too and is a no-op when the ring is not started.
- Drops that were silent (`ESP_ERR_NO_MEM` from `malloc` or a 50 ms timeout) are now visible in the `usb` report.

## Validation and on-board plan

Host: `tools/test_net.py` runs the real `tinyusb_net.c` under ASan/UBSan, including the original ownership cases (unchanged) and `tests/mocks/net_ring_cases.c` (producer never waits or defers, exact capacity and backpressure, link-loss flush, duplicate and stale drain callbacks, wrap-around soak with random sizes, NTB credit and link flaps, sync and ring sharing one pipe). `tests/mocks/net_ring_threads.c` runs the ring with two real threads under ThreadSanitizer. Mutating the code (capacity off by one, no wrap copy, wrong second-part source, tail not advanced after xmit, ring frames calling the free callback, the producer deferring, link generation ignored, `drain_pending` never cleared or never tested, IN completion not draining, `tud_ready()` ignored, release store of `head` weakened) fails the tests. `tests/test_usb_rx_budget.c` covers the receive bound, including a concurrent producer/consumer. `tools/test-tcp-window.py` covers the window.

Board (coordinator), serial `memory` before and after each run (kind `usb`: `tx_dropped_full`, `tx_high_water`, `tx_ntb_blocked`, `tx_xfer_events`, `tx_worker_stack_free`, `rx_dropped_busy`), plus `admission` for the margin:

1. Download direction (tunnel to host, the one that was slow): `iperf3 -c 198.18.0.86 -B 192.168.77.2 -R -t 30` with the server on 100.106.216.83 (`iperf3 -s -B 100.106.216.83`). Before this change 0.5-0.6 Mbit/s. Expect a rise and `tx_dropped_full` near 0. If `tx_dropped_full` > 0 with `tx_high_water` equal to `tx_ring_bytes`, raise the ring one frame at a time (6,100, then 7,624), watching the admission `free` against `budget`, before touching NTBs.
2. Upload (host to tunnel): same without `-R`, to confirm the `rx_dropped_busy` cap does not bite (expect 0).
3. Lock hold: with `-R` running, `tailscale ping -c 100` through the gateway; the spikes caused by `usb_tx` waits (up to 50 ms) should go away. Compare p99.
4. NTB: repeat 1 with `CONFIG_TINYUSB_NCM_IN_NTB_BUFF_MAX_SIZE=6400` only if `tx_ntb_blocked` grows during run 1. Also read `tx_worker_stack_free`: below 768 means the 1,536 B stack should be raised.
4a. Admission: on a fresh boot of the release image read `admission` (`free` against `budget`, `largest`) and confirm the margin is at least 4 KB; this PR predicts about 4.4 KB.
5. DERP only: block UDP between the dongle and the peer so the tunnel falls back to DERP (below), repeat 1 and 2, read the TCP rate against the table above (1.44 Mbit/s at 64 ms with this window), and watch `heap min` and Wi-Fi RX drops.

Forcing DERP (not verified on the board; the dongle side cannot be told to avoid direct paths):

- On the iperf3 server's host (100.106.216.83), start `tailscaled` with the environment knob `TS_DEBUG_ALWAYS_USE_DERP=1`. That peer then never sends or answers direct (UDP) path probes, so the dongle's disco pings go unanswered and traffic stays on DERP. This needs the open-source `tailscaled` (the macOS App Store build does not take environment variables).
- Otherwise block direct UDP at the server host's firewall for the dongle's source address, for example with `pf` on macOS (`block drop quick proto udp from <dongle-wifi-ip> to any`), leaving DNS alone.
- Confirm the path before measuring with `tailscale ping 198.18.0.86` from the server host or the dongle's peer status: the reply must say `via DERP(<region>)`, not `via <ip>:<port>`.

## Invalidation

- `tx_dropped_full` stays high with the ring at 12 KB: the USB drain is slower than the producer, not bursty; look at the TinyUSB task priority and endpoint rate instead.
- Wi-Fi RX buffer exhaustion or `memory` heap minimum below the admission floor after the window change: return to 5,760 B and treat the DERP read path (PR-A) as the lever.
