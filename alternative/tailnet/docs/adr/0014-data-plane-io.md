# ADR 0014: Data-plane I/O: non-blocking USB transmit, bounded USB receive, DERP TCP window

Status: accepted for on-board validation, 2026-10-05. Follows ADR 0013 and `docs/research/forwarding-latency.md` (R4). Nothing here has been measured on the board yet; the plan is at the end.

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
  return ESP_OK / ESP_ERR_NO_MEM       usbd_defer_func(do_drain) ---> do_drain:
                                       (may block; holds no lock)       tud_network_can_xmit()
                                                                        tud_network_xmit()  (copies to NTB)
                                                                        publish tail (release)
```

- **No wait, no allocation under the lock.** The producer does a bounded `memcpy` into preallocated memory, two atomic stores and a task notification. The blocking `usbd_defer_func` is done by the worker, which holds no lock.
- **Single producer, single consumer.** `head` is written only by the producer and `tail` only by the TinyUSB task, with release/acquire ordering. No spinlock. Producers must be serialized by the caller, the same contract `send_sync` already had (the gateway sends under the core lock).
- **Byte ring, variable records** `[len:2][reserved:2][payload padded to 4]`. A record never wraps; a pad record skips the tail end. One word is always free so `head == tail` means empty. Capacity is bytes, not worst-case slots, so small frames (ACKs, DNS) do not each cost 1.5 KB.
- **Exactly-once.** A record is consumed once: the copy into the NTB is synchronous inside `tud_network_xmit()`, then `tail` advances. The ring owns its copy, so there is nothing for the caller to free and `free_tx_buffer` is not called for ring frames (a `ring` flag on the packet keeps the sync path's callback contract, including the v122 fix 505b08e, untouched). A stale or duplicate `do_drain` callback finds an empty ring and does nothing. Frames queued when USB goes away (`tud_ready()` false) are discarded and counted, not sent late.
- **Backpressure and drops, all counted** (serial `memory` report, kind `usb`): `tx_dropped_full` (ring full: the new frame is dropped, TCP sees ordinary loss), `tx_dropped_link_down`, `tx_dropped_invalid` (length outside 14..1518), `tx_flushed_link_down`, `tx_ntb_blocked` (a drain stopped because every NTB was in flight), plus `tx_high_water` and `tx_sent`. When every NTB is busy the worker polls once per tick; when idle it sleeps indefinitely.
- **Why a worker task** and not `usbd_defer_func` from the producer: see wait 2 above. Cost: one task, 2,560 B of stack plus a TCB.
- **Why tail-drop** and not drop-oldest: with one producer and one consumer only the consumer may move `tail`. Tail-drop is also the right signal for TCP (loss of the newest segment) and keeps frames in order.

Ring size is `GATEWAY_USB_TX_RING_BYTES` = 6,144 B (four full frames, 1,518 B including header). That is heap allocated once at USB start, in tailnet mode only.

### B. Bounded receive (`usb_rx_budget.h`)

`usb_rx` admits at most 12 frames (18 KB) in flight between the NTB copy and lwIP's free (`usb_free_rx`). Over the cap, the frame is dropped and counted (`rx_dropped_busy`). Frames outside 14..1518 bytes are rejected before the allocation (`rx_dropped_invalid`). Slots are released exactly once from `usb_free_rx`, which esp_netif calls on every path, including its own error paths. This replaces an effectively unbounded queue (tcpip mailbox 32 + router) with a bound that is visible in the report.

### C. NTB count: keep 2

Measured on the unified build (esp32s3, IDF 5.5.5), each extra IN NTB costs:

| `CONFIG_TINYUSB_NCM_IN_NTB_BUFFS_COUNT` | DIRAM used | Delta | Image |
|---|---|---|---|
| 2 (current) | 205,367 | | 1,248,659 |
| 3 | 211,775 | +6,408 | 1,255,123 (+6,464) |
| 4 | 218,183 | +6,408 | 1,261,487 (+6,364) |

One NTB is 6,400 B of data plus 8 B of list slots, and the buffers live in `.data`, so they also grow the flash image. With the ring decoupling the producer, a second NTB exists only to keep the USB endpoint fed while the next is filled. At full-speed USB (12 Mbit/s, about 1.1 MB/s of bulk payload) a 6,400 B NTB is on the wire for about 5.5 ms, and tunnel throughput is single-digit Mbit/s, so two NTBs plus the ring cover bursts. A third NTB (6.4 KB) buys less than the same memory in the ring (4 more frames) would. We keep 2 and expose `tx_ntb_blocked` and `tx_dropped_full`: raise the ring first, and only add an NTB if `tx_ntb_blocked` climbs while the ring stays below `tx_high_water` == `tx_ring_bytes`. This is a decision from the memory cost and the USB arithmetic, not from a throughput measurement; the on-board plan below measures it.

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

- `CONFIG_LWIP_TCP_RECVMBOX_SIZE` 6 -> 10 (window/MSS + 2, as the Kconfig says). With 6, lwIP would drop segments the window had admitted. Cost: 16 B per TCP socket.
- `CONFIG_LWIP_TCP_SND_BUF_DEFAULT` 5,760 -> 11,520. The send buffer holds unacknowledged copies, so this is real heap while a socket uploads at high rate (at most window-sized per socket, in flight only). Segment structures come from one shared pool of 16 (`MEMP_NUM_TCP_SEG`, not configurable in IDF), so across all sockets at most 16 x 1,440 = 23 KB can be queued, and one socket can fill its 8-segment buffer.
- Setup, HTTP and DNS sockets are not given larger windows (they cannot be), but they do not use them: the HTTP server is limited to 2 open sockets (`max_open_sockets = 2`) and DNS is UDP. A reader that keeps up holds nothing.

Honest cost: no standing heap; transient heap up to 11.5 KB per uploading socket, and up to 8 Wi-Fi RX buffers (about 13 KB of dynamic heap, taken from the same 16-buffer cap that already bounds Wi-Fi) per stalled-reader socket. The ceiling doubles; it does not lift the DERP path to the multi-Mbit/s that the egress changes may reach. Raising it further is a one-line change, but only with a larger Wi-Fi dynamic RX pool (each extra buffer is on-demand heap), and that trade should be made from the on-board numbers below.

`main/tcp_window_budget.h` makes the constraints build-time `_Static_assert`s in `gateway_main.c` (window below 64 KB without scaling, mailbox >= window/MSS + 2, window at most half the RX pool, send buffer fits the segment pool, at least two segments). `tools/test-tcp-window.py` compiles the same header against the values parsed from `sdkconfig.defaults` and proves each assertion is live by compiling five wrong configurations and requiring a failure.

## Rejected

- **A larger global window (12+ segments) now.** One stalled socket could pin most of the Wi-Fi RX pool, and `MEMP_NUM_TCP_SEG` caps the shared send side anyway. Revisit with on-board numbers.
- **Patching lwIP for per-pcb windows** (to give only DERP sockets more). The accounting above shows the cost is in the stalled-reader case, which a per-socket option would not remove for DERP itself; the patch would diverge from the pinned IDF.
- **A static pool of preallocated RX frames** for `usb_rx`. 12 x 1.5 KB of standing memory against a transient bound with the same limit.
- **Drop-oldest transmit** (needs the producer to move `tail`) and **a lock around the ring** (the producer would block the TinyUSB task or take a critical section with interrupts masked for every frame).
- **More NTBs** instead of a ring: 6.4 KB each, and they do nothing for the producer-side wait.

## Consequences

- `usb_tx` can no longer hold the core lock, so USB stalls stop being IP-stack stalls. They become counted ring drops.
- The tunnel-to-USB path costs one copy (into the ring) and one copy (into the NTB), and no `malloc`/`free` per packet.
- Standing memory: 6,144 B ring, one task (2,560 B stack + TCB). Static: +80 B `.bss`, +1.6 KB flash (see PR for `idf.py size`).
- Drops that were silent (`ESP_ERR_NO_MEM` from `malloc` or a 50 ms timeout) are now visible in the `usb` report.

## Validation and on-board plan

Host: `tools/test_net.py` runs the real `tinyusb_net.c` under ASan/UBSan, including the original ownership cases (unchanged) and `tests/mocks/net_ring_cases.c` (producer never waits or defers, exact capacity and backpressure, link-loss flush, duplicate and stale drain callbacks, wrap-around soak with random sizes, NTB credit and link flaps, sync and ring sharing one pipe). Mutating the code (wrap off-by-one, tail not advanced after xmit, ring frames calling the free callback, the producer deferring, a blocked frame dropped, full == empty) fails the tests. `tests/test_usb_rx_budget.c` covers the receive bound, including a concurrent producer/consumer. `tools/test-tcp-window.py` covers the window.

Board (coordinator), serial `memory` before and after each run (kind `usb`: `tx_dropped_full`, `tx_high_water`, `tx_ntb_blocked`, `rx_dropped_busy`):

1. Download direction (tunnel to host, the one that was slow): `iperf3 -c 198.18.0.86 -B 192.168.77.2 -R -t 30` with the server on 100.106.216.83 (`iperf3 -s -B 100.106.216.83`). Before this change 0.5-0.6 Mbit/s. Expect a rise and `tx_dropped_full` near 0. If `tx_dropped_full` > 0 with `tx_high_water` equal to `tx_ring_bytes`, raise the ring (try 8,192, then 12,288) before touching NTBs.
2. Upload (host to tunnel): same without `-R`, to confirm the `rx_dropped_busy` cap does not bite (expect 0).
3. Lock hold: with `-R` running, `tailscale ping -c 100` through the gateway; the spikes caused by `usb_tx` waits (up to 50 ms) should go away. Compare p99.
4. NTB: repeat 1 with `CONFIG_TINYUSB_NCM_IN_NTB_BUFFS_COUNT=3` only if `tx_ntb_blocked` grows during run 1.
5. DERP only: block UDP between the dongle and the peer so the tunnel falls back to DERP (below), repeat 1 and 2, read the TCP rate against the table above (1.44 Mbit/s at 64 ms with this window), and watch `heap min` and Wi-Fi RX drops.

Forcing DERP (not verified on the board; the dongle side cannot be told to avoid direct paths):

- On the iperf3 server's host (100.106.216.83), start `tailscaled` with the environment knob `TS_DEBUG_ALWAYS_USE_DERP=1`. That peer then never sends or answers direct (UDP) path probes, so the dongle's disco pings go unanswered and traffic stays on DERP. This needs the open-source `tailscaled` (the macOS App Store build does not take environment variables).
- Otherwise block direct UDP at the server host's firewall for the dongle's source address, for example with `pf` on macOS (`block drop quick proto udp from <dongle-wifi-ip> to any`), leaving DNS alone.
- Confirm the path before measuring with `tailscale ping 198.18.0.86` from the server host or the dongle's peer status: the reply must say `via DERP(<region>)`, not `via <ip>:<port>`.

## Invalidation

- `tx_dropped_full` stays high with the ring at 12 KB: the USB drain is slower than the producer, not bursty; look at the TinyUSB task priority and endpoint rate instead.
- Wi-Fi RX buffer exhaustion or `memory` heap minimum below the admission floor after the window change: return to 5,760 B and treat the DERP read path (PR-A) as the lever.
