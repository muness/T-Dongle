# ADR 0018: wg_mgr packet path: per-packet overhead removed, and a per-stage profiler (`wgperf`)

Status: accepted for on-board validation, 2026-10-05. Follows ADR 0013 (shared runtime), 0014 (router), 0015 (data plane), 0016 (DFS). **Nothing here has been measured on the board.** The code analysis below says what was removed and why it is wasteful; whether it explains the ~2.4 ms per packet is for the `wgperf` counters to say (plan at the end).

## Context

Board, diagnostics build, 240 MHz, iperf3 TCP upload host to tailnet over a direct UDP path: 1.64-1.65 Mbit/s in every build, whatever the RTT (125 ms down to 7-14 ms changed nothing). That is about 150 data packets a second. `ml_wg_mgr` used 61.4% of core 1 for about 3,900 packets in 15.8 s (2,581 data out, 1,323 ACKs in), i.e. about 2.4 ms of wg_mgr CPU per packet, while sealing 1,400 bytes is 62.6k cycles (0.26 ms at 240 MHz). About 90% of the task's time is not cryptography. No queue dropped anything, so the cap is the serialised latency of the per-packet path: a window of 8 segments, each paying the per-packet cost in the outbound and the ACK in the inbound direction.

## What one outbound data packet cost (reading the code)

`usb_routes` -> `route_emit_tunnel` -> `ml_gateway_queue_packet` -> `peer_update_queue` -> wg_mgr `process_peer_updates` -> pending slot -> `directory_flush_packets` -> `wg->output` under the lwIP core lock -> `wireguardif_peer_output` -> `wg_udp_output_cb` -> `udp_sendto`.

| Item | Before, per packet | Where |
|---|---|---|
| Heap allocations | **6**: `calloc(sizeof(ml_peer_update_t) + len)` (a ~600 B header, zeroed, plus the packet), the flush pbuf, the transport pbuf, the linearising buffer in `wireguardif_peer_output`, the "SPIRAM" wrapper and its data buffer in `wg_udp_output_cb` (this board has no PSRAM: they are internal heap) | ml_wg_mgr.c, wireguardif.c |
| Copies of the packet | **5** (into the queue block, `pbuf_take`, into the transport pbuf, linearise, into the custom pbuf), plus a `memset` of the whole transport pbuf and the zeroing `calloc` | |
| Ledger operations (diagnostics builds) | 6 tagged alloc/free pairs, each `heap_caps_get_free_size` + `heap_caps_get_allocated_size` + a critical section: the board run was a diagnostics image, so this is inside the 2.4 ms | `tdongle_memory.h`, `memory_diagnostics.c` |
| Peer lookups | `find_peer_by_ip` four times (queue, `trigger_handshake`, `peer_is_up`, flush), then the allowed-IP longest-prefix scan in wireguardif | each is a short linear scan of at most `ML_MAX_PEERS` entries in internal RAM: ~100 cycles. **Not a cost**; kept linear on purpose (a hash would be more code for nothing) |
| `ESP_LOGI` | **2 per outbound packet** (`WG peer UP` with `ipaddr_ntoa` and a key dump in `ml_wg_mgr_peer_is_up`, `WG UDP TX`), **1 per inbound packet** (`WG RX`) | see Logging |
| Pending slot, `trigger_handshake`, flush pass | every packet was parked in one of 8 slots, `ml_wg_mgr_trigger_handshake` called, and sent by the flush that follows in the same pass | |
| Seq-cst RMW on `peer_generation` | 4 | |
| Clock reads | about 4 `ml_get_time_ms` (a 64-bit division) per packet in the egress code, about 15 per pass | |
| Wake-ups | one `ml_rt_wake` per packet; `ulTaskNotifyTake` clears the count, so a burst leaves at most one wake-up behind that finds nothing, but that pass still pays the PM lock pair, three queue peeks and the clock reads | |

Inbound (ACK): `net_io` malloc+copy, `wg_rx_queue`, `process_wg_packet` (one `ESP_LOGI`, pbuf alloc+copy, begin under the core lock, decrypt outside it, complete under it, NAT and the router and the USB ring inside `complete`).

What was checked and is **not** a per-packet problem: the loop already drains the whole queue on a wake (`process_peer_updates` loops until empty; the 8 pending slots are the budget, not a per-pass limit), the wake is event driven (no 10 ms tick), `find_peer_by_ip` is trivially cheap, the budgets (`WG_MGR_*_BUDGET_MS`) are not reached at 150 pps, periodic and DISCO work run every 400 ms and 1 s and are sliced.

### Logging: does `ESP_LOGI` still cost anything with `CONFIG_ESP_CONSOLE_NONE=y`?

Yes. `sdkconfig.defaults` sets only the console channel (`CONFIG_ESP_CONSOLE_NONE=y`); the log level is the IDF default: `CONFIG_LOG_DEFAULT_LEVEL_INFO` and `CONFIG_LOG_MAXIMUM_EQUALS_DEFAULT` (read from IDF v5.5.5 `components/log/Kconfig.level`; the effective value is also printed from the build's `sdkconfig` in the PR). So `ESP_LOGI` is neither compiled out nor filtered: every call runs `esp_log_is_tag_loggable`, evaluates `esp_log_timestamp()` and calls `vprintf` (`esp_log_vprint_func`, nothing in this tree installs another), which formats the whole line before the console layer finds no (or a non-blocking secondary USB-Serial-JTAG) sink. Format cost is what it is regardless of where the bytes go. (The comments in wireguardif.c that say INFO is compiled out describe the project this code came from, which set `CONFIG_LOG_MAXIMUM_LEVEL=2`; this tree does not.) The board can measure it: `wgperf logbench` runs 200 `ESP_LOGI` of the old `WG UDP TX` line from the console task and prints cycles per line.

Every per-packet log site on the data path, found by grepping router.c, ml_net_io.c, ml_derp*.c, ml_zerocopy.c, wireguardif.c, gateway_main.c and ml_wg_mgr.c:

| Site | Before | Now |
|---|---|---|
| `wg_udp_output_cb` "WG UDP TX" | every datagram | handshake and cookie only (type != 4) |
| `ml_wg_mgr_peer_is_up` "WG peer UP ... key=%02x.." | every flushed packet | not called on the data path (`wg_peer_session_up` is the silent form); the function keeps its line for its other callers (`ml_tcp.c`, once per connect) |
| `process_wg_packet` "WG RX" | every inbound datagram | handshake and cookie only (type != 4) |
| ml_net_io `UDP RX` | `ESP_LOGD`: above the maximum level (INFO), compiled out | unchanged |
| wireguardif `WG_DEBUG` / `WG_HSLOG` | compiled out (`WG_DEBUG_LOGGING 0`, `WG_HS_TRACE 0`) | unchanged |
| router.c, ml_derp.c, ml_zerocopy.c, gateway_main.c usb paths | none per packet (rate-limited drop lines only: `& 0x1F`) | unchanged |

State-transition lines (handshake, session established, DERP connect, peer activation, rekey, send failure `[WG_OUT_FAIL]`) are all still logged.

### A finding outside this PR: the tailnet image runs at 100 Hz

`alternative/tailnet/sdkconfig.defaults` does not set `CONFIG_FREERTOS_HZ`; only the legacy root `sdkconfig.defaults` does (1000). The diagnostics build (`tools/build-diagnostics.sh` passes the tailnet defaults only) reads back `CONFIG_FREERTOS_HZ=100`, so one tick is 10 ms: every `vTaskDelay(1)` and every `wait_for_work` floor (`ticks == 0 -> 1`) is 10 ms. It does not cap 150 pps by itself (the wg_mgr wait ends on notification, `usb_routes` sleeps one tick only after 32 packets in a row), but the earlier "1 kHz tick" note in `docs/research/forwarding-latency.md` does not describe this tree. Left unchanged here (a global trade with heat, ADR 0016); the coordinator should know which tick the board images had.

## Decision

### A. One allocation and one copy per outbound packet, sealed in place

`ml_gateway_queue_packet` (called by `usb_routes`) builds the WireGuard datagram where it will be sent from: one `PBUF_TRANSPORT` RAM pbuf laid out `[16 B header space][plaintext, zero padded to 16][16 B tag space]`, a 12-byte record (destination, enqueue time, length) in its headroom (`pbuf_add_header`), and queues the pbuf pointer itself (bit 0 set to tell it from a peer-update block: `ml_pu_tag_packet`). wg_mgr removes the record, and for a resident peer with a session calls the new `wireguardif_output_prepared`, which picks the keypair, fills the header, encrypts in place and hands the same pbuf to `wireguardif_peer_output`. There the datagram goes to `udp_output_pbuf_fn` (`wg_udp_output_pbuf_cb`: `udp_sendto` on the pbuf as it is; lwIP adds its UDP, IP and link headers in the headroom and does not take them off again, so the callback reads the length before the send and never afterwards) or, for DERP, the payload pointer goes straight to the callback (which copies into its own queue block, as before). Chained pbufs and callers that register only the copying callbacks still take the old path, which is unchanged.

`wireguardif_output_to_peer` was split, not rewritten: `wireguardif_tx_keypair` (which keypair may send, with the same lazy-handshake arming, destruction of an expired keypair and result codes) and `wireguardif_tx_seal_send` (header, encrypt, send, `last_tx`, rekey flags) are shared by the copying and the in-place path, so they cannot drift apart. Equivalence is a test on the real wireguardif.c (`tests/test_wg_egress.c`): over every length around the padding boundary, both keypair roles, direct and DERP, send failure, no keypair, responder that never received, expired and exhausted keypairs, unknown destination, and both rekey triggers, the in-place datagram equals the copying one byte for byte and every side effect on the peer is identical; a receiver can open it; the callback sees the same pbuf and payload pointer (no copy). Mutating the in-place padded length fails it.

`directory_flush_packets` and parking keep the ADR-0012 amendment rules: a peer that is not resident is activated first (`directory_activate`, eviction rules and the trial rules untouched, the generation bumped around the activation), a packet for a peer without a session waits in one of `ML_JIT_PENDING` slots (queued plus parked, per membership) for at most 5 s while the handshake is triggered, and is dropped and counted when the peer goes away or the time runs out. New: a packet for an up peer with nothing parked ahead of it for the same destination is sent in the pass that dequeues it, without a slot, a handshake call, or the flush; a packet never overtakes one parked for the same peer, and parked packets are flushed in arrival order (`seq`), not slot order: slots are reused by whichever packet comes next, so slot order is not arrival order (a review finding, test in `test_jit_queue.c`). A packet no longer touches the odd/even `peer_generation` unless it activates a peer (status readers only care about changes to peer metadata).

Memory: the ledger no longer tags pending packets to the `wg` owner (they are lwIP pbufs now); the bound is unchanged (8 per membership, 1,466 B plus the pbuf header each, refused below the recovery reserve). A packet in flight is one allocation instead of the `calloc`.

### E. The seal runs outside the core lock (review of this PR)

`ChaCha20-Poly1305` over a 1,400 B packet is 62.6k cycles (0.26 ms); done inside the lock it stalls the tcpip thread (Wi-Fi receive, NAT) for that long on the other core, per packet. `wireguardif_output_prepared` is now three steps, the same pattern as the receive direction (PR #30, `wireguardif_rx_begin` / `wireguard_rx_decrypt` / `wireguardif_rx_complete`):

| Step | Lock | Does |
|---|---|---|
| `wireguardif_tx_begin` | held | allowed-IP lookup; `wireguardif_tx_keypair` (same rules and side effects as before); validates the pbuf (contiguous, at least `WIREGUARDIF_DATA_ALLOC(len)`, else `ERR_ARG`, nothing written or reserved); writes the header; copies the 32-byte key; **reserves the nonce** (`sending_counter++`); sets the rekey flags (post-increment counter, as before) |
| `wireguard_tx_seal` | none | encrypts the pbuf in place from the private key copy, then zeroes the copy. Reads and writes nothing but `job` and the pbuf, which only this task can reach |
| `wireguardif_tx_commit` | held | finds the peer again (removed meanwhile: `ERR_RTE`, dropped, pbuf still the caller's), `wireguardif_peer_output` with the endpoint as it is now, then `last_tx`: on the peer, and on whichever of the current and previous keypair still has the remote index the datagram was sealed with |

Why it is safe: a nonce is taken under the lock, by the same code that the lwIP timer's keepalive and the copying path use, so no (key, nonce) pair is ever used twice, and gaps are legal in WireGuard (a packet dropped at commit simply burns one). The key is copied, so a keypair rolled, destroyed or zeroed by the receive path while the seal runs cannot change what is sealed, and the seal cannot see a half-updated keypair; the datagram carries the receiver index of the key it was sealed with. The lock is taken twice per packet instead of once; an uncontended recursive-mutex pair is a few microseconds against 260 us of crypto no longer inside it. `gateway_send_packet` is the one caller; `wireguardif_output_prepared` remains the three steps in a row for callers that hold the lock throughout and for the equivalence tests.

Tests (`tests/test_wg_egress.c`): the split form equals the copying path byte for byte over 40 packets of different lengths on direct and DERP (counter advances by one, header counter field, `last_tx`), the previous-keypair fallback, the empty (keep-alive) datagram, a keypair rolled between begin and commit (sealed with the old key, nonce used once, timestamp to the keypair that now holds that index, none to the new one), keys destroyed between, peer removed between, refused short or missing pbuf, no keys arms the lazy handshake and reserves nothing. `test_wg_egress race`, under TSan: the egress sequence against a thread that rolls, destroys and replaces keypairs and seals its own datagrams from the same keypair, every datagram opens with the key of its receiver index and no (index, nonce) pair repeats.

### B. Logs

See the table above. Per-packet lines are gone; control and state lines stay.

### C. Idle slice early exit (`ml_wg_idle.h`)

Producers wake wg_mgr after every enqueue and the notification count is cleared in one `ulTaskNotifyTake`, so a burst can leave one wake-up that finds nothing. A slice that has no queued item, no pending packet or trial, a current directory generation, no due timer (400 ms, 1 s, 10 s), no STUN CallMeMaybe pending and no DERP state change only re-arms its timers and returns. `ml_wg_slice_idle` is a pure predicate with an exhaustive test (every blocker, 2^6 combinations, every timer boundary); any doubt is "not idle".

### D. `wgperf` (diagnostics builds only)

`components/tdongle_runtime/include/tdongle_wgperf.h`: per-stage (count, total, max), in CPU cycles (CCOUNT, exact at any DFS frequency) or microseconds (the enqueue-to-dequeue latency crosses cores), 64-bit atomic totals so a reader never sees a torn sum. Call-site macros compile to nothing without `CONFIG_TDONGLE_MEMORY_DIAGNOSTICS`, including the stamp variables (a release-mode host compile with `-Werror` proves it). Serial: `wgperf` (one JSON line), `wgperf reset`, `wgperf logbench`.

| Stage | Unit | What it covers |
|---|---|---|
| `q_latency` | us | `usb_routes` enqueue to wg_mgr dequeue: wake-up, scheduling, queue wait |
| `prep` | cy | producer side: heap guard, pbuf, copy, enqueue, wake (runs in `usb_routes`) |
| `pass`, `pm` | cy | one wg_mgr pass; the PM lock acquire and release around it |
| `updates`, `lookup` | cy | the egress drain of a pass; per packet peer lookup and session test |
| `lock_wait`, `lock_hold` | cy | taking the lwIP core lock, and the body under it, every wg_mgr site |
| `send` | cy | one egress packet from ready to handed to UDP/DERP, lock wait included |
| `out_lookup`, `out_seal`, `out_udp` | cy | wireguardif: allowed-IP match; keypair, header and encrypt; `peer_output` (UDP, IP, ARP, Wi-Fi hand-off) |
| `rx_pkt`, `rx_prep`, `rx_decrypt`, `rx_deliver` | cy | inbound datagram: all, pbuf copy, decrypt (lock released), `rx_complete` under the lock (NAT, router, USB ring) |
| `drain_wg`, `disco_rx`, `periodic`, `disco_tick` | cy | the receive drains, DISCO drain, 400 ms WireGuard periodic, 1 s probes |
| `batch` | pkt | packets sent in a pass that sent any (n = such passes) |

Counters: `wakes`, `passes`, `passes_idle` (no work), `passes_skipped` (early exit), `out_direct`, `out_parked`, `out_flushed`, `out_discard`, `in_pkts`, `lookup_scans`. Loop iterations per packet is `passes / (out_direct + out_flushed + in_pkts)`.

## Expected effect, honestly

Removed per outbound packet: 5 of 6 allocations, 4 of 5 copies, the 1.9 KB zeroing and the 1.4 KB `memset`, 3 of 4 peer lookups, 2 formatted log lines (1 per ACK), 4 seq-cst RMWs, the pending-slot round trip, and about 3 of 4 clock reads; in a diagnostics build also 5 of 6 ledger pairs. I expect this to be a clear fraction of the 2.4 ms but **cannot say how much without the board**: the cost of a formatted `ESP_LOGI` on a 240 MHz S3 and of a tagged allocation in the diagnostics build are exactly what `wgperf logbench` and the stage totals will show. Left in place and **not** attributed by analysis: the core-lock hold across `udp_sendto` and the Wi-Fi hand-off (`out_udp` and `lock_hold`), the ChaCha20-Poly1305 seal is no longer under the lock (section E; `out_seal` is now time outside it, and `lock_hold` should shrink by about that much), and instruction-cache behaviour now that FreeRTOS, the ring buffers and the heap run from flash (commit cc72801): a stage that is large per call but short in instructions would point there.

Microbenchmark (`build-host/bench_wg_egress bench`, the real wireguardif.c, -O2, a desktop heap, so read ratios only): sealing a 64 B packet takes 323 ns through the copying path and 219 ns in place (1.47x); at 1,400 B both are 2.04 us because ChaCha20-Poly1305 dominates on the host and its malloc and memcpy are cheap. That is the honest size of the wireguardif half of the change on a desktop; the board's allocator, the diagnostics ledger and the log formatting are what make the rest expensive there, and only `wgperf` can price them.

## Rejected

- **A hash for `find_peer_by_ip`.** Measured by reading: at most `ML_MAX_PEERS` compares in internal RAM. Four lookups became one; a table would add code and an invalidation rule for no gain. `lookup_scans` in the report shows the entries visited, so this can be revisited with a number.
- **A lock-free keypair.** The seal runs outside the lock (section E) from a copy of the key and a nonce reserved under the lock; making the keypair itself lock-free would change every reader in the lwIP receive path for no further gain.
- **Raising `ML_JIT_PENDING`.** The budget bounds memory for cold peers; with established peers sent in-pass, the queue now holds a packet only for the time of a pass.

## Validation

Host (all in `tools/test-gateway.sh`): `test_wgperf.c` (carry past 2^32, maximum, reset, call-site macros with an injected clock including counter wrap, four writers against a reader under ASan and TSan, release macros compile to nothing), `test_memory_report` (the `wgperf` lines are valid bounded JSON, reset zeroes), `test_wg_egress.c` (above), `test_jit_queue.c` (the producer builds exactly one pbuf in the transport layout and the budget, direct send, parking, ordering, activation under the odd generation, expiry, disappearance and every failure path give back the pbuf and the budget; it found a budget leak in the first draft of the direct path), `test_wg_idle.c`. Also: the PM activity hold had a race (below) found while investigating a flaky `test_pm_burst` run; see its commit.

## On-board plan (diagnostics build)

```
tools/build-diagnostics.sh                      # from the repo root, IDF v5.5.5 sourced
wgperf reset
# host:   iperf3 -B 192.168.77.2 -c 198.18.0.86 -t 15
wgperf                                          # one JSON line; elapsed_ms is the run
wgperf logbench                                 # cycles per formatted ESP_LOGI line
cpu                                             # per-task CPU, as before
```
Read: `stages.X = [count, total, max]` in `units`. Per packet cost of a stage is `total / count`; share of the pass is `total_X / total_pass`; compare `lock_wait` and `lock_hold` (CPU waiting versus working under the core lock), `out_udp` (the Wi-Fi hand-off), `out_seal` (62.6k cycles expected for 1,400 B), `q_latency` (wake and scheduling), `pm` (PM lock pair), `passes / out_direct` (loop iterations per packet) and `passes_skipped`. Run the same twice: this branch, and the base (`wgperf` is the new thing, so on the base use `cpu` and `memory locks` only) to read the throughput change.
