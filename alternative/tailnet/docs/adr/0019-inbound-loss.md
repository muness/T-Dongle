# ADR 0019: Inbound path: count every drop; the silent UDP loss (socket mailbox, one datagram per pass) and the replay window

Status: accepted for on-board validation, 2026-10-05. Follows ADR 0013 (shared runtime), 0015 (data-plane I/O), 0018 (wg_mgr packet path). **The cause below is established by reading the code and by host models, not yet by a board run.** The counters this ADR adds exist to confirm or refute it in one run (plan at the end).

## Context

Board, diagnostics build, UDP `iperf3 -R` tailnet to USB host, `-l 1200`, 10 s, direct path, RSSI -48 dBm, no disconnects:

| | sent by iperf3 | lwIP `udp.recv` | USB frames sent | received by host | lost inside the dongle |
|---|---|---|---|---|---|
| 3 Mbit/s | 3,133 | 3,228 (about 95 control datagrams) | 2,927 | 2,905 | about 210-225 (7 %) |
| 2 Mbit/s | 2,091 | 2,189 | 1,995 | 1,967 | about 6 % |

No existing counter moved: `usb.tx_dropped_full` 0, router drops 0, `net_wg_full` 0, DERP drops 0, lwIP link/ip/udp drop 0, pool errors 0. TCP downloads showed 100-140 retransmissions in 15 s at about 2 Mbit/s.

So datagrams reached lwIP's UDP layer, and were gone before the USB transmit, without anything counting them.

## Where inbound datagrams were lost without a trace

Reading the whole inbound path (lwIP socket -> `ml_net_io` -> `wg_rx_queue` -> `process_wg_packet` -> `wireguardif` -> `gateway_tunnel_input` -> `usb_tx`):

1. **lwIP's socket mailbox (the cause).** The direct-path UDP socket is a BSD socket. lwIP counts `udp.recv` in `udp_input`, then `recv_udp()` posts the datagram to the socket's receive mailbox and, **if the mailbox is full, frees it and returns without incrementing any counter** (`api_msg.c`: `sys_mbox_trypost` failure; `udp.drop` and `udp.memerr` stay 0). The mailbox holds `CONFIG_LWIP_UDP_RECVMBOX_SIZE` datagrams: 6, the IDF default, which `sdkconfig.defaults` never set. And `ml_net_io` read **one datagram per ready socket per `select()` pass**, on core 0 at priority 7, the core where the Wi-Fi and tcpip tasks (higher priority) deliver a burst before net_io is scheduled. A burst longer than the passes net_io gets between two bursts leaves a backlog; the backlog fills the 6-slot mailbox; the next datagrams vanish. Every observation fits: `udp.recv` includes them (counted before the mailbox), `udp.drop`/`memerr` are 0 (recv_udp does not count), `net_wg_full` is 0 (the queue behind net_io never filled, because net_io was the slow stage), the loss rises with the offered rate (more datagrams per burst), and the dongle-side total is `udp.recv` minus what net_io read.
2. **The replay window was 32 packets** (RFC 2401 shift register, `wireguard_check_replay`). A datagram more than 32 counters behind the highest accepted one is dropped as "too old" with nothing counted. Whether the firmware reorders was checked, not assumed: one `wg_rx_queue` per membership, one consumer (`wg_mgr`), each datagram is begun, decrypted and completed before the next is taken, and the decrypt-off-lock split (ADR 0013) is inside one task, so completion order is arrival order (`tests/test_wg_rx_counters.c`, "ordering": in order, and pipelined begin/decrypt/complete batches deliver in order). Arrival order itself is not firmware's to control: a path switch between DERP and a direct endpoint, Wi-Fi retries or a multi-queue sender reorder datagrams, and the old register lost 1.6 % of a stream reordered 33 deep, 45 % at 64, 82 % at 200 (host reproduction on the real algorithm, below). With in-order arrival (the iperf test) the old window loses nothing, so it is not the explanation of the 7 % but it is a real defect and `wg.rx_replay_old` will say if it contributes.
3. Smaller silent drops on the same path, each now counted: net_io `malloc` failure copying the datagram; a zero-length datagram; the DERP source key admitted to no slot (`derp_sender_admit`), no WireGuard interface, `pbuf_alloc` failure in `process_wg_packet` and in `wireguardif_rx_data_prepare`; every post-decrypt refusal in `wireguardif_rx_data_complete` (replay, short or non-IP plaintext, allowed-IPs, bad length, `netif->input` failure); the router's tunnel-to-USB refusals (one counter, `reply_nomatch`, for four different reasons); `gateway_tunnel_input`'s allocation failure; `usb_tx` refusals.

## Decision

### A. Fix the mailbox loss

- **`ml_net_io_drain.h`: read a ready socket until it is empty**, at most `ML_NET_IO_DRAIN_CAP` = 16 datagrams per socket per pass (a full mailbox at the largest allowed size, `CONFIG_LWIP_UDP_RECVMBOX_SIZE` <= 16, empties in one pass). The cap keeps one busy socket from holding the shared net_io task and the mux lock; what is left stays in the mailbox and `select()` returns at once (`drain_capped` counts it). The wg_mgr wake is now once per drain, not once per datagram (a burst used to leave one idle wg_mgr pass behind per datagram). Datagram order within a socket is preserved. The loop body is a header so the host tests run the real code; `ml_net_io.c` only supplies `recvfrom` and the sink.
- **`CONFIG_LWIP_UDP_RECVMBOX_SIZE` 6 -> 10** (`sdkconfig.defaults`). 4 B per slot per UDP socket, but a queued datagram pins its Wi-Fi RX buffer until net_io reads it (the IDF Wi-Fi to lwIP path is zero-copy), so it is kept small: 10 of the 22 Wi-Fi RX buffers (6 static + 16 dynamic) at the very worst, and only until net_io's next pass. The drain loop is the fix; the mailbox widens the burst that may arrive between two net_io runs. Rejected: 64 (the Kconfig maximum), which would let one socket pin every Wi-Fi RX buffer and starve the driver.
- Loss that is still possible is now visible: `ml.q_wg_full` (wg_rx_queue overflow: the consumer is the slow stage, the right place to drop), `ml.udp_alloc_fail`, and the mailbox itself as `lwip.udp_recv - ml.udp_rx`.

### B. Replay window: 32 -> 512 bits, RFC 6479 ring

`wireguard_replay.h` replaces the shift register with a ring of 32-bit blocks (the algorithm of the kernel's `counter_validate()` and wireguard-go's `replay.Filter`): a forward jump clears only the blocks it passes (at most the ring), a counter inside the window is a bit test and set, nothing older than `WINDOW = RING - 32` below the highest accepted counter is accepted, a counter at or above `REJECT_AFTER_MESSAGES` is refused outright, and nothing is recorded unless the datagram authenticated. It returns *why* (`DUPLICATE`, `TOO_OLD`, `LIMIT`) so each has its own counter.

**Size: 512 bits (window 480), 64 B per keypair.** The window must cover the reordering the network produces, and every byte is paid three times per peer slot (current, previous, next keypair) in a pool that the admission budget charges (ADR 0013, `ml_admission.h` reads `sizeof(struct wireguard_peer)`).

| Ring | Window | Per keypair | `sizeof(wireguard_peer)` on the target | Admission requirement, first membership (4 slots charged) | Margin against ~107,000 B free after boot | Covers a lateness of, at 600 pps (the USB full-speed ceiling is about 580 1,500 B datagrams a second) |
|---|---|---|---|---|---|---|
| 32 (before) | 32 | 4 B | 904 B (read from the ELF) | 103,052 B | 3,948 B | 53 ms |
| **512 (this)** | **480** | **64 B** | **1,096 B** (read from the ELF) | **103,820 B** | **3,180 B** | **0.8 s** |
| 1,024 | 992 | 128 B | about 1,288 B | about 104,590 B | about 2,410 B | 1.7 s |
| 2,048 | 2,016 | 256 B | about 1,672 B | about 106,120 B | about 880 B | 3.4 s |

The 3,948 B margin of the first membership is all the headroom there is (`tests/test_admission.c` prints the arithmetic); 2,048 bits (the size suggested by wireguard-go's old default; its current ring and the kernel's cover 8,128) would take it to about 880 B and 1,024 would take 39 % of it for a window the evidence does not ask for: the reordering that exists is a DERP/direct path switch (tens to a few hundred milliseconds of skew) and Wi-Fi retries (milliseconds), and 480 covers 0.8 s at the highest rate this device can forward. 512 costs +192 B per slot (+768 B admission, 19 % of the margin; +2,304 B if all 12 pool slots are resident) and the stack of the three by-value keypair copies in `wireguard_start_session` and `add_new_keypair` grows by 64 B per copy. `WIREGUARD_REPLAY_RING_BITS` is a compile-time constant (64..8192, power of two) and every test runs at 64, 128, 512, 2048 and 8192, so the number can be changed with the arithmetic in this table and nothing else.

### C. Count everything

Always compiled (a relaxed atomic add on a cold path, or one per delivered packet, against about 2.4 ms of wg_mgr CPU per forwarded packet in ADR 0018; 4 B per counter; no timestamps, no locks, no allocation). Reported by the serial `inbound` command (diagnostics build; `wgperf reset` does not touch them: they are cumulative and meant to be subtracted) and, for the router, in `route`.

**`ml` (`ml_rx_stats.h`)**: `udp_rx` (every datagram net_io read from any socket), `udp_rx_empty`, `udp_unclassified` (< 4 bytes), `udp_alloc_fail`, `udp_recv_err`, `udp_wg` / `udp_disco` / `udp_stun` (classification), `q_wg_full` / `q_disco_full` / `q_stun_full` (queue overflow when net_io offered the packet), `derp_rx_wg`, `derp_q_wg_full`, `drain_calls`, `drain_capped`, `drain_burst_max` (gauge: the most datagrams one drain call read), `wg_in`, `wg_sender_unknown`, `wg_no_netif`, `wg_pbuf_fail`, `wg_to_wireguardif`.

**`wg` (`wireguard_stats.h`)**: every transport datagram counted by `rx_data` ends in exactly one terminal counter (identity checked at quiescence on 12,000 mixed datagrams, both entry points): `rx_no_peer` (receiver index owned by no peer), `rx_keepalive_skipped` (below), `rx_keypair_unusable`, `rx_expired` (REJECT_AFTER_TIME / MESSAGES; the keypair is destroyed, as before), `rx_alloc_fail`, `rx_session_gone` (peer or keypair vanished while the datagram was decrypted outside the lock), `rx_decrypt_fail` (tag did not verify), `rx_keepalive` (authenticated, nothing to deliver), `rx_replay_dup`, `rx_replay_old`, `rx_replay_limit`, `rx_bad_ip` (not a whole IPv4/IPv6 header), `rx_allowed_ip`, `rx_bad_length`, `rx_input_fail`, `rx_delivered`. `rx_bad_type` counts datagrams that were never transport data.

**`route`**: `tunnel_malformed`, `tunnel_nomem`, `bad_packet`, and the reasons that used to be one `reply_nomatch` (still the sum of the membership and flow reasons): `reply_no_member`, `reply_not_us`, and from `rt_flow_in_why` `reply_flow_range`, `reply_no_flow`, `reply_generation` (USB re-enumerated since), `reply_owner` (membership, peer, remote port, mapped port or protocol mismatch), `reply_idle`; `usb_tx` / `usb_tx_err` (every frame the USB netif transmit saw, and those it refused); `tx_fail`. `forwarded_in` now counts only frames the USB netif accepted.

**Reconciliation** (`tools/inbound_accounting.py`, quiet gateway): `lwip.udp_recv - ml.udp_rx` is the mailbox loss (a handful for DNS and other non-net_io sockets; the pre-fix run would show about 220); `ml.udp_wg = q_wg_full + enqueued`; `ml.wg_in` counts what wg_mgr took (DERP and handshakes included); `wg.rx_data` <= `ml.wg_to_wireguardif`; `wg.rx_delivered = route.forwarded_in + route.(refusals)`; `route.usb_tx` >= `usb.tx_sent` + ring drops.

## Defects found while tracing the path (fixed unless said)

1. **Replayed datagrams moved the peer's endpoint and refreshed its timers.** `wireguardif_rx_data_complete` ran `update_peer_addr`, `last_rx` and the keypair promotion *before* the replay check, so anyone on the path who captured one authentic datagram could replay it from another address and redirect the peer (WireGuard's roaming is safe only because replay protection comes first; the kernel checks the counter before anything else). Now the order is decrypt, replay check, then endpoint, timers, promotion (test: a replay from another address leaves the endpoint and `last_rx` untouched).
2. **The datagram that promoted a responder's next keypair was checked against the wiped slot.** `keypair_update` copies next to current and zeroes next; the replay check then ran on the zeroed struct, so that one datagram was never recorded in the live window and could be replayed once more. Fixed by the same reordering (the check happens on the keypair that received the packet, before it is copied; the window travels with the copy). Test: `t_promotion`.
3. **Keepalives were not replay-checked** (only datagrams with a payload were). They now consume counters like every other authenticated datagram.
4. **A short plaintext was read past its end.** The authenticated peer chooses the plaintext length (padding is not enforced); `IPH_V` and `IPH_LEN` read the first 20 bytes of a buffer that could hold 1. The decrypted buffer is exactly the plaintext's size, so this was a heap over-read of up to 19 bytes (found by writing the test: ASan fails on the exact-size buffer). Now `rx_bad_ip`.
5. **`gateway_tunnel_input` freed the packet and returned `ERR_MEM`; the caller then freed it again** (lwIP's input contract: on an error the caller owns the pbuf). A double free the first time the heap ran out under load. Test: ASan on `tests/test_router_rx_reasons.c`.
6. `forwarded_in` was incremented even when the USB netif refused the frame; it now counts accepted frames, and `tx_fail` the refusals.
7. **Not changed, flagged: the wg_mgr split path discards keepalives.** `wireguardif_rx_begin` required `len > 16 + 16`, and a keepalive is exactly 32 bytes, so it never reaches decryption: no endpoint update, no `last_rx`, no promotion of a responder's next keypair until a data packet arrives (the one-piece `wireguardif_network_rx` path handles them). Fixing it changes behaviour that other code reads (`wg_peer_activity` feeds `jit_used_ms`, i.e. peer residency and eviction), so it is counted as `rx_keepalive_skipped` and left for the owner of that policy; the counter says how often it happens.
8. Not changed: the IPv6 branch of the receive path reads the flow-label bytes as a length (`IPH_LEN` on an IPv6 header) and has no AllowedIPs check (existing TODO); the gateway router drops everything but IPv4 downstream, so nothing reaches USB either way.

## Rejected

- **Raising `ML_WG_RX_QUEUE_DEPTH`** (8) to hide bursts: each slot is a 1.3 KB heap packet, and the loss was upstream of it. `q_wg_full` will say if it is needed next (the diagnostics `--queue-depth` sweep exists).
- **Moving the UDP receive to a raw PCB callback** (`CONFIG_ML_ZERO_COPY_WG`, present and off): removes the mailbox entirely but runs WireGuard receive in the tcpip thread, which ADR 0013 moved off it.
- **A replay window per peer instead of per keypair**: the previous and next keypairs receive concurrently with the current one during a rekey, and sharing a window would accept a counter twice.
- **2,048-bit ring**: see the table; it takes the admission margin from 3,948 B to about 880 B.

## Cost (measured from the builds of the base commit 97f2feb and this branch, IDF v5.5.5, same defaults)

| | Base | This branch | Delta |
|---|---|---|---|
| Release unified image (`.bin`) | 1,261,088 B (0x133e20) | 1,261,936 B (0x134170) | +848 B (flash code +812, flash data +32) |
| Diagnostics image (`.bin`) | 1,278,464 B (0x138200) | 1,280,672 B (0x138aa0) | +2,208 B (code +1,208, data +992: the `inbound` report) |
| Static DRAM, release | `.bss` 88,728 B, `.data` 38,624 B | `.bss` 88,928 B, `.data` 38,624 B | +200 B (the counters, about 160 B, and alignment) |
| Static DRAM, diagnostics | `.bss` 91,624 B | `.bss` 91,824 B | +200 B |
| Legacy bridge image | unchanged source | builds | 0 |
| `sizeof(struct wireguard_peer)` (xtensa, from the objects) | 904 B | 1,096 B | **+192 B per peer slot** (3 keypairs x 64 B), heap, on demand |
| `sizeof(struct wireguard_keypair)` | 120 B | 184 B | +64 B |
| Admission requirement, first membership | 103,052 B | 103,820 B | +768 B (4 slots charged), margin 3,948 B -> 3,180 B |
| All 12 pool slots resident | 10,848 B | 13,152 B | +2,304 B |
| Frame of `wireguard_start_session` (it holds a keypair by value) | 272 B | 400 B | +128 B on the stack of the task that completes a handshake |
| `wireguardif_rx_data_complete`, `wireguardif_network_rx`, `wireguardif_rx_begin` frames | 48 / 224 / 48 B | 48 / 224 / 48 B | 0 |
| `CONFIG_LWIP_UDP_RECVMBOX_SIZE` | 6 | 10 | +16 B per UDP socket (4 slots x 4 B) |

Per-datagram CPU: the replay check is a block test and set (the shift register did a shift and an or); each counter is one relaxed atomic add (a compare-and-swap loop on the S3, on cold paths except `rx_delivered`, `udp_rx` and the per-class counters, a handful per datagram); the drain loop adds one failed `recvfrom` per pass (an `EWOULDBLOCK` the old loop's next `select()` paid anyway). Against about 2.4 ms of wg_mgr CPU per forwarded packet (ADR 0018) this is below what `wgperf` can resolve; the board run reads `rx_pkt` to confirm.

## Validation

Host, all in `tools/test-gateway.sh`:

- `test_wg_replay.c` (ASan/UBSan, at 512, 64, 128, 2,048 and 8,192 bits): the ring against an exact reference model (the set of accepted counters and the maximum): every sequence of up to 5 counters over spans that straddle the window, the 32-bit boundary and `REJECT_AFTER_MESSAGES`; 3,000 random sequences per size (in-order jitter, reordering around the window edge, jumps of several rings, replays from the bottom, the top of the number space, random 64-bit values); window-edge and jump-size sweeps; the reject limit and wrap at 2^64; an attacker replaying captured datagrams in any order (never accepted twice, never makes the filter forget). The same file reproduces the arrival patterns the old register lost (above). Mutants killed: window +-1, limit `>`, no block clear, clear cap, no duplicate test, clear from 0, wrong ring mask (8 of 8).
- `test_wg_rx_counters.c` (ASan/UBSan, the real `wireguard.c` and `wireguardif.c` on lwIP fakes, both the wg_mgr split path and the one-piece path): each drop point increments exactly its counter and nothing else (a one-hot delta over every counter), including exact-size short plaintexts; `rx_data` equals the sum of terminals over a random mix; replay protection precedes endpoint and timer updates; promotion; the previous keypair; reordered arrival accepted to the window edge and refused beyond it with exact counts; in-order and pipelined delivery order.
- `test_net_io_drain.c` (ASan/UBSan): the real drain code on a scripted socket (cap, empty datagrams, errors, order, every counter) and a mailbox model that shows the old loop's dependence on how many passes fall between bursts (0 % to 42 % in the model) against the new loop's none up to the mailbox size. Mutants killed: 6 of 6.
- `test_rx_stats_threads.c` (TSan and ASan): four writers and a reader, no lost increments, a max gauge that only grows.
- `test_router_rx_reasons.c` (ASan/UBSan): every tunnel-to-USB reject reason moves exactly its counter (plus the `reply_nomatch` sum where it applies), the allocation-failure ownership rule (mutant: freeing in the router fails under ASan), the USB refusal.
- `test-memory-report.py`, `test-measurement-scripts.py` (the `inbound` report and the accounting script), `test_admission.c` (slot size 1,096 B).

Not testable on the host: the Xtensa build's behaviour of the lwIP mailbox, Wi-Fi burst structure, and the actual scheduling of net_io on core 0. That is the board run.

## On-board plan (diagnostics build)

```
tools/build-diagnostics.sh                       # repo root, IDF v5.5.5 sourced; flash the image it prints
tools/inbound_accounting.py snapshot before.json --port /dev/cu.usbmodemXXXX
iperf3 -c <dongle tailnet address> -u -b 3M -l 1200 -t 10 -R     # note: datagrams sent, datagrams received
tools/inbound_accounting.py snapshot after.json --port /dev/cu.usbmodemXXXX
tools/inbound_accounting.py diff before.json after.json --sent <sent> --received <received>
```
Repeat at 2 and 3 Mbit/s, `-R` and not, direct and DERP. Read, in order:

- **Mailbox loss** (`lwip.udp_recv - ml.udp_rx`): about 220 before, a handful after (DNS). If it is still tens, the mailbox is still overflowing: raise `CONFIG_LWIP_UDP_RECVMBOX_SIZE` (and look at `ml.drain_burst_max` and `ml.drain_capped`: a `drain_burst_max` of 16 with `drain_capped` rising means net_io is falling behind, not the mailbox).
- **`ml.q_wg_full` and `ml.derp_q_wg_full`**: drops move here if wg_mgr is the slow stage (about 2.4 ms per forwarded packet, ADR 0018: 3 Mbit/s of 1,200 B is 312 packets a second against a ceiling near 400). This is the expected next bottleneck; it is a counted, tail-drop loss, and `wgperf` says where wg_mgr's time goes.
- **`wg.rx_replay_old`** (must be 0 for an in-order iperf), `rx_replay_dup`, `rx_decrypt_fail`, `rx_allowed_ip`, `rx_bad_ip`, `rx_input_fail`, `rx_alloc_fail`: non-zero says which stage; the pre-fix run is expected to show all zero.
- **`route.reply_*`, `route.tunnel_*`, `route.usb_tx_err`, `usb.tx_dropped_full`**: the tail of the chain.
- **`tools/inbound_accounting.py`'s `unattributed`** (sent - received - mailbox - counted): near zero. Control and DNS datagrams make a few of either sign.
- Heap and cost: `memory` `heap.min` should be about 768 B lower with one membership than the base image (four peer slots charged at +192 B) and `peer_slot_bytes` 1,096 in `/status`; `wgperf` `rx_pkt` per packet should not move (the replay check is a few instructions; the counters are atomics).
