# ADR 0020: Inbound pipeline: runs instead of datagrams, a router hand-off outside the core lock, a bounded queue, and cryptokey routing for IPv6

Status: accepted for on-board validation, 2026-10-05. Follows ADR 0013 (shared runtime), 0014 (router hot path), 0015 (data-plane I/O), 0016 (DFS), 0018 (wg_mgr packet path, `wgperf`), 0019 (inbound loss). **Nothing here has been measured on the board.** The host measurements below are about structure (allocations, copies, lock takes, time inside the lock), which carries over; their nanoseconds do not. Section "On-board plan" says which `wgperf` stage and which counter confirms or refutes each claim.

## Context

Board, diagnostics build, UDP `iperf3 -R` tailnet to USB, `-l 1200`, 10 s, RSSI -48 dBm, after ADR 0019:

| | 2 Mbit/s | 3 Mbit/s | 6 Mbit/s |
|---|---|---|---|
| loss | 0.9 % | 3,137 sent, 2,819 received (10 %) | 63 % |
| counters at 3 Mbit/s | | `ml.udp_wg` 3,045 (92 gone before net_io), **`ml.q_wg_full` 153**, `usb.tx_dropped_full` 53 with `usb.tx_grow_denied_heap` 1 (the elastic ring hit the heap floor, `heap.free` fell ~14 KB), `ml.drain_capped` 4 | |

TCP download: 2.31 Mbit/s with 73-111 retransmissions per 10 s. Earlier `wgperf` (240 MHz, diagnostics): per inbound datagram `rx_pkt` ~313k cycles = `rx_prep` 21k + `rx_decrypt` 78k + `rx_deliver` ~166k (the remaining ~48k is the `begin` hold), wg_mgr ~39 % of a core at ~2 Mbit/s. So at 3 Mbit/s (312 datagrams a second against a ceiling of about 770 at 1.3 ms each) the loss is the burst, not the average: the queue in front of the slow stage overflowed.

## What the code says (three premises corrected)

1. **There was no lwIP IP-stack round trip to remove.** `ml_wg_mgr.c` sets `netif->input = gateway_tunnel_input` (the router's own entry point), and `wireguardif_rx_data_complete` called it directly under the core lock. So `rx_deliver` was never "netif input -> `ip_input` -> hook -> router". It was: replay window, endpoint, timers, AllowedIPs, then, **inside the same hold**, the router (a 20-byte probe, a pbuf allocation, a copy of the packet, header validation, MSS clamp, the RCU section, the flow lookup, the NAT rewrite) and the USB netif output (`etharp_output`: ARP lookup, then the ring copy). Everything the router does except the ARP lookup needs no lwIP lock at all. Nothing "for the gateway itself" is delivered to lwIP on this netif today: a packet addressed to the gateway's own tunnel address is, exactly as before, refused by the router (`bad_packet` for ICMP and any protocol but TCP/UDP, `reply_flow_range` or `reply_no_flow` for TCP/UDP that answers no USB-origin flow). That behaviour is preserved and tested; there is no lwIP delivery to keep.
2. **A queued datagram pins heap, not a Wi-Fi RX buffer.** net_io copies the datagram out of the socket (`malloc` + `memcpy`), which releases the RX buffer; `wg_rx_queue` holds the pointer. The 6 static + 16 dynamic RX buffers are held only by the socket mailbox (10 slots) until net_io's next pass. Moving a datagram from the mailbox into the queue gives an RX buffer back and takes ~1.3 KB of heap for it. The scarce resource the queue competes for is therefore the heap that the elastic transmit ring and the admission margin also need (`tx_grow_denied_heap`), not the RX buffers.
3. **The queue bound that matters is bytes.** Eight slots of 1,264-byte datagrams and sixteen slots of ACKs are different things; ADR 0019 rejected "raise the depth" for exactly this reason.

## Decision

### A. Cryptokey routing for IPv6 (security)

The IPv6 branch of the receive path read bytes 2-3 of the header (the low flow-label bits) as the packet length and **did not check the source against the peer's AllowedIPs at all** (`// TODO: IPV6 support for route filtering`). Authenticated is not authorised: a peer allowed to use one tunnel address could inject packets with any IPv6 source, and its flow label chose how much of the buffer was "the packet". Whitepaper 5.4.6: the source address of the plaintext packet must be in the sending peer's AllowedIPs, else it is dropped.

`wireguardif_inner_check` (raw bytes in, a verdict out, so it is tested without a pbuf) now decides every inner packet, in this order, each with its own counter:

| Verdict | Rule | Counter |
|---|---|---|
| bad IP | version is not 4 or 6, or fewer bytes than that version's header (20, 40) | `rx_bad_ip` |
| not allowed | source not in an AllowedIPs entry **of the same family** (a `0.0.0.0/0` exit-node entry does not admit an IPv6 source, a `::/0` entry does not admit an IPv4 one; an IPv6 prefix is compared bit for bit at every length) | `rx_allowed_ip` (IPv4), `rx_allowed_ip6` (IPv6) |
| bad length | IPv4 Total Length below 20 or above the decrypted bytes; IPv6 Payload Length (bytes 4-5) such that 40 + Payload Length exceeds them, or 0 unless the next header is 59 (a jumbogram or an empty packet: not carried by this tunnel) | `rx_bad_length` |
| unsupported | well formed IPv6 from an allowed source while the interface does not deliver IPv6 (`wireguardif_set_rx_ipv6`, default off, never enabled by the gateway: README) | `rx_ipv6_unsupported` |

Impersonation is counted as impersonation whatever else is wrong with the packet (the order is the order of the counters). On the stock gateway no peer has an IPv6 AllowedIPs entry (microlink adds the peer's IPv4 tunnel address, an exit-node `0.0.0.0/0` and subnet routes, all IPv4), so **every inner IPv6 packet is counted `rx_allowed_ip6`**; `rx_ipv6_unsupported` fires only for a deployment that configures an IPv6 entry and still does not deliver IPv6. Both are drop-and-count; nothing reaches `netif->input`. Adding an AllowedIPs entry whose address and mask are of different families is refused (`ERR_VAL`) instead of stored, and the longest-prefix lookup for IPv4 destinations skips non-IPv4 entries (the old code compared the overlay bytes of an IPv6 entry as if they were IPv4). The IPv4 branch also stops trusting Total Length below the header size.

The delivered packet is exactly the inner packet: the 16-byte padding (and the tag, and the WireGuard header in the in-place form) is trimmed with `pbuf_realloc`, so the router sees a packet of its own length as lwIP's input contract expects (`docs/wireguard-padding-2026-10-02.md` is why the router used to cope with padding itself; it still does, tested, but is no longer given any).

### B. The run: begin, decrypt in place, complete, deliver (`ml_wg_rx_batch.h`)

wg_mgr takes up to `ML_WG_RX_BATCH` (8) datagrams off the queue and handles them as one run:

```
core lock   begin     wireguardif_rx_begin_ex for each: keypair lookup, key copy        (no allocation: in place)
no lock     decrypt   wireguard_rx_decrypt for each: ChaCha20-Poly1305 over the datagram itself
core lock   complete  wireguardif_rx_complete_deferred for each: replay, endpoint, timers, AllowedIPs, trim
no lock     deliver   wireguardif_rx_deliver -> gateway_tunnel_input_batch (validate, NAT, then ONE lock for the output)
```

* **No second buffer.** The datagram stays in the heap block net_io or the DERP loop allocated; wg_mgr wraps it in a custom pbuf (`pbuf_alloced_custom`, a free callback that releases the block; no allocation, no copy: `rx_prep` was 21k cycles) and the plaintext replaces the ciphertext where it lies. The AEAD open verifies the tag **before** it writes a byte and supports `dst == src` (`tests/test_wg_crypto.c`, in-place at both alignments), so a forged datagram leaves the buffer untouched (tested). After the decrypt the same pbuf, advanced past the 16-byte header and trimmed, is what the router reads. A run therefore holds the bytes the queue held and allocates nothing of its own.
* **Ordering.** Datagrams complete and are delivered in the order they were taken off the queue, so one peer's counters reach the replay window in arrival order exactly as before. A message that is not transport data (handshake, cookie) can change keypairs: wg_mgr never stages one behind data; it finishes the run before it, handles it alone in one piece (as before), and starts a new run (`ml_wg_rx_run` also splits a mixed array the same way: defence in depth).
* **Crypto off the lock** (ADR 0013): the decrypt is the only step that runs unlocked besides delivery, and it works from the key copied by begin and from a datagram only this task owns. Tested under TSan against a thread that rolls, destroys and replaces the same keypairs meanwhile.
* **Bounded holds.** Two holds per run (begin, complete), each at most `ML_WG_RX_BATCH` operations of a few microseconds, instead of two holds per datagram of which the second contained the whole router. The tcpip task, which takes the same lock for every Wi-Fi frame it receives, waits for a hold that is now microseconds instead of ~0.7 ms (the cost of one `rx_deliver` at 240 MHz).
* **Per-datagram steps after wireguardif are kept**: a DERP sender's residency is refreshed only when WireGuard accepted something from it and the datagram was not a keepalive (`jit_used_ms`), measured per datagram before and after the run (an authenticated datagram earlier in the same run counts for the sender, a forgery or a replay alone does not), and `directory_trial_poll` runs after every run (and after a handshake handled alone).
* A job built by hand (the pool tests) or by `wireguardif_rx_begin` still gets its own plaintext pbuf and `netif->input` under the lock: the one-piece and zero-copy paths are unchanged.

### C. The router takes the batch (`gateway_tunnel_input_batch`)

Per packet nothing the router decides changes (same checks, same counters, same NAT, same RCU pin, same flow ownership and generation rules; the differential tests and a frozen-reference comparison pass). What changes is where it runs. Validation, the flow lookup and the NAT rewrite touch only the packet and the router's own lock-free or `portMUX` state, so they run **with the core lock released**; the membership is pinned with RCU across them and **unpinned before** the lock is taken, once per chunk of 16 packets, for the output of every frame of the chunk (`etharp_output` and the ring copy, the only step that needs the lock). A suspend can therefore never wait on a reader that waits for the lock (ADR 0014/0013's "at most about 60 ms" is now the duration of the validation of a chunk). The order of frames to the host is the order of the input.

### D. Absorbing bursts: bytes, not slots (`ml_wg_rx_budget.h`)

* `ML_WG_RX_QUEUE_DEPTH` 8 -> 12 slots (the count bound, for small datagrams: ACKs, DNS, keepalives), **and a byte bound shared by every membership**: a datagram is refused when it would take the queued bytes past `ML_WG_RX_QUEUE_BYTES` (12,288 B: nine 1,264-byte datagrams, one more than the eight slots held) or leave less free internal heap than the recovery reserve (`ML_ADM_RECOVERY_BYTES`, 16 KiB). Both producers (net_io, the DERP loop) charge it, wg_mgr releases it at the pop, the teardown flush releases the rest. Refusals are counted (`ml.q_wg_bytes`, `ml.q_wg_heap`); `q_wg_full` still counts the slot bound.
* **Sizing, from the evidence.** A burst arrives as a step: net_io empties the socket mailbox (at most 10 datagrams, at most `ML_NET_IO_DRAIN_CAP` = 16 per pass) into the queue within microseconds, before wg_mgr on the other core is awake, so what does not fit at that instant is lost whatever wg_mgr's speed afterwards. 153 of 3,045 datagrams (5 %) found the 8-slot queue full. The speed of the consumer decides how often a second burst finds the queue still occupied; the size of the queue decides what one burst loses. Memory: the queue is bounded at 12 KiB across all memberships (the old bound was 8 x 1.3 KB per membership: 10.4 KB for one, 21 KB for two). The run in progress (at most 8 datagrams, already popped) is the only memory outside the bound; it is the same bytes moved from the queue, not new ones, and the heap-floor check refuses new arrivals while free heap is at the reserve.
* **Why not bigger.** The transmit ring's last growth step is denied at 32 KB free heap (`GATEWAY_USB_TX_FLOOR_FREE`) and free heap with one membership is about 38 KB (~106 KB after boot minus the first membership's ~68 KB, ADR 0013), so the headroom the ring and the queue share is a few KB. A larger queue buys burst absorption with the heap the ring needs at the same moment (and the ring is where a burst ends up once wg_mgr is faster). `wgperf` `rx_qdepth` (queue depth at the start of every drain: mean and maximum) says whether 12 KiB is right: a maximum pinned at the cap while `q_wg_bytes` rises means bursts bigger than the heap can hold, and the remedy is elsewhere.
* **Cost**: +192 B of queue storage per membership (4 slots x 48 B), +8 B per WireGuard device (`rx_batch_fn`, `rx_ipv6`); both are charged by admission from `sizeof`/the queue depths (first membership: requirement +200 B, margin ~3,180 -> ~2,980 B). Static DRAM +1,184 B (the run's pbuf wrappers, items, jobs and per-datagram notes, in `.bss`, not on wg_mgr's stack).

### E. The loss before net_io (~92 of 3,137 at 3 Mbit/s)

What is known: the datagram count at the sender minus `ml.udp_wg` is 92. Which of three mechanisms it is, is not decidable without `lwip.udp_recv`, which the report did not include; the tools now separate them in one run:

| Mechanism | Signature in the accounting | What changed here |
|---|---|---|
| lwIP socket mailbox overflow (10 slots) | `lwip.udp_recv - ml.udp_rx` > a handful (DNS) | already addressed by ADR 0019; `ml.drain_deep` (new: drains that found at least 8 datagrams waiting) says how close the mailbox runs to the edge, `drain_burst_max` how deep it got |
| Wi-Fi driver RX buffers exhausted (6 + 16 = 22 for the whole pipeline; the mailbox pins up to 10 until net_io runs; the tcpip task, which must take the core lock per frame, was blocked behind wg_mgr's ~0.7 ms holds) | `sent - udp_recv` > 0 while every lwIP counter is flat (`link`, `ip`, `udp` drops, `PBUF` pool errors in `wifistats`) | the holds are microseconds now (section B): the tcpip task no longer sits behind the router while frames queue in the driver. This is the mechanism the lock hold can explain; it is a hypothesis until `lock_wait` and this signature are read together |
| the air / the access point | the same signature as the previous row | not countable: ESP-IDF v5.5.5 exposes no driver RX counters (ADR 0019) |

`tools/inbound_accounting.py` now prints `lost before net_io`, the part of it that is mailbox, the remainder (air, AP, driver, up to a few datagrams of WireGuard control traffic), the drain depth, and every lwIP counter that moved (`link`, `etharp`, `ip`, `udp` drops, pool errors) with the 16-bit wrap handled: lwIP's counters are `STAT_COUNTER` wide and the old diff was plain subtraction, which gives a nonsense mailbox loss for a run that crosses 65,536 (the report now carries `counter_bits`). With `--reset-wgperf` / `--wgperf` the same snapshot carries the per-stage costs.

Not changed, deliberately: the mailbox size, `net_io`'s priority and the Wi-Fi buffer numbers. A bigger mailbox pins more RX buffers (22 in all); raising net_io above the tcpip task (priority 7 -> 19) would turn every datagram into two context switches on core 0 and rests on a mechanism nobody has measured. Those are the next steps if `lost before udp` stays non-zero after the holds shrink, and the counters above say which.

## What the ADRs required, and where it is held

| Invariant | Held by |
|---|---|
| Replay ring, replay check before endpoint/timers/promotion (0019) | unchanged code order in `wireguardif_rx_data_complete`; `test_wg_rx_counters` (replay from another address moves nothing), `test_wg_rx_batch` equivalence (random traffic with duplicates, ancient counters, forgeries, side by side with the one-datagram path: same delivery, counters, windows, endpoint, timers) |
| Keepalive handling, keypair confirmation, residency not refreshed by a keepalive (0019 item 7, 0013) | `t_keepalive_confirms_inside_run`, `test_wg_mgr_rx` residency cases (keepalive, forgery, replay, accepted, two in one run) |
| Crypto off the core lock (0013), PM burst locks (0016) | decrypt runs unlocked (asserted by a seam in the run, TSan race test); wg_mgr's pass-level PM burst is untouched, the shared task still releases it before sleeping; the router's usb_routes burst lock is untouched |
| Router reply-path checks, flow ownership/generation, RCU (0014) | `gateway_tunnel_input_batch` runs the same checks in the same order; `test_router_batch` (batch equals one by one over random mixes of every reject reason, padded and exact), `test_router_rx_reasons`, `test_router_hotpath` incl. the lifecycle test under TSan with the batch call, `test_router_differential`; the membership is unpinned before the core lock |
| Terminal counter identity (0019): `rx_data` = sum of terminals | holds through every path (the new counters `rx_allowed_ip6`, `rx_ipv6_unsupported` are terminals); asserted in `test_wg_rx_counters`, `test_wg_ipv6_rx`, `test_wg_rx_batch` |
| Trial activation, DERP sender admission (0012/0013) | admission before staging, `directory_trial_poll` per run, handshakes alone and in order: `test_wg_mgr_rx` (patterns DDHD, DHDD, HDD, ... with exact poll counts and lock-site order) |
| Logging policy (0018): per-packet lines off, handshake lines on | `wg_rx_stage` keeps the non-data `WG RX` line only |
| Heap floor / ring (0015) | the byte and heap bound on the queue; ring unchanged |

## Measurements (host, `tools/bench-inbound.sh`, -O2, the real `wireguardif.c` and `router.c` in one program, 30,000 rounds of 8 datagrams, median of three runs on an idle machine)

| UDP payload | ns/datagram total (before -> after) | crypto alone | ns/datagram that is not crypto | ns inside the lock | pbuf allocations | bytes copied by pbuf_take / pbuf_copy_partial | core-lock takes |
|---|---|---|---|---|---|---|---|
| 32 B | 321 -> 274 | 185 | 136 -> 89 (-35 %) | 126 -> 20 | 3.00 -> 1.00 | 176 -> 80 | 2.00 -> 0.38 |
| 180 B | 567 -> 513 | 429 | 138 -> 84 (-39 %) | 127 -> 20 | 3.00 -> 1.00 | 468 -> 228 | 2.00 -> 0.38 |
| 600 B | 1,121 -> 1,046 | 955 | 166 -> 91 (-45 %) | 143 -> 20 | 3.00 -> 1.00 | 1,320 -> 648 | 2.00 -> 0.38 |
| 1,200 B | 1,960 -> 1,868 | 1,790 | 170 -> 78 (-54 %) | 162 -> 20 | 3.00 -> 1.00 | 2,512 -> 1,248 | 2.00 -> 0.38 |

Reading it: the cipher is the same; everything else per datagram falls 35-54 % (the 1,200 B row ranged 1,960-2,161 before and 1,864-1,883 after over the three runs); the time spent inside the lock falls to a seventh or a sixth; two of three pbuf allocations and half the copying go; the lock is taken 0.375 times per datagram (begin, complete and one router output per run of 8) instead of twice, and the router work that used to sit in the second hold is gone from it. This host has a cheap allocator, no diagnostics ledger and a no-op lock, so the nanoseconds understate the board, where an allocation or a contended lock costs far more; the structure columns (allocations, copies, takes, time inside the lock) are the portable result.

Host tests (all in `tools/test-gateway.sh`, ASan/UBSan unless noted):

| Test | What it pins down | Mutants killed |
|---|---|---|
| `test_wg_ipv6_rx.c` (dual-stack lwIP fake, `-DWG_HOST_IPV6`) | the decision on raw bytes for IPv4 and IPv6: every prefix length 0..128 against a bit-by-bit model, one-bit-off sources, family isolation (`0.0.0.0/0` vs IPv6 and `::/0` vs IPv4, overlay-byte spoof), flow label that is not a length, Payload Length 0 / jumbogram / short / boundary, exact-size buffers, a 200,000-case fuzz against an independent model, and through the real path (split, in-place deferred, one-piece): counters, nothing delivered, trimmed delivery when IPv6 delivery is on | 13 of 13 (no v6 check, flow-label length, family leaks both ways, `unsupported` before `allowed`, IPv6 counted as IPv4, no trim, length off by one, payload 0, IPv4 total minimum, short header, last mask word, mixed-family entry) |
| `test_wg_rx_batch.c` | equivalence with the one-datagram path over 12 seeds x 400 random groups; lock sites; runs of 8 / cut by a handshake; two peers interleaved; replay and forgery in one run; session gone between begin and complete; keepalive confirming the next keypair inside a run; router refusals through `netif->input` and through the batch callback; no netif; **TSan race against a thread rolling the keypairs** | 14 of 14 across wireguardif and the run header (reversed delivery, header not stripped, trim skipped, refused counted as delivered, refused leaked, double free, tag not verified first, input freed twice, decrypt or delivery under the lock, no cut at a handshake, uninitialised job field with a poisoned scratch array, ...) |
| `test_router_batch.c` | batch == one by one (6 seeds x 3,000 mixed packets, batches of 1-40), USB output only under the lock, one lock per chunk and none when nothing is emitted, ERR_MEM at any position of a batch refuses only that packet, USB refusals, no leak, no double free | 8 of 8 |
| `test_wg_mgr_rx.c` (the real staging/flush/drain code of `ml_wg_mgr.c`, extracted) | drain equivalence (4 seeds x 300 rounds, queue and byte budget), burst/window/pass limits, drops before wireguardif, ownership of every heap block, residency refresh rules, runs cut by handshakes with exact lock-site order and trial-poll counts | 13 of 13 |
| `test_wg_rx_budget.c` (ASan, TSan) | the byte/heap bound against an exact model (400,000 offers and pops), the capacities the ADR quotes, four producers and a consumer | |
| `test_router_hotpath` (TSan) | the membership lifecycle test now alternates single and batch hand-off against stop/destroy/start | |
| `test-measurement-scripts.py`, `test-memory-report.py` | the accounting script (wrap, pre-net_io rows, `wifistats`, `wgperf` per-datagram costs), the `inbound` report fields | |

Builds, IDF v5.5.5 (`idf.py size`), base 0010832 against this branch:

| | Base | This branch | Delta |
|---|---|---|---|
| Unified release image (`.bin`) | 1,265,808 B | 1,267,856 B | +2,048 B (flash code +1,984, flash data +64) |
| Static DRAM, unified release `.bss` | 88,936 B | 90,120 B | +1,184 B (`.data` unchanged at 38,640) |
| Diagnostics image (`.bin`) | 1,292,960 B | 1,295,568 B | +2,608 B (flash code +2,256, data +352: the new `wgperf` stages and report fields) |
| Static DRAM, diagnostics `.bss` | 92,192 B | 93,520 B | +1,328 B |
| Legacy bridge image (`tools/build.sh full`, `tdongle_adapter.bin`) | 1,238,784 B | 1,238,784 B | 0 (unchanged source) |
| Admission requirement, first membership | 103,820 B (ADR 0019) | +200 B | margin ~3,180 -> ~2,980 B |

## Expected effect on the board, honestly

I cannot price the board's cycles from here. What follows from the structure, and what would refute it:

* `rx_prep` (21k cycles per datagram) is an allocation and a 1.3 KB copy that no longer exist: it should fall to the cost of filling in a pbuf header. `rx_begin` loses an allocation and a memset. **Refuted if** `rx_prep` per datagram stays above a few thousand cycles.
* `rx_deliver` (166k) was the router and the USB output inside the hold plus the wait for the lock. The new stages split it: `rx_complete` (lock wait + the hold that is left: replay, endpoint, AllowedIPs, trim), `rx_route` = `rt_check` (lock released) + `rt_lock_wait` + `rt_emit` (ARP lookup and ring copy, under the lock). **If `lock_wait` was most of the 166k**, `rx_complete` and `rt_lock_wait` per datagram should collapse because the holds are shorter and amortised over a run, and the tcpip task's own waits shrink with them (watch `lost before lwIP` in the accounting). **If `rt_emit` is most of it**, the gain is smaller and the next step is the one rejected below (a lock-free emit).
* `q_wg_full + q_wg_bytes` at 3 Mbit/s should fall well below 153: bursts of up to nine full-size datagrams fit (eight before), the consumer finishes a burst sooner, and the drain no longer pays two lock round trips per datagram. **Refuted if** `rx_qdepth` shows a maximum at the cap with the refusals still high: the bursts are bigger than the heap allows (section D).
* Faster wg_mgr moves the loss downstream when the USB side is the limit: `usb.tx_dropped_full` may rise at 4-6 Mbit/s even as `q_wg_full` falls, because the ring (3 frames + up to 20 elastic, heap-limited) now receives bursts faster than USB full speed (~7 Mbit/s) drains them. That is the honest ceiling of this device, and `tx_grow_denied_heap` says whether the heap floor or the ring size is the limit.
* TCP download (2.31 Mbit/s, serialised on the per-ACK latency of the path) should improve if the inbound latency per segment was the cap; the retransmissions follow the loss.

## On-board plan (diagnostics build)

```
tools/build-diagnostics.sh                         # repo root, IDF v5.5.5 sourced; flash the image it prints
P=/dev/cu.usbmodemXXXX                             # the dongle's console
T=alternative/tailnet/tools/inbound_accounting.py
for R in 3 4 6; do
  $T snapshot before-$R.json --port $P --reset-wgperf
  iperf3 -c <dongle tailnet ip> -u -b ${R}M -l 1200 -t 10 -R      # note datagrams sent and received (the Lost/Total line)
  $T snapshot after-$R.json --port $P --wgperf
  $T diff before-$R.json after-$R.json --sent <sent> --received <received>
done
$T snapshot before-tcp.json --port $P --reset-wgperf
iperf3 -c <dongle tailnet ip> -t 15 -R --get-server-output       # Mbit/s, and Retr in the server's table
$T snapshot after-tcp.json --port $P --wgperf
$T diff before-tcp.json after-tcp.json
```

Read, in order: `lost before net_io` and its split (mailbox, lwIP drops, the remainder), `drains >= 8 deep`; `ml.q_wg_full`, `q_wg_bytes`, `q_wg_heap`; the per-datagram cycles (`rx_pkt`, `rx_prep`, `rx_begin`, `rx_decrypt`, `rx_complete`, `rx_route`, `rx_deliver`, `rt_check`, `rt_lock_wait`, `rt_emit`) against 313k / 21k / 78k / 166k; datagrams per run and queue depth at the start of a drain; the core-lock `lock_wait` and `lock_hold` means; `wg.rx_*` (all zero except `rx_delivered` and the keepalives), `route.reply_*`, `usb.tx_dropped_full` with `usb.tx_grow_denied_heap`, `heap.min`. Repeat with `tools/build-diagnostics.sh --queue-depth 8` and `--queue-depth 16` (the byte bound stays at 12 KiB) if the queue size is in question.

## Rejected

- **Delivering to the lwIP IP stack and hooking from there.** The decrypted packets never went through it; adding that path would add the round trip the task was asked to remove.
- **A lock-free output (cached host MAC, build the frame, `linkoutput` without `etharp`).** It would remove the last step under the lock, but bypassing `etharp_output` stops refreshing the ARP entry the host's own traffic keeps alive and has to track the host's MAC across re-enumeration. Do it only if `rt_emit` turns out to dominate.
- **A bigger queue, or a per-slot budget.** Heap shared with the transmit ring; see section D.
- **Backpressure into the socket mailbox** (net_io stops reading while the queue is full, the datagrams wait in the mailbox): free in heap but it pins up to 10 of the 22 RX buffers for tens of milliseconds (a 10 ms tick), and needs a wake from wg_mgr to net_io that the shared runtime does not have.
- **net_io above the tcpip task** (section E): unmeasured.
- **Holding the RCU pin through the output.** The output waits for the core lock; a suspend that holds `members_lock` while polling the grace period would then wait on a reader that waits on a lock held across the suspend's caller.
- **Batching the egress** (the reverse direction): out of scope, and `usb_routes` is the producer there.

## Validation

`alternative/tailnet/tools/test-gateway.sh`, `components/tdongle_runtime/tests/run.sh` and `tools/test.sh` pass; the unified, diagnostics, legacy (`tools/build.sh full`) and tailnet gateway builds succeed with no new compiler warnings (the warning sets of the base and this branch are identical). Mutation checks were run by hand on the new tests (counts in the table above): each mutant listed was introduced into the production source and the test failed.
