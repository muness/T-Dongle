# Problem weave: multi-tailnet memory headroom

Date: 2026-10-05. Status: candidate frames; evidence group **Ev** must run before solution selection.

## Current frame

The T-Dongle-S3 gateway (ESP32-S3, 512 KB SRAM, no PSRAM, ESP-IDF 5.5.5) admits one tailnet. Admission (`member_start_budget()`, `main/gateway_main.c`) needs about 107 KB free plus a 24,000 B contiguous block. After one membership only about 44–66 KB is free. Aim: run two or more simultaneous tailnets with less memory per tailnet, per peer and during negotiation, without losing throughput. Freed headroom may be handed out dynamically to shared buffers. Exhausting a buffer must cause a counted drop or backpressure, never a crash.

Inputs, all verified 2026-10-05:

- Wi-Fi up with 0 memberships: about 153 KiB free, largest block 110,592 B (v0.2.6). With 1 membership: 43,840–66,460 B free, minimum 16,120 B. v120 panicked during a map read at 7,464 B minimum free with a 6,144 B largest block.
- Each membership: 4 tasks totalling 36,864 B of stack, of which about 14.9 KB is used at high water; about 9,216 B of context; a 40,000 B deferred WireGuard/TLS allowance; up to 28 × 1,500 B of in-flight packet payloads. About 45–68 KB per membership is not attributed to anything.
- The control connection runs ts2021 Noise over plaintext HTTP on port 80, without TLS (`ml_coord.c:10-11`). DERP serves `/derp` only over TLS on 443; port 80 carries ACME challenges and `/generate_204` (`cmd/derper/derper.go`).
- Go `crypto/tls` implements neither max_fragment_length nor record_size_limit. derp1 and derp10 ignored both in a live probe. Records grow to 16 KB after 128 KB has been sent (`conn.go recordSizeBoostThreshold`). A standard client therefore needs about 16 KB of record buffer for each DERP connection.
- A DERP connection authenticates exactly one node key. `FrameForwardPacket` requires the mesh key (`derpserver.go:1391-1393`). The result is one DERP connection per membership.

## Contradictions resolved during synthesis

- The claim that the whole map is buffered is **incorrect**. `gateway_handshake.inc:81` allocates EarlyNoise, which is capped at 1,024 B, and maps already stream (`memory-execution.md`).
- `ML_MAX_PEERS` = 16 is **8 in effect**. The 16 in `ml_config_override.h:17-18` is an `#ifndef` fallback; `sdkconfig.defaults` sets 8.
- Shrinking DERP records with TLS max-fragment-length is **rejected**. The live probe shows the servers ignore it.
- The 16 KiB recovery reserve is a free-heap threshold that admission rechecks; it is not allocated per member. The 40,000 B allowance is a real cost per member.

## Shared core

1. Each membership reserves its own worst case, and that is what multiplies. Stacks, queue payloads, peer slots and negotiation scratch space should become **shared pools allocated once, with bounded failure**.
2. **Negotiations must not overlap.** Overlapping join or rejoin peaks are what crashed v120.
3. **The largest free block is its own budget**, tracked separately from total free bytes.
4. **Measure on one build before sizing anything.**

## Distinct problem statements

1. **Per-tailnet fixed cost.** Each extra tailnet must cost far less than about 90–113 KB. Today each one owns 4 tasks and one DERP TLS session that needs 16 KB records.
2. **Per-peer cost.** Peer state should scale with the peers active across all tailnets, not with slots × tailnets. Today it is about 10–20 KB per membership (estimated from field lists, not `sizeof`).
3. **Negotiation.** A join or rejoin must not push the heap below its floor while other tailnets keep forwarding. Today nothing schedules joins.
4. **Data plane.** Each tailnet should run at close to bridge throughput. Each packet goes through 3–6 heap copies or allocations, queues are fixed per tailnet, and throughput has never been measured.
5. **Evidence.** Every capacity estimate is arithmetic over captures from different firmware versions, and no second membership has ever run on the board.

## S&T steps

| ID | Parent | D | Strategy / tactic | Disposition | Gate / invalidation |
|---|---|---|---|---|---|
| R | — | 0 | Keep N≥2 tailnets resident in SRAM without losing throughput | — | — |
| E1 | R | 1 | Same-build ladder at 0, 1 and 2 memberships, with a diagnostics admission override | candidate | Gates all sizing work. Invalid if the 2nd membership's marginal cost is already under 40 KB, which would make admission accounting the only blocker |
| E1.1 | E1 | 2 | Record free, minimum and largest block at each phase: connect, Noise, map, steady state | candidate | If largest-block fragmentation dominates, the "KB per tailnet" model is wrong |
| E1.2 | E1 | 2 | Tag mallocs by owner (TLS, Noise, map, peer, WG, packet) and report live and peak bytes | candidate | Re-scope if more than 10 KB stays unattributed |
| E1.4 | E1 | 2 | Run two joins concurrently and then sequentially; record minimum free and largest block | candidate | If the peaks add, N1 becomes mandatory |
| D1 | R | 1 | Tailnet iperf over the direct and DERP paths, sweeping queue depth 1/2/4/8 | candidate | If CPU-bound, shrink buffers freely |
| F1 | R | 1 | One task set or event loop shared by all memberships | candidate | Invalid if coord or TLS blocking sections cannot be split |
| F1a | F1 | 2 | Interim: right-size stacks from high-water captures taken at the map and TLS peaks | candidate | Overflow during qualification (v121 shows rare paths matter) |
| F2 | R | 1 | Shrink DERP TLS, the largest buffer each member holds | candidate | — |
| F2a | F2 | 2 | One 16 KB inbound record buffer shared across connections, decrypting one at a time | candidate | Head-of-line blocking across tailnets; lwIP window smaller than a record |
| F2b | F2 | 2 | Streaming record layer: data frames stream into WireGuard; control frames wait for the tag | candidate | **Needs crypto review** |
| F2c | F2 | 2 | Tear down idle DERP connections when every peer has a direct path | candidate | Peers cannot reach a node that is absent from its home DERP |
| N1 | R | 1 | Global negotiation token covering registration, Noise/H2, the initial map and the DERP TLS handshake | candidate | Join latency during a reconnect storm |
| N1.1 | N1 | 2 | Contiguous negotiation arena allocated at boot, lent to the packet pool between joins | candidate | mbedTLS allocations cannot be confined to it |
| N1.2 | N1 | 2 | Admission = steady cost + arena available, replacing the fixed sum | candidate | — |
| N2′ | R | 1 | Confirm whether `lp_acc` (64 KB) and the 64 KB H2 window are still used in gateway mode; size the window to the workspace | candidate | Control server stalls with a small window |
| N3 | R | 1 | Cut the DERP handshake peak: trimmed trust set, ECDSA/X25519 only, free state early | candidate | Measured peak is already under ~20 KB |
| P2 | R | 1 | One global WireGuard slot pool with LRU across tailnets | candidate | Eviction thrash |
| P3 | R | 1 | Hot/cold peer split, with cold metadata in the flash directory | candidate | DISCO timing regresses |
| D2 | R | 1 | Shared prioritized packet pool: per-tailnet reserve, control first, DRR, drop on exhaustion and never malloc | candidate | Fairness or latency regression |
| D3 | R | 1 | Remove hot-path copies: in-place pbufs, WireGuard writes into headroom, DERP header built in place | candidate | ChaCha dominates the profile |
| F4 | R | 1 | Shared DISCO/STUN UDP socket | deferred | Only needed at N≥4 |

Deferred polish: P2b, P4, P6, D5, D6, N4, F5, E3, E5.

## Sufficiency groups

| Group | Steps | Mode | Claim | Gap |
|---|---|---|---|---|
| Ev | E1, E1.1, E1.2, E1.4, D1 | all required | Gives per-tailnet, per-peer, negotiation and throughput numbers from one build | Long-duration drift |
| A | F1 (F1a interim) | alternatives | Removes the ~36 KB of stack each member reserves | Blocking-call slicing |
| B | F2a or F2b, plus N3, optionally F2c | one of a/b | Bounds DERP TLS | F2b needs review; F2a conflicts with the pool |
| C | N1, N1.1, N1.2, D2, P2 | all required | Reservations become shared bounded pools, and negotiation peak stays constant as N grows | Arena/pool coupling |
| Perf | D1, D2, D3 | all required | Memory savings do not cost throughput or fairness | DISCO direct-path rate |
| Overall | Ev → A ∧ B ∧ C ∧ Perf | sequenced | Candidate-sufficient for N = 2–3 | N≥4 needs F4 |

## Tensions

- **Arena lent to the packet pool (N1.1) vs packet latency (D2).** Trade-off: a join waits for packets to drain. Proposal: pool slabs are returned on demand, with a bounded wait.
- **Shared DERP record buffer (F2a) vs per-tailnet fairness (D2a).** Evidence dispute: does the lwIP window hold a full record? Prefer F2b if it does not.
- **Serialized negotiation (N1) vs a Wi-Fi reconnect storm.** Trade-off: needs priority order and a cap on join latency.
- **Shared pools vs isolation between tailnets.** Proposed compromise: a minimum reserve per tailnet.
- **C vs Rust.** A sequencing question. A Rust rewrite would satisfy A and C by construction, but no layer found that decisive on its own. Decide after Ev.

## Recommended working frame

The gateway reserves the worst case separately for each tailnet. It should instead share bursty resources across tailnets (stacks, packet buffers, peer slots, negotiation scratch), serialize the peaks, and keep per tailnet only what cannot be shared: keys, one DERP TLS record path, and sockets. Size everything from same-build attribution against both total free and largest block, and gate every change on throughput.

Alternate frames worth keeping:

- **DERP TLS is the floor**, which points toward F2b and F2c.
- **Fragmentation, not bytes**, which points toward static arenas allocated at boot, or a static Rust design.
- **The data plane is CPU-bound**, which means buffers can shrink freely.

## Evidence still needed

- Marginal cost of the 2nd membership on one build (free and largest block)
- Attribution of the unexplained 45–68 KB per membership
- Whether join peaks add
- Tailnet throughput on the direct and DERP paths
- Whether `lp_acc` and the 64 KB H2 window are used
- lwIP default TCP window
- DISCO direct-path success rate

## Plan

Updated 2026-10-05. Epic [muness/T-Dongle#22](https://github.com/muness/T-Dongle/issues/22) is experimental. Every step below is still a *candidate*, and `/solution-space` selection happens after Ev.

| S&T Step | Disposition | Issue | Parent Step | Depends On |
|---|---|---|---|---|
| E1, E1.1 | candidate (discovery) | #7 | R | — |
| E1.2, N2′ | candidate (discovery) | #8 | E1 | #7 |
| E1.4 | candidate (discovery) | #9 | E1 | #7 |
| D1 | candidate (discovery) | #10 | R | — |
| F1a | candidate | #11 | F1 | #7, #9 |
| F1, F1b | candidate | #12 | R | #11, #8 |
| N1, N1.2 | candidate | #13 | R | #9 |
| D2, D2a, D2b | candidate | #14 | R | #10 |
| N1.1 | candidate | #15 | N1 | #13, #14, #9 |
| D3 | candidate | #16 | R | #10, #14 |
| P2, P3 | candidate | #17 | R | #8 |
| F2a, N3 | candidate | #18 | F2 | #8, #9 |
| F2b | candidate (review) | #19 | F2 | — |
| F2c | candidate (discovery) | #20 | F2 | #10 |
| R (acceptance) | candidate | #21 | R | all |
| F4 | deferred | — | R | N ≥ 4 target |

## Solution Space and Dissent (2026-10-05)

Option C, a staged shared runtime in C plus a crypto track, was selected after `/dissent` returned ADJUST. Details are in [ADR 0013](adr/0013-shared-runtime.md).

| Step | Disposition |
|---|---|
| F1a | selected (stop-line PR) |
| F1/F1b | selected, staged (coord gated) |
| N1/N1.2 | selected |
| P2/P3 | selected |
| D2 | selected (subsumes D3) |
| D4 crypto (new) | selected |
| N3 shared entropy/DRBG | selected |
| N1.1 arena | deferred: largest block stable at 24–31 KB |
| N3 record caps | deferred |
| F4 | deferred |
| F2a, F2b, F2c, D3-as-perf | rejected |
