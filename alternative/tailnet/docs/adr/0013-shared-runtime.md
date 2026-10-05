# ADR 0013: Shared runtime for tailnet memberships, staged

Status: accepted for execution, 2026-10-05. Epic muness/T-Dongle#22.

## Context

A diagnostics build (0.2.22, PR #25) on the board measured one membership's steady cost at about **68.4 KB**:

- task stacks 36,864 B
- context 9,728 B
- WireGuard device 7,952 B
- TCBs and queues 3,256 B
- TLS 1,336 B live, 9,460 B peak during the handshake
- about 9.3 KB untagged

Free heap reached 29,764 B at the minimum during a join. Traffic transients add packet buffers (12,132 B peak) and WireGuard working buffers (+6.4 KB). Free heap after boot is about 106 KB, so the admission budget of 108,200 B leaves a margin that is sometimes negative.

ChaCha20-Poly1305 benchmarked at 2.95 ms per 1,400 B packet, while a copy takes 5.7 µs. Research (#24) showed that the DERP TLS buffers are already dynamic, at about 1.3 KB idle.

## Decision

1. Replace thread-per-membership execution with shared tasks, in stages.
   - **Stage 1:** net_io, derp_tx (DERP I/O) and wg_mgr serve every membership. coord stays one task per membership, sized to its measured peak.
   - **Stage 2:** coord joins the shared loop only if board measurements after stage 1 show it is needed for the target N.
2. One global WireGuard peer-slot pool with hot/cold peer state (P2/P3).
3. A global negotiation token that serializes start, Noise, register, initial map and the DERP TLS handshake. Admission uses the measured steady cost plus the transient reserve.
4. A static, prioritized, shared packet pool. When it is empty, packets are dropped and counted; it never falls back to malloc (D2, subsuming D3).
5. Crypto performance (D4): first a cycle-accurate benchmark on the release build, then an optimized ChaCha20-Poly1305.

## Rejected

- Thread-per-membership with only shrinking (cannot fit N=2).
- A no_std Rust rewrite (reimplements an unlibraried protocol stack and discards the tested code; revisit if slicing fails).
- Time-sharing memberships (violates the aim of simultaneous use).
- DERP shared-record, streaming and idle-teardown schemes (see #24).

## Consequences

Capacity becomes statistical with bounded drops. A join may wait behind another membership's negotiation. microlink's per-instance task model diverges further from upstream.

## Invalidation and pivot

- Slicing check fails (a stalled member blocks the others), or the marginal cost per membership measured on the board after stage 1 exceeds 35 KB: revisit, with Rust as the alternative.
- Any reset under `-P 8` load: stop.

## Amendment 2026-10-05: crypto is not the throughput bottleneck

An on-board cycle-accurate benchmark (PR #28, `crypto bench`, 160 MHz, interrupts masked) measured ChaCha20-Poly1305 seal of 1,400 B at:

- legacy: ~89k cycles (~0.56 ms)
- new implementation: 62,596 cycles (0.39 ms), a cipher-only ceiling of ~28 Mbit/s

IRAM placement had no effect. The 2.95 ms per packet from PR #25's `memory bench` was a measurement artifact, not cipher cost.

D4 stays merged as a 30% cipher improvement. The ~1 Mbit/s tailnet throughput and the 47–74 ms LAN disco RTT point to forwarding-path latency and queue drops (the 4-deep route queue, `router_ingress` drops). PR-B now targets that.

## Status 2026-10-05: stage 1 implemented (PR "Shared runtime stage 1")

Implemented and host-tested; **not yet measured on the board**.

| Decision item | State |
|---|---|
| 1. Shared net_io / derp / wg_mgr tasks | Done. `ml_runtime.c` + `ml_rt_core.c` (task lifecycle, attach/detach quiesce), `ml_mux.c` (registry, round robin), `ml_derp_link.c` (DERP as a non-blocking state machine), `ml_derp.c` (DNS via the lwIP resolver callback, non-blocking connect, one TLS handshake step per call). coord stays one task per membership. |
| Slicing check (pivot trigger) | **Passed, no pivot.** `tests/test_shared_derp.c` (virtual time) and `test_shared_derp_realtime.c` (threads, sockets, real clock; ASan/UBSan and TSan): a stalled server (5 s mid-record, deaf to writes, hung TLS handshake, silent HTTP upgrade) costs only its own membership a redial; the other membership's relay keeps a 5 ms worst-case latency in both directions. A negative control (a blocking read on the shared loop) shows B starving for 5 s, so the harness can see the failure. Protocol bytes were not changed; the blocking client became a resumable state machine. |
| 3. Negotiation token | Done (`ml_negotiation.c`): FIFO within priority, aging, bounded acquire with no trace on timeout, lease and stale-waiter reaping. Phase A (start allocations, Noise, registration, initial map) and phase B (DERP handshake) are separate holds; the control task's hold follows its state machine (`ml_coord_state.h`) so every error path releases. |
| Admission (N1.2) | `ml_admission.h`: shared stacks once, per-membership start + steady growth, one negotiation peak (16,000 B, from the 17.3 KB handshake peak against 1.3 KB live), 16,384 B recovery reserve, 24,000 B largest block; all inputs in `/status`. |
| 2. Global peer-slot pool (P2) | Done: `wireguard_pool.c`, K = 12 slots of 904 B allocated on demand (8 = one full single-membership working set as in ADR 0012, +4 shared headroom). Receiver indices are unique across the pool (the old check only ever compared the last slot), lookups are scoped to the device, eviction is cross-membership LRU honouring the ADR 0012 idle window, priority peer and trial rules (`ml_peer_policy.h`), counters in `/status`. P3 (moving `ml_peer_t`'s cold fields out of RAM) is **not** done: the eight `ml_peer_t` per membership (3,712 B) remain. |
| 4. Shared entropy | Done (`ml_rng.c`): one CTR-DRBG, 496 B per membership freed, state resident only while a DERP link exists. |

### Predicted marginal cost of membership 2 (for the coordinator to verify)

Measured one-membership steady cost, 0.2.22: 68,436 B. Changes: shared stacks net_io 7,168 + derp 7,680 + wg_mgr 7,680 = 22,528 B and three TCBs (1,020 B) are paid by the first membership only (the new wg_mgr stack is 8,192 B, 512 B more, also paid once); the WireGuard device with eight slots (7,952 B) becomes a 228 B device plus the slots actually resident, three typically (2,712 B), so 5,012 B less; the entropy and DRBG contexts, 496 B, go. `sizeof(microlink_t)` is unchanged at 10,256 B (496 B out, the link and loop state in).

68,436 - 22,528 - 1,020 - 5,012 - 496 = **about 39.4 KB** for each further membership (the admission arithmetic, with four slots charged, gives 40.9 KB), against the 35 KB pivot figure above. The first membership costs about 62.9 KB. One join then peaks about 16 KB above steady. With about 107 KB free after boot that leaves about 44 KB after the first membership, so the second would end at about 4.7 KB free and dip to about -11 KB at its DERP handshake: **stage 1 alone does not make N = 2 fit**, and it trips the pivot trigger as written. Moving coord into the shared loop (stage 2, 8,704 B + a TCB) would bring the marginal cost to about 30.4 KB, still short during the join peak. The remaining measured levers are the eight `ml_peer_t` (3.7 KB), the lwIP sockets and PCBs (about 9.3 KB per membership, 5 sockets), and the packet pool (PR-B). The prediction is arithmetic over one capture and carries about +-3 KB.

### Runtime behaviour added by the coordinator's scope addition

- The derp and wg_mgr tasks block on task notifications with a computed deadline (a link's retry or connect step, the next membership timer) instead of `vTaskDelay(10)`; queue producers wake them. The established DERP relay is still read every 10 ms because the TLS transport has no readiness callback; PR-B can add one.
- WireGuard handshake initiation (two X25519, about 40 ms) runs with the lwIP core lock released (begin/compute/commit), periodic work takes the lock once per peer, and transport data is decrypted outside the lock (begin/decrypt/complete, re-validating the keypair on completion). Outbound encryption still runs where lwIP calls `netif->output`, under the lock, in the tcpip thread; moving it needs an asynchronous output queue and is not done. Handshake responses and cookie messages are still processed in one piece under the lock (rare).
- `memory locks` (diagnostics image) prints a per-call-site histogram of core-lock hold times.

## Review 2026-10-05 (PR #30): decisions

- **Detach timeout is a deferral, not a leak.** `ml_rt_detach` returns false when a slice outlives `ML_RT_DETACH_TIMEOUT_MS`; the membership stays attached and is not freed. `stop_incomplete` is now recomputed by every `microlink_stop` (it used to be sticky, so the manager's ten-second retry could detach successfully and still never destroy). A slice that merely overran is reclaimed on the next tick; one that never returns holds one context (~10 KB) and is visible as `detach_timeouts` in `/status`.
- **Shared task handles are cleared by the task before it deletes itself**, inside the critical section that `ml_rt_wake` and `ml_rt_task_handle` use. Before, a wake from any core after the last membership left was a notify into a freed TCB.
- **Peer slots stay on demand, behind a largest-block guard, not a static pool.** Evidence: the steady largest free block is 24,576 B against the 24,000 B admission floor (576 B of margin, less than one 904 B slot), and slots live for hours, which is the fragmenting pattern. A static pool of 12 would pin 10,848 B for ever, 7,232 B more than the four slots admission charges; against about 107 KB free after boot that takes the first membership's margin from about 9.7 KB to about 2.4 KB (`tests/test_admission.c` prints the arithmetic). Instead a slot allocation that would be the one to take the largest free block from at least 17,408 B (the DERP TLS record buffer, `ML_ADM_TLS_BLOCK_FLOOR`) to below it is refused and counted (`wg_pool.refused_largest`, `wg_pool.largest_low` in `/status`). The board run should read `largest_low`: if it stays above the floor with room to spare, nothing more is needed; if `refused_largest` moves, the static arena (or P3) comes back into scope.
- **A WireGuard initiation computed outside the lock is committed only if the peer's handshake state is unchanged and its receiver index is still unused pool-wide.** The lock is free for about 40 ms while the X25519 runs, and `begin` only drew the index; a competing initiation (the output path starts one when a packet finds no session) would otherwise have been replaced by ours and its response orphaned.
- **The shared-runtime tests are part of `test-gateway.sh` again.** Commit 2cdc3d7 dropped them from the script (shared DERP virtual-time and real-thread runs, TSan, negotiation, token rule, admission, peer policy, runtime lifecycle, pool core and pool-on-lwIP-fakes); one of them (`test_wg_peer_pool_if`, split crypto) had been failing since.
