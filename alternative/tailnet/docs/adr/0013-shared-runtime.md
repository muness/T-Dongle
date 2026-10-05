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
