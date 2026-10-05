---
id: multi-tailnet-gateway
kind: outcome
status: proposed
s_and_t_step: R
owner: gateway owner
review_trigger: "Evidence group Ev (E1, E1.1, E1.2, E1.4, D1) completes on one build"
files:
  - alternative/tailnet/docs/problem-weave-multi-tailnet-memory.md
  - alternative/tailnet/main/gateway_main.c
---

# Two or more tailnets at once through one dongle

## Desired behavior change
A host plugged into one T-Dongle-S3 uses two or more tailnet memberships simultaneously. Each tailnet forwards at close to bridge throughput, and joining or rejoining one tailnet does not disrupt the others. Today admission caps the device at one tailnet. It needs about 107 KB free plus a 24,000 B block, and only about 44–66 KB remains after the first membership.

## Mechanism
Each membership reserves its own worst case, and that multiplies with N. Share the bursty resources (stacks, packet buffers, peer slots, negotiation scratch) as pools allocated once with bounded failure. Serialize negotiation peaks. Keep per membership only what cannot be shared: keys, one DERP TLS record path, and sockets. Hypothesis: this makes N = 2–3 fit in 512 KB SRAM without PSRAM.

## Feedback
- Signals `second-membership-marginal-cost` and `tailnet-throughput-per-membership`.
- Invalidated if a measurement on one build shows the marginal cost is already under 40 KB, which would make admission accounting the only blocker.
- Invalidated if fragmentation of the largest block, rather than total bytes, sets capacity.
