---
id: per-membership-worst-case-reservation
title: "Multi-tenant capacity on no-PSRAM firmware comes from sharing bursty resources, not shrinking each tenant"
outcome: multi-tailnet-gateway
---

Five independent framing passes (problem weave of 2026-10-05) agreed that the multiplier is each membership reserving its own worst case. Each tailnet holds 4 task stacks (36,864 B allocated, ~14.9 KB used), fixed queues of up to 28 × 1,500 B of heap packets, an 8-slot WireGuard array, and a 40,000 B negotiation allowance. The language does not matter here: a static Rust design still reserves worst cases unless resources are shared.

What sets the floor per tailnet is state that cannot be shared: keys, one DERP connection per node key (forwarding needs the mesh key), and that connection's 16 KB TLS record buffer. Production DERP is 443-only, and Go TLS cannot negotiate smaller records. The control connection already runs without TLS, because ts2021 is Noise over plaintext HTTP on port 80.

Two further lessons:
1. The largest free block is a budget separate from total free bytes (v120: 6,144 B largest with 7,464 B free).
2. Once headroom is freed, three consumers compete for it: the DERP record buffer, the negotiation arena and the packet pool. Deciding who gets it first is a design decision in its own right.

Process lesson: two of the five passes built branches on code misreadings (whole-map buffering; 16 peers when the effective value is 8). Check each claim against the code before synthesizing.
