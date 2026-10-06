---
id: pool-exhaustion-bounded-failure
severity: candidate
statement: "Exhausting a shared pool (packets, peer slots, negotiation arena) results in a counted drop or backpressure, never a fallback malloc, panic or reset."
outcome: multi-tailnet-gateway
---

S&T steps D2 and D2b, sufficiency group C. Per-packet heap allocation at `router.c:211/312` means memory pressure today surfaces as failed allocations. The v120 panic happened at 7,464 B minimum free and a 6,144 B largest block. Shared statistical pools are only acceptable if every exhaustion path is bounded and visible in counters. TCP endpoints recover from tail drop; the device does not recover from a heap panic.
