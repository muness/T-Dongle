---
id: second-membership-marginal-cost
outcome: multi-tailnet-gateway
type: metric
threshold: "After membership k+1 is steady: free internal heap >= 16 KiB and largest free block >= 24,000 B, with minimum free during its join >= 16 KiB. Report the marginal cost (free and largest-block delta, k -> k+1) from one firmware build."
---

S&T step E1 (with E1.1, E1.2, E1.4), sufficiency group Ev. This measures what each additional tailnet really costs, using the same image at 0, 1 and 2 memberships. A diagnostics admission override lets the second join run into a bounded failure instead of being refused. Capture per phase: control connect, Noise, map, DERP TLS, steady state. Use the per-membership `start_heap_before/after` counters and the low-water recorder. Attribute bytes to owners with malloc tags (TLS, Noise, map, peer, WG, packet). Present baselines mix firmware versions (v0.2.6 vs v120–v122), so the current "~90–113 KB per membership" figure is derived, not measured.
