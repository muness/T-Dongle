---
id: tailnet-throughput-per-membership
outcome: multi-tailnet-gateway
type: metric
threshold: "Per active tailnet, over the direct and DERP paths: throughput and p50/p99 RTT do not regress beyond run-to-run variance from the pre-change baseline on the same board and path; drop/backpressure counters are reported; no resets."
---

S&T step D1, sufficiency groups Ev and Perf. Tailnet throughput has never been measured; the bridge figure is about 7/5.5 Mbit/s and USB 1.1 bound. Run iperf and ping through the tailnet to a fixed reference peer, on the direct and DERP paths, sweeping queue depth 1/2/4/8. This sets the buffer budget a shared packet pool needs, and it gates every memory change so that savings do not cost throughput or fairness between tailnets.
