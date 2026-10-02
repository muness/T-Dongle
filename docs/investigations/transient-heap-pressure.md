# Solution Space: transient internal heap pressure

Problem: retain sufficient internal SRAM and contiguous allocation capacity while routing and recovering control connections. Constraint: original ESP32-S3 has no PSRAM; flash cannot hold live TLS state, stacks or DMA buffers. Working story: temporary overlapping work, rather than a demonstrated leak. Success: identify the allocating operation at each low-water transition and keep routing/recovery functional under the measured peak.

Evidence: latest capture has 43,840 bytes free, 31,744 largest block, eight sockets, routing ready; minimum free is 16,120. Saved serial samples show minimum changing from 23,680 to 16,120, while later free returned to 48,876. Their telemetry uptime remained stale at 474,525 ms; do not use it to attribute the dip. Current ELF differs from retained crash ELF. No measured temperature.

| Candidate | Frame | Trade-off |
|---|---|---|
| A: raise admission floor or disable diagnostics | Band-aid | May reject recoverable work and lose the evidence; does not identify the transient allocator. Deferred. |
| B: operation-scoped heap accounting, then serialize/reduce measured overlapping allocations | Reframe then local optimization | Small bounded instrumentation; identifies cause before buffer changes. Selected. |
| C: bounded reusable workspaces / in-place transfer where ownership allows | Redesign | Reduces churn but can increase persistent baseline and create shared-buffer races. Deferred pending B. |
| D: reduce task stacks from observed high-water marks | Local optimization | High-water observations do not cover rare recovery paths; stack corruption risk. Deferred. |

Decision criteria: preserve working routing, credentials, saved diagnostics and recovery; reduce peak internal allocation rather than merely improve an idle number. Critical assumption: transient allocating work causes low-water dips. Investigate serial/Web diagnostics snapshots and NVS operations, control reconnect/TLS allocations, Wi-Fi scans and packet bursts independently, then in overlapping combinations. A and D assume SRAM shortage; B tests attribution; C assumes churn/duplication.

| Risk | Planned disposition | Tempting patch this check must fail | Evidence / pivot |
|---|---|---|---|
| Persistent leak rather than transient overlap | Retired by evidence, pending | Merely lower telemetry frequency | Repeated connect/recover/map/diagnostic cycles with before/after free and largest block; pivot if baseline declines. |
| Large contiguous allocation failure | Retired by evidence, pending | Report total heap alone | Record largest block and requested allocation size with operation; inject failures and verify cleanup. |
| Instrumentation causes its own pressure | Retired by evidence, pending | Allocate diagnostic trace buffers on each request | Fixed compact records; compare enabled/disabled stress peaks and avoid passwords/payloads. |
| Duplicate concurrent workspace ownership | Retired by evidence, pending | Global reusable scratch without locking | Overlapping clients, send failures, detach and recovery tests must preserve bytes and release exactly once. |
| Device-specific long uptime and heat | Accepted with rationale | N/A | Requires hardware after verified build; chip temperature is not enclosure temperature or proof of thermal causation. |

Execution handoff: instrument bounded operation entry/exit and allocation failure, carrying firmware uptime/sample timestamps; first use this to choose serialization, in-place processing or workspace bounds. Preserve 0/1/N membership behavior and both packet paths. Avoid blanket stack/buffer cuts and moving live buffers to flash. Physical long-duration pressure remains unverified. Temperature/true transparent bridge unified code is unfinished and unshipped; v132/0.2.17 remains available.
