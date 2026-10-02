# Runtime panic and recovery, firmware 0.2.12

## Aim and observed evidence

Make one real peer connection survive enrollment, map refresh and traffic, retain enough evidence to locate any remaining panic, and preserve management and saved identities after failure. The product goal remains independent simultaneous 0, 1, N memberships. No fixed two-membership limit is introduced.

The Android v120 archive was retrieved after the user unplugged the dongle and returned Android to Wi-Fi. The sanitized [111-sample numerical timeline](v120-runtime-panic-2026-10-02.json) contains firmware 0.2.11, complete maps of roughly 50 KB, 30–31 directory entries and periods with routing_ready=true. Subsequent map attempts repeatedly failed after about four seconds with map_error=12 even while DATA was advancing. Minimum internal heap reached 3536 bytes; socket allocation failures remained zero. Captured per-task stack high-water values were not close to exhaustion.

At 00:01:36 local time a sample retained uptime 546379 ms, map generation 9, seven map failures and routing_ready=true. HTTP then failed; a subsequent sample reported reset_reason=4 (ESP_RST_PANIC) and a newly starting membership. This confirms a runtime panic. Firmware 0.2.11 did not retain its task or PC, so the exact triggering instruction and its causal relation to the user's peer request remain unproven. JIT counters were zero in the last pre-panic sample. Do not claim that an assigned Tailscale address or a peer directory proves working traffic.

## Changes and mechanisms

Map reads now renew a 15-second inactivity deadline when DATA advances, with a 90-second total bound. Idle incremental polls retain their four-second bound. PING/control frames cannot extend an incomplete map indefinitely. Previously, the whole incremental map had four seconds regardless of progress; flash persistence made this especially fragile.

Each membership now has one DERP TLS I/O owner. The previous reader could write a PING reply concurrently with the writer, and reconnect could free TLS after a 200 ms reader wait even though a read could last five seconds. Reads, all writes and reconnect now execute sequentially. Bounded TX/RX batches avoid starving either direction. Removing the second task saves a 10240-byte stack plus its task control block per active membership. Dynamic mbedTLS record buffers release idle workspace without reducing maximum record sizes. Admission reserves another 40000 bytes for deferred WireGuard/TLS allocations and retains management headroom; this is a conservative budget, not measured multi-member capacity.

Oversized synthetic USB packets can no longer bypass the route queue and run directory/flash work on lwIP's thread. TCP SYN MSS is capped at 1360 in both directions to fit the existing 1400-byte inner packet limit. Larger UDP datagrams remain unsupported. WireGuard netif teardown holds the TCP/IP core lock and allocation failures roll back partial interfaces.

CDC management starts before NVS, networking, directory and Wi-Fi initialization. Optional stage errors are returned and reported rather than aborting. A crash or unfinished startup in the same binary latches recovery, suppressing optional Wi-Fi/tailnet startup while allowing CDC and, when available, USB HTTP. A newly installed binary gets one fresh attempt. An explicit retry preserves the sanitized crash record and saved settings. Allocation or parsing failure cannot load or save a partial membership list; a nonblank damaged peer partition is never automatically formatted.

A new 1 MiB coredump partition begins at 0x820000. Existing NVS, factory application and peerstore offsets and sizes are unchanged. ESP-IDF captures the failing task with a separate panic stack; the full dump stays on the device. Only bounded task identity, ELF SHA, numeric PC/cause/backtrace and startup/routing stages are exported. RTC breadcrumbs perform no packet-path flash writes. NVS retains the crash summary and recovery latch across power loss. Android obtains `/boot-status` or the capability-gated CDC `boot-status`, sanitizes it and saves it automatically before later connection work can fail.

## Verification and risk retirement

| Risk | Evidence | Deliberately rejected failure |
| --- | --- | --- |
| Progressing maps killed by elapsed time | Slow fragmented map host test passes production code; running the same test with the previous stream implementation aborts at the slow-map assertion | Merely increase the initial-map timeout while incremental maps still have four seconds |
| Unbounded map ownership | Stalled partial response and slow drip tests fail within inactivity/total bounds | Keep a lock alive indefinitely with trickled control traffic |
| Concurrent TLS mutation/free | One-task lifecycle plus production `derp_service.inc` tests for PING serialization, direction fairness and error exits | Keep the 200 ms teardown heuristic or a reader that can still write |
| Recovery unavailable after an optional failure | Production startup sequence fault injection for each stage and dependency combinations | Change error text while keeping fatal assertions before management |
| Power-cycle loses panic or automatically restarts crashing services | Production boot-health tests simulate RTC reset, flash/NVS persistence, explicit retry, changed binary and allocation/storage failures | Rely only on Android's live console or RTC RAM |
| OOM corrupts saved memberships | Inject every allocation failure into production load/save; previous stored bytes and live list remain unchanged | Serialize a partially built JSON list |
| Corrupt peer volume silently erased | Blank-volume, last-byte-used, read-error and mount-error tests | Format on any FAT mount failure |
| Oversized peer packet does flash work on lwIP | Production ingress ownership tests at 20/1400/1401/1500/65535 bytes, queue full and allocation failure | Only bound the queue and let large packets fall through |
| MTU regression or cross-membership routing | Router checksum/MSS/options tests plus existing 0/1/3 membership collision and malformed-packet sanitizer cases | Fix ordinary internet while bypassing membership isolation |

Pinned ESP-IDF v5.5.5 firmware build, size report, effective configuration and compiled startup-frame check pass. Full host checks use ASan/UBSan, including streamed maps, JIT directory/queue, settings, recovery, relay ownership and router fixtures. Android JVM/lint/assembly pass. The recovery Activity fixture compiles; execution is pending because the local emulator stalled before exposing ADB. These tests do not reproduce the physical panic instruction or qualify end-to-end traffic.

## Review and remaining acceptance

Decision: continue with this consolidated correction. The evidence invalidates treating this solely as an authentication or USB reconnect problem. The broader resilience changes are within the user's explicit request to retain useful diagnostics and recover from firmware failures; no protocol rewrite, account switching, hardware change or entitlement system was added.

Real-board startup, the exact remaining panic site if any, one sustained TCP peer connection, DERP-only traffic, memory peaks and multiple simultaneous memberships remain hardware acceptance boundaries. A local build is not evidence of those outcomes. The next captured panic should include the failing task and matching ELF address evidence instead of requiring another speculative reflash. A flash/NVS hardware failure that prevents all writes, or a panic inside USB initialization itself, cannot be made recoverable by this application-level guard.
