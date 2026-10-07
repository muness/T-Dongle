# 0.4.0-rc2 hardware qualification

Tracking: [#53](https://github.com/muness/T-Dongle/issues/53). Boot defect: [#52](https://github.com/muness/T-Dongle/issues/52). Integration branch: `rust/rc2-int`. Board MAC `30:ed:a0:d7:88:bc`. Single tailnet on esp-rs. No tag until explicit owner go-ahead.

The production TLS-fixed firmware built from `fb43561` passes the repeated board qualification below. App SHA-256: `fa54fe3cb99d3e47b3fa16d67cff0c788edd7e4af73ebd8dea48d6814affa553`. ELF SHA-256: `15f1a794c4758d18c0b779dca47f3c848b675d994795ccd085fb315301cfd763`. Later host-only test and evidence commits do not change this firmware. The [initial qualification](release-0.4.0-rc2-initial.md), [initial metrics](release-0.4.0-rc2-initial-metrics.json) and [initial soak](release-0.4.0-rc2-initial-soak.jsonl) preserve the preceding image's results separately.

## Current board qualification

| # | Gate | Result | Measurement |
|---|---|---|---|
| 1 | Flash selftest | Pass | `nvs_capacity=16777216` |
| 2 | Join time | Measured | First observed state 4 at 12.428/19.900/13.164 s; current rc1 12.102/12.582/12.549 s |
| 3 | Flash directory and reboot | Pass | 22 peers restored at 1.645 s before first map; generation 162; errors 0 |
| 4 | Direct TCP | Pass | 15 s iperf3 received: up 1.2378, down 1.3278 Mbit/s; rc1 1.3 / 1.1–1.2 |
| 5 | Relay TCP | Pass | Forced DERP: up 0.3963, down 0.7687 Mbit/s; rc1 approximately 0.4 / 0.5; force-DERP restored off |
| 6 | Traffic rate | Pass | Upload sample: down 44, up 1266 kbit/s; counters advance |
| 7 | Temperature | Owner accepted | Valid 1; traffic peak 72.9°C; original 70°C ceiling remains recorded; owner accepted temperature |
| 8 | Mode switch | Pass | HTTP `/command` to bridge, healthy boot, then serial return to gateway and healthy state 4 |
| 9 | HTTP | Pass | `/status` reports 0.4.0-rc2; `/serial` replies; `/wifi-scan` lists 12 networks; `/command` switches mode |
| 10 | Heap admission floor | Pass | Minimum outside negotiation 38,744 B vs 29,884 B floor, margin 8,860 B; raw load minimum 38,744 B |
| 11 | Panic recovery | Pass | Running console within 4.168 s after command completion, rescue healthy, rejoined, no replug |
| 12 | 30-minute soak | Pass | 1,800 s, 61 samples, trips 0/0, no resets, states [4], setup inactive throughout, directory errors 0 |

Heap remains 246,784 B; the admission floor is unchanged. The fixed control workspace may operate below the elastic floor, but the final traffic runs have a raw minimum of 38,744 B. The smallest observed marked control-stack free space under load is 12,812 B. The largest emitted frame is 11,152 B and reserved stack is 44,200 B, above the 40,960 B minimum. The direct-call lower-bound check passes 36,000 B; it omits indirect poll dispatch and does not prove the full synchronous chain.

The [current soak log](release-0.4.0-rc2-soak.jsonl) contains all 61 samples, from 2026-10-07T20:43:26.524807+00:00 through 2026-10-07T21:13:26.537118+00:00. This is an idle joined gateway with brief status exchanges every 30 seconds, rather than continuous iperf. Every exchange closes serial. Tailnet states observed: [4]; setup active values: [0]. USB-reset counter stays 1 after the planned panic. Lowest free heap is 46,020 B and minimum outside negotiation is 46,020 B. Setup AP is entered only after this gateway soak.

## Join trace and TLS correction

Five passive traces on temporary diagnostic commit `4043d34` applied the first map at 12.055/13.216/13.341/12.060/13.086 seconds. A representative boot started control at 4.998 s, fetched the server key by 8.094 s, finished the second TCP/TLS connection at 9.189 s, completed registration at 9.667 s, requested the map at 9.673 s and applied it at 12.060 s. Every trace recorded a failed primary DNS query followed by secondary-resolver success, adding approximately two seconds of fallback. The two TLS handshakes total about 1.7 s. Map read time is 2.1–2.2 s and includes TLS work and network waiting; parsing/feed is 99–109 ms, Noise processing 32–37 ms and HTTP/2 processing 2–6 ms. [Sanitized phase traces](release-0.4.0-rc2-join-trace.json) contain no peer identities. Both resolver addresses answered a separate Mac query in 33 ms; that different client path does not explain the failed dongle query or establish a general primary-server outage. Diagnostic logging and its larger temporary queue are excluded from the release image.

The previous 51.827-second boot recorded `Map(Deadline)` at 41.192 s, retried at 42.288 s and joined at 51.827 s. That timeout was not reproduced in the five passive traces. The audit nevertheless found deterministic receive cancellation defects present in both rc1 and rc2: the control driver cancels reads on one-second ticks, while the old TLS reader kept partial header/body progress in the discarded future. A separate post-record allocation could wait after plaintext was already consumed into a temporary Vec. These are candidate contributors to map deadlines; they are not a proven cause of the specific 51.827-second attempt.

The fix keeps partial header/body progress and the original admitted record lease in persistent connection state. Plaintext drains from that lease without a second allocation. The original body timeout deadline survives interrupted reads; timeout poisons the stream and refunds the lease. Both cancellation regressions fail on old code and pass after the fix. Further tests verify exact plaintext across cancellation, two large records through small caller buffers, no new admission while draining below the floor, and refunds on timeout/drop. Heap floors and timeout budgets are unchanged.

The final image's repeat joins above still include a slower attempt. Current rc1 joins in 12.1–12.6 s, so the historical approximately eight-second baseline did not reproduce. Fast rc2 joins overlap that current range; a specific location/time/server cause remains unproven. [Matched baseline evidence](release-0.4.0-rc2-join-comparison.json) preserves every earlier slow attempt.

## Release fixes and host validation

The stack guard and static initialization fixes remain verified. Directory restore is bound to the persisted WireGuard public node key; authentication and session validity still require fresh control data. `flash.sh` pins the board MAC, enters download mode through bounded raw exchanges, uses `--before no_reset --after watchdog_reset`, closes serial handles and verifies a fresh advancing running boot with rescue health. Repeated flashes and panic recovery need no replug.

All five requested follow-ups are integrated: Android embedded page uses `/command`; JSON nesting property range starts at 1; queue feature conflict is resolved; web UI tests run in CI; and directory clear invalidates the NOR header without two immediate erases. CI also runs vendor TLS cancellation tests. Existing formatting and lint failures were corrected separately.

Final native workspace and doctests: 1,604 passed, zero failed, 8 ignored across 238 groups. Vendor TLS: 15 passed. Focused post-cleanup tests: 480 passed, zero failed, 5 ignored. Formatting, clippy, boot order, rescue-first checks, 13 flash-helper tests, 3 stack-parser tests, web UI contracts, generated goldens and loom pass. Miri results are recorded separately when complete.

## Owner qualification and setup handoff

The owner accepted temperature and reviewed the matched join evidence. Phone setup-AP testing, the Android app and [the web UI checklist](../../docs/webui-checklist.md) remain owner qualification. Package hardware qualification flags stay false until that review. Tag 0.4.0 only after explicit owner go-ahead.

Final setup-AP handoff is verified after the current gateway soak: pending. SSID `TDongle-D788BC`, open network; portal `http://192.168.4.1/`. The session lasts ten minutes, then returns to saved gateway mode; connecting a phone does not extend it.
