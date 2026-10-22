# C5 A → B plus wireless mode execution

## Aim and scope

Finish C5 feature parity needed for a shared tailnet appliance, enable PSRAM-backed concurrent memberships (initial target three), and offer USB/Android and wireless-client gateway modes using one persisted membership registry and identities. Preserve S3 behavior and its internal-memory budget. No hardware flashing, publishing a release, or claim of qualified capacity without device evidence.

## Dissent / decision

ADJUST the earlier standalone C5 transport binary: reuse the existing firmware application, configuration schema, UI and tailnet runtime rather than invent a second registry. The strongest objection is that S3 hardware glue is deeply embedded in application modules. Separate board-specific peripherals and transport seams; compile both targets at every substantial seam change. Functional failure: configuration works but the tailnet packet path is bypassed. Adoption failure: wireless mode requires recreating identities or loses console access. Opportunity-cost failure: a blanket PSRAM allocator produces a compiling image with unsafe cache-disabled flash accesses. Checks below must reject each.

## Execution checklist

- [x] A: saved profiles, shared tailnet management, display/buttons, setup and recovery on C5.
- [x] B: PSRAM initialized, explicit internal/external allocation policy, three membership workers; actual runtime and packet routing, not capability flags alone.
- [x] C: selectable client-facing wireless gateway; same registry/keys across changes; protected AP; routing through the same runtime.
- [x] Companion: full configuration through the C5 transport, no Ethernet-only dependency; same UI/commands where possible.
- [x] Shared config tests: mode changes preserve identity blobs and registry, invalid mode/config rejected, interrupted updates recover.
- [x] Packet tests: tailnet alias/DNS path vs ordinary NAT, malformed frames, client isolation/address mapping, mode/session stale queues.
- [x] Memory checks: external placement for bulky state, internal reserves and cache-disabled operations verified by inspection/build tests; no unbounded queues.
- [x] Both firmware targets, Android build/tests, host suites and checksums.
- [x] Review actual changes against this list before completion.

## Risk retirement boundary

Model-checkable risks remain required checks: raising slot counts without workers, bypassing tailnet through direct NAT, duplicated settings, stale queues, using PSRAM buffers during flash-disabled cache operations, and unbounded backlogs. Physical-only tests are accepted pending hardware: PSRAM stress while radio and flash run; simultaneous login/rekey/reconnect storms; fairness and latency under direct/DERP encrypted load; AP/STA band/channel coexistence; USB detach and Android VPN; TeslaAndroid downstream traffic. Any failing physical test invalidates capacity/compatibility claims, not permission to preserve source progress. Do not relabel an unimplemented feature as hardware-pending.

## Software delivery evidence (2026-10-22)

The checklist above describes software implementation; hardware qualification is separate. A uses the shared application, display/profile controls, settings and setup flow. B initializes external memory, routes bulky allocations to it, asserts the runtime state is in PSRAM, and starts three actual worker sets. C switches only the downstream transport and keeps the same registry/identity storage. Android uses the shared configuration page over its C5 tunnel or the gateway AP. The old standalone C5 main was removed.

Additional shared reliability fixes: destination-IP neighbor lookup for multiple clients; retry cycles exclude a failed preferred profile before trying it again; hidden profiles still receive directed probes; reconnect waits use the existing 1/2/4/8/16/30-second policy; explicit profile requests interrupt the wait; scanning works with an empty saved list; disconnect reasons reach diagnostics and the C5 connection page. A healthy association is not continuously rescanned.

Local verification:

- Full Rust workspace: **1,618 passed, zero failed, eight ignored**. The subsequent saved-profile changes passed all **12** focused profile tests, including two new fallback/backoff regressions. These counts overlap; do not add them as independent suites.
- Runtime regressions include two different client MAC/IP pairs and unknown-neighbor refusal, actual DNS/alias/NAPT dispatch, malformed frames and bounded queues.
- Transport persistence tests simulate 400 cuts/tear combinations across USB→wireless and wireless→USB and retain three identity blobs plus a registry; invalid schema values remain untouched.
- C5 layout tests: three passed (long SSID, independent password/URL/expiry rows, UTF-8 truncation). Existing shared renderer/button/traffic tests passed in the workspace suite.
- Python owner-console codec: four tests passed, including the existing Rust/Java golden wire vector, corruption/truncation, oversize input and boot noise. Web UI tests passed.
- Android: **100 core + 57 app tests passed**, zero failed/skipped; debug APK assembly and lint succeeded. Lint reports **73 warnings**, zero errors; this is not a warning-free build. No emulator or device test was performed.
- C5 and S3 release binaries were compiled and packaged locally. C5 still has unused S3-path/dead-code warnings; S3 retains its compiler/linker warnings. Exact artifact sizes, checksums and source revisions are recorded with the packages. The S3 boot-order, rescue-first, embedded ELF hash, stack-frame/direct-call and DRAM checks passed. ESP-IDF's optional esptool image-info check was skipped because that installation is unavailable; espflash packaging succeeded.
- The C5 linker leaves about 31 KiB for the main stack. This is a static region measurement, not a measured stack watermark or a verified RISC-V maximum call chain. Runtime stack/heap/PSRAM measurements remain physical acceptance work.

## Review and risk retirement

| Risk | Evidence / disposition |
|---|---|
| Claiming extra memberships without a runtime | Same `main.rs`, shared `tailnet::start`, three worker pools/slots; PSRAM allocator and external-state assertion compiled. Simultaneous live membership performance remains physical-only. |
| USB bypasses tailnet via a separate NAPT | Standalone C5 entry removed; serial and AP frames enter the same `tailnet::usb_rx`/`try_host_rx` path. Existing DNS/alias/NAPT tests pass. |
| Mode switch erases keys | Separate atomic transport byte; power-cut/identity-preservation tests pass. |
| First host receives every reply | Two-client destination lookup regression passes. |
| AP completions corrupt station TX budget | Callback explicitly filters AP completions; shared station budget tests pass. Physical bidirectional load remains pending. |
| Stale USB sessions affect a new owner | Nonce-filtered queues, partial command reset, host queue clear/generation update, wire/session tests and source review. Wireless mode does not clear flows on USB console disconnect. |
| PSRAM passed into cache-disabled flash routines | NVS wrapper and directory writer stage through aligned internal stack arrays; inspected against esp-storage calls. Radio/flash stress on C5 remains pending. |
| PSRAM failure prevents recovery forever | Sticky recovery bypasses PSRAM and radio startup; watchdog/boot policy tests pass. ROM/BOOT procedure documented; physical recovery still pending. |
| Invented status | Local readiness differs from Internet and upstream DHCP. Invalid RSSI is not displayed; C5 health omits unsupported temperature/largest-block/USB-reset claims. |
| Wrong preferred credentials starve fallback | New tried-profile regression and bounded-backoff test pass. |
| Secret leaks | Routine status omits AP/upstream passwords; only explicit local console request and setup screen reveal AP secret. Python password entry uses getpass; Android views disable saved/autofill credential state. |
| Hardware compatibility/capacity | **Pending physical verification:** no flash, USB hardware session, RF test, Android VPN test, PSRAM stress or TeslaAndroid test performed. |

Review was a fresh local diff/source review. No external reviewer, CI success, upstream PR, merge or release is claimed. The selected scope remains A→B plus C using one configuration store; no additional tailnet registry, independent router product or host network changes were introduced.
