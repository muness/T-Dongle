# Upstream comparison and boot-failure salvage

## Aim and why this is a salvage

One original, no-PSRAM T-Dongle-S3 must carry 0, 1 or N independent, concurrent tailnet memberships and forward USB-host traffic. Repeated map, routing and recovery patches have not established hardware acceptance. The latest failure occurs before the management service answers, so another map parser change would target the wrong layer. Preserve the streaming parser, transactional flash directory, independent identities and bounded JIT cache; stop treating successful host tests or flash verification as successful boot or traffic.

## Primary sources inspected

| Project and inspected revision | Finding | Carry over / boundary |
| --- | --- | --- |
| [Csontikka/MicroLink](https://github.com/Csontikka/microlink/tree/7de6a93684a34991fdfa1eeb9281e08523646ef7), `7de6a93` | This is exactly our recorded import baseline. The fetched upstream has no newer engine commit to cherry-pick. Its C protocol and WireGuard code are already the basis of this fork. | Maintain a reproducible diff; a wholesale re-import would discard our identity isolation, streaming and flash-directory work. MIT notices remain. |
| [Original MicroLink](https://github.com/CamM2325/microlink/tree/216da3300f0493b0860247d43f7af5ce29df63a5), `216da33` | Its upstream documentation describes large PSRAM-backed map buffers and interface rebind support. Its performance claims are not measurements on our board. | Reuse protocol/transport work, but do not copy its memory sizing or claim its single-node examples qualify multiple concurrent no-PSRAM sessions. |
| [ESPHome Tailscale](https://github.com/Csontikka/esphome-tailscale/tree/35a471c16f240ae836b5417db463d985a70ceda0), `35a471c` | Another MicroLink integration, explicitly requiring PSRAM for its runtime. | Useful lifecycle and time-sync checks; not an independent lower-memory replacement or proof our target fits. |
| [ESP32 Tailscale subnet router](https://github.com/Csontikka/esp32-tailscale-subnet-router/tree/e3e2e502249fbdda2e7ddbded0af40a285d45824), `e3e2e50` | `main/main.c` captures boot/reset/crash evidence early. `sdkconfig.defaults` increases main stack from 3584 to 7168 bytes. `tailscale_manager.c` waits for wall-clock time before connection. | Adopt startup headroom, early recovery access and actionable saved crash evidence now. Its PSRAM log buffers, full coredumps, OTA layout and automatic NVS erase are not copied. Time-sync gating is a separate follow-on after boot recovery. |
| [ESP-IDF WireGuard](https://github.com/trombik/esp_wireguard/tree/9217c5be0836e908005301ad2c2d42009e560c0e), `9217c5b` | Example obtains time before WireGuard. Implementation has a static WireGuard netif and can change the global default route. | Time readiness is useful. A singleton interface/default-route switch is unsuitable for our simultaneous memberships; this library is not a Tailscale control client. |
| [Tailscale tsnet](https://github.com/tailscale/tailscale/blob/67f8c81e610d9f469baf648dcea24a9589b17fb6/tsnet/tsnet.go), `67f8c81` | Multiple server instances require distinct persistent state directories and hostnames. | Keep membership identity/storage/transport ownership explicit. The Go runtime is not a drop-in ESP-IDF implementation. |
| [WireGuard routing and namespaces](https://www.wireguard.com/netns/) and [OpenWrt policy routing](https://openwrt.org/docs/guide-user/network/routing/pbr_netifd) | Tunnel address spaces and outer transport routing can be isolated; OpenWrt assigns interfaces separate routing tables. | Preserve membership-scoped aliases, flows and DNS. Explicit physical-uplink binding is worth strengthening; do not install a global `100.64.0.0/10` route that cannot distinguish colliding tailnets. Linux namespaces and OpenWrt are design references, not firmware to transplant. |

These sources narrow the recommendation: retain the adapted C engine and isolation design, but borrow more of the router integration and recovery discipline. The inspected ESP Tailscale projects share the same engine family; their existence does not independently validate our custom gateway.

## New device evidence

Android v118 reported a verified flash followed by `CONSOLE_IDENTIFY` failure. USB descriptors showed Espressif `303a:1001`, CDC plus Serial/JTAG, with no NCM interface. Repeated received-byte counts were consistent with repeated boot output but could not establish its cause because the app discarded the bytes.

Android v119 captured 14 repetitions of `panic=task stack overflow`, ELF digest prefix `1bf50e67b`, and the following program counters. That prefix matches the exact local 0.2.10 ELF SHA-256 `1bf50e67b2062b0522683bd45e4617b87701f990a3e8e791f2458d475057b563`.

| PC | Resolution against the matching ELF |
| --- | --- |
| `0x4037ac41` | `panic_abort` |
| `0x4037ac09` | `esp_system_abort` |
| `0x4037bb12` | `vApplicationStackOverflowHook` |
| `0x4037cbf7` | `vTaskSwitchContext` |
| `0x4037bc18` | `_frxt_dispatch` |
| `0x4037bc0e` | `_frxt_int_exit` |

This proves an actual stack-overflow crash, not an authentication failure or a USB permission explanation. V119 did not preserve the task name; the kernel backtrace alone does not identify which task overflowed. The following changes target the observed pre-management failure and a directly measured stack hazard. Physical startup confirmation is still required.

## Execute: bounded recovery correction

Success criteria: a reviewable firmware correction that lowers startup stack pressure, exposes management before optional initialization, preserves NVS and peer storage, and gives Android durable, bounded boot evidence plus an available manual install action. No physical flash, full erase, tailnet switching, protocol rewrite, merge or release publication is performed by the agent.

Firmware 0.2.11 uses the upstream router's 7168-byte main stack, which FreeRTOS releases when `app_main` returns. The diagnostic journal writer no longer places its 1640-byte journal on every caller's stack: it allocates temporary workspace, releases it on success and duplicate suppression, and skips the write safely on allocation failure. Actual Xtensa writer frame falls from 1776 to 160 bytes. USB CDC management starts before peerstore mounting, journal writes and Wi-Fi startup. The firmware still requires successful NVS and basic USB/network initialization; this is not a complete recovery partition.

Android preserves only recognized reset codes, panic classes, allowlisted task names, program counters, backtraces and ELF identifiers. Unknown serial content, passwords and login URLs are not archived. Evidence is captured before the identification drain discards input, survives failed writes and reconnect attempts, and is included in the automatic on-disk archive. New flash attempts clear the live fault summary so an old crash is not attributed to new firmware; archived prior samples remain.

The firmware installer remains usable after verification without management recovery, and Help no longer redirects to Overview. Firmware selection, board confirmation and Install precede optional downloads. The USB descriptor alone no longer claims the current firmware is in download mode.

## Risk retirement and review

| Risk | Status and evidence | Wrong patch rejected |
| --- | --- | --- |
| Firmware failure misclassified as connection friction | Retired for this observed failure: saved panic plus matching ELF decode | Another replug prompt or map-size tweak |
| Journal stack pressure and insufficient configured startup stack | Compiled frame reduced to 160 bytes; generated config is 7168. `tools/check-startup-stack.py` checks actual build outputs | Edit defaults while an existing sdkconfig silently retains 3584; add logging while retaining a large automatic journal |
| Low-memory journal allocation or duplicate event leaks | Host journal tests with ASan/UBSan, injected OOM and duplicate suppression | Move the ring to heap but leak it or keep the mutex on OOM |
| Recovery action hidden or Help inaccessible | `FirmwareRecoverySurfaceTest` exercises the actual Android Activity with a verified-but-failed state | Change wording while keeping the installer hidden or forcing navigation |
| Boot diagnostics lose or leak information | `BootEvidenceTest` tests every split boundary, pre-identification drain followed by a failed write, floods, oversized input, task allowlisting and a new-flash reset | Record byte counts only; retain raw arbitrary console lines; attribute old crashes to the new image |
| Boot succeeds on the actual board | Accepted hardware boundary pending a new installed image | Claim a successful build proves the crash is fixed |
| One working tailnet, then concurrent N memberships, relay traffic and memory capacity | Accepted hardware boundary; not retired by boot recovery | Announce multi-tailnet acceptance from host parser/router tests |

Review: the stack overflow invalidates the prior explanation that this particular failure was merely a USB reconnect issue. Keep the broader product aim, change the immediate frame to boot recovery, then resume one-peer traffic qualification before two-membership collision and relay tests. Clock readiness, explicit outer-transport pinning, MTU/MSS handling, and bounded recovery after repeated crashes are the next integration comparisons to pursue; they are not claimed as delivered here.
