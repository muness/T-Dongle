> **Scope.** This record was taken on the v0.1.x bridge-only firmware (now archived under `legacy/`). The combined firmware has not been re-validated on hardware by this record; see the release notes for the current state.

# Validation record — 2026-09-25

**Implemented**, **compiled**, **host-unit-tested**. **Not tested on T-Dongle hardware, macOS USB networking or TeslaAndroid.** No target was flashed; no Pi network configuration changed. This is a development release for physical validation, not an accepted replacement for the working PIX-LINK yet.

Firmware sources built from `61eda53` (subsequent changes are tests, documentation, license retention and packaging). The final generated package manifest records the repository commit and dirty flag. Build environment: Linux x86_64; ESP-IDF v5.5.1 exact commit in SOURCE_AUDIT; Xtensa GCC 14.2.0 `esp-14.2.0_20241119`; Python 3.12.3; host tests GCC 13.3.0. No system package installation or root was needed; local tools were installed in user space.

## Actual build results

All commands exited successfully; final firmware builds had no compiler warnings/errors:

| Command | App size | USB descriptors read from linked ELF |
|---|---:|---|
| `tools/build.sh full` | 1,186,880 bytes | VID:PID `303a:4001`; CDC-ACM control/data + NCM control/data (alternate 0/1); 500 mA |
| `tools/build.sh headless` | 884,064 bytes | Same classes/VID/PID; LCD/LED disabled |
| `tools/build.sh network-only` | 1,178,608 bytes | `303a:4000`; NCM only, no ACM; 500 mA |

Each artifact has a 16 MB ESP32-S3 configuration, PSRAM disabled, NCM enabled, custom 4 MiB app partition and reproducible-build mode. Bootloader and partition images were generated. Checking linked descriptors is **not physical enumeration testing**.

A separate fresh local Git clone, with no build directory or managed components, fetched locked dependencies and ran `tools/build.sh full` successfully. Its **application, bootloader and partition image were byte-identical** to the working-directory full build on the same toolchain. This is a demonstrated two-path clean build, not a claim of universal cross-toolchain reproducibility.

Application SHA256:

```
full          1ce493876c13d2e56cb9a3d6bd2c43d34dd95bd1fd69cf7b9f7537393ca41a74
headless      0490dbacbd0a62fc292b2a3cbd698fce4c5908e8b960f45f3303246ee5f96b54
network-only  e63c3075e71835e8b62b3214b1f7ab2ea2ff263cf56cc40688e9303618640718
```

Versioned packages are generated in `dist/tdongle-0.1.0-{full,headless,network-only}/` and matching `.tar.gz` files. Internal `SHA256SUMS` covers all package files; adjacent `.sha256` covers each archive. Effective sdkconfig, ELF, source lock, license notices and exact flash offsets are included. No auto-flash step exists. Machine-readable results: [builds.json](results/builds.json).

## Actual host test results

`TEST_CFLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' tools/test.sh`, with GCC 13.3.0 and pinned IDF_PATH: **PASS**. Four C test executables, eight Python unittest cases, and five synthetic layout previews. ASan/UBSan symbols were verified in all four test executables. The script now includes an ASan compiler/runtime probe so unsupported sanitizer flags cannot silently produce a claimed pass.

- Portable core: 100,000 deterministic arbitrary/short frame inputs plus explicit IPv4/ARP/IPv6 boundary cases; reflection filter; address TTL/clock regression; large counter/rate math and counter reset; preferred/priority/exhausted selection; bounded backoff; candidate validation deadline and association-epoch changes between polls; button bounce, hold one-shot and wake suppression; clipped UI text, unknown RSSI, terminal escape sanitization and truthful Internet label.
- Actual vendored `tinyusb_net.c` body compiled against a deterministic FreeRTOS/USB scheduler: successful copy, cancellation before copy, timeout racing completed copy, backpressure and subsequent recovery. Verifies exactly-once release behavior at the known donor-wrapper failure boundary. It is not a real USB controller stress test.
- Actual `settings.c` against a mock NVS transaction contract: default settings, commit failure preserves old blob, candidate consumption, reboot-during-trial preservation, unknown schema rejection and explicit reset. Real flash power-cut integrity remains pending.
- Shared browser/serial JSON parser with IDF's pinned cJSON source: malformed/non-object input, duplicate/unknown fields, escaped NUL, fractional index, control characters, short passwords and trailing content rejected; valid profile accepted.
- Python: credential bounds/open mode, password entry approach, unavailable tools, permission denial, read-only command inventory, artifact notice recursion prevention and distinct version/variant archive names.
- Five 160×80 bounds previews generated from synthetic states using production text formatting; approximate browser font. No hardware screenshots or invented runtime values.

Raw host results: [host-tests.txt](results/host-tests.txt). Python bytecode compilation, shell syntax checks and Git whitespace checks also passed. `host_diagnostics.py` ran read-only on this development Linux host; mocked unavailable-tool/permission paths passed. That host is **not** the user's Pi or a dongle enumeration target. CI workflow is supplied but has not been run by GitHub in this local-only repository.

Earlier failures were corrected before this record: compiler API integration, a console symbol collision, archive notice recursion, executable bits missing in a fresh checkout, archive suffix collapsing variant names. An initial Zig run accepted ASan flags without emitting ASan; it is **not counted as ASan coverage**. The final sanitizer result above uses native GCC.

## Memory evidence and limits

Link-time size, not runtime free heap:

| Variant | Static DIRAM used | DIRAM remaining in linker budget | Dedicated IRAM used |
|---|---:|---:|---:|
| full | 187,515 B | 154,245 B | 16,384 B |
| headless | 144,491 B | 197,269 B | 16,384 B |
| network-only | 184,683 B | 157,077 B | 16,384 B |

Fixed buffers include eight 1514-byte copied frames, three 3200-byte NCM NTBs in each direction, 32 KiB LVGL arena, bounded command/output queues and event/history arrays. Display allocates separate 5120-byte render/DMA buffers. Dynamic Wi-Fi, task stacks, setup netif/HTTP and driver allocations consume additional memory. **Remaining linker RAM is not measured usable runtime heap.** Runtime current/min heap, DMA-capable free memory and UI/control stack watermarks are exposed for the physical test. Throughput, latency, current draw, recovery timing, overnight stability and UI-on/off impact remain unmeasured.

## Pending acceptance / next physical step

[ACCEPTANCE.md](ACCEPTANCE.md) has the complete unchecked matrix. First: inspect the actual board and ROM-reported flash size, resolve the schematic/product discrepancy, then obtain owner authorization to flash the **headless** build on a Linux test host. Verify power budget, USB enumeration, station association, DHCP/ARP and bidirectional traffic before the full UI build and actual Pi/TeslaAndroid coexistence test.

Hardware release gates include the board's published 800 mA maximum versus USB2's 500 mA descriptor budget, suspend-current compliance, panel offset/color/brightness, all authentication modes, IPv6/multicast, AP/profile failover and power-cut recovery. The installed TeslaAndroid release/fingerprint is unknown; repository NCM support cannot establish it. No real compatibility blocker has yet been observed, so no Android modification, ECM/RNDIS implementation or NAT fallback is proposed.

## macOS hardware session, 2026-09-28

First physical run, on an original T-Dongle-S3 (ESP32-S3 rev v0.2, Winbond 16 MB flash) with a Mac as USB host. Not the Pi, not TeslaAndroid.

- The packaged QIO 80 MHz setting boot-looped on this unit; DIO 40 MHz boots. Defaults changed accordingly.
- The firmware wedged its USB device side after a transfer test: CDC-ACM console silent, NCM link reported inactive, LCD and Wi-Fi still running, chip still enumerated. Cause attributed to the forwarding worker deferring a link-state refresh into TinyUSB's 16-entry event queue once per frame, competing with ISR transfer-complete events. Now rate-limited to link changes plus a 1 s heartbeat. Not reproduced since, but the attribution is inference, not a captured trace.
- Downstream drops were 15% because a frame was dropped the instant all NCM IN transfer blocks were in flight. With a bounded retry (up to ~100 ms) and 4 × 6400-byte IN blocks: 10 MB HTTP download at ~700 KB/s, 134 drops in 8,854 frames, console answering throughout. Before: ~214 KB/s, 1,502 drops in 9,775 frames.
- Setup AP was not visible after the first boot following an esptool reset; visible after a power-cycle. Unexplained.
- macOS placed the NCM service above Wi-Fi, so the laptop routed all traffic through the dongle as soon as it had a lease. Host-side service order, not firmware.

### iperf3 to a LAN NAS through the dongle, same evening

Mac host, `iperf3 -c 192.168.1.2 -B <dongle address>`, 30 s each way, dongle counters sampled at 1 Hz over the console throughout (no console dropouts in either run).

| Build | Down Mbit/s | Down drops / frames | Up Mbit/s | Up retransmits | poolfail / up frames | RSSI |
|---|---:|---:|---:|---:|---:|---:|
| 100 ms USB retry, no Wi-Fi retry | 7.2 | 100 / 19,377 | 5.7 | 190 | 193 / 14,837 | -73 |
| 300 ms USB retry, 20 ms Wi-Fi retry | 7.1 | 125 / 18,938 | 5.3 | 68 | 55 / 13,686 | -66 |

Downstream sits at 7.1 to 7.5 Mbit/s, which is within about 15% of what NCM over full-speed USB can carry; the longer retry window changed nothing. Upstream is not limited by the dropped frames: retrying the Wi-Fi transmit cut refusals by 70% and TCP retransmits by two thirds, yet throughput was unchanged with the congestion window hovering at 45 to 70 KB, which points at round-trip latency through the dongle's Wi-Fi transmit queue and air-time on a shared 2.4 GHz channel. Further firmware work on throughput is not justified by this data.

`esp_restart()` arms a 1 s RTC watchdog with flash-boot protection before resetting. Entering ROM download mode that way leaves the watchdog running, which reset the chip out of download mode within seconds: once during a write (erasing the app partition; recovered with plain esptool since the bootloader loop leaves USB-Serial-JTAG up) and twice into a boot whose USB device side never worked (console and NCM data both dead, link reported up). Both forced-download paths now use the bare ROM software reset.

### Roaming and Wi-Fi TX queue, same evening

- **RSSI-only roaming was tried and removed.** A handwritten roam (floor -70 dBm, 8 dB gain) left a -68 dBm channel 11 AP for a channel 6 AP within 20 s of boot and moved three times in three minutes. Both radios sit between -60 and -75 dBm in the test room, so the floor was inside normal variation, and instantaneous RSSI is too noisy to compare against a scan. ESP-IDF's roaming app is gated behind IDF_EXPERIMENTAL_FEATURES. The firmware now enables 802.11k/v (RRM + WNM) so a steering controller can move the dongle, and does no self-initiated roaming. `status` reports `roams=`, counting any association to a new BSSID. Steering by a real controller has not been observed yet.
- **A smaller Wi-Fi TX queue did not help.** Same AP (channel 6, -56 to -62 dBm), 25 s iperf3 each way:

| Dynamic TX buffers | Down Mbit/s | Up Mbit/s | Up RTT under load | poolfail (up) |
|---:|---:|---:|---:|---:|
| 8 | 7.00 | 5.18 | 69 ms | 35 |
| 24 (default, kept) | 7.21 | 5.57 | 66 ms | 5 |

Upload latency is unchanged, so the queueing is not in the dongle's Wi-Fi TX buffers. The Mac's interface queue or air-time is the likelier source. The channel 6 AP that gave 3.4 to 4.1 Mbit/s down at -74 dBm gave 7.0 to 7.2 at -60, so that was signal, not a repeater.
- `tools/flash.sh` now reflashes with no button and no replug. macOS pyserial reports the ROM's USB-Serial-JTAG as pid 0x9, which the script previously did not recognise.
