# 0.4.0-rc2 hardware qualification

Tracking: [#53](https://github.com/muness/T-Dongle/issues/53). Boot defect: [#52](https://github.com/muness/T-Dongle/issues/52). Integration branch: `rust/rc2-int`. Measured on 2026-10-07 on the ESP32-S3 T-Dongle with MAC `30:ed:a0:d7:88:bc`. Single tailnet only. No release tag has been created.

The firmware built from `c7fbe28` boots and reaches tailnet state 4. Later commits update packaging and this evidence, without changing firmware code. The flashed app SHA-256 is `5bbe01a3abf79baa8b815729dc0deb67fb89eab992c89d34b3dd09753d7b42e0`; the ELF SHA-256 is `d44c4e4e21053084ba9d0b69ccb580779f43dc8cccec1312d44bac5eeb50e08d`.

## Board gates

| # | Gate | Result | Measurement |
|---|---|---|---|
| 1 | Flash selftest | Pass | `nvs_capacity=16777216` |
| 2 | Join time | Measured | State 4 at uptime 14,236 ms; rc1 approximately 8 s |
| 3 | Flash directory and reboot | Pass | 20 peers restored before the first control map; errors 0; generation 30 |
| 4 | Direct TCP | Pass | 15 s iperf3 received rates: up 1.2396, down 1.2579 Mbit/s; rc1 1.3 / 1.1–1.2 |
| 5 | Relay TCP | Pass | Forced DERP, 15 s iperf3 received rates: up 0.4623, down 0.6291 Mbit/s; rc1 0.4 / 0.5; force-DERP restored off |
| 6 | Traffic rate | Pass | Sample under load: down 210, up 926 kbit/s; byte counters advance |
| 7 | Temperature | **Fail: owner decision pending** | Valid 1, peak 74.9°C under traffic, approximately 69.9°C idle; exceeds the specified 70°C ceiling |
| 8 | Mode switch | Pass | HTTP `/command` to `wifi_bridge`, healthy boot, then serial return to `tailnet_gateway` and healthy boot |
| 9 | HTTP | Pass | `/status` JSON reports 0.4.0-rc2; `/serial` replies; `/wifi-scan` returns 11 networks; `/command` successfully switches mode |
| 10 | Heap admission floor | Pass | Under throughput load, minimum excluding control negotiation 32,688 B versus floor 29,884 B: margin 2,804 B |
| 11 | Panic recovery | Pass | `selftest panic` returns running console within 6.078 s of command completion; rescue becomes healthy; no replug |
| 12 | 30-minute soak | Pass | 1,800 s, 61 samples, trips 0/0, no resets, state 4 throughout, directory errors 0 |

Heap qualification uses `min_without_negotiation`, the admission floor defined for elastic consumers. The fixed control workspace is explicitly allowed below that floor. The raw global minimum during a later control retry was 23,852 B; it is not concealed or treated as an elastic-floor measurement. The heap allocation is 246,784 B. No heap floor or stack minimum was lowered to obtain a pass.

The soak workload is an idle joined gateway with brief status exchanges every 30 seconds, rather than continuous iperf. Each serial exchange closes its descriptor. The USB-reset counter starts at 1 following the intentional panic recovery; qualification requires no counter increase, no uptime restart, and USB-watch trips `0/0`. The [sanitized sample log](release-0.4.0-rc2-soak.jsonl) records all 61 samples. Directory count changes from 20 to 18 through normal control-map updates. Lowest free heap is 46236 B; raw minimum is 40,844 B and the minimum outside negotiation is 46,132 B. Sampled temperature ranges from 65.9 to 70.9°C.

## Fixes verified

The stack guard remains intact when marking free stack. Hardware testing also exposed excessive constructor frames and a restored-directory clear on member attachment. Large bridge and USB buffers now initialize in static storage; outlined member and setup constructors bound stack use. The directory is bound to the persisted WireGuard public node key: the same key restores it, a different or legacy key invalidates it, and attach failures do not authorize stale session state. Fresh control data is still required for authentication and session validity.

The stack checker now parses hexadecimal Xtensa entry immediates, which previously escaped its checks. The largest emitted frame is 11,232 B, initialization is 10,560 B, and main is 7,488 B. Reserved stack is 46,456 B, above the 40,960 B minimum. The compiled direct-call lower-bound check passes its 36,000 B budget. Indirect calls and poll dispatch are omitted; it does not prove the maximum synchronous chain, so hardware stack observations remain necessary. Final load and pre-panic status samples report 15,296 B free on the marked control stack.

`flash.sh` discovers only the pinned board by USB serial metadata, checks its MAC before writing, requests download mode through bounded raw console exchanges, uses `--before no_reset --after watchdog_reset`, and retries only transient port-ownership failures. Success requires a fresh running boot with advancing uptime and rescue health after at least 30 seconds. It detects intervening resets and closes serial between exchanges. Package instructions now direct flashing through this helper. Repeated final-image flashes and panic recovery worked without another BOOT-held replug.

All five requested host follow-ups are integrated: Android embedded page uses `/command`; JSON nesting property range starts at 1; queue feature conflict is resolved; web UI tests run in CI; and `FlashDir::clear()` invalidates the NOR header without two immediate sector erases.

## Host validation

The final serial workspace run passed 1,601 tests, with zero failures and 8 ignored, across 238 test groups. This includes 23 passing tailnet end-to-end tests and one ignored e2e test. The flash helper has 13 passing host tests, the stack parser has 3 passing regression tests, and `node rust/webui/test.mjs` passes. Bridge static initialization and loom compilation were checked. CI runs workspace tests serially because the e2e fixtures share host resources.

## Owner qualification

The strict temperature gate still blocks declaring all 12 board gates passed. The owner also needs to test the setup AP from a phone, the Android app, and [the web UI checklist](../../docs/webui-checklist.md). Package Android hardware qualification remains false pending that review. Tag 0.4.0 only after the owner explicitly says go.

## Setup-AP handoff

Setup AP was entered only after the completed gateway soak. The fresh setup boot reports stage `running`, rescue `healthy`, safe mode false, and recovery false. Serial status confirms `setup active=1 ap=TDongle-D788BC`. Join that open network from the phone and open `http://192.168.4.1/`. The setup session lasts ten minutes and then returns to the saved tailnet-gateway mode; it does not extend when a client connects. This AP handoff is separate from the 30-minute state-4 gateway soak.
