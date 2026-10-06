# ADR 0001: Port the T-Dongle firmware from C/ESP-IDF to Rust (esp-rs)

Status: accepted by the owner for implementation, 2026-10-06. Phase 1 (bridge mode) is built and host-tested; **nothing in this ADR has run on a board yet**: every throughput, latency, heap and stack number below is either measured on the host, read from a built image, or a *prediction with a stated refutation*, and is labelled so.

The decision to port was made by the owner and is not argued here. What this ADR decides is *how*: which Rust platform, which crates, how the C firmware's on-flash and on-wire contracts are kept, how the code is laid out so that most of it is testable without a board, in what order it is built, and what has to be true before each phase replaces the C image. The C firmware is the specification: its ADRs (`alternative/tailnet/docs/adr/0013` to `0024`), its tests and its status output decide every question about behaviour.

## Context

The point of the port is to use Rust's guarantees to remove the defect classes the C firmware actually hit, not to translate it line by line. The defects, from the C ADRs and their review findings:

| C defect | Where it came from | Rule below |
|---|---|---|
| a TX ring slot released twice or never (v122, `l2_release`) | a pointer plus a counter store the caller had to remember | 1 |
| a frame that "fell through" every counter (silent drops, ADR 0023 section 3) | `if / else if` chains with counters bumped by hand | 2 |
| the open setup access point routed to the USB host (ADR 0024, HIGH) | a stage re-reading `setup_active` and creating the USB netif anyway | 3 |
| `vTaskDelay` in the TinyUSB receive callback (ADR 0023 context) | nothing says what a callback may call | 4 |
| lost wake-up and torn reads in the host queue's hold/resume | lock-free code argued in comments | 5 |
| the IPv6 extension-header bypass of the ECN exemptions (ADR 0023 amendment 7) | a hand-written parser tested by examples | 6 |
| "about 6 KB unattributed" heap (ADR 0022) | the owner ledger was opt-in and diagnostics-only | 7 |
| a driver call whose result nobody read | `(void)` and unchecked `esp_err_t` | 8 |

What the port keeps exactly, because other software depends on it: the serial `status`/`list`/`mode`/`help`/`capabilities` text (the Android app parses it), the NVS namespaces, keys and blob layouts (`tn_settings`, `adapter`), the partition table, the USB device identity, the flash parameters (DIO, 40 MHz: the tested board boot-loops at QIO 80 MHz) and the numbers of ADR 0023 amendment 7.

## Decision

1. **Platform: `std` Rust on ESP-IDF v5.5.5 (esp-idf-sys / esp-idf-hal / esp-idf-svc), with a hybrid fall-back rule.** The evidence is in "Platform decision" below; it includes the four driver spikes (S1 to S4). Rust is used for everything that is policy, protocol, accounting and glue. C is used only for what the C firmware also did not own: the Wi-Fi blobs and their private API, TinyUSB, lwIP, mbedTLS, the HAL. **The C firmware is not wrapped through FFI**: no function of `components/tdongle_runtime`, `components/esp_tinyusb`, `alternative/tailnet/main` or `microlink` is compiled into the Rust image.
2. **Layout: pure `no_std` crates with host tests, thin hardware crates around them** ("Crate layout").
3. **Compatibility by golden test generated from the C sources**, never from a transcription ("Compatibility").
4. **Four phases with measured acceptance gates** ("Phasing").
5. **Twelve design rules** ("Design rules"), each with the way it is enforced in phase 1 and honestly marked where it is not yet.

## Platform decision

<!-- SPIKES -->

## Toolchain (exact, and where they are recorded)

Installed with `espup install --targets esp32s3 --toolchain-version 1.97.0.0 --export-file ~/.cache/tdongle/export-esp.sh`; recorded in `rust/rust-toolchain.toml` and re-installed by the `firmware` job of `.github/workflows/rust.yml`.

| Component | Version |
|---|---|
| espup | 0.17.1 (0.18.0 exists; 0.17.1 is what produced the installed toolchain) |
| Xtensa Rust (`channel = "esp"`) | 1.97.0.0, `rustc 1.97.0-nightly (8ea53bcd7 2026-07-08)`, `-Zbuild-std=std,panic_abort` |
| LLVM for bindgen | `esp-20.1.1_20250829` |
| Host Rust for the pure crates and CI | stable (1.98.1 locally; `rust-version = 1.90`); nightly only for Miri and `cargo fuzz` |
| ESP-IDF | v5.5.5, commit `b774170ff46c393eeb5e495ea37936038d3f4f4f`, the checkout the C firmware pins (`tools/bootstrap.sh`), selected with `ESP_IDF_TOOLS_INSTALL_DIR=fromenv` and its own GCC 14.2 (`esp-14.2.0_20260121`) |
| esp-idf-sys / esp-idf-svc / esp-idf-hal / embuild | 0.38.1 / 0.53.0 / 0.47.0 / 0.33.5 |
| TinyUSB | `espressif/tinyusb` 0.21.0~2, the C firmware's pin, pulled by `extra_components` |
| ldproxy / espflash / cargo-espflash | 0.3.5 / 4.6.0 / 4.6.0 |
| loom / proptest / cargo-fuzz | 0.7.2 / 1 / latest at install |

`espup`'s own GCC 15.2 must **not** be on `PATH` when the IDF builds (it checks its toolchain version): `rust/tools/env.sh` sources the pinned IDF's `export.sh` and adds only `LIBCLANG_PATH`. The first build compiles ESP-IDF (about 6 minutes on an M-series laptop); after that an incremental firmware build is 5 to 25 seconds.

## Crates for the protocol and crypto (phase 3; decided now so phases 1 and 2 do not preclude them)

Checked against crates.io and the crates' sources on 2026-10-06:

| Need | Choice | Why / what was checked |
|---|---|---|
| Noise IK (ts2021 control) | `snow` 0.10.0 (`no_std` + `alloc`, pluggable resolver) with RustCrypto primitives | audited and widely used; handshake state is small and bounded. The C microlink code is hand-rolled; rule 10 forbids porting it |
| ChaCha20-Poly1305 | `chacha20poly1305` 0.11.0 (RustCrypto) | `no_std`; mbedTLS's version (already enabled in the C image, hardware-assisted SHA only) is the fallback if the S4 numbers say software is too slow |
| X25519 | `x25519-dalek` 3.0.0 / `curve25519-dalek` 5.0.0 | `no_std`; `precomputed-tables` costs flash, to be measured |
| BLAKE2s, HMAC, HKDF | `blake2` 0.11.0, `hmac` 0.13.0, `hkdf` 0.13.0 | `no_std`; WireGuard's KDF and MAC |
| WireGuard | a small `no_std` crate of our own (Noise IKpsk2 handshake, transport, replay window, timers) over the primitives above, tested against the C firmware's `test_wg_replay.c`/`test_wg_crypto.c` vectors and against `wg` interop | **`boringtun` 0.7.1 is not usable on the device**: it is `std` only (`std::net`, `std::sync`, `parking_lot`, `ring`, `nix`). The only existing Rust Tailscale-on-ESP32 code found (`0xdilo/tailscale-esp32`, MIT, 0.1.0, 5 stars) is `std` and a reference, not a dependency |
| TLS (DERP, HTTPS) | on `std`: mbedTLS through `EspTls` with the certificate bundle and `CONFIG_MBEDTLS_DYNAMIC_BUFFER` (IDF docs: about 22 KB per HTTPS connection with dynamic buffers, 42 KB without). On `no_std`: `embedded-tls` / `mbedtls-rs` 0.3.0, young; `rustls` needs a crypto provider (`rustls-rustcrypto` 0.0.2-alpha says "do not use in production") | see S4 |
| constant-time compares | `subtle` (`ConstantTimeEq`) for every MAC, tag and key comparison | rule 10 |

Test vectors: the Noise and WireGuard vectors of the Tailscale and WireGuard test suites, RFC 7539/8439 vectors (already in `alternative/tailnet/tests`), and the `control_interop.go` interoperability test the C firmware runs against the real Go `tailscale` control protocol code.

## Compatibility

* **Serial text.** `tdongle-serial` renders the `status`, `list`, `display`, `pm`, `help`, `capabilities` and bridge lines from typed structs through one formatter each. `tools/gen_golden.py` compiles the **real C function bodies** (`serial_status`, `pm_report`, `bridge_visit`/`bridge_line_emit`, the `list`/`display`/`scan` formats, `wifi_link.h`, `clock_sync.h`, `memory.c`), cut out of the C sources by brace matching, over 208 scenarios and writes the expected bytes; the Rust tests assert byte equality, and CI re-runs the generator and fails on any diff. The Android rules (the `chip_temperature` line is end-anchored; additions go on new lines) are asserted as tests. New information goes on **new lines** only: phase 1 adds `rust_port ...` and `rust_heap ...`.
* **NVS.** `tdongle-nvs-format` encodes and decodes `tn_settings/wifi_profiles` (784 B), `wifi_meta` (516 B), `display` (8 B), `mode`, the single-network `wifi` blob, and the v0.1.x `adapter/config` (1,004 B), with the C's validation and the load rules of `wifi_load_profiles()`. 88 golden blobs are generated by compiling the C encoders (`wifi_meta.c`, `legacy_import.c`, `ui_settings.c`, `profile_json.c` with cJSON) and each must round-trip byte for byte. **Phase 1 only reads** these namespaces (read-only handles), so a board can alternate between the C and the Rust image; the single exception is `mode wifi_bridge`, the same one-byte write the C command makes. The Rust image never calls `nvs_flash_erase` (esp-idf-svc's `EspNvsPartition::take()` would, on a version change: it is not used).
* **Partition table and flash parameters.** `rust/firmware/partitions.csv` is the C firmware's file; `rust/tools/check_image.py` parses the table out of the merged image and compares it with `partitions.csv`, and checks DIO / 40 MHz / 16 MB in the bootloader and the app image headers (the C's `tools/check_build.py` rules).
* **USB identity.** `tdongle-usb-descriptors` builds the device, configuration and string descriptors in `const` code and tests them against the bytes dumped from the C image's ELF (`tools/dump_c_descriptors.py`): VID 0x303A, PID 0x4001, the CDC-ACM + CDC-NCM composite, "T-Dongle-S3 NCM", the station MAC as serial and as the NCM MAC.

## Crate layout

```
rust/
  rust-toolchain.toml  Cargo.toml (workspace)  docs/adr/
  crates/                         #![no_std], host-tested (`cargo test`), unsafe forbidden unless stated
    tdongle-aqm                   CoDel (RFC 8289, hold-evidenced signal), ECN classify/mark, IPv6 extension-header walk
    tdongle-bridge                the bridge's forwarding logic over an `Env` trait; outcome enums; link tokens; counters
    tdongle-spsc                  THE unsafe: the slot queue with move-only handles, TaskContext; loom-checked
    tdongle-usb-ring              Wi-Fi->host elastic slab ring over a `RingEnv` trait (unsafe confined to its raw-memory accessors, Miri-checked)
    tdongle-wifi-budget           TX/RX pin budget, heap-floor constants (ML_HB_*)
    tdongle-wifi-policy           ranking, hysteresis, the `use N` pin, retry/backoff
    tdongle-nvs-format            blob codecs and load rules
    tdongle-serial                console line discipline, command grammar, every reply text, status and bridge lines
    tdongle-traffic, tdongle-pm   rate sampler; CPU-clock bursts and the activity hold
    tdongle-usb-descriptors       the USB identity
  firmware/                       std, esp-idf-svc: thin glue, every `unsafe` block carries a SAFETY comment
    src/sys/                      the audited unsafe layer (critical section, heap, task notify, read-only NVS)
    src/usb/ wifi/ bridge.rs pm.rs console.rs report.rs settings.rs boot.rs alloc.rs diag.rs
  fuzz/                           cargo-fuzz targets (classifier, command line, JSON, blobs)
  spikes/                         the S1 to S4 driver spikes (own cargo projects, not workspace members)
  tools/                          env.sh  build.sh  check_image.py
```

Host tests: 400+ tests across the pure crates (`cargo test`, about 15 s), including the ports of the C `test_aqm.c`, `test_l2.c`, `net_ring_cases.c`, `test_wifi_pin_budget.c`, `test_pm_burst.c`, `test_wifi_meta.c`, `test_legacy_import.c`, `test_ui_settings.c`, `test_wifi_policy.c`, `test_traffic.c`, `test_wifi_link.c`, `test_clock_sync.c`, `test_serial_commands.c` cases and invariants.

## Design rules (the coordinator's twelve), and how phase 1 applies them

| # | Rule | Phase 1 status |
|---|---|---|
| 1 | **Ownership for buffers.** Slot handles are move-only; release is `Drop`; handing a frame on consumes the handle | **Done for the host queue**: `tdongle_spsc::Lease` (not `Clone`/`Copy`; its `Drop` is the single release, `SeqCst` store of `tail + 1`) and `Reservation` (consumed by `publish`). A test proves release-on-drop only and abandoned reservations publish nothing. **Not done**: the USB ring's slabs and the Wi-Fi driver RX buffer are still bookkeeping inside `tdongle-usb-ring` and a `free` call in `bridge.rs::wifi_rx` (freed once on every path by construction, but not a `Drop` type). The ring's exactly-once property is tested (model, threads, soak) rather than typed. Planned for phase 2 with the RX buffer as a `DriverRxBuffer` handle |
| 2 | **Exhaustive outcomes.** Every frame ends as one variant of a `#[must_use]` enum; counters come from a `match` with no wildcard | **Done** in `tdongle-bridge`: `ToHost`, `HostOutcome`, `Delivery`; `settle_to_host`, `settle_host`, `settle_delivery` are the only places the counters move and have no `_` arm, so an uncounted path does not compile. The identities (`w2h_frames = forwarded + the drops`, and two more) are checked after every operation of a 6 x 60,000-step randomised run and of a threaded run (`Stats::check_identities`) and by property tests in `tdongle-aqm`. `proptest` generators for whole bridge operation sequences are phase 2 |
| 3 | **Typestate for boot modes and links** | **Done**: `boot.rs` has `SetupBoot`, `BridgeBoot`, `TailnetBoot` (uninhabited until phase 3); `UsbNetwork`, the capability `wifi::start` and the bridge need, can be produced only by the last two (there is no `SetupBoot::usb_network`). Links: frames carry a `LinkToken`; `Bridge::validate` is the only source of the `Fresh` proof `transmit()` requires, so a frame of a dead association cannot reach the driver |
| 4 | **Callback context safety** | **Done at the type level for the bridge**: every `Env` method that may block (`wifi_tx`, `wait_retry`, `rx_resume`) and `Bridge::link` take `&TaskContext`, which the TinyUSB and Wi-Fi receive callbacks never hold (not `Clone`/`Copy`; `unsafe fn assume()` only at the event-task entry). **IRAM**: the Wi-Fi tx-done callback is `#[link_section = ".iram1..."]`, `WifiPins::done` and the lock are `#[inline(always)]`, and `tools/check_image.py` disassembles it and fails the build if any call or literal address it loads is outside IRAM/ROM. Not yet typed: ISR-only contexts (phase 1 has no ISR code of its own) |
| 5 | **Concurrency verification** | **loom** (0.7.2): `tdongle-spsc/tests/loom_spsc.rs` explores every interleaving of the slot queue with loom's tracked `UnsafeCell` (data-race and torn-read freedom). **Found and recorded**: loom models `SeqCst` as acquire/release, so it cannot check the hold/resume handshake (a store-buffering pattern that needs sequential consistency): it reported a deadlock that real `SeqCst` atomics forbid. That test is kept `#[ignore]`d with the explanation; the property is instead checked by `sc_handshake.rs`, an exhaustive enumeration of every interleaving of the protocol's atomic steps under SC, with **mutation tests** (delete the re-check, delete the worker's swap: the checker must find the lost wake-up). **Miri** runs on `tdongle-spsc`, the USB ring, the descriptors and the traffic crate (all pass; the bridge's `cases` pass with `-Zmiri-ignore-leaks` because the tests leak the bridge on purpose) |
| 6 | **Parsers are fuzzed** | `cargo-fuzz` targets for the ECN/IPv4/IPv6 classifier (with a marking invariant), the serial line reader and command parser, the `profile JSON` parser and every NVS blob decoder (`rust/fuzz`; CI builds them); `proptest` round trips for the classifier (mark -> classify == CE, checksum valid, nothing else changes, every prefix safe). All parsers are safe slice code (`#![forbid(unsafe_code)]`). **Not yet**: DNS, control/map, DERP and the setup HTTP/DNS parsers (their phases) |
| 7 | **Memory made visible** | `firmware/src/alloc.rs`: a `GlobalAlloc` counting live/peak/allocs/frees/failures in total and per owner (`Owner` = Other, Tls, Noise, Map, Peer, WireGuard, Packet; per-thread scoped tag, underflows counted, not hidden), reported on the new `rust_heap` status line with the internal free, minimum and largest block. The bridge's queue (12 KB) and ring base (12 KB) are `static`s sized by `const` (with `const` assertions tied to the C's boot-heap-neutrality and drain-time arguments, `board.rs`); the elastic ring chunks are the only bridge allocation that grows, and only above `ML_HB_FLOOR`. Fragmentation: the largest free block is reported on every `status` and noted every 10 s in the `memory_pressure` records. **Honest limit**: memory allocated by C code (Wi-Fi blobs, lwIP, mbedTLS, TinyUSB) never passes through the Rust allocator |
| 8 | **Errors** | Every `esp_err_t` is a `Result` or is logged where it cannot propagate (`reset_thread_spawn_defaults`, `esp_wifi_set_ps`, radio profile); `let _ =` appears only on `fmt::Write` into the console sink (which cannot fail: `infallible()` asserts it) and nowhere on a driver call. The `clippy` job runs `-D warnings`. Failures during the Wi-Fi stage stop the stage and leave USB management up, as the C does |
| 9 | **Compatibility by test** | **Done**, see "Compatibility". Fixtures for v0.1.1 (`adapter/config`) and 0.3.0 (`tn_settings`) blobs are the 88 golden files |
| 10 | **Crypto** | Decided ("Crates"); phase 3. Constant-time compares via `subtle` |
| 11 | **Stack** | Task stacks are named constants (`board.rs`, `console.rs`): TinyUSB 4,096, `usb_txq` 3,072 (C: 1,536), `l2_wifi` 4,096, `gateway_control` 6,144 (C: 4,096), `console_tx` 3,072. The reported high-water marks are `worker_stack_free` (bridge_link), the control task's `control_stack_free_bytes` and (to add in phase 1.1) the ring worker's. **The 1 KB measured-margin rule is not yet verified: it needs the board.** No static stack analysis step exists for Xtensa: `-Zemit-stack-sizes` is LLVM-only, `cargo-call-stack` has no Xtensa support, and the C's `tools/stack-frames.py` reads GCC `.su` files. The substitute is the C's discipline: no big locals (the largest frame is the 1.5 KB `Line` buffer in the TinyUSB callback), no recursion, and a failing threshold test on the board plan |
| 12 | **Unsafe policy** | `#![forbid(unsafe_code)]` in `tdongle-aqm`, `-bridge`, `-nvs-format`, `-wifi-policy`, `-wifi-budget`, `-serial`, `-traffic`, `-pm`, `-usb-descriptors`. **Not met, and why**: `tdongle-spsc` (slot cells, `TaskContext::assume`) and `tdongle-usb-ring` (raw slab memory, `unsafe trait RingEnv`) contain `unsafe` because there is no safe way to hand disjoint regions of shared memory to two contexts; both are Miri-checked, every block has a SAFETY comment, and the unsafe is confined to `ring.rs` + `mem.rs` and `lib.rs` respectively. `firmware/` is the FFI/HAL layer: its `unsafe` is in `sys/`, `usb/`, `wifi/`, `bridge.rs`, `pm.rs`, `diag.rs`, `settings`-adjacent NVS, each commented |

## What Rust does not fix

* **The Wi-Fi blobs.** `libpp`, `libnet80211`, `libphy` are closed source and identical on both stacks. Their heap use (the dynamic RX/TX buffers pinned in the driver, the 16-buffer pools), their callbacks' IRAM requirement and their private API (`esp_wifi_internal_*`, no documented contract) are exactly the C firmware's risk. The pin budget still has to be right.
* **lwIP and mbedTLS on `std`.** The tailnet gateway's NAPT/forwarding and TLS stay the IDF's C code; their allocation behaviour, the TLS record buffer (~16 KB) and the 13.5 KB handshake peak are unchanged by Rust. Rust gives them safer call sites, not a smaller footprint.
* **TinyUSB.** A C library; the DWC2 DMA-mode behaviour, the NTB sizing and the `netd_xfer_cb` link-time wrap are the C firmware's, kept.
* **Code size is a risk, not a win.** Phase 1's app image is **1,007,744 B against the C's 1,333,360 B** (-24%), but it contains no tailnet runtime, no display, no setup access point, no HTTP, no certificate bundle: it is not comparable and **will grow** (rustls/embedded-tls, the WireGuard crate, the LCD driver and the setup HTML are all additions). Generic monomorphisation, `core::fmt` and `snow`/`curve25519-dalek` tables are the known inflators; `opt-level = "s"`, fat LTO and `panic = "abort"` are on. Re-measured at every phase gate.
* **Stack use is higher than C's**: Rust's formatting machinery and larger frames (see rule 11).
* **A Rust port has its own new risks**: `std` on ESP-IDF is a community effort ("little to no paid developer time" in the esp-idf-sys README), the toolchain is a nightly fork, and `esp-idf-sys` rebuilds all of ESP-IDF from bindgen on a version change.

## Phasing and acceptance gates

C reference numbers are ADR 0023 amendment 7 (release image, same board, same session, `iperf3` against 192.168.1.2 over the bridged interface) and amendment 6; heap numbers are ADR 0022 (`ML_HB_FLOOR` 29,884 B; the bridge sits near 100 KB free; the release bridge's measured minimum was 110 KB). **A gate is passed only by an A/B run in one session against the C image on the same board**; a number below is the C's, not a target to be tuned to.

### Phase 1: bridge mode parity (this change)

Scope: USB CDC-ACM + CDC-NCM identical to the C descriptors; the Wi-Fi STA bridge with USB backpressure, CoDel/ECN, counted drops, the Wi-Fi TX budget, the elastic ring; DFS; read-only import of the saved networks; scan/rank/join; `status` (with the bridge lines), `list`, `use`, `mode`, `help`, `capabilities`, `pm`, `reboot`, `bootloader`; the status LED, the button and the LCD are phase 2. Gate (all measured by the coordinator on the board, A/B in one session):

| Measure | C v0.3.0 (amendment 7) | Gate for the Rust image |
|---|---|---|
| TCP down (`iperf3 -R`) | 6.8-7.3 Mbit/s ("about 7") | not below 6.5 (about 7% under the C's low end) |
| TCP up | 5.7-6.0 ("about 5.8") | not below 5.4 |
| UDP up 4 Mbit/s loss | 1% | 1% or less |
| UDP down 4 Mbit/s loss | 0% | 1% or less |
| UDP up / down 8 Mbit/s loss | 26% / 3-13% | no worse than the C's range |
| load ping (TCP up) | 43 ms (27 ms on the original bridge) | not above 45 ms; idle p50 within 2 ms of the C |
| retransmits per run | 12-43 | within a factor of 2 |
| heap | minimum 110 KB, never below `ML_HB_FLOOR` | `minimum_internal` (`rust_heap` line) at least 100 KB after the three runs, **no `memory_pressure` record below 29,884 B**, no growth denial storm in `bridge_usb_ring` |
| identities | hold at rest | `Stats::check_identities` on the printed numbers after each run (script in the board plan) |
| stability | no crash across link flap and USB replug | `boot-status`-equivalent: no coredump in the `coredump` partition; stack margins at least 1 KB (rule 11) |
| image | 1,333,360 B app, DIO 40 MHz header | header DIO 40 MHz 16 MB (checked by `check_image.py`), partition table identical |

### Phase 2: setup, UI and NVS parity

The setup access point and portal (open AP, captive DNS, the HTTP page, `setup_access` rules), the button menu, the APA102 status light, the ST7735 LCD pages, display settings, factory reset, saved-network editing and **writing** NVS in the C's order (metadata first, then the list, one commit; rollback on failure), `profile`, `del`, `scan`, `boot-status`, crash evidence. Gate: ACCEPTANCE.md section 6 items 1 to 12 pass on the Rust image, including the upgrade from a v0.1.1 dongle with erase declined, setup limits (the USB host unreachable from the setup network: by construction here, by test on the board), downgrade to the C image with all networks intact, and `control_stack_free_bytes >= 1,024`. The Phase 1 throughput gate is re-run (the UI must not cost the data path).

### Phase 3: tailnet gateway

The microlink runtime in Rust: ts2021 Noise control, HTTP/2 + map parsing (streaming, bounded), DERP over TLS, WireGuard, DISCO, STUN, the router, NAPT, DNS, the heap admission. Gate: the C numbers of ADR 0015/0022 for the first membership (tailnet TCP upload about 1.6 Mbit/s: 1.63-1.65 in the C's ELF-verified A/B; download and forwarded UDP no worse than the C's recorded runs in `docs/results`), **the first membership admitted on 3 of 3 cold boots with start heap at least the C's 103,448 B**, the minimum heap under the 6 Mbit/s UDP flood never below `ML_HB_FLOOR`, interop with the real control server and a real peer (the `control_interop` and DERP tests), the full test vectors, and a 24 h soak. The N=2 and N=3 memberships are a *stretch* target only if S4 and the board say so; they are not a gate.

### Phase 4: cutover

Rust becomes the default release; the C firmware stays buildable on `main` for one release as the rollback path. Gate: phases 1 to 3 pass on two boards, the release workflow builds, signs and packages the Rust image with the same `dist/` layout and `tools/package.py` checks (SHA256, header), the site and docs name the Rust image, an in-place upgrade from the last C release and a downgrade both keep every saved setting, and one full release cycle has run without a P1/P2 finding. Only then is the C tree archived.

## Phase 1: what is built and verified (2026-10-06)

| Item | Result |
|---|---|
| `cargo test` on the pure crates (stable) | all pass; spsc loom, Miri on spsc/ring/descriptors/traffic/bridge cases pass; the SC handshake model passes with both mutations caught |
| Golden tests against the real C | 208 status scenarios, the bridge schema, texts, 88 NVS blobs, USB descriptors: all byte-equal |
| `firmware` for `xtensa-esp32s3-espidf` | builds (`rust/tools/build.sh`), 0 warnings; no flashing was done |
| `app.bin` | **1,007,744 B** (C: 1,333,360 B), 24% of the 4 MB factory partition |
| `bootloader.bin` | 20,752 B (identical size to the C's, built by the same IDF) |
| Headers | bootloader and app: `e9 06 02 40` = DIO, 40 MHz, 16 MB (`check_image.py`); merged image 16 MiB; partition table equal to `partitions.csv` |
| Static RAM | `.dram0.data` 54,672 + `.bss` 33,304 = 88 KB (C: 38,916 + 91,648 = 130 KB; the C counts its 12 KB queue and 12 KB ring base in the heap, Rust in `.bss`) |
| IRAM | `.iram0.text` 65,827 B (C: 75,627 B); tx-done callback in IRAM, calls only IRAM (checked) |

### Open risks (phase 1)

1. **Nothing has run on hardware.** Every throughput, latency, heap and stack claim is a prediction until the board plan below is run. The biggest unknown is the cost of Rust frames and `core::fmt` in the callbacks and in the 4 KB TinyUSB task (stack), then the cost of the critical sections in `tdongle-usb-ring` (identical in structure to C, but compiled by LLVM).
2. **The esp_wifi RX callback registration and the tx-done callback are private APIs** (as in C) reached through bindings generated from `esp_private/wifi.h`; a bindgen or IDF change that renames them fails the build, not the board.
3. **`tud_network_recv_cb` and `tud_network_xmit_cb` are now Rust symbols.** TinyUSB calls them from the TinyUSB task; a panic there aborts (`panic = "abort"`); the code in them is non-allocating and bounds-checked, but it is new.
4. **The Wi-Fi event task** runs `bridge::link` (USB ring flush, the host's carrier change, `rx_resume`): a Rust frame on a 3 KB stack (raised from the IDF's 2,304 B by `CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE`).
5. **`status` is serialised through the control task**; `use N` does not save the preference (read-only NVS: the reply says "(preference not saved)").
6. **Allocator accounting is per-thread-tag**: a block freed under another tag underflows that owner (counted).
7. **loom could not check the hold/resume handshake** (limit of loom); the SC enumeration is a model of the code, not the code. The SeqCst orderings are exactly those of the C, but the compiler differs.

### Board test plan for phase 1 (for the coordinator)

Build and checksum: `rust/tools/build.sh` (or the CI artifact `tdongle-rust-firmware`); flash `merged.bin` at 0x0 **or** `app.bin` at 0x20000 (keeps NVS) with `espflash write-bin`; the C image can be restored the same way. Server 192.168.1.2 `iperf3 -s`; client bound to the bridged interface (en19).

1. **Enumerate.** macOS shows "T-Dongle-S3 NCM" and a serial port; `system_profiler SPUSBDataType` VID 303a PID 4001, serial = STA MAC. Compare with the C image: same service name and order.
2. **Serial.** `status`: the first five lines parse with the Android parser (`tools/check-android-status.py` on the output); `list` and `help` equal the C's; `capabilities`; `pm` shows 80 MHz idle, 240 under load; `rust_port` and `rust_heap` are new last lines. Record `rust_heap minimum_internal`, `control_stack_free_bytes`, `bridge_link worker_stack_free`, `bridge_usb_ring` and the `memory_pressure` records at boot (the baseline).
3. **Wi-Fi.** The saved networks from the C image join (rank, hidden, `use N`); `wifi_link` fields; `roams=` with two APs.
4. **Throughput A/B.** Per the table: TCP up/down x 3 runs of `-t 30`, UDP 4M and 8M both ways, ping idle and under load. Alternate C and Rust in the same session (flash `app.bin` only). After each run read `status`: `bridge_to_host`, `bridge_to_wifi`, `bridge_ecn`, `bridge_usb_ring` (grow/shrink), `bridge_wifi_tx` (`tx_done_cb=1`, `stale`/`unmatched` about 0, `inflight` 0 at rest); verify the three identities on the printed numbers.
5. **Backpressure.** `bridge_rx_class holds`/`hold_us_*` rise only under upload saturation, `h2w_codel_*` fire after about 105 ms of continuous holds, UDP 4 Mbit/s up has no loss.
6. **Faults.** AP off/on during a transfer; USB unplug/replug during a transfer; `reboot`; `bootloader` (ROM download mode, then reflash); power cycle. No crash (no coredump), carrier follows the link, counters explain every missing frame.
7. **Stack and heap margins.** All high-water marks leave at least 1 KB; minimum heap per the gate.
8. **Revert.** Flash the C `app.bin` over it: saved networks, display and mode intact.

## Consequences

* Two firmwares live in the tree until phase 4; the C one is unchanged and its CI is untouched (`.github/workflows/build.yml`, `release.yml`); the Rust CI is `rust.yml`.
* The Rust image's behaviour is specified by the C's tests and numbers, not by Rust idiom: where Rust would naturally differ (a different CoDel, a simpler status), the C wins until an ADR amends it.
* Contributors need the Xtensa toolchain only for the `firmware/` crate; the pure crates build and test on stable Rust anywhere.
