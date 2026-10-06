# ADR 0002: Phase 3, the tailnet gateway in no_std Rust (embassy), decided with measurements

Status: accepted by the owner for implementation (the port itself is not argued here, ADR 0001). **Nothing in this ADR has run on a board.** Every number is tagged:

* **M-host**: measured on the 64-bit macOS host (requested bytes from a counting allocator, `size_of`, wall time; CPU times are *relative* only, the target is an Xtensa LX7 at 240 MHz without SIMD).
* **M-elf**: measured from an xtensa-esp32s3 build (`size`, `-Zprint-type-sizes`, const-assert sizes, static stack bounds).
* **EST**: arithmetic or inference, with the error stated.
* **C**: a number the C firmware measured on the board (ADR 0013 to 0022 of `alternative/tailnet`), quoted as its authority.

The specification is the C implementation: `alternative/tailnet/components/microlink`, `alternative/tailnet/main`, its ADRs 0013 to 0022 and its tests. Every pure crate below ports the behaviour and the test cases of the C component it replaces, and adds the protocol vectors of the real implementations (Tailscale, wireguard-go, RFCs).

## What was built (crates, `rust/crates/tdongle-tailnet-*`)

| Crate | Replaces (C) | Tests |
|---|---|---|
| `types`, `crypto` | `refc/*`, `ml_x25519.c`, `nacl_box.c` | RFC 7748, 8439, 7693, XChaCha draft, NaCl box against `crypto_box` |
| `noise` | `ml_noise.c`, the EarlyNoise reader | Tailscale `controlbase` v1.104.0 byte vectors (ran Go to generate), `snow` differential, `test_control_send.c`, `test_noise_inplace.c` |
| `control` | `ml_h2.c`, `gateway_h2_close.inc`, register/map request builders, `/key`, ts2021 upgrade | `test_control_interop.c` against Go's net/http HTTP/2 server, `test_h2_handshake.c`, `test_map_request.c`, `test_control_key.c` |
| `ctl` | `ml_coord.c` control task | scripted peers over 315 chunkings; **the real Tailscale `testcontrol` server** (see Interop) |
| `map` | `gateway_project*.inc`, `gateway_stream.inc`, `ml_directory.c` rules, `ml_published_name.h` | `test_json_depth.c`, `test_semantic_*.c`, `test_projection.c`, `test_project_stream.c`, serde_json differential, real `tailcfg` fixtures |
| `derp` | `ml_derp.c`, `ml_derp_link.c`, `ml_mux.c`, `ml_derp_pace.h` | `test_shared_derp.c` (virtual-time slicing check), Go `derp` vectors |
| `tls` | `ml_derp_tls.c`, `ml_derp_cert.c` | `test_derp_tls.c`, real derp1 chains, 88 of 88 DERP hosts verified, local 16 KB-record server |
| `wg` | `wireguard.c`, `wireguardif.c` (protocol and timers), `wireguard_replay.h` | `test_wg_replay.c` (full), wireguard-go transcripts (Rust initiates and responds, PSK, cookies), `kdf_test.go`, RFC 8439 |
| `disco` | `ml_stun.c`, `ml_netcheck.c`, the DISCO half of `ml_wg_mgr.c` | Go `disco_test.go`, `stun_test.go`, Go `x/crypto/nacl/box` differential, `test_peer_policy.c`, `test_inbound_trial.c` |
| `peers` | `wireguard_pool.c`, `ml_peer_policy.h`, `ml_peer_nvs.c`, the directory | `test_wg_peer_pool*.c`, `test_peer_policy.c`, `test_peer_directory.c`, proptest against a naive model |
| `router` | `router.c`, `route_table.c` | `test_router*.c`, `test_route_*.c`, the frozen-old-vs-new differential against an independent naive reference |
| `dns` | `dns.c` | `test_dns.c` |
| `usbnet` | lwIP on the USB netif: ARP, `dhcps`, NAPT (ESP-IDF 5.5.5 sources) | derived from the IDF sources; independent checksum oracle |
| `admission` | `ml_admission.h`, `ml_heap_budget.h`, `ml_negotiation.c`, the budgets | `test_admission.c`, `test_heap_budget.c`, `test_negotiation.c` and a golden replay against the real `ml_negotiation.c`; status text byte-identical to the compiled C over 88 scenarios |
| `members`, `status` | `gateway_main.c` members and `/status`, the serial reports | golden from the compiled C (2,690 + 319 member cases, 90 `/status` scenarios, 101 diagnostic reports), Android `DongleStatus.parse` |
| `engine` | `microlink.c`, `ml_wg_mgr.c`, `ml_runtime.c`, the netmap glue | two simulated dongles through a DERP relay and a NAT (DERP, direct, fall back), 3 memberships on one pool, flood and heap-floor tests, chaos proptest |
| `fw` | (new) | the seam to the firmware image |

Every parser has a proptest and a deterministic mini-fuzz in `cargo test` and a libfuzzer target (`rust/fuzz`); all are `#![forbid(unsafe_code)]`.

(The decisions below, the interop results and the per-membership RAM table follow.)
