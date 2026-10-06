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

## Decisions

1. **One engine, sans-IO; one set of async tasks for every membership.** The C's thread per control task, shared net/DERP/wg tasks and stacks become one joined embassy future (`tdongle-tailnet-runtime`). Stacks are gone, so per-membership RAM is buffers, futures and records, not stacks.
2. **No heap in the runtime.** Everything is a static or part of the one joined future; admission compares the C's dynamic requirement (16,384 + 13,500 + 2,800 B) with the free heap the image still has, and `charge_static_bytes` exists for the conservative reading.
3. **One shared 16,640 B TLS record lease** for all DERP connections, serialised by the negotiation token (phase B), as the C's single 17,408 B block floor.
4. **The seam is `tdongle-tailnet-fw`**: `Platform`, `Storage`, `UsbFrames` in; `TailnetApi` out (`Shared` implements it). The image carries bytes only.
5. **Backpressure, not loss** (ADR 0023 of the Rust port): the runtime stops reading sockets and the host's USB endpoint rather than dropping what it accepted.
6. **Divergences from the C** are listed in the runtime crate docs (no STUN probe before the first negotiation, split stop, IPv4 only, one workspace per slot until the diet lands).

## Interop (M-host, real Tailscale code)

`rust/tools/tailnet-interop` is a Go program built on Tailscale's own `testcontrol` (control, ts2021 Noise over HTTP/2 on :80), `derpserver` behind a self-signed TLS listener (the DERP node advertised with a `sha256-raw` pin), a `stun` responder and optional `tsnet` nodes. The Rust gateway (runtime + engine over a tokio `Net`, a fake USB host and a fake Wi-Fi) runs against it:

* `interop_ts2021`: `/key`, ts2021 upgrade, register (with and without auth key), streaming map, endpoint update, keepalive, server-dropped stream, wrong control key (clean Noise failure).
* `e2e` (12 tests, ~170 s in one run): DERP-only end to end (DHCP, DNS alias, MagicDNS, TCP echo through WireGuard to a real tsnet peer), direct path discovery and move, throughput over DERP and direct, two memberships on two control servers, PeersChanged/Removed deltas, member actions under traffic without leaks, Wi-Fi bounce, control restart, STUN endpoint report, direct to DERP fallback after the 60 s trust lapses, admission refusals, passthrough without a membership, and a soak (100 s default, `TAILNET_SOAK_SECS=600` for ten minutes; the 600 s run held the model heap floor, flat queue high-water marks and flat RSS, with 10 of 717 transactions failed (1.4 %; the test tolerates 3 % because the direct path is cut for 10 s every 90 s)).

## RAM

Static RAM of the runtime, xtensa build (M-elf from `-Zprint-type-sizes`, `size-table.sh`; M-host where marked). **Before the diet:**

| Item | Bytes |
|---|---|
| control + DERP + UDP futures, per membership | 4,568 + 17,600 + 3,632 |
| `Slot` static (ctl `Workspace` 19,928, UDP queue, DERP queue, status 1,152, identity 352) | 26,832 |
| engine `Member<8>` record (M-host) | 9,752 |
| embassy socket buffers (`GatewayBuffers::PER_MEMBER`) | 23,744 |
| **per membership** | **about 86,100** |
| fixed: `Shared` without slots/engine members, joined fixed futures, DNS socket buffers | about 80,300 |
| TLS record lease (shared, inside `Shared`) | 16,668 |
| **N = 1 / 2 / 3** | **166 KB / 253 KB / 339 KB** |

The C measured on the board (ADR 0013): first membership 62.9 KB, each further 39.4 KB, about 107 KB free after boot, and N = 2 did not fit. The first Rust cut is therefore over the C by 2.2x per membership and cannot share DRAM with the bridge image's 182 KB `.bss` and 192 KB heap. This is a measured defect of the first cut, not a design limit: the `ctl` workspace (one per slot for a long poll that never ends), the DERP future (TLS handshake staging per slot although the token already serialises phase B), the TCP windows and the engine's resident per-peer state are all poolable. The diet results follow; N = 2 and N = 3 projections are computed from them against the heap floor (29,884 B).

Projection rule (EST until measured on the board): free DRAM after the image's own `.bss` and Wi-Fi heap use `F` must satisfy `static(N) + heap floor 29,884 + Wi-Fi/USB heap <= F`; `static(N) = fixed + N * per_membership`.

(RAM diet results, board measurements and the final N = 2 / N = 3 table are appended below as they are measured.)

