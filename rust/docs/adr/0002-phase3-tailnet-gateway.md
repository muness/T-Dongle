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


## RAM diet results

Branch `rust/tailnet-diet`. All sizes are bytes of **static RAM** of the runtime (`.bss` plus the joined `run` future plus the socket buffer set), measured with `rust/crates/tdongle-tailnet-runtime/size-table.sh` (**M-elf**, `-Zprint-type-sizes` of the xtensa build, one build per slot count) and `cargo test -p tdongle-tailnet-host --test memory -- --nocapture` (**M-host**, 64-bit, futures inflated). Nothing here ran on a board. The goal was a per-membership marginal of about 40 KB, `MAX_RUN=1` at about 100 KB and `MAX_RUN=3` at about 180 KB. **None of the three is met**; the numbers and the reasons are below.

### Before and after (M-elf)

| | before | after | target |
|---|---:|---:|---:|
| marginal per extra membership (`MAX_RUN` 2 -> 3) | 85,872 | **58,800** | about 40,000 |
| `MAX_RUN=1`, total | about 166,700 (lead: 166 KB) | **149,968** | about 100,000 |
| `MAX_RUN=2`, total | about 252,600 (lead: 253 KB) | **208,784** | |
| `MAX_RUN=3`, total | 338,448 (lead: 339 KB) | **267,584** | about 180,000 |

The "before" figures for `MAX_RUN` 1 and 2 are the `MAX_RUN=3` build minus two or one marginal membership (the build option did not exist); the lead's own figures agree to 1 KB. `MAX_RUN` is now a build option of the runtime (cargo features `slots-2`, `slots-1`; default 3) that scales every static, future and engine record with it; `size-table.sh` prints the table for 1, 2 and 3.

Per membership slot (one each), before -> after:

| item | before | after | how |
|---|---:|---:|---|
| control future | 4,568 | 4,624 | (+56: the lease handling) |
| DERP future | 17,600 | 13,080 | `drive` took its work future by value, so the 3 KB TLS handshake lived twice in the frame (as the argument and as the pinned local): now pinned at the call site (-2,960); the 1,600-byte relay packet buffer moved to the shared scratch (-1,560) |
| UDP future | 3,632 | 384 | no datagram buffers of its own (-3,248): the shared scratch |
| `Slot` static | 26,832 | 8,064 | the control workspace (19,928) left the slot: it is leased (-18,768; 1,160 stay as `SessionBuf`) |
| engine `Member<8>` record | 9,560 | 9,560 | not changed (see "what is left") |
| socket buffers (`GatewayBuffers::PER_MEMBER`) | 23,680 | 22,656 | control transmit window 2,048 -> 1,024 |
| **marginal** | **85,872** | **58,368** (58,800 measured, with the join overhead) | |

Once for the gateway, before -> after (`MAX_RUN=3`): the control `Bulk` 0 -> 17,744 (it was 3 x 19,928 inside the slots); the TLS record lease 16,668 (unchanged: a TLS record is 16,640); USB pump future 7,800 -> 4,712; DNS upstream future 3,184 -> 144; registry 6,320 -> 2,220 (its 4 KB JSON scratch is the shared one); the shared scratch 0 -> 4,096.

### Per lever (M-elf, `MAX_RUN=3`, each step built and measured)

| step | total | change |
|---|---:|---:|
| baseline | 338,448 | |
| 1. lease the control workspace per record / message; `drive` pins its work future at the call site | 292,160 | -46,288 (lease -37,536, `drive` -8,880) |
| 3 + 4. shared scratch for datagrams (UDP, DNS, DERP), USB frames and the registry JSON; early payload shares the JSON buffer; control transmit window 1,024 | 267,584 | -24,576 |
| 5. `MAX_RUN` as a build option | | `MAX_RUN=1` 149,968, `MAX_RUN=2` 208,784 |
| 2. share the TLS handshake state across memberships | not done | see below |

### What changed

1. **The control workspace is leased** (`tdongle_tailnet_ctl::run_session_leased`, `Bulk`, `BulkLease`, `SessionBuf`). The 17,744-byte `Bulk` (record reader, sealed-record buffer, request / response JSON, map projector) exists once. A session takes it after its TCP connect and keeps it while it negotiates (the negotiation token is held for the same time, so there is no new waiting between negotiations, but a streaming membership's next map message waits for a negotiation to finish: at most the 30 s first-map deadline, normally seconds). After its first map it holds it only from the first byte of a record until the map message that record belongs to is applied, and gives it back whenever it waits for the server with nothing in progress, which is nearly all the time. What a membership keeps is a 1,160-byte `SessionBuf` (TCP input buffer and counters). **Stall bound**: a server that goes quiet for `Timeouts::lease_stall_ms` (5 s, the C's "5 s mid-record" slicing scenario) while the session holds the lease ends *only that session* (`SessionEnd::LeaseStall`, `map_error` 2); writes after the first map are bounded by the same figure. Tests (`rust/crates/tdongle-tailnet-ctl/tests/driver.rs`): two sessions through one contended lease both join and never overlap; an idle streaming session does not hold the lease (the test fails if the release is removed: mutation-checked); a server that stops in the middle of a map message ends its own session at the stall bound and the membership waiting behind it then joins.
2. **A shared scratch buffer** (`Shared::with_scratch`, `shared::SCRATCH` = 4,096): the datagram being handled by the UDP, DNS and DERP tasks, the USB side's reply frame and host record, the registry's JSON. It is held only inside synchronous code, so no task keeps such a buffer across a wait (lock order: registry, scratch, engine, leaf queues). To make that possible without dropping anything, `UdpConn` gained `wait_readable` / `try_recv_from` / `wait_writable` / `try_send_to` (buffer-less waits plus non-blocking copy-in / copy-out; implemented for embassy-net and the host's tokio net), and `ByteQueue` gained `try_peek` / `discard_front`: a record the socket has no room for stays in the queue, in order (test: `peek_leaves_the_record_queued_until_it_is_discarded`).
3. **`MAX_RUN`** is `tdongle_tailnet_engine::GATEWAY_M`, 3 by default, 2 or 1 with the features `slots-2`, `slots-1` (runtime and engine). The default build and every test are unchanged; the tests assume 3.
4. The early payload (at most 1,024 bytes, the node-key challenge) is read into the start of the JSON buffer, which is unused before registration (-1,024 in `Bulk`), through a buffer-less `EarlyParser` (`EarlyReader` is a wrapper over it).
5. The layout guard in `sizes.rs` now holds ceilings at the new sizes.

### What is left per membership (58.8 KB), and what could not be reduced

* **Socket buffers 22.7 KB (39 %)**: control rx 4,096 + tx 1,024, DERP rx 5,760 + tx 2,048, UDP rx 6,400 + tx 3,200 + metadata 128. They are static rings; the C's lwIP windows are dynamic pbufs (about 9.3 KB for the five sockets, ADR 0013), which is most of the difference to the C's 39.4 KB. Cuts considered and **rejected, with the arithmetic**: control rx 4,096 -> 2,920: the window is the join throughput, `W / RTT` = 82 kB/s -> 58 kB/s at 50 ms, which makes a 750 KB netmap (about 500 peers) take 13 s instead of 9 s against the 30 s first-map deadline and lowers the largest netmap that joins by 29 %; DERP windows: the relay's throughput at its RTT (5,760 is the C's baseline `TCP_WND`); UDP rings: bursts of DISCO and WireGuard datagrams arrive together, and fewer slots means drops that TCP over the tunnel pays for. No host test can see any of this (loopback has no RTT), so none was cut on a guess. Only the control transmit window was cut: its writes are single requests (a few hundred bytes to about 1.5 KB) that a short buffer takes in pieces, at worst one more round trip per request, nothing on the map stream, which only the server writes. The sealed-record buffer stays at 4,096 (a server-supplied `Followup` URL, JSON-escaped, can need 2.3 KB; a smaller buffer would refuse requests that fit before).
* **DERP future 13.1 KB**: the `Link` 4.4 (frame reader 1.6, transmit ring 2.1), the TLS handshake 3.0 (the largest await state: alive only while connecting, but a future's frame is the size of its largest state), the staged frame 1.6, the TLS write record 2.0, the rest 2.0. **Sharing the handshake across memberships through the token was not done.** It is not a matter of the token: a future cannot be moved between tasks, and the connection it builds borrows the slot's socket and write buffer, so a shared handshake needs one task that owns every TLS connection (a rewrite of `derp.rs` around a connection array); it would save about 3 KB per membership beyond the first and nothing at `MAX_RUN=1`. The vendored `embedded-tls` could lease its 2 KB write record as it leases the 16 KB read record (`PATCH.md` calls it not worth it next to 16 KB; it is 2 KB per membership now); not done.
* **Engine `Member<8>` 9.6 KB**: eight resident peers at 456 bytes (hostname, 8 endpoints, 8 routes, DISCO state), the per-peer path state (248 bytes each), the DERP map (1.5 KB), STUN and netcheck state. The records are the C's own and already tight; the hostname, endpoint and route fields (about 1.7 KB per membership) are what the directory could restore, but every DISCO ping reads them, so moving them out costs a flash read on the hot path. Not done.
* **`Slot` 8.1 KB**: the two egress queues (3,072 + 2,048), `SessionBuf` 1,160, status 1,152, identity 352. The queues' capacities are the engine's burst absorption (a full queue refuses and counts); not cut without a load test.
* **Control future 4.6 KB**: Noise session, HTTP/2 session, the identity keys and the provisioning key copied into the frame, the `Followup` URL copy (388).

The fixed part is 91 KB at `MAX_RUN=1`: engine shared half 30.3 (WireGuard pool 11.5, parked-packet store 6.2, router 6.2), `Bulk` 17.7, TLS lease 16.7, host queue 8.2, shared scratch 4.1, USB future 4.7, registry 2.2, the DNS socket 4.2 and the rest. The lease does not help `MAX_RUN=1` (the workspace is there either way); the total there fell by 16.7 KB from the scratch, the future fixes and the transmit window.

**Why the targets are not reachable with this layout**: a marginal of 40 KB would need the sockets (22.7 KB) to be dynamic, as lwIP's are, or the windows cut at a throughput cost nobody has measured on a board; `MAX_RUN=1` at 100 KB would need the TLS record (16.7 KB), the control workspace (17.7 KB) and the engine's shared half (30.3 KB) to shrink by two thirds. The two mechanical levers left (the handshake in one connection task, a leased TLS write record) are worth about 3 KB and 2 KB per membership. The control `Bulk` could share the TLS lease's 16.6 KB buffer (its four byte arrays are 13.3 KB) at the price of control negotiation blocking every membership's relay reads for seconds, which the C's "a stalled member must not block the others" check forbids.

### Risks

* A server that stalls 5 s in the middle of a map message now costs a redial of its own session (before: 30 s of patience). That is the C's behaviour; a flaky Wi-Fi link that stops for 5 s mid-message restarts the session.
* While one membership negotiates (join or rejoin), the others' map messages wait for the shared control buffers, up to the 30 s first-map deadline. Relay and WireGuard traffic is not affected (the TLS record lease is separate).
* The shared scratch is a lock taken inside the UDP, DNS, DERP, USB and registry paths: a firmware raw mutex that is not reentrant and is shared with an interrupt context would deadlock the way the engine lock would. Same rule as for the engine lock.
* `UdpConn` has four new required methods: any other `Net` implementation must add them (two exist: embassy-net and the host's tokio net).

## RAM fit (branch `rust/tailnet-fit`)

The diet ended at 150 KB of statics for one membership and an image that did not link: the DRAM the Wi-Fi driver, the bridge and the stack leave is 298.9 KB (341,760 B, minus 42,856 B that the Wi-Fi blobs' IRAM code takes from the same SRAM). This section is what was done about it, what was measured, and what remains an estimate. Nothing here ran on a board.

### The idea: what only exists while something runs comes from one pool, as the C's pbufs and mbedTLS buffers do

`tdongle-tailnet-pool` is one bounded pool (`Pool`, `PoolBuf`, `Mem`). An allocation is **admitted like every elastic consumer of ADR 0022**: after taking `len` bytes the free heap must still be `ML_HB_FLOOR` (29,884 B), or, for a control negotiation, `ML_ADM_RECOVERY_BYTES` (the negotiation peak is what the floor reserves). A refusal is a counter and backpressure, never a panic: the connection backs off (`NetError::NoMem`), a TLS read or a control lease waits for memory (`alloc_wait`: woken by every refund, ticking every 100 ms), a datagram or a frame is dropped and counted. The pool has a byte cap of its own (`shared::POOL_CAP`). What moved into it:

| what | before (static) | now | where |
|---|---:|---|---|
| socket windows, TCP and UDP | 22,656 per membership + 4,096 DNS | taken at `connect` / `bind`, given back at `release` / `close`: 22,528 per membership + 3,072 DNS while the sockets exist | `net_embassy::SockMem`, implemented by `tdongle-tailnet-sockmem` (the only `unsafe` of the path: pool blocks as `&'static mut` for embassy-net, reclaimed by address from a table of what was handed out) |
| TLS record buffer | 16,640 shared, one holder at a time | one block of the record's own length per record (about 2 KB from a Go derper; 16,640 at most; a longer header is refused before any allocation), handshake records as negotiation class | `tdongle-tailnet-tls::lease`, vendored `embedded-tls` patch `lease2` |
| control workspace (`ctl::Bulk`) | 17,744 shared | taken per negotiation or map message, negotiation class | `shared::BulkSource` |
| radio receive ring, host receive frames, NAT queues | 15,172 + 3,064 + 12,000 | one block per frame, of its length, above the floor | firmware `wifi_rx` / `usb_rx`, `wifimux::Ring` |
| DERP relay write record and staging frame | 3,648 in the derp future of every slot | taken per run (waiting for memory does not hide a stop) | `derp_slot` |
| peer directory | 23,320 | one block per record and per staged update (a 10-peer tailnet holds 2.9 KB); refused at the floor | `RamDirectory`, engine `hb_ok` on stage and commit |

Admission now charges what the pool holds for a running membership (the windows) with the C's arithmetic; the runtime's own state is a heap block the firmware admits before any membership (`tailnet::start`: heap >= state + steady pool use + floor, else a counted refusal and a bridge boot).

### Statics and stack frames

* **`Shared` is built at compile time.** Every constructor under it (`Engine`, the router, the WireGuard pool, `Slot`, the counters, the directory, the NAT, the Wi-Fi mux) is `const`; the firmware keeps `Shared` as a `const` item and copies it from flash into a heap block when tailnet mode starts. A host test (`const_build`) fails if one of them stops being `const`. Before, `start` and the joined `run` future were 112 KB and 50 KB stack frames, and the bridge's own `main` poll was 37 KB (three 12 KB copies of `Bridge::new`: one `#[inline(always)]` fixed it).
* **The runtime's tasks are spawned one by one** (`tn_control`, `tn_derp`, ...), each future built in place in its task storage; the joined future (24 KB plus the 49 KB frame that built it) is gone.
* **The setup access point's tasks (DHCP, captive DNS, two HTTP servers, the stack runner, the control check; 17 KB) run as boxed futures on one small task**: every boot used to carry them.
* `rust/tools/check_stack.py` reads the built image: the **largest frame of any function is 240 B** (limit 12 KB), the deepest chain of direct calls is 3,888 B (the Wi-Fi blob, which runs on its own stack); indirect calls (the executor's poll) are not followed, so this bounds the tasks' own code, not a proof. The 40 KB minimum is the owner's rule; the measured need is far lower, and every 4 KB of it given up is 4 KB of heap.

### The DRAM budget of the image (`--features tailnet,members-1`, `rust/tools/build_tailnet.sh`)

| | bytes |
|---|---:|
| DRAM `0x3FC88000..0x3FCDB700` | 341,760 |
| IRAM overlap (`.rwdata_dummy`) | 42,856 |
| `.data` (the NAT table, the mux, the Wi-Fi blobs) | 44,028 |
| `.bss` without the heap (task storage, stack table, bridge, USB) | 85,960 |
| **stack** (what is left; the link asserts >= 40,960) | 41,936 |
| regular heap | 126,976 |
| heap in dram2 (all of it; the bridge image takes 64 KB) | 73,728 |
| heap in the data cache (`ESP_HAL_CONFIG_DATA_CACHE_SIZE=32KB`, the C's own size) | 32,768 |
| **heap in all** (the bridge image: 196,608) | 233,472 |

The heap must hold, and a `const` assert in `tailnet::budget` says so: the Wi-Fi driver and USB (60 KB: **48 KB from the bridge's board run, heap minimum 102 KB of 192 KB with the ring at its 42 KB maximum, plus 12 KB margin; an estimate**), the bridge ring's permanent slots 12,288, tailnet's own state 109,648 (`Shared` 59,088, the windows 22,528 + 3,072, the DERP relay's write record and staging frame and a TLS record or control workspace in flight 7,680, a full directory 6,912, elastic frames 10,240, the receive ring 128) and `ML_HB_FLOOR` 29,884: **213,260, headroom 20,212**. `members-2` does not fit: the assert fails at about 265,000 bytes needed against 233,472, before its 15 KB of extra statics shrink the heap further (about 47 KB short); the C's three are further away. A tailnet bigger than the directory's 24 records per membership is truncated exactly as before (the C keeps the directory in flash: the open item).

### Per crate (M-elf, one membership)

| | before | now |
|---|---:|---:|
| `tdongle-tailnet-runtime` total (the diet's definition: `Shared` + futures + socket buffers + lease + Bulk) | 149,968 | `Shared` 59,088 (a heap block; the directory is in it by value only) + futures 20,984 = **80,072** static or at start; windows, records and workspace pooled |
| marginal per membership, statics | 58.8 KB (22.7 of it sockets) | **32.7 KB** (Slot 8,112, engine member 9,560, futures 15,008) + 22,528 pooled windows; the first extra membership also needs the 12-slot pool and 24 parked-packet blocks (+5.9 KB) |
| `tdongle-tailnet-engine` | directory 23,320, pool 12 slots, 24 JIT blocks | directory by content, 8 slots and 16 blocks at one membership (the other four slots could never be used), refusal at the floor |
| `tdongle-tailnet-wifimux` | queues (4 + 4) x 1,504 | 12 B a slot, frames on demand |
| firmware tailnet statics (first link attempt: about 233,000: `Shared` 122,576, sockets 26,884, futures 24,232, NAT 19,144, ring 15,172, mux 14,160, ...) | 233,000 | **50,315** (NAT 19,136, futures 20,984, stack table 4,536, mux 2,240, the rest 3.4 KB) |

### Host measurements (`cargo test --release -p tdongle-tailnet-host --test e2e`, loopback, real Tailscale testcontrol and DERP, 13 tests)

| | before | after |
|---|---:|---:|
| TCP through the tunnel, DERP down / up (Mbit/s) | 155.1 / 7.5 | 138 to 170 / 7.5 to 7.7 (six runs) |
| direct down / up | 186.8 / 14.8 | 191 to 211 / 14.6 to 14.9 |
| join to routing (loopback; the first map is due within 30 s) | n/a | 1.07 to 1.12 s |
| soak, two tailnets | min free 92,500 | min free 80,494 (the model heap now includes the pool, high water 25.5 KB), no floor crossing |

The host's network is tokio, so the embassy-net path (windows from the pool) is covered by its own host test (`embassy_net.rs`: windows held exactly while connected, none after `release`, refusal is a counted `NoMem`), not by the e2e. The per-record TLS buffer costs a block allocation per record (16 KB zeroing at worst); the loopback numbers include it, a board's do not exist yet.

### Not done, not verified

* Nothing ran on a board. The Wi-Fi/USB figure, the 32 KB data cache, the whole of dram2 as heap, per-frame allocations in the radio callback and the throughput of a pool block per TLS record are the things the board checklist settles.
* One membership. Two would need the directory and the WireGuard pool in flash, the NAT table in chunks, and about 50 KB more than the image has.
* The NAT table (19,136 B at the C's 512 entries) is still a static.


## Download cap (branch `rust/tailnet-fit`, hypothesis, not yet measured on a board)

The host-bound path already is the bridge's: `FwUsb::send` pushes into the bridge ring and `usb_tx_task` (interrupt executor, woken by `RING_SIG`) packs up to 8 datagrams / 3,200 B per NTB; the pump drains `host_q` event-driven (no tick, no per-frame wait). So nothing in the USB send path can hold 70 frames/s, and `usb_tx_refused=0`, `backpressure_waits=4` agree. The suspect is the ingress side of the same flow: the member UDP socket held **4 datagrams** (6,400 B) and its task took **one datagram per wake**; the radio delivers A-MPDU bursts of 8, and smoltcp drops UDP that does not fit silently (no counter), which TCP inside the tunnel reads as loss. Changes: UDP receive ring 9,600 B / 8 packets, task drains up to 16 datagrams per wake (still admitted on `host_q` room), `WIFI_AND_USB` margin 12 -> 8 KB to pay for it (the heap assert had 292 B of headroom). New board line `tn_in` (IN NTBs, frames per NTB, IN wait us avg/max, IN task wakes, ring, pump wakes/moved/pass max, `udp_batch_max`): `udp_batch_max` at or above 6 before the change would confirm the overflow; `in_wait_us_avg` x NTBs near the run time would mean the host side of IN is the cap instead.

`tn force-derp on|off` (console): outbound direct data goes through DERP and every datagram the member socket receives is dropped (counted in `tn_force_derp dropped_udp`), so no disco pong is sent and the peer's direct path expires; allow about 10 s after `on` before measuring. Radio rx reserve 14 KB, regular heap 127 KB (stack 41,240 B) for heap margin.

Resolvers (`tdongle-tailnet-runtime::resolver`): the control and relay dials and SNTP resolve through `net_embassy::resolve_a` (one lookup at a time, one UDP socket): the candidate that answered last, then the DHCP servers, the DHCP gateway, then 1.1.1.1, 8.8.8.8, 9.9.9.9, two seconds each with one resend. The USB-side DNS forwarder keeps the engine's upstream until it has been silent for two seconds, then moves down the same list and sticks to the one that answers. `tn_dns` prints `resolvers[addr:answers/timeouts*]` and the forwarder's upstream. A DHCP-provided resolver that drops this client's queries (measured on the board: NextDNS from the dongle's address) costs one timeout, not the lookup.
