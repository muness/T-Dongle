# Per-membership byte recovery plan (second membership on a no-PSRAM ESP32-S3)

Branch `overhaul/p2-bytes-research`, from `origin/overhaul/p2-shared-runtime` (PR #30, `b0d9628`). Date 2026-10-05. Read-only research: no firmware file was edited and no hardware was touched.

**Method.** `idf.py -B build-bytes build` (ESP-IDF 5.5.5, `sdkconfig.defaults`) for the effective config; struct layouts from `xtensa-esp32s3-elf-gdb -batch -ex 'ptype /o ...'` on an object compiled with the firmware's own flags (`evidence/xtensa_microlink_sizeof.c`); lwIP struct sizes the same way; `nm --size-sort` on the ELF for statics; a host mbedTLS 3.6.6 handshake against live DERP servers with an allocation counter and per-phase accounting (`evidence/host_derp_verify_phases.c`). **Not measured on the board.** Host numbers are 64-bit and overstate struct-heavy allocations; big-integer (RSA) buffers are the same size on both. Everything labelled "estimate" is arithmetic over those sources.

## 0. Answer first

The bytes to recover are mostly **not** where the PR #30 prediction table puts them, and two of its constants are weaker than they look.

1. **The DERP handshake peak is dominated by one RSA-4096 signature check, not by the P-384 chain.** DERP serves a cross-signed `ISRG Root X2` whose signature is by `ISRG Root X1` (RSA). ESP-IDF's `esp_crt_verify_callback` finds X1 in the bundle, parses a 4096-bit RSA key and verifies it. Measured on the host: **9,952 B** extra peak with verification, of which **5,824 B** disappears if the callback accepts that top certificate because its subject and public key *equal a bundle entry* (prototype below, verified on `derp1` and `derp10`; all 88 DERP hostnames verify with it, every one at the same 10,184 B peak, `evidence/derp_verify_spki_88.txt`). The three P-384 verifications are not cumulative and cost about 4.1 KB of the host delta.
2. **The "9.3 KB lwIP per membership" is not sockets.** In steady state a membership holds 3 to 4 sockets (DISCO UDP, control TCP, DERP TCP, and an IPv6 STUN UDP socket once an AAAA record resolved). The IPv4 STUN socket is **never created** while the DISCO socket exists, because `ml_stun_send_probe_to` sends STUN from `disco_sock4` (`ml_stun.c:258-278`, `:313-319`). With `MEMP_MEM_MALLOC=1` each socket is a handful of small heap blocks: about **0.36 KB (UDP)** and **0.48 KB (TCP)** plus whatever is in flight, **about 1.7 to 2.0 KB for four sockets**. That leaves **about 7 KB of the 9.3 KB (and the 5.6 KB "other") unattributed**. It is the cheapest large unknown: R1 below.
3. **Tier-1 trims do not reach 15 KB with margin by themselves.** SPKI acceptance, a smaller coord stack, context slimming and the peer split sum to about 13 KB at the join. The dip at the second join goes from about -11.4 KB to about +2 KB, under every floor the firmware uses (guard floor 12,288 B, override minimum 8,192 B, the v120 panic at 7,464 B). The item that provides the margin is a **handshake arena overlaid on the 41.9 KB of static map workspace that is idle during a DERP handshake** (R6): it removes the whole transient from the heap, about 10 KB beyond R2.
4. The admission formula as written would still refuse the second membership after all of that (section 6), because it adds a 16,384 B recovery reserve and an unmeasured 5,600 B "other" on top of the physical dip. That is a policy decision, not a byte problem.

### Ranked table

"Steady" bytes recur per extra membership. "Peak" bytes are paid once, at the join, and are what makes the second membership fail today. Rank is bytes saved per unit of risk and effort. Effort: XS under a day, S a few days, M one to two weeks, XL more.

| Rank | Option | Steady / membership | Peak (one join) | Risk | Effort | Section |
|---|---|---|---|---|---|---|
| R1 | **Attribute the unexplained 7 KB + 5.6 KB** with a heap-trace diff (script included) | up to about 12 KB, unknown | | none (measurement) | XS | 2 |
| R2 | **Accept a presented cross-signed root whose subject and public key equal a bundle entry** (skips the RSA-4096 verify) | | **-5.8 KB** host (target estimate 4.5 to 5.8) | low | S | 4 |
| R3 | **Coord stack 8,704 to 6,144 B** when control is plain HTTP (high-water 4,152 B) | **-2,560 B** | | low to medium | XS | 1 |
| R4 | **Slim `microlink_t`**: home-region-only DERP map, 24 B probe records, negotiation strings off the context, drop duplicates | **about -3.0 KB** | | low | S | 1 |
| R5 | **Hot/cold `ml_peer_t` split** (P3) | **about -1.6 KB** (range 1.2 to 1.9) | | medium | M | 1 |
| R6 | **Handshake arena on the idle static map workspace** (`CUSTOM_MEM_ALLOC` scope + `gateway_lock`) | | **-10 KB beyond R2 (-16 KB alone)** | medium to high | M | 4 |
| R7 | Do not open the IPv6 STUN socket without a global IPv6 address | -0.4 KB and one socket | | low | XS | 2 |
| R8 | Lower `ML_ADM_LARGEST_BLOCK` 24,000 to about 12,000 B | 0 | 0 (removes fragmentation refusals) | low to medium | XS | 6 |
| R9 | **Coord stage 2**: negotiator task + non-blocking steady loop | **-9.0 KB** (6.5 KB once R3 is in) | | high | XL | 3 |
| R10 | Disable client session tickets | | -0.2 KB | none | XS | 4 |
| R11 | Stream `/status` per membership instead of a 1,464 B snapshot each | transient -1.46 KB x N | | low | S | 5 |
| R12 | Share one DISCO UDP socket across memberships | -0.4 KB | | **high** | L | 2 (rejected) |

### Minimal set and what it buys

Starting point (PR #30 author's numbers): 44 KB free after the first membership, second membership steady about 39.4 KB, one join peaks about 16 KB above steady, so the minimum free at the second join is **about -11.4 KB**.

| Set | Recovered at the join | Minimum free at second join | Verdict |
|---|---|---|---|
| Today | 0 | **-11.4 KB** | does not fit |
| R2 + R3 + R4 + R5 + R7 (all low risk, no allocator change) | 5.8 + 2.6 + 3.0 + 1.6 + 0.4 = **13.4 KB** | **+2.0 KB** | fits on paper, under every floor |
| **R2 + R3 + R4 + R6** (recommended minimum) | R2 and R6 together remove about 15 KB of peak, R3 + R4 add 5.6 KB: **about 20.6 KB** | **about +9 to +10 KB** | meets the 8 KB override minimum with about 1.5 KB to spare; add R5 for about 11 KB |
| above + R5 + R7 | about 22.6 KB | about +11 KB | margin for the author's stated +-3 KB uncertainty |
| above + R9 | about 29 KB | about +18 KB | only if N = 3 or more is needed |

R1 can change all of this in either direction and should run first, in parallel with R2/R3, because it needs no code.

## 1. `sizeof(microlink_t)` on xtensa, field by field

`sizeof(microlink_t)` = **10,256 B** (the brief's 9,728 B is the pre-link-state figure; ADR 0013 notes the change). 163 top-level members account for 10,189 B; the rest is alignment holes. Reproduce: `evidence/xtensa_microlink_sizeof.c`, `evidence/xtensa_microlink_s_layout.txt` (full `ptype /o`), `evidence/microlink_layout.py`.

Classes (a judgement from reading each member's users in `components/microlink/src` and `main/`):

| Class | Bytes | Meaning |
|---|---|---|
| per-membership | 7,272 | state this membership needs for its whole life |
| shareable | 1,851 | identical across memberships that use the same control server and DERP map |
| negotiation-only | 1,026 | read only while registering or logging in; could live in the negotiation token holder's scratch |
| dead in the gateway build | 40 | never assigned or read here |

Top 20 members:

| # | Bytes | Offset | Member | Class | Action | Saves |
|---|---|---|---|---|---|---|
| 1 | 3,712 | 3960 | `ml_peer_t peers[8]` (464 B each) | per-membership | **R5**: split hot/cold (below) | about 1.6 KB |
| 2 | 1,712 | 7756 | `ml_derp_region_t derp_regions[4]` (428 B each: two 196 B nodes with a 65 B cert field) | shareable | **R4**: keep only the home region; run netcheck from the staged copy in `gateway_stage` before commit | 1,284 B |
| 3 | 1,280 | 32 | `ml_disco_probe_t pending_probes[32]` (40 B each) | per-membership | **R4**: 24 B records (`peer_index` u8, `sent_ms` u32); 16 slots if the burst bound allows | 512 B (768 at 24 B x 16 slots: 896 B) |
| 4 | 816 | 3104 | `ml_derp_conn_t derp` = ssl 252 + ssl_conf 140 + link 376 + 48 | per-membership | link `hs` (64 B) is HTTP-upgrade-only: move to the `derp_xport` already on the heap during connect | about 0.1 KB |
| 5 | 384 | 1344 | `auth_url[384]` | negotiation-only | allocate on `NeedsLogin`, free after; read by `gateway_main.c:385,783` for status only | 384 B |
| 6 | 256 | 9996 | `advertise_routes[256]` | negotiation-only | used only when building the register request (`ml_coord.c:1055`); allocate `strlen+1` or none | about 250 B |
| 7 | 148 | 2704 | `ml_directory_t directory` (128 B path) | per-membership | store the id, format the path on use | 120 B |
| 8 | 132 | 2252 | `self_dns_name` | per-membership | keep (seqlock-published) | |
| 9 | 128 | 2496 | `jit_pending[8]` | per-membership | keep | |
| 10 | 96 | 9588 | `nvs_auth_key[96]` | negotiation-only | duplicates `membership_t.key[160]`; point `config.auth_key` there (`microlink.c:263`) | 96 B |
| 11 | 80 | 2164 | `microlink_config_t config` | per-membership | keep | |
| 12 | 72 | 9868 | `ctrl_host_hdr[72]` | per-membership | derive into a stack buffer per request (only `ml_coord.c:107,371,796`) | 72 B |
| 13 | 64 | 9796 | `ctrl_host_parsed[64]` | negotiation-only | derive on use | 64 B |
| 14 | 64 | 9732 | `ctrl_host[64]` | shareable | one string per distinct control server | 64 B |
| 15 | 64 | 1792 | `transport_error[64]` | per-membership | keep (status) | |
| 16 | 64 | 1728 | `last_error[64]` | per-membership | keep (status) | |
| 17 | 56 | 2081 | `stream_special[56]` | per-membership | long-poll reassembly state: keep | |
| 18 | 49 | 1892 | `h2_debug[49]` | negotiation-only | diagnostic; allocate on failure | 49 B |
| 19 | 48 | 9684 | `nvs_device_name[48]` | negotiation-only | duplicates `membership_t.hostname[48]` | 48 B |
| 20 | 48 | 2856 | `ml_wg_loop_t wgm` | per-membership | keep | |

Needed per membership and not shrinkable: the six 32 B keys (192 B), the TLS contexts (`ssl` 252 + `ssl_conf` 140, inline), queue handles, timers and counters. Removable outright (40 B): `lp_acc`, `lp_acc_len` ("never allocated in gateway mode", `microlink_internal.h`), `config_httpd` (`CONFIG_ML_ENABLE_CONFIG_HTTPD=n`), the six callback fields, `disco_sock6` (set to -1 and never created).

**R4 total (estimate):** 512 to 896 (probes) + 1,284 (regions) + about 1,050 (negotiation strings, duplicates, `directory.base`) = **2.8 to 3.2 KB**, about 3.0 KB. The strings move to heap on demand and are freed when the token is released, so the join peak grows by about 0.8 KB but steady falls. Risk is low: no protocol or data-path change; the work is allocation lifetime.

**R5 hot/cold peers.** `ml_peer_t` is 464 B. Fields only `ml_wg_mgr.c` touches (11 `uint64_t` timestamps: `jit_used_ms`, `last_ping_sent_ms`, `last_pong_recv_ms`, `trust_until_ms`, `last_send_ms`, `last_upgrade_ms`, `last_cmm_rx_ms`, `best_last_pong_ms`, `last_init_handshake_ms`, `peer_added_ms`, `last_derp_attempt_ms`) fit in `uint32_t` deltas (saves 44 B). `hostname[64]` (99 uses, mostly status/DNS) and `subnet_routes[8]` + count (65 B) are cold and the peers are already in the flash directory (ADR 0012), so they can be fetched by key on demand. `disco_shared_for[32]` duplicates `disco_key`. About 464 to 264 B per peer, **1.6 KB for eight** (range 1.2 to 1.9 KB). Risk medium: 32-bit time deltas need wrap handling; the DNS path would take a directory lookup per query.

**R3 coord stack.** `ML_TASK_COORD_STACK` is 8,704 B; the 0.2.22 baseline reported 8,136 free of 12,288, so the high-water mark (all phases since boot) was **4,152 B**. 6,144 B keeps 2.0 KB (48 %) of headroom and saves 2,560 B per membership. Do not shrink when `use_tls` is true: `esp_tls_conn_new_sync` runs on the coord task (`ml_coord.c:503,832`) and a TLS handshake needs several KB of stack that the plain-HTTP measurement never exercised. Pick the size at `xTaskCreatePinnedToCore` (`microlink.c:449`) from `ml->use_tls`. Re-verify with `stack_free_bytes` in `/status` through a join, a map update and a reconnect.

## 2. lwIP cost per membership

### Sockets that exist in steady state (code-backed)

| Socket | Created at | Closed at | Steady? |
|---|---|---|---|
| DISCO/WG UDP `disco_sock4` | `microlink.c:403` | `microlink.c:570` (destroy) | yes. Also carries IPv4 STUN. |
| IPv4 STUN `stun_sock` | `ml_stun.c:116`, only if `disco_sock4 < 0` | destroy | **no**: `ml_stun.c:258-278,313-319` send from `disco_sock4` |
| IPv6 STUN `stun_sock6` | `ml_stun.c:464` on the first `ml_stun_send_probe_ipv6` (`ml_coord.c:2420,2761`, when an AAAA address resolved) | destroy | yes once an AAAA record resolved, whether or not the board has a global IPv6 address (`CONFIG_LWIP_IPV6=y` always lets `socket()` succeed) |
| Control TCP `coord_sock` | `ml_coord.c:863` | `ml_conn_close` | yes (long poll). Plain HTTP upgrade by default (`use_tls` is false, `microlink.c:195`). |
| DERP TCP `derp.sockfd` | `ml_derp.c:336` | transport close | yes |
| Netcheck UDP | `ml_netcheck.c:78` | `ml_netcheck.c:260` | **transient**, once per DERP map activation (`ml_coord.c:1915`), inside the control negotiation |

So **three sockets with IPv6 never probed, four with**. `socket_budget.h` reserves five per membership (it counts the transient one) and `ml_admission.h:31` says "two STUN sockets": the comment is wrong, the IPv4 one does not exist.

### Heap per socket from the IDF lwIP configuration

`CONFIG_LWIP_...` (`build-bytes/config/sdkconfig.h`) with `MEMP_MEM_MALLOC 1` (`lwipopts.h:105`): the pools are not preallocated; each `netconn`, pcb, mailbox and semaphore is a separate heap block, so the `MAX_*` options are only caps. Sizes from an xtensa compile: `netconn` 52, `udp_pcb` 80, `tcp_pcb` 208, `StaticQueue_t` 84, `pbuf` 16, `tcp_seg` 20.

| Object | Calculation | Bytes |
|---|---|---|
| UDP socket | netconn 52 + `udp_pcb` 80 + recv mailbox (84 + 6 x 4) + `op_completed` semaphore 84, + about 8 B heap header per block | about **360** |
| TCP socket | netconn 52 + `tcp_pcb` 208 + recv mailbox 108 + semaphore 84 + headers | about **480** |
| TCP in flight | up to `TCP_SND_BUF` 5,760 B of unacked segments and the 5,760 B receive window of queued pbufs | traffic dependent, idle about 0 |
| `lwip_sock` slot | static array, 20 B x `LWIP_MAX_SOCKETS` 20 | 400 B once, not per membership |

Steady total for 4 sockets: 2 x 360 + 2 x 480 = **about 1.7 KB**, **2.0 KB** counting small segment and pbuf residue. Worst-case UDP backlog is the 6-deep mailbox of pbufs (about 9 KB if net_io stalls), which is a transient, not a steady cost.

### Options

| Option | Saves per extra membership | Verdict |
|---|---|---|
| **R7**: probe and open IPv6 STUN only if the STA netif has a global IPv6 address (`esp_netif_get_ip6_global`) | 360 B, one socket | do it; the `stun_has_ipv6` path already tolerates absence |
| Netcheck socket transient only | already true; ensure it runs inside the negotiation hold (it does) | no change |
| Share one DISCO socket across memberships by demultiplexing | about 360 B | **reject**. Needs demux of DISCO by sender key and WG handshake initiations by MAC1 against each membership's public key (transport packets can use the pool's globally unique receiver index). The shared endpoint changes what STUN advertises. About 360 B for a data-path rewrite. |
| Lower `CONFIG_LWIP_UDP_RECVMBOX_SIZE` 6 to 3 | transient worst case 4.5 KB per UDP socket | consider after R1; costs burst tolerance |

**The remaining question is the roughly 7 KB.** `ML_ADM_LWIP_BYTES` (9,300) is the *untagged* heap growth, labelled lwIP by assumption (`ADR 0013`: "about 9.3 KB untagged"), and `ML_ADM_OTHER_BYTES` (5,600) is `68,436` minus the itemised parts. Candidates that the allocation ledger cannot see: the FATFS `FIL` and 512 B sector buffer behind the open `FILE *stage` of `ml_directory_t`; FreeRTOS objects (event group, queues' control blocks, mutexes); the `wireguardif` netif and its timers; lwIP timers and TIME_WAIT pcbs left by DERP reconnects (`CONFIG_LWIP_TCP_MSL` 60 s keeps a 208 B pcb for 120 s per closed connection); heap block headers (about 8 B x several hundred blocks). **R1:** build the diagnostics image with `CONFIG_HEAP_TRACING_STANDALONE=y`, `CONFIG_HEAP_TRACING_STACK_DEPTH=6`, trace live blocks at N=0 and N=1 steady, and attribute the diff by caller. `evidence/heap_trace_attribute.py` aggregates a `heap_trace_dump` by symbolised caller and diffs two dumps. The ledger already reports `owners.peer/map/packet.live` at steady, which splits the 5.6 KB with no new build.

## 3. Coord stage-2 merge: savings and risk

Saving: the stack (8,704 B, or 6,144 B after R3) plus one TCB (340 B) per extra membership, so **9.0 KB, or 6.5 KB after R3**, minus about 0.3 KB because `ml_noise_state_t` (a stack local of `ml_coord_task`) must move into per-membership storage.

Why it is expensive: `ml_coord_task` (`ml_coord.c:2321`) is one 2,899-line state machine whose states **block**: `ml_getaddrinfo` (`:522,855`), a TCP connect with 5 to 10 s send/receive timeouts (`:525,871`), `esp_tls_conn_new_sync` (`:503,832`), the Noise handshake, the HTTP/2 preface, the register response (read into the shared workspace) and the map exchange. A shared loop cannot run any of these on the shared stack without stalling every other membership's control channel for up to 10 s, which is the starvation the DERP slicing check was built to rule out (`test_shared_derp_realtime.c`).

A cheaper decomposition that reuses what exists:

| Piece | How | Status |
|---|---|---|
| Negotiator: DNS, connect, Noise, register, initial map | one shared task, **blocking is acceptable because negotiations are already serialised by the token** (`ml_negotiation.c`) | new, but the code is the existing states |
| Steady control: long-poll read, 5 s PING, endpoint updates, watchdogs | serviced from the shared net_io loop with non-blocking reads | `gateway_stream.inc` already keeps incremental state (`stream_header_used`, `stream_remaining`), but reads through `noise_recv_inplace` with a socket timeout |

Risks: the long-poll watchdog (`ctrl_stream_rx_ms`) and the H2 PING cadence run on the same loop as DERP and WG slices; `microlink_stop` waits on `tasks_alive` and the detach quiesce protocol (`ml_rt_detach`) would have to learn a fourth shared task; the TLS control path (`use_tls`) needs a stack the size of the old per-membership one on the negotiator. Effort XL; do it only if R1 to R6 leave N = 3 out of reach. ADR 0013's own figure (stage 2 brings the marginal cost to about 30.4 KB, "still short during the join peak") agrees.

## 4. DERP TLS verify peak

### What the 17.3 KB is made of

Live chain from `derp1.tailscale.com` (2026-10-05, `openssl s_client -showcerts`):

| # | Subject | Key | DER B | Signed by |
|---|---|---|---|---|
| 0 | `derp1.tailscale.com` | P-256 | 919 | `YE2` (P-384, ECDSA) |
| 1 | `YE2` (Let's Encrypt) | P-384 | 656 | `Root YE` |
| 2 | `Root YE` (ISRG) | P-384 | 682 | `ISRG Root X2` |
| 3 | `ISRG Root X2`, cross-signed | P-384 | 1,140 | **`ISRG Root X1`, RSA-4096** |
| 4 | `derpkey...` meta cert | Ed25519 | 359 | self (mbedTLS skips it) |

The leaf has an 80 day lifetime (`notAfter` 2026-12-23), so pinning leaves or intermediates is not viable; intermediates also rotate (`YE1`, `YE2`).

mbedTLS parses every presented certificate into an `x509_crt` (408 B each on xtensa), then walks leaf to top. Leaf by `YE2`, `YE2` by `Root YE`, `Root YE` by the presented X2: all three verified by mbedTLS itself with already-parsed P-384 keys, one ECDSA operation at a time. The presented X2 has no parent in the chain, so its flags are `NOT_TRUSTED` and `esp_crt_verify_callback` (`esp_crt_bundle.c:216`) runs: it looks up the issuer **by name** (`ISRG Root X1`), `mbedtls_pk_parse_public_key` parses a 4096-bit RSA key and `mbedtls_pk_verify_ext` checks the cross-signature.

Host measurement (`evidence/derp_verify_phases_host.txt`, same `ml_derp_tls.c` + IDF `esp_crt_bundle.c` the firmware compiles; peak heap above the post-setup baseline, static buffers excluded):

| Variant | Extra peak vs VERIFY_NONE (6,056 B) | Largest live allocations at the peak |
|---|---|---|
| Bundle only (the firmware today) | **+9,952 B** (peak 16,008) | 2,608; 2,120; 1,064 x 2; **1,048 x 3 (RSA-4096 mpis)**; 744 x 4 (certs); 520 x 2; 512 |
| Static anchor = `YE2` / `Root YE` / X2 cross-signed (no RSA) | **+4,112 to +4,128 B** | 2,120; 744 x 4; 384 x 2; 256 x 4 |
| **R2 prototype: accept presented cert if subject and SPKI equal a bundle entry** | **+4,128 B** (peak 10,184) | same as the anchored runs |

Reading it: anchoring at any of the three P-384 certificates is equal, so the P-384 chain is a **flat 4.1 KB** (parsed chains and one ECDSA at a time), not the problem. The 5.8 KB difference is the RSA path inside the callback (`peak_inside_callbacks` = 10,696 B on the bundle-only run). On the board the author measured 17.3 KB against 9.46 KB with `VERIFY_NONE`: +7.8 KB, consistent with the host's +9.95 KB once structs shrink to 32-bit and the S3 hardware MPI (`CONFIG_MBEDTLS_HARDWARE_MPI=y`) shortens the exponentiation. Scaling the 58 % RSA share gives **about 4.5 KB on the target**; use 4.5 to 5.8 KB.

### Options for the peak

| Option | Peak saved | Verdict |
|---|---|---|
| **R2** accept by subject + SPKI match against a bundle entry | 4.5 to 5.8 KB | **do it first.** About 40 lines in `ml_derp_tls.c`'s `verify_cb`: when the flags are exactly `NOT_TRUSTED`, scan the bundle (`x509_crt_imported_bundle_bin_start`, layout `[u16 name_len][u16 key_len][subject][SPKI]`) for an entry with equal subject and equal `crt->pk_raw`; if found, clear the flags. This is the standard "a cross-signed copy of a root we already trust is that root" rule. Expiry and name checks are untouched; no match falls through to today's path. Add a negative host test (same subject, different key must fail). |
| Pin a root or intermediate as an extra `ca_chain` entry | 4.5 to 5.8 KB (same as R2) | worse than R2: needs a hard-coded anchor, breaks on rotation, does not help other CAs. Keep only as the cheap emergency version for `Root YE`. |
| Smaller `MBEDTLS_SSL_IN_CONTENT_LEN` | 0 on the peak | `DYNAMIC_BUFFER=y` already sizes each record from its header (`derp-tls-buffer-options.md` (a)); the certificate record is 3,778 + 333 B. Lowers only the largest single block (R8). |
| Free the peer chain after verify | 0 | `SSL_KEEP_PEER_CERTIFICATE=n`; the chain is parsed in place from the record buffer and dropped at wrap-up (host `after=0` in every run). |
| `MBEDTLS_X509_*` / unused curves trimming | 0 RAM | flash only |
| Client session tickets off (`mbedtls_ssl_conf_session_tickets(..., DISABLED)`), **R10** | about 0.2 KB | free, do it |
| `MBEDTLS_ECP_WINDOW_SIZE` 4 to 2 | about 1 KB (unmeasured) | not exposed as a Kconfig; slower ECDSA; skip |

### R6: overlay the handshake on the idle static workspace

Three statics are only used while a map is applied under `gateway_lock` (`gateway_workspace.inc`, `ml_coord.c:2247`, `gateway_stream.inc:21-24`): `gateway_plain` **20,496 B**, `gateway_storage` **16,384 B**, `gateway_projection` **5,012 B**, **41.9 KB** of BSS (`nm`). The DERP handshake (phase B) and the map workspace (phase A and steady long-poll updates) are separate token holds (ADR 0013), so apart from steady-state map updates of *other* memberships they are never live together.

Design: set `CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC=y` (not set today) and install `mbedtls_platform_set_calloc_free` with a dispatcher that serves from `gateway_plain` only while the **derp task is inside `mbedtls_ssl_handshake`**, and from `heap_caps` otherwise. `esp_mbedtls_dynamic_impl.c` allocates every record buffer with `mbedtls_calloc`, so the dispatcher sees them. Mechanics:

1. `xport_tls_setup` (`ml_derp.c:389`) already calls `mbedtls_ssl_setup` first; keep it outside the scope so `handshake`, `transform_negotiate` and `session_negotiate` come from the heap.
2. Before the first handshake step, `xSemaphoreTake(gateway_lock, 0)`. On failure return `ML_DERP_T_PENDING` (the same retry the `tls_deferred` path uses). Hold the lock across slices until the handshake finishes, fails or the link detaches; between slices the shared derp task serves other relays, whose TLS allocations are outside the scope and go to the heap.
3. Allocator: a bump allocator with a free list over 20,496 B; if full, return NULL (mbedTLS fails the handshake, retry on the ladder, counter in `/status`). Never fall back to the heap inside the scope.
4. At scope exit assert **zero live arena blocks**. The host runs show `after=0` (nothing allocated during the handshake survives it, relative to the post-setup baseline), which is the property this depends on; the assert turns a violation into a failed handshake instead of a use-after-reuse.

What it saves: the whole DERP transient, about 16 KB per the author's figure, 10 KB after R2 (R2 also keeps the peak inside the 20,496 B arena with room to spare; without R2 the 17.3 KB peak leaves 3 KB). With R6 the join peak becomes the control phase (4.5 KB). It also removes the TLS record buffers from the largest-block requirement.

Risks, in order: (a) a global allocator hook with a per-task scope flag, wrong scoping corrupts memory; (b) `gateway_lock` is a FreeRTOS *mutex* (`xSemaphoreCreateMutexStatic`), so the derp task must take and release it itself, including on detach and error paths (use an arena-owned flag set under the lock, or a binary semaphore, if teardown can run on another task); it is held for the handshake duration (seconds): other memberships' incremental map updates wait (`gateway_stream.inc:24` takes it with a 100 ms timeout and must treat failure as "try later"; that behaviour needs a test); (c) a persistent allocation made inside the scope would dangle after reuse, guarded by the zero-live assert. Medium to high risk, medium effort, hardware validation needed. The earlier note's scoped-arena option (`derp-tls-buffer-options.md` option 7) concluded "fragmentation control, not byte savings" because it assumed the arena is carved from the heap; **overlaying an existing static region is what makes it a byte saving**.

## 5. Per-membership buffers in `gateway_main`, router and DNS

| Item | Size | Scales with N? |
|---|---|---|
| `membership_t` (`main/gateway.h`), heap | 336 B each (holds `key[160]`, a duplicate of `nvs_auth_key`) | yes, small |
| `/status` snapshot `status_member` x N (`gateway_main.c:739`, `calloc`), per request | **1,464 B each** (login 384, dns 128, error strings, 8 peer names) | yes, transient: 2.9 KB at N=2 while a request is served |
| `router.c` `aliases[64]` | 768 B static | no, shared by id |
| `router.c` `flows[64]` + `flow_generations[64]` | 2,048 + 256 B static | no |
| `dns.c` `dns_domains`, `dns_domains_next` | 780 B each static, with an `overflow` flag | bounded, no |
| `dns_self_scratch`, `dns_table` | static | no |
| `gateway_plain`, `gateway_storage`, `gateway_projection` | 20,496 + 16,384 + 5,012 B static, one copy under `gateway_lock` | no (this is the R6 overlay target) |
| `wireguard_pool` | 12 slots of 904 B on demand | shared, not per membership |

Nothing in `main/` allocates per membership at steady state except `membership_t`. The only N-scaling cost is the `/status` snapshot (R11: build and send one membership at a time under `members_lock`, or cap the copy). The 64-entry alias table caps total peers across all memberships at 64, far above 8 x N.

## 6. Admission arithmetic with the current constants

`ml_adm_budget` with the compiled sizes (xtensa): context 10,256, coord stack 8,704, TCB 340, queues 1,896 (8 x 44 + 20 x 48 + 4 x 4 + 16 x 4 + 6 x 84) so `member_start` = **21,196**; growth = device 228 + 4 x 904 + TLS 1,336 + lwIP 9,300 + other 5,600 = **20,080**; steady **41,276**. Required for the second membership: 41,276 + 16,000 (negotiation) + 16,384 (recovery) = **73,660 B** against about 44 KB free: a **29.7 KB gap in admission terms** versus 11.4 KB physically.

After R2 + R3 + R4 + R5 + R6 + R7 (steady 41,276 - 8,000 = 33.3 KB, negotiation 16,000 to about 4,500 B) the formula still needs 33.3 + 4.5 + 16.4 = **54.2 KB**, 10 KB more than is free. Three levers, none of them bytes of code: re-measure `ML_ADM_LWIP_BYTES`/`ML_ADM_OTHER_BYTES` after R1 (they are residuals, 14.9 KB together); count the 16,384 B recovery reserve against the *minimum* free heap during the join instead of adding it to the steady need; and lower `ML_ADM_LARGEST_BLOCK` (R8). The 24,000 B gate dates from a 16.7 KB static record buffer; what is contiguous today is the 10,256 B context, the 8,704 B (or 6,144 B) coord stack and, until R6, a 4.4 KB TLS output buffer, so about 12 KB suffices. After nine iperf runs the largest block was 19,456 B (baseline doc), so the 24,000 B gate refuses a membership that has 36.9 KB free.

## 7. Validation plan

1. R1 on the board (diagnostics image): `memory`-ledger owners at N=0 and N=1 steady; heap-trace diff with `heap_trace_attribute.py`. Decide whether the 14.9 KB residual is real per-membership cost.
2. R2: host test with the fake PKI in `tests/test_derp_tls.c` plus a negative case; `host_derp_verify_phases.c` against the 88 DERP hosts (done on the host: 88 of 88 verified, peak 16,008 to 10,184 B); board `[TIMING]` TLS handshake time (it removes an RSA-4096 verify, so it should be faster).
3. R3/R4/R5: `stack_free_bytes` and `membership_context_bytes` in `/status`; N=1 and N=2 ladder (`tools/memory_ladder.py`) for the marginal cost.
4. R6: a join storm (N=2, simultaneous start) with `memory locks` for `gateway_lock` hold times; a map update on membership A during membership B's handshake.

## 8. Reproduction

All under `docs/research/evidence/`:

| File | Purpose |
|---|---|
| `xtensa_microlink_sizeof.c` | probe object; compile with the `microlink.c` command from `build-bytes/compile_commands.json` plus `-g -c`, read with `xtensa-esp32s3-elf-gdb -batch -ex 'ptype /o struct microlink_s'` |
| `xtensa_microlink_s_layout.txt`, `xtensa_microlink_nested_layout.txt` | the layouts used above |
| `microlink_layout.py` | class totals and top-N table |
| `host_derp_verify_phases.c` | per-phase heap accounting; `ANCHOR=<der>` and `SPKI=1` (R2 prototype) variants; build as in `host_derp_verify.c`'s header |
| `derp_verify_phases_host.txt`, `derp_verify_spki_88.txt` | outputs |
| `heap_trace_attribute.py` | R1 attribution of a `heap_trace_dump` |
