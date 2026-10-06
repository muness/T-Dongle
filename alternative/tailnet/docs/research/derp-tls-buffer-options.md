# DERP TLS buffer options: handshake peak, shared record buffer, lwIP window, arenas

Issues #18 (F2a + N3), #15 (arena). Parent #22. Date 2026-10-05.
Evidence base: ESP-IDF 5.5.5 (mbedTLS 3.6.6) read at `~/.cache/tdongle/esp-idf-v5.5.5`; the effective `sdkconfig` produced by `idf.py reconfigure` from `alternative/tailnet/sdkconfig.defaults` (firmware `c1f1e7a`); `sizeof` values from an Xtensa `xtensa-esp32s3-elf-gcc` compile against that config; a host mbedTLS 3.6.6 handshake against derp1 and derp10 with an allocation counter; a TLS probe of all 88 hostnames in the DERP map. Reproduction sources are in `evidence/`.

**Estimates on the 32-bit target are derived, not measured on the board.** Host numbers use 64-bit pointers and a different mbedTLS config, so they overstate struct-heavy allocations.

## Headline

**The premise behind F2a ("16 KB of record buffer per DERP connection") does not hold on this firmware's configuration, so build neither F2a nor F2b yet.** Do the cheap changes in the ranked table, then measure on the board.

1. `CONFIG_MBEDTLS_DYNAMIC_BUFFER=y` is in the effective config and IDF's wrappers are linked in. The receive buffer is **sized from each record's header and freed after the record is consumed**. Idle cost is about 24 bytes per direction, not 16 KB.
2. Tailscale's `derper` writes through a 2 KiB `bufio.Writer`, so data records are about 2,064 bytes. The in-flight buffer is about 2.4 KB, not 16.7 KB. A 16 KB record needs a single frame larger than about 4 KB, which a 1,280-byte-MTU tailnet does not produce.
3. The handshake peak is about 10 to 11 KB (estimate; range 9 to 14 KB), not 20 KB or more. This likely trips N3's own invalidation gate ("measured peak already under about 20 KB") once confirmed on the board.
4. **The DERP certificate chain is never verified** (`ml_derp.c:771`), so a "trimmed trust set" saves no RAM. The bundle is flash-resident and only touched in the control-plane TLS paths.
5. The lwIP receive window is **5,760 bytes** (`CONFIG_LWIP_TCP_WND_DEFAULT`, no window scaling). That window caps each DERP connection at about 0.7 to 1.3 Mbit/s at 36 to 64 ms RTT. It is also the bound that decides head-of-line risk: a 2 KB record fits, a 16 KB record does not.

## (a) How mbedTLS allocates record buffers in IDF 5.5.5

### Lifecycle

| Phase | In (receive) buffer | Out (transmit) buffer | Source |
|---|---|---|---|
| `mbedtls_ssl_setup` | None. `in_buf = NULL`. | Idle cache: 13 B header + 24 B (counter + IV) = 37 B, plus 8 B head | `esp_ssl_tls.c:312-328`, `esp_mbedtls_dynamic_impl.c:207-222` |
| Handshake, each server flight (`SERVER_HELLO`, `SERVER_CERTIFICATE`, `SERVER_KEY_EXCHANGE`, `SERVER_HELLO_DONE`, ticket, CCS, Finished) | Allocated per record: `in_msglen + 333` B (+8 head), freed after the step unless one record carries several messages | n/a | `esp_ssl_cli.c:20-270`, `esp_mbedtls_dynamic_impl.c:359-512` |
| Handshake, each client flight (`CLIENT_HELLO`, key exchange, CCS, Finished) | n/a | Allocated at full `MBEDTLS_SSL_OUT_BUFFER_LEN` = **4,429 B** (+8), shrunk back to the idle cache after the step | `esp_ssl_cli.c:20-270`, `esp_mbedtls_dynamic_impl.c:274-357` |
| Data phase, `mbedtls_ssl_read` | Peeks the 5-byte header via the BIO, allocates record length + 333 + 8, frees when `in_msglen == 0` | n/a | `esp_ssl_tls.c:345-397` |
| Data phase, `mbedtls_ssl_write` | n/a | **Full 4,429 B + 8 per call** (`add_tx_buffer(ssl, 0)` maps to `OUT_BUFFER_LEN`), freed when `out_left == 0` | `esp_ssl_tls.c:330-343`, `esp_mbedtls_dynamic_impl.c:67-80` |
| Idle | 24 B (16 B cache + 8 head) | 45 B | `esp_mbedtls_dynamic_impl.c:461-512` |

The wrappers are installed with `-Wl,--wrap=` for `mbedtls_ssl_read`, `_write`, `_setup`, `_free`, `_session_reset`, `_send_alert_message`, `_close_notify`, and the client/server handshake steps (`CMakeLists.txt:361-379`). I confirmed all appear in the generated `build.ninja`. The 333 B overhead is `MBEDTLS_SSL_IN_BUFFER_LEN - IN_CONTENT_LEN`, so `IN_BUFFER_LEN` is 16,717 B and `OUT_BUFFER_LEN` is 4,429 B (Xtensa compile).

### Handshake peak

Live probe (all 88 DERP hostnames): every host presents **five certificates, all ECDSA**, and negotiated `ECDHE-ECDSA` suites:

| Cert | Key | DER bytes (derp1) | Signature |
|---|---|---|---|
| Leaf (`derpN.tailscale.com`) | ECDSA P-256 | 919 | ECDSA-SHA384 |
| `YE1`/`YE2` intermediate | ECDSA P-384 | 656 | ECDSA-SHA384 |
| `Root YE` | ECDSA P-384 | 682 | ECDSA-SHA384 |
| `ISRG Root X2` (cross-signed by X1) | ECDSA P-384 | 1,140 | **RSA**-SHA256 |
| Meta cert (`derpkey<hex>`, from `ModifyTLSConfigToAddMetaCert`, `derpserver.go:851`) | **Ed25519** | 359 | Ed25519 (unknown to mbedTLS; ignored via `ssl_tls.c:7877-7885`) |

No presented certificate holds an RSA public key. RSA appears only as the signature on the cross-signed root, which matters only if verification walked to X1.

Host handshake with the device's settings (TLS 1.2 only, `KEEP_PEER_CERTIFICATE` off, `VERIFY_NONE`, mbedTLS 3.6.6), derp1 and derp10 identical:

| Item | Measured |
|---|---|
| Suite | `TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256` |
| Server flight records | ServerHello 67 B, **Certificate 3,778 B**, ServerKeyExchange 115 B, ServerHelloDone 4 B, NewSessionTicket 133 B, CCS 1 B, Finished 32 B. 4,165 bytes received in total. |
| Peak live heap, excluding the static in/out buffers | **9,280 B** (host, 64-bit) |
| Largest allocations at the peak | 2,120 (handshake params); 744 x 5 (one `x509_crt` per presented cert, 3,720 B in total); 384; 256 x 4; 216 |
| Live after the handshake, excluding static buffers | 1,415 B (host) |

On the target, struct sizes are smaller (Xtensa `sizeof`): `mbedtls_ssl_context` 252, `ssl_config` 140, `handshake_params` 592, `ssl_session` 152, `ssl_transform` 220, `x509_crt` 408, `entropy_context` 420, `ctr_drbg_context` 76. Scaling the two largest host allocations to those sizes (handshake 2,120 to 592; 5 certs 3,720 to 2,040) takes about 3.2 KB off the host peak.

| Component | Estimate on target |
|---|---|
| Structs and crypto scratch (X.509 chain, handshake params, ECDHE and ECDSA P-256 scratch, hashes) | **about 6 KB (range 5 to 9 KB)** |
| Record buffer live at the peak | 4.1 KB (Certificate record: 3,778 + 333 + 8; `parse_der_nocopy` keeps it live while the chain parses, `ssl_tls.c:7877`) or 4.4 KB (client TX) |
| **Handshake peak** | **about 10 to 11 KB (range 9 to 14 KB)** |
| Without dynamic buffers (for comparison) | add 16,717 + 4,429 = 21.1 KB |

Verification is **off**, so nothing in the table depends on trust-set size. With the bundle attached, `esp_crt_verify_callback` looks up one issuer by name in flash and parses one public key at a time (`esp_crt_bundle.c:216-260`, `:125-160`): a transient of about 1 to 2 KB plus signature work, not a function of bundle size. A **trimmed or pinned trust set saves flash, not RAM.**

### What can be freed before the first data record

| Item | Already freed by IDF or mbedTLS? | Remaining opportunity |
|---|---|---|
| Handshake params, ECDH state, transcript hashes | Yes, at handshake wrap-up (host: 9.3 KB peak falls to 1.4 KB live) | None |
| Peer certificate chain | Yes (`KEEP_PEER_CERTIFICATE` off; parsed in place from the record buffer) | None |
| CA chain, key and cert data | n/a (no CA chain set; client has no key or cert). `MBEDTLS_DYNAMIC_FREE_CA_CERT` and `_FREE_CONFIG_DATA` do nothing here. | None |
| Server session ticket (133 B record plus a retained ticket) | No. `MBEDTLS_CLIENT_SSL_SESSION_TICKETS=y` by default (`Kconfig:913-919`) and the firmware never resumes a session | Disable at runtime with `mbedtls_ssl_conf_session_tickets(conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED)`. About 0.2 KB per connection. |
| `ml->derp.entropy` (420 B) and `ctr_drbg` (76 B) per membership | No, they live in `microlink_t` (`ml_derp.c:759-766`) | Replace with `esp_fill_random` as `f_rng` (`esp_random.h`: true random while Wi-Fi is enabled), or share one seeded DRBG. **496 B per membership.** |

## (b) One shared 16 KB inbound buffer across N contexts

| Question | Answer |
|---|---|
| Does mbedTLS 3.6 provide an API to supply an external receive buffer? | **No.** The `in_buf`, `in_ctr`, `in_hdr`, `in_len`, `in_iv` and `in_msg` fields are `MBEDTLS_PRIVATE`. |
| Is swapping them feasible? | Yes, and **IDF already does it.** The dynamic layer nulls and re-points those fields on every record (`esp_mbedtls_dynamic_impl.c:118-152`), saving the counter and IV in a 16-byte cache. It also exports `esp_mbedtls_dynamic_set_rx_buf_static` (`esp_mbedtls_dynamic.h:24`), which switches one context to a full-size static buffer. So a shared slot is a variation of existing, shipped IDF code. |
| What would a shared slot add over today? | Only (1) a contiguity guarantee (no `ALLOC_FAILED` on a fragmented heap) and (2) a hard bound of one slot instead of one transient per connection. At 2.4 KB per in-flight record, (2) is worth at most about 2.4 KB x (N-1) at the instant all connections have a record in flight. |
| How would it be built? | Either patch IDF's port layer (vendoring `components/mbedtls`), or use `CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC` plus a scoped allocator (see (d)) that serves RX-buffer allocations from a slab while the calling task is inside `mbedtls_ssl_read`. |
| Hazard: slot held across slow reads | The slot is held from the header peek until the record is fully consumed. `derp_read_exact` allows 5 s (`ml_derp.c:379-397`). One stalled connection could starve the others for up to 5 s. |
| Hazard: failed allocation at the header peek | In `esp_mbedtls_add_rx_buffer` the 5 header bytes are read into a **stack** buffer (`msg_head`) before the `calloc`. On failure it returns `ALLOC_FAILED` with `in_hdr` pointing at that stack buffer and `in_left` still 5 (`esp_mbedtls_dynamic_impl.c:359-455`). A retry may parse stale stack memory. I have not tested it. Treat `ALLOC_FAILED` on read as fatal until proven otherwise. The firmware already tears down on any negative return. |

**Verdict: feasible, low value.** The dynamic layer already delivers most of what a shared slot would.

## (c) lwIP window versus a 16 KB record

Effective values from the generated `sdkconfig` and `lwipopts.h`:

| Setting | Value | Source |
|---|---|---|
| `CONFIG_LWIP_TCP_WND_DEFAULT` | **5,760** (4 x MSS) | `lwipopts.h:568`; `ESP_PER_SOC_TCP_WND 0` (`:1659`), so no per-socket window |
| `CONFIG_LWIP_TCP_SND_BUF_DEFAULT` | 5,760 | `lwipopts.h:627` |
| `CONFIG_LWIP_TCP_MSS` | 1,440 | `components/lwip/Kconfig:620-625` |
| `CONFIG_LWIP_TCP_RECVMBOX_SIZE` | 6 | |
| Window scaling | **Off** (`LWIP_WND_SCALE` unset) | |
| `LWIP_SO_RCVBUF` | Off. The firmware sets only `SO_RCVTIMEO`, `SO_SNDTIMEO` and `TCP_NODELAY` on the DERP socket (`ml_derp.c:740-741,880-889`). | |

| Record | Size | Fits in one window? | Round trips to receive |
|---|---|---|---|
| `derper` data record | about 2,064 B | Yes | 1 |
| Certificate record | 3,778 B | Yes | 1 |
| 16 KB record | 16,400 B | **No** (2.85 windows) | at least 3 |

**Head-of-line risk for F2a:** a shared slot is held at least about 3 RTT (roughly 110 to 200 ms at 36 to 64 ms RTT) for a 16 KB record. For 2 KB records it is held about one RTT or less. The risk is real only if records of 16 KB actually arrive, which `derper` does not produce.

**Side finding, throughput:** with a 5,760 B window and no scaling, a single DERP connection is capped at roughly window / RTT. That is about 160 KB/s (1.3 Mbit/s) at 36 ms and 90 KB/s (0.7 Mbit/s) at 64 ms (derived, not measured on the board). This matters for D1. Raising `LWIP_TCP_WND_DEFAULT` is a global change that costs memory under load, and the DERP path cannot be tuned on its own because `ESP_PER_SOC_TCP_WND` is 0.

## (d) Confining mbedTLS allocations by phase

| Mechanism | Status in IDF 5.5.5 | Detail |
|---|---|---|
| `mbedtls_platform_set_calloc_free` | **Not available in the current config.** `esp_config.h:130-137` defines `MBEDTLS_PLATFORM_STD_CALLOC` to `esp_mbedtls_mem_calloc` unless `CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC` is set. | Set `CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC=y` (`Kconfig:5-50`) and call `mbedtls_platform_set_calloc_free()` once at boot, before any TLS use. It is process-global. |
| Current allocator | `heap_caps_calloc(..., MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)` (`esp_mem.c:14-20`) | Every mbedTLS allocation, including IDF's dynamic buffers, goes to internal DRAM today |
| Scoping | **Not provided.** | The dispatcher must decide per call. Per-task thread-local storage works because a handshake runs entirely on the calling task. Index 0 is reserved for pthreads (`pthread_local_storage.c:23`), and `CONFIG_FREERTOS_THREAD_LOCAL_STORAGE_POINTERS` is 1, so set it to 2 and use index 1 (4 bytes per task). |
| Arena | `multi_heap_register(start, size)`, `multi_heap_malloc/free` are public (`heap/include/multi_heap.h:44,61,98`) | Register a boot-allocated block as a private heap. In `free`, tell arena pointers from heap pointers by address range. |
| What must stay **outside** the arena | Anything that lives as long as the connection: `ssl->transform`, `session`, the session ticket, the 16 B and 24 B cache buffers. mbedTLS allocates these **during** the handshake. | If they land in the arena it is pinned for the connection's lifetime. Two mitigations: call `mbedtls_ssl_setup` outside the scope (it allocates `handshake`, `transform_negotiate` and `session_negotiate` up front), and disable session tickets. Everything allocated after that is transient except `transform` and `session`, which are already allocated. I have not verified that no other persistent allocation happens inside the handshake; the host trace shows 1,415 B live afterwards, which bounds it. |
| Required arena size | About 10 to 11 KB of allocations (see (a)), plus headroom for fragmentation: **12 to 16 KB contiguous** | One arena serves one handshake at a time, so it needs N1's negotiation token. |
| Failure mode | If the arena is exhausted, return NULL. mbedTLS returns `ALLOC_FAILED`, the join fails retryably, and a counter increments. A fallback to the main heap would defeat the point. | |
| Other mbedTLS users | `esp-tls` HTTPS (control `/key` fetch when `use_tls`), wpa_supplicant crypto, and so on call the same hook | Outside a scope they fall through to `heap_caps`. The dispatcher must be reentrant and cheap. |

This gives **fragmentation control, not byte savings.** It addresses #15's "largest free block" goal for the TLS part only. It is worth doing only if measurement shows the TLS handshake is what fragments the heap.

## Ranked options

Savings are bytes of heap or contiguous block, on the target, estimated unless stated.

| # | Option | Saves | Risk | Needs hardware first? |
|---|---|---|---|---|
| 1 | **Measure first (E1.2): tag TLS allocations, confirm dynamic buffers are active, collect a histogram of record lengths and `[TIMING]` logs.** Do not build F2a or F2b before this. | 0 B; avoids building for a premise that is likely false | None | Yes, cheap |
| 2 | **Cap `CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN` to 8,192** (tighten to 6,144 once the histogram exists). It bounds any single receive allocation. | Worst-case single block from 16,725 B to 8,533 B (about **8.2 KB** less contiguous requirement; at 6,144 about 10.2 KB). Could lower the 24,000 B contiguous admission block. | A server record above the cap becomes `INVALID_RECORD` and the connection reconnect-loops. The certificate record is 3,778 B and data records are about 2 KB for Tailscale's `derper`. It is global: affects every mbedTLS user, including HTTPS control. The Kconfig help for `MBEDTLS_SSL_MAX_CONTENT_LEN` lists this failure mode (`Kconfig:53-70`). | Yes, to confirm no larger records |
| 3 | **Cap `CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN` 4,096 to 1,600.** Every `mbedtls_ssl_write` allocates the full out buffer today. | **About 2.5 KB per write and per client handshake flight** (4,437 to about 1,941 B) | Low. `derp_tls_write_all` already loops on partial writes (`ml_derp.c:189-215`); the largest DERP send is about 1.6 KB. | No |
| 4 | Serialize handshakes (N1 token) | Prevents the peaks adding: **(N-1) x about 10 to 11 KB** during a join storm | Join latency under a reconnect storm | Yes (E1.4) |
| 5 | Replace per-membership entropy + `ctr_drbg` with `esp_fill_random` | **496 B per membership** | RNG is true random only while Wi-Fi or BT is on; the gateway always has Wi-Fi up | No |
| 6 | Disable client session tickets (runtime call) | about 0.2 KB per connection; removes a pinned allocation | None found | No |
| 7 | Scoped handshake arena (CUSTOM_MEM_ALLOC + `multi_heap`) | 0 B; **12 to 16 KB contiguous** held back from fragmentation | Pinned persistent allocations, a global hook, TLS slot index 1, arena sizing | Yes |
| 8 | Shared 16 KB inbound slot (F2a) | At most about 2.4 KB x (N-1) at the in-flight peak | Head-of-line (5 s read deadline), fragile private-field patching, the `ALLOC_FAILED` hazard | Yes |
| 9 | Trimmed or pinned trust set (N3) | **0 B RAM** (flash only) | Pinning breaks custom DERPs | n/a |
| 10 | Streaming record layer (F2b) | under 1 KB transient | See `derp-streaming-record-threat-model.md` | **Rejected** |

### Consequences for the problem weave

- **N3:** the gate "measured peak already under about 20 KB" very likely holds. Confirm with the E1.2 tags, then close N3 with the number. Keep option 3 and option 5 as free wins.
- **F2a / F2b:** invalidated by the dynamic buffer plus `derper`'s 2 KiB writes unless step 1 contradicts it.
- **The "45 to 68 KB unattributed per membership":** DERP TLS steady state is about 1 to 2 KB heap plus 888 B inline (`ssl` 252 + `ssl_config` 140 + `entropy` 420 + `ctr_drbg` 76). It cannot be the main contributor.
- **Admission's 40,000 B WG/TLS allowance** looks conservative relative to a TLS transient of about 11 KB. That needs the WG half measured before it can be lowered.

### Security finding to route separately

`ml_derp.c:771` sets `MBEDTLS_SSL_VERIFY_NONE` and attaches no trust anchors. **DERP TLS is currently unauthenticated.** An active attacker can terminate it. WireGuard protects payloads end to end, but the attacker can read DERP metadata (who talks to whom), drop traffic, and inject DERP control frames and forged source keys (see the threat model). If verification is added, the cheapest correct design is the existing bundle for Tailscale-run hostnames (all 88 are under `tailscale.com` today, issued through the ISRG hierarchy), costing about 1 to 2 KB transient and about three ECDSA P-384 verifications, which I did not time on hardware.

## Open questions

- What are the real receive-buffer and handshake peaks on the board? The existing instrumentation (`/status`, `[TIMING]` logs) does not report mbedTLS allocations.
- Do any DERP servers a user may configure send records above 8 KB?
- Is the 5 s `derp_read_exact` deadline the right bound if a shared slot is ever built?
- Does `CONFIG_LWIP_TCP_WND_DEFAULT` need to rise for D1, and what does it cost with N memberships?
