# F2b threat model: streaming DERP data frames before the TLS tag verifies

Issue #19 (parent #22). Guardrail: `.oh/guardrails/derp-plaintext-before-tag-needs-review.md`. Date 2026-10-05.
Evidence base: firmware `c1f1e7a` (branch `overhaul/multi-tailnet`), Tailscale `9128778` (2026-10-02), ESP-IDF 5.5.5 with mbedTLS 3.6.6, live probes of all 88 DERP hostnames in `login.tailscale.com/derpmap/default`.
Author: an AI research pass. **This is input to a human crypto review, not a review.**

## Headline

**Recommendation: reject F2b as scoped. Do not write the streaming record layer.** Keep the guardrail.

Three reasons, strongest first:

1. **The benefit is close to zero on this firmware.** `CONFIG_MBEDTLS_DYNAMIC_BUFFER=y` is in effect. IDF's wrapper already sizes the receive buffer to the record header's length and frees it after each record (see `derp-tls-buffer-options.md`). Tailscale's `derper` writes through a 2 KiB `bufio.Writer`, so its records are about 2 KiB, not 16 KiB. Streaming would cut a roughly 2.4 KB transient buffer to roughly 1.6 KB (one DERP frame). It saves nothing when idle.
2. **The risk is real and new.** Today a node that cannot terminate the TLS session cannot make the firmware act on altered bytes. Under F2b, an on-path attacker with no keys can. ChaCha20-Poly1305 and AES-GCM are XOR-keystream ciphers, so bit flips pass through to the plaintext unchanged. The firmware also lets the unauthenticated sender-key field of a frame drive peer activation (`ml_wg_mgr.c:1749-1753`).
3. **It forces a custom record layer.** mbedTLS exposes no streaming receive path. F2b would mean exporting TLS 1.2 keys and re-implementing record parsing, sequence numbers, AAD and alert handling around `mbedtls_chachapoly_*` and `mbedtls_gcm_*` update calls. That is a new, unreviewed crypto-adjacent component whose payoff is under 1 KB.

A cheaper alternative gets most of the benefit with no crypto change: cap `MBEDTLS_SSL_IN_CONTENT_LEN` and refuse oversized records (see `derp-tls-buffer-options.md`, option 2).

## 1. Baseline: what the firmware does today

| Fact | Evidence |
|---|---|
| DERP TLS does **not verify the server certificate** | `ml_derp.c:771` `mbedtls_ssl_conf_authmode(..., MBEDTLS_SSL_VERIFY_NONE)`; no `ca_chain` or `esp_crt_bundle_attach` in `ml_derp.c`. The bundle is attached only for the control-plane HTTPS paths (`ml_coord.c:341`, `ml_coord.c:764`). The problem weave's "cert bundle attached" does not apply to DERP. |
| TLS 1.2 only | `CONFIG_MBEDTLS_SSL_PROTO_TLS1_3` is unset in the effective config. Kconfig makes it depend on `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` (`components/mbedtls/Kconfig:175-177`), which `sdkconfig.defaults:56` turns off. |
| Negotiated suite is `TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256` | A host mbedTLS 3.6.6 client with the device's settings negotiated it with derp1 and derp10. mbedTLS lists ChaCha-Poly first (`ssl_ciphersuites.c:51-54`). Go's server prefers ChaCha-Poly when the client lists it before AES-GCM (`handshake_server.go` `pickCipherSuite`: `cipherSuites(isAESGCMPreferred(client list))`). A Go client with AES hardware gets `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`. All 88 DERP hosts present the same chain shape, so the same suites apply everywhere. |
| Frames are read, then dispatched, only after `mbedtls_ssl_read` returns | `ml_derp.c:379-433`. The header is read first. A `RecvPacket` payload is allocated with `ml_psram_malloc(len)` for any `len <= 65536` (`:410`, `:419`). |
| Control frames that cause an action: `Ping` (writes a `Pong`), `PeerGone` (logs only) | `ml_derp.c:344-363`. Everything else (`Health`, `Restarting`, `PeerPresent`) is ignored. |
| `RecvPacket` payloads go to the WG or DISCO queue by first-byte sniffing | `ml_derp.c:301-324`, `classify_packet`. |
| The 32-byte sender key in `RecvPacket` triggers flash-directory lookup and **peer activation** before any WG authentication | `ml_wg_mgr.c:1749-1753`: `find_peer_by_key`, else `ml_directory_find` plus `directory_activate`. |

The VERIFY_NONE row matters most for the threat model. **An active attacker who can terminate TLS can already inject arbitrary DERP frames today**, including a forged sender key. F2b changes the outcome only for attackers who cannot terminate TLS. It also changes nothing for a malicious DERP operator, who can already send any frame.

## 2. TLS record structure and ciphers

| Item | TLS 1.2 (this firmware) | TLS 1.3 (not built in) |
|---|---|---|
| Header | 5 bytes: type, version, 2-byte length. The header is cleartext and is covered by the AEAD AAD. | Same 5 bytes, but the type is always `application_data (23)`. |
| Content type | In the cleartext header. | **Inside the encrypted body, after the payload** (RFC 8446 §5.2, `TLSInnerPlaintext`). A receiver cannot tell handshake, alert and data apart until the tag verifies. |
| AEAD input | Nonce from the implicit sequence number. AAD = `seq(8) \|\| type \|\| version \|\| length` (RFC 5246 §6.2.3.3, RFC 7905 §2). | AAD = the 5-byte header (RFC 8446 §5.2). |
| Tag | 16 bytes at the end of the record. | 16 bytes at the end of the record. |
| Size limits | Ciphertext at most 2^14 + 2048. | Ciphertext at most 2^14 + 256, else `record_overflow` (RFC 8446 §5.2). |
| Failure rule | "If the decryption fails, a fatal bad_record_mac alert MUST be generated" (RFC 5246 §6.2.3.3). | "MUST terminate the connection with a bad_record_mac alert" (RFC 8446 §5.2). |
| Interface | RFC 5116 §2.2: decryption "has only a single output, either a plaintext value P or a special symbol FAIL". The AEAD interface does not release plaintext on failure. | Same. |

mbedTLS itself decrypts and compares in one call. It writes plaintext into the record buffer and then zeroizes it on tag mismatch (`chachapoly.c:291-319`, `gcm.c:764-794`). The plaintext is never visible to the application, and a failed record is fatal to the session.

Sequence numbers are implicit, so reordered, duplicated or replayed records fail the tag and kill the session. That is true for both designs; only the timing of the detection differs.

## 3. DERP frame types (derp/derp.go at `9128778`)

"Inner auth" means authentication that survives if the TLS tag is ignored.

| Type | Hex | Direction | Payload | Inner auth | Firmware action today | Risk if acted on before the tag |
|---|---|---|---|---|---|---|
| ServerKey | 0x01 | S to C | magic + 32 B server key | None. The key is not pinned. | Handshake only | n/a (handshake) |
| ClientInfo | 0x02 | C to S | key + nonce + NaCl box | Box to the server key | Sent | n/a |
| ServerInfo | 0x03 | S to C | nonce + NaCl box, up to 1 MiB (`MaxInfoLen`) | Box, but the server key is unauthenticated | Handshake only | n/a |
| SendPacket | 0x04 | C to S | dest key + packet | n/a | Sent | n/a |
| ForwardPacket | 0x0a | mesh only | src key + dst key + packet | Mesh key | Never | n/a |
| **RecvPacket** | 0x05 | S to C | **32 B source key + packet** | **Packet only**: WG AEAD or DISCO NaCl box. **The 5-byte header and the source key are unauthenticated.** | Queue to WG or DISCO; source key drives peer activation | See §4 |
| KeepAlive | 0x06 | S to C | none | None | No-op | None |
| NotePreferred | 0x07 | C to S | 1 B | n/a | Sent | n/a |
| **PeerGone** | 0x08 | S to C | 32 B key + reason | **None** | Logs | A forged one makes a Tailscale client drop its route (`magicsock/derp.go:652-664`). This firmware only logs. |
| PeerPresent | 0x09 | mesh only | key + IP:port + flags | None | Ignored | Mesh only |
| WatchConns / ClosePeer | 0x10 / 0x11 | mesh only | none / 32 B key | Mesh key | Never | n/a |
| **Ping** | 0x12 | S to C | 8 B | **None** | **Writes a Pong echoing the 8 bytes** (`ml_derp.c:344-354`) | An echo oracle and a small amplifier |
| Pong | 0x13 | C to S | 8 B | n/a | Sent | n/a |
| **Health** | 0x14 | S to C | text, unbounded up to the frame limit | **None** | Ignored | A Tailscale client records it as region health (`magicsock/derp.go:649-651`) |
| **Restarting** | 0x15 | S to C | 2 x uint32 ms | **None** | Ignored | A Tailscale client would back off or reconnect. A future implementation that honours it must wait for the tag. |

Frame types with no inner authentication that reach the client are `PeerGone`, `Ping`, `Health`, `Restarting` and `KeepAlive`, plus the 5-byte header and the source key of every `RecvPacket`. The F2b design ("control frames wait for the tag") covers the first five. It does **not** by itself cover the source key, which sits inside the "data" frame.

## 4. Consequences of acting on unverified bytes

Attacker classes:

- **A1**: on path, no TLS keys, can modify, drop, truncate, duplicate and splice the TCP stream. **This is the only class where F2b changes anything.**
- **A2**: active MITM that terminates TLS. Possible today because of VERIFY_NONE. F2b changes nothing.
- **A3**: DERP operator or compromised server. Same as A2.

| Threat | Today (tag first) | Under F2b (stream data frames) | Mitigation | Residual |
|---|---|---|---|---|
| **Forgery of a data payload** | Impossible for A1. | A1 flips chosen bits of a WG packet. The WG AEAD rejects it, so no packet is forged. Cost: one decrypt attempt, plus a `pbuf_alloc` per bad packet (`wireguardif.c:582-584`). | WG authenticates the payload. | Small CPU and heap churn. |
| **Forgery of the 5-byte frame header** | Impossible. | **Feasible with known plaintext.** `KeepAlive` is `06 00 00 00 00`, so A1 can XOR it into any 5-byte header. They can set type, set length up to 65536, or turn a data frame into a control frame. | Hold every non-data frame until the tag. Cap `RecvPacket` length to the maximum the firmware can handle (about 1.6 KB). Do not allocate by declared length before the tag. | The attacker's frame is consumed until the record ends (at most about 2 KB). Then the tag fails and the session dies. |
| **Forgery of the source key** (32 B inside `RecvPacket`) | Impossible. | A1 can retarget a packet to another peer's key if they guess the true sender. `process_wg_packet` then calls `directory_activate` for that peer, which **allocates a peer slot and does a flash read before WG authenticates**. A tag failure cannot undo it. | Do not activate a peer on an unverified source key. Activate only after the WG packet authenticates, or after the tag. | Slot thrash needs real traffic to mutate. **This weakness already exists for A2 and A3 today.** |
| **Truncation** (RST or FIN at any point) | The partial record never verifies, so no bytes are released. mbedTLS reports EOF. | Partial frames were already streaming. | Deliver a frame only when it is complete. Discard partials on EOF. Treat a missing `close_notify` as an error (RFC 5246 §7.2.1). | None if the rule holds. |
| **Reordering** | TCP preserves order. Reordering needs a new TCP stream, which breaks the sequence number. | Same, but detected after the record is consumed. | None needed beyond tag check. | One record. |
| **Duplication or replay of a record** | Fails the tag (implicit sequence number). | The replay is processed once, then detected. For a replayed WG initiation: `mac1` is public-key-derived, so it passes. The cost is two Curve25519 operations and an AEAD decrypt, then the timestamp check rejects it (`wireguard.c:600-625`). | Same as above. | One per session, because tag failure kills the session. |
| **Length-field manipulation** | Impossible. | See "forgery of the header". The record length is also unauthenticated until the tag. IDF's dynamic buffer allocates `in_msglen + 333` **before** parsing, for any 16-bit length. That means up to about 64 KB on a heap that cannot supply it, so it fails with `ALLOC_FAILED`. This is **already true today** (`esp_mbedtls_dynamic_impl.c:359-455`). | Cap `IN_CONTENT_LEN`. | Bounded failure. |
| **DoS and amplification** | Needs A2 or A3. | A1 can force allocation, `Ping`-driven writes and WG handshake processing, but only by mutating real traffic and only once per session (see below). | Ping and control frames wait for the tag. | Low. |
| **WG replay and counter state** | n/a | **A forged packet cannot advance the replay window.** AEAD decrypt happens first (`wireguardif.c:584`). The window is updated only after success (`:612`, `wireguard.c:320-355`). | None needed. | None. |
| **WG handshake init, response and cookie via DERP** | Tag gates delivery. | A1 cannot originate these without keystream. A1 can replay or bit-flip. Init: `mac1` pass, DH work, AEAD, timestamp reject. Response: the receiver index and AEAD reject. Cookie reply: AEAD under a mac1-keyed key (`wireguard.c:742-760`). | WG's own checks. | CPU only. |
| **DISCO via DERP** | Tag gates delivery. | NaCl box authenticates it. Forgery fails the box. | None needed. | None. |
| **Oracle and side channels** | None. | Behavior now depends on unverified plaintext: peer-activation latency, a frame completing early or late, a `Pong` or WG reply being emitted. With XOR keystream ciphers, A1 can test whether plaintext equals a guess by flipping `guess XOR candidate` and watching for the effect. | Make nothing observable depend on unverified bytes except discard. | **Rate-limited, because tag failure ends the session**: roughly one probe per TLS session, which costs a handshake of seconds. It leaks mostly metadata (which peer sent), but TLS currently hides that from passive observers. See Moxie Marlinspike, "The Cryptographic Doom Principle" (2011). |

### What happens on tag failure

- **mbedTLS today:** returns `MBEDTLS_ERR_SSL_INVALID_MAC`, sends a fatal alert, and the context is unusable. `derp_read_exact` returns -1, `poll_derp_read` returns -1 and the firmware tears the connection down and reconnects (`ml_derp.c:379-433`). A standard fatal-alert path, which the RFCs require.
- **Under F2b**, rollback is only partial:
  - A partially assembled frame can be freed.
  - **Frames already queued to WG or DISCO cannot be recalled** (`xQueueSend`, `ml_derp.c:316`). They are handled by WG's own authentication.
  - Peer activation, `jit_used_ms` updates and any `Pong` already written **cannot be rolled back**.
  - The new record layer must itself implement "fatal alert, wipe keys, close the socket". The firmware has no code for this today because mbedTLS does it.

## 5. Precedent search

| Source | What it shows | Relevance |
|---|---|---|
| RFC 5116 §2.2; RFC 8446 §5.2; RFC 5246 §6.2.3.3 | AEAD decryption returns plaintext **or** an error, and failure is fatal. | The interface contract F2b would bypass. |
| mbedTLS 3.6.6 `chachapoly.c`, `gcm.c`; IDF `esp_ssl_tls.c` | Whole-record decrypt, tag compare, zeroize. The only streaming APIs (`mbedtls_chachapoly_update`, `mbedtls_gcm_update`) are cipher-level, not record-level. | No record-level streaming exists. |
| BearSSL (bearssl.org/api1.html) | Needs the whole record in its buffer. It supports smaller buffers (minimum 512 bytes plus 325 overhead) only when the peer cooperates, via max_fragment_length, and calls smaller buffers in heterogeneous deployments "a kind of hit-and-miss game". | The standard embedded answer is "bound the peer's record size", not "stream before the tag". |
| embedded-tls (Rust, embassy-rs) | README: handles one frame at a time and gives no guarantee that a buffer below 16 KB can parse any frame. | Same. |
| RFC 6066 (max_fragment_length), RFC 8449 (record_size_limit) | The protocol-level mechanisms for small buffers. Go `crypto/tls` implements neither, and derp1 and derp10 ignored both in a live probe (problem weave). | Not available. |
| Andreeva, Bogdanov, Luykx, Mennink, Mouha, Yasuda, "How to Securely Release Unverified Plaintext in Authenticated Encryption" (ASIACRYPT 2014, ePrint 2014/144) | Formalizes releasing unverified plaintext. Its abstract names devices without memory for the whole plaintext as the motivating case, and requires schemes with plaintext awareness. I did not check which standard AEADs meet it. | The closest academic precedent. It says this is a delicate design, not a free optimisation. |
| Hoang, Reyhanitabar, Rogaway, Vizar, "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance" (CRYPTO 2015, ePrint 2015/189) | Streaming-friendly AE needs a segmented construction (STREAM/CHAIN) designed for it. | TLS records are not that construction. |
| QUIC, RFC 9001 §5 | Each packet (about 1.2 to 1.5 KB) is a self-contained AEAD unit. Packets that cannot be unprotected are discarded (§5.5). | Reaches small buffers by using small packets, not by streaming. |
| OpenSSL `SSL_MODE_RELEASE_BUFFERS`; ESP-IDF dynamic buffers | Free the buffer when idle. | **This is the precedent we are already using.** |

I found no TLS library or protocol that releases application plaintext before the record tag verifies. Absence of a precedent is not proof that none exists. I searched only the sources above.

## 6. Cost and benefit

| Quantity | Value | Source |
|---|---|---|
| Idle receive buffer per connection today | About 24 B (cache buffer) | `esp_mbedtls_free_rx_buffer`, `esp_mbedtls_dynamic_impl.c:461-512` |
| Receive buffer while a record is in flight | Record length + 333 B + 8 B head. About 2.4 KB for a 2,064 B record. | `tx_buffer_len` (`:67-80`), `add_rx_buffer` (`:359-455`) |
| Largest app-data record `derper` writes | About 2,064 B (2,048 B plaintext + 16 B tag). Frames larger than about 4 KB would bypass the buffer and use up to 16 KB records. | `derpserver.go:3310-3314` (2 KiB `bufio.Writer` pool), `:3316-3347` (`lazyBufioWriter`), Go `crypto/tls/conn.go` `maxPayloadSizeForWrite` (record size follows each `Write`). The same 2 KiB size appears in tags v1.20, 1.40, 1.60, 1.80 and 1.90. **Not measured on the wire**: public derpers do not accept unauthenticated clients, so I could not generate data records. |
| Streaming saving per in-flight record | Record (about 2.1 KB) minus frame (at most 1.5 KB + 37 B). **About 0.5 to 0.9 KB, transient.** | derived |
| New code to review | A TLS 1.2 record layer: key export (`mbedtls_ssl_set_export_keys_cb`), sequence numbers, AAD construction, incremental AEAD, alert handling | design |

## 7. Recommendation

**Reject F2b. Keep the guardrail in force.** The value is under 1 KB of transient heap per in-flight record and nothing at idle. The cost is a new record layer and a new attack surface (A1 can make the device act on chosen bytes).

**A human crypto reviewer must sign off on any future version of this design.** This document is an AI-produced input, not a verdict. It has not been reviewed by a cryptographer. Where it says "feasible" or "impossible" for an attacker, treat it as a hypothesis for the reviewer to attack.

### Conditions that would have to hold before reopening (testable)

Reopen only if Ev measurements show a 16 KB record actually arriving (for example from a non-Tailscale DERP) **and** the cheaper cap in `derp-tls-buffer-options.md` option 2 is shown to break it. Then require:

1. A named human reviewer approves in the PR. Pass: approval comment on the implementing PR.
2. Control frames (`Ping`, `PeerGone`, `Health`, `Restarting`, `KeepAlive`, unknown types) are not acted on until the tag verifies. Test: bit-flip a `KeepAlive` into a `Ping` in a captured record and confirm no `Pong` is written.
3. `RecvPacket` length is capped at `ML_DERP_MAX_FRAME` before any allocation, and the cap is tested with a 64 KB declared length.
4. The source key does not trigger `directory_activate` or any state change until the WG packet authenticates or the tag verifies. Test: flip source-key bits and confirm no slot is activated.
5. A frame is delivered only when complete. Test: truncate mid-frame and confirm nothing is queued.
6. Tag failure closes the connection, zeroes the receive keys and leaves no frame queued from the failed record. Test: corrupt the last byte of 1,000 random records and check all three.
7. A negative-corpus fuzz run (bit flips, length fields, truncation) under ASan and UBSan with no leak or crash, and a counter for each drop reason.
8. Measured saving of at least 4 KB per connection at the transient peak, on hardware, with the dynamic buffer already enabled. If the saving is below that, reject.

### Cheap hardening that is worth doing now, independent of F2b

- Cap `RecvPacket` length in `poll_derp_read` at `ML_DERP_MAX_FRAME` (1,564 B) instead of 65,536 (`ml_derp.c:410`).
- Defer `directory_activate` on a DERP source key until the WG packet authenticates (`ml_wg_mgr.c:1749-1753`).
- Decide whether to verify the DERP server certificate (see `derp-tls-buffer-options.md`); today an active MITM is in scope.

## Open questions

- Does any DERP implementation you must interoperate with (Headscale's embedded server imports Tailscale's `derpserver`; custom forks may differ) send records above 4 KB? Needs a field histogram of record lengths. IDF's `esp_mbedtls_parse_record_header` is the place to count them.
- After `MBEDTLS_ERR_SSL_ALLOC_FAILED` at the header peek, is retrying safe? `esp_mbedtls_add_rx_buffer` points `in_hdr` at a stack buffer and leaves `in_left` at 5 (`esp_mbedtls_dynamic_impl.c:359-455`). I have not tested a retry. The firmware currently tears down on any negative return.
- Whether `mbedtls_ssl_set_export_keys_cb` is enabled in the IDF build. Not checked, since F2b is rejected.
