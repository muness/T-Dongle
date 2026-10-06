# ADR 0021: DERP trust-anchor match (no RSA-4096 on the handshake peak) and the coord stack rule

Status: accepted for on-board validation, 2026-10-05. Implements R2 and R3 of `docs/research/membership-bytes.md`. Host numbers are measured; the DERP-handshake board number is measured (see Admission); the coord stack check is still open. Follows ADR 0013 (shared runtime, admission) and the DERP server authentication of PR #27 (`ml_derp_tls.h`).

## R2: accept a presented certificate that is a trust anchor

### What happens today

DERP serves `leaf <- YE2 <- Root YE <- ISRG Root X2`, where the `ISRG Root X2` it sends is the *cross-certificate*: X2's subject and public key, signed by `ISRG Root X1` (RSA-4096). mbedTLS verifies the first three links with the P-384 keys it has already parsed. The presented X2 has no parent in the chain and no configured anchor, so it is flagged `NOT_TRUSTED` and the ESP-IDF bundle callback runs: it finds `ISRG Root X1` in the bundle **by name**, parses a 4096-bit RSA key and verifies the cross-signature. That one verification is 5.8 KB of the 9.95 KB the handshake adds over `VERIFY_NONE` on the host (three RSA-4096 integers of 1,048 B and the work around them), and it is the join's largest transient.

### Decision

`ml_derp_tls.c` `verify_cb` asks the trust store one more question before it chains to the bundle callback (`ml_derp_trust_t.is_anchor`, implemented for the ESP-IDF bundle by `ml_derp_bundle_has_anchor`):

> is this presented certificate **itself** a trust anchor of the store: equal full subject DN (raw DER bytes) **and** equal full SubjectPublicKeyInfo (raw DER bytes) to a bundle entry?

If so, and only if mbedTLS flagged it with exactly `NOT_TRUSTED` (the weak-hash flag aside, as the bundle callback does) and it is not the leaf (depth > 0), `NOT_TRUSTED` and `BAD_MD` are cleared. Nothing else is. Everything else goes to the bundle callback exactly as before.

### Security rationale

RFC 5280 section 6.1.1(d) takes the trust anchor as an input to path validation, established out of band, as a name, a public key and an algorithm; section 6.1 starts every path at such an anchor. A trust anchor is not defined by a certificate or by the signature on one. The signature on the presented X2 only says who issued *that copy*; the key and name it carries are already trusted because the bundle contains them. The cross-signature therefore adds no trust: forging a path below it needs the X2 private key, exactly as when it was checked. mbedTLS has already verified the child's signature with the presented certificate's key, which is byte-equal to the anchor's, and has checked that certificate's CA constraints (`basicConstraints`, `keyUsage`, path length) when it used it as a parent.

What keeps this from widening trust:

| Constraint | Why |
|---|---|
| Subject DN **and** SPKI both equal, by bytes | A name alone is what an attacker copies; a key alone says nothing about who it is. A different key under the same name falls through to the bundle callback, which looks the issuer up by name and fails the signature. Byte equality is stricter than the name matching of RFC 5280 section 7.1 (no case or whitespace folding), so it can only miss a match, never invent one. |
| Flags exactly `NOT_TRUSTED` | `EXPIRED`, `FUTURE`, `BAD_KEY`, `BAD_PK`, ... stay and fail the handshake. The validity of the presented certificate is still enforced although an anchor needs no validity period (the bundle stores none and the ESP-IDF callback never checks one): stricter than the standard, and unchanged from today for an expired cross-certificate. |
| Never the leaf | The certificate that names the server must be issued by a CA. An anchor presented as the server certificate takes today's path (and fails the host name unless its SAN names the host). |
| Below the anchor, nothing changes | Signatures, validity of every intermediate and the leaf, the CA constraints of each link, the SAN-only host name check of PR #27 (`ml_derp_cert_names`, which still replaces mbedTLS's CommonName fallback), `CertName` semantics (SNI stays HostName, the chain must name CertName), and `VERIFY_REQUIRED`. |
| `sha256-raw:` pin | Its own branch of `verify_cb`; never reaches the match. Exactly one certificate, expiry and host name still enforced. |
| No store, no match | `is_anchor == NULL` (or a malformed bundle: every entry is bounds-checked, bad ones skipped) matches nothing and the old path runs. A configuration problem still fails closed (`ml_derp_tls_configure`). |

Scope: only the DERP handshake (`ml_derp.c`, `xport_tls_setup`). The control connection and the control key fetch of `https://` login servers use `esp_tls` with the ESP-IDF bundle directly and are untouched.

### Tests and measurements

`tests/test_derp_tls.c` (real mbedTLS handshakes, ASan/UBSan; the generated PKI in `tests/derp_pki.py` now has an RSA-4096 X1, an EC X2 and X2's cross-certificate):

- All 101 existing PR #27 cases pass: the 12 `CertName` parser cases, and the 89 handshake scenarios, which now run **twice**, with the match on and off, with identical expectations (178 verdicts).
- 70 new cases: the cross-signed chain verifies in both modes, and with the match **on** the client handshake peak is lower (host: 13,912 B -> 6,720 B in the test PKI, asserted at least 2,500 B lower); with only X2 in the store the match is the only way in (and without it the chain is `NOT_TRUSTED`); with only X1 in the store the match is not claimed and the RSA path still works; **same subject DN with a different key** (self-made X2, and an X2 cross-certificate signed by a key that only carries X1's name) is rejected; **same key under a different subject DN** is rejected; **expired and not-yet-valid presented anchor**, expired leaf, expired intermediate, wrong host (SAN, IP), CertName match and mismatch, an unrelated store, and the anchor's own certificate presented as the leaf are all rejected with the expected flag; `ml_derp_bundle_has_anchor` itself against one-byte changes in a stored subject or key, every truncation, and every single-bit change of the offset table and of every entry's length header (no out-of-bounds read under ASan).
- Mutation checks run once by hand (not kept): matching the subject only, clearing flags unconditionally, and allowing depth 0 each make a named test fail.

Live, `docs/research/evidence/host_derp_anchor_live.c` (the shipped `ml_derp_tls.c` and the IDF `esp_crt_bundle.c`, the full Mozilla bundle, all 88 hostnames of the current DERP map, 2026-10-05):

| | verified | handshake extra peak vs `VERIFY_NONE` | peak (host, 64-bit) | anchor matches |
|---|---|---|---|---|
| match off (before) | 88 / 88 | 9,952 B | 16,008 B | 0 |
| match on (this change) | 88 / 88 | 4,128 B | 10,184 B | 88 |

-5,824 B on the host. Measured on the board: 2,780 B (14,476 B DERP-phase owner peak against 17,256 B); the board governs.

### Admission

`ML_ADM_NEG_PEAK_BYTES` 16,000 -> **13,500**. Board measurement (coordinator, diagnostics build of PR #36 head eae4306, real join on a live tailnet): DERP-phase TLS owner peak **14,476 B**, against 17,256 B before the change, a saving of **2,780 B**. The host measured 5,824 B; the discrepancy is real and the **board's value governs** (the board's allocator, record buffers and a 4096-bit RSA that the hardware MPI handles differently are not what the host runs). The earlier board transient above steady was 15,964 B, so the new one is about 15,964 - 2,780 = 13,184 B, and the constant is 13,500 B with small headroom. Phase data at that join: free at the DERP boundary 57,440 B, minimum during the DERP phase 37,396 B, largest block 31,744 B; admission verdict ok at 110,776 B free against a budget of 95,024 B (an earlier build). The peak is charged once, whatever the number of memberships, so `required` falls by 2,500 B for the first membership and for every further one. `ML_ADM_LARGEST_BLOCK` (24,000) and `ML_ADM_TLS_BLOCK_FLOOR` (17,408) are TLS record buffers, which the match does not change. The 11,500 B first committed here was an estimate (4,500 B saving) and was too low.

## R3: the coord stack stays at 8,704 B; the research's 6,144 B is not taken

The research proposes 6,144 B for plain-HTTP control. The sizing rule of `microlink_internal.h` (at least twice the highest *measured* use, rounded to 512 B, and at least 2 KiB over the highest *analysed* path) does not allow it.

Which paths run on the coord task today (verified in `ml_coord.c`, all of them on `ml_coord_task`):

| Path | When | Stack |
|---|---|---|
| Noise handshake, register, map exchange, long poll, netcheck at DERP-map activation | every membership | measured **4,152 B** (board, 0.2.22, all phases; the deepest is the netcheck) |
| `/key` fetch over **plain HTTP**, then cJSON parse of the body | an `http://` login server; added after that capture, body written by anyone on the path | analysed |
| `/key` fetch over **TLS** (`esp_tls_conn_new_sync` in `key_tls_open`) | an `https://` or bare-host login server | analysed; not measured |
| the **control connection** itself over TLS (`do_tcp_connect`, same call) | same | analysed; not measured |
| cJSON parse of the RegisterResponse | every join | analysed |

So yes: for a custom `https://` login server a TLS handshake (including the ESP-IDF bundle callback and its RSA check, which R2 does not touch) runs on the coord task, twice per session start (key, then control). Moving it off the coord task is not a small change (the control connection is the same `esp_tls` handle for the whole session), so the stack is sized for it instead.

Numbers (`docs/research/evidence/coord_stack_paths.py`, from GCC's own frame sizes, `-fcallgraph-info=su`, along the real call chains; output in `coord_stack_paths_output.txt`): `ml_coord_task` 896 B (the key fetch and parse are inlined into it), `do_register_locked` 448 B, cJSON `parse_value` 64 B a level (xtensa, `parse_object`/`parse_array` inlined). The frame sums are calibrated against the one board measurement: the deepest measured path (DERP-map activation, netcheck 608 B) has 2,272 B of visible frames against 4,152 B measured, so 1,880 B are invisible (exception frame, newlib `printf`, internals behind function pointers) and are added to every path below, which over-counts the ones that never print at their deepest point.

| Path | Bytes |
|---|---|
| measured, board | 4,152 |
| RegisterResponse, JSON bounded to 16 levels (authenticated server) | 5,736 |
| `/key` response over plain HTTP, bounded to 4 levels | 4,520 |
| TLS key fetch / control connect (direct calls only; function pointers not followed) | 5,384 |
| (for comparison) RegisterResponse at the build's limit of 32 levels | 6,760 |

The rule: **2 x 4,152 = 8,304 B** and **5,736 + 2,048 = 7,784 B**, so at least 8,304 B, rounded to 512 B: **8,704 B**, which is the current constant for plain and TLS control alike. 6,144 B is 2,160 B below the first bound. Reaching it would need the measured high-water to fall to 3,072 B, which no change in this PR can show (no board). Static asserts in `microlink_internal.h` (`ML_COORD_STACK_MEASURED`, `ML_COORD_STACK_ANALYSED`) now state the rule, so lowering the stack requires lowering those with new evidence.

Without a bound the cJSON row would be 6,760 B and 6,760 + 2,048 = 8,808 B > 8,704 B: the build's nesting limit of 32 alone is too deep for this stack. `ml_coord.c` therefore refuses a `/key` body nested deeper than 4 levels and a RegisterResponse deeper than 16 (`json_nesting_within`, a string-aware scan that counts at least what cJSON would descend into; real documents are 1 and about 3 levels deep) before calling cJSON. Tested in `tests/test_control_key.c` (scan semantics, brackets inside strings, escapes, every depth from 1 to 40, the parser's rejection without allocation, a 1,400-level bomb through the whole fetch).

Not changed: `ML_TASK_COORD_STACK` (so no admission arithmetic change from the stack), the TLS and plain paths use the same constant. If the board's `stack_free` for the coord task, after a join, a map update and a reconnect on the current build, shows a high-water at or below 3,072 B (so, free at least 5,632 B of 8,704 B), the stack can drop to 6,144 B by editing the two measured constants and the stack together; the asserts will say if the arithmetic no longer holds.

## Merged with ADR 0020 (renumbered from 0016)

This ADR was first written as 0016, which `0016-dfs-power-management.md` took; it is 0021 now. On the ADR 0015/0019/0020 base the first-membership requirement is shared runtime 24,060 + member start 20,992 + growth 18,664 + negotiation **13,500** + recovery 16,384 + router floor 2,800 = **96,400 B** (98,900 B with the 16,000 B peak). Margin at 107,000 B boot free: **10,600 B** (was 8,100 B); at 102,000 B: 5,600 B. A second membership needs 72,340 B.

The elastic floors of ADR 0020 are defined as recovery reserve + one negotiation peak, so they follow the peak: the USB ring growth floor, the WireGuard receive queue floor while a join runs and the floor for peer slots beyond the guaranteed two are **29,884 B** (were 32,384 B). `gateway_main.c` and `test_wg_rx_budget.c` assert the 16,384 + 13,500 sum explicitly, so a change of the peak cannot go unnoticed. The board's 13,184 B transient leaves 316 B of headroom under the 13,500 B the floors and `required` assume.

Security review notes (R2): the match requires equal subject DN bytes and equal SubjectPublicKeyInfo bytes, only on a certificate above the leaf that mbedTLS flagged with exactly NOT_TRUSTED (weak hash aside); a different key under a bundle subject, a bundle key under another subject, an expired or not-yet-valid anchor, an expired intermediate or leaf, a wrong host and a bundle without the anchor are all refused in `tests/test_derp_tls.c`. Go's `crypto/x509` treats a root the same way: the pool entry is chosen by subject and key identifier and only the child's signature is checked against its key, never the root's own signature. One difference, accepted: the anchor's basicConstraints and pathLen come from the presented copy, not the bundle entry, so someone able to forge a copy still needs the anchor's private key to sign anything below it; the bundle's roots carry no name constraints.

## On-board verification (coordinator)

1. **DERP handshake peak** (done, see Admission): board 14,476 B owner peak, saving 2,780 B, transient about 13,184 B; constant 13,500 B. Re-read it on any change to the handshake (the `members` ledger, DERP phase). Also `[TIMING]` TLS handshake time: it should fall (one RSA-4096 verification fewer).
2. **Verification still happens**: a join to a node whose DERP certificate does not name it, or a bundle without X2, must still fail the handshake (`/status` DERP transport error shows the X509 flags); the DERP log line `Certificate validated` from `esp_crt_bundle` no longer appears for the cross-signed link (the match replaced it).
3. **Coord stack**: `stack_free_bytes` (diagnostics `members` and `/status`) for the coord task after a join, a map update and a reconnect on the current build, on plain HTTP and with an `https://` login server. 8,704 B total: expect at least 4,500 B free on plain; a TLS login server is the unmeasured path and should show at least 2,048 B free. Record both next to the 4,152 B in `microlink_internal.h`.
4. N=1 and N=2 memory ladder (`tools/memory_ladder.py`) for the marginal cost and the second join's minimum free heap.
