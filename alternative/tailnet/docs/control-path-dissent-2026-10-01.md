# Control-path dissent and solution space — 2026-10-01

The earlier conclusion that another phone capture was the only useful next step was too passive. Source comparison and host reproductions identify actionable defects now: the current proactive Noise reader discards partial records; the old SETTINGS-ACK sequence produces a Go HTTP/2 protocol error; and the gateway's socket budget has no management headroom with two fully active identities. The semantic map parser also rejects a ninth peer update in a section. None of these findings alone establishes the cause of every Android screenshot.

Research baseline: firmware commit `20c0115`; MicroLink reference commit `7de6a93684a34991fdfa1eeb9281e08523646ef7`; Rust reference commit `dbd49fe4018023ba07596e4377496718ef21d6ae`. No production firmware or APK behavior changed during this investigation. Reproductions are in [control-path-replays](control-path-replays/).

## Evidence

| Finding | Status | Evidence | Consequence |
|---|---|---|---|
| The old map failure happened before map JSON parsing. | Verified for the saved v0.2.5 attempts | Saved diagnostics report `map_bytes=0`, `map_declared_bytes=0`, `map_error=10`, `map_frame_type=7`, `map_stream_id=0`, `noise_error=0`, `noise_frame_bytes=33`. | Investigate connection protocol handling before changing the map parser or buffer sizes for these attempts. The error code was not saved, so GOAWAY alone does not prove the exact server reason. |
| The old firmware could acknowledge one SETTINGS twice. | Verified code defect; strong causal candidate for the old capture | `10e448c^` emits an unconditional ACK in `do_h2_preface`, while `gateway_read_registration` also ACKs received SETTINGS. A local Go 1.23.5 HTTP/2 server replay returns `GOAWAY(PROTOCOL_ERROR)`, code 1, with 17 plaintext bytes; the same frame occupies 33 ciphertext bytes including its Noise tag. One ACK permits both registration and map responses. [Go's handler](https://github.com/golang/net/blob/master/http2/server.go) rejects an ACK when its count of unacknowledged SETTINGS becomes negative. | The existing `10e448c` fix is well motivated. This replay validates the defect and its failure signature, not Tailscale SaaS causality or timing on the dongle. The failing replay can terminate before registration completes, depending on scheduling. |
| The current handshake reader loses bytes when a TCP read ends inside a proactive Noise record. | Verified by source and targeted reproduction | `do_noise_handshake` stores bytes returned by one read. `process_proactive_frames` stops at an incomplete record, then frees the entire input. The reproduction gives it complete EarlyNoise plus eight bytes of the following SETTINGS transport record: all eight consumed bytes disappear, while the next socket byte is 0 rather than the required record type 4. Splitting the challenge record also discards its consumed prefix and leaves no challenge. | Read and preserve the byte stream by declared record lengths. Do not infer record completeness from socket-read boundaries. Increasing sleep time or a raw buffer does not fix this. |
| Other implementations provide a better framing model. | Verified code comparison | The [Rust ESP32 client](https://github.com/0xdilo/tailscale-esp32/blob/dbd49fe4018023ba07596e4377496718ef21d6ae/src/client.rs) reads exactly the EarlyNoise header and declared payload while retaining pending plaintext. The [official Tailscale Noise connection](https://github.com/tailscale/tailscale/blob/main/control/controlbase/conn.go) retains partial transport messages and reads until their declared length is available. | Borrow the bounded framing behavior without replacing the whole routing stack. Our current complete-record handshake tests do not exercise partial ciphertext records. |
| The gateway can consume every socket with two active memberships. | Verified configured resource mismatch; runtime attribution unresolved | The generated configuration has `CONFIG_LWIP_MAX_SOCKETS=10`. [ESP-IDF v5.5.5's HTTP server](https://github.com/espressif/esp-idf/blob/v5.5.5/components/esp_http_server/src/httpd_main.c) opens three internal sockets. `dns.c` holds one. Each membership normally holds DISCO UDP, control TCP and DERP TCP. Thus the baseline is `4 + 3*n`: seven with one, ten with two, before HTTP clients or a forwarded DNS query. HTTP permits seven client sockets without reserving capacity for these other services. | Resource admission must account for descriptors as well as RAM, and reserve management/recovery capacity. Two connected memberships have no room for even one new management client under this configuration. One or zero memberships can also exhaust descriptors if enough HTTP clients remain open. Actual socket occupancy at the captured Android failures was not saved. |
| Streaming maps still have an eight-entry peer-section limit. | Verified source and targeted parser test | `gateway_stage_record` rejects a peer section once its count exceeds `ML_MAX_PEERS=8`. The semantic test explicitly rejects nine entries. That test passes after adding the two newly required H2 fields to a temporary copy of its stub. | A ninth visible peer/update can prevent map admission independently of raw map size. Separate a bounded active WireGuard working set from the policy for accepting/discovering a larger tailnet; preserve explicit capacity errors until that design is implemented. It cannot explain the old zero-map-byte GOAWAY. |
| No PSRAM makes any Tailscale connection impossible. | Incorrect as a blanket claim | [MicroLink's reference README](https://github.com/Csontikka/microlink/blob/7de6a93684a34991fdfa1eeb9281e08523646ef7/README.md) documents smaller buffers and eight peers for boards without PSRAM. Our allocator falls back to internal RAM and our parser uses bounded semantic projection. | Memory remains a real resource constraint, but PSRAM is not the only productive explanation. The reference's hardware claims are project reports, not our board qualification. |
| The latest saved v0.2.6 attempt proves a running membership exhausted memory. | Unsupported; the saved fields point elsewhere | Four readable samples show about 153 KiB free memory and a 110592-byte largest block. They contain no live-client diagnostics and startup heap counters remain zero. At offsets 0, 2.12 and 4.14 seconds the member is enabled; at 6.17 seconds it is disabled. Socket failures begin at 8.19 seconds. | This sequence never records a started membership. It neither reproduces a new map failure nor proves the socket-budget hypothesis caused this particular management failure. Keep its diagnosis separate; record startup eligibility/attempts and socket operations as well as map events. |

The proactive-reader reproduction extracts the current production function but mocks decryption to isolate buffering; it does not test cryptography or a real SaaS login. The Go replay uses real local TLS and HTTP/2 with the equivalent preface/ACK sequence; it does not emulate the complete Tailscale server. No hardware or physical flashing occurred.

The unmodified host suite currently does not compile: `test_status_stream.c` and `test_semantic_map.c` omit `map_h2_error` and `map_h2_last_stream` from their `microlink_t` stubs. Checks earlier in the runner pass, but the suite cannot be reported as passing. The targeted semantic run only repaired that temporary stub; repository tests remain unchanged. The new partial-record reproduction also demonstrates a coverage gap that the existing complete-record handshake test misses.

## Dissent

### Dissent report

**Decision under review:** Treat lack of a new physical capture as a reason to defer causal investigation and ask the user to repeat installation/reproduction.

**Stakes:** Repeated reflash/retry loops cost user effort, while configuration and stream-handling defects remain model-checkable.

**Confidence before dissent:** Medium that more runtime detail would help; low that another capture was the only useful next action.

### Steel-man position

The screenshots mix management HTTP failures, map failures and routing status. A saved USB lease does not prove HTTP reachability, a peer list does not prove usable traffic, and no-PSRAM hardware differs from the reference router's PSRAM boards. Preserving observations after disconnect is necessary to avoid inventing one root cause for all of them.

### Contrary evidence

1. The old decrypted GOAWAY with zero map bytes localizes that attempt before JSON parsing. The duplicate-ACK replay provides a specific protocol mechanism with the same frame size.
2. The current reader demonstrably loses a partial ciphertext record. The official client and Rust ESP implementation retain stream state across reads.
3. Descriptor arithmetic demonstrates an independent multi-membership resource failure without requiring another board test. RAM-only admission cannot guarantee setup remains reachable.
4. The current latest capture has no started membership and ample pre-start memory. It contradicts a confident attribution of every failure to map memory.

### Pre-mortem scenarios

1. **Functional failure:** Additional logs and larger buffers leave partial-record loss and descriptor starvation intact; retries remain sensitive to packet timing and concurrent HTTP requests.
2. **Adoption failure:** Each investigation requires the user to install, flash, authorize, fail, unplug and retrieve diagnostics. They stop testing before the feature becomes reliable.
3. **Opportunity cost:** Time goes into generic error copy and broad captures while a small deterministic interoperability harness would expose the actual protocol defect. Extra diagnostic requests can also increase the socket pressure being investigated.

### Hidden assumptions

| Assumption | Evidence | Risk if wrong | Test |
|---|---|---|---|
| We cannot learn more without live Android access. | Live USB-only routing does limit retrieval. | We defer checkable defects. | Source-derived partial-record and H2 ACK reproductions already disprove the broad assumption. |
| The control reader behaves independently of TCP segmentation. | Existing tests split H2/plaintext input, but provide complete proactive ciphertext records. | Valid server traffic is discarded or interpreted with the wrong framing. | Split ciphertext at every header/payload offset, fragment HTTP 101 headers, delay EarlyNoise, and coalesce SETTINGS with its final plaintext bytes. |
| Enough heap means another membership can start safely. | Admission measures heap and largest block. | Connected memberships consume management descriptors. | Account for actual open sockets, inject descriptor-allocation failure and concurrent setup/DNS traffic, and require a recovery request to succeed. |
| A large streamed map can be accepted if eight peers are active. | The parser streams dropped fields. | The ninth peer/update fails admission before a useful working set is chosen. | A valid map with more than eight visible peers must either work under a documented selection policy or report an explicit retained-topology limit; raw-buffer growth must not pass this check. |

### Reconstructed story

- **Still true:** Diagnostics must survive disconnect, physical packet forwarding remains unverified, and the different failure stages should be distinguished.
- **Weakest assumption:** The current hand-written control reader is a faithful stream implementation merely because complete-record fixtures pass.
- **Changed situation model:** There are concrete protocol and descriptor-admission defects, plus a peer-capacity restriction. The issue is broader than netmap DOM size.
- **Changed beliefs:** Confidence is high in the demonstrated defects. Confidence remains lower in assigning any one of them to the latest Android socket screenshot.
- **Next action:** Repair framing and resource reservation, fix stale test stubs, and test the real control sequence locally before asking for another physical retry.

### Decision

**Recommendation: ADJUST.** Continue on the original dongle, but replace the diagnostics-first retry cycle with targeted protocol/resource corrections and adversarial checks. The existing ACK fix stays. No new architecture commitment or ADR is required for those correctness repairs. This note is the decision handoff; a peer-directory/working-set redesign would require its own design decision before implementation.

## Solution space

### Frame and decision criteria

**Problem:** Establish a usable tailnet path through the original USB dongle while keeping setup and failure evidence available.

**Key constraint:** Original no-PSRAM hardware, independent 0/1/n saved memberships, bounded resources, preserved NVS identities, and Android diagnostics retrievable after unplugging.

**Working story:** Hand-written stream handling and incomplete resource admission can fail independently of JSON memory size. Correct those boundaries before replacing the protocol stack.

**Success signal:** Equivalent valid control traffic survives arbitrary fragmentation/coalescing; registration, map application and a real USB-origin peer request succeed; management remains responsive at the admitted resource limit; evidence is saved automatically and retrieved after disconnect.

**Decision criteria:** Direct explanatory evidence; minimal hardware/user-test burden; preservation of independent identities and routing isolation; bounded memory and descriptors; maintainable tests that can reject superficial fixes.

**Critical assumptions:** The existing Noise/WireGuard implementation can work once its framing and resource boundaries are corrected; the supported peer working set can be represented within the board's measured resources; fixes must not introduce shared nonce or leftover-byte state across memberships.

### Candidates considered

| Option | Level | Approach | Main trade-off |
|---|---|---|---|
| A | Band-aid / status quo | Add more capture fields and request another phone retry. | Useful for the latest unexplained socket failure, but does not repair demonstrated defects and consumes user effort. |
| B | Local optimum | Correct length-driven HTTP/Noise/H2 reading; preserve pending bytes; reserve descriptors for setup/DNS; repair regression checks; record exact failures in the automatic archive. | Some protocol work remains, but this directly addresses proven defects while preserving the gateway. **Selected.** |
| C | Reframe / diagnostic oracle | Run a minimal single-membership MicroLink reference path with the USB/router integration temporarily bypassed on identical hardware. | Distinguishes inherited protocol behavior from our integration, but alone does not deliver USB forwarding or n identities. **Deferred comparison if B still fails.** |
| D | Redesign | Replace the control stack with the Rust implementation or move tunnel execution to Android. | Higher integration/memory cost; the Rust implementation does not supply our routed USB stack, and Android execution changes the portable hardware use case. **Deferred unless interoperability evidence invalidates B.** |

### Interpretive variety check

B assumes the current stack can be repaired and tests that assumption against a real HTTP/2 implementation. C tests whether our USB integration is the failing frame. D changes the system boundary. If repaired framing interoperates locally but the minimal on-board reference still cannot sustain one identity, revisit platform/stack fit rather than adding another timeout.

### Risk retirement plan

“Retired by evidence” below specifies the required disposition and evidence for execution; planned checks are not claimed to have passed. The reproductions above establish failures in the current/old paths.

| Risk / alternate frame | Planned disposition | Tempting patch this must fail | Required evidence | Stop/pivot if |
|---|---|---|---|---|
| Socket-read boundaries lose bytes or EarlyNoise is delayed. | Retired by evidence | Larger receive buffer or longer sleep. | Every ciphertext split, fragmented HTTP upgrade, delayed EarlyNoise and combined EarlyNoise/H2 preserve authenticated bytes/nonces or close explicitly without resuming a corrupted stream. | Residual-byte growth cannot be bounded or identities share reader state. |
| ACK ordering/count still violates server expectations. | Retired by evidence | Catch GOAWAY and label it a transient server failure. | Go H2 replay through the actual request builders: one ACK per received SETTINGS, map response successful, deliberate duplicate rejected. Capture numeric GOAWAY/RST and bounded diagnostic text. | Valid wire traffic is still rejected; compare with the reference path before another retry patch. |
| Management is starved by memberships or the diagnostic collector. | Retired by evidence | Increase socket count alone or count only RAM. | Derived descriptor reservation, verified open/peak counts and allocation errors; constrained-budget concurrent setup/DNS/diagnostic test; graceful admission refusal preserves existing traffic and a management request. Reports should read the cached diagnostic collector result rather than starting overlapping probes. | Recovery capacity cannot be reserved at the board's measured memory limit. |
| More than eight visible peers fails an otherwise valid map. | Triggered | Grow the raw map buffer while keeping the same semantic section cap. | Preserve a precise capacity error. If the user's actual map exceeds the limit, design a bounded peer directory/active WireGuard working set with authoritative updates/removals, explicit selection, and collision/isolation tests. | Required topology cannot fit even as a measured working set; reframe storage or platform before claiming support. |
| The latest management failure has another cause, with no live client. | Retired by evidence | Assume every SocketException is a map/RAM problem. | Persist startup eligibility, attempts, reset reason, socket operation/errno and HTTP accept failures; correlate with Android request stages and interface evidence. The no-client reproduction must remain a test case. | New evidence shows NCM/service/lifecycle failure independent of descriptor pressure; investigate that path directly. |
| Shared workspace damages independent identities. | Retired by evidence | One global stream/nonce buffer with locking but untracked leftovers. | Two interleaved fragmented control sessions, separate nonce/pending state, no cross-membership map or peer updates. | Correct bounded pending state does not fit the admitted identities. |
| Physical peer traffic is still broken after control success. | Accepted with rationale | Declare success from peers or `routing_ready=true`. | A known USB-origin TCP or UDP request must complete to a selected peer and return through the same membership; compare forced DERP and direct paths. This needs the board and Android. | A verified map/handshake passes but packets fail; move to forwarding/path tests, not another control-buffer patch. |

### Recommendation and execution handoff

**Selected: B.** Prioritize the reproduced handshake defect and socket-budget mismatch. Preserve the ACK correction. Treat peer-section capacity as a named independent trigger. Keep a reference-path comparison available if the same failure survives these checks.

- **Preserve:** Original board, NVS layout and saved identities, independent membership keys/nonces, explicit capacity failures, automatic diagnostics after USB loss, and no arbitrary two-membership product limit.
- **Verify via:** The split/coalesced control corpus, local Go H2 interoperability, socket-pressure admission/recovery checks, then actual USB-to-peer traffic. A larger buffer, stale peer list or green lifecycle flag is insufficient.
- **Accepted trade-offs:** Hardware has finite resource capacity; unsupported topology remains explicit until a working-set design exists. Physical forwarding needs user hardware verification after software checks retire the known defects.
- **Risk retirement checks:** All named rows above stay in the execution handoff. Repair the stale host stubs before reporting a complete passing suite, and convert the partial-record reproductions into acceptance tests for the corrected receiver.
- **Invalidated if:** A corrected bounded receiver cannot interoperate with the real protocol, or measured resources cannot reserve a usable first membership and management channel. Use C to isolate inherited versus integration failure before selecting D.
- **Needs human verification:** One real peer request and later simultaneous independent membership traffic on Android/dongle; diagnostics must be saved first and retrieved after unplugging.

There is no Problem Weave/S&T selection artifact for this investigation; no lineage IDs were invented and no new GitHub issues were created.
