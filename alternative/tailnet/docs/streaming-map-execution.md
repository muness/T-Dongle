# Streaming map execution — 0.2.4

Aim: maintain usable independent tailnet memberships on the original no-PSRAM dongle, despite control maps exceeding the previous 48 KiB receive limit. Selected approach: validate and project incoming JSON while receiving it, rather than increasing the full raw buffer. Registration shares the same serialized workspace. Independent identities, peer update semantics, routing aliases, and the NVS layout remain unchanged.

Scope: control-plane memory and startup allocation accounting. Task stack reductions without measured high-water marks, Android-assisted routing, new hardware, and UI redesign are outside this change. Hardware acceptance is pending; compilation does not prove two memberships fit or forward traffic.

## Checks and results

- `tools/build-gateway.sh`: pinned ESP-IDF build, size report, host checks with AddressSanitizer/UndefinedBehaviorSanitizer, and package generation.
- `tests/test_project_stream.c`: byte-by-byte 300 KB discarded string with retained identity; exact output equivalence to the old projector for initial peers, changes, removals, endpoint patches, escaped keys, scalar values, and preferred DERP region after the ordinary region limit. Malformed discarded JSON, excessive nesting and retained output overflow fail explicitly.
- `tests/test_stream.c`: 80 KB raw map across fragmented HTTP/2 DATA and Noise records; multiple maps; padding, incomplete maps, invalid length prefixes, stream reset, and flow-control handling. Registration tests include SETTINGS/PING acknowledgments, fragmented 12 KB response, padded DATA, missing END_STREAM, reset/GOAWAY, and workspace overflow. Raw-callback mode remains bounded and tested separately.
- Existing routing, identity/protocol, Noise and setup checks remain in the build suite. Partition layout and NVS preservation are checked when packaging the APK.

## Memory accounting

Compiled Xtensa debug information reports `sizeof(microlink_t) = 9208`, `sizeof(gs_parser) = 5000`, queue item sizes 44/48/4 bytes, `StaticQueue_t = 84`, and `StaticTask_t = 340`. Map JSON workspace falls from 49152 to 24576 bytes; parser state adds 5000, yielding **19576 bytes less static RAM**. Registration removes its separately allocated 16384-byte H2 accumulator, 8192-byte response buffer and 4096-byte receive buffer. The shared plaintext buffer is 20496 bytes; it is not a per-membership allocation.

Admission now derives its baseline from the compiled context, five task stacks (47104 bytes), queue payloads and bookkeeping, plus a 2048-byte allocator allowance and 16384-byte recovery reserve: **78340 bytes**, with the existing 24000-byte largest-free-block requirement. `/status` reports this budget, context size and each membership's heap before/after startup. The reserve is a provisional bound, not a measurement of JSON/network peaks. No claim of two fitting follows from this arithmetic.

Raw map limit is 1 MiB; retained JSON limit is 24575 bytes plus terminator. Nesting is bounded to 32 containers, encoded field names to 128 bytes and scalar tokens to 95 bytes. Discarded string values stream without size-dependent allocation. Unsupported sizes produce explicit failures rather than truncated usable maps. cJSON still allocates the retained DOM; removing all dynamic map memory is not claimed.

## Risk retirement

| Risk / alternate cause | Status | Tempting shortcut rejected | Evidence / remaining check |
| --- | --- | --- | --- |
| Large raw map exhausts assembly buffer | Retired by evidence | Raise raw buffer to 64 KiB | 300 KB parser and 80 KB framed map checks pass with 24 KiB output workspace. |
| Projection loses identity, incremental changes or preferred DERP | Retired by evidence | Retain only initial peers | Exact old/new projected output checks retain all consumed root fields and preferred region. Existing consumers are unchanged. |
| Malformed discarded fields bypass validation | Retired by evidence | Skip ignored subtree as raw text | Bad escapes, commas, numbers, literals and depth fail under sanitizers. |
| Retained topology exceeds capacity | Retired by evidence for explicit failure | Truncate silently | Retained-output overflow sets a distinct capacity failure; no map is applied. Large useful topologies remain unsupported. |
| Registration buffers consume peak heap or partial responses are accepted | Retired by evidence | Remove buffers but parse the first record | Shared-workspace inspection and fragmented 12 KB/END_STREAM/overflow tests. |
| Multiple independent sessions corrupt shared workspace | Retired by code inspection for serialization | Share arrays without locking | Registration and map readers both hold the same static mutex; all returns release it through wrapper/cleanup. Task/dataplane contexts remain separate. Real scheduling and startup latency need hardware. |
| Two memberships fit and remain usable | Accepted with rationale | Lower a fixed threshold and declare success | Derived compiled allocation baseline plus reported runtime deltas; board required to measure peak heap/fragmentation and forward traffic on both. |
| Setup HTTP failures have another cause | Accepted with rationale for runtime behavior | Claim map streaming fixes every timeout | Inspection confirms status can wait up to 1 s on membership lock during startup, and JSON response printing can fail with explicit OOM. These mechanisms remain; concurrent HTTP/control-plane stress needs connected Android/board. |
| NVS identities/Wi-Fi are erased | Retired by packaging/code inspection | Change partitions or erase flash | No persistence schema, erase operation or partition change; compare packaged partition table with v107. Physical upgrade persistence still needs hardware. |

## Review and acceptance

Review skill used with its code lens: selected mechanism remains aligned; no frame or authority change. Fresh diff review and sanitizer/build results are the software evidence. No CodeRabbit, independent agent review or physical tests are claimed.

Hardware acceptance: flash 0.2.4 through the APK without erase; confirm saved Wi-Fi and identities; open Networks while registration/maps run; fetch a known peer HTTP page; then activate a second membership and fetch one peer from each repeatedly while status remains responsive. Inspect recorded map failures, heap deltas and largest block. Stop/pivot if retained topology exceeds capacity, heap reserve is insufficient, independent routes fail, or HTTP failures persist: collect the automatic Android capture and investigate the failing layer instead of another buffer increase.
