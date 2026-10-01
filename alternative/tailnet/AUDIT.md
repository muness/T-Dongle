# N-membership feasibility audit

## Aim and scope

Keep 0, 1 or N memberships active simultaneously inside the original no-PSRAM T-Dongle-S3 and provide isolated USB-host access. Membership count is dynamic; two is a test case, not the maximum. This audit implements the entry gate of Android issue #35 and preserves findings for #36–#41. It does not complete those issues or deliver a usable alternative gateway firmware.

## Direct evidence

Native ESP-IDF v5.5.5, commit b774170ff46c393eeb5e495ea37936038d3f4f4f, compiled the pinned MicroLink component sources for esp32s3 with CONFIG_SPIRAM disabled, 8 configured peers and the upstream minimum 64 KiB H2/JSON buffers. Compile-time Xtensa ABI measurements were extracted from the audit ELF, not guessed from the README. audit-result.json records the values and excluded memory costs.

| Retained per-membership item | Bytes |
|---|---|
| microlink_t context | 23,936 |
| Five task stacks | 47,104 |
| Queue item storage (excluding control blocks) | 6,544 |
| Fragmented-stream h2_acc | 65,536 |
| lp_acc JSON allocation, conservative count omitting terminator | 65,536 |
| Total lower bound for this adversarial retained-state case | 208,656 |

One fragmented H2 stream causes h2_acc allocation in src/ml_coord.c:3141; lp_acc allocation occurs at src/ml_coord.c:3012. Both are retained in the instance until instance destruction. This is not a claim that every idle session always allocates both buffers. It is a reachable allocation demand that concurrent sessions must handle without disconnecting or switching another membership. Three such sessions demand 625,968 bytes, exceeding the entire chip SRAM (524,288), before Wi-Fi, USB, TLS, WireGuard state, dynamic packet queues, parsing trees, gateway or allocator overhead. Lowering the exchange H2 setting alone does not resize the hard-coded retained h2_acc. The two-member figure (417,312) is not evidence that two actually fits.

## Other integration blockers

- src/microlink.c uses the single `microlink` NVS namespace for identity keys and boot timestamp state. Two instances would load the same identity. Namespace must be instance-owned with atomic persistence and independent removal.
- src/ml_peer_nvs.c has static s_nvs/s_initialized/s_table and namespace `ml_peers`; per-membership peer state is not isolated.
- src/ml_wg_mgr.c has the shared s_wg_output_pcb. Transport binding and lifecycle must be instance-owned, with explicit upstream and interface routing.
- src/ml_wg_mgr.c:298 and components/wireguard_lwip/src/wireguardif.c:197 require PSRAM for packet payloads. The ordinary control allocator falls back to malloc; these packet paths do not. Successful no-PSRAM compilation does not imply successful transmission.
- No `PacketFilter` / `FilterRule` parser or evaluator was found in the vendored control and receive paths. wireguardif.c checks IPv4 peer source AllowedIPs, then dispatches to netif input; peer authentication/source binding does not establish destination/port policy enforcement. IPv6 source filtering is explicitly TODO. Disable IPv6 for the proposed first spike; implement and adversarially verify received tailnet policy before enabling host forwarding. This inspection is not a cryptographic audit or a live exploit demonstration.
- Peer queues and map-buffer overflow cannot silently evict/truncate while reporting complete access. The upstream overflow paths require explicit admission/capacity failure semantics.

## Dissent

Steel-man: C/ESP-IDF and an existing protocol client may avoid implementing all Tailscale protocols from scratch. Contrary evidence: global persistence/transport, retained per-instance allocations and missing policy enforcement make a multi-instance wrapper insufficient. Functional failure: fragmentation, relays and third-member enrollment exhaust memory. Adoption failure: a proxy-only feature cannot fulfill arbitrary host access. Opportunity cost: maintaining this fork may cost more than a purpose-built bounded runtime or different hardware. Weakest assumption: modest traffic implies modest control-plane/identity overhead; source and ABI measurements contradict it. Decision: RECONSIDER the per-instance client model, not the multi-tailnet product aim. No public gateway protocol or address contract is frozen.

## Execute risk retirement

| Risk | Result | Tempting shortcut rejected |
|---|---|---|
| N-membership memory | Triggered for the audited per-instance retained-buffer model | Two-only fixtures, swapping active accounts, lowering one setting while leaving hard-coded buffers |
| Identity isolation | Triggered by shared NVS identity/cache and transport state | Multiple handles mistaken for independent identities |
| Packet authorization | Not implemented/verified; forwarding must remain disabled | Treat authenticated WireGuard peer as authorization for every port/destination |
| Routing and DNS collisions | Not reached; blocked behind foundation | Test only distinct IPs/names |
| Relay fallback and useful throughput | Requires redesigned runtime and physical tests | Compile success or direct-only connectivity |
| Alternative hardware/custom engine | Deferred product/architecture pivot | Claim original hardware impossible from one implementation's measurements |

## Review and handoff

Review verdict: reframe the runtime architecture before #36–#41. The measured failure invalidates cloning this client per membership; it does not prove the product impossible on S3. Next design must bound total memory, share worker stacks and staging buffers where safe, stream/limit maps explicitly and preserve concurrent independent identities and deny policies. Shared control-buffer work must not become tailnet switching; all established data-plane sessions remain active.

No physical flash, tailnet enrollment, credentials, original bridge changes or companion firmware-selector changes occurred. No actual-board, relay, isolation or host-access test passed. Model source review cannot establish cryptographic correctness. sg is unavailable, so a fresh manual diff and source/measurement cross-check is the recorded review. No external automated review claimed.
