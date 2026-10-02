# Execute: flash directory and JIT routing

Aim: accept real tailnet maps beyond eight peers while retaining bounded RAM and usable Android USB routing. Scope includes directory and map staging, DNS, alias backing storage, lazy activation, bounded first-packet waiting, setup pagination, packaging and delivery. Preserve the original repository, NVS identities, Wi-Fi settings, automatic Android diagnostic retention, and 0/1/n membership admission. Do not flash physical hardware.

| Risk | Disposition | Evidence that rejects the tempting shortcut |
|---|---|---|
| Simply increasing the runtime peer array | Retired by evidence | Production semantic flash path accepts 1000 records and 12 removals with the original eight-slot runtime |
| Publishing partially parsed maps | Retired by evidence | Malformed trailing JSON retains the old directory; failed writes do not publish a new generation |
| Ignoring removal or key rotation | Retired by evidence | Directory tests remove cold records and rotate keys; production activation/reconciliation tests evict warm revoked and rotated keys |
| Cross-membership IP collisions | Retired by evidence | Same IP in distinct public-key namespaces returns distinct key material; existing NAT isolation tests pass |
| Cache churn destroying recent traffic | Retired by evidence | Production selection tests reject a ninth recent peer, preserve MRU/pinned peers, and evict idle LRU peers |
| Unbounded pending first packets | Retired by evidence | Production queue tests enforce four packets, wait for handshake, release on queue rejection, and expire waits |
| Reboot or interrupted storage generation | Retired by host evidence; physical behavior accepted | CRC recovery chooses the older complete bank after a torn newest bank; actual electrical FAT power-loss qualification remains hardware work |
| 64 aliases becoming the next directory cap | Retired by backend evidence | 1000 persistent aliases and torn-tail recovery; existing router tests verify identity/flow isolation |
| Hidden initial-map authorization from old cache | Retired by evidence | Production activation rejects saved records before current authoritative map approval |
| Hot-path flash I/O in network callbacks | Retired by inspection | USB routes enqueue into a four-item worker; peer provisioning and cold reads occur outside lwIP callbacks |
| Snapshot write amplification | Accepted with quantified rationale | Snapshot-per-changed-map is the initial storage format; 1000 records require roughly 281 KiB per snapshot. Keepalives do not write. Physical update rate and latency are unmeasured; sustained churn triggers append/compaction work |
| Firmware stats or inactive metadata consuming bulk RAM | Accepted with inspection rationale | Settings/identities and the small diagnostic journal already use NVS; moving live state or small linked-list metadata is not the present capacity bottleneck |

Host tests cover production parser/store and production cache/queue functions with mocked WireGuard effects, not live cryptographic connectivity. Full firmware build plus Android packaging/tests are required before delivery. No physical success is claimed.
