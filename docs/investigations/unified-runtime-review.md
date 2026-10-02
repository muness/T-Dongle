# Unified runtime execution and review

Aim: one firmware with a persistent switch between the original transparent Wi-Fi bridge and the tailnet router, common Wi-Fi/recovery/diagnostics, chip temperature, and evidence for transient memory pressure. Preserve NVS offsets, credentials, saved tailnet identities, working routing and Android debug signing. A controlled restart switches the selected data plane; a physical unplug/reinsert may still be required by this Android USB host.

Decision: preserve the original Layer-2 forwarding path rather than reuse NAT for ordinary mode. This retires the tempting shortcut of silently changing host addressing: bridge startup has no USB DHCP/NAPT/DNS server or membership clients, and production-frame tests retain DHCP/ARP/IPv6 bytes. Shared CDC setup works without the router's fixed USB address. Root builds unified sources by default; legacy source remains available with TDONGLE_LEGACY_BRIDGE=ON. The integration branch already contains the original bridge's Git ancestry.

Memory investigation: recovered idle free memory does not prove absence of a leak. Fixed 16-record allocation-free instrumentation retains low-water transitions and failed allocation sizes with operation and firmware uptime. Operations: 0 manager fallback, 1 Noise/control allocation, 2 flash journal write workspace, 3 journal HTTP read workspace, 4 status snapshot, 5 automatic Wi-Fi scan. Records are copied into Android's rolling saved diagnostics via CDC in either mode. Uninstrumented allocations may appear under the manager fallback; do not attribute them to the manager without further evidence.

Reduce unnecessary work: full automatic diagnostics once per 30 seconds instead of two; independent CDC health every ten seconds; no redundant HTTP boot report in healthy mode; no background Wi-Fi scan when an existing saved network has stronger than -75 dBm signal unless explicitly forced. Weak-signal roaming, manual scans and strongest selection on startup remain. This reduces work by inspection; it does not establish the cause of the previous minimum-heap dip or measured thermal improvement.

Risk retirement:

| Risk | Disposition | Adversarial evidence / remaining boundary |
|---|---|---|
| Transparent bridge replaced with NAT | Retired by evidence | Production L2 byte preservation and bridge startup rejects HTTP/DNS/route stages; same station/USB MAC. |
| Frame ownership under USB backpressure and Wi-Fi disconnect | Retired by evidence | Pool exhaustion, failed sends, stale epochs, driver release, task/queue/heap startup failures under ASan/UBSan; existing TinyUSB copy/deadline ownership tests. |
| Mode storage silently clears credentials or activates on failed save | Retired by evidence | Exact helper uses only mode key; missing/corrupt/read/set/commit failures and subsequent load tested. No storage erase path. |
| Sensor failure shown as valid current temperature | Retired by evidence | Install failure, NaN read, retained peak, recovered read and Android valid=0 parsing tests. |
| Trace creates allocation churn or ordinary traffic evicts evidence | Retired by evidence | Exact production recorder uses static storage; 100 unchanged observations do not evict low-water record; ring wrap and oversized failed allocations tested. |
| Unsafe global scratch workspace | Retired by evidence / not selected | No shared payload scratch introduced; original ownership tests remain. |
| Strong-signal optimization prevents startup selection or weak roaming | Retired by evidence | Eight-SSID test selects strongest and retries; healthy automatic scan skipped, weak scan still runs. |
| Persistent leak or fragmented heap after hours | Accepted with rationale | Requires new handset hardware captures; local ownership/failure tests pass but cannot retire full network/hardware lifetime behavior. Retain baseline and largest-block metrics; investigate if recovered baseline declines. |
| Full hardware USB switch, temperature accuracy and long uptime | Accepted with rationale | No physical dongle attached to build machine. Need handset verification; chip sensor measures internal silicon, not enclosure or regulator. |

Fresh diff review replaces sg (unavailable on this host). Notable corrections during review: native setup must use shared profile store in bridge mode; no HTTP diagnostic probes in bridge mode; clear cached gateway status when switching; mode persistence rejects invalid values; slot replacement retains transactional in-memory state; CDC queue remains bounded. All selected checks are required before packaging. No physical flash, erase, PR merge or publication performed.
