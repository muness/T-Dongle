# F2c: can a node close its home DERP connection when every active peer is direct?

Issue #20 (parent #22). Date 2026-10-05.
Evidence base: Tailscale `9128778` (2026-10-02) read from a shallow clone; firmware `c1f1e7a`; a latency probe from this Mac to three DERP hosts. Headscale lines were read from `main` on 2026-10-05 and I did not pin a commit.

## Headline

**Recommendation: reject for any membership that accepts inbound connections. Adopt only for strictly outbound-only memberships, and only after two prerequisites below.** Within what the sources show, the answer to "can peers still reach a node that is not on its home DERP?" is **no, except in narrow cases**.

Tailscale ships exactly this mode as a debug switch and documents its cost. `SetHomeless` says that in homeless mode "the node is unreachable by others" (`wgengine/magicsock/magicsock.go:4039-4042`). The only caller outside tests is the debug LocalAPI (`ipn/localapi/debug.go:189-192`).

Today the gateway's one DERP connection is both its home and its only route to peers. The firmware advertises `PreferredDERP` in every MapRequest (`ml_coord.c:1008`) and sends every DERP packet over that single connection regardless of the peer's own region (`ml_derp.c:658-710`; callers `ml_wg_mgr.c:200,339,1254,1314,1320,1896`, `microlink.c:790`). Closing it removes the node's only inbound path and its only DERP path.

## 1. How peers reach a node, from the source

| Question | Answer | Source |
|---|---|---|
| Where does a node tell the world it can be reached? | `NetInfo.PreferredDERP`: "the region ID that the node subscribes to traffic at ... Zero means disconnected or unknown." Control republishes it to peers as `Node.HomeDERP`. | `tailcfg/tailcfg.go:1128-1135`, `:418-423`. Headscale: `hscontrol/types/node.go:658-662`, `hscontrol/mapper/tail.go:1202,1284` (unpinned). |
| Which DERP does a peer send to? | `de.derpAddr = DerpMagicIP:<HomeDERP>` from the netmap. A zero `HomeDERP` clears it. | `wgengine/magicsock/endpoint.go:1733-1752` |
| What if the node is not connected there? | The DERP server drops the packet. It sends `PeerGone(NotHere)` back to the sender **only if the dropped packet was a disco message**, and rate-limited. | `derp/derpserver/derpserver.go:1470-1508`, `:1092-1101` |
| What does the sender do on `PeerGone(NotHere)`? | Removes its cached reverse route and logs. It does **not** pick another region or retry elsewhere. | `wgengine/magicsock/derp.go:652-664` |
| How does an initiating peer try to avoid DERP? | Sends WG and disco pings to every known UDP endpoint **and** via DERP, then sends `CallMeMaybe` over the node's home DERP so the node pings back and opens its NAT. | `endpoint.go:1115-1141`, `:1440-1458`; `magicsock.go:2665-2709` |
| Is `CallMeMaybe` deliverable without a DERP connection? | No. It travels only over DERP to `derpAddr`. | same |
| Does home DERP ever get idle-closed in Tailscale? | **No.** Non-home connections close after 60 s idle; the home connection is skipped. | `derp.go:990-1010` (`if i == c.myDerp { continue }`), `:1071-1073` |
| Can a node with `HomeDERP == 0` ever be reached over DERP? | Only through a **learned reverse route**: if the node itself first sent over DERP region R, peers remember R and reply there. Tailscale built this for "large one-way nodes" that never advertise a home. | `derp.go:72-88` (`fallbackDERPRegionForPeer`), `endpoint.go:1133-1141`, `derp.go:620-628` |
| Is there any control-plane "wake up, a peer wants you" signal? | None found. `PingRequest` is a control-to-node probe, not a peer-initiated wake. I did not find any other MapResponse field for it. For the closed-source control server this is unverified. | `tailcfg/tailcfg.go:1890-1930` |
| Does Tailscale avoid changing home while disconnected from control? | Yes. "Even if this DERP region is down, changing our home DERP isn't correct since peers can't discover that change." | `magicsock/derp.go:159-175` |

### Who can still reach a node that has closed home DERP

| Peer situation | Reaches the node? | Why |
|---|---|---|
| Established direct UDP path, still within NAT binding and WG keepalive | **Yes** | No DERP needed |
| Same LAN as the node | **Yes** | Peers ping the node's LAN endpoints from the netmap |
| Node has a public IP, port-mapping, or a full-cone NAT | **Probably** | Endpoint discovery works without `CallMeMaybe` |
| Typical address- or port-restricted home NAT, peer on the internet | **No** | The inbound ping is dropped until the node sends first, and the "send first" trigger is `CallMeMaybe` over DERP |
| Peer already holds a reverse route from the node's own earlier DERP traffic | **Only while that DERP connection stays open** | `derpRoute` is dropped on `PeerGone` or disconnect |
| Peer using the stale `HomeDERP` the node still advertises | **No** | Black hole: the server drops, and the only feedback is `PeerGone` for disco packets |

The black-hole case is the worst. If the node closes DERP but keeps advertising `PreferredDERP=R`, peers keep sending into R. If it advertises 0 instead, peers must be told via a MapRequest update and then told again on reconnect, and I have no measurement of control-plane propagation delay. Both variants are visible to peers as the node going dark for the gap.

## 2. What breaks

| Scenario | Effect of closing home DERP | Evidence |
|---|---|---|
| **Inbound-initiated connection** (a peer connects to a service or subnet behind the gateway, or uses it as an exit node) | First WG handshake and `CallMeMaybe` are lost. The peer retries the WG handshake on its own timer (`REKEY_TIMEOUT` is 5 s in `wireguard.h:71`) and keeps hitting a dead region until the node reconnects. | §1 table. No wake signal exists. |
| **Outbound-initiated connection** | The firmware sends to the peer via **its own** region only (`ml_derp.c:658-710`). If the peer's home is a different region, the packet already goes nowhere today. Replies reach the node only through a DERP connection it holds open. If the node reconnects only to send, replies work while it stays connected, because the peer learns a reverse route from the first packet. | `derp.go:620-628`; firmware as cited above |
| **Direct path breaks later** (NAT rebind, Wi-Fi roam) | Recovery needs DERP on both sides. The peer's fallback goes to a region the node left. The stall lasts until the node notices (WG keepalive timeout, tens of seconds), reconnects (see §3) and a new disco round completes. | `endpoint.go` send path |
| **Peer-initiated disco ping over DERP** | Lost. The peer cannot find a direct path until the node is back. | same |
| **Control-plane online status** | Unchanged: it comes from the map long-poll, not DERP. Peers still see the node "online" while they cannot reach it. | `tailcfg` `PreferredDERP` comment |

## 3. Reconnect latency a peer would see

The firmware logs a per-phase breakdown on every connect (`ml_derp.c:1050`, `[TIMING] DERP total: ... DNS, TCP, TLS, proto`), and I found no collected values in the repo. The numbers below are from this Mac to production DERP hosts, TLS 1.2 (the firmware's only version), three runs each:

| Host | TCP connect | TLS 1.2 handshake | HTTP upgrade response | Total |
|---|---|---|---|---|
| derp1 | 36-43 ms | 74-80 ms | 31-33 ms | 144-155 ms |
| derp10 | 63-64 ms | 129-131 ms | 58-61 ms | 251-256 ms |
| derp2 | 67-69 ms | 132-139 ms | 64-65 ms | 264-274 ms |

That is about 4 round trips of network time. The DERP `ClientInfo`/`ServerInfo` exchange after the upgrade adds roughly one more, which I did not measure. The ESP32-S3 adds its own CPU cost for the ECDHE key exchange and one ECDSA P-256 signature check, which I did not measure. I expect it to be several hundred milliseconds. Treat any figure under 1 s as unproven until the `[TIMING]` log is collected on hardware.

Add what a peer experiences on top of the reconnect:

- **Detection:** the node cannot know a peer wants it. A periodic wake (reconnect every N seconds) trades latency against exactly the memory this proposal is meant to save, because a TLS handshake is the peak (see `derp-tls-buffer-options.md`).
- **WG retry:** the peer's first handshake is lost. The next attempt is up to 5 s later.
- **Netmap churn:** every home change or "no home" update is a control round trip for each tailnet.

For an inbound-capable node the expected first-connection delay is detection time plus up to 5 s, with no upper bound if the node sleeps its DERP indefinitely.

## 4. Recommendation

| Option | Verdict | Reason |
|---|---|---|
| Adopt for all memberships | **Reject** | Matches Tailscale's own "unreachable by others" mode. Fails for inbound and for path-failure recovery. |
| Adopt for memberships that are strictly outbound-only | **Adopt later, with prerequisites** | Saves one TLS session's idle state. But the idle state is already small (about 1-2 KB, see `derp-tls-buffer-options.md`), so the real saving is the avoided handshake **peak** only while the connection is down, and it comes back on every reconnect. |
| Keep DERP up, shrink the peak instead | **Preferred** | The peak, not the idle state, is the cost. See the other document. |

Prerequisites before any outbound-only variant:

1. The membership must be configured as outbound-only (no subnet routes, no exit-node advertisement, no inbound service). Test: with the flag set, advertise nothing in `RoutableIPs` and confirm control shows no routes.
2. The firmware must send to a peer through **that peer's home region** (a short-lived second connection, as Tailscale's `derpWriteChanForRegion` does), not through its own. Without this, outbound over DERP already only works for same-region peers. This is independent of F2c and a larger task. Test: reach a peer whose home is in another region over DERP only.
3. Advertise `PreferredDERP=0` before closing, then the real home on reconnect, and measure how long peers take to see each change.
4. Measure on hardware: reconnect time from the `[TIMING]` log, and the success rate of an inbound probe from a peer on another network with the flag **off**, as the baseline that shows what the flag costs.

## Open questions

- How fast does Tailscale's control plane push a `PreferredDERP` change to peers? I could not test this and the control server is closed source.
- What does Headscale do when `PreferredDERP` is 0? Lines `hscontrol/mapper/tail.go:1202` and `:1284` suggest it forwards 0, but I did not trace the full path.
- Does any real gateway deployment have only outbound traffic? If the product is an exit-node or subnet-router device (inbound by definition), F2c is moot.
