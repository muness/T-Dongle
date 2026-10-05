# ADR 0014: Router hot path, RAM-resident and flash-free

Status: accepted, 2026-10-05. Follows the on-board per-task CPU result in `docs/research/forwarding-latency.md`.

## Context

On the board, `usb_routes` used 32% of a core (about 1.5 ms per packet at 100 to 200 pps), more than all of WireGuard, with `ipc1` at 12.7%. The code explains both. For an alias that is not in the 64-entry RAM table, `gateway_process_host_input` called `ml_directory_alias_find`, which opens the FAT file and reads records until it matches. The result was never inserted into the table, so every following packet of the flow did the same. A flash access disables the cache on both cores, which is what `ipc1` shows. A raw peer address used after a reboot (or any peer beyond the 64th) hits this on every packet.

Everything else on the path was cheap by comparison (host-measured in `tools/bench-router.sh` and `tests/bench_components.c`): two 64-entry linear scans, a full checksum recompute, a `malloc`/`free` of the packet, a `members_lock` try-lock that drops the packet whenever any task holds the lock.

## Decision

1. **Flash is never read on the forwarding path.** The flash file stays the only source of truth for aliases (ADR 0012: append-only, monotonic NVS reservation, never reassigned). RAM holds a cache.
   - An alias miss drops the packet and posts a background fill. `usb_routes` performs the fill only when its queue is empty and at most once per 20 ms. Fills are deduplicated, and a record that is absent is remembered for 10 s.
   - An address at or beyond the highest allocated alias cannot exist, so it is dropped with no request. A scan of 198.18.0.0/15 cannot cause flash reads.
   - Boot preloads the cache from the flash file (`ml_directory_alias_scan`, read only), so aliases that were in use before a reboot forward on the first packet.
2. **O(1) tables sized by the existing bounds.** 64 aliases: chained hash on the (sequential) alias, CLOCK replacement. 64 flows: chained hash on (alias, host, ports, protocol) for USB to tunnel; for the reply, the mapped source port already encodes the slot (`40000 + slot + 64 * generation`), so the reply is one index plus an exact tuple comparison. Ownership is never inferred from the index. An established flow carries its membership and peer, so eviction of its alias from the cache does not affect it.
3. **Short critical sections instead of `members_lock`.** One `portMUX` section (a few microseconds, nothing called inside it) protects both tables. Membership state is pinned with a two-bucket epoch RCU: `gateway_suspend` and `gateway_forget` unpublish the membership, then wait until no packet is still using it. `stop_member` already calls `gateway_suspend` before `microlink_destroy`, so a client is never used after it is destroyed. `members_lock` is taken only on the cold path, when a membership has not been published yet (at most once per 100 ms, 2 ms timeout), and never inside a forwarding section. Memberships are published by `gateway_alias`, which DNS and the peer views already call with `members_lock` held.
4. **Incremental checksums (RFC 1624)** for NAT address, port, TTL and MSS-clamp rewrites. This also stops the router from repairing a checksum it did not break: a packet with a bad TCP/UDP checksum leaves bad, a UDP datagram with no checksum stays that way.
5. **One buffer, not two.** USB to tunnel copies into a static scratch buffer owned by `usb_routes` (no `malloc`). Tunnel to USB copies once, straight into the pbuf that goes to USB. The two seams that PR-B replaces with the shared packet pool are `route_emit_tunnel` and `route_emit_usb`.
6. **Oversized packets.** A packet larger than 1400 bytes with DF set gets an ICMP "fragmentation needed" (type 3, code 4, next-hop MTU 1400, RFC 1191), rate limited to one per 50 ms and sent only to a validated USB host. Without DF it is dropped and counted: the host's only remedy would be to fragment, and fragments are rejected. This replaces the silent drop of every oversized packet.
7. **Scheduling.** `usb_routes` is pinned to core 1 at priority 8: one above `ml_wg_mgr` (7) so forwarding does not wait behind a handshake, below Wi-Fi (23) and tcpip (18) on core 0. At about 100 microseconds per packet and under 400 pps it needs under 4% of a core. Wakeup is the queue itself (`portMAX_DELAY`); the only timed wait is the 20 ms spacing after a cache miss. Queue depth is 16 entries and 16 KiB of pbuf data (compile-time `ROUTE_QUEUE_DEPTH`, `ROUTE_QUEUE_BYTES`): a USB OUT transfer carries about 3 full frames or tens of ACKs, and the byte budget bounds the memory a stalled consumer can hold when the heap minimum is 6 KB.

## Consequences

- The first packet to an address whose alias is neither cached nor preloaded is dropped; TCP retries after its retransmission timeout. This only happens beyond 64 distinct peers or for an alias never resolved since boot and older than the 64 most recent records.
- The router no longer drops packets because another task holds `members_lock`.
- `memory_diagnostics` builds report the router counters with the serial command `route` (forwarded, drops by reason, alias misses and fills, ICMP replies, queue bounds).
- Cost: about 3.6 KB more flash code and 2.8 KB more static RAM (tables, 1400-byte scratch buffer); the per-packet 1400-byte heap allocation is gone.

## Validation

Host: `tests/test_route_table.c` (checksums, hash tables against the old linear model, eviction, ownership, ASan/UBSan and TSan), `tests/test_router_hotpath.c` (zero flash calls during 30,000 round trips, miss/fill/preload, invalidation, membership lifecycle against concurrent forwarding under TSan, ICMP), `tests/test_router_differential.c` (the frozen old router and the new one receive the same random packets and control events; emitted packets and flow tables must be identical), `tests/test_route_ingress.c` (queue overflow accounting). Run by `alternative/tailnet/tools/test-gateway.sh`.
