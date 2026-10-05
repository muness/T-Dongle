# Same-build baseline: firmware 0.2.22 (commit 040aff5), 2026-10-05

Board: original T-Dongle-S3 (STA MAC 30:ed:a0:d7:88:bc). Firmware is the unified image in tailnet mode with one membership on tail434280, flashed app-only so NVS was preserved. The host is macOS on USB `en21`. The tailnet path between the dongle and the host's own Tailscale node is **direct** over the LAN (192.168.1.141), not DERP. `tailscale ping` reports 47 ms.

## Memory, one membership (`/status`)

| Point | Free (B) | Largest block (B) | Minimum since boot (B) |
|---|---|---|---|
| Before `microlink_init/start` | 109,648 | — | — |
| Immediately after start | 58,732 (start allocates **50,916**) | — | — |
| Map read (before) | 43,468 | 26,624 | — |
| Steady, idle | 36,404 | 24,576 | 22,096 |
| **After 9 iperf runs** | 36,932 | **19,456** | **5,884** |

- Admission for the next membership needs `membership_start_budget` = 108,200 B plus a 24,000 B largest block. With 36 KB free, the 2nd membership is refused.
- First membership's total steady cost ≈ 109,648 − 36,404 = **73,244 B**. This replaces the mixed-version estimate of 90–113 KB.
- `membership_context_bytes` = 9,648.
- Free stack bytes at steady state: net_io 2,768/6,144; derp_tx 6,524/10,240; coord 8,136/12,288; wg_mgr 5,652/8,192.
- **Ordinary traffic took the heap within 5.9 KB of exhaustion.** Per-packet heap allocation on the data path (router.c, ml_wg_mgr.c, ml_derp.c) is the likely cause; issue #14 targets it.

## Throughput (USB host → dongle → WireGuard direct → host's Tailscale node)

iperf3 3 × 10 s, client bound to 192.168.77.2, server on 100.106.216.83 reached through the dongle alias 198.18.0.86.

| Test | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| TCP up (host → tailnet) | 1.05 Mbit/s, 99 retrans | 1.03, 97 | 0.83, 85 |
| TCP down (tailnet → host) | 1.36 Mbit/s, 63 retrans | 1.36, 70 | 1.36, 59 |
| UDP up, 8 Mbit/s offered (received) | 1.68 Mbit/s | 1.71 | 1.98 |

Tailnet mode delivers about 1–1.4 Mbit/s, far below the ~7 Mbit/s USB 1.1 ceiling. The data plane, not USB, is the bottleneck, and buffers are not being starved for bandwidth-delay reasons. ICMP through the tailnet is unsupported, which matches the README's TCP/UDP-only scope.

## Defects found during this capture

1. **Fixed (040aff5):** in router mode the USB host and the gateway had the same MAC, so macOS could not ARP the gateway.
2. **Open:** the dongle's DNS returns NXDOMAIN for the MagicDNS names that `/status` advertises (`<host>.tail434280.ts.net`). Only `<host>.tailnet.tailnet` resolves.

## Ceiling: transparent bridge on the same link (2026-10-05, integration 0010832, verified flash)

The unified image was switched to `mode wifi_bridge`. The host used the bridged port (`en19`, 192.168.1.141) to reach a wired LAN iperf3 server at 192.168.1.2; the server itself sustains 2.37 Gbit/s wired. Dongle RSSI −50 dBm, channel 11, HT20.

| Bridge | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| TCP up | 6.36 Mbit/s (132 retrans) | 6.27 (103) | 6.07 (87) |
| TCP down | 5.03 (189) | 4.30 (181) | 4.82 (185) |

UDP delivered: 4 Mbit/s offered gave 3.84 up / 3.57 down; 8 Mbit/s offered gave 6.59 up / 6.08 down (18–24% loss).

Tailnet at the same integration point: about 2.0 Mbit/s up and 2.3 down. That is roughly 32% and 49% of the bridge. The bridge retransmits too, so part of the TCP loss is the radio link and not the firmware.
