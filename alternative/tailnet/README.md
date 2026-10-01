# Experimental USB multi-tailnet gateway

This separate ESP32-S3 firmware implements USB NCM Ethernet, Wi-Fi upstream, tailnet enrollment, saved independent identities, and concurrent membership contexts. It replaces adapter mode while installed. The original bridge source and `adapter` NVS namespace stay untouched. This build has not yet been qualified on physical hardware; do not treat compilation or host tests as proof of simultaneous traffic on the dongle.

## Try it

Install the explicitly labeled tailnet preview APK and use its existing board-confirmed firmware installer. Reconnect USB after flashing, allow management access, and choose **Set up and use your tailnets**. The companion binds its setup view to the USB Ethernet interface. A computer can instead open http://192.168.77.1/ after obtaining a USB DHCP lease.

Save Wi-Fi first, then add each membership with a unique label. Leave its auth key empty for browser authorization, or supply a Tailscale auth key. Follow **Sign in to this tailnet** when shown. The firmware preserves that membership's machine, WireGuard and discovery keys in its own NVS namespace. The provisioning auth key is removed from the saved settings after successful connection. Disable and reactivate individual memberships, or remove their stored identities. Removing a local identity does not delete its node from the Tailscale admin console.

Each peer receives a USB-visible address in `198.18.0.0/15`. These mappings persist across reboot and are never reassigned to another identity when removed. For example, use a displayed address with SSH or an HTTP service. DNS provides `<peer>.<membership>.tailnet`; identical peer addresses or short names across memberships remain distinct. Unqualified names use upstream DNS. Ambiguous qualified names return NXDOMAIN.

## Bounds and current limitations

Membership records form a dynamic list: zero, one or N, with no two-slot model. Active admission depends on actual free memory, including a reserve for control-plane work; a rejected activation leaves existing memberships running and its saved record available. Physical capacity, two simultaneous enrollments, DERP-only operation, throughput and long-running stability still need measurement. The preview reports memory admission failures instead of switching or evicting another membership.

The implementation currently supports IPv4 peer TCP/UDP connections originating from USB, 8 peers per membership, 64 persistent peer aliases, and 64 active flows. It rejects fragmented IP packets, unsolicited inbound traffic, and IPv6 tunnel traffic. Subnet routes and exit nodes are not exposed. A retired alias continues to occupy its allocation to prevent old DNS caches from reaching a new identity. Oversized control maps or Noise records fail the connection rather than overflowing a buffer. The shared workspace bounds maps to 48 KiB and Noise plaintext to 20 KiB. These protocol bounds must be tested against the intended tailnets.

The setup service accepts USB-subnet clients only, verifies Host/Origin, and requires JSON for mutations. Traffic returning from a tunnel must match an outbound flow belonging to that same membership and peer. Remote peers enforce their Tailscale ingress policy; this preview exposes no inbound tailnet service or route between memberships. It does not implement the full reference client's policy/capability surface or Tailnet Lock. The screen is not driven by this alternative firmware yet.

## Build and validate

Source the pinned ESP-IDF v5.5.5 environment and run `tools/build-gateway.sh` from this project. It builds the actual gateway, runs router and fragmented HTTP/2 map tests under ASan/UBSan, and packages `dist/` for the companion. The existing `AUDIT.md` and `audit-result.json` describe the historical unmodified runtime baseline, not current active-session memory. No physical flashing is performed by the build script.
