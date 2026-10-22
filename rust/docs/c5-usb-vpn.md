# C5 USB VPN development build

This experimental C5 binary is based on the Rust 0.4.0-rc2 integration branch at `bf18c5e0d078d10ac0e847f144237e84d02f82dc`, not the legacy ESP-IDF application. The inherited workspace version still says 0.3.0-dev; the integration release record is `release-0.4.0-rc2.md`. The S3 firmware is unchanged.

## Architecture decision

The ESP32-C5 USB Serial/JTAG peripheral cannot implement the S3 USB NCM device. The Android companion uses Android USB Host APIs and a consented foreground VpnService: Android TUN → bounded serial IPv4 frames → existing Rust NAPT and Wi-Fi multiplexer → upstream Wi-Fi. Return traffic follows the reverse path. This is routed IPv4, not the S3 MAC-adopting L2 adapter. It occupies Android's VPN slot and does not provide Android hotspot/tethering integration. No root, kernel driver, PPP daemon, or upstream administrative server is required.

The new code reuses `tdongle-tailnet-usbnet` NAPT, `tdongle-tailnet-wifimux`, embassy-net DHCP, the existing vendored esp-hal, and esp-radio. Dependencies are pinned by the separate C5 Cargo.lock; existing licenses and vendored notices remain applicable. The new crate inherits the workspace license. No Arduino board application, fonts, or display driver was copied.

## Build

Install Rust 1.98.1 with `riscv32imac-unknown-none-elf` and espflash 4.6.0. From the repository root:

```sh
cargo +1.98.1 test --locked --manifest-path rust/Cargo.toml -p tdongle-serial-ip -p tdongle-tailnet-usbnet -p tdongle-tailnet-wifimux -- --test-threads=1
rust/tools/build-c5.sh
```

The script never accesses a device. It builds a release ELF and uses espflash's pinned C5 bootloader to generate `rust/dist/tdongle-c5-vpn-0.4.0-rc2/{app.bin,merged.bin,firmware.elf,partitions.csv,SHA256SUMS}`. Flash settings are C5, 16 MB, DIO, 40 MHz. `merged.bin` is a complete image for offset 0; `app.bin` belongs at 0x20000 with this partition table. Do not use the S3 installer or flash offsets from another image. Confirm the physical C5 board and preserve existing firmware/settings before an explicitly authorized flash. BOOT held while plugging in remains the ROM recovery path. This session performed no flashing.

## Serial-IP version 1

SLIP END (c0) delimits frames; escape c0 as db dc and db as db dd. Each encoded frame starts and ends with END. Unescaped bytes are `54 44 01 kind | session:u64be | payload_length:u16be | payload | crc:u16be`. CRC16-CCITT uses polynomial 0x1021, initial 0xffff, no final xor, covering header and payload. MTU is 1500; raw maximum is 1516 bytes. Corrupt, oversize and malformed frames are discarded with delimiter resynchronization. CRC and nonce provide corruption/stale-session protection, not authentication or encryption against a malicious USB peer.

Kinds: HELLO=1, IDENTITY=2, JOIN=3, STATUS=4, IP=5, STOP=6, PING=7. Android generates a nonzero random session nonce. HELLO clears old forwarding state and returns ASCII `TDONGLE-C5 0.4.0-rc2 serial-ip/1`. Only then does Android send JOIN: one SSID byte length, UTF-8 SSID (1–32 bytes), then password (empty for open or 8–63 printable ASCII bytes for WPA2). STATUS is five bytes: code (0 waiting, 1 associated with DHCP address, 2 invalid configuration, 3 join failed), followed by IPv4 DNS. DHCP DNS is used, with 1.1.1.1 fallback when none is supplied. No Internet probe is implied.

Android uses 192.168.77.2/32 on its TUN. Outbound source and inbound destination are checked. Firmware rewrites traffic through the reused NAPT, which retains its protocol/fragmentation limitations. Android sends heartbeat every second; firmware expires the session after ten seconds. Control and packet queues are bounded separately. Link/session changes clear NAPT and queued multiplexer state. Android terminates the VPN on link loss, DNS change, detach, timeout or revocation; the user reconnects explicitly. Normal Android networking then resumes: this is not a kill switch.

## Scope and verification

This is a headless transport build: no C5 screen/buttons/LEDs, saved profiles, provisioning portal, tailnet tunnel, or OTA. Credentials are session-only, never intentionally logged or written to NVS; volatile driver memory is not guaranteed to be securely erased. Wi-Fi currently configures open or WPA2 personal authentication. C5 radio band/channel compatibility must be checked on hardware. Queues have four packets, NAPT has 64 flows, heap allocation is 160 KiB; actual runtime headroom and throughput have not been measured.

Host tests cover encoding, CRC, malformed input recovery, credentials, IPv4 validation, and a synthetic outbound/return flow through the actual NAPT. Rust and Java share a golden wire vector. Passing these tests does not establish physical USB, Wi-Fi, Android VPN or TeslaAndroid compatibility.

Physical acceptance: confirm C5 revision; explicitly flash; install the companion preview; grant USB and VPN consent; verify the identity handshake and DHCP; test DNS, TCP, UDP and real Internet traffic; verify IPv6 cannot bypass the tunnel; test unplug, revoke, wrong credentials, AP loss, changed subnet, process death and reconnect. Verify S3 management still works after leaving C5 mode. Measure bidirectional throughput, drops, heap and an overnight soak. TeslaAndroid's existing AP and downstream clients require a separate test: ordinary VpnService does not automatically route tethered clients through this tunnel.

Local validation on 2026-10-22: C5 release build succeeded (app image 580,048 bytes); 114 Rust tests passed, zero failed, two existing documentation examples ignored. Workspace rustfmt check and serial-IP clippy with warnings denied passed. These are local results; the added CI workflow has not yet been observed running. Android validation: 99 core and 55 app unit tests passed; debug APK assembly and lint succeeded, with 70 lint warnings. No hardware tests performed.
