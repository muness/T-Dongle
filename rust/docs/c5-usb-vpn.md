# C5 shared gateway preview — Rust 0.4 base

This experimental branch uses the Rust 0.4 integration base `bf18c5e0d078d10ac0e847f144237e84d02f82dc`. C5 now compiles the **same application entry point** as S3, rather than a separate NAPT demo. It includes the shared profile manager, LCD/button UI, settings, diagnostics, HTTP configuration and tailnet runtime. No hardware has been flashed or tested for this change.

## Modes and shared configuration

* **USB / Android VPN** (default): C5 USB Serial/JTAG carries IPv4 to the companion's foreground VpnService. Connect with Wi-Fi fields blank to use saved profiles; select **Wi-Fi & tailnets** to configure the same saved registry and identities used by S3. Entering credentials on the connection screen explicitly saves them on the dongle. Local management is available before upstream Wi-Fi connects.
* **Wireless gateway**: select this in the same configuration page's routing selector, or issue `gateway wireless` through the framed console. The dongle acknowledges and restarts. Its WPA2 AP identity/password appear on the Setup screen; open `http://192.168.77.1`. The AP starts even without an upstream profile. Up to four associated clients share the runtime. The AP password grants access to management too; this is not an isolated guest network. Select USB mode through that page or use `gateway usb` to return. Android's companion can also use the configuration page while connected to this AP.

Both modes use **one tailnet registry and the same identity keys**. Three concurrent membership worker sets are enabled in the C5 build. The admission policy can still defer work; successful authentication, routing readiness and useful performance must be verified separately. This is not a promise of three fully loaded tailnets at a particular rate.

USB mode is routed IPv4, not NCM or an L2 bridge. It occupies Android's VPN slot, blocks IPv6, and does not establish TeslaAndroid hotspot/tethered-client routing. Wireless mode also routes IPv4. The local subnet is fixed at 192.168.77.0/24 and must not overlap upstream. Profiles use the shared open/WPA2-Personal path; enterprise authentication is unsupported and WPA3-only operation is not advertised. C5's single radio does not provide simultaneous independent 2.4/5 GHz links; AP+STA channel/band migration must be tested with the intended clients. No host daemon, root or kernel modification is part of normal operation.

## Board and memory

Target: original LILYGO T-Dongle-C5, ESP32-C5 HR8, 16 MB flash / 8 MB PSRAM. LCD MOSI2, CLK6, CS10, DC3, RESET1, backlight0 active-low; APA102 data5/clock4; BOOT28. MicroSD is disabled. The [LILYGO pin configuration](https://github.com/Xinyuan-LilyGO/T-Dongle-C5/blob/master/include/pin_config.h), [factory example](https://github.com/Xinyuan-LilyGO/T-Dongle-C5/blob/master/examples/Factory/Factory.ino) and [ST7735 implementation](https://github.com/Xinyuan-LilyGO/T-Dongle-C5/blob/master/lib/lcd_st7735/st7735.cpp) were checked for pins, backlight polarity, 20 MHz SPI, inversion and landscape offsets (1,26). Audited revision: `0fe7367959509af38b45bd1b81471018932df625`. No Arduino application or font code was imported. Confirm the physical revision before flashing.

The shared 160×80 renderer provides connection, traffic, health and setup pages, dimming/orientation, profile selection and confirmed reset. Short press cycles pages; the existing deliberate hold/menu gestures are retained. C5's setup view shows local AP credentials and URL; temporary setup also shows expiry. Internet reachability remains “not checked.” C5 temperature is reported unavailable rather than reading S3 registers.

The C5 allocator initializes 8 MB PSRAM, retains 96 KiB internal heap, directs large application allocations to PSRAM, and reserves 32 KiB from small application allocations for internal consumers. Radio and RTOS explicitly allocate internal memory. Tailnet startup asserts its large state is externally allocated. Flash accesses stage NVS/peer-directory data through internal buffers. `gateway` reports initialized PSRAM and current internal free space; `tn-mem`, `status`, and health show runtime evidence. These are allocation rules, not measured runtime headroom. Recovery mode skips PSRAM and radio initialization so a PSRAM boot failure can leave a console available.

## Build and artifacts

Install Rust 1.98.1 with `riscv32imac-unknown-none-elf` and espflash **4.6.0**. Dependencies are locked in `c5-firmware/Cargo.lock`. Build from the repository root:

```sh
cargo +1.98.1 test --locked --manifest-path rust/Cargo.toml --workspace -- --test-threads=1
rust/tools/build-c5.sh
```

For both targets, also install the pinned Xtensa 1.97.0.0 toolchain through espup 0.17.1, source its export file, then run `rust/tools/build-shared-variants.sh`. It builds only; it never accesses a device. C5 output is `rust/dist/tdongle-c5-vpn-0.4.0-rc2/`: application image, merged first-install image, ELF, partition table and `SHA256SUMS`. S3 output remains separate. Verify checksums before use. Do not flash an S3 image to C5 or vice versa.

First installation is a separate physical step requiring confirmation. Hold BOOT while plugging in to enter ROM download mode. A merged image starts at offset 0; an application-only update uses the partition table's factory offset 0x20000 and preserves settings. Never use the bridge helper's default esp32 chip/0x10000 offset for these images. C5 does not use the S3 custom rescue bootloader; a console `bootloader` request explains the physical recovery procedure instead of pretending a normal reset enters ROM.

## Android and console

Companion branch: `feature/c5-usb-vpn`, based on its latest multi-tailnet integration `150e5f5bd14c9e53de187045322e10fa7f6054c1`. Build with JDK17 / Android SDK36:

```sh
./gradlew -Pc5VpnDevelopment=true :core:test :app:testDebugUnitTest :app:assembleDebug :app:lintDebug
```

The development APK is separately packaged as `ai.openhorizonlabs.tdongle.c5vpn`; it does not contain a C5 flashing flow. Grant USB and VPN consent. Disconnect another VPN first. Upstream loss does not remove local setup; service/USB failure tears down the tunnel. Return from the external Tailscale browser sign-in to the shared page to see membership state.

For macOS/Linux management without Android, install pyserial and run:

```sh
python3 rust/tools/c5-console.py /dev/ttyACM0
```

The script verifies the exact C5 identity, maintains the session heartbeat and provides the existing console. `wifi` prompts privately for a password; no shell history contains it. `gateway ap` deliberately reveals only the local gateway password. Ordinary status/diagnostic exports exclude that password. Do not open this tool and the Android VPN on the same USB interface at once.

## Transport contract

SLIP framing, CRC16 and header format remain shared with the host-tested Rust/Java codec. Application identity is now `TDONGLE-C5 0.4.0-rc2 serial-ip/2`; older identity is rejected. Kinds: HELLO1, IDENTITY2, JOIN3, STATUS4, IP5, STOP6, PING7, COMMAND8, REPLY9. Nonzero random session nonce scopes each exchange; stale queued output is discarded. Commands are one bounded printable line; replies use the same console dispatcher.

STATUS code 1 means **local gateway ready**, with DNS 192.168.77.1. It does not mean upstream DHCP, Internet or tailnet readiness. Optional JOIN retains the existing bounded credential encoding but now saves a profile; it is unnecessary on reconnect. HELLO/STOP/lease expiry clear USB host queues and generation in USB mode. USB management disconnects do not reset wireless gateway flows. No packet payload logging is enabled.

## Validation boundary

See [execution evidence](c5-execution.md) for exact current results and [ADR](adr/0003-c5-shared-gateway.md) for decisions. Earlier 580 KB headless C5 packages are superseded by this shared application and must not be confused with it.

Pending physical acceptance: display orientation/brightness and BOOT gestures; PSRAM/radio/flash stress; first provisioning and interrupted saves; three membership login/rekey/reconnect/DERP load; two wireless clients with distinct return traffic; AP+STA band migration; Android USB/VPN consent/revocation, unplug, upstream loss and cold starts; S3 regression; UI-on/off throughput/latency and overnight soak. TeslaAndroid's downstream network remains a separate unverified requirement. No benchmark, radio capacity or end-to-end TeslaAndroid pass is claimed.
