# Reference

Full technical detail. For setup, start with the [README](../README.md).

One firmware for the **original LILYGO T-Dongle-S3 with 160x80 screen** (ESP32-S3, 16 MB flash, no PSRAM): ESP-IDF + TinyUSB CDC-NCM network plus a CDC-ACM serial console, and two runtime modes.

| Mode | Data plane | Host address |
|---|---|---|
| `wifi_bridge` (default) | Transparent layer-2 forwarding between the Wi-Fi station and the USB NCM link (`components/tdongle_runtime/l2.c`). Same station MAC on both sides. No NAT, no DHCP server. USB product string `T-Dongle-S3 NCM`, as v0.1.x. | From the upstream Wi-Fi network |
| `tailnet_gateway` | Router on `192.168.77.0/24` with DHCP/DNS on the USB side, NAPT to Wi-Fi and WireGuard membership contexts (`alternative/tailnet`). Setup service at `http://192.168.77.1/` (USB clients only). USB product string `T-Dongle-S3 tailnet gateway`. | From the dongle |

Only the selected data plane starts. Both modes share eight saved Wi-Fi networks, the setup access point, the button menu, the status light, the screen pages, boot/recovery reporting, chip temperature and bounded memory diagnostics. The design record is [unified runtime review](investigations/unified-runtime-review.md); the archived bridge-only firmware (v0.1.x) is described in [legacy/README.md](../legacy/README.md).

## Selecting and persisting the mode

`mode wifi_bridge|tailnet_gateway` on the serial console, the setup service's `/command` action `mode`, or the companion app (Help, Mode). The choice is stored as the `mode` byte of NVS namespace `tn_settings` and the dongle restarts. A device that has never saved a mode boots in **Wi-Fi bridge mode**, except an install that already holds tailnet memberships (a tailnet build older than the mode switch), which keeps running the gateway until a mode is chosen (`components/tdongle_runtime/mode_store.c`, tested in `tests/test_mode_store.c`).

## Upgrading from v0.1.x

The partition table is unchanged (NVS `0x9000`, app `0x20000`), so a flash that declines erase keeps saved data. v0.1.x stored everything in NVS namespace `adapter`, key `config` (blob of `settings_t`, schema version 1: eight slots of name, SSID, password and priority, the preferred slot, brightness, rotation and dim time). The unified firmware **reads that blob and never changes it** until a factory reset, and carries every field (`main/legacy_import.c`, layout pinned by `tests/test_legacy_import.c`):

| v0.1.x | Unified |
|---|---|
| SSID and password of each slot | `tn_settings/wifi_profiles` (format unchanged since the first unified build) |
| Display name and priority per slot | `tn_settings/wifi_meta`, keyed by SSID (`main/wifi_meta.c`) |
| Preferred slot | the same blob: the preferred network, by SSID |
| Brightness, rotation, dim time | `tn_settings/display` |

Until the first explicit save (a `profile`, a `use`, a save from the setup page or the app) the import simply repeats at each boot and gives the same answer; the first save moves the networks and metadata to the unified keys and leaves the old blob alone. An install that already ran an earlier unified build (networks saved without metadata) still finds its v0.1.x priorities in the old blob and keeps them. Differences that remain: slots are a packed list (empty slots are skipped, so slot numbers after a gap move up by one; the preferred slot follows its network); a network whose SSID repeats in two slots keeps the first slot's data (the store is keyed by SSID); the crash counters are not carried (they are RAM tallies).

`wifi_profiles` is deliberately unchanged, so a build that knows nothing of the metadata can still read it (a downgrade): it ignores `wifi_meta` and `display`, and a list it edits is matched back to the metadata by SSID.

## Setup access point

Hold the button (menu: **Enter setup AP**), type `setup` on the serial console, or plug in a dongle with no network saved: it restarts into a **setup boot** (`main/setup_boot.c`; the request survives the restart in RTC memory, only after a software reset with a valid magic). A setup boot runs the access point and the HTTP server and **nothing else**: no bridge, no tailnet runtime, no DNS or NAT, no manager. That is what keeps the access point out of the tailnet heap budget; see [ADR 0024](../alternative/tailnet/docs/adr/0024-setup-access-point-front-panel-and-usb-identity.md).

- **Network:** open (`CONFIG_TDONGLE_SETUP_AP_OPEN`, default y: owner decision, guarded by `tests/test_open_ap.py`), `TDongle-XXXXXX` from the station MAC, channel 1, two clients, `192.168.4.1/24`. Turn the option off for a random WPA2 password that the screen shows.
- **Captive portal:** the DHCP server names the dongle as DNS; the DNS server (`main/captive_dns.c`, bound to 192.168.4.1 only) answers every A query with the dongle and any other type with an empty answer; every unknown URL redirects to `http://192.168.4.1/`. No DHCP option 114 (RFC 8910 requires an HTTPS API with a valid certificate).
- **Page and API:** the same HTTP server as the USB setup page. `GET /` serves `setup_ap.html` with a per-boot token; the page uses `GET /wifi-scan` (asynchronous here: it polls until `busy` clears), `GET /wifi-saved` and `POST /command` with the actions `wifi` (ssid, password, optional name, slot, priority), `wifi_remove` and `setup_done`. Rules in `main/setup_access.c`: a client of the setup network can reach **only** those three endpoints and actions, never `/status`, `/diagnostics`, `/boot-status`, tailnet memberships (their sign-in keys), or the routing mode; the request must carry `X-Setup-Token` and the canonical `Host: 192.168.4.1` (a phone's captive-portal probes arrive with arbitrary host names and are redirected, not served). USB clients are unchanged.
- **Limits of the open network:** a setup boot creates no USB netif and runs no NAT, so the setup network has no route to the USB host (in either mode the USB setup page is not served during setup). A client may add networks and delete them, but not set a name or priority, replace a saved network, or read priorities; requests are classified by source subnet, the connection's local address and `Host`/`Origin`. The setup boot arms an `esp_timer` failsafe in `app_main` that restarts into normal mode even if USB/console init failed. Threat model: ADR 0024.
- **Closing:** after 10 minutes (`SETUP_SESSION_MS`, counted from the boot, not from the access point coming up), on the page's **Done**, on `cancel`, or from the menu (**Cancel setup AP**), the dongle restarts into its normal mode; if the access point has not come up 30 s into the boot it leaves at once (`setup_session_should_end`). A crash-loop recovery boot never opens setup. While setup is open `use N` is refused and the menu lists no saved networks (the one radio belongs to the access point).
- **Not ported:** v0.1.x's 45-second candidate trial when replacing a saved network (the new network is saved at once; the old one is lost if it is overwritten), and the `portal` serial trace.

## Front panel

Everything below is polled by the `gateway_control` task between commands (`device_ui.inc`): no task of its own, because a task would cost about 3 KB of the heap the tailnet admission budget is measured against. A long serial command (`scan`, about 3 s) therefore pauses the button, light and screen for that long.

- **Button** (GPIO0, `main/core.c` debounce 30 ms, hold 1.5 s): short = next page, hold = menu (`main/menu.c`). A press while the backlight is dimmed only wakes it. Menu items: Enter or Cancel setup AP, each saved network (`use N`), Factory reset (hold, then hold again within 10 s: `reset`, `confirm-reset`), Exit. Factory reset erases the saved networks, the metadata and display settings (`wifi_profiles`, `wifi_meta`, `display`, the single-network key `wifi`, and the old `adapter` namespace, which would otherwise be imported again); **the mode and tailnet memberships are kept**. It then restarts into setup.
- **Light** (APA102, GPIO39 clock, GPIO40 data; `main/led.c`): breathing blue (setup or nothing saved), breathing amber (joining or waiting for the USB side), green with an arrival glow, two red blinks (network not found or password refused, reasons 201, 202, 15; tailnet failure), breathing cyan (tailnet sign-in), slow red (recovery mode).
- **Screen pages** (`lcd_view.c`): Connection, Traffic, Health, Setup, each with the v0.1.1 content that exists in this firmware; the setup access point screen, INSTALLING, STARTING and RECOVERY replace the page, the menu replaces everything. Traffic counts frames at the two TinyUSB NCM callbacks (link-time wrappers, `main/traffic_hooks.c`), so it is identical in both modes and touches neither data path. The host's IP address, shown by v0.1.1 on the Connection page, is not: it needed a hook in the bridge's receive path.
- **Display settings:** `display BRIGHTNESS ROTATION DIM_SECONDS` (5 to 100, 0 or 1, 10 to 3600), no arguments to read; stored in `tn_settings/display`, applied on the next screen refresh (backlight by LEDC PWM on the active-low pin, rotation by the panel mirror flags).

## Roaming assist and the Wi-Fi station

Every saved network is joined with the v0.1.1 station configuration (`wifi_fill_station`): scan all channels and take the strongest access point of the SSID, WPA3 (SAE both methods) and protected management frames, no access point weaker than WPA2 for a network with a password, and **802.11k neighbour reports plus 802.11v BSS transition requests** so the network can steer the dongle to a better access point. Self-initiated roaming stays off (an RSSI-only rule ping-ponged between two similar access points on v0.1.x). The support is built into the image (`sdkconfig.defaults`: `CONFIG_ESP_WIFI_11KV_SUPPORT`, `RRM`, `WNM`) and **requested per mode**: in bridge mode always; in tailnet mode only with `CONFIG_TDONGLE_WIFI_ROAMING_TAILNET` (default off: a roam briefly drops the link and the tunnels, and the tailnet heap margin has not been measured with it on). Bridge mode also restores the v0.1.1 radio profile: 20 MHz channels and maximum transmit power. `status` reports `wifi_prefs ... roaming_assist=N roams=N` (a roam is an association to a different access point than the previous one).

Which saved network is joined (`wifi_policy.h`): the preferred network if usable (`-85 dBm` or stronger), then the highest priority (0 to 100, default 50), then the strongest signal. With every priority at 50 and no preferred network (a fresh install) that is the strongest network, as before. A healthy link (`-75 dBm` or stronger) is never left, a weaker one only for a candidate 12 dB stronger, and a network chosen with `use N` stays pinned for the session. `use N` also makes N the preferred network.

## USB product string

`T-Dongle-S3 NCM` in bridge mode (byte for byte v0.1.x: a Mac or Pi keeps the adapter's network service name and its place in the service order), `T-Dongle-S3 tailnet gateway` in tailnet mode (as the gateway always enumerated; its USB MAC pair differs anyway, so a host sees a different interface). Manufacturer (`T-Dongle Adapter Project`) and serial (the station MAC) are the same in both modes. `usb_identity.h`, `tests/test_usb_identity.c`. A mode switch restarts the dongle, so the string is chosen once per boot.

## Build

Linux/macOS prerequisites: Git, Python 3.10+, CMake, Ninja, a native C compiler, Go 1.24 (control-protocol interoperability test), several GB of disk.

```sh
./tools/bootstrap.sh
. "$HOME/.cache/tdongle/esp-idf-v5.5.5/export.sh"
./tools/test.sh                                # host tests
alternative/tailnet/tools/test-gateway.sh      # gateway and runtime host tests
components/tdongle_runtime/tests/run.sh        # runtime component tests (also run by the line above)
./tools/build.sh                               # release image: build, check, package
./tools/build.sh diagnostics [--queue-depth N] # memory-evidence image, never shipped
./tools/ci.sh [all|release]                    # what CI runs
```

IDF v5.5.5 commit `b774170ff46c393eeb5e495ea37936038d3f4f4f`; TinyUSB `0.21.0~2`. Exact commits, registry hashes and per-file licenses are in [source audit](SOURCE_AUDIT.md), [dependencies.lock](../dependencies.lock) and [attribution](THIRD_PARTY.md). Build scripts reject a different IDF commit and give every build directory its own sdkconfig. Defaults come from `alternative/tailnet/sdkconfig.defaults` then the root `sdkconfig.defaults` (board flash settings); the diagnostics image adds `sdkconfig.diagnostics`.

### Version

One source: the `VERSION` file (a development value such as `0.3.0-dev`), overridden by the `TDONGLE_VERSION` environment variable, which the release workflow sets from the git tag (`v0.3.0` gives `0.3.0`). The root `CMakeLists.txt` turns it into the ESP-IDF app version and the firmware's `GATEWAY_VERSION` (serial `status` `firmware=`, setup `/status`, screen footer). `tools/package.py` reads the version back from the build, so package names, `manifest.json` and the binary cannot disagree.

### Package

`tools/build.sh` writes `dist/tdongle-VERSION/` and `dist/tdongle-VERSION.tar.gz` (+ `.sha256`): `bootloader.bin`, `partition-table.bin`, `app.bin`, the ELF, effective `sdkconfig`, `manifest.json` (version, commit, dirty flag, offsets, flash parameters), `android-firmware.json` (companion payload), `FLASH.txt`, dependency notices and `SHA256SUMS`. `tools/check_build.py` fails the build unless the **bootloader and app image headers carry DIO, 40 MHz, 16 MB**, the partition table keeps NVS/PHY/app at their offsets, the effective sdkconfig matches, and the linked USB descriptors contain NCM and ACM. Scripts never flash.

| Offset | File |
|---|---|
| `0x0` | `bootloader.bin` |
| `0x8000` | `partition-table.bin` |
| `0x20000` | `app.bin` (4 MiB partition) |

## First flash and recovery

1. Confirm an original T-Dongle-S3 (not Dual/Plus) and its [pin map](../main/board.h). Target is ESP32-S3, 16 MB flash written as **DIO at 40 MHz**: the tested unit (Winbond W25Q128) boot-loops at QIO 80 MHz, and ESP-IDF's own default for this target is 80 MHz, hence the explicit pin in `sdkconfig.defaults`.
2. If the firmware is running, `tools/flash.sh` (or the flash page's *Prepare for update*) sends the `bootloader` console command and writes the package without the button. Otherwise hold **BOOT while plugging in** for the ROM loader.
3. Manual write, from the package directory: `python -m esptool --chip esp32s3 --port PORT write_flash --flash_mode dio --flash_freq 40m --flash_size 16MB 0x0 bootloader.bin 0x8000 partition-table.bin 0x20000 app.bin`. Do not erase for an update: NVS holds Wi-Fi networks, the mode and tailnet identities.
4. Unplug and replug without BOOT.

If NVS cannot initialize the firmware does not erase it. A boot that crashes repeatedly enters recovery (services off, USB console on); `retry-startup` or the app's Restart services clears it.

## Release

Pushing a `v*` tag runs `.github/workflows/release.yml`: host and gateway tests, the release build with `TDONGLE_VERSION` from the tag, a check that tag, manifest, flash parameters and the embedded `firmware=` string agree, then a GitHub release (tarball, checksum and the three images) and the flash page on `gh-pages`. `workflow_dispatch` is a dry run that builds and verifies but publishes nothing. `build.yml` runs `tools/ci.sh all` (including the diagnostics image) on PRs and main. Both use the prepared ESP-IDF fleet runner when the repository variable `LOCAL_LINUX_CI_ENABLED` is `true`, else a GitHub-hosted runner that bootstraps IDF.

The flash page (`site/index.html`, `tools/site.py`) lists bootloader, partition table and app at their own offsets; a merged image is deliberately not used because it would overwrite NVS. The page also has an *Add a Wi-Fi network* card that sends `list` and `profile` over Web Serial to the running firmware.

## Serial console (115200 baud, CDC-ACM, no echo)

| Command | Both modes |
|---|---|
| `help`, `status`, `capabilities`, `pm` | Mode-aware help; `status` reports `mode=adapter|tailnet`, Wi-Fi state, RSSI, USB state, `firmware=`, uptime, heap, chip temperature, clock and Wi-Fi link counters |
| `list`, `use N`, `del N`, `scan` | Saved networks (`N* name=.. ssid=.. priority=..`, `*` marks the one in use), switch (and prefer) N, delete, scan |
| `profile {"slot":N,"priority":50,"name":"..","ssid":"..","password":".."}` | Save a network to slot N (1 to 8; `list` count + 1 adds one) |
| `mode wifi_bridge|tailnet_gateway` | Save the mode and restart |
| `setup [N]`, `cancel` | Restart into the setup access point (N preselects saved network N for replacement); `cancel` leaves setup (a no-op otherwise, as clients send it after `profile`) |
| `reset`, `confirm-reset` | Factory reset in two steps: `reset`, then `confirm-reset` within 10 seconds |
| `display [BRIGHTNESS ROTATION DIM_SECONDS]` | Show or set the display settings (5 to 100, 0 or 1, 10 to 3600 s) |
| `reboot`, `bootloader`, `boot-status`, `retry-startup` | Restart, ROM loader, startup report, clear recovery |

`status` also prints, on their own lines so no existing parser changes, `wifi_prefs` (saved, preferred, priorities, roaming assist, roams), `display`, `setup` and `traffic` (USB-side byte and frame counters, rates, bus resets, `control_stack_free_bytes`: the control task's lowest free stack). `mode=` is `setup` during a setup boot.

Diagnostics images add `memory`, `members`, `cpu`, `wifistats`.

## Known differences from v0.1.x

What the unified image does differently on purpose:

- The 45-second **candidate trial** when replacing a saved network is not ported (a network is saved at once; the setup page says so).
- **Crash loops** enter recovery mode (services off, USB console on, the screen and light say RECOVERY) instead of v0.1.x's drop into the ROM loader after three crashes; the Health page still shows boots, watchdog resets and panics.
- Slots are a **packed list** (see Upgrading), `status` has the unified format (`firmware=`, temperature, extra lines), and `mode=` says `adapter` for the bridge.
- The Connection page does not show the **host's observed IP address**, and the Traffic page shows frames, not drops: both would need a hook in the bridge's data path, which is owned elsewhere.
- NCM transfer blocks are 2 x 3,200 B (v0.1.x: 4 x 6,400 B); their effect on throughput is being measured separately.
- The setup page's trace tool (`portal` console command) is not ported.

## Troubleshooting

- **USB absent:** use ROM BOOT recovery; verify the power/data port and board revision.
- **USB enumerates but no address (bridge mode):** `status` should show `usb_transport_ready=1`; check the host interface MAC and carrier and the router's lease table. In tailnet mode the host must take a DHCP lease from `192.168.77.1`.
- **Associated but no internet:** the firmware does not probe the internet. Check routes and DNS on the host and the upstream network.
- **Power resets:** the USB descriptor requests 500 mA; measure the 5 V rail on the actual host.
- **Storage error:** do not auto-erase; recover with ROM tools and read the flash before erasing.

Read-only host evidence: `python3 tools/host_diagnostics.py > host-evidence.json` (add `--adb` on an authorized Android host). It includes MACs and addresses; review before sharing. The [acceptance checklist](ACCEPTANCE.md) covers downstream coexistence, recovery and soak.
