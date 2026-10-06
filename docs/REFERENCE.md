# Reference

Full technical detail. For setup, start with the [README](../README.md).

One firmware for the **original LILYGO T-Dongle-S3 with 160x80 screen** (ESP32-S3, 16 MB flash, no PSRAM): ESP-IDF + TinyUSB CDC-NCM network plus a CDC-ACM serial console, and two runtime modes.

| Mode | Data plane | Host address |
|---|---|---|
| `wifi_bridge` (default) | Transparent layer-2 forwarding between the Wi-Fi station and the USB NCM link (`components/tdongle_runtime/l2.c`). Same station MAC on both sides. No NAT, no DHCP server. | From the upstream Wi-Fi network |
| `tailnet_gateway` | Router on `192.168.77.0/24` with DHCP/DNS on the USB side, NAPT to Wi-Fi and WireGuard membership contexts (`alternative/tailnet`). Setup service at `http://192.168.77.1/` (USB clients only). | From the dongle |

Only the selected data plane starts. Both modes share eight saved Wi-Fi networks, boot/recovery reporting, chip temperature and bounded memory diagnostics. The design record is [unified runtime review](investigations/unified-runtime-review.md); the archived bridge-only firmware (v0.1.x) is described in [legacy/README.md](../legacy/README.md).

## Selecting and persisting the mode

`mode wifi_bridge|tailnet_gateway` on the serial console, the setup service's `/command` action `mode`, or the companion app (Help, Mode). The choice is stored as the `mode` byte of NVS namespace `tn_settings` and the dongle restarts. A device that has never saved a mode boots in **Wi-Fi bridge mode**, except an install that already holds tailnet memberships (a tailnet build older than the mode switch), which keeps running the gateway until a mode is chosen (`components/tdongle_runtime/mode_store.c`, tested in `tests/test_mode_store.c`).

## Upgrading from v0.1.x

The partition table is unchanged (NVS `0x9000`, app `0x20000`), so a flash that declines erase keeps saved data. v0.1.x stored its networks in NVS namespace `adapter`, key `config` (blob of `settings_t`, schema version 1). On first boot with no `tn_settings/wifi_profiles` entry, the unified firmware imports valid networks from that blob without modifying it, and persists them on the next explicit save (`alternative/tailnet/main/wifi_profiles.inc`, tested in `tests/test_wifi_profiles.c`). The old adapter namespace is left untouched. Not carried over: profile priority and the preferred slot (the strongest saved network is chosen), display settings, and crash counters.

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
| `list`, `use N`, `del N`, `scan` | Saved networks (`*` marks the one in use), switch, delete, scan |
| `profile {"slot":N,"priority":50,"name":"..","ssid":"..","password":".."}` | Save a network to slot N (1 to 8; `list` count + 1 adds one) |
| `mode wifi_bridge|tailnet_gateway` | Save the mode and restart |
| `reboot`, `bootloader`, `boot-status`, `retry-startup` | Restart, ROM loader, startup report, clear recovery |

Diagnostics images add `memory`, `members`, `cpu`, `wifistats`.

## Known differences from v0.1.x

The unified image has no setup access point or captive portal, no button menu or factory-reset gesture, no APA102 status light, no Traffic/Health/Setup screen pages and no brightness/rotation settings. See the release notes of the combining change for the full parity audit. Wi-Fi is provisioned over USB (flash page, app or serial). USB product string is now `T-Dongle-S3 tailnet gateway` in both modes (was `T-Dongle-S3 NCM`).

## Troubleshooting

- **USB absent:** use ROM BOOT recovery; verify the power/data port and board revision.
- **USB enumerates but no address (bridge mode):** `status` should show `usb_transport_ready=1`; check the host interface MAC and carrier and the router's lease table. In tailnet mode the host must take a DHCP lease from `192.168.77.1`.
- **Associated but no internet:** the firmware does not probe the internet. Check routes and DNS on the host and the upstream network.
- **Power resets:** the USB descriptor requests 500 mA; measure the 5 V rail on the actual host.
- **Storage error:** do not auto-erase; recover with ROM tools and read the flash before erasing.

Read-only host evidence: `python3 tools/host_diagnostics.py > host-evidence.json` (add `--adb` on an authorized Android host). It includes MACs and addresses; review before sharing. The [acceptance checklist](ACCEPTANCE.md) covers downstream coexistence, recovery and soak.
