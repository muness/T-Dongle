# T-Dongle-S3 Wi-Fi → USB Ethernet adapter

Development firmware for the **original LILYGO T-Dongle-S3 with 160×80 screen**. ESP-IDF + TinyUSB CDC-NCM, optional CDC-ACM console, Wi-Fi profiles, local browser setup, four status pages and APA102 state LED. No PSRAM, microSD, extra controller or Android companion app.

**Compiled and host-tested is not hardware-validated.** See [validation results](docs/VALIDATION.md) for exact builds/tests and pending checks. No claim of TeslaAndroid compatibility or throughput has been established on physical hardware. The user's existing Pi 400/TeslaAndroid installation is treated as working and must not be reconfigured to accommodate an unverified dongle.

```
Router / phone hotspot (2.4 GHz)
           ↕ Wi-Fi station
      T-Dongle-S3 (status LCD)
           ↕ USB CDC-NCM
       Pi 400 / TeslaAndroid
           ↕ existing Wi-Fi AP
          display clients
```

The Pi obtains its address from the upstream router. This is a **single-host, station-MAC-sharing L2 forwarder**, not a general bridge or NAT router. The Pi must use the advertised station MAC on its USB interface; its existing client routing remains TeslaAndroid's responsibility. [Architecture and setup-mode decisions](docs/ADR-001.md).

## Build from pinned sources

Linux/macOS prerequisites: Git, Python 3.10+, CMake, Ninja, standard ESP-IDF prerequisites and a native C compiler for host tests. Disk budget: several GB. No project files contain development-machine paths.

```sh
./tools/bootstrap.sh
# Source the export.sh path printed by bootstrap:
. "$HOME/.cache/tdongle/esp-idf-v5.5.5/export.sh"
./tools/test.sh
./tools/build.sh full
./tools/build.sh headless
./tools/build.sh network-only
```

IDF v5.5.5 commit `b774170ff46c393eeb5e495ea37936038d3f4f4f`; Espressif integration 2.0.1 vendored with small reviewed fixes; TinyUSB `0.21.0~2`; LVGL `9.3.0`. Exact commits, registry hashes and per-file licenses are in [source audit](docs/SOURCE_AUDIT.md), [dependencies.lock](dependencies.lock), and [attribution](docs/THIRD_PARTY.md). Do not run dependency update as part of a reproducibility check. Build scripts reject a different IDF commit and isolate sdkconfig per variant. Reproducible-build mode removes compile timestamps; cross-machine bit identity is not claimed without comparison.

Successful builds generate `dist/tdongle-0.1.0-VARIANT/` containing application, bootloader, partition image, ELF, effective sdkconfig, manifest, flash offsets, dependency notices and SHA256SUMS. `dist` is generated/ignored, not a promise that an image already exists. Build scripts **never flash**. `full` has LCD/LED + ACM; `headless` disables LCD/LED for A/B benchmarks but keeps physical controls; `network-only` retains display/browser setup and omits ACM. None adds ECM/RNDIS/NAT. CI builds all three and uploads versioned artifacts.

## First flash and recovery

1. Physically confirm original T-Dongle-S3, board revision, screen and [pin map](main/board.h). The schematic flash label conflicts with product documentation; check chip and flash size using the ROM tools before writing. Target is ESP32-S3, 16 MB QIO flash at 80 MHz, PSRAM disabled. Do not flash Dual/Plus hardware with this image.
2. Hold **BOOT while plugging into USB** to enter Espressif ROM download mode. Identify its port (`/dev/ttyACM…` on Linux, `/dev/cu.usbmodem…` on macOS). Close serial tools.
3. Read-only identification: `python -m esptool --chip esp32s3 --port PORT chip_id` and `python -m esptool --chip esp32s3 --port PORT flash_id`.
4. After authorizing the write yourself, run `idf.py -B build-full -p PORT flash`, or use the exact command in the built package's `FLASH.txt` from that directory. No erase-all is required for an ordinary update. Custom partitions: NVS `0x9000`/64 KiB, PHY `0x19000`/4 KiB, app `0x20000`/4 MiB; remaining flash unused.
5. Unplug/replug **without holding BOOT**. TinyUSB takes over native USB pins 19/20; subsequent reflashing may require holding BOOT while plugging in again. This ROM route remains available even if firmware USB fails.

If NVS cannot initialize, the firmware does not erase it automatically. Use ROM recovery and preserve flash before investigating. Explicit confirmed factory reset clears only the adapter namespace, not PHY calibration. Flash encryption and secure boot are not enabled; saved NVS credentials are plaintext to physical flash access.

## First use: local browser setup

First unconfigured boot starts a temporary password-protected `TDongle-XXXXXX` Wi-Fi AP. The **screen shows the random temporary password** and `192.168.4.1`. Connect a phone/laptop to it, keep the connection despite “no Internet,” then visit **http://192.168.4.1/**. There is no captive DNS redirect and no mandatory QR code. No saved upstream password is displayed or encoded.

Enter slot 1–8, profile name, exact SSID, password and priority 0–100. Save reboots into a 45-second candidate trial. Ten continuous seconds associated commits the replacement; failure retains previous saved profiles and shows an error. This validates association, **not Internet reachability**. Static host addresses are supported; no DHCP success is inferred from a source IP.

Setup is an exclusive mode: NCM link down, forwarding paused, AP DHCP/HTTP active. Cancel or ten-minute timeout reboots to adapter mode. With no saved profile, cancellation leaves it unconfigured until setup is explicitly reopened or the next cold boot. Ordinary network failures do **not** expose a setup AP or erase credentials. Anyone possessing the temporary AP password can configure the device. There is no administrative listener on upstream Wi-Fi.

## Console and terminal tools

Install `python3 -m pip install -r tools/requirements.txt` in a virtual environment, then:

```sh
python3 tools/tui.py --port /dev/ttyACM0
python3 tools/provision.py --port /dev/ttyACM0 --provision
python3 tools/provision.py --port /dev/ttyACM0 --status
```

Use the corresponding `/dev/cu.usbmodem…` on macOS. Explicit port selection avoids probing unrelated devices. Tools prompt for passwords with `getpass`, never accept password command-line arguments, and suppress replies to secret-bearing requests. The firmware does not echo any input. Do not log raw serial input or type credentials into shell history. Tools are optional; normal operation is autonomous.

Any serial terminal at 115200 can type `help` (characters do not echo). Commands:

| Command | Effect |
|---|---|
| `status` / `diagnostics` / `show` | USB and association state, observed IP/age, byte/frame/drop counters, warm crash counts, heaps, task watermarks and bounded event log; no passwords |
| `scan` | One explicit foreground scan; not automatic during a healthy connection. Auth mode numbers use ESP-IDF enum. Unavailable during setup/trial. |
| `list` | Named profiles, SSIDs, priority and active slot, no credentials |
| `profile JSON` | Add/edit a slot through the interactive tool; validates candidate before replacing saved profile |
| `use N` | Save selected preferred slot and reconnect; unavailable during setup/trial |
| `del N` | Delete one slot and save; use tools' confirmation prompt |
| `display 60 0 60` | Brightness 5–100%, orientation 0/1 (opposite landscape), dim timeout 10–3600 s |
| `setup` / `cancel` | Enter/leave temporary AP by reboot |
| `reset`, then `confirm-reset` within 10 s | Explicit credential/settings reset |
| `reboot` | Restart with saved state |

Writes are configuration-only, spaced at least two seconds for regular settings. There is no `save` needed after validated profile submission, selection, deletion or display settings. Profiles use versioned NVS blobs; unknown/corrupt schema is reported and protected against overwrite until explicit reset. Add/edit uses a separate consumed candidate key so a power interruption cannot replace working credentials before validation. Eight slots total; replacing an existing slot preserves its old contents through trial.

Preferred slot is tried first at boot, then remaining slots by descending priority. A failed attempt gets a 15-second join window plus bounded backoff of 1–30 seconds; once all slots are exhausted the cycle repeats. There are no background scans or preferred-network oscillations while associated. A newly available preferred AP is tried after a failure cycle or explicit selection. SSID/name/password are currently **printable ASCII only**: name 1–24, SSID 1–32, WPA passphrase 8–63 characters, or empty for an open network. Raw 64-hex PSKs, WEP, enterprise/EAP, Unicode SSIDs, 5 GHz and VLAN trunking are unsupported. WPA2-PSK and WPA3-SAE/transition are configured; each authentication mode still needs AP testing. Country uses the driver's conservative default/802.11d; no hardcoded region override.

## Screen, button and LED

Short press cycles **Connection → Traffic → Health → Setup**. Debounce: 30 ms. Runtime hold: 1.5 seconds, fires once until release. A dimmed screen consumes the **entire first gesture** to wake without performing an action. BOOT held at power-on retains ROM behavior.

Hold opens the setup/profile menu; short press advances, release then hold selects. Entries: enter/cancel setup AP, slots 1–8, factory reset, exit. Factory reset requires selecting its entry, releasing, then a second deliberate hold within ten seconds; short press cancels. Empty slot selection is rejected without altering credentials.

| Page | Meaning |
|---|---|
| Connection | SSID/RSSI, USB `ENUM` (configured transport) versus `WAIT`/`SUSP`, association, **observed** host IPv4 and age/expiry; Internet always “not checked.” Last connection error is shown when no fresh address. |
| Traffic | D = Wi-Fi → Pi USB, U = Pi USB → Wi-Fi. Mb/s from byte deltas/time, decimal MB session totals, forwarded/dropped frames and 8-second rolling aggregate-rate graph (autoscaled). Per-cause and reflection counts are in diagnostics. |
| Health | Three detail groups rotate every four seconds: device/connection uptime, join attempts and last disconnect reason, actual USB bus resets; current/minimum heap and reset reason; warm boot/watchdog/panic counts and last notice. |
| Setup | Active named profile, trial status and setup instructions. In AP mode, temporary SSID/password/URL replace normal pages. |

Long SSIDs/addresses are clipped within fixed 156×13 pixel rows. Full IPv6 source observations (including link-local/ULA) and freshness are available in console diagnostics; they do not overwrite LCD fields. [Synthetic layout previews](docs/preview-0.svg) use the actual text formatter with an approximate browser font, **not runtime measurements or hardware screenshots**.

Backlight is active-low PWM at 1 kHz, default 60%, dims to 5% after 60 seconds. Orientation selects either landscape direction. APA102: blue = unconfigured/setup; blinking amber = joining/waiting for USB; green = associated **and USB transport ready**, not Internet verified; red = common no-AP/auth failure. Optional LED/display errors do not abort network startup. SPI timeout disables further rendering while retaining any in-flight DMA buffer.

## Troubleshooting and physical validation

- **USB absent:** use ROM BOOT recovery, verify power/data port and actual board revision. Try network-only build only after recording the composite enumeration failure.
- **USB enumerates but no address:** record host interface MAC, driver, NCM carrier, Wi-Fi status, DHCP/ARP and router lease evidence. `ENUM` does not claim the host interface is configured. Do not add NAT to mask this.
- **AP not found:** check 2.4 GHz, exact case/SSID, channel/region, hotspot availability and antenna clearance near the Pi. Source observations clear/expire; old addresses are not current leases.
- **Auth failed:** correct password/auth mode through a staged profile. WPA3 behavior, static IP, multicast/IPv6 and captive-portal networks need explicit tests. Adapter does not solve a captive portal for the host.
- **No Internet but associated:** check Pi routes/DNS and upstream access. The IP-less adapter does not invent its own probes. Check a real downstream TeslaAndroid browser client as well as the Pi.
- **Power resets:** hardware docs specify up to 800 mA while USB2 descriptor requests 500 mA. Measure peaks and 5 V rail on the actual Pi. Bus-power budget and suspend compliance are unresolved physical release gates.
- **Display wrong colors/offset:** verify original-board revision, SPI pins and ST7735 panel. Diagnose networking with headless build. Do not connect a WS2812 driver to GPIO38.
- **Storage error:** do not auto-erase. Recover/read flash with ROM tools, investigate, or perform the explicit confirmed factory reset.

Read-only host evidence (unavailable tools/permissions are recorded, not fatal):

```sh
python3 tools/host_diagnostics.py > host-evidence.json
# Only if adb is already available and authorized on the existing Android image:
python3 tools/host_diagnostics.py --adb > teslaandroid-evidence.json
```

No root command, kernel modification, daemon or custom Android app is required by this firmware. Diagnostics include MACs, addresses and other network metadata; review before sharing. [Acceptance/benchmark checklist](docs/ACCEPTANCE.md) covers downstream coexistence, recovery, provisioning failure cases and overnight soak. Do not reflash attached hardware or change the working TeslaAndroid network without explicit owner confirmation.
