# Physical acceptance and measurement record

**All physical tests below are pending.** No ESP32, Pi 400, macOS host or TeslaAndroid device was accessed in this implementation session. Checkboxes are deliberately unchecked. Keep the existing PIX-LINK available for rollback. Do not change TeslaAndroid routing or flash any device without owner authorization.

## Record before testing

Firmware version, artifact SHA256, board silkscreen/revision and photos, ROM chip/flash identity, flash frequency/mode, host model/OS, TeslaAndroid release/build fingerprint/kernel, USB topology/other loads, AP model/firmware/auth/channel/subnet, signal strength/distance, Pi supply model and measured rail/current. Preserve read-only host evidence before/after. Repository driver presence alone is not installed-image evidence.

## 1. Board/power and headless baseline

- [ ] Confirm original board, 16 MB flash (schematic discrepancy), no PSRAM; only then authorize first flash.
- [ ] Check 5 V power and peak/steady current on Pi port at boot, AP mode, association, full traffic and dim/bright UI. Confirm USB2 500 mA budget or stop and resolve; published board maximum is 800 mA.
- [ ] Check LCD offsets/color/inversion/rotation, backlight active-low levels, BOOT ROM entry, APA102 fixed pins. No SD required.
- [ ] Inspect descriptors on Linux (`lsusb -v -d 303a:` if available) and macOS System Information: NCM control+data, ACM optional, stable eFuse serial/MAC, bus-powered 500 mA. Record actual VID/PID from artifact descriptor check.
- [ ] Linux and macOS enumerate repeatedly; NCM driver loads, host uses advertised MAC, Wi-Fi association produces carrier; USB host-interface readiness remains a separate observation.
- [ ] Pi obtains a real upstream lease; verify router lease record / host DHCP evidence independently of passive adapter IP. ARP, static IPv4, DNS and bidirectional traffic work. Clear source observation on link change; expire after 60 s silence.
- [ ] IPv6 SLAAC/DAD, link-local/ULA/global address, ND, multicast/mDNS work where upstream supports them; reflection filter does not cause duplicate-address failures. VLANs are intentionally unsupported.

## 2. Actual TeslaAndroid coexistence

- [ ] Record installed build fingerprint and kernel; run read-only diagnostics (adb only if already available/authorized). Missing tools/permissions remain missing evidence, not grounds to request root.
- [ ] Plug adapter into Pi; observe interface/driver/carrier, upstream address, routes and DNS. No custom app/kernel/daemon or manual route change.
- [ ] Existing Pi Wi-Fi AP remains available; existing Tesla display/browser continues functioning simultaneously.
- [ ] Generate actual Internet traffic from Pi **and from the downstream TeslaAndroid client**; confirm DNS, browsing, streaming and expected upstream route. Check that the routed client traffic uses the Pi NCM MAC.
- [ ] If composite enumeration fails, preserve descriptors/logs then test network-only variant. Only consider ECM/RNDIS or NAT with a documented failing step and evidence; do not silently change host networking.

## 3. Recovery matrix

For each case record time to carrier, host address refresh, restored downstream browser traffic, UI error/freshness, drop counters and memory:

- [ ] AP missing at boot; wrong password; WPA2; WPA3-SAE; transition; open AP.
- [ ] AP power restart; phone hotspot off/on; different subnet; static-host address case.
- [ ] Preferred AP absent and another saved profile available; all profiles absent; preferred returns during a healthy fallback connection (must not oscillate); explicit selection.
- [ ] USB unplug/replug, host reboot, USB bus reset, host suspend/resume. USB suspend current compliance specifically remains a release gate.
- [ ] At least 30 cold starts; first boot, saved config and setup timeout; check warm-reset versus cold-reset diagnostics.
- [ ] Sustained full queues / USB backpressure; no packet-buffer leak or double free. Packet ownership host tests complement, not replace, real stress.
- [ ] Watchdog/panic recovery in a **separate test build** or debugger-triggered fault, with owner approval. Production console has no accidental `hang`/`crash` commands.

## 4. Provisioning and UI

- [ ] Serial interactive password is not echoed/stored in shell history/log export. Status never prints upstream or AP credentials.
- [ ] Add/edit/delete/select all eight slots, named priorities; 32-character SSID; hidden SSID entered manually; open network; invalid/overlength/Unicode/control/escaped-NUL inputs rejected; malformed JSON and duplicate fields rejected.
- [ ] AP portal on mobile Safari/Chrome; no external resources; random password changes on re-entry, token rejects cross-origin/missing-token requests; request size and slow-client timeouts.
- [ ] Cancel and ten-minute timeout restore saved adapter mode; invalid submission reports error without erasing old profile.
- [ ] Power interruption before candidate commit, during trial and during NVS update: old working config survives; schema-corrupt state does not auto-reset.
- [ ] Candidate must achieve ten continuous seconds association within 45 seconds; failure reverts. Successful association alone must never show Internet OK.
- [ ] Short press page cycle; debounce under switch chatter; long hold one-shot; dim wake consumes entire gesture; menu hold selection; reset requires release and second hold; reset timeout/cancel.
- [ ] Worst-length SSID/error/IPv6 via console; no row overflow at 160×80; orientation, dimming and brightness; failed optional display/LED still permits network operation.

## 5. Benchmark and soak

Use an upstream LAN `iperf3` server to separate adapter performance from Internet variability. Use only tools already available on each host or explicitly authorized installations. If Android lacks iperf, measure from a downstream browser/client and state that path; do not invent Pi-only figures.

Example on an authorized Linux/macOS test host:

```sh
iperf3 -c SERVER -t 120 -P 1 --json > upload.json
iperf3 -c SERVER -R -t 120 -P 1 --json > download.json
iperf3 -c SERVER --bidir -t 120 --json > bidirectional.json
ping -c 100 SERVER > idle-latency.txt
# Repeat ping under load, then repeat same conditions with UI headless build.
```

D = upstream Wi-Fi → USB host, U = USB host → upstream Wi-Fi. Run three repetitions of each direction; report median plus range, packet loss, idle/loaded median and p95 latency. Record screen brightness, RSSI, AP channel/interference, NCM host driver and concurrent traffic. Donor ~5.7 Mbps is historical context **not a target result or promise**.

- [ ] Full UI versus headless throughput/latency/power/memory comparison.
- [ ] Current/min heap, DMA heap, control/UI stack watermarks, frame drops/reflections, reconnects, USB resets and reset reason recorded before/after.
- [ ] Overnight (8–12 hours) bidirectional soak plus periodic downstream browsing; time series of counters/heap, no unbounded decline or unexpected reboot.
- [ ] AP-loss/USB-reset during sustained load; connection/UI state clears correctly and restores without reflashing.

| Build / conditions | D Mb/s | U Mb/s | Loaded p95 ms | Min heap | Drops | Resets | Duration |
|---|---:|---:|---:|---:|---:|---:|---|
| No hardware measurements yet | — | — | — | — | — | — | — |

## 6. Unified image: setup access point, front panel, roaming and heap (restored v0.1.1 features)

**All of these are pending**: the change that restored them (ADR 0024) was built and host tested, never flashed. Section 4 above still describes the original bridge's acceptance; its candidate-trial and random-AP-password items do not apply to the unified image (no trial; the access point is open by decision, `CONFIG_TDONGLE_SETUP_AP_OPEN`). Record the release and diagnostics build SHA256 and the PR #44 base build's SHA256 for every comparison.

1. **Upgrade from a v0.1.1 dongle, erase declined.** Before flashing record v0.1.1's `list`, `status` and the screen brightness. Flash the release image. Expect: `list` shows every name and priority with empty slots skipped; `status` `wifi_prefs preferred=` names the old preferred network (0 means none); `display` shows the old brightness, rotation and dim time; macOS still shows the network service **T-Dongle-S3 NCM** in its old place in the service order. Then `mode tailnet_gateway`: the product string becomes `T-Dongle-S3 tailnet gateway`; switch back.
2. **Setup access point, phone only.** `reset`, `confirm-reset` (or the menu). The dongle restarts into setup: the screen shows `TDongle-XXXXXX`, the light breathes blue. On an iPhone and an Android phone: join it (no password); the captive sheet should open the page on its own, else browse to 192.168.4.1. Scan, save a network, add a second, delete it, tap Done. Expect the dongle to restart, amber then green. Record time to the captive sheet, and whether a scan while the phone is joining drops it.
3. **Setup limits.** In tailnet mode too: from a phone on the setup network the USB host (192.168.77.x) must be unreachable (no USB netif exists). A phone must be unable to set a priority/name, replace or re-password a saved network (refused), and `/wifi-saved` returns only slot and SSID. Kill USB/console init (or watch an AP that fails to come up) and confirm the dongle still restarts out of setup. Read `status` `control_stack_free_bytes` after `profile` and a menu use. From a phone on the setup network: `/status`, `/diagnostics`, `/boot-status` and a `POST /command` with `action:"add"` or `"mode"` must be refused or redirected; a request without `X-Setup-Token`, or with another `Host`, must be refused. Leave setup open and do nothing: the screen counts down and at 10 minutes the dongle restarts into normal mode (once; no setup loop with nothing saved). `setup` while a crash-loop recovery is active must be refused.
4. **Button and menu.** Short press cycles Connection, Traffic, Health, Setup. Hold 1.5 s opens the menu; short steps and wraps; hold runs. Enter setup AP, `use N` (it also becomes preferred: restart and check), Factory reset (hold, release, hold again within 10 s; short press cancels; waiting 10 s cancels). A press while the backlight is dimmed only wakes it. Factory reset must leave the mode and tailnets alone and erase the old `adapter` data (flash back v0.1.1: nothing saved).
5. **Display settings.** `display 100 1 10` and `display 5 0 3600`: brightness, 180 degree rotation without a shifted image, dim after the time, remembered across a power cycle.
6. **Status light.** Breathing blue (setup, nothing saved), amber (joining), green with the arrival glow, two red blinks (wrong password; network absent), cyan (tailnet sign-in pending), slow red (recovery). Compare with v0.1.1 side by side.
7. **Pages.** Traffic rates against `iperf3` on the host (within a few percent; the counters sit at the USB NCM callbacks), the graph, Health values against `status`, USB resets increase on unplug and bus reset. Worst-length SSID and values never overflow a row.
8. **Roaming (bridge).** Two access points of one SSID that support 802.11k/v (or `hostapd_cli bss_tm_req`): `status` `roams=` increments when the network steers the dongle and the link recovers; compare with v0.1.1 on the same network. In tailnet mode `roaming_assist=0` unless built with `CONFIG_TDONGLE_WIFI_ROAMING_TAILNET`.
9. **Bridge radio and throughput.** Against v0.1.1 and the PR #44 base: D/U Mbit/s and loaded latency with the restored 20 MHz profile and the 11k/v option (coordinate with the bridge data-path measurements, which are separate); confirm the traffic wrappers cost nothing measurable (compare a build without `-Wl,--wrap=tud_network_*` if the numbers move).
10. **Tailnet heap (diagnostics image).** Against the PR #44 base: `memory` and `members` after boot: `start_heap_before` no more than about 3 KB lower (the build predicts 2.5 KB), the first membership admitted on 3 of 3 cold boots, `heap_budget` refusals and the minimum free heap under the 6 Mbit/s UDP flood unchanged. Overnight soak with the screen on the Traffic page.
11. **Downgrade.** Flash the PR #44 base image over this one: the networks are all still there (the new `wifi_meta` and `display` keys are ignored); flash this one again: priorities, names and the preferred network are back.

12. **Control task stack.** After a boot exercising every command, the button menu, the display pages and setup, read `status` `traffic` `control_stack_free_bytes`: expect at least 1,024 (the build's model predicts about 1,056 at the worst command); `tools/check-control-stack.py` prints the worst path.
