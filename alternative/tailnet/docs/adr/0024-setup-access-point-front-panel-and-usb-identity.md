# ADR 0024: The setup access point is a boot mode; the front panel is polled, not a task; the USB product string follows the mode

Status: accepted for on-board validation, 2026-10-06. **Nothing here has been run on the board** (no flashing in this change); the host tests establish structure and the numbers below say which are measured (the build) and which are predictions. Follows ADR 0013 (admission), 0016 (PM) and 0022 (the one elastic floor). Restores, in the unified image, the v0.1.1 features its parity audit listed as missing: setup access point with captive portal, button menu and factory reset, APA102 states, LCD pages and display settings, serial `setup`/`reset`/`confirm-reset`/`display`, saved-network priority and preferred slot, 802.11k/v roaming assist, and decides the USB product string.

## Context

The unified image of PR #44 has one onboarding path in bridge mode that needs a computer or an app (flash page, app, serial). A Pi-attached dongle used with only a phone cannot be configured, and the on-device gestures and light v0.1.1 documented are gone. v0.1.1 got its access point by **restarting into a setup mode** that ran no bridge; the unified image also has a second mode whose heap is budgeted to the byte (ADR 0013, 0022): admission needs 103,448 B free for the first membership against about 107 KB free after USB start (an 8,100 B margin), and every elastic consumer shares one floor (`ML_HB_FLOOR` = 16,384 + 13,500 B). An access point is not small: the AP netif, DHCP server, DNS task, HTTP server with seven sockets and a scan buffer.

## Decisions

### 1. The access point is a boot mode, never a service inside a running dongle

Setup is entered by restarting (button menu, `setup`, first plug-in with nothing saved) and runs the access point and the HTTP server **and nothing else**: no bridge frame pool (`tdongle_l2_start` is not called), no tailnet runtime, no manager task, no DNS or NAT. After 10 minutes, `cancel`, or the page's Done it restarts into normal mode. The request travels in three RTC words that are honoured only after a software reset with a valid magic (`main/setup_boot.c`).

*Heap accounting.* The requirement was that the access point must not run while a tailnet is active unless admission accounts for it. It never does: `start_member` refuses in a setup boot, `start_manager` is not in the setup sequence (`tests/test_startup.c` asserts it for both modes and every stage fault), and recovery mode outranks a setup request. So admission needs no new term and the elastic floor needs no new reservation. The access point's own cost (about 25 KB: AP netif and DHCP server, DNS task stack 3 KB, scan task stack 4 KB and 24 records, HTTP server) is an estimate from v0.1.1, not a measurement; it is paid out of memory that a setup boot leaves free by construction (the 48 KB bridge pool and the 103 KB tailnet budget are not allocated). The alternative, an access point alongside a running tailnet, would have had to be charged to admission and to ADR 0022's floor (a flood and a phone joining at once are both allocation peaks), for a feature that is only needed when there is no working Wi-Fi uplink to share.

*Ending.* The 10 minute clock starts when the boot decides to run setup, not when the access point comes up, and it is checked by the control task before anything that can be unavailable (`setup_session_should_end`): a setup boot whose access point did not start 30 s after the boot began (no memory, no radio, the settings or the network layer failed) restarts into normal mode instead of idling for ten minutes, and a request in a crash-loop recovery boot is ignored. While setup is open `use` is refused and the button menu lists no saved networks: joining one would move the single radio off the access point's channel under the phone.

*Consequence:* while setup is open the dongle forwards nothing. v0.1.1 had the same property and says so on the page.

### 2. One HTTP server, two kinds of client

The setup service already exists (USB, tailnet mode). A second server would double the sockets, stacks and attack surface. The same `esp_http_server` now also starts in a setup boot of either mode, with its socket budget raised for phones (7 sockets, 5 s timeouts) only then. `local_request` became `request_origin` (`main/setup_access.c`, pure and host tested): USB host, setup-network client, or nobody. A setup-network client reaches `/`, `/wifi-scan`, `/wifi-saved` and `/command` with the actions `wifi`, `wifi_remove`, `setup_done`, and nothing else; the access point is open (owner decision, `CONFIG_TDONGLE_SETUP_AP_OPEN`), so it is treated as hostile: no tailnet memberships (they carry sign-in keys), no mode switch, no diagnostics. Requests need the per-boot token (`X-Setup-Token`, constant-time compare) and the canonical `Host`; a captive-portal probe arriving under any other host name is redirected to `http://192.168.4.1/`, which also keeps DNS rebinding from reaching the API. The token and the optional WPA2 password come from the hardware RNG with its entropy source enabled before the radio is initialised (esp_random is pseudo-random until RF runs). The DHCP server's DNS option is set before the access point starts, so starting it cannot race the option. A client of the open network that forged a USB-subnet source address would still need the 32 bit initial sequence number of a SYN-ACK that goes to the real USB host, so the source address is accepted as the USB boundary (considered, not defended further). `tests/test_setup_page.py` ties the page to the rules from both sides. The nearby-networks list is scanned in its own task and polled, because a blocking scan in the single HTTP task would stall a phone that opens several connections at once.

### 3. The front panel has no task

Button, light and screen are polled by the existing `gateway_control` task every 20 ms (`gateway_display_tick`, `device_ui.inc`), instead of a `status_ui` task as in v0.1.1. A task is about 3 KB of static stack plus its control block, charged 1:1 to the tailnet's admission margin; polling costs nothing. The price is that a long serial command (`scan`, about 3 s) pauses them. The screen is redrawn only when its content changed (the existing exact-compare) and at most every 250 ms; the light is written only when the colour changes.

### 4. Saved networks: metadata beside the list, keyed by SSID

`tn_settings/wifi_profiles` stays byte for byte what the first unified build wrote (a downgrade still reads it). Names, priorities and the preferred network live in `wifi_meta`, keyed by SSID, so no reordering, deletion, partial write or older firmware can attach a priority to the wrong network; a save is two flash writes, not one transaction (`nvs_set_blob` writes at once): metadata first, then the list, then a commit, and a failed write restores the previous metadata and changes nothing in RAM. A power cut between the two writes leaves new metadata beside the old list; because the metadata is keyed by SSID that cannot attach a priority to a different network (an entry for a network not in the list is ignored), and the worst outcome is a stale priority, name or preference on the same network until the next save. A generation counter would add nothing the SSID key does not already give. v0.1.1's `adapter/config` is only ever read: import is lossless for every field (`main/legacy_import.c`) and repeats until the first explicit save. Selection ranks preferred (if usable, -85 dBm), then priority, then signal, with the existing hysteresis; with default priorities and no preferred network it is the existing strongest-wins rule (the existing tests run unchanged).

### 5. Roaming assist: built in, requested per mode

`CONFIG_ESP_WIFI_11KV_SUPPORT`, `RRM` and `WNM` are in `sdkconfig.defaults` for the one image; the station asks for them (`rm_enabled`, `btm_enabled`) in bridge mode, as v0.1.1 did, and not in tailnet mode unless `CONFIG_TDONGLE_WIFI_ROAMING_TAILNET`: a roam drops the link and the tunnels, and the tailnet heap margin is unmeasured with the feature on. The same station configuration also restores WPA3 (SAE) and protected management frames, which the unified image had silently dropped, and bridge mode gets the v0.1.1 radio profile (20 MHz, maximum transmit power).

### 6. USB product string: per mode

Bridge mode enumerates as `T-Dongle-S3 NCM`, exactly as v0.1.1, so a Mac or Pi keeps the adapter's service name and its place in the service order across the upgrade (a neutral name would have changed it for everyone). Tailnet mode keeps `T-Dongle-S3 tailnet gateway`: it already has its own USB MAC pair, subnet and DHCP, so a host sees a different interface anyway, and the name says what it is. The console greeting follows the same split (`T-Dongle-S3 adapter` in bridge mode, the v0.1.x prefix).

### 7. Traffic counters at the NCM callbacks

The Traffic page needs bytes per direction in both modes. Counting in the bridge's receive path or the transmit ring would touch code under change elsewhere and differ per mode, so `main/traffic_hooks.c` wraps TinyUSB's `tud_network_recv_cb` and `tud_network_xmit_cb` at link time (the `--wrap` mechanism the socket budget and the transmit ring already use) and counts what the class driver accepted. Cost: one relaxed atomic add per frame.

## Threat model of the open setup network

The setup access point is open by owner decision, so everyone in radio range for up to 10 minutes is an attacker, and the home Wi-Fi password crosses the air in clear when it is typed on the page. What the design limits:
- **No route to the USB host.** A setup boot creates no USB netif (`start_network`), runs no NAT, and has no other netif to forward between: with `CONFIG_LWIP_IP_FORWARD` an AP client could otherwise reach 192.168.77.0/24.
- **Nothing of the tailnet side is served** (memberships, sign-in keys, mode, diagnostics), and a request is classified by source subnet **and** the connection's own local address (`getsockname`) **and** `Host`/`Origin`, so a header or a source address alone proves nothing.
- **An AP client can add and delete, not rewrite.** It cannot set a name or a priority, cannot replace a saved network (a new password or SSID in an occupied slot) and gets no priorities or preference back from `/wifi-saved` (only slot and SSID, which its delete buttons need). A planted network gets the default priority, so it competes only by signal strength; it can still be an open evil twin the owner must notice on the screen or in `list`, and delete-then-add remains possible: the cost of a phone-only setup flow. Setting `CONFIG_TDONGLE_SETUP_AP_OPEN=n` (WPA2 password on the screen) is the stronger answer.
- **It always ends**: the control task's check, an `esp_timer` failsafe armed in `app_main` that does not depend on USB or console init, and a 30 s limit when the access point is not up.

## Measured (the build) and predicted (the board)

Release and diagnostics images against the PR #44 base build (same toolchain, IDF v5.5.5; `esp_idf_size --diff` of the two linker maps):

| | Release | Diagnostics |
|---|---:|---:|
| Static RAM, DRAM `.data` + `.bss` | +1,260 B (`.data` +116, `.bss` +1,144) | +1,260 B (`.data` +100, `.bss` +1,160) |
| IRAM `.text` (the hal's GPIO/LEDC functions) | +440 B | +440 B |
| D/IRAM total | **+1,700 B** (190,603 B used) | **+1,700 B** (194,671 B used) |
| Static IRAM (instruction cache) | +0 (16,384 B, full) | +0 |
| Flash `.text` / `.rodata` | +30,860 B / +18,596 B | +31,032 B / +18,580 B |
| `app.bin` | +50,016 B (1,324,576 B of the 4 MiB partition) | +50,144 B (1,354,032 B) |

Where the flash goes: about 8 KB is the 802.11k/v/WNM support in the supplicant, about 12.6 KB the setup page, the rest the new code and strings. Where the RAM goes: about 1.0 KB the front panel's state and the saved-network metadata, 0.2 KB the supplicant's 11k/v state. The scan list and its lock are allocated only in a setup boot.

The 802.11k/v support (`CONFIG_ESP_WIFI_11KV_SUPPORT`, RRM, WNM) compiled in costs 192 B of `.bss` in libwpa_supplicant and about 8 KB of flash; its runtime allocations happen only when a station asks for it (bridge mode, or tailnet with the Kconfig option), so a tailnet boot pays only the static part. The WPA3/PMF/WPA2-threshold station settings are bridge-only; tailnet mode keeps #44's configuration. The Traffic page counts frames the NCM class driver accepted; the bridge data path of #45 may drop a frame after accepting it, so "up" is an upper bound there (follow-up: count from #45's stats once both are merged).

The static RAM is charged to the tailnet heap 1:1: predicted free heap after boot about 1.7 KB lower, margin to admission (8,100 B at ~107 KB) about 6.4 KB. **Prediction, to be checked on the board:** first-membership `start_heap_before` stays within 3 KB of the PR #44 value, admission still passes on 3 of 3 boots, `heap_budget` refusals unchanged under the 6 Mbit/s UDP flood. **Refuted if** admission refuses a boot that PR #44 admitted: then the 802.11k/v support (0.2 KB of RAM, 8 KB of flash) is the first thing to make conditional, and the front panel's statics (about 1 KB) the second.

## Consequences

- A phone alone can configure a bridge-mode dongle again; the button, light, pages and display settings are back; nothing v0.1.1 stored is lost on upgrade.
- Setup always costs a restart and a pause in forwarding.
- Not restored: the 45 s candidate trial for replacing a saved network (a new network is saved immediately), v0.1.1's drop to the ROM loader after three crashes (recovery mode replaced it on purpose), the host-IP line and drop counters (they need hooks in the bridge's data path), and the `portal` trace.
- Open on the board: the access point against iOS, Android and a laptop (captive sheet, 10-minute close), scan while a phone joins, the light and menu feel, 11k/v against a real mesh, and the heap prediction above. The plan is in the pull request.
