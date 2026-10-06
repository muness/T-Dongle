# S3 (no_std): S1 + S2 as a bridge (USB CDC-NCM <-> Wi-Fi STA raw L2), host->Wi-Fi through the real `tdongle-bridge` crate

Builds as an app-only image `rust/spikes/dist/s3-app.bin` (0x20000; 515,120 B = 12.3% of the 4 MiB partition; DIO / 40 MHz / 16 MB; `esptool image_info` valid). **Not run on hardware.** No credentials are built in: it reads the saved networks from the NVS (read-only), scans (hidden SSIDs included), joins the best-ranked visible saved network (`tdongle-wifi-policy`) and otherwise tries the list in order. The ACM console also answers `bootloader` and `boot-status`; USB serial = base MAC. Build: `rust/spikes/build-app.sh s3-bridge`.
(Written by the coordinator from the spike agent's report; the Write tool refused the agent's own attempt.)

Versions equal S1/S2 (esp-hal 1.2.2, esp-radio 1.0.0-beta.1, esp-rtos 0.4.0, esp-alloc 0.11.0, embassy-usb 0.6.0, embassy-executor 0.10.0) plus `embassy-net-driver` 0.2, `critical-section` and the path crates `tdongle-bridge`, `-aqm`, `-spsc`, `-serial`, `-traffic`.

## Structure (one embassy thread-mode executor on core 0 over esp-rtos)
* Wi-Fi -> host: `wifi_rx_task` polls `Interface` through the embassy-net-driver trait (woken by wakers); `rx.consume_token` calls `Bridge::wifi_rx(frame)` so every `ToHost` outcome is counted by the crate.
  `FwEnv::usb_ring_send` copies into an 8-slot x 1514 B drop-tail ring (critical section), a `Signal` wakes `usb_tx_task`, which pops straight into the NTB body and sends (`Sender::body_mut` / `send_prepared`).
* Host -> Wi-Fi: `usb_rx_task` feeds each datagram to `Producer::host`; on HOLD the datagram stays in the NTB buffer and `read_ntb` is not called (the OUT endpoint is not re-armed), waiting on `RESUME_SIG`
  (set by `Env::rx_resume`, reset before each `host()`), with a 250 ms safety poll for alt-1 drops. `worker_task` (woken by `notify_worker`) waits up to 5 ms for esp-radio TX credit, then `Worker::drain_one()`.
  `wifi_room` = `Interface::transmit().is_some()`; `wifi_tx` consumes the token (no token = `TxError::NoMem`); `wait_retry` is a blocking 500 us delay on the rare refusal path.
* esp-radio: `with_tx_queue_size(6)` works (unstable builder); RX queue 8; MTU 1514 (`ESP_RADIO_CONFIG_WIFI_MTU`); power save off; HT20; 20 dBm. 240 MHz fixed (no DFS). Heap 64 KiB reclaimed + 48 KiB regular.
* Console on the ACM port: `status` = `tdongle_serial::status::write_status` (zeros where no source) + `bridge_*` lines + `heap` + one `s3 ...` line (`ring_write_err wifi_room_no ntb_tx usb_resets cpu_mhz tx_queue rx_queue`); `help`, `capabilities`, `heap on|off`. A `heap total/used/free cpu_mhz up_ms` line every 5 s.

## Not equivalent to the C bridge (attribute a shortfall to these)
1. RX is coupled to TX credit (esp-radio `receive()` yields only if a frame is queued AND inflight < tx_queue_size): upload ACKs stall while TX is saturated; drops in esp-radio's RX queue are not in the bridge counters. Fix: xarxa `receive()` (extra copy) or `esp_wifi_internal_reg_rxcb` via esp-wifi-sys (S1 hybrid).
2. TX-done accounting is owned by esp-radio: `bridge_wifi_tx` is zeros except `refused_pool`; `installed`/`tx_done_cb` false; `consume_token` silently drops when not Connected yet the bridge counts `Sent`.
3. Wi-Fi->host is a whole-frame drop-tail ring (8 slots), not the elastic slab ring (`grow/shrink/cold_*` = 0).
4. IN NTBs carry one datagram each (no aggregation; 28 B header + possible ZLP per frame).
5. esp-hal OTG does single-packet transfers (25 interrupts per 1.5 KB NTB) and no DMA, while the C image runs the DWC2 in DMA mode (`CONFIG_TINYUSB_MODE_DMA=y`): most likely cause of a download shortfall. A driver patch would program multi-packet transfers (`DIEPTSIZ.PKTCNT/XFRSIZ/MCNT`, one `XFRC` interrupt; OUT `DOEPTSIZ.PKTCNT > 1`).
6. No carrier-change notification to the host on Wi-Fi flaps (NETWORK_CONNECTION once at alt 1).
7. No CPU scaling (`note_activity` is a no-op): power numbers are not comparable. 8. No 11k/v, hidden-SSID scan, roaming, profiles, greeting; `traffic` kbps are 0.

## ELF numbers
IRAM ~42 KB; `.data` 12.3 KB; `.bss` 95.2 KB (includes the 48 KiB heap, `BRIDGE` 12.4 KB, ring 12.1 KB); `.dram2_uninit` 64 KiB reclaimed; `.text` 363 KB; rodata 76 KB. No heap measurement is possible without running: read the `heap` lines.

## iperf3 A/B procedure (against ADR 0023 amendment 7: TCP down ~7, up ~5.8 Mbit/s; UDP 4 Mbit/s loss <= 1%; load ping 43 ms)
Same host, AP, channel and cable as the C runs. `status` before and 5 s after each 60 s test: TCP down `iperf3 -c SRV -R -t 60`; TCP up `-t 60`; UDP `-u -b 4M` and `-R`; load ping `ping -i 0.2 SRV`.
Capture `bridge_to_host`, `bridge_to_wifi`, `bridge_ecn`, `bridge_rx_class`, `bridge_usb_ring`, `bridge_timing`, `bridge_wifi_tx`, `s3`, `heap`, `traffic`.
Down short: `ring_full`/`dropped_full` rising -> USB IN (items 4, 5); zeros with `bridge_link` fine -> Wi-Fi. Up short: `h2w_held` and `rx_class holds/hold_us_max`, `tx_failed/tx_retries` -> Wi-Fi side; low with no holds -> OTG single-packet OUT (`rx_class ntbs` per second); ACK stalls -> `wifi_room_no` (item 1).

## Board result (coordinator, 2026-10-06): FAIL, and the rebuild
The first `s3-app.bin` flashed and verified, then the board never enumerated and left the USB bus entirely (no ROM port, no app port); it needed BOOT held to recover. Not a crash loop.
That build read the NVS, initialised the radio and scanned **before** the USB device attached, with a `println!` after `Usb::new_fs` had moved the pads to the OTG PHY. Rule 13 (ADR 0001) rebuilt it:
`guard::begin()` first, watchdogs, USB + console spawned before anything that can block, then `init_task` (storage, radio, scan, connect) with stages recorded in RTC memory, every `unwrap` in the radio
setup turned into a reported error, timeouts on scan (8 s) and connect (30 s), esp-println on the UART (not USB-Serial-JTAG), a panic handler that records `file:line message` and resets, safe mode after two boots
that did not stay up. New console commands: `boot-status` (now with `reset_reason`, `stage`, `previous_stage`, `previous_panic`, `safe_mode`, `unstable_boots`), `init` (stage and the last note), `normal` (leave safe mode).
The cause of the original stall is not established; candidates are in the ADR. If the rebuild still stalls, `boot-status` after the next boot says in which stage.

## Board result 2 (coordinator): the rebuilt S3 boots, the bridge wedges; and the fixes
Boots (USB first, `boot-status` stage=running, safe_mode=false), heap 53,180 of 114,684 free, `status` in C format. Defects and what was done:

1. **The bridge wedged within a second** (Wi-Fi to host stopped at 176 frames; host to Wi-Fi `tx_retries` 784, `wifi_room_no` 788; ping 100% loss). Cause, from esp-radio 1.0.0-beta.1's source: both directions are gated on one
   counter, `WIFI_TX_INFLIGHT`, that only the driver's tx-done callback decrements and that nothing resets: `receive()` yields only while `inflight < tx_queue_size`, and `transmit()` likewise. A frame the driver drops
   when the link changes (the AP was at -87 dBm) is never completed, and a frame sent while the station is not Connected is counted and then silently dropped by `esp_wifi_send_data`; each costs one credit for good.
   With a full TX queue one flap uses all six. Reproduced as a model (`tdongle-wifi-budget/tests/coupled_credit.rs`) next to the same events against the C's `WifiPins` (which survives them).
   **Fix:** `src/l2.rs` takes over both directions as the C does: RX through `esp_wifi_internal_reg_rxcb` (a callback in the Wi-Fi task that copies into `Bridge::wifi_rx` and frees the buffer; no TX credit involved),
   TX through `esp_wifi_internal_tx` charged to `WifiPins` (limit 6, heap floor, tx-done releases, flush on every link change, 3 s lease). esp-radio's token API is no longer used. `status` shows the budget (`bridge_wifi_tx charged/done/flushed/stale/unmatched`), `rx_cb`, `tx_drv_err`.
2. **Wrong network, `phy=lr`, `saved=1`.** `phy=lr` and `saved=1` were the spike's own status code: `Info::default()` is the C `{0}` whose PHY 0 prints `lr` (the C reads the driver and uses PHY_UNKNOWN), and `Prefs.saved` was a literal 1. Now `l2::link_read` is the C `wifi_link_read`
   (AP record, negotiated PHY, bandwidth, power save, tx power) and the prefs come from the loaded list. The radio was never in LR (esp-radio's default protocols are b/g/n; the link loop now sets `Protocols::default()` after each `set_config`, HT20 as before).
   The list itself was incomplete: C builds it from `tn_settings/wifi_profiles` when present, otherwise from the single `tn_settings/wifi` config (a 184-byte `wifi_config_t`) **plus** the v0.1.x `adapter/config` blob. The spike read only the latter.
   `tdongle-saved` has the C order and the C ranking (usable at -85 dBm or better first, then preferred, then priority, then signal), tested on NVS images made by IDF's generator for the two board layouts (`board_v01`, `board_v03`) and, if present, a real dump (`tests/fixtures/board_dump.bin`, from `esptool read_flash 0x9000 0x10000`, read-only).
   `list` prints the C lines (`N[*] name= ssid= priority=`). The scan result per slot is in the `s3` line (`scan_seen`) and the `init` command shows why a join was slow.
3. **`list` and `help`.** `help` and `capabilities` list exactly what the image implements (`write_help_implemented`; a test keeps every listed command parsing to a real command and the unimplemented C commands out). The std firmware's `help` does the same.

OUT patch: the NCM OUT endpoint is armed for a whole NTB as in S2 (board A/B: OUT 8.41 Mbit/s). `s3-stock-app.bin` is the same image without it (`stock-out`).
USB-side modes (console `usb bridge|sink|source RATE_KBPS|max`): `sink` counts OUT datagrams and drops them (`sink_frames`, `sink_bytes` in the `s3` line), `source` sends 1,442 B broadcast frames on IN (`source_frames`, `source_bytes`); in either mode the Wi-Fi to host ring is refused so the radio cannot interfere. Use them to separate USB from the radio.

## Board result 3: the wedge fix holds; associated to a far access point
Verified: no wedge (`rx_cb` 5,130; budget charged = done = 2,541; inflight 0; no refusals), `list`/`help`/`saved=3 preferred=1` correct, heap free 64 to 67 KB. But `wifi_link` showed 217IoT at -88 dBm on channel 1 (the C joins it at -50 to -67 on channel 11), so TCP/UDP were unusable.
**Cause:** esp-radio's `StationConfig` defaults to `ScanMethod::Fast`, which joins the first access point that answers; 217IoT is several access points. The C sets `WIFI_ALL_CHANNEL_SCAN` and `WIFI_CONNECT_AP_BY_SIGNAL` (`wifi_fill_station`); esp-radio already sets by-signal, the scan method was the miss.
**Fix:** `with_scan_method(ScanMethod::AllChannels)`; the rest of the C station profile (PMF capable, SAE both methods, WPA2 threshold) is what esp-radio already applies; 802.11k/v are switched on after `set_config` as C does in bridge mode (`wifi_roaming_assist`). The pre-join scan is the C's (active, 40 to 100 ms a channel, hidden shown, no 40-result cap).
Per access point, not per SSID: `tdongle_saved::strongest_bss` picks the strongest BSS of the chosen SSID, and `Bss::usable` applies -85 dBm to that BSS (host tests with several BSSes of one SSID, in any scan order, ties, prefix SSIDs).
**Console:** `scan` runs a live scan (also while connected) and prints every access point strongest first, `ssid= bssid= channel= rssi= auth= usable=` plus `saved=N` and `joined=1`, then `scan_done seen= listed= seq=`.
`status` has a new line `s3_bss joined=<bssid channel rssi> best=<bssid channel rssi> match=0|1 pin=0|1 scan_method=all_channel`: the access point the driver joined against the strongest one the scan saw for the chosen SSID. `bss pin on|off` (default off = the C) pins the BSSID and channel of the strongest usable BSS in the station config, to separate "the driver chose badly" from "the radio is bad there" without a reflash.

## Board result 4: 30d5d68 unreachable (regression), and the fix
Boot 1 of 30d5d68 reached stage `running` and was then reset by TIMG1 twice (`reset_reason CoreMwdt1`, `unstable_boots 2`), so the third boot was safe mode and the console worked. After `normal` the port enumerated but the console never answered, `bootloader` included, and the owner had to press BOOT.
**Why the watchdog fired after `running`: leading cause, not proven on a board.** In the connect path I had put `esp_wifi_sta_get_ap_info` (to record the BSS the driver joined) inside `critical_section::with(...)`, immediately after `guard::stage(Running)`. That driver call can wait for the Wi-Fi task (an internal mutex or queue), which cannot run while interrupts are off on the one core esp-rtos uses, so the thread blocks forever with interrupts disabled. Everything stops at once: the USB interrupt (the device stays enumerated, the pull-up is still on, and nothing answers), the heartbeat task (so the MWDT stops being fed), the console. Only the hardware watchdog still works, and it fired, 10 s later, with the stage recorded as `running`. That matches every symptom of boot 1.
After `normal`, boots A and B would hang the same way and be reset by the hardware watchdog about 15 s apart, and boot C would be safe mode (two unstable boots): the console should have answered from about 40 s on. That did not happen in 90 s, so either the host tool kept a stale handle on the port across the resets (the port name does not change when the device re-enumerates), or a second fault exists; I cannot tell from here, and the new `previous_hang` / `previous_op` fields exist to say.
**What was changed (rule 13, item 5 in the ADR):**
1. The driver call is outside the critical section, tagged with `guard::op("joined_bss")`; the scan table is formatted outside critical sections; no radio call in the console.
2. The USB device, the console, a console heartbeat and the supervisor run in an interrupt-mode executor (`InterruptExecutor`, priority 3); the bridge and radio stay in the thread executor with its own heartbeat. `status` reads a link snapshot the link task publishes.
3. The watchdog is fed by the supervisor only while both heartbeats advance; a stall is recorded as `previous_hang` (`thread` or `console`) and resets at once.
4. `boot-status` has `previous_hang` and `previous_op` (the operation in progress when the chip last reset, named for every driver call that can block).
5. Host tests: `tdongle-boot-guard/tests/watch.rs` (starvation model: a spinning bridge task must not stop the console answering, and is named; stuck console; healthy board; interrupts off; wrap) and the RTC tag tests.
Not verified on a board: that the interrupt executor at priority 3 coexists with the radio's interrupts (if the Wi-Fi interrupt needs to preempt the console, lower it); that `esp_wifi_sta_get_ap_info` really blocks on the Wi-Fi task (the tags will say if another call is the culprit).
