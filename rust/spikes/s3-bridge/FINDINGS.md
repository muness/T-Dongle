# S3 (no_std): S1 + S2 as a bridge (USB CDC-NCM <-> Wi-Fi STA raw L2), host->Wi-Fi through the real `tdongle-bridge` crate

Builds; merged image `s3.bin` (16 MiB, app image 494,432 B = 11.79% of the 4 MiB partition, headers `e9 03 02 40` at 0 and `e9 05 02 40` at 0x20000 = DIO / 40 MHz / 16 MB).
**Not run on hardware. `s3.bin` was built with dummy credentials: rebuild with `WIFI_SSID=.. WIFI_PASS=.. cargo build --release` and re-run espflash save-image before flashing.**
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
