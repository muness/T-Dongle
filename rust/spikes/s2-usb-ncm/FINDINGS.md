# S2 (no_std): embassy-usb CDC-ACM + CDC-NCM on the ESP32-S3 OTG at full speed

Verdict: WORKS WITH CAVEATS. Built, image header verified (DIO / 40 MHz / 16 MB), descriptors byte-identical to the C firmware's on the host.
**Nothing was run on hardware.** (This file was written by the coordinator from the spike agent's report, which the Write tool refused to save itself.)

Versions: esp-hal 1.2.2 (`esp32s3`, `unstable`), esp-rtos 0.4.0, embassy-usb 0.6.0, embassy-usb-driver 0.2.2, embassy-usb-synopsys-otg 0.4.0,
embassy-executor 0.10.0, embassy-time 0.5.1, embassy-sync 0.8.0, static_cell 2.1.1, esp-bootloader-esp-idf 0.6.0, esp-backtrace 0.20.0,
esp-println 0.18.0; toolchain `esp` Rust 1.97.0.0.

## API path
`Usb::new_fs(USB_FS, GPIO20 /*D+*/, GPIO19 /*D-*/)` -> `esp_hal::usb::otg::embassy_usb_device::Driver` -> embassy-usb `Builder` + `Handler`, on
`esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0)` and `#[esp_rtos::main]`. The spike carries its own ACM (`src/acm.rs`, ~70 lines) and NCM
(`src/ncm.rs`, ~250 lines) functions copied from embassy-usb 0.6.0 and changed, because the upstream `CdcNcmClass` cannot match the C identity (14 descriptor
differences below), carries one datagram per NTB, hard-codes a 2048-byte NTB (`NTB_MAX_SIZE`, mod.rs:64) and rejects `SET_ETHERNET_PACKET_FILTER`.

## Descriptors
`rust/spikes/s2-desc-check` runs the spike's real `acm.rs`/`ncm.rs` against a mock driver with the OTG endpoint allocator's behaviour and prints
`BYTE-IDENTICAL` to `tdongle-usb-descriptors/tests/golden/c_config_descriptor_fs.bin` (160 bytes). The device descriptor is derived from the embassy formula
(bcd_usb Two, device_release 0x0100, max_power 500, strings) and equals `c_device_descriptor.bin`. Serial and NCM MAC are the same 12 hex digits of the efuse base MAC.

Upstream embassy-usb 0.6.0 defaults vs the C (155 vs 160 bytes): bcdUSB 0x0210 (host requests a BOS) vs 0x0200; bcdDevice 0x0010 vs 0x0100; bMaxPower 100 mA vs 500;
no ACM interface string vs 4; ACM bcdCDC 0x0110 vs 0x0120; Call Management descriptor missing; ACM bmCapabilities 0x02 vs 0x06; ACM interrupt bInterval 255 vs 1;
ACM data OUT EP 0x01 vs 0x02; no NCM interface string vs 5; iMACAddress string index 4 vs 6; bmNetworkCapabilities 0x00 vs 0x21; NCM notification EP mps 8/interval 255 vs 64/50;
NCM data alt 1 endpoint order (OUT 0x02 then IN 0x84) vs (IN 0x84 then OUT 0x04).
The spike handles `GET_NTB_PARAMETERS`, `GET/SET_NTB_FORMAT`, `GET/SET_NTB_INPUT_SIZE` (4 or 8 bytes), `SET_ETHERNET_PACKET_FILTER`, and sends NETWORK_CONNECTION and
CONNECTION_SPEED_CHANGE (12 Mbit/s) after alt 1. Not verifiable here: what macOS does with the NTB divisor/alignment values (read from the spec, not from TinyUSB).

## Backpressure by not reading OUT
embassy-usb-synopsys-otg 0.4.0: each OUT endpoint has ONE 64-byte packet buffer; the ISR drains the RX FIFO into it (lib.rs:32-110); `read()` hands it over and only then
re-arms with `pktcnt=1` and `CNAK` (lib.rs:1331-1385), so until the next `read()` the endpoint NAKs. A second packet with the buffer occupied is dropped with
`ep_out buffer overflow` (lib.rs:99), a defence, not the normal path. The NAK point is therefore **one 64-byte packet**, with nothing queued beyond the class driver's own NTB buffer.

| | C (TinyUSB) | upstream embassy | spike |
|---|---|---|---|
| OUT NTBs | 3 x 3200 B | 1 x 2048 B transient | 1 x 3200 B static |
| datagrams per OUT NTB | many | 1 (`wNtbOutMaxDatagrams = 1`, drops the rest) | many, parsed one by one |
| IN NTBs | 2 x 3200 B, up to 8 datagrams | none; 1 datagram from the caller's slice | 1 x 1542 B, 1 datagram |
| host NAK point | no free OUT NTB | one 64 B packet | one 64 B packet beyond the NTB in RAM |

**Datagram-granular hold/resume** is expressible: `read_ntb()` fills the spike's buffer, `peek_datagram()` returns the next datagram without consuming it, `advance()`
consumes it; `rx_task` advances only after the TX queue accepts the frame; while held (`hold on`, or the queue full) `read_ntb()` is not called, so at most the rest of the
current NTB (<= 3200 B) plus one 64-byte packet stay buffered and the host is NAKed. Upstream `read_packet` cannot do this (no way to offer the datagram again; not cancel-safe mid-NTB).
**TX when the host is not polling IN:** `write()` (lib.rs:1398-1519) loads one packet and returns; the next `write()` blocks without timeout until the host polls or the endpoint is disabled.
A real bridge needs its own drop-tail ring in front of it (which is what the S3 spike has).

## Throughput limits of the esp-hal OTG driver (source only, nothing measured)
* **Single-packet transfers:** `read` arms `pktcnt=1`, `write` programs one packet. A 1542-byte NTB is 25 packets = 25 interrupts, 25 task wakes, 25 NAK windows. TinyUSB programs `pktcnt=N`
  and refills the FIFO from the TX-empty interrupt. embassy-usb-driver 0.2.2 has `read_transfer`/`write_transfer` hooks (src/lib.rs:261-282, 393-410; embassy #2753) but the
  Synopsys driver still uses the per-packet defaults. A vendored patch (`[patch.crates-io]`) implementing them with the existing `ineptxfem` refill path is estimated at 150-250 lines; not attempted.
* **FIFO:** 256 words total; RX = 30 + sum(OUT mps/4) = 78; each IN FIFO 16 words (one packet); 98 words idle because the driver never queues more than one packet.
* **No DMA** in the esp-hal driver (`gahbcfg` sets only the global interrupt bit, lib.rs:850). **Correction of the agent's claim about the C:** the agent concluded the C firmware does not use DMA
  either (TinyUSB's `CFG_TUD_DWC2_DMA_ENABLE` defaults to 0); the C image's effective sdkconfig has `CONFIG_TINYUSB_MODE_DMA=y` (build-release/sdkconfig), which
  esp_tinyusb's `tusb_config.h` turns into `CFG_TUD_DWC2_DMA_ENABLE 1`. So the C firmware DOES run the DWC2 in DMA mode and the no_std driver does not: that is a real gap to attribute any shortfall to.
* **Latency:** the device ISR is registered at `Priority::max()` (esp-hal usb/otg/mod.rs:144); `critical_section` only around register pokes and the <= 16-word FIFO copy.
* **Bracket (estimate, not measurement):** if macOS re-polls a NAKed bulk endpoint at once: several Mbit/s, wire-bound; if it re-polls only on the next 1 ms frame: about 64 KB/s (0.5 Mbit/s).
  The coordinator's reflector run decides which.

## Known issues (searched 2026-10-06)
esp-hal: #1991 (open) USB-Serial-JTAG disappears once OTG starts (no esp-println over USB; the console is the ACM port; reflashing needs ROM download mode); #6411 (open, 2026-10-06) esp-rtos 0.3.0
`BorrowMutError` on S3 at the first task switch (not reproduced with 0.4.0); #6102 `write_async` not cancel-safe (different peripheral). embassy: #6935 (open) ESP32-S3 UAC1 isochronous IN fails with this driver;
#2376 NCM shows no link on Ubuntu when the runner starts before the USB task (the spike notifies only after the data endpoints are enabled); #3686 packed-struct header not endian safe (spike uses `to_le_bytes`);
#7112 cdc-ncm moving to `xarxa` on embassy main. Unreleased fixes on embassy main (EPENA on `read`, endpoint disable waits for ack, bus reset wakes endpoint futures) are not in the 0.4.0 esp-hal pins.

## Footprint (ELF)
.text 55,577 + .rodata 14,728 + appdesc 256 ~ 70.5 KB flash; app image **121,184 B** (2.89% of the 4 MB partition); IRAM 9,624 B; static DRAM 23,956 B (.data 3,912 + .bss 20,044); heap 0 (no allocator).
Largest statics: reflector channel 6,112 B, tx task future 4,800 B (includes the 1542 B NTB), NTB reassembly 3,200 B, rx task future 3,200 B.

## To flash and test (macOS)
`espflash write-bin 0x0 s2.bin` with the board in ROM download mode (hold BOOT while plugging in); this overwrites the C firmware and NVS. After the first boot there is no USB-Serial-JTAG: hold BOOT to reflash.
Expect `/dev/cu.usbmodem*` and the service "T-Dongle-S3 NCM", VID 0x303A PID 0x4001, serial = chip MAC. Console `screen /dev/cu.usbmodemXXXX 115200`: `status`, `hold on`, `hold off`, `help`
(`--features hold-rx` boots held). Reflector: the host adopts the chip MAC as its own; send raw frames (scapy `sendp` as root) and watch `tcpdump -e`; `rx_frames` should equal `tx_frames`.
Backpressure: flood with `iperf3 -u`, `hold on` -> `rx_frames` freezes and the OUT pipe stalls; `hold off` resumes with the same datagram. Throughput: increasing UDP rates against the reflector; that
single number decides whether the OTG driver needs the multi-packet patch.
