# s2-upstream-pr: S2 on the exact code of embassy PR #7191

Copy of `s2-usb-ncm` that replaces the vendored `embassy-usb-synopsys-otg` with the PR driver (https://github.com/embassy-rs/embassy/pull/7191, fork `muness/embassy` branch
`synopsys-otg-multi-packet-out`, head `f81997b6109b119e856767959f6c6591221bd6a8`, only `embassy-usb-synopsys-otg/{CHANGELOG.md,src/lib.rs,src/out_transfer.rs}` changed).
Not run on hardware. Image: `rust/spikes/dist/s2-upstream-app.bin` (app-only, DIO/40m/16MB).

## Adaptations needed (feedback for the PR)
1. **The whole embassy family must come from the PR checkout.** The driver is on embassy main: it needs `embassy-sync` where `CriticalSectionRawMutex: Copy` (released 0.8.0 lacks it:
   `E0277` on every `M: RawMutex + Copy` bound), so `[patch.crates-io]` takes `embassy-usb-synopsys-otg`, `-usb-driver`, `-sync`, `-usb`, `-net-driver-channel`, `-time`, `-time-driver`,
   `-time-queue-utils` from the one git rev (patching only sync breaks the released `embassy-net-driver-channel` 0.4.0, hence usb and net-driver-channel too). The driver alone cannot be dropped into a graph on released crates.
2. **esp-hal 1.2.2 glue does not compile** (local copy `esp-hal-patched`, stock 1.2.2 plus 3 edits in `src/usb/otg/`):
   * `embassy_usb_device.rs`: `OtgInstance` has a new required field `tx_fifo_count`; set to `state.endpoint_count() as u8` (7 on the S3 FS core), the old behaviour of one TX FIFO per endpoint slot.
   * `mod.rs` (x4): `StateStorage::new()` / `HostStateStorage::new()` now take the mutex value, `StateStorage::new(CriticalSectionRawMutex::new())` (plus the import).
3. **Spike code**: `Config::bulk_out_transfer_bytes = 3200` replaces `out_transfer_bytes[4]`; `ncm.rs` `read_ntb` calls the stock `EndpointOut::read_transfer` into the 3200 B NTB buffer; `read_chunk`, the `ReadTransfer` trait,
   `NtbCollector` and the `tdongle-usb-out` dependency and the `stock-out` feature are gone. A zero-length result is skipped (see below). `EP_OUT_BYTES` = 64 + 2 x 3200 (see below).

## API notes for the PR / esp-hal users
* `bulk_out_transfer_bytes` is global to all bulk OUT endpoints and each takes that many bytes of `ep_out_buffer`: the CDC-ACM data OUT endpoint also gets 3200 B (two NTB-sized slices, 6.4 KB, for one useful one). A per-endpoint setting (by address or via `alloc_endpoint_out`) would fit composite devices.
* `read_transfer` ends only on a short packet or a full buffer. An NTB of exactly the buffer size (3200 = 50 x 64) returns with no short packet; its ZLP then arrives as a separate `Ok(0)` transfer that the class must skip. Documenting this (or consuming the ZLP) would help; the vendored `read_chunk` returned a `short` flag instead.
* `Config` is `#[non_exhaustive]`: fine via `Default` + field assignment, but esp-hal re-exports it, so it cannot be built with struct syntax by users.
* Generic `RawMutex + Copy` bound: esp-hal hardcodes `CriticalSectionRawMutex` and needs the new `new(mutex)` arguments; the `Copy` bound requires unreleased embassy-sync, which blocks a release of the driver until embassy-sync ships.
* `tx_fifo_count` is a required public field with no default; esp-hal has to know it per chip (it was implicit before).
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

## Board result (coordinator, 2026-10-06): PASS
Flashed app-only and verified against the running ELF; boots under the C bootloader; `bootloader` and `boot-status` work. Enumerates as "T-Dongle-S3 NCM", serial and NCM MAC = chip MAC.
The reflector carries 2, 4, 8 and max Mbit/s of UDP broadcast with no drops (rx_drop 0, chan_full 0) and saturates at **4.58 Mbit/s in each direction at the same time (9.2 Mbit/s on the bus)**;
the full-speed bulk ceiling at 64-byte packets is about 9.7. **CORRECTED (second board session, one direction at a time): this conclusion was wrong.** `source max` (IN alone) reaches 7.41 Mbit/s, 0 drops; `sink` (OUT alone) stays at 4.52 / 4.62 / 4.62 Mbit/s at 6 / 8 / max offered, 0 drops. OUT is the bottleneck (one-packet arming), and the multi-packet patch **is** required for OUT; see the ADR section "USB OUT patch". The earlier both-directions-at-once figure (4.58 each) was the OUT cap, not the bus.
Backpressure: `hold on` under a 3 Mbit/s flood froze `rx_frames`; `hold off` resumed with no drops, bad NTBs, runts or resets.

## Patched OUT (multi-packet), and the console modes
The vendored driver arms the NCM OUT endpoint for a whole NTB (3,200 B, 50 packets); `s2-app.bin` is the patched build and `s2-stock-app.bin` the same image with the `stock-out` feature (stock one-packet arming) for the A/B.
`status` shows `out=multi|stock`. Console: `reflect` (default), `sink` (count OUT, send nothing), `source RATE_KBPS|max` (1,442 B broadcast frames on IN). Host model: `rust/crates/tdongle-usb-out`.

## Board A/B of the OUT patch (coordinator; every flash verified against the running ELF; 0 drops throughout)
| Build | OUT 6M offered | OUT 8M offered | OUT max | IN max |
|---|---|---|---|---|
| out=stock | 4.43 | 4.53 | 4.54 | 7.39 |
| out=multi, run 1 | 5.95 | 7.94 | 8.41 | 7.41 |
| out=multi, run 2 | 5.96 | 7.95 | 8.40 | 7.41 |
OUT +85%, above the C bridge's upload of about 5.8; IN unchanged. USB is no longer the limit for the no_std stack.
