# S1 (no_std): raw L2 on a Wi-Fi STA with esp-radio, no smoltcp / embassy-net

Verdict: WORKS WITH CAVEATS (builds, image verified DIO/40 MHz/16 MB; NOT run on hardware, no flashing was allowed).
Raw L2 is possible with the public-but-`#[doc(hidden)]` token API and nothing from smoltcp or embassy-net in the path.

Versions (crates.io, 2026-10-06): esp-radio 1.0.0-beta.1 (0.18.0 has the same API shape), esp-hal 1.2.2, esp-rtos 0.4.0,
esp-alloc 0.11.0, esp-bootloader-esp-idf 0.6.0, esp-println 0.18.0, esp-backtrace 0.20.0, esp-wifi-sys-esp32s3 0.3.0
(blobs = ESP-IDF Wi-Fi), embassy-futures 0.1.2 (only for `block_on`), toolchain `esp` Rust 1.97.0.0.
Paths below are relative to `esp-radio-1.0.0-beta.1/src/wifi/mod.rs` (ESP-radio).

## API path that makes raw L2 possible
```
esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);                 // scheduler (no embassy feature needed)
let mut ctl = WifiController::new(peripherals.WIFI, ControllerConfig::default().with_initial_config(Config::Station(..)))?;  // :2673
let mut sta = Interface::station();            // :1561 (singleton; Interface::mac_address() :1616 = efuse STA MAC)
block_on(ctl.connect_async())                  // :3337 (only an async connect exists; embassy_futures::block_on is enough)
while let Some((rx, _tx)) = sta.receive() {    // :1622 pub, #[doc(hidden)]; returns (WifiRxToken, WifiTxToken)
    rx.consume_token(|frame: &mut [u8]| ..)    // :1978  frame = full 802.3 frame, dst(6) src(6) ethertype(2) payload
}
sta.transmit()?.consume_token(len, |buf| ..)   // :1628/:2013  buf = full Ethernet frame incl. src MAC you choose
```
The `Interface` implements embassy-net-driver / xarxa-driver traits (:2122, :2197) but those are optional consumers of the
same `receive()/transmit()` inherent methods; calling the inherent methods needs neither trait nor a stack.
The `wifi` feature still compiles `embassy-net-driver` and `xarxa-driver` (trait-only crates, no code in the path). smoltcp:
absent (removed in esp-radio 0.17, "Support for the feature smoltcp has been removed", CHANGELOG; `grep smoltcp Cargo.lock` = 0).
Caveat: `receive`/`transmit` are `#[doc(hidden)]` ("not ready to stabilize"), so expect API churn between betas; pin `=1.0.0-beta.1`.

## Internals (does it call esp_wifi_internal_*?)
- RX: `wifi_init` registers `esp_wifi_internal_reg_rxcb(STA, recv_cb_sta)` (:1177) and `esp_wifi_set_tx_done_cb` (:1175).
  `recv_cb_sta` (:1242) wraps `(buffer,len,eb)` in a `PacketBuffer` and pushes into a `VecDeque` (STA queue, default 5 frames,
  `ControllerConfig::rx_queue_size`). Queue full => returns ESP_ERR_NO_MEM (frame dropped, "RX QUEUE FULL").
- RX buffer ownership: ZERO-COPY, hold-then-free. The driver's own RX buffer (`eb`) stays alive while the frame sits in the queue;
  `consume_token` pops it, hands `&mut [u8]` pointing straight into the driver buffer to your closure, and when the closure returns the
  `PacketBuffer` drops => `esp_wifi_internal_free_rx_buffer(eb)` (:1396). Extra copies by esp-radio on RX: 0
  (the only copy is the driver's own DMA->rx-buffer copy). Your closure must be quick: each queued frame pins a driver RX buffer
  (static 10 x ~1.6 KB + up to 32 dynamic by default). Must not drop a PacketBuffer inside a critical section.
  `receive()` only yields when BOTH an RX frame is queued AND tx credit exists (inflight < tx_queue_size, default 3) AND STA is Connected (:1465).
  It also calls `yield_task()` when empty, so the poll loop is cooperative with the radio task.
- TX: `WifiTxToken::consume_token` (:2013) zero-fills a stack `[u8; MTU]` (:2019), lets you fill it, then `esp_wifi_send_data` (:2034)
  calls `esp_wifi_internal_tx(WIFI_IF_STA, ptr, len)` (:2053), which copies into its own TX buffer. Extra copies on TX: 1 (your data ->
  stack buffer) + the driver's own copy; plus an MTU-sized memset per frame. Silently drops if STA state != Connected.
- TX done accounting: internal. `esp_wifi_tx_done_cb` (:1295) decrements `WIFI_TX_INFLIGHT`; `transmit()` returns None when
  inflight >= tx_queue_size (default 3, `ControllerConfig::with_tx_queue_size`, unstable). No user hook for tx-done; if you need your own,
  re-register `esp_wifi_set_tx_done_cb` via esp-wifi-sys (breaks the built-in accounting).
- MTU TRAP: `ESP_RADIO_CONFIG_WIFI_MTU` default 1492 (esp_config.yml). A 1493..1514-byte Ethernet frame from the USB host would
  panic on `&mut buffer[..len]` (:2019-2020). This spike sets it to 1514 in `.cargo/config.toml [env]`.

## Source MAC
`esp_wifi_internal_tx` takes the Ethernet frame as-is; the driver converts it to 802.11 with SA/TA from the frame/own MAC (ToDS frame:
addr1=BSSID, addr2=TA/SA, addr3=DA). Frames with src = STA MAC (the bridge case) are the normal case. Non-STA source MACs (a different
host MAC) are not testable without hardware and are not something this API validates or rewrites in software; AP policy decides.
(Not verified on-air: that is what the hardware run measures via the `gw_arp_reply` counter.)

## Settings: what esp-radio exposes
| need | result |
|---|---|
| power save off | `controller.set_power_saving(PowerSaveMode::None)` (:2889, unstable, default is None already) |
| HT20 | `controller.set_bandwidths(controller.bandwidths()?.with_2_4(Bandwidth::_20MHz))` (:3120; `Bandwidths` has no `new/default`, derive from `bandwidths()`) |
| max tx power | `controller.set_max_tx_power(i8)` (:3206, 0.25 dBm units, 8..84; init sets 20 = 5 dBm at :2774; warns >65 may break auth). Spike sets 80 |
| STA MAC | `Interface::mac_address()` (:1616) |
| scan incl. hidden | `controller.scan_async(&ScanConfig::default().with_show_hidden(true)...)` (:3277, scan.rs:99). Async only; `StationConfig` has no hidden-SSID flag (directed connect to a hidden SSID via set_config works in IDF; not verified) |
| rm_enabled / btm_enabled (11k/v) | NOT exposed: `apply_sta_config` builds `_bitfield_1: new([0;4])` (:3623), i.e. all off. Workaround used in this spike: depend directly on `esp-wifi-sys-esp32s3 =0.3` (`esp_radio::sys` is pub(crate)), `esp_wifi_get_config`, `c.sta.set_rm_enabled(1); set_btm_enabled(1)`, `esp_wifi_set_config` after `WifiController::new`. Compiles; behaviour untested. A later `controller.set_config()` with a changed config will overwrite it |
| pmf, sae | pmf capable=true required=false, sae_pwe_h2e=3 hardcoded (:3617-3621) |
| sort/scan method, listen_interval, beacon_timeout, bssid, channel | in `StationConfig` |

## What is NOT possible through the public API
- No hook to receive frames before the internal queue, nor to change queue depth below defaults without `ControllerConfig` (rx_queue_size only grows capacity: `change_capacity` takes max(old,new), :1021).
- rm/btm/mbo/ft flags and 802.11 header-level control (needs esp-wifi-sys).
- Blocking connect; promiscuous/sniffer is a separate `sniffer` feature, unrelated to data path.
Smallest hybrid if the queue/copy overhead matters: keep esp-radio for init/connect/state, then call
`esp_wifi_internal_reg_rxcb(WIFI_IF_STA, my_cb)` from esp-wifi-sys directly to take the callback (driver buffer handed straight to e.g. a USB
bulk-IN endpoint, then `esp_wifi_internal_free_rx_buffer`). No esp-idf-svc needed. Not tried here.

## Footprint (release, opt-level s, lto fat; ELF from `xtensa-esp-elf-size`)
- Image (merged, 16 MiB file): `s1.bin`; app image 437,824 bytes (10.44 % of the 4 MiB factory partition; `espflash` reported 437,824).
- text 426,191 B (incl. .text 320,369; rwtext/IRAM 8,312 + 31,980 wifi = 40,292 B; rodata 29,008 + 35,236 wifi); data 11,520 B; bss 48,224 B
  (includes the 36 KiB `heap_allocator!(size: 36*1024)` static); plus a 64 KiB "reclaimed" heap region (`.dram2_uninit` 65,536 B, bootloader RAM reuse).
  Static DRAM actually used ~ 11.5 + 48.2 = ~60 KB (of which 36 KiB is heap); IRAM ~40 KB. The reported bss 461,308 in the default `size` view includes the linker's `.stack` fill (240 KB) and is not real use.
- Heap: configured 100 KiB total (64 reclaimed + 36 regular). Actual radio-init heap need is NOT measured (not run). The binary prints
  `heap total/used/free` at boot, after `WifiController::new`, and after connect, and `heap_used` in each counter line. Expect roughly
  10 static RX x ~1.6 KB + wifi driver/supplicant allocations (tens of KB); the esp-hal wifi examples use 64 KiB reclaimed + 36 KiB. Coordinator: read those lines and shrink.
- Note: esp-hal/esp-radio need `esp_rtos::start` first (esp-rtos supplies the OS adapter); the scheduler uses TIMG0 timer0 + FROM_CPU_INTR0.

## Files / how to build
`cd rust/spikes/s1-wifi-l2`, then
```
export LIBCLANG_PATH=$(ls -d ~/.rustup/toolchains/esp/xtensa-esp32-elf-clang/*/esp-clang/lib)
export PATH=$(ls -d ~/.rustup/toolchains/esp/xtensa-esp-elf/*/xtensa-esp-elf/bin):$PATH
WIFI_SSID=... WIFI_PASS=... GATEWAY_IP=192.168.x.1 cargo build --release
espflash save-image --chip esp32s3 --flash-mode dio --flash-freq 40mhz --flash-size 16mb --merge \
  --partition-table ../../../partitions.csv target/xtensa-esp32s3-none-elf/release/s1-wifi-l2 s1.bin
```
The committed `s1.bin` was built with DUMMY credentials (WIFI_SSID=dummy): REBUILD with real values before flashing, otherwise it
logs "WIFI_SSID / WIFI_PASS not set" or fails to join. Merged image headers verified: bootloader@0x0 and app@0x20000 both `e9 .. 02 40` =
magic 0xE9, byte2 = 0x02 (DIO), byte3 = 0x40 (16 MB flash size, freq nibble 0x0 = 40 MHz).
Logging: esp-println `auto` = USB-Serial-JTAG on the S3's GPIO19/20 (the same pins the OTG stack will use in S2; fine for this spike).
Counter line every 5 s: `CNT frames=.. bytes=.. max=.. uc_us=.. bc=.. mc=.. uc_other=.. arp=.. ip4=.. ip6=.. eapol=.. other=.. runt=.. src_us=.. gw_arp_reply=.. tx_ok=.. tx_none=.. rssi=.. heap_used=..`
Pass criteria on hardware: `gw_arp_reply` > 0 (ARP probe with src = STA MAC, sender IP 0.0.0.0, was answered by the gateway), `src_us` should stay 0.

## Update: app-only image, NVS credentials, console
`rust/spikes/dist/s1-app.bin` (0x20000 only; build with `rust/spikes/build-app.sh s1-wifi-l2`) replaces the merged `s1.bin` and has no built-in credentials: it reads the saved networks
from the NVS (read-only), scans with `show_hidden`, joins the best-ranked visible one. It now runs under an embassy executor with a USB CDC-ACM console (serial = base MAC; `status` with
`mode=spike_s1`, `boot-status`, `bootloader`, `gw A.B.C.D` to set the ARP-probe target at run time). esp-println output still goes to USB-Serial-JTAG, which disappears once the OTG device starts.
