//! Spike S1 (no_std): raw L2 on an esp-radio Wi-Fi station with no smoltcp / embassy-net.
//!
//! Credentials are read from the existing NVS (read-only, `common/saved.rs`), never built in. The gateway for the ARP probe is set on the
//! console (`gw 192.168.1.1`). A USB CDC-ACM console (serial = chip MAC) answers `status`, `boot-status`, `bootloader`, `gw`.
#![no_std]
#![no_main]

extern crate alloc;

mod acm;
#[path = "../../common/ops.rs"]
mod ops;
#[path = "../../common/guard.rs"]
mod guard;
#[path = "../../common/saved.rs"]
mod saved;

use core::cell::RefCell;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use critical_section::Mutex as CsMutex;
use embassy_executor::Spawner;
use embassy_futures::yield_now;
use embassy_time::{Duration, Instant, Timer};
use embassy_usb::control::{InResponse, OutResponse, Recipient, Request, RequestType};
use embassy_usb::types::{InterfaceNumber, StringIndex};
use embassy_usb::{Builder, Handler, UsbDevice, UsbVersion};
use esp_backtrace as _;
use esp_hal::{clock::CpuClock, timer::timg::TimerGroup};
use tdongle_boot_guard::Stage;
use esp_hal::usb::otg::Usb;
use esp_hal::usb::otg::embassy_usb_device::{Config as OtgConfig, Driver as UsbDriver};
use static_cell::StaticCell;
use esp_println::println;
use esp_radio::wifi::{
    scan::ScanConfig, sta::StationConfig, AuthenticationMethodConfig, Bandwidth, Config, ControllerConfig,
    Interface, PowerSaveMode, WifiController,
};

esp_bootloader_esp_idf::esp_app_desc!();

/// ARP probe target (big-endian IPv4 as u32), 0 = none; set with the console command `gw`.
static GATEWAY: AtomicU32 = AtomicU32::new(0);
static DTR: AtomicBool = AtomicBool::new(false);
static STATS: CsMutex<RefCell<Stats>> = CsMutex::new(RefCell::new(Stats::new()));
static TX_OK: AtomicU32 = AtomicU32::new(0);
static TX_NONE: AtomicU32 = AtomicU32::new(0);
static LINKED: AtomicBool = AtomicBool::new(false);
type Drv = UsbDriver<'static>;

const BCAST: [u8; 6] = [0xff; 6];

fn parse_ip(s: &str) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (i, part) in s.split('.').take(4).enumerate() {
        out[i] = part.parse().unwrap_or(0);
    }
    out
}

#[derive(Default, Clone, Copy)]
struct Stats {
    frames: u32,
    bytes: u64,
    unicast_to_us: u32,
    bcast: u32,
    mcast: u32,
    other_unicast: u32,
    arp: u32,
    ipv4: u32,
    ipv6: u32,
    eapol: u32,
    other_type: u32,
    runt: u32,
    src_is_us: u32,
    arp_reply_from_gw: u32,
    max_len: u16,
}

impl Stats {
    const fn new() -> Self {
        Self { frames: 0, bytes: 0, unicast_to_us: 0, bcast: 0, mcast: 0, other_unicast: 0, arp: 0, ipv4: 0, ipv6: 0, eapol: 0, other_type: 0, runt: 0, src_is_us: 0, arp_reply_from_gw: 0, max_len: 0 }
    }
}

fn classify(st: &mut Stats, f: &[u8], mac: &[u8; 6], gw: [u8; 4]) {
    st.frames += 1;
    st.bytes += f.len() as u64;
    st.max_len = st.max_len.max(f.len() as u16);
    if f.len() < 14 {
        st.runt += 1;
        return;
    }
    let dst = &f[0..6];
    if dst == BCAST {
        st.bcast += 1;
    } else if dst[0] & 1 == 1 {
        st.mcast += 1;
    } else if dst == mac {
        st.unicast_to_us += 1;
    } else {
        st.other_unicast += 1;
    }
    if &f[6..12] == mac {
        st.src_is_us += 1;
    }
    match u16::from_be_bytes([f[12], f[13]]) {
        0x0806 => {
            st.arp += 1;
            // ARP reply (op 2) with sender IP == gateway
            if f.len() >= 42 && f[20] == 0 && f[21] == 2 && f[28..32] == gw {
                st.arp_reply_from_gw += 1;
                println!(
                    "ARP reply: gateway {:?} is-at {:02x?} (eth src {:02x?}, dst {:02x?})",
                    gw,
                    &f[22..28],
                    &f[6..12],
                    dst
                );
            }
        }
        0x0800 => st.ipv4 += 1,
        0x86dd => st.ipv6 += 1,
        0x888e => st.eapol += 1,
        _ => st.other_type += 1,
    }
}

/// Raw Ethernet ARP who-has (probe style, sender IP 0.0.0.0) with eth.src = ARP.sha = STA MAC.
fn build_arp_probe(mac: &[u8; 6], tpa: [u8; 4]) -> [u8; 42] {
    let mut p = [0u8; 42];
    p[0..6].copy_from_slice(&BCAST);
    p[6..12].copy_from_slice(mac);
    p[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    p[14..16].copy_from_slice(&1u16.to_be_bytes()); // htype ethernet
    p[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // ptype IPv4
    p[18] = 6;
    p[19] = 4;
    p[20..22].copy_from_slice(&1u16.to_be_bytes()); // op: request
    p[22..28].copy_from_slice(mac); // sha
    // spa = 0.0.0.0 (p[28..32])
    // tha = 00.. (p[32..38])
    p[38..42].copy_from_slice(&tpa);
    p
}


struct Ctl {
    acm_if: InterfaceNumber,
    acm_str: StringIndex,
    hex: &'static str,
}

impl Handler for Ctl {
    fn reset(&mut self) {
        DTR.store(false, Ordering::Relaxed);
    }
    fn control_out(&mut self, req: Request, _data: &[u8]) -> Option<OutResponse> {
        if req.request_type != RequestType::Class || req.recipient != Recipient::Interface || req.index != u16::from(u8::from(self.acm_if)) {
            return None;
        }
        Some(match req.request {
            0x00 | 0x20 => OutResponse::Accepted,
            0x22 => {
                DTR.store(req.value & 1 != 0, Ordering::Relaxed);
                OutResponse::Accepted
            }
            _ => OutResponse::Rejected,
        })
    }
    fn control_in<'a>(&'a mut self, req: Request, buf: &'a mut [u8]) -> Option<InResponse<'a>> {
        if req.request_type != RequestType::Class || req.recipient != Recipient::Interface || req.index != u16::from(u8::from(self.acm_if)) {
            return None;
        }
        Some(match req.request {
            0x21 if req.length == 7 => {
                buf[0..4].copy_from_slice(&115_200u32.to_le_bytes());
                buf[4] = 0;
                buf[5] = 0;
                buf[6] = 8;
                InResponse::Accepted(&buf[0..7])
            }
            _ => InResponse::Rejected,
        })
    }
    fn get_string(&mut self, index: StringIndex, _lang: u16) -> Option<&str> {
        if index == self.acm_str { Some("Management") } else { let _ = self.hex; None }
    }
}

#[embassy_executor::task]
async fn usb_task(mut dev: UsbDevice<'static, Drv>) -> ! {
    dev.run().await
}

struct Line<const N: usize> {
    buf: [u8; N],
    len: usize,
}
impl<const N: usize> core::fmt::Write for Line<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(N - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

fn counters_line(l: &mut impl core::fmt::Write) {
    let st = critical_section::with(|cs| *STATS.borrow_ref(cs));
    let _ = write!(
        l,
        "CNT frames={} bytes={} max={} uc_us={} bc={} mc={} uc_other={} arp={} ip4={} ip6={} eapol={} other={} runt={} src_us={} gw_arp_reply={} tx_ok={} tx_none={} heap_used={}",
        st.frames, st.bytes, st.max_len, st.unicast_to_us, st.bcast, st.mcast, st.other_unicast, st.arp, st.ipv4, st.ipv6, st.eapol,
        st.other_type, st.runt, st.src_is_us, st.arp_reply_from_gw, TX_OK.load(Ordering::Relaxed), TX_NONE.load(Ordering::Relaxed),
        esp_alloc::HEAP.used()
    );
}

async fn reply(port: &mut acm::Acm<'static, Drv>, text: &[u8]) {
    let _ = embassy_time::with_timeout(Duration::from_millis(500), port.write_all(text)).await;
}

#[embassy_executor::task]
async fn console_task(mut port: acm::Acm<'static, Drv>, state: &'static guard::State) -> ! {
    let mut line = [0u8; 64];
    let mut n = 0usize;
    loop {
        port.wait_connection().await;
        loop {
            let mut pkt = [0u8; 64];
            let Ok(len) = port.read_packet(&mut pkt).await else { break };
            for &c in &pkt[..len] {
                if c == b'\r' || c == b'\n' {
                    if n > 0 {
                        let cmd = core::str::from_utf8(&line[..n]).unwrap_or("").trim();
                        let mut l = Line::<400> { buf: [0; 400], len: 0 };
                        match cmd {
                            "status" => {
                                let linked = LINKED.load(Ordering::Relaxed);
                                let _ = write!(l, "status mode=spike_s1 linked={} up_ms={} ", linked as u8, Instant::now().as_millis());
                                counters_line(&mut l);
                            }
                            "boot-status" => guard::boot_status(&mut l, "s1-wifi-l2", ESP_APP_DESC.app_elf_sha256(), state, Instant::now().as_millis(), Some(esp_alloc::HEAP.free() as u32)),
                            "normal" => {
                                guard::leave_safe_mode();
                                reply(&mut port, b"leaving safe mode: resetting\r\n").await;
                                Timer::after(Duration::from_millis(200)).await;
                                esp_hal::system::software_reset()
                            }
                            "bootloader" => {
                                guard::leave_safe_mode(); // a deliberate reset is not a failed boot
                                reply(&mut port, b"rebooting to ROM download mode\r\n").await;
                                Timer::after(Duration::from_millis(200)).await;
                                ops::enter_bootloader()
                            }
                            "help" | "?" => {
                                let _ = write!(l, "commands: status | boot-status | bootloader | normal | gw A.B.C.D | help");
                            }
                            other if other.starts_with("gw ") => {
                                let ip = parse_ip(other[3..].trim());
                                GATEWAY.store(u32::from_be_bytes(ip), Ordering::Relaxed);
                                let _ = write!(l, "gateway {:?}", ip);
                            }
                            other => {
                                let _ = write!(l, "unknown command: {}", other);
                            }
                        }
                        let _ = l.write_str("\r\n");
                        reply(&mut port, &l.buf[..l.len]).await;
                        n = 0;
                    }
                } else if n < line.len() {
                    line[n] = c;
                    n += 1;
                }
            }
        }
        n = 0;
    }
}

/// Feeds the watchdogs every 500 ms and marks the boot stable after `STABLE_AFTER_MS`.
#[embassy_executor::task]
async fn heartbeat_task(mut dogs: guard::Dogs, safe_mode: bool) -> ! {
    let mut marked = false;
    loop {
        dogs.feed();
        if !marked && Instant::now().as_millis() >= tdongle_boot_guard::STABLE_AFTER_MS {
            guard::mark_stable(safe_mode);
            marked = true;
        }
        Timer::after_millis(500).await;
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    static STATE: StaticCell<guard::State> = StaticCell::new();
    let state: &'static guard::State = STATE.init(guard::begin());
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    // Heap: 64 KiB of reclaimed (post-bootloader) RAM + 36 KiB regular. Measured use printed below.
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    esp_alloc::heap_allocator!(size: 36 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    let dogs = guard::Dogs::arm(peripherals.TIMG1, peripherals.RTC_TIMER);
    guard::stage(Stage::Usb);
    println!("S1 boot. heap total={} used={} free={}", esp_alloc::HEAP.stats().size, esp_alloc::HEAP.used(), esp_alloc::HEAP.free());

    // ---- USB console (CDC-ACM only), serial = chip MAC ----
    static HEX: StaticCell<[u8; 12]> = StaticCell::new();
    let hex = HEX.init(ops::mac_hex(&esp_hal::efuse::base_mac_address().as_bytes().try_into().unwrap_or([0; 6])));
    let hex: &'static str = core::str::from_utf8(hex).unwrap_or("000000000000");
    let usb = Usb::new_fs(peripherals.USB_FS, peripherals.GPIO20, peripherals.GPIO19);
    static EP_OUT: StaticCell<[u8; 128]> = StaticCell::new();
    let driver = UsbDriver::new(usb, EP_OUT.init([0; 128]), OtgConfig::default());
    let mut config = embassy_usb::Config::new(0x303A, 0x4001);
    config.bcd_usb = UsbVersion::Two;
    config.device_release = 0x0100;
    config.manufacturer = Some("T-Dongle Adapter Project");
    config.product = Some("T-Dongle-S3 NCM");
    config.serial_number = Some(hex);
    config.max_power = 500;
    static CFG: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS: StaticCell<[u8; 16]> = StaticCell::new();
    static CTRL: StaticCell<[u8; 64]> = StaticCell::new();
    let mut b = Builder::new(driver, config, CFG.init([0; 256]), BOS.init([0; 16]), &mut [], CTRL.init([0; 64]));
    let (ids, port) = acm::build(&mut b, 64);
    static CTL: StaticCell<Ctl> = StaticCell::new();
    b.handler(CTL.init(Ctl { acm_if: ids.comm_if, acm_str: ids.iface_string, hex }));
    let dev = b.build();
    spawner.spawn(usb_task(dev).unwrap());
    spawner.spawn(console_task(port, state).unwrap());
    spawner.spawn(heartbeat_task(dogs, state.boot.safe_mode).unwrap());
    // The console is up and enumerating: now the steps that can block or fail, each one recorded.
    Timer::after_millis(300).await;
    if state.boot.safe_mode {
        println!("safe mode: storage and radio not started");
        loop {
            Timer::after_secs(60).await;
        }
    }
    guard::stage(Stage::Settings);
    let mut flash = esp_storage::FlashStorage::new(peripherals.FLASH);
    let loaded = saved::load(&mut flash).ok().filter(|l| !l.saved.list().is_empty());
    println!("nvs: {} saved networks", loaded.as_ref().map_or(0, |l| l.saved.list().len()));

    let Some(loaded) = loaded else {
        println!("no saved networks: console stays up");
        loop {
            Timer::after_secs(60).await;
        }
    };

    guard::stage(Stage::RadioInit);
    let Ok(mut controller) = WifiController::new(peripherals.WIFI, ControllerConfig::default()) else {
        println!("radio init failed");
        loop {
            Timer::after_secs(60).await;
        }
    };
    let mut sta = Interface::station();
    let mac = sta.mac_address();
    println!("STA MAC {:02x?}", mac);
    println!("after radio init: heap used={} free={}", esp_alloc::HEAP.used(), esp_alloc::HEAP.free());

    // Tunings, not requirements: a failure is logged and the run goes on.
    if controller.set_power_saving(PowerSaveMode::None).is_err() {
        println!("set_power_saving failed");
    }
    match controller.bandwidths() {
        Ok(bw) => {
            if controller.set_bandwidths(bw.with_2_4(Bandwidth::_20MHz)).is_err() {
                println!("set_bandwidths failed");
            }
        }
        Err(_) => println!("bandwidths failed"),
    }
    if controller.set_max_tx_power(80).is_err() {
        // 0.25 dBm units: 80 = 20 dBm (range 8..84)
        println!("set_max_tx_power failed");
    }

    // 802.11k/v (rm_enabled / btm_enabled): not exposed by esp-radio (it zeroes the bitfields), so go through esp-wifi-sys.
    // SAFETY: plain FFI calls with a zeroed, correctly sized wifi_config_t; the Wi-Fi driver is initialised above.
    unsafe {
        use esp_wifi_sys_esp32s3::include as sys;
        let mut c: sys::wifi_config_t = core::mem::zeroed();
        if sys::esp_wifi_get_config(sys::wifi_interface_t_WIFI_IF_STA, &mut c) == 0 {
            c.sta.set_rm_enabled(1);
            c.sta.set_btm_enabled(1);
            let r = sys::esp_wifi_set_config(sys::wifi_interface_t_WIFI_IF_STA, &mut c);
            println!("set rm/btm via sys: esp_err={}", r);
        }
    }

    // Strongest saved network the scan sees (hidden SSIDs included); none seen: the saved list in order (directed probe finds hidden ones).
    let mut next = 0usize;
    loop {
        guard::stage(Stage::Scan);
        let scan = embassy_time::with_timeout(Duration::from_secs(8), controller.scan_async(&ScanConfig::default().with_show_hidden(true).with_max(40))).await;
        let slot = match scan.map_err(|_| ()).and_then(|r| r.map_err(|_| ())) {
            Ok(aps) => {
                println!("scan(show_hidden): {} APs", aps.len());
                saved::choose(&loaded, aps.iter().map(|a| (a.ssid.as_str(), a.signal_strength)))
            }
            Err(()) => {
                println!("scan failed or timed out");
                None
            }
        };
        let slot = slot.unwrap_or_else(|| {
            next = (next + 1) % loaded.saved.list().len();
            next
        });
        let Some((ssid, pass)) = saved::credentials(&loaded.saved, slot) else {
            Timer::after_secs(2).await;
            continue;
        };
        let auth = match pass.try_into() {
            Ok(p) if !pass.is_empty() => AuthenticationMethodConfig::Wpa2Personal(p),
            _ => AuthenticationMethodConfig::Open,
        };
        let Ok(ssid_t) = ssid.try_into() else {
            Timer::after_secs(2).await;
            continue;
        };
        let sta_cfg = StationConfig::default().with_ssid(ssid_t).with_authentication(auth);
        println!("joining saved slot {}", slot);
        if controller.set_config(&Config::Station(sta_cfg)).is_err() {
            Timer::after_secs(2).await;
            continue;
        }
        guard::stage(Stage::Connect);
        match embassy_time::with_timeout(Duration::from_secs(30), controller.connect_async()).await {
            Ok(Ok(info)) => {
                println!("connected: {:?}", info);
                break;
            }
            Ok(Err(_)) | Err(_) => {
                println!("connect failed or timed out, trying again");
                Timer::after_secs(2).await;
            }
        }
    }
    guard::stage(Stage::Running);
    LINKED.store(true, Ordering::Relaxed);
    println!("after connect: heap used={} free={}", esp_alloc::HEAP.used(), esp_alloc::HEAP.free());

    let mut last_arp = Instant::now() - Duration::from_secs(10);
    let mut last_report = Instant::now();
    loop {
        // RX: drain. receive() returns (rx, tx) tokens only when a frame is queued AND tx credit is available.
        while let Some((rx, _tx)) = sta.receive() {
            let gw = GATEWAY.load(Ordering::Relaxed).to_be_bytes();
            rx.consume_token(|f| critical_section::with(|cs| classify(&mut STATS.borrow_ref_mut(cs), f, &mac, gw)));
        }
        let gw = GATEWAY.load(Ordering::Relaxed);
        if gw != 0 && last_arp.elapsed() >= Duration::from_secs(5) {
            last_arp = Instant::now();
            let frame = build_arp_probe(&mac, gw.to_be_bytes());
            match sta.transmit() {
                Some(tx) => {
                    tx.consume_token(frame.len(), |b| b.copy_from_slice(&frame));
                    TX_OK.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    TX_NONE.fetch_add(1, Ordering::Relaxed); // link down or tx queue full
                }
            }
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            last_report = Instant::now();
            let mut l = Line::<400> { buf: [0; 400], len: 0 };
            counters_line(&mut l);
            println!("{} rssi={:?}", core::str::from_utf8(&l.buf[..l.len]).unwrap_or(""), controller.rssi().ok());
        }
        yield_now().await;
    }
}
