//! Spike S1 (no_std): raw L2 on an esp-radio Wi-Fi station with no smoltcp / embassy-net.
//!
//! Credentials come from compile-time env: WIFI_SSID, WIFI_PASS. Gateway: GATEWAY_IP (default 192.168.1.1).
#![no_std]
#![no_main]

extern crate alloc;

use esp_backtrace as _;
use esp_hal::{clock::CpuClock, main, time::{Duration, Instant}, timer::timg::TimerGroup};
use esp_println::println;
use esp_radio::wifi::{
    scan::ScanConfig, sta::StationConfig, AuthenticationMethodConfig, Bandwidth, Config, ControllerConfig,
    Interface, PowerSaveMode, WifiController,
};

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: Option<&str> = option_env!("WIFI_SSID");
const PASS: Option<&str> = option_env!("WIFI_PASS");
const GATEWAY_IP: &str = match option_env!("GATEWAY_IP") {
    Some(s) => s,
    None => "192.168.1.1",
};

const BCAST: [u8; 6] = [0xff; 6];

fn parse_ip(s: &str) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (i, part) in s.split('.').take(4).enumerate() {
        out[i] = part.parse().unwrap_or(0);
    }
    out
}

#[derive(Default)]
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
                    "ARP reply: gateway {} is-at {:02x?} (eth src {:02x?}, dst {:02x?})",
                    GATEWAY_IP,
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

#[main]
fn main() -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    // Heap: 64 KiB of reclaimed (post-bootloader) RAM + 36 KiB regular. Measured use printed below.
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    esp_alloc::heap_allocator!(size: 36 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    println!("S1 boot. heap total={} used={} free={}", esp_alloc::HEAP.stats().size, esp_alloc::HEAP.used(), esp_alloc::HEAP.free());

    let (Some(ssid), Some(pass)) = (SSID, PASS) else {
        println!("WIFI_SSID / WIFI_PASS not set at build time; rebuild with them. Halting.");
        loop {}
    };
    let gw = parse_ip(GATEWAY_IP);

    let sta_cfg = StationConfig::default()
        .with_ssid(ssid.try_into().unwrap())
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(pass.try_into().unwrap()));
    let cfg = ControllerConfig::default().with_initial_config(Config::Station(sta_cfg.clone()));
    let mut controller: WifiController<'_> = WifiController::new(peripherals.WIFI, cfg).unwrap();
    let mut sta = Interface::station();
    let mac = sta.mac_address();
    println!("STA MAC {:02x?}", mac);
    println!("after radio init: heap used={} free={}", esp_alloc::HEAP.used(), esp_alloc::HEAP.free());

    controller.set_power_saving(PowerSaveMode::None).unwrap();
    let bw = controller.bandwidths().unwrap().with_2_4(Bandwidth::_20MHz);
    controller.set_bandwidths(bw).unwrap();
    controller.set_max_tx_power(80).unwrap(); // 0.25 dBm units: 80 = 20 dBm (range 8..84)

    // 802.11k/v (rm_enabled / btm_enabled): not exposed by esp-radio (it zeroes the bitfields), so go through esp-wifi-sys.
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

    // Hidden-network-capable scan for the configured SSID (show_hidden = true).
    match embassy_futures::block_on(controller.scan_async(&ScanConfig::default().with_show_hidden(true).with_max(10))) {
        Ok(aps) => println!("scan(show_hidden): {} APs", aps.len()),
        Err(e) => println!("scan failed: {:?}", e),
    }

    loop {
        match embassy_futures::block_on(controller.connect_async()) {
            Ok(info) => {
                println!("connected: {:?}", info);
                break;
            }
            Err(e) => {
                println!("connect failed: {:?}, retrying", e);
                let t = Instant::now();
                while t.elapsed() < Duration::from_millis(2000) {}
            }
        }
    }
    println!("after connect: heap used={} free={}", esp_alloc::HEAP.used(), esp_alloc::HEAP.free());

    let mut st = Stats::default();
    let mut last_arp = Instant::now() - Duration::from_secs(10);
    let mut last_report = Instant::now();
    let (mut tx_ok, mut tx_none) = (0u32, 0u32);
    loop {
        // RX: drain. receive() returns (rx, tx) tokens only when a frame is queued AND tx credit is available.
        while let Some((rx, _tx)) = sta.receive() {
            rx.consume_token(|f| classify(&mut st, f, &mac, gw));
        }
        if last_arp.elapsed() >= Duration::from_secs(5) {
            last_arp = Instant::now();
            let frame = build_arp_probe(&mac, gw);
            match sta.transmit() {
                Some(tx) => {
                    tx.consume_token(frame.len(), |b| b.copy_from_slice(&frame));
                    tx_ok += 1;
                }
                None => tx_none += 1, // link down or tx queue full
            }
        }
        if last_report.elapsed() >= Duration::from_secs(5) {
            last_report = Instant::now();
            println!(
                "CNT frames={} bytes={} max={} uc_us={} bc={} mc={} uc_other={} arp={} ip4={} ip6={} eapol={} other={} runt={} src_us={} gw_arp_reply={} tx_ok={} tx_none={} rssi={:?} heap_used={}",
                st.frames, st.bytes, st.max_len, st.unicast_to_us, st.bcast, st.mcast, st.other_unicast, st.arp, st.ipv4, st.ipv6,
                st.eapol, st.other_type, st.runt, st.src_is_us, st.arp_reply_from_gw, tx_ok, tx_none, controller.rssi().ok(),
                esp_alloc::HEAP.used()
            );
        }
    }
}
