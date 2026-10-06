//! Spike S2 (no_std): USB composite device on the ESP32-S3 native OTG (full speed):
//! one CDC-ACM console (`status`, `hold on|off`) + one CDC-NCM function running an Ethernet reflector.
#![no_std]
#![no_main]

#[path = "../../common/ops.rs"]
mod ops;
mod acm;
mod ncm;

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Instant, Timer};
use embassy_usb::control::{InResponse, OutResponse, Recipient, Request, RequestType};
use embassy_usb::types::{InterfaceNumber, StringIndex};
use embassy_usb::{Builder, Handler, UsbDevice, UsbVersion};
use esp_backtrace as _;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::usb::otg::Usb;
use esp_hal::usb::otg::embassy_usb_device::{Config as OtgConfig, Driver as UsbDriver};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

const MTU: usize = 1514;

type Drv = UsbDriver<'static>;

// ---- shared counters (read by `status`) ----
static RX_FRAMES: AtomicU32 = AtomicU32::new(0);
static RX_BYTES: AtomicU32 = AtomicU32::new(0);
static TX_FRAMES: AtomicU32 = AtomicU32::new(0);
static TX_BYTES: AtomicU32 = AtomicU32::new(0);
static RX_RUNT: AtomicU32 = AtomicU32::new(0);
static CHAN_FULL_WAITS: AtomicU32 = AtomicU32::new(0);
static HOLD: AtomicBool = AtomicBool::new(cfg!(feature = "hold-rx"));
static HOLD_SINCE_MS: AtomicU32 = AtomicU32::new(0);
static ALT: AtomicU8 = AtomicU8::new(0);
static DTR: AtomicBool = AtomicBool::new(false);
static RESETS: AtomicU32 = AtomicU32::new(0);
/// What the data path does with OUT datagrams and the IN endpoint (console `reflect`, `sink`, `source`): measure each USB direction alone.
const MODE_REFLECT: u8 = 0;
const MODE_SINK: u8 = 1;
const MODE_SOURCE: u8 = 2;
static MODE: AtomicU8 = AtomicU8::new(MODE_REFLECT);
/// `source` rate in kbit/s of frame bytes; 0 = as fast as the endpoint takes them.
static SOURCE_KBPS: AtomicU32 = AtomicU32::new(0);
/// Length of the dummy frames `source` sends (a 1,442 B Ethernet frame, header included).
const SOURCE_FRAME: usize = 1442;

struct Frame {
    len: usize,
    data: [u8; MTU],
}
static REFLECT: Channel<CriticalSectionRawMutex, Frame, 4> = Channel::new();

// ---- combined control handler: strings + ACM + NCM class requests ----
struct Ctl {
    acm_if: InterfaceNumber,
    ncm_if: InterfaceNumber,
    ncm_data_if: InterfaceNumber,
    acm_str: StringIndex,
    ncm_str: StringIndex,
    mac_str: StringIndex,
    mac_hex: &'static str,
}

impl Handler for Ctl {
    fn reset(&mut self) {
        RESETS.fetch_add(1, Ordering::Relaxed);
        DTR.store(false, Ordering::Relaxed);
        ALT.store(0, Ordering::Relaxed);
    }

    fn set_alternate_setting(&mut self, iface: InterfaceNumber, alt: u8) {
        if iface == self.ncm_data_if {
            ALT.store(alt, Ordering::Relaxed);
        }
    }

    fn control_out(&mut self, req: Request, data: &[u8]) -> Option<OutResponse> {
        if req.request_type != RequestType::Class || req.recipient != Recipient::Interface {
            return None;
        }
        if req.index == u16::from(u8::from(self.acm_if)) {
            return Some(match req.request {
                0x00 | 0x20 => OutResponse::Accepted, // SEND_ENCAPSULATED, SET_LINE_CODING
                0x22 => {
                    DTR.store(req.value & 1 != 0, Ordering::Relaxed);
                    OutResponse::Accepted
                }
                _ => OutResponse::Rejected,
            });
        }
        if req.index == u16::from(u8::from(self.ncm_if)) {
            return Some(match req.request {
                ncm::REQ_SEND_ENCAPSULATED_COMMAND => OutResponse::Accepted,
                ncm::REQ_SET_ETHERNET_PACKET_FILTER => {
                    ncm::PKT_FILTER.store(req.value as u32, Ordering::Relaxed);
                    OutResponse::Accepted
                }
                ncm::REQ_SET_NTB_FORMAT if req.value == 0 => OutResponse::Accepted, // NTB-16 only
                ncm::REQ_SET_NTB_INPUT_SIZE if data.len() >= 4 => {
                    let sz = u32::from_le_bytes(data[0..4].try_into().unwrap());
                    ncm::NTB_IN_SIZE_SET.store(sz, Ordering::Relaxed);
                    OutResponse::Accepted
                }
                _ => OutResponse::Rejected,
            });
        }
        None
    }

    fn control_in<'a>(&'a mut self, req: Request, buf: &'a mut [u8]) -> Option<InResponse<'a>> {
        if req.request_type != RequestType::Class || req.recipient != Recipient::Interface {
            return None;
        }
        if req.index == u16::from(u8::from(self.acm_if)) {
            return Some(match req.request {
                0x21 if req.length == 7 => {
                    buf[0..4].copy_from_slice(&115_200u32.to_le_bytes());
                    buf[4] = 0;
                    buf[5] = 0;
                    buf[6] = 8;
                    InResponse::Accepted(&buf[0..7])
                }
                _ => InResponse::Rejected,
            });
        }
        if req.index == u16::from(u8::from(self.ncm_if)) {
            return Some(match req.request {
                ncm::REQ_GET_NTB_PARAMETERS => InResponse::Accepted(ncm::ntb_parameters(buf)),
                ncm::REQ_GET_NTB_FORMAT => {
                    buf[0..2].copy_from_slice(&0u16.to_le_bytes());
                    InResponse::Accepted(&buf[0..2])
                }
                ncm::REQ_GET_NTB_INPUT_SIZE => {
                    let v = ncm::NTB_IN_SIZE_SET.load(Ordering::Relaxed);
                    buf[0..4].copy_from_slice(&v.to_le_bytes());
                    InResponse::Accepted(&buf[0..4])
                }
                _ => InResponse::Rejected,
            });
        }
        None
    }

    fn get_string(&mut self, index: StringIndex, _lang: u16) -> Option<&str> {
        if index == self.acm_str {
            Some("Management")
        } else if index == self.ncm_str {
            Some("USB network")
        } else if index == self.mac_str {
            Some(self.mac_hex)
        } else {
            None
        }
    }
}

type NcmSender = ncm::Sender<'static, Drv>;
type NcmReceiver = ncm::Receiver<'static, Drv>;
type AcmPort = acm::Acm<'static, Drv>;

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    // Stable "chip MAC" -> 12 uppercase hex digits for the serial and the NCM iMACAddress string (same as the C firmware).
    let mac = esp_hal::efuse::base_mac_address();
    static HEX: StaticCell<[u8; 12]> = StaticCell::new();
    let hex = HEX.init(ops::mac_hex(mac.as_bytes().try_into().unwrap()));
    let hex: &'static str = core::str::from_utf8(hex).unwrap();

    let usb = Usb::new_fs(peripherals.USB_FS, peripherals.GPIO20, peripherals.GPIO19);
    // OUT endpoints: EP0 (64) + ACM bulk (64) + NCM bulk (64) = 192 B needed.
    static EP_OUT: StaticCell<[u8; 192]> = StaticCell::new();
    let driver = UsbDriver::new(usb, EP_OUT.init([0; 192]), OtgConfig::default());

    let mut config = embassy_usb::Config::new(0x303A, 0x4001);
    config.bcd_usb = UsbVersion::Two; // C: bcdUSB 0x0200 (upstream default 0x0210 also makes the host fetch a BOS)
    config.device_release = 0x0100;
    config.manufacturer = Some("T-Dongle Adapter Project");
    config.product = Some("T-Dongle-S3 NCM");
    config.serial_number = Some(hex);
    config.max_power = 500; // C: bMaxPower 250 (500 mA), bmAttributes 0x80
    config.self_powered = false;
    config.supports_remote_wakeup = false;

    static CFG: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS: StaticCell<[u8; 16]> = StaticCell::new();
    static CTRL: StaticCell<[u8; 64]> = StaticCell::new();
    let mut b = Builder::new(driver, config, CFG.init([0; 256]), BOS.init([0; 16]), &mut [], CTRL.init([0; 64]));

    let (acm_ids, acm) = acm::build(&mut b, 64);
    let (ncm_ids, ncm) = ncm::build(&mut b, 64);

    static CTL: StaticCell<Ctl> = StaticCell::new();
    b.handler(CTL.init(Ctl {
        acm_if: acm_ids.comm_if,
        ncm_if: ncm_ids.comm_if,
        ncm_data_if: ncm_ids.data_if,
        acm_str: acm_ids.iface_string,
        ncm_str: ncm_ids.iface_string,
        mac_str: ncm_ids.mac_string,
        mac_hex: hex,
    }));

    static NTB: StaticCell<[u8; ncm::NTB_OUT_MAX]> = StaticCell::new();
    let (tx, rx) = ncm.split(NTB.init([0; ncm::NTB_OUT_MAX]));

    let dev = b.build();
    spawner.spawn(usb_task(dev).unwrap());
    spawner.spawn(console_task(acm).unwrap());
    spawner.spawn(rx_task(rx).unwrap());
    spawner.spawn(tx_task(tx).unwrap());
    core::future::pending().await
}

#[embassy_executor::task]
async fn usb_task(mut dev: UsbDevice<'static, Drv>) -> ! {
    dev.run().await
}

/// Receive NCM OUT NTBs, reflect every datagram (src/dst MAC swapped) into the TX channel.
/// BACKPRESSURE: while `HOLD` is set this task calls neither `read_ntb` nor `next_datagram`, so the
/// OUT endpoint is never re-armed and the host is NAKed (see FINDINGS.md).
#[embassy_executor::task]
async fn rx_task(mut rx: NcmReceiver) -> ! {
    loop {
        if rx.wait_connection().await.is_err() {
            continue;
        }
        'conn: loop {
            while HOLD.load(Ordering::Relaxed) {
                Timer::after(Duration::from_millis(10)).await;
            }
            let mut f = Frame { len: 0, data: [0; MTU] };
            match rx.peek_datagram() {
                Some(d) => {
                    let n = d.len();
                    f.data[..n].copy_from_slice(d);
                    f.len = n;
                    RX_FRAMES.fetch_add(1, Ordering::Relaxed);
                    RX_BYTES.fetch_add(n as u32, Ordering::Relaxed);
                    if MODE.load(Ordering::Relaxed) != MODE_REFLECT {
                        // `sink`/`source`: counted above, not echoed
                    } else if n >= 14 {
                        let (dst, rest) = f.data.split_at_mut(6);
                        dst.swap_with_slice(&mut rest[..6]);
                        if REFLECT.is_full() {
                            CHAN_FULL_WAITS.fetch_add(1, Ordering::Relaxed);
                        }
                        // Datagram-granular backpressure: the datagram stays in the NTB buffer (not advanced)
                        // until the TX queue accepted it; while this awaits, the OUT endpoint is not re-armed.
                        REFLECT.send(f).await;
                    } else {
                        RX_RUNT.fetch_add(1, Ordering::Relaxed);
                    }
                    rx.advance();
                }
                None => {
                    if rx.read_ntb().await.is_err() {
                        break 'conn; // endpoint disabled (host closed the data interface / reset)
                    }
                }
            }
        }
    }
}

#[embassy_executor::task]
async fn tx_task(mut tx: NcmSender) -> ! {
    let mut dummy = [0u8; SOURCE_FRAME];
    dummy[0..6].fill(0xff); // broadcast
    dummy[6..12].copy_from_slice(&[0x02, 0x54, 0x44, 0x53, 0x32, 0x01]); // locally administered source
    dummy[12..14].copy_from_slice(&0x88b5u16.to_be_bytes()); // IEEE 802 local experimental ethertype
    let mut seq = 0u32;
    let mut next = Instant::now();
    loop {
        if MODE.load(Ordering::Relaxed) == MODE_SOURCE {
            dummy[14..18].copy_from_slice(&seq.to_be_bytes());
            match tx.write_packet(&dummy).await {
                Ok(()) => {
                    seq = seq.wrapping_add(1);
                    TX_FRAMES.fetch_add(1, Ordering::Relaxed);
                    TX_BYTES.fetch_add(SOURCE_FRAME as u32, Ordering::Relaxed);
                }
                Err(_) => Timer::after(Duration::from_millis(10)).await, // not configured / endpoint disabled
            }
            let kbps = SOURCE_KBPS.load(Ordering::Relaxed);
            if kbps != 0 {
                // frame bits / (kbit/s) = ms per 1000 frames-bits: interval in us = bytes * 8 * 1000 / kbps
                next += Duration::from_micros(SOURCE_FRAME as u64 * 8 * 1000 / u64::from(kbps));
                let now = Instant::now();
                if next > now {
                    Timer::at(next).await;
                } else if now - next > Duration::from_millis(100) {
                    next = now; // the endpoint cannot keep up with this rate: do not bank a backlog
                }
            } else {
                next = Instant::now();
            }
            continue;
        }
        next = Instant::now();
        // reflect: echo what rx_task queued; wake regularly to notice a mode change
        let Ok(f) = embassy_time::with_timeout(Duration::from_millis(50), REFLECT.receive()).await else { continue };
        if MODE.load(Ordering::Relaxed) != MODE_REFLECT {
            continue; // a frame queued before the switch to `sink`/`source`: dropped
        }
        if tx.write_packet(&f.data[..f.len]).await.is_ok() {
            TX_FRAMES.fetch_add(1, Ordering::Relaxed);
            TX_BYTES.fetch_add(f.len as u32, Ordering::Relaxed);
        }
    }
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

async fn reply(port: &mut AcmPort, args: core::fmt::Arguments<'_>) {
    let mut l = Line::<320> { buf: [0; 320], len: 0 };
    let _ = l.write_fmt(args);
    let _ = l.write_str("\r\n");
    // Do not wedge the console if nobody reads the port.
    let _ = embassy_time::with_timeout(Duration::from_millis(500), port.write_all(&l.buf[..l.len])).await;
}

#[embassy_executor::task]
async fn console_task(mut port: AcmPort) -> ! {
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
                        handle(&mut port, cmd).await;
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

async fn handle(port: &mut AcmPort, cmd: &str) {
    match cmd {
        "status" => {
            let up = Instant::now().as_millis();
            reply(
                port,
                format_args!(
                    "status mode=spike_s2 path={}{} up_ms={} alt={} dtr={} resets={} hold={} rx_ntbs={} rx_frames={} rx_bytes={} rx_runt={} rx_bad_ntb={} rx_drop={} tx_frames={} tx_bytes={} chan_full={} filter={:#x} ntb_in={}",
                    ["reflect", "sink", "source"][usize::from(MODE.load(Ordering::Relaxed)).min(2)],
                    if MODE.load(Ordering::Relaxed) == MODE_SOURCE { if SOURCE_KBPS.load(Ordering::Relaxed) == 0 { "(max)" } else { "(rate)" } } else { "" },
                    up,
                    ALT.load(Ordering::Relaxed),
                    DTR.load(Ordering::Relaxed) as u8,
                    RESETS.load(Ordering::Relaxed),
                    HOLD.load(Ordering::Relaxed) as u8,
                    ncm::RX_NTBS.load(Ordering::Relaxed),
                    RX_FRAMES.load(Ordering::Relaxed),
                    RX_BYTES.load(Ordering::Relaxed),
                    RX_RUNT.load(Ordering::Relaxed),
                    ncm::RX_BAD_NTB.load(Ordering::Relaxed),
                    ncm::RX_BAD_DGRAM.load(Ordering::Relaxed),
                    TX_FRAMES.load(Ordering::Relaxed),
                    TX_BYTES.load(Ordering::Relaxed),
                    CHAN_FULL_WAITS.load(Ordering::Relaxed),
                    ncm::PKT_FILTER.load(Ordering::Relaxed),
                    ncm::NTB_IN_SIZE_SET.load(Ordering::Relaxed),
                ),
            )
            .await
        }
        "reflect" => {
            MODE.store(MODE_REFLECT, Ordering::Relaxed);
            reply(port, format_args!("path reflect: OUT datagrams are echoed (default)")).await
        }
        "sink" => {
            MODE.store(MODE_SINK, Ordering::Relaxed);
            reply(port, format_args!("path sink: OUT datagrams are counted (rx_frames, rx_bytes) and dropped, nothing is sent on IN")).await
        }
        c if c == "source" || c.starts_with("source ") => {
            let arg = c.strip_prefix("source").unwrap_or("").trim();
            let kbps = if arg == "max" { Some(0) } else { arg.parse::<u32>().ok().filter(|k| *k > 0) };
            match kbps {
                Some(k) => {
                    SOURCE_KBPS.store(k, Ordering::Relaxed);
                    MODE.store(MODE_SOURCE, Ordering::Relaxed);
                    if k == 0 {
                        reply(port, format_args!("path source: {} B broadcast frames on IN as fast as the endpoint takes them (tx_frames, tx_bytes)", SOURCE_FRAME)).await
                    } else {
                        reply(port, format_args!("path source: {} B broadcast frames on IN at {} kbit/s (tx_frames, tx_bytes)", SOURCE_FRAME, k)).await
                    }
                }
                None => reply(port, format_args!("usage: source RATE_KBPS|max")).await,
            }
        }
        "hold on" => {
            HOLD_SINCE_MS.store(Instant::now().as_millis() as u32, Ordering::Relaxed);
            HOLD.store(true, Ordering::Relaxed);
            reply(port, format_args!("hold on: NCM OUT no longer read")).await
        }
        "hold off" => {
            HOLD.store(false, Ordering::Relaxed);
            let held = Instant::now().as_millis() as u32 - HOLD_SINCE_MS.load(Ordering::Relaxed);
            reply(port, format_args!("hold off (held {} ms)", held)).await
        }
        "boot-status" => {
            let mut l = Line::<320> { buf: [0; 320], len: 0 };
            ops::boot_status(&mut l, "s2-usb-ncm", ESP_APP_DESC.app_elf_sha256(), Instant::now().as_millis());
            reply(port, format_args!("{}", core::str::from_utf8(&l.buf[..l.len]).unwrap_or(""))).await
        }
        "bootloader" => {
            reply(port, format_args!("rebooting to ROM download mode")).await;
            Timer::after(Duration::from_millis(200)).await;
            ops::enter_bootloader()
        }
        "help" | "?" => reply(port, format_args!("commands: status | boot-status | bootloader | reflect | sink | source RATE_KBPS|max | hold on | hold off | help")).await,
        _ => reply(port, format_args!("unknown command: {}", cmd)).await,
    }
}
