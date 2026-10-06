//! Spike S3 (no_std): the transparent Wi-Fi bridge = S1 (esp-radio raw L2 STA) + S2 (embassy-usb CDC-ACM + CDC-NCM),
//! host -> Wi-Fi through the real `tdongle-bridge` crate (bounded queue, HOLD/RESUME, CoDel/ECN, counters).
//!
//! Credentials: compile-time env WIFI_SSID / WIFI_PASS (never in the source). CPU clock: 240 MHz fixed (`CpuClock::max()`).
//! Console: the CDC-ACM port (`status`, `help`, `heap on|off`, `heap`); USB-Serial-JTAG is unavailable once the OTG core runs.
#![no_std]
#![no_main]

extern crate alloc;

mod acm;
mod ncm;

use alloc::string::String;
use core::cell::RefCell;
use core::fmt::Write as _;
use core::future::poll_fn;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, Ordering};
use core::task::Poll;

use critical_section::Mutex as CsMutex;
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_futures::yield_now;
use embassy_net_driver::Driver as NetDriver;
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embassy_usb::control::{InResponse, OutResponse, Recipient, Request, RequestType};
use embassy_usb::types::{InterfaceNumber, StringIndex};
use embassy_usb::{Builder, Handler, UsbDevice, UsbVersion};
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::usb::otg::Usb;
use esp_hal::usb::otg::embassy_usb_device::{Config as OtgConfig, Driver as UsbDriver};
use esp_println::println;
use esp_radio::wifi::{
    AuthenticationMethodConfig, Bandwidth, Config, ControllerConfig, Interface, PowerSaveMode, WifiController,
    sta::StationConfig,
};
use static_cell::StaticCell;
use tdongle_bridge::{Bridge, Env, HostOutcome, RingSend, TaskContext, TxError};
use tdongle_serial::bridge_report::{Report, RingReport, RxClassReport, WifiTxReport, write_status_lines};
use tdongle_serial::command::Command;
use tdongle_serial::console::{Event, LineReader};
use tdongle_serial::memory_log::Record;
use tdongle_serial::reply;
use tdongle_serial::status::{DisplayState, Mode, Prefs, Snapshot, Traffic, write_status};
use tdongle_serial::wifi_link::{Events, Info};

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: Option<&str> = option_env!("WIFI_SSID");
const PASS: Option<&str> = option_env!("WIFI_PASS");

const FIRMWARE: &str = "0.3.0-s3-spike";
const MTU: usize = 1514;
/// esp-radio queues: the C budget is 6 frames in flight to the radio.
const WIFI_TX_QUEUE: usize = 6;
const WIFI_RX_QUEUE: usize = 8;
/// Heap: 64 KiB reclaimed (post-bootloader DRAM) + this regular region.
const HEAP_RECLAIMED: usize = 64 * 1024;
const HEAP_REGULAR: usize = 48 * 1024;
const CPU_MHZ: u32 = 240;

type Drv = UsbDriver<'static>;
type AcmWriter = acm::AcmWriter<'static, Drv>;
type AcmReader = acm::AcmReader<'static, Drv>;
type NcmSender = ncm::Sender<'static, Drv>;
type NcmReceiver = ncm::Receiver<'static, Drv>;

// ======================================================================================================================
// Shared state
// ======================================================================================================================

static ALT: AtomicU8 = AtomicU8::new(0); // NCM data interface alternate setting (1 = streaming)
static CONFIGURED: AtomicBool = AtomicBool::new(false);
static DTR: AtomicBool = AtomicBool::new(false);
static RESETS: AtomicU32 = AtomicU32::new(0);
static LINK_UP_USB: AtomicBool = AtomicBool::new(false); // what the bridge told the USB side (carrier)
static WIFI_RX_ON: AtomicBool = AtomicBool::new(false);
static HEAP_STREAM: AtomicBool = AtomicBool::new(true);

// Wi-Fi link info for `status`
static RSSI: AtomicI32 = AtomicI32::new(0);
static RSSI_VALID: AtomicBool = AtomicBool::new(false);
static CHANNEL: AtomicU8 = AtomicU8::new(0);
static CONNECTS: AtomicU32 = AtomicU32::new(0);
static DISCONNECTS: AtomicU32 = AtomicU32::new(0);
static LAST_REASON: AtomicU32 = AtomicU32::new(0);

// USB ring (Wi-Fi -> host) counters
static RING_ENQ: AtomicU32 = AtomicU32::new(0);
static RING_SENT: AtomicU32 = AtomicU32::new(0);
static RING_FULL: AtomicU32 = AtomicU32::new(0);
static RING_NOT_READY: AtomicU32 = AtomicU32::new(0);
static RING_FLUSHED: AtomicU32 = AtomicU32::new(0);
static RING_HIGH: AtomicU32 = AtomicU32::new(0);
static RING_WRITE_ERR: AtomicU32 = AtomicU32::new(0);
static DOWN_BYTES: AtomicU32 = AtomicU32::new(0);
static DOWN_FRAMES: AtomicU32 = AtomicU32::new(0);
// host -> Wi-Fi (receiver side)
static RX_DATAGRAMS: AtomicU32 = AtomicU32::new(0);
static UP_BYTES: AtomicU32 = AtomicU32::new(0);
static UP_FRAMES: AtomicU32 = AtomicU32::new(0);
static HOLDS: AtomicU32 = AtomicU32::new(0);
static HOLD_US_SUM: AtomicU32 = AtomicU32::new(0);
static HOLD_US_MAX: AtomicU32 = AtomicU32::new(0);
// Wi-Fi TX
static WIFI_TX_REFUSED: AtomicU32 = AtomicU32::new(0);
static WIFI_TX_ROOM_NO: AtomicU32 = AtomicU32::new(0);

static RING_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static WORKER_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static RESUME_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();

// ---- Wi-Fi -> host: bounded drop-tail ring of whole frames (the C's slab ring, simplified) ----
const RING_SLOTS: usize = 8;

struct RingSlot {
    len: u16,
    data: [u8; MTU],
}
struct Ring {
    slots: [RingSlot; RING_SLOTS],
    head: usize,
    count: usize,
}
impl Ring {
    const EMPTY: RingSlot = RingSlot { len: 0, data: [0; MTU] };
    const fn new() -> Self {
        Self { slots: [Self::EMPTY; RING_SLOTS], head: 0, count: 0 }
    }
    fn push(&mut self, frame: &[u8]) -> bool {
        if self.count == RING_SLOTS {
            return false;
        }
        let i = (self.head + self.count) % RING_SLOTS;
        self.slots[i].data[..frame.len()].copy_from_slice(frame);
        self.slots[i].len = frame.len() as u16;
        self.count += 1;
        RING_HIGH.fetch_max(self.count as u32, Ordering::Relaxed);
        true
    }
    fn pop_into(&mut self, out: &mut [u8; MTU]) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let s = &self.slots[self.head];
        let n = s.len as usize;
        out[..n].copy_from_slice(&s.data[..n]);
        self.head = (self.head + 1) % RING_SLOTS;
        self.count -= 1;
        Some(n)
    }
    fn flush(&mut self) -> usize {
        let n = self.count;
        self.count = 0;
        self.head = 0;
        n
    }
}
static RING: CsMutex<RefCell<Ring>> = CsMutex::new(RefCell::new(Ring::new()));

// ======================================================================================================================
// The Env of tdongle-bridge
// ======================================================================================================================

struct FwEnv {
    iface: &'static RefCell<Interface>,
}

impl Env for FwEnv {
    fn now_us(&self) -> u32 {
        Instant::now().as_micros() as u32
    }

    // Wi-Fi RX callback context (the poll task): copy and return, never wait.
    fn usb_ring_send(&self, frame: &[u8]) -> RingSend {
        if ALT.load(Ordering::Relaxed) == 0 {
            RING_NOT_READY.fetch_add(1, Ordering::Relaxed);
            return RingSend::NotReady;
        }
        if frame.is_empty() || frame.len() > MTU {
            return RingSend::Invalid;
        }
        if critical_section::with(|cs| RING.borrow_ref_mut(cs).push(frame)) {
            RING_ENQ.fetch_add(1, Ordering::Relaxed);
            RING_SIG.signal(());
            RingSend::Accepted
        } else {
            RING_FULL.fetch_add(1, Ordering::Relaxed);
            RingSend::Full
        }
    }

    fn usb_ring_flush(&self) {
        let n = critical_section::with(|cs| RING.borrow_ref_mut(cs).flush());
        RING_FLUSHED.fetch_add(n as u32, Ordering::Relaxed);
    }

    fn usb_link_state(&self, up: bool) {
        // Deviation: only recorded. No NETWORK_CONNECTION notification on the interrupt endpoint on a carrier change
        // (S2's receiver sends it once, when the host selects alt 1).
        LINK_UP_USB.store(up, Ordering::Relaxed);
    }

    fn wifi_rx_register(&self, on: bool) {
        WIFI_RX_ON.store(on, Ordering::Release);
    }

    fn notify_worker(&self) {
        WORKER_SIG.signal(());
    }

    fn wifi_tx(&self, frame: &[u8], _context: &TaskContext) -> Result<(), TxError> {
        let token = self.iface.borrow_mut().transmit();
        match token {
            Some(tx) => {
                tx.consume_token(frame.len(), |b| b.copy_from_slice(frame));
                Ok(())
            }
            None => {
                WIFI_TX_REFUSED.fetch_add(1, Ordering::Relaxed);
                Err(TxError::NoMem)
            }
        }
    }

    fn wifi_room(&self) -> bool {
        // esp-radio owns the in-flight accounting (tx_queue_size); a token exists iff inflight < queue size and the link is up.
        let room = self.iface.borrow_mut().transmit().is_some();
        if !room {
            WIFI_TX_ROOM_NO.fetch_add(1, Ordering::Relaxed);
        }
        room
    }

    fn wait_retry(&self, _context: &TaskContext) {
        // Only reached when `wifi_room` was true and the driver still refused, or the room wait was skipped (rare): the async worker
        // normally waits for room on the TX-done waker before calling `drain_one`. Blocking 500 us on the current thread.
        esp_rtos::CurrentThreadHandle::get().delay(esp_hal::time::Duration::from_micros(tdongle_bridge::RETRY_US as u64));
    }

    fn rx_resume(&self, _context: &TaskContext) {
        RESUME_SIG.signal(());
    }

    fn note_activity(&self) {
        // CPU is 240 MHz fixed: nothing to raise.
    }
}

// ======================================================================================================================
// USB control handler (copied from S2, plus `configured`)
// ======================================================================================================================

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
        CONFIGURED.store(false, Ordering::Relaxed);
    }

    fn configured(&mut self, configured: bool) {
        CONFIGURED.store(configured, Ordering::Relaxed);
        if !configured {
            ALT.store(0, Ordering::Relaxed);
        }
    }

    fn set_alternate_setting(&mut self, iface: InterfaceNumber, alt: u8) {
        if iface == self.ncm_data_if {
            ALT.store(alt, Ordering::Relaxed);
            if alt == 0 {
                // streaming stopped: whatever sits in the ring belongs to a stream that no longer exists
                let n = critical_section::with(|cs| RING.borrow_ref_mut(cs).flush());
                RING_FLUSHED.fetch_add(n as u32, Ordering::Relaxed);
            }
        }
    }

    fn control_out(&mut self, req: Request, data: &[u8]) -> Option<OutResponse> {
        if req.request_type != RequestType::Class || req.recipient != Recipient::Interface {
            return None;
        }
        if req.index == u16::from(u8::from(self.acm_if)) {
            return Some(match req.request {
                0x00 | 0x20 => OutResponse::Accepted,
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
                ncm::REQ_SET_NTB_FORMAT if req.value == 0 => OutResponse::Accepted,
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

// ======================================================================================================================
// main
// ======================================================================================================================

fn heap_line(out: &mut String) {
    let s = esp_alloc::HEAP.stats();
    let _ = write!(
        out,
        "heap total={} used={} free={} cpu_mhz={} up_ms={}\r\n",
        s.size,
        esp_alloc::HEAP.used(),
        esp_alloc::HEAP.free(),
        CPU_MHZ,
        Instant::now().as_millis()
    );
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: HEAP_RECLAIMED);
    esp_alloc::heap_allocator!(size: HEAP_REGULAR);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    println!(
        "S3 boot: cpu={} MHz fixed (no DFS); heap configured {} KiB reclaimed + {} KiB regular; esp-radio tx_queue={} rx_queue={} mtu={}",
        CPU_MHZ,
        HEAP_RECLAIMED / 1024,
        HEAP_REGULAR / 1024,
        WIFI_TX_QUEUE,
        WIFI_RX_QUEUE,
        MTU
    );

    let (Some(ssid), Some(pass)) = (SSID, PASS) else {
        println!("WIFI_SSID / WIFI_PASS not set at build time; rebuild with them. Halting.");
        loop {
            Timer::after_secs(60).await;
        }
    };

    // ---- Wi-Fi (S1) ----
    let sta_cfg = StationConfig::default()
        .with_ssid(ssid.try_into().unwrap())
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(pass.try_into().unwrap()));
    let cfg = ControllerConfig::default()
        .with_tx_queue_size(WIFI_TX_QUEUE)
        .with_rx_queue_size(WIFI_RX_QUEUE)
        .with_initial_config(Config::Station(sta_cfg));
    let mut controller: WifiController<'static> = WifiController::new(peripherals.WIFI, cfg).unwrap();
    static IFACE: StaticCell<RefCell<Interface>> = StaticCell::new();
    let iface: &'static RefCell<Interface> = IFACE.init(RefCell::new(Interface::station()));
    let mac = iface.borrow().mac_address();
    println!("STA MAC {:02x?}", mac);

    controller.set_power_saving(PowerSaveMode::None).unwrap();
    let bw = controller.bandwidths().unwrap().with_2_4(Bandwidth::_20MHz);
    controller.set_bandwidths(bw).unwrap();
    controller.set_max_tx_power(80).unwrap();

    // ---- the bridge ----
    static BRIDGE: StaticCell<Bridge<FwEnv>> = StaticCell::new();
    let bridge: &'static Bridge<FwEnv> = BRIDGE.init_with(|| Bridge::new(FwEnv { iface }, mac));
    let producer = bridge.producer().unwrap();
    let worker = bridge.worker().unwrap();

    // ---- USB (S2): the NCM MAC string is the STA MAC ----
    static HEX: StaticCell<[u8; 12]> = StaticCell::new();
    let hex = HEX.init([0; 12]);
    for (i, b) in mac.iter().enumerate() {
        hex[2 * i] = b"0123456789ABCDEF"[(b >> 4) as usize];
        hex[2 * i + 1] = b"0123456789ABCDEF"[(b & 15) as usize];
    }
    let hex: &'static str = core::str::from_utf8(hex).unwrap();

    let usb = Usb::new_fs(peripherals.USB_FS, peripherals.GPIO20, peripherals.GPIO19);
    static EP_OUT: StaticCell<[u8; 192]> = StaticCell::new();
    let driver = UsbDriver::new(usb, EP_OUT.init([0; 192]), OtgConfig::default());

    let mut config = embassy_usb::Config::new(0x303A, 0x4001);
    config.bcd_usb = UsbVersion::Two;
    config.device_release = 0x0100;
    config.manufacturer = Some("T-Dongle Adapter Project");
    config.product = Some("T-Dongle-S3 NCM");
    config.serial_number = Some(hex);
    config.max_power = 500;
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
    let (acm_rd, acm_wr) = acm.split();
    static ACM_WR: StaticCell<Mutex<NoopRawMutex, AcmWriter>> = StaticCell::new();
    let acm_wr: &'static Mutex<NoopRawMutex, AcmWriter> = ACM_WR.init(Mutex::new(acm_wr));

    let dev = b.build();

    println!("S3 up: heap used={} free={}", esp_alloc::HEAP.used(), esp_alloc::HEAP.free());

    spawner.spawn(usb_task(dev).unwrap());
    spawner.spawn(console_task(acm_rd, acm_wr, bridge).unwrap());
    spawner.spawn(heap_task(acm_wr).unwrap());
    spawner.spawn(usb_rx_task(rx, producer).unwrap());
    spawner.spawn(usb_tx_task(tx).unwrap());
    spawner.spawn(wifi_rx_task(iface, bridge).unwrap());
    spawner.spawn(worker_task(iface, worker).unwrap());
    link_loop(&mut controller, bridge).await
}

// ======================================================================================================================
// Wi-Fi link supervision (connect, wait for disconnect, bridge.link)
// ======================================================================================================================

async fn link_loop(controller: &mut WifiController<'static>, bridge: &'static Bridge<FwEnv>) -> ! {
    // SAFETY: this is the link supervisor task; it may block and is not a driver callback.
    let ctx = unsafe { TaskContext::assume() };
    loop {
        match controller.connect_async().await {
            Ok(info) => {
                println!("connected: {:?}", info);
                CONNECTS.fetch_add(1, Ordering::Relaxed);
                if let Ok((ch, _)) = controller.channel() {
                    CHANNEL.store(ch, Ordering::Relaxed);
                }
                bridge.link(true, &ctx);
                loop {
                    match select(controller.wait_for_disconnect_async(), Timer::after_secs(2)).await {
                        Either::First(r) => {
                            DISCONNECTS.fetch_add(1, Ordering::Relaxed);
                            println!("disconnected: {:?}", r.is_ok());
                            let _ = &LAST_REASON; // reason code: DisconnectedInfo field not mapped in the spike
                            break;
                        }
                        Either::Second(()) => match controller.rssi() {
                            Ok(r) => {
                                RSSI.store(r, Ordering::Relaxed);
                                RSSI_VALID.store(true, Ordering::Relaxed);
                            }
                            Err(_) => RSSI_VALID.store(false, Ordering::Relaxed),
                        },
                    }
                }
                RSSI_VALID.store(false, Ordering::Relaxed);
                bridge.link(false, &ctx);
            }
            Err(e) => println!("connect failed: {:?}, retrying", e),
        }
        Timer::after_secs(2).await;
    }
}

// ======================================================================================================================
// Wi-Fi -> host: the RX poll (the C's esp_wifi_internal_reg_rxcb callback). Copies into the ring through `Bridge::wifi_rx`.
// ======================================================================================================================

#[embassy_executor::task]
async fn wifi_rx_task(iface: &'static RefCell<Interface>, bridge: &'static Bridge<FwEnv>) -> ! {
    loop {
        // `receive` yields a token only when a frame is queued AND esp-radio has TX credit (see FINDINGS: RX/TX coupling).
        let (rx, _tx) = poll_fn(|cx| match <Interface as NetDriver>::receive(&mut iface.borrow_mut(), cx) {
            Some(t) => Poll::Ready(t),
            None => Poll::Pending,
        })
        .await;
        rx.consume_token(|frame| {
            if WIFI_RX_ON.load(Ordering::Acquire) {
                let _ = bridge.wifi_rx(frame); // counted inside; the buffer goes back to the driver when the closure returns
            }
        });
        yield_now().await;
    }
}

// ======================================================================================================================
// host -> Wi-Fi: the worker (async wrapper around `Worker::drain_one`; waits for TX room on the TX-done waker)
// ======================================================================================================================

#[embassy_executor::task]
async fn worker_task(iface: &'static RefCell<Interface>, mut worker: tdongle_bridge::Worker<'static, FwEnv>) -> ! {
    loop {
        WORKER_SIG.wait().await;
        loop {
            // Wait (bounded) until esp-radio has TX credit and the link is up, so the sync `drain_one` rarely has to block.
            // Bounded because a link-down never fires the TX waker: drain_one then drops the frame as stale/link-down at once.
            let room = poll_fn(|cx| {
                if <Interface as NetDriver>::transmit(&mut iface.borrow_mut(), cx).is_some() { Poll::Ready(()) } else { Poll::Pending }
            });
            let _ = with_timeout(Duration::from_millis(5), room).await;
            if !worker.drain_one() {
                break;
            }
            yield_now().await;
        }
    }
}

// ======================================================================================================================
// USB tasks
// ======================================================================================================================

#[embassy_executor::task]
async fn usb_task(mut dev: UsbDevice<'static, Drv>) -> ! {
    dev.run().await
}

/// host -> Wi-Fi: one datagram at a time into `Producer::host`. HOLD keeps the datagram in the NTB buffer and does not read the next
/// NTB packet until `rx_resume` (RESUME_SIG) fires: the OUT endpoint is not re-armed, the host is NAKed.
#[embassy_executor::task]
async fn usb_rx_task(mut rx: NcmReceiver, mut producer: tdongle_bridge::Producer<'static, FwEnv>) -> ! {
    loop {
        if rx.wait_connection().await.is_err() {
            continue;
        }
        'conn: loop {
            let Some(d) = rx.peek_datagram() else {
                if rx.read_ntb().await.is_err() {
                    break 'conn;
                }
                continue;
            };
            RX_DATAGRAMS.fetch_add(1, Ordering::Relaxed);
            let len = d.len() as u32;
            let mut held_since: Option<Instant> = None;
            loop {
                RESUME_SIG.reset();
                match producer.host(d) {
                    HostOutcome::Hold => {
                        if held_since.is_none() {
                            held_since = Some(Instant::now());
                            HOLDS.fetch_add(1, Ordering::Relaxed);
                        }
                        loop {
                            match select(RESUME_SIG.wait(), Timer::after_millis(250)).await {
                                Either::First(()) => break,
                                Either::Second(()) if ALT.load(Ordering::Relaxed) == 0 => break 'conn, // host left the data interface
                                Either::Second(()) => {}
                            }
                        }
                    }
                    outcome => {
                        if outcome == HostOutcome::Queued {
                            UP_FRAMES.fetch_add(1, Ordering::Relaxed);
                            UP_BYTES.fetch_add(len, Ordering::Relaxed);
                        }
                        break;
                    }
                }
            }
            if let Some(t0) = held_since {
                let us = t0.elapsed().as_micros() as u32;
                HOLD_US_SUM.fetch_add(us, Ordering::Relaxed);
                HOLD_US_MAX.fetch_max(us, Ordering::Relaxed);
            }
            rx.advance();
        }
    }
}

/// Wi-Fi -> host: the ring drains into one NTB per datagram (no IN aggregation yet).
#[embassy_executor::task]
async fn usb_tx_task(mut tx: NcmSender) -> ! {
    loop {
        let n = loop {
            if let Some(n) = critical_section::with(|cs| RING.borrow_ref_mut(cs).pop_into(tx.body_mut())) {
                break n;
            }
            RING_SIG.wait().await;
        };
        match tx.send_prepared(n).await {
            Ok(()) => {
                RING_SENT.fetch_add(1, Ordering::Relaxed);
                DOWN_FRAMES.fetch_add(1, Ordering::Relaxed);
                DOWN_BYTES.fetch_add(n as u32, Ordering::Relaxed);
            }
            Err(_) => {
                RING_WRITE_ERR.fetch_add(1, Ordering::Relaxed);
                Timer::after_millis(1).await; // endpoint disabled: do not spin
            }
        }
    }
}

// ======================================================================================================================
// Console (CDC-ACM)
// ======================================================================================================================

async fn out(w: &'static Mutex<NoopRawMutex, AcmWriter>, s: &str, timeout_ms: u64) {
    let mut g = w.lock().await;
    // Do not wedge the console if nobody reads the port.
    let _ = with_timeout(Duration::from_millis(timeout_ms), g.write_all(s.as_bytes())).await;
}

fn build_status(bridge: &Bridge<FwEnv>, out: &mut String) {
    let st = bridge.stats();
    let none: [Record; 0] = [];
    let linked = st.linked;
    let snap = Snapshot {
        mode: Mode::Adapter,
        wifi_current: 0,
        online: linked,
        firmware: FIRMWARE,
        usb_mounted: CONFIGURED.load(Ordering::Relaxed),
        usb_ready: ALT.load(Ordering::Relaxed) != 0,
        uptime_ms: Instant::now().as_millis(),
        free_heap: esp_alloc::HEAP.free() as u32,
        temperature: Default::default(),
        clock: Default::default(),
        clock_valid: false,
        link: Info {
            connected: linked,
            rssi_valid: RSSI_VALID.load(Ordering::Relaxed),
            rssi: RSSI.load(Ordering::Relaxed) as i8,
            channel: CHANNEL.load(Ordering::Relaxed),
            ..Default::default()
        },
        events: Events {
            connects: CONNECTS.load(Ordering::Relaxed),
            disconnects: DISCONNECTS.load(Ordering::Relaxed),
            last_reason: LAST_REASON.load(Ordering::Relaxed) as u16,
            ..Default::default()
        },
        prefs: Prefs { saved: 1, preferred: None, priorities: &[], roaming_assist: false },
        display: DisplayState::default(),
        setup_ap_name: "",
        setup_seconds_left: 0,
        traffic: Traffic {
            counters: tdongle_traffic_reading(),
            down_kbps: 0,
            up_kbps: 0,
            usb_resets: RESETS.load(Ordering::Relaxed),
            control_stack_free_bytes: 0,
        },
        memory: &none,
    };
    let _ = write_status(out, &snap);

    let ring = RingReport {
        ring_bytes: (RING_SLOTS * MTU) as u32,
        high_water_slabs: RING_HIGH.load(Ordering::Relaxed),
        enqueued_frames: RING_ENQ.load(Ordering::Relaxed),
        sent_frames: RING_SENT.load(Ordering::Relaxed),
        dropped_full: RING_FULL.load(Ordering::Relaxed),
        dropped_link_down: RING_NOT_READY.load(Ordering::Relaxed),
        flushed_link_down: RING_FLUSHED.load(Ordering::Relaxed),
        max_bytes: (RING_SLOTS * MTU) as u32,
        ..Default::default()
    };
    let rx = RxClassReport {
        ntbs: ncm::RX_NTBS.load(Ordering::Relaxed),
        ntb_bytes: ncm::RX_NTB_BYTES.load(Ordering::Relaxed),
        ntb_max_bytes: ncm::RX_NTB_MAX.load(Ordering::Relaxed),
        datagrams: RX_DATAGRAMS.load(Ordering::Relaxed),
        holds: HOLDS.load(Ordering::Relaxed),
        hold_us_sum: HOLD_US_SUM.load(Ordering::Relaxed),
        hold_us_max: HOLD_US_MAX.load(Ordering::Relaxed),
        ..Default::default()
    };
    // esp-radio owns the TX-done accounting: no charged/done/aborted equivalents; `refused_pool` = wifi_tx refusals (no token).
    let wtx = WifiTxReport { refused_pool: WIFI_TX_REFUSED.load(Ordering::Relaxed), ..Default::default() };
    let _ = write_status_lines(out, &Report { l2: &st, ring: &ring, rx: &rx, wifi_tx: &wtx });
    heap_line(out);
    let _ = write!(
        out,
        "s3 ring_write_err={} wifi_room_no={} ntb_tx={} usb_resets={} cpu_mhz={} tx_queue={} rx_queue={}\r\n",
        RING_WRITE_ERR.load(Ordering::Relaxed),
        WIFI_TX_ROOM_NO.load(Ordering::Relaxed),
        ncm::TX_NTBS.load(Ordering::Relaxed),
        RESETS.load(Ordering::Relaxed),
        CPU_MHZ,
        WIFI_TX_QUEUE,
        WIFI_RX_QUEUE
    );
}

fn tdongle_traffic_reading() -> tdongle_traffic::Reading {
    tdongle_traffic::Reading {
        down_bytes: DOWN_BYTES.load(Ordering::Relaxed),
        up_bytes: UP_BYTES.load(Ordering::Relaxed),
        down_frames: DOWN_FRAMES.load(Ordering::Relaxed),
        up_frames: UP_FRAMES.load(Ordering::Relaxed),
    }
}

#[embassy_executor::task]
async fn console_task(mut rd: AcmReader, wr: &'static Mutex<NoopRawMutex, AcmWriter>, bridge: &'static Bridge<FwEnv>) -> ! {
    let mut reader = LineReader::new();
    loop {
        rd.wait_connection().await;
        loop {
            let mut pkt = [0u8; 64];
            let Ok(len) = rd.read_packet(&mut pkt).await else { break };
            for &c in &pkt[..len] {
                let Some(ev) = reader.feed(c) else { continue };
                if let Some(text) = ev.reply() {
                    out(wr, text, 500).await;
                    continue;
                }
                let Event::Line(line) = ev else { continue };
                let mut owned = String::new();
                let _ = owned.write_str(line);
                handle(wr, bridge, &owned).await;
            }
        }
    }
}

async fn handle(wr: &'static Mutex<NoopRawMutex, AcmWriter>, bridge: &'static Bridge<FwEnv>, line: &str) {
    let mut s = String::new();
    match line {
        "heap" => heap_line(&mut s),
        "heap on" => {
            HEAP_STREAM.store(true, Ordering::Relaxed);
            s.push_str("heap stream on\r\n");
        }
        "heap off" => {
            HEAP_STREAM.store(false, Ordering::Relaxed);
            s.push_str("heap stream off\r\n");
        }
        _ => match Command::parse(line) {
            Command::Status => build_status(bridge, &mut s),
            Command::Help => {
                let _ = reply::write_help(&mut s, false, "");
                s.push_str("heap [on|off]\r\n");
            }
            Command::Capabilities => {
                let _ = reply::write_capabilities(&mut s, false, "");
            }
            _ => {
                let _ = reply::write_unknown(&mut s, false);
            }
        },
    }
    out(wr, &s, 3000).await;
}

/// `heap` line every 5 s: to the console when the host holds DTR (`heap off` silences it) and to esp-println.
#[embassy_executor::task]
async fn heap_task(wr: &'static Mutex<NoopRawMutex, AcmWriter>) -> ! {
    loop {
        Timer::after_secs(5).await;
        let mut s = String::new();
        heap_line(&mut s);
        println!("{}", s.trim_end());
        if HEAP_STREAM.load(Ordering::Relaxed) && DTR.load(Ordering::Relaxed) {
            out(wr, &s, 200).await;
        }
    }
}
