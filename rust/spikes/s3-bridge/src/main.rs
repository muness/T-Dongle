//! Spike S3 (no_std): the transparent Wi-Fi bridge = S1 (esp-radio raw L2 STA) + S2 (embassy-usb CDC-ACM + CDC-NCM),
//! host -> Wi-Fi through the real `tdongle-bridge` crate (bounded queue, HOLD/RESUME, CoDel/ECN, counters).
//!
//! Credentials: read from the existing NVS partition (read-only; `saved.rs`), never built in. CPU clock: 240 MHz fixed (`CpuClock::max()`).
//! Console: the CDC-ACM port (`status`, `help`, `heap on|off`, `heap`); USB-Serial-JTAG is unavailable once the OTG core runs.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../../common/ops.rs"]
mod ops;
#[path = "../../common/guard.rs"]
mod guard;
#[path = "../../common/saved.rs"]
mod saved;
mod l2;
mod acm;
mod ncm;

use alloc::string::String;
use core::cell::RefCell;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, Ordering};

use critical_section::Mutex as CsMutex;
use embassy_executor::Spawner;
use tdongle_boot_guard::Stage;
use embassy_futures::select::{Either, select};
use embassy_futures::yield_now;
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
use esp_radio::wifi::Protocols;
use esp_radio::wifi::scan::ScanConfig;
use esp_radio::wifi::{
    AuthenticationMethodConfig, Bandwidth, Config, ControllerConfig, PowerSaveMode, WifiController,
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
use tdongle_serial::wifi_link::Events;

esp_bootloader_esp_idf::esp_app_desc!();


const FIRMWARE: &str = "0.3.0-s3-spike";
const MTU: usize = 1514;
/// OUT endpoint buffers: EP0 (64) + ACM bulk OUT (64) + the NCM bulk OUT transfer buffer (one whole NTB).
const EP_OUT_BYTES: usize = 64 + 64 + ncm::NTB_OUT_MAX;
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

/// USB-side modes (console `usb bridge|sink|source`): measure the host link without the radio. `sink` counts OUT datagrams and drops them; `source` sends 1,442 B broadcast frames on IN.
const USB_BRIDGE: u8 = 0;
const USB_SINK: u8 = 1;
const USB_SOURCE: u8 = 2;
static USB_MODE: AtomicU8 = AtomicU8::new(USB_BRIDGE);
static SOURCE_KBPS: AtomicU32 = AtomicU32::new(0);
const SOURCE_FRAME: usize = 1442;
static SINK_FRAMES: AtomicU32 = AtomicU32::new(0);
static SINK_BYTES: AtomicU32 = AtomicU32::new(0);
static SOURCE_FRAMES: AtomicU32 = AtomicU32::new(0);
static SOURCE_BYTES: AtomicU32 = AtomicU32::new(0);

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

/// The environment of the bridge: the S3 board.
pub struct FwEnv;

impl Env for FwEnv {
    fn now_us(&self) -> u32 {
        Instant::now().as_micros() as u32
    }

    // Wi-Fi RX callback context (the poll task): copy and return, never wait.
    fn usb_ring_send(&self, frame: &[u8]) -> RingSend {
        if ALT.load(Ordering::Relaxed) == 0 || USB_MODE.load(Ordering::Relaxed) != USB_BRIDGE {
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
        l2::RX_ON.store(on, Ordering::Release);
    }

    fn notify_worker(&self) {
        WORKER_SIG.signal(());
    }

    fn wifi_tx(&self, frame: &[u8], _context: &TaskContext) -> Result<(), TxError> {
        let sent = l2::tx(frame);
        if sent.is_err() {
            WIFI_TX_REFUSED.fetch_add(1, Ordering::Relaxed);
        }
        sent
    }

    fn wifi_room(&self) -> bool {
        // the C budget: charges outstanding under the limit (6), healed by tx-done, link flush and the 3 s lease
        let room = l2::room();
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

/// The saved networks (set by the init task once read), the slot joined, and the last scan's reading per slot (for `list` and `status`).
static SAVED: embassy_sync::blocking_mutex::Mutex<CriticalSectionRawMutex, RefCell<Option<tdongle_nvs_format::load::Loaded>>> =
    embassy_sync::blocking_mutex::Mutex::new(RefCell::new(None));
static SELECTED: AtomicI32 = AtomicI32::new(-1);
static CONNECTED_NOW: AtomicBool = AtomicBool::new(false);
static SCAN_SEEN: AtomicU32 = AtomicU32::new(0);
static SCAN_SIGNAL: [AtomicI32; 8] = [const { AtomicI32::new(-127) }; 8];

/// What the init task could not do, for the console (`init`): the console stays up whatever happens here.
static INIT_NOTE: CsMutex<RefCell<guard::heapless_str::Text>> = CsMutex::new(RefCell::new(guard::heapless_str::Text::new()));

fn init_note(text: &str) {
    println!("init: {}", text);
    critical_section::with(|cs| {
        let mut t = guard::heapless_str::Text::new();
        let _ = t.write_str(text);
        *INIT_NOTE.borrow_ref_mut(cs) = t;
    });
}

/// The boot order that keeps the device reachable (ADR 0001, "Design rules" 13): record, watchdogs, heap and scheduler, **USB and the console**, and only
/// then everything that can block or fail (storage, radio, scan, connect) in `init_task`, with the step recorded in RTC memory and the watchdog fed by a
/// task on the same executor, so a step that blocks resets the chip and the next `boot-status` says where.
#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    static STATE: StaticCell<guard::State> = StaticCell::new();
    let state: &'static guard::State = STATE.init(guard::begin());
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: HEAP_RECLAIMED);
    esp_alloc::heap_allocator!(size: HEAP_REGULAR);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    let dogs = guard::Dogs::arm(peripherals.TIMG1, peripherals.RTC_TIMER);
    guard::stage(Stage::Usb);

    // ---- the bridge (no radio needed yet: the interface is filled in by `init_task`) ----
    let mac: [u8; 6] = esp_hal::efuse::base_mac_address().as_bytes().try_into().unwrap_or([0; 6]); // STA MAC = base MAC
    static BRIDGE: StaticCell<Bridge<FwEnv>> = StaticCell::new();
    let bridge: &'static Bridge<FwEnv> = BRIDGE.init_with(|| Bridge::new(FwEnv, mac));
    let (Some(producer), Some(worker)) = (bridge.producer(), bridge.worker()) else {
        // Cannot happen (first and only call); if it ever does, the console still comes up below without the data path.
        loop {
            Timer::after_secs(60).await;
        }
    };

    // ---- USB (S2): serial and NCM MAC string = chip MAC ----
    static HEX: StaticCell<[u8; 12]> = StaticCell::new();
    let hex = HEX.init(ops::mac_hex(&mac));
    let hex: &'static str = core::str::from_utf8(hex).unwrap_or("000000000000");

    let usb = Usb::new_fs(peripherals.USB_FS, peripherals.GPIO20, peripherals.GPIO19);
    static EP_OUT: StaticCell<[u8; EP_OUT_BYTES]> = StaticCell::new();
    let mut otg_config = OtgConfig::default();
    // PATCH (vendor/embassy-usb-synopsys-otg): the NCM bulk OUT endpoint (0x04) is armed for a whole NTB.
    #[cfg(not(feature = "stock-out"))]
    {
        otg_config.out_transfer_bytes[4] = ncm::NTB_OUT_MAX as u16;
    }
    let driver = UsbDriver::new(usb, EP_OUT.init([0; EP_OUT_BYTES]), otg_config);

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

    // The USB device attaches when `usb_task` first runs: spawn it before anything else and do not block between here and the first `.await`.
    spawner.spawn(usb_task(dev).unwrap());
    spawner.spawn(console_task(acm_rd, acm_wr, bridge, state).unwrap());
    spawner.spawn(heartbeat_task(dogs, state.boot.safe_mode).unwrap());
    spawner.spawn(usb_rx_task(rx, producer).unwrap());
    spawner.spawn(usb_tx_task(tx).unwrap());
    spawner.spawn(heap_task(acm_wr).unwrap());
    spawner.spawn(init_task(peripherals.WIFI, peripherals.FLASH, spawner, bridge, worker, state.boot.safe_mode).unwrap());
    loop {
        Timer::after_secs(3600).await;
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

/// Everything that can block or fail, after the console is up. Any failure is noted (`init` on the console) and leaves the console running.
#[embassy_executor::task]
async fn init_task(
    wifi: esp_hal::peripherals::WIFI<'static>,
    flash: esp_hal::peripherals::FLASH<'static>,
    spawner: Spawner,
    bridge: &'static Bridge<FwEnv>,
    worker: tdongle_bridge::Worker<'static, FwEnv>,
    safe_mode: bool,
) {
    // Let the USB device enumerate before the first long step.
    Timer::after_millis(300).await;
    if safe_mode {
        init_note("safe mode: storage and radio not started (console `normal` and a reset to leave)");
        return;
    }

    // ---- the saved networks: read-only from the NVS the C firmware wrote ----
    guard::stage(Stage::Settings);
    let mut flash = esp_storage::FlashStorage::new(flash);
    let loaded = match saved::load(&mut flash) {
        Ok(l) if !l.saved.list().is_empty() => Some(l),
        Ok(_) => {
            init_note("no saved networks");
            None
        }
        Err(e) => {
            println!("nvs: {:?}", e);
            init_note("saved networks unreadable");
            None
        }
    };
    let Some(loaded) = loaded else { return };

    // ---- Wi-Fi (S1) ----
    guard::stage(Stage::RadioInit);
    let cfg = ControllerConfig::default().with_tx_queue_size(WIFI_TX_QUEUE).with_rx_queue_size(WIFI_RX_QUEUE);
    let mut controller: WifiController<'static> = match WifiController::new(wifi, cfg) {
        Ok(c) => c,
        Err(e) => {
            println!("radio init failed: {:?}", e);
            init_note("radio init failed");
            return;
        }
    };
    // Both directions go through `l2` (the C data path), not esp-radio's token API (which wedged: see l2.rs).
    l2::start(bridge);
    // Each of these is a tuning, not a requirement: report and carry on.
    if controller.set_power_saving(PowerSaveMode::None).is_err() {
        init_note("set_power_saving failed");
    }
    match controller.bandwidths() {
        Ok(bw) => {
            if controller.set_bandwidths(bw.with_2_4(Bandwidth::_20MHz)).is_err() {
                init_note("set_bandwidths failed");
            }
        }
        Err(_) => init_note("bandwidths failed"),
    }
    if controller.set_max_tx_power(80).is_err() {
        init_note("set_max_tx_power failed");
    }
    spawner.spawn(worker_task(worker).unwrap());
    SAVED.lock(|c| *c.borrow_mut() = Some(loaded));
    link_loop(&mut controller, bridge, loaded).await
}

// ======================================================================================================================
// Wi-Fi link supervision (scan, join the best saved network, wait for disconnect, bridge.link)
// ======================================================================================================================

async fn link_loop(controller: &mut WifiController<'static>, bridge: &'static Bridge<FwEnv>, loaded: tdongle_nvs_format::load::Loaded) -> ! {
    // SAFETY: this is the link supervisor task; it may block and is not a driver callback.
    let ctx = unsafe { TaskContext::assume() };
    let mut next = 0usize;
    loop {
        // Strongest saved network that a scan (hidden SSIDs included) sees; none seen: try the saved list in order (directed probes find hidden ones).
        guard::stage(Stage::Scan);
        let scan = with_timeout(Duration::from_secs(8), controller.scan_async(&ScanConfig::default().with_show_hidden(true).with_max(40))).await;
        let slot = match scan {
            Ok(Ok(aps)) => {
                let signal = tdongle_saved::signals(&loaded.saved, aps.iter().map(|a| (a.ssid.as_str().as_bytes(), a.signal_strength)));
                SCAN_SEEN.store(aps.len() as u32, Ordering::Relaxed);
                for (i, v) in signal.iter().enumerate() {
                    SCAN_SIGNAL[i].store(*v as i32, Ordering::Relaxed);
                }
                tdongle_saved::choose(&loaded, &signal)
            }
            Ok(Err(_)) => {
                init_note("scan failed");
                None
            }
            Err(_) => {
                init_note("scan timed out");
                None
            }
        };
        let count = loaded.saved.list().len();
        let slot = slot.unwrap_or_else(|| {
            next = (next + 1) % count;
            next
        });
        let Some((ssid, pass)) = tdongle_saved::credentials(&loaded.saved, slot) else {
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
        println!("joining saved network slot {}", slot);
        if controller.set_config(&Config::Station(StationConfig::default().with_ssid(ssid_t).with_authentication(auth))).is_err() {
            init_note("set_config failed");
            Timer::after_secs(2).await;
            continue;
        }
        if controller.set_protocols(Protocols::default()).is_err() {
            init_note("set_protocols failed"); // default is b/g/n: never LR
        }
        guard::stage(Stage::Connect);
        match with_timeout(Duration::from_secs(30), controller.connect_async()).await {
            Ok(Ok(info)) => {
                println!("connected: {:?}", info);
                guard::stage(Stage::Running);
                CONNECTS.fetch_add(1, Ordering::Relaxed);
                if let Ok((ch, _)) = controller.channel() {
                    CHANNEL.store(ch, Ordering::Relaxed);
                }
                l2::register(); // the driver is started now: (re-)register the callbacks (the tx-done registration needs a started driver)
                l2::link_changed(); // the driver cleared its queues when the link came up
                SELECTED.store(slot as i32, Ordering::Relaxed);
                CONNECTED_NOW.store(true, Ordering::Relaxed);
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
                CONNECTED_NOW.store(false, Ordering::Relaxed);
                l2::link_changed(); // and when it dropped, without completing what was in them
                bridge.link(false, &ctx);
            }
            Ok(Err(e)) => println!("connect failed: {:?}, retrying", e),
            Err(_) => init_note("connect timed out"),
        }
        Timer::after_secs(2).await;
    }
}

// ======================================================================================================================
// Wi-Fi -> host: the RX poll (the C's esp_wifi_internal_reg_rxcb callback). Copies into the ring through `Bridge::wifi_rx`.
// ======================================================================================================================

// ======================================================================================================================
// host -> Wi-Fi: the worker (async wrapper around `Worker::drain_one`; waits for TX room on the TX-done waker)
// ======================================================================================================================

#[embassy_executor::task]
async fn worker_task(mut worker: tdongle_bridge::Worker<'static, FwEnv>) -> ! {
    loop {
        WORKER_SIG.wait().await;
        loop {
            // Wait (bounded) for room under the TX limit; the tx-done callback wakes this. Bounded because a link-down never completes anything:
            // drain_one then drops the frame as stale/link-down at once, and the lease heals a lost completion.
            if !l2::room() {
                let _ = with_timeout(Duration::from_millis(5), l2::TX_DONE_SIG.wait()).await;
            }
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
            if USB_MODE.load(Ordering::Relaxed) == USB_SINK {
                // `usb sink`: count the datagram and drop it (measures host -> device alone)
                SINK_FRAMES.fetch_add(1, Ordering::Relaxed);
                SINK_BYTES.fetch_add(len, Ordering::Relaxed);
                rx.advance();
                continue;
            }
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
    let mut seq = 0u32;
    let mut next = Instant::now();
    loop {
        if USB_MODE.load(Ordering::Relaxed) == USB_SOURCE {
            // `usb source`: broadcast dummy frames on IN (measures device -> host alone)
            let body = tx.body_mut();
            body[..SOURCE_FRAME].fill(0);
            body[0..6].fill(0xff);
            body[6..12].copy_from_slice(&[0x02, 0x54, 0x44, 0x53, 0x33, 0x01]);
            body[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
            body[14..18].copy_from_slice(&seq.to_be_bytes());
            match tx.send_prepared(SOURCE_FRAME).await {
                Ok(()) => {
                    seq = seq.wrapping_add(1);
                    SOURCE_FRAMES.fetch_add(1, Ordering::Relaxed);
                    SOURCE_BYTES.fetch_add(SOURCE_FRAME as u32, Ordering::Relaxed);
                }
                Err(_) => Timer::after_millis(10).await,
            }
            let kbps = SOURCE_KBPS.load(Ordering::Relaxed);
            if kbps != 0 {
                next += Duration::from_micros(SOURCE_FRAME as u64 * 8 * 1000 / u64::from(kbps));
                let now = Instant::now();
                if next > now {
                    Timer::at(next).await;
                } else if now - next > Duration::from_millis(100) {
                    next = now;
                }
            } else {
                next = Instant::now();
            }
            continue;
        }
        next = Instant::now();
        let n = loop {
            if USB_MODE.load(Ordering::Relaxed) == USB_SOURCE {
                break 0;
            }
            if let Some(n) = critical_section::with(|cs| RING.borrow_ref_mut(cs).pop_into(tx.body_mut())) {
                break n;
            }
            let _ = with_timeout(Duration::from_millis(50), RING_SIG.wait()).await; // wake regularly to notice a mode change
        };
        if n == 0 {
            continue;
        }
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
    // saved list and priorities as loaded (not a constant): `saved=0` until the init task has read them
    let (saved_count, preferred, priorities) = SAVED.lock(|c| match c.borrow().as_ref() {
        Some(l) => {
            let mut p = [0u8; 8];
            for (d, s) in p.iter_mut().zip(l.meta.slot.iter()) {
                *d = s.priority;
            }
            (l.saved.list().len() as u32, l.meta.preferred.map(|i| i as u32), p)
        }
        None => (0, None, [0u8; 8]),
    });
    let snap = Snapshot {
        mode: Mode::Adapter,
        wifi_current: if linked { SELECTED.load(Ordering::Relaxed) } else { -1 },
        online: linked,
        firmware: FIRMWARE,
        usb_mounted: CONFIGURED.load(Ordering::Relaxed),
        usb_ready: ALT.load(Ordering::Relaxed) != 0,
        uptime_ms: Instant::now().as_millis(),
        free_heap: esp_alloc::HEAP.free() as u32,
        temperature: Default::default(),
        clock: Default::default(),
        clock_valid: false,
        link: {
            // the driver's own view (`wifi_link_read`): unknown stays unknown (an all-zero Info prints phy=lr)
            let mut info = l2::link_read();
            let selected = SELECTED.load(Ordering::Relaxed);
            info.selected_slot = if linked && (0..8).contains(&selected) { selected as u8 + 1 } else { 0 };
            info
        },
        events: Events {
            connects: CONNECTS.load(Ordering::Relaxed),
            disconnects: DISCONNECTS.load(Ordering::Relaxed),
            last_reason: LAST_REASON.load(Ordering::Relaxed) as u16,
            ..Default::default()
        },
        prefs: Prefs { saved: saved_count, preferred: preferred, priorities: &priorities[..saved_count as usize], roaming_assist: false },
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
    let pins = l2::pins_stats();
    let wtx = WifiTxReport {
        installed: true,
        tx_done_cb: l2::tx_done_registered(),
        charged: pins.tx_charged,
        done: pins.tx_done,
        aborted: pins.tx_aborted,
        flushed: pins.tx_flushed,
        stale: pins.tx_stale,
        unmatched: pins.tx_unmatched,
        inflight: pins.tx_outstanding,
        high_water: pins.tx_high_water,
        refused_pool: pins.tx_refused_pool,
        refused_heap: pins.tx_refused_heap,
    };
    let _ = write_status_lines(out, &Report { l2: &st, ring: &ring, rx: &rx, wifi_tx: &wtx });
    heap_line(out);
    let _ = write!(
        out,
        "s3 ring_write_err={} wifi_room_no={} ntb_tx={} usb_resets={} cpu_mhz={} tx_queue={} rx_queue={} usb={} out={} sink_frames={} sink_bytes={} source_frames={} source_bytes={} rx_cb={} rx_ignored={} tx_drv_err={} tx_last_err={:#x} scan_seen={}\r\n",
        RING_WRITE_ERR.load(Ordering::Relaxed),
        WIFI_TX_ROOM_NO.load(Ordering::Relaxed),
        ncm::TX_NTBS.load(Ordering::Relaxed),
        RESETS.load(Ordering::Relaxed),
        CPU_MHZ,
        WIFI_TX_QUEUE,
        WIFI_RX_QUEUE,
        ["bridge", "sink", "source"][usize::from(USB_MODE.load(Ordering::Relaxed)).min(2)],
        if cfg!(feature = "stock-out") { "stock" } else { "multi" },
        SINK_FRAMES.load(Ordering::Relaxed),
        SINK_BYTES.load(Ordering::Relaxed),
        SOURCE_FRAMES.load(Ordering::Relaxed),
        SOURCE_BYTES.load(Ordering::Relaxed),
        l2::RX_CALLBACKS.load(Ordering::Relaxed),
        l2::RX_IGNORED.load(Ordering::Relaxed),
        l2::TX_DRIVER_ERR.load(Ordering::Relaxed),
        l2::TX_LAST_ERR.load(Ordering::Relaxed),
        SCAN_SEEN.load(Ordering::Relaxed)
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
async fn console_task(mut rd: AcmReader, wr: &'static Mutex<NoopRawMutex, AcmWriter>, bridge: &'static Bridge<FwEnv>, state: &'static guard::State) -> ! {
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
                handle(wr, bridge, state, &owned).await;
            }
        }
    }
}

async fn handle(wr: &'static Mutex<NoopRawMutex, AcmWriter>, bridge: &'static Bridge<FwEnv>, state: &'static guard::State, line: &str) {
    let mut s = String::new();
    match line {
        "heap" => heap_line(&mut s),
        "boot-status" => {
            guard::boot_status(&mut s, FIRMWARE, ESP_APP_DESC.app_elf_sha256(), state, Instant::now().as_millis(), Some(esp_alloc::HEAP.free() as u32));
            s.push_str("\r\n");
        }
        usb if usb == "usb" || usb.starts_with("usb ") => {
            let arg = usb.strip_prefix("usb").unwrap_or("").trim();
            let (mode, kbps) = match arg {
                "bridge" => (Some(USB_BRIDGE), 0),
                "sink" => (Some(USB_SINK), 0),
                "source max" => (Some(USB_SOURCE), 0),
                a => match a.strip_prefix("source ").and_then(|r| r.trim().parse::<u32>().ok()).filter(|k| *k > 0) {
                    Some(k) => (Some(USB_SOURCE), k),
                    None => (None, 0),
                },
            };
            match mode {
                Some(mode) => {
                    SOURCE_KBPS.store(kbps, Ordering::Relaxed);
                    USB_MODE.store(mode, Ordering::Relaxed);
                    let _ = write!(s, "usb {} {}\r\n", ["bridge", "sink", "source"][usize::from(mode)], if mode == USB_SOURCE { if kbps == 0 { "max" } else { "rate" } } else { "" });
                }
                None => s.push_str("usage: usb bridge|sink|source RATE_KBPS|max\r\n"),
            }
        }
        "init" => {
            let note = critical_section::with(|cs| *INIT_NOTE.borrow_ref(cs));
            let _ = write!(s, "init stage={} note={}\r\n", guard::current_stage().name(), note.as_str());
        }
        "normal" => {
            guard::leave_safe_mode();
            out(wr, "leaving safe mode: resetting\r\n", 500).await;
            Timer::after(Duration::from_millis(200)).await;
            esp_hal::system::software_reset()
        }
        "bootloader" => {
            guard::leave_safe_mode(); // a deliberate reset is not a failed boot
            out(wr, "rebooting to ROM download mode\r\n", 500).await;
            Timer::after(Duration::from_millis(200)).await;
            ops::enter_bootloader()
        }
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
                let _ = reply::write_help_implemented(&mut s, "T-Dongle Wi-Fi bridge (S3 spike)", reply::SPIKE_S3_COMMANDS);
            }
            Command::Capabilities => {
                let _ = reply::write_capabilities_implemented(&mut s, &["boot_diagnostics"]);
            }
            Command::List => {
                SAVED.lock(|c| {
                    if let Some(l) = c.borrow().as_ref() {
                        let current = SELECTED.load(Ordering::Relaxed);
                        for (i, p) in l.saved.list().iter().enumerate() {
                            let slot = &l.meta.slot[i];
                            let line = reply::ListLine::new(i as u32, current == i as i32 && CONNECTED_NOW.load(Ordering::Relaxed), slot.name_bytes(), p.ssid_bytes(), slot.priority);
                            // SSIDs are raw bytes; the console is text: lossy is what a terminal shows anyway
                            s.push_str(&String::from_utf8_lossy(line.as_bytes()));
                        }
                    }
                });
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
