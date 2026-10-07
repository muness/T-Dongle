//! Spike S3 (no_std): the transparent Wi-Fi bridge = S1 (esp-radio raw L2 STA) + S2 (embassy-usb CDC-ACM + CDC-NCM),
//! host -> Wi-Fi through the real `tdongle-bridge` crate (bounded queue, HOLD/RESUME, CoDel/ECN, counters).
//!
//! Credentials: read from the existing NVS partition (read-only; `saved.rs`), never built in. CPU clock: 240 MHz fixed (`CpuClock::max()`).
//! Console: the CDC-ACM port (`status`, `help`, `heap on|off`, `heap`); USB-Serial-JTAG is unavailable once the OTG core runs.
#![no_std]
#![no_main]

extern crate alloc;

mod ops;
mod guard;
mod supervise;
mod settings;
mod l2;
mod dhcp;
mod pm;
mod setup;
mod ui;
mod acm;
mod ncm;
#[cfg(feature = "tailnet")]
mod tailnet;

use alloc::string::String;
use core::cell::RefCell;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, Ordering};

use critical_section::Mutex as CsMutex;
use embassy_executor::Spawner;
use tdongle_boot_guard::Stage;
use embassy_futures::select::{Either, Either3, select, select3};
use embassy_futures::yield_now;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use esp_hal::interrupt::Priority;
use esp_rtos::embassy::InterruptExecutor;
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
use esp_radio::wifi::scan::ScanTypeConfig;
use esp_radio::wifi::sta::ScanMethod;
use tdongle_saved::Bss;
use esp_radio::wifi::scan::ScanConfig;
use esp_radio::wifi::{
    AuthenticationMethodConfig, Bandwidth, Config, ControllerConfig, PowerSaveMode, WifiController,
    sta::StationConfig,
};
use static_cell::StaticCell;
use tdongle_bridge::{Bridge, Env, HostOutcome, RingSend, TaskContext, TxError};
use tdongle_serial::bridge_report::{Report, RingReport, RxClassReport, WifiTxReport, write_status_lines};
use tdongle_nvs_format::mode::Mode as StoredMode;
use tdongle_serial::command::{Command, DisplayArgs, SlotArg};
use tdongle_serial::console::{Event, LineReader};
use tdongle_serial::memory_log::Record;
use tdongle_serial::reply;
use tdongle_serial::status::{DisplayState, Mode, Prefs, Snapshot, Traffic, write_status};
use tdongle_serial::wifi_link::Events;

esp_bootloader_esp_idf::esp_app_desc!();


/// The version `status`, `boot-status` and the LCD report: `TDONGLE_VERSION` when the release workflow sets it, else the development name.
const FIRMWARE: &str = match option_env!("TDONGLE_VERSION") {
    Some(v) => v,
    None => "0.3.0-rust",
};
const MTU: usize = 1514;
/// OUT endpoint buffers: EP0 (64) + ACM bulk OUT (64) + the NCM bulk OUT transfer buffer (one whole NTB).
const EP_OUT_BYTES: usize = 64 + 64 + ncm::NTB_OUT_MAX;
/// esp-radio queues: the C budget is 6 frames in flight to the radio.
const WIFI_TX_QUEUE: usize = 6;
const WIFI_RX_QUEUE: usize = 8;
/// Heap: 64 KiB reclaimed (post-bootloader DRAM) + this regular region.
#[cfg(not(feature = "tailnet"))]
const HEAP_RECLAIMED: usize = 64 * 1024;
#[cfg(not(feature = "tailnet"))]
const HEAP_REGULAR: usize = 128 * 1024; // DRAM has ~210 KB free beyond .data/.bss: the ring (28 slots = 42 KB) and the TX budget's heap floor (29,884 B) both live in this heap
/// The tailnet image's heap is three regions (see `tailnet::budget`): all of dram2 (`0x3FCDB700..0x3FCED710`, 73,744 bytes), the 32 KB of data cache the build gives
/// back (`ESP_HAL_CONFIG_DATA_CACHE_SIZE=32KB`, the C's own setting), and what is left of DRAM after the statics and the 40 KB stack.
#[cfg(feature = "tailnet")]
const HEAP_RECLAIMED: usize = tailnet::budget::HEAP_RECLAIMED;
#[cfg(feature = "tailnet")]
const HEAP_REGULAR: usize = tailnet::budget::HEAP_REGULAR;

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
/// Bumped whenever the host (re)selects or leaves the NCM data interface or resets the bus: the tailnet runtime drops flows of an older generation.
static USB_GEN: AtomicU32 = AtomicU32::new(0);
static DTR: AtomicBool = AtomicBool::new(false);
static RESETS: AtomicU32 = AtomicU32::new(0);
static LINK_UP_USB: AtomicBool = AtomicBool::new(false); // what the bridge told the USB side (carrier)
static WIFI_RX_ON: AtomicBool = AtomicBool::new(false);
static HEAP_STREAM: AtomicBool = AtomicBool::new(true);

// Wi-Fi link info for `status`
static RSSI: AtomicI32 = AtomicI32::new(0);
static RSSI_VALID: AtomicBool = AtomicBool::new(false);
static CHANNEL: AtomicU8 = AtomicU8::new(0);
/// Moves to another access point of the same network without a disconnect (802.11k/v steering or the driver's own roam).
static ROAMS: AtomicU32 = AtomicU32::new(0);
static CONNECTS: AtomicU32 = AtomicU32::new(0);
static LAST_CONNECT_MS: AtomicU32 = AtomicU32::new(0);
static DISCONNECTS: AtomicU32 = AtomicU32::new(0);
static LAST_REASON: AtomicU32 = AtomicU32::new(0);

// USB ring (Wi-Fi -> host) counters
static RING_ENQ: AtomicU32 = AtomicU32::new(0);
static RING_SENT: AtomicU32 = AtomicU32::new(0);
static RING_FULL: AtomicU32 = AtomicU32::new(0);
static RING_NOT_READY: AtomicU32 = AtomicU32::new(0);
static RING_FLUSHED: AtomicU32 = AtomicU32::new(0);
/// Ring growth and the Wi-Fi burst shape (the next board run explains residual TCP-down retransmits with these): how deep the ring got, how many frames the radio delivered back to
/// back (gaps under 2 ms), how many datagrams went into each IN NTB.
static RING_GROWS: AtomicU32 = AtomicU32::new(0);
static RING_SHRINKS: AtomicU32 = AtomicU32::new(0);
static RING_GROW_DENIED: AtomicU32 = AtomicU32::new(0);
static RING_CAP: AtomicU32 = AtomicU32::new(0);
static LAST_BUSY_MS: AtomicU32 = AtomicU32::new(0);
static RX_LAST_US: AtomicU32 = AtomicU32::new(0);
static RX_BURST_LEN: AtomicU32 = AtomicU32::new(0);
static RX_BURST_MAX: AtomicU32 = AtomicU32::new(0);
/// Gap between consecutive Wi-Fi frames: under 100 us, 100-299, 300-999, 1-3 ms, over 3 ms.
static RX_GAP_HIST: [AtomicU32; 5] = [const { AtomicU32::new(0) }; 5];
static RX_BURSTS_GE4: AtomicU32 = AtomicU32::new(0);
static NTB_IN_COUNT: AtomicU32 = AtomicU32::new(0);
static NTB_IN_FRAMES: AtomicU32 = AtomicU32::new(0);
static NTB_IN_FRAMES_MAX: AtomicU32 = AtomicU32::new(0);
/// Datagrams per IN NTB: 1, 2, 3 to 4, 5 to 8.
static NTB_IN_HIST: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
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

static USB_NETWORK_RX: Signal<CriticalSectionRawMutex, tdongle_setup::boot::UsbNetwork> = Signal::new();
static USB_NETWORK_TX: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static RING_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static HOUSEKEEP_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static WORKER_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static RESUME_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();

// ---- Wi-Fi -> host: bounded drop-tail ring of whole frames (the C's slab ring, simplified) ----
/// The Wi-Fi to host frame ring, ADR 0023: 8 permanent slots and up to 10 elastic chunks of 2, 28 in all (`tdongle_usb_out::elastic`), the C ring's capacity. Slots are heap boxes; only the
/// housekeeping task (thread executor) allocates or frees them, never the producer in the Wi-Fi task, which just copies into a free one under a short critical section.
const MAX_SLOTS: usize = tdongle_usb_out::elastic::STORAGE_SLOTS;
/// The ring's limit now (console `ring max N`): the C's 28 by default.
static RING_MAX: AtomicU32 = AtomicU32::new(tdongle_usb_out::elastic::MAX_SLOTS as u32);
const BASE_SLOTS: usize = tdongle_usb_out::elastic::BASE_SLOTS;
const RING_SLOTS: usize = BASE_SLOTS;

struct RingSlot {
    len: u16,
    data: [u8; MTU],
}
struct Ring {
    store: [Option<alloc::boxed::Box<RingSlot>>; MAX_SLOTS],
    /// FIFO of slot ids.
    queue: [u8; MAX_SLOTS],
    head: usize,
    count: usize,
    /// Stack of free slot ids.
    free: [u8; MAX_SLOTS],
    free_count: usize,
    /// Slots allocated now.
    cap: usize,
}
impl Ring {
    const fn new() -> Self {
        Self { store: [const { None }; MAX_SLOTS], queue: [0; MAX_SLOTS], head: 0, count: 0, free: [0; MAX_SLOTS], free_count: 0, cap: 0 }
    }
    /// Add a slot (id `id`, box already allocated) to the free list.
    fn add_slot(&mut self, id: usize, slot: alloc::boxed::Box<RingSlot>) {
        self.store[id] = Some(slot);
        self.free[self.free_count] = id as u8;
        self.free_count += 1;
        self.cap += 1;
    }
    fn push(&mut self, frame: &[u8]) -> bool {
        if self.free_count == 0 {
            return false;
        }
        self.free_count -= 1;
        let id = usize::from(self.free[self.free_count]);
        let Some(slot) = self.store[id].as_mut() else { return false };
        slot.data[..frame.len()].copy_from_slice(frame);
        slot.len = frame.len() as u16;
        self.queue[(self.head + self.count) % MAX_SLOTS] = id as u8;
        self.count += 1;
        RING_HIGH.fetch_max(self.count as u32, Ordering::Relaxed);
        true
    }
    /// Length of the oldest frame.
    fn front_len(&self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        self.store[usize::from(self.queue[self.head])].as_ref().map(|s| usize::from(s.len))
    }
    /// Move the oldest frames into the NTB while they fit (up to 8 datagrams, 3,200 bytes). Returns how many.
    fn pop_into_ntb(&mut self, ntb: &mut tdongle_usb_out::ntb_in::NtbBuilder<{ ncm::NTB_IN_MAX }>) -> usize {
        let mut moved = 0;
        while let Some(len) = self.front_len() {
            let Some(room) = ntb.slot(len) else { break };
            let id = usize::from(self.queue[self.head]);
            if let Some(slot) = self.store[id].as_ref() {
                room.copy_from_slice(&slot.data[..len]);
            }
            ntb.commit(len);
            self.head = (self.head + 1) % MAX_SLOTS;
            self.count -= 1;
            self.free[self.free_count] = id as u8;
            self.free_count += 1;
            moved += 1;
        }
        moved
    }
    fn flush(&mut self) -> usize {
        let n = self.count;
        while self.count > 0 {
            let id = self.queue[self.head];
            self.free[self.free_count] = id;
            self.free_count += 1;
            self.head = (self.head + 1) % MAX_SLOTS;
            self.count -= 1;
        }
        n
    }
    /// Take two free elastic slots out of the ring (ids at or above the base), for the housekeeping task to free. `None` if two are not free.
    fn take_chunk(&mut self) -> Option<[alloc::boxed::Box<RingSlot>; 2]> {
        let mut found = [0usize; 2];
        let mut n = 0;
        for i in (0..self.free_count).rev() {
            if usize::from(self.free[i]) >= BASE_SLOTS && n < 2 {
                found[n] = i;
                n += 1;
            }
        }
        if n < 2 {
            return None;
        }
        // remove the higher index first so the lower one stays valid
        found.sort_unstable_by(|a, b| b.cmp(a));
        let mut out = [None, None];
        for (k, &i) in found.iter().enumerate() {
            let id = usize::from(self.free[i]);
            self.free[i] = self.free[self.free_count - 1];
            self.free_count -= 1;
            out[k] = self.store[id].take();
            self.cap -= 1;
        }
        match out {
            [Some(a), Some(b)] => Some([a, b]),
            _ => None,
        }
    }
    /// The first id at or above the base that has no box, for growth.
    fn next_free_id(&self) -> Option<usize> {
        (BASE_SLOTS..MAX_SLOTS).find(|&i| self.store[i].is_none())
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
        // the shape of the Wi-Fi bursts: frames within 300 us of each other belong to one burst (an A-MPDU delivers its subframes back to back; at 6 Mbit/s consecutive frames of a
        // steady flow are about 2 ms apart, so a 2 ms window counted the whole stream as one burst)
        let now = Instant::now().as_micros() as u32;
        let gap = now.wrapping_sub(RX_LAST_US.swap(now, Ordering::Relaxed));
        RX_GAP_HIST[match gap {
            0..=99 => 0,
            100..=299 => 1,
            300..=999 => 2,
            1_000..=2_999 => 3,
            _ => 4,
        }]
        .fetch_add(1, Ordering::Relaxed);
        let burst = if gap < 300 { RX_BURST_LEN.fetch_add(1, Ordering::Relaxed) + 1 } else {
            RX_BURST_LEN.store(1, Ordering::Relaxed);
            1
        };
        RX_BURST_MAX.fetch_max(burst, Ordering::Relaxed);
        if burst == 4 {
            RX_BURSTS_GE4.fetch_add(1, Ordering::Relaxed);
        }
        let (accepted, busy) = critical_section::with(|cs| {
            let mut r = RING.borrow_ref_mut(cs);
            let ok = r.push(frame);
            (ok, r.free_count <= tdongle_usb_out::elastic::GROW_HEADROOM + 1)
        });
        if busy {
            LAST_BUSY_MS.store(Instant::now().as_millis() as u32, Ordering::Relaxed);
            HOUSEKEEP_SIG.signal(());
        }
        if accepted {
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
        pm::note_activity();
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
        supervise::USB_CONFIGURED.store(false, Ordering::Relaxed);
        RESETS.fetch_add(1, Ordering::Relaxed);
        USB_GEN.fetch_add(1, Ordering::Relaxed);
        DTR.store(false, Ordering::Relaxed);
        ALT.store(0, Ordering::Relaxed);
        CONFIGURED.store(false, Ordering::Relaxed);
    }

    fn configured(&mut self, configured: bool) {
        CONFIGURED.store(configured, Ordering::Relaxed);
        supervise::USB_CONFIGURED.store(configured, Ordering::Relaxed);
        if !configured {
            ALT.store(0, Ordering::Relaxed);
        }
    }

    fn set_alternate_setting(&mut self, iface: InterfaceNumber, alt: u8) {
        if iface == self.ncm_data_if {
            ALT.store(alt, Ordering::Relaxed);
            USB_GEN.fetch_add(1, Ordering::Relaxed);
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
        pm::status().cpu_mhz,
        Instant::now().as_millis()
    );
}

/// The saved networks (set by the init task once read), the slot joined, and the last scan's reading per slot (for `list` and `status`).
static SAVED: embassy_sync::blocking_mutex::Mutex<CriticalSectionRawMutex, RefCell<Option<tdongle_nvs_format::load::Loaded>>> =
    embassy_sync::blocking_mutex::Mutex::new(RefCell::new(None));
/// What `status` shows of the link: read from the driver by the link task (never by the console, which must not call the radio) and kept here.
static LINK_SNAPSHOT: CsMutex<core::cell::Cell<tdongle_serial::wifi_link::Info>> = CsMutex::new(core::cell::Cell::new(tdongle_serial::wifi_link::Info {
    connected: false,
    rssi_valid: false,
    rssi: 0,
    channel: 0,
    secondary: tdongle_serial::wifi_link::SECOND_UNKNOWN,
    phy: tdongle_serial::wifi_link::PHY_UNKNOWN,
    bw_cfg_mhz: 0,
    ap_bw_mhz: 0,
    ap_modes: 0,
    ps: tdongle_serial::wifi_link::PS_UNKNOWN,
    tx_power_valid: false,
    tx_power_qdbm: 0,
    selected_slot: 0,
    pinned: false,
    pin_failed_slot: 0,
}));

/// Read the link from the driver (link task only) and publish it.
fn publish_link_snapshot() {
    guard::op("link_read");
    let mut info = l2::link_read();
    guard::op("");
    info.pinned = PINNED.load(Ordering::Relaxed) >= 0;
    info.pin_failed_slot = PIN_FAILED.load(Ordering::Relaxed) as u8;
    critical_section::with(|cs| LINK_SNAPSHOT.borrow(cs).set(info));
}
static SELECTED: AtomicI32 = AtomicI32::new(-1);
static CONNECTED_NOW: AtomicBool = AtomicBool::new(false);
static SCAN_SEEN: AtomicU32 = AtomicU32::new(0);
static SCAN_SIGNAL: [AtomicI32; 8] = [const { AtomicI32::new(-127) }; 8];

/// The last scan, strongest first (`scan`, and the `s3_bss` line), the access point chosen for the slot being joined and the one the driver actually joined.
const BSS_TABLE: usize = 32;
#[derive(Clone, Copy)]
struct BssRow {
    ssid: [u8; 33],
    ssid_len: u8,
    bss: Bss,
    auth: u8,
}
const NO_ROW: BssRow = BssRow { ssid: [0; 33], ssid_len: 0, bss: Bss { bssid: [0; 6], channel: 0, rssi: 0 }, auth: 0 };
struct ScanTable {
    rows: [BssRow; BSS_TABLE],
    count: usize,
    seen: usize,
    seq: u32,
}
static SCAN_TABLE: CsMutex<RefCell<ScanTable>> = CsMutex::new(RefCell::new(ScanTable { rows: [NO_ROW; BSS_TABLE], count: 0, seen: 0, seq: 0 }));
static BSS_BEST: CsMutex<RefCell<Option<Bss>>> = CsMutex::new(RefCell::new(None));
static BSS_JOINED: CsMutex<RefCell<Option<Bss>>> = CsMutex::new(RefCell::new(None));
/// Console `bss pin on|off`: pin the BSSID and channel of the strongest usable access point in the station config. Off (default) is the C: all-channel scan, join by signal.
static PIN_BSS: AtomicBool = AtomicBool::new(false);
/// Console `scan`: ask the link task to scan now, wait for the table.
static SCAN_REQ: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static SCAN_DONE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// The mode and display settings read from the NVS at boot (`None` until the init task has read them).
static STORED: CsMutex<core::cell::Cell<Option<settings::Stored>>> = CsMutex::new(core::cell::Cell::new(None));
/// Console `use N`: the saved network (0-based) the link task must join and keep; -1 = by rank. A failed join of the pinned slot drops the pin (C `pin_failed_slot`).
static PINNED: AtomicI32 = AtomicI32::new(-1);
static PIN_FAILED: AtomicU32 = AtomicU32::new(0);
static USE_REQ: Signal<CriticalSectionRawMutex, ()> = Signal::new();

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
    tdongle_rescue::arm();
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: HEAP_RECLAIMED);
    #[cfg(feature = "tailnet")]
    esp_alloc::heap_allocator!(#[esp_hal::ram(unstable(dcache_reclaimed))] size: tailnet::budget::HEAP_DCACHE);
    esp_alloc::heap_allocator!(size: HEAP_REGULAR);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    let dogs = guard::Dogs::arm(peripherals.TIMG1);
    guard::stage(Stage::Usb);

    // The console and the USB device run in an interrupt-mode executor above everything else (rule 13: always reachable). A bridge task that spins, a radio call that
    // takes seconds or a scan cannot stop them being polled; they therefore never call the radio driver (status reads a snapshot the link task keeps).
    static INT_EXEC: StaticCell<InterruptExecutor<1>> = StaticCell::new();
    let int_spawner = INT_EXEC.init(InterruptExecutor::new(peripherals.FROM_CPU_INTR1)).start(Priority::Priority3);

    // the ring's permanent slots (8), allocated once; the housekeeping task adds and removes the elastic chunks
    critical_section::with(|cs| {
        let mut r = RING.borrow_ref_mut(cs);
        for id in 0..BASE_SLOTS {
            r.add_slot(id, alloc::boxed::Box::new(RingSlot { len: 0, data: [0; MTU] }));
        }
        RING_CAP.store(r.cap as u32, Ordering::Relaxed);
    });

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
    static ACM_WR: StaticCell<Mutex<CriticalSectionRawMutex, AcmWriter>> = StaticCell::new();
    let acm_wr: &'static Mutex<CriticalSectionRawMutex, AcmWriter> = ACM_WR.init(Mutex::new(acm_wr));
    #[cfg(feature = "tailnet")]
    let _ = tailnet::WRITER.init(acm_wr);
    let dev = b.build();

    // The USB device attaches when `usb_task` first runs: spawn it before anything else and do not block between here and the first `.await`.
    int_spawner.spawn(usb_task(SendDevice(dev)).unwrap());
    int_spawner.spawn(console_task(acm_rd, acm_wr, bridge, state).unwrap());
    int_spawner.spawn(supervise::supervisor_task(dogs, state.boot.safe_mode).unwrap());
    int_spawner.spawn(supervise::reattach_task().unwrap());
    supervise::THREAD_SPAWNER.get_or_init(|| spawner.make_send());
    spawner.spawn(supervise::thread_pulse_task().unwrap());
    spawner.spawn(usb_rx_task(rx, producer).unwrap());
    int_spawner.spawn(usb_tx_task(SendTx(tx)).unwrap());
    spawner.spawn(ring_housekeeping_task().unwrap());
    spawner.spawn(heap_task(acm_wr).unwrap());
    spawner.spawn(settings::task().unwrap());
    spawner.spawn(
        ui::ui_task(ui::Hardware {
            spi: peripherals.SPI2,
            mosi: peripherals.GPIO3,
            clk: peripherals.GPIO5,
            cs: peripherals.GPIO4,
            dc: peripherals.GPIO2,
            rst: peripherals.GPIO1,
            bl: peripherals.GPIO38,
            button: peripherals.GPIO0,
            led_data: peripherals.GPIO40,
            led_clk: peripherals.GPIO39,
            ledc: peripherals.LEDC,
        })
        .unwrap(),
    );
    spawner.spawn(init_task(peripherals.WIFI, peripherals.FLASH, peripherals.RNG, peripherals.ADC1, spawner, bridge, worker, state.boot.safe_mode).unwrap());
    loop {
        Timer::after_secs(3600).await;
    }
}

/// Everything that can block or fail, after the console is up. Any failure is noted (`init` on the console) and leaves the console running.
#[embassy_executor::task]
async fn init_task(
    wifi: esp_hal::peripherals::WIFI<'static>,
    flash: esp_hal::peripherals::FLASH<'static>,
    rng: esp_hal::peripherals::RNG<'static>,
    adc: esp_hal::peripherals::ADC1<'static>,
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

    // ---- the stored settings: the NVS the C firmware wrote (the C load rules, v0.1.x import included) ----
    guard::stage(Stage::Settings);
    let mut tailnet_mode = false;
    let loaded = match settings::mount(flash).await {
        Ok((l, stored)) => {
            // the stored mode picks the data path; safe mode returned above, so tailnet mode is never reachable from it
            tailnet_mode = cfg!(feature = "tailnet") && matches!(stored.mode, Ok(StoredMode::TailnetGateway));
            critical_section::with(|cs| STORED.borrow(cs).set(Some(stored)));
            if l.saved.list().is_empty() {
                init_note("no saved networks");
            }
            Some(l)
        }
        Err(why) => {
            init_note(why);
            None
        }
    };
    // ---- what kind of boot is this? (`setup_boot_early` + `gateway_startup_sequence`): setup when asked for over a software reset, or when nothing is saved ----
    let words = guard::setup_take();
    let software = matches!(esp_hal::system::reset_reason(), Some(esp_hal::rtc_cntl::SocResetReason::CoreSw));
    let store_ok = loaded.is_some();
    let networks_saved = loaded.as_ref().is_none_or(|l| !l.saved.list().is_empty()); // an unreadable store counts as "has networks" (a damaged store never opens an access point by itself)
    let decision = tdongle_setup::boot::SetupBoot::decide(software, words[0], words[1], words[2], networks_saved, store_ok);
    let boot = tdongle_setup::boot::Boot::decide(decision, false);
    let Some(loaded) = loaded else {
        // no settings: the bridge cannot choose a network, but the USB side stays a plain bridge boot
        if let tdongle_setup::boot::Boot::Bridge(b) = &boot {
            USB_NETWORK_RX.signal(b.usb_network());
        }
        return;
    };
    SAVED.lock(|c| *c.borrow_mut() = Some(loaded));
    let boot = match boot {
        tdongle_setup::boot::Boot::Setup(setup_boot) => setup::run(setup_boot, wifi, rng, adc, spawner).await,
        tdongle_setup::boot::Boot::Tailnet(_) => return, // not built yet: uninhabited
        tdongle_setup::boot::Boot::Bridge(b) => b,
    };
    USB_NETWORK_RX.signal(boot.usb_network());

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
    if tailnet_mode {
        // the bridge's host to Wi-Fi worker is not used when tailnet mode runs: the runtime's USB task is the data path. If tailnet mode cannot start (the heap is
        // short), this boot is a bridge boot, and `running=` in `status` says so.
        #[cfg(feature = "tailnet")]
        if let Err(e) = tailnet::start(spawner) {
            println!("tailnet gateway not started: {:?}", e);
            init_note("tailnet not started: heap short");
            spawner.spawn(worker_task(worker).unwrap());
        } else {
            drop(worker);
        }
        #[cfg(not(feature = "tailnet"))]
        drop(worker);
    } else {
        spawner.spawn(worker_task(worker).unwrap());
    }
    spawner.spawn(pm::timer_task().unwrap());
    pm::start();
    link_loop(&mut controller, bridge).await
}

// ======================================================================================================================
// Wi-Fi link supervision (scan, join the best saved network, wait for disconnect, bridge.link)
// ======================================================================================================================

/// An all-channel active scan (40 to 100 ms a channel, hidden SSIDs shown, as C `wifi_maintain`), recorded for `scan` and the `s3_bss` line. Wakes a console waiting on it.
async fn scan_all(controller: &mut WifiController<'static>) -> Result<alloc::vec::Vec<esp_radio::wifi::ap::AccessPointInfo>, &'static str> {
    guard::stage(Stage::Scan);
    SCAN_REQ.reset();
    let config = ScanConfig::default()
        .with_show_hidden(true)
        .with_scan_type(ScanTypeConfig::Active { min: esp_hal::time::Duration::from_millis(40), max: esp_hal::time::Duration::from_millis(100) })
        .with_max(64);
    let result = match with_timeout(Duration::from_secs(15), controller.scan_async(&config)).await {
        Ok(Ok(aps)) => Ok(aps),
        Ok(Err(_)) => Err("scan failed"),
        Err(_) => Err("scan timed out"),
    };
    if let Ok(aps) = &result {
        critical_section::with(|cs| {
            let mut t = SCAN_TABLE.borrow_ref_mut(cs);
            let mut order: heapless_order::Order = heapless_order::Order::new();
            for (i, a) in aps.iter().enumerate() {
                order.push(i, a.signal_strength);
            }
            t.count = 0;
            t.seen = aps.len();
            t.seq = t.seq.wrapping_add(1);
            for &i in order.sorted() {
                if t.count == BSS_TABLE {
                    break;
                }
                let a = &aps[i];
                let mut row = NO_ROW;
                let name = a.ssid.as_str().as_bytes();
                row.ssid[..name.len()].copy_from_slice(name);
                row.ssid_len = name.len() as u8;
                row.bss = Bss { bssid: a.bssid, channel: a.channel, rssi: a.signal_strength };
                row.auth = a.auth_method.map_or(0xff, |m| m as u8);
                let n = t.count;
                t.rows[n] = row;
                t.count += 1;
            }
        });
        SCAN_SEEN.store(aps.len() as u32, Ordering::Relaxed);
    }
    SCAN_DONE.signal(());
    result
}

/// Indices of up to 64 scan results ordered strongest first, without allocating.
mod heapless_order {
    pub struct Order {
        idx: [usize; 64],
        rssi: [i8; 64],
        n: usize,
    }
    impl Order {
        pub const fn new() -> Self {
            Self { idx: [0; 64], rssi: [0; 64], n: 0 }
        }
        pub fn push(&mut self, i: usize, rssi: i8) {
            if self.n < 64 {
                self.idx[self.n] = i;
                self.rssi[self.n] = rssi;
                self.n += 1;
            }
        }
        pub fn sorted(&mut self) -> &[usize] {
            // insertion sort, strongest first, stable
            for a in 1..self.n {
                let (i, r) = (self.idx[a], self.rssi[a]);
                let mut b = a;
                while b > 0 && self.rssi[b - 1] < r {
                    self.idx[b] = self.idx[b - 1];
                    self.rssi[b] = self.rssi[b - 1];
                    b -= 1;
                }
                self.idx[b] = i;
                self.rssi[b] = r;
            }
            &self.idx[..self.n]
        }
    }
}

/// A button gesture that needs the setup boot, the factory reset or the NVS writer (milestone C): not available yet, said on the console.
fn ui_command(cmd: tdongle_ui::ui::Command) {
    let mut t = String::new();
    let _ = write!(t, "ui command `{}` needs the setup/storage layer (not in this image yet)", cmd);
    init_note(&t);
}

/// A pinned slot that cannot be joined is released, so the dongle falls back to ranking instead of retrying one dead network for ever.
fn drop_failed_pin(slot: usize) {
    if PINNED.compare_exchange(slot as i32, -1, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
        PIN_FAILED.store(slot as u32 + 1, Ordering::Relaxed);
    }
}

/// Tailnet mode owns the data path in this boot.
fn tailnet_active() -> bool {
    #[cfg(feature = "tailnet")]
    return tailnet::active();
    #[cfg(not(feature = "tailnet"))]
    false
}

/// The link went up or down: tell whichever data path runs (the bridge, or the tailnet runtime's embassy-net driver).
fn link_hook(bridge: &'static Bridge<FwEnv>, up: bool, ctx: &TaskContext) {
    #[cfg(feature = "tailnet")]
    if tailnet::active() {
        tailnet::link(up);
        return;
    }
    bridge.link(up, ctx);
}

async fn link_loop(controller: &mut WifiController<'static>, bridge: &'static Bridge<FwEnv>) -> ! {
    // SAFETY: this is the link supervisor task; it may block and is not a driver callback.
    let ctx = unsafe { TaskContext::assume() };
    let mut next = 0usize;
    loop {
        // The list as it is now (a console `profile`, `del` or reset replaces it): nothing saved means nothing to join.
        let Some(loaded) = SAVED.lock(|c| *c.borrow()).filter(|l| !l.saved.list().is_empty()) else {
            let _ = with_timeout(Duration::from_secs(2), USE_REQ.wait()).await;
            continue;
        };
        // Strongest saved network that a scan (hidden SSIDs included) sees; none seen: try the saved list in order (directed probes find hidden ones).
        guard::stage(Stage::Scan);
        let scan = scan_all(controller).await;
        let mut best_bss: Option<Bss> = None;
        let slot = match &scan {
            Ok(aps) => {
                let signal = tdongle_saved::signals(&loaded.saved, aps.iter().map(|a| (a.ssid.as_str().as_bytes(), a.signal_strength)));
                for (i, v) in signal.iter().enumerate() {
                    SCAN_SIGNAL[i].store(*v as i32, Ordering::Relaxed);
                }
                let chosen = tdongle_saved::choose(&loaded, &signal);
                if let Some(slot) = chosen {
                    // the strongest access point of that SSID: what the all-channel, by-signal join selects, and what `bss pin on` pins
                    let ssid = loaded.saved.list()[slot].ssid_bytes();
                    best_bss = tdongle_saved::strongest_bss(ssid, aps.iter().map(|a| (a.ssid.as_str().as_bytes(), a.bssid, a.channel, a.signal_strength)));
                }
                chosen
            }
            Err(why) => {
                init_note(why);
                None
            }
        };
        critical_section::with(|cs| *BSS_BEST.borrow_ref_mut(cs) = best_bss);
        let count = loaded.saved.list().len();
        let pinned = PINNED.load(Ordering::Relaxed);
        let slot = if pinned >= 0 && (pinned as usize) < count {
            pinned as usize
        } else {
            slot.unwrap_or_else(|| {
                next = (next + 1) % count;
                next
            })
        };
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
        // The C station configuration (`wifi_fill_station`): all-channel scan, join by signal. esp-radio's default is the FAST scan, which joins the first access point
        // that answers: on the board that was a far BSS of the right SSID (-88 dBm, channel 1) while the C joined -50 on channel 11.
        let mut station = StationConfig::default().with_ssid(ssid_t).with_authentication(auth).with_scan_method(ScanMethod::AllChannels);
        if let (true, Some(b)) = (PIN_BSS.load(Ordering::Relaxed), best_bss.filter(Bss::usable)) {
            station = station.with_bssid(b.bssid).with_channel(b.channel);
        }
        if controller.set_config(&Config::Station(station)).is_err() {
            init_note("set_config failed");
            Timer::after_secs(2).await;
            continue;
        }
        if controller.set_protocols(Protocols::default()).is_err() {
            init_note("set_protocols failed"); // default is b/g/n: never LR
        }
        if !tailnet_active() {
            guard::op("roaming_assist");
            l2::roaming_assist(); // bridge mode: 802.11k/v on, as C (`wifi_roaming_assist`)
            guard::op("");
        }
        guard::stage(Stage::Connect);
        match with_timeout(Duration::from_secs(30), controller.connect_async()).await {
            Ok(Ok(info)) => {
                println!("connected: {:?}", info);
                guard::stage(Stage::Running);
                CONNECTS.fetch_add(1, Ordering::Relaxed);
                LAST_CONNECT_MS.store(Instant::now().as_millis() as u32, Ordering::Relaxed);
                if let Ok((ch, _)) = controller.channel() {
                    CHANNEL.store(ch, Ordering::Relaxed);
                }
                guard::op("register");
                l2::register(); // the driver is started now: (re-)register the callbacks (the tx-done registration needs a started driver)
                guard::op("");
                l2::link_changed(); // the driver cleared its queues when the link came up
                SELECTED.store(slot as i32, Ordering::Relaxed);
                CONNECTED_NOW.store(true, Ordering::Relaxed);
                publish_link_snapshot();
                // A driver call: never inside a critical section (it can wait for the Wi-Fi task, which cannot run while interrupts are off: that was the S3 regression).
                guard::op("joined_bss");
                let joined = l2::joined_bss();
                guard::op("");
                critical_section::with(|cs| *BSS_JOINED.borrow_ref_mut(cs) = joined);
                link_hook(bridge, true, &ctx);
                loop {
                    match select(select3(controller.wait_for_disconnect_async(), SCAN_REQ.wait(), USE_REQ.wait()), Timer::after_secs(2)).await {
                        Either::First(Either3::Second(())) => {
                            let _ = scan_all(controller).await; // a console `scan` while connected
                        }
                        Either::First(Either3::Third(())) => {
                            // console `use N`: leave this network; the next round joins the pinned slot
                            let _ = controller.disconnect_async().await;
                            break;
                        }
                        Either::First(Either3::First(r)) => {
                            DISCONNECTS.fetch_add(1, Ordering::Relaxed);
                            println!("disconnected: {:?}", r.is_ok());
                            let _ = &LAST_REASON; // reason code: DisconnectedInfo field not mapped in the spike
                            break;
                        }
                        Either::Second(()) => match {
                            publish_link_snapshot();
                            guard::op("joined_bss");
                            let now_bss = l2::joined_bss();
                            guard::op("");
                            critical_section::with(|cs| {
                                let mut j = BSS_JOINED.borrow_ref_mut(cs);
                                if let (Some(old), Some(new)) = (*j, now_bss) {
                                    if old.bssid != new.bssid {
                                        ROAMS.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                if now_bss.is_some() {
                                    *j = now_bss;
                                }
                            });
                            controller.rssi()
                        } {
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
                link_hook(bridge, false, &ctx);
            }
            Ok(Err(e)) => {
                println!("connect failed: {:?}, retrying", e);
                drop_failed_pin(slot);
            }
            Err(_) => {
                init_note("connect timed out");
                drop_failed_pin(slot);
            }
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

/// The USB device, moved to the interrupt executor. `UsbDevice` is not `Send` only because its handler list is `dyn Handler` without the bound; the one handler (`Ctl`) holds
/// interface numbers and `&'static str`s and touches only atomics and critical-section statics, and after this move nothing else uses the device.
struct SendDevice(UsbDevice<'static, Drv>);

// SAFETY: see above: single owner after the move, handler state is atomics and critical-section guarded statics.
unsafe impl Send for SendDevice {}

#[embassy_executor::task]
async fn usb_task(mut dev: SendDevice) -> ! {
    dev.0.run().await
}

/// host -> Wi-Fi: one datagram at a time into `Producer::host`. HOLD keeps the datagram in the NTB buffer and does not read the next
/// NTB packet until `rx_resume` (RESUME_SIG) fires: the OUT endpoint is not re-armed, the host is NAKed.
#[embassy_executor::task]
async fn usb_rx_task(mut rx: NcmReceiver, mut producer: tdongle_bridge::Producer<'static, FwEnv>) -> ! {
    // the USB network belongs to a bridge boot: a setup boot never gets the capability, so these tasks never run (ADR 0001 rule 3)
    let _network = USB_NETWORK_RX.wait().await;
    USB_NETWORK_TX.signal(());
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
            #[cfg(feature = "tailnet")]
            if tailnet::active() {
                // tailnet mode owns the data path: the datagram goes to the runtime (waiting for it, which keeps the OUT endpoint un-armed) and never to the bridge
                if !tailnet::usb_rx(d).await {
                    break 'conn;
                }
                UP_FRAMES.fetch_add(1, Ordering::Relaxed);
                UP_BYTES.fetch_add(len, Ordering::Relaxed);
                rx.advance();
                continue;
            }
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
async fn usb_tx_task(tx: SendTx) -> ! {
    USB_NETWORK_TX.wait().await;
    let mut tx = tx.0;
    let mut seq = 0u32;
    let mut next = Instant::now();
    loop {
        if USB_MODE.load(Ordering::Relaxed) == USB_SOURCE {
            // `usb source`: broadcast dummy frames on IN (measures device -> host alone), one datagram per NTB as in the S2 measurement (7.41 Mbit/s)
            if let Some(room) = tx.ntb().slot(SOURCE_FRAME) {
                room.fill(0);
                room[0..6].fill(0xff);
                room[6..12].copy_from_slice(&[0x02, 0x54, 0x44, 0x53, 0x33, 0x01]);
                room[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
                room[14..18].copy_from_slice(&seq.to_be_bytes());
                tx.ntb().commit(SOURCE_FRAME);
            }
            match tx.send_ntb().await {
                Ok(_) => {
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
        // Everything the radio delivered while the last NTB was on the wire goes into the next one (up to 8 datagrams, 3,200 bytes): one transfer per burst, not per frame.
        let moved = loop {
            if USB_MODE.load(Ordering::Relaxed) == USB_SOURCE {
                break 0;
            }
            let moved = critical_section::with(|cs| RING.borrow_ref_mut(cs).pop_into_ntb(tx.ntb()));
            if moved != 0 {
                break moved;
            }
            let _ = with_timeout(Duration::from_millis(50), RING_SIG.wait()).await; // wake regularly to notice a mode change
        };
        if moved == 0 {
            continue;
        }
        pm::usb_tx_begin();
        let sent = tx.send_ntb().await;
        pm::usb_tx_end();
        match sent {
            Ok((frames, bytes)) => {
                RING_SENT.fetch_add(frames as u32, Ordering::Relaxed);
                DOWN_FRAMES.fetch_add(frames as u32, Ordering::Relaxed);
                DOWN_BYTES.fetch_add(bytes as u32, Ordering::Relaxed);
                NTB_IN_COUNT.fetch_add(1, Ordering::Relaxed);
                NTB_IN_FRAMES.fetch_add(frames as u32, Ordering::Relaxed);
                NTB_IN_FRAMES_MAX.fetch_max(frames as u32, Ordering::Relaxed);
                NTB_IN_HIST[match frames {
                    0 | 1 => 0,
                    2 => 1,
                    3 | 4 => 2,
                    _ => 3,
                }]
                .fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                RING_WRITE_ERR.fetch_add(1, Ordering::Relaxed);
                Timer::after_millis(1).await; // endpoint disabled: do not spin
            }
        }
    }
}

/// The IN sender, moved to the interrupt executor so a Wi-Fi burst is on the wire within microseconds of `rx_cb` (the thread executor runs the bridge worker and can be busy).
/// `NcmSender` is not `Send` only because the driver's endpoint types are not marked so; after the move nothing else uses it.
struct SendTx(NcmSender);

// SAFETY: single owner after the move; the endpoint is touched only by `usb_tx_task`.
unsafe impl Send for SendTx {}

/// Grows and shrinks the frame ring (the only code that allocates or frees its slots), in the thread executor.
#[embassy_executor::task]
async fn ring_housekeeping_task() -> ! {
    use tdongle_usb_out::elastic::{self, Step};
    loop {
        let _ = with_timeout(Duration::from_millis(100), HOUSEKEEP_SIG.wait()).await;
        l2::HEAP_MIN.fetch_min(esp_alloc::HEAP.free() as u32, Ordering::Relaxed);
        let (used, cap) = critical_section::with(|cs| {
            let r = RING.borrow_ref(cs);
            (r.count, r.cap)
        });
        let now = Instant::now().as_millis() as u32;
        let idle = now.wrapping_sub(LAST_BUSY_MS.load(Ordering::Relaxed));
        match elastic::step(used, cap, RING_MAX.load(Ordering::Relaxed) as usize, elastic::CHUNK_SLOTS * core::mem::size_of::<RingSlot>(), esp_alloc::HEAP.free(), idle) {
            Step::Grow => {
                let a = alloc::boxed::Box::new(RingSlot { len: 0, data: [0; MTU] });
                let b = alloc::boxed::Box::new(RingSlot { len: 0, data: [0; MTU] });
                let added = critical_section::with(|cs| {
                    let mut r = RING.borrow_ref_mut(cs);
                    match (r.next_free_id(), a, b) {
                        (Some(i), a, b) => {
                            r.add_slot(i, a);
                            let j = r.next_free_id().unwrap_or(i);
                            r.add_slot(j, b);
                            RING_CAP.store(r.cap as u32, Ordering::Relaxed);
                            true
                        }
                        _ => false,
                    }
                });
                if added {
                    RING_GROWS.fetch_add(1, Ordering::Relaxed);
                }
            }
            Step::Shrink => {
                let chunk = critical_section::with(|cs| {
                    let mut r = RING.borrow_ref_mut(cs);
                    let c = r.take_chunk();
                    RING_CAP.store(r.cap as u32, Ordering::Relaxed);
                    c
                });
                if chunk.is_some() {
                    RING_SHRINKS.fetch_add(1, Ordering::Relaxed); // the boxes drop here, outside the critical section
                }
            }
            Step::DeniedHeap => {
                RING_GROW_DENIED.fetch_add(1, Ordering::Relaxed);
            }
            Step::None => {}
        }
    }
}

// ======================================================================================================================
// Console (CDC-ACM)
// ======================================================================================================================

async fn out(w: &'static Mutex<CriticalSectionRawMutex, AcmWriter>, s: &str, timeout_ms: u64) {
    let mut g = w.lock().await;
    // Do not wedge the console if nobody reads the port.
    let _ = with_timeout(Duration::from_millis(timeout_ms), g.write_all(s.as_bytes())).await;
}

/// `scan`: every access point of the last scan, strongest first (C `scan` prints `ssid= rssi= auth=`; the BSSID and channel are added), then a summary.
fn scan_text(out: &mut String) {
    // One row is copied out of the table at a time: formatting (which allocates) happens outside any critical section.
    let (count, seen, seq, joined) = critical_section::with(|cs| {
        let t = SCAN_TABLE.borrow_ref(cs);
        (t.count, t.seen, t.seq, *BSS_JOINED.borrow_ref(cs))
    });
    let connected = CONNECTED_NOW.load(Ordering::Relaxed);
    for i in 0..count {
        let Some(row) = critical_section::with(|cs| {
            let t = SCAN_TABLE.borrow_ref(cs);
            (i < t.count && t.seq == seq).then(|| t.rows[i])
        }) else {
            break; // a newer scan replaced the table while we were printing
        };
        let name = &row.ssid[..usize::from(row.ssid_len)];
        let ssid: String = name.iter().map(|&b| if (32..127).contains(&b) { b as char } else { '?' }).collect();
        let b = row.bss.bssid;
        let slot = SAVED.lock(|c| c.borrow().as_ref().and_then(|l| l.saved.list().iter().position(|p| p.ssid_bytes() == name)));
        let _ = write!(
            out,
            "ssid={} bssid={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} channel={} rssi={} auth={} usable={}",
            ssid, b[0], b[1], b[2], b[3], b[4], b[5], row.bss.channel, row.bss.rssi, row.auth, u8::from(row.bss.usable())
        );
        if let Some(i) = slot {
            let _ = write!(out, " saved={}", i + 1);
        }
        if connected && joined.is_some_and(|j| j.bssid == row.bss.bssid) {
            out.push_str(" joined=1");
        }
        out.push_str("\r\n");
    }
    let _ = write!(out, "scan_done seen={} listed={} seq={}\r\n", seen, count, seq);
}

/// The rows of the last scan as the setup page lists them: SSID (32 byte field), signal, not open.
fn scan_rows(mut f: impl FnMut(&[u8; 32], i32, bool)) {
    let n = critical_section::with(|cs| SCAN_TABLE.borrow_ref(cs).count);
    for i in 0..n {
        let row = critical_section::with(|cs| SCAN_TABLE.borrow_ref(cs).rows[i]);
        let mut ssid = [0u8; 32];
        let len = usize::from(row.ssid_len).min(32);
        ssid[..len].copy_from_slice(&row.ssid[..len]);
        f(&ssid, i32::from(row.bss.rssi), row.auth != 0);
    }
}

/// The strongest access point of the joined network's SSID in the latest scan table.
fn best_from_latest_scan() -> Option<Bss> {
    let selected = SELECTED.load(Ordering::Relaxed);
    let ssid: heapless_ssid::Ssid = SAVED.lock(|c| c.borrow().as_ref().and_then(|l| l.saved.list().get(usize::try_from(selected).ok()?).map(|p| heapless_ssid::Ssid::from(p.ssid_bytes()))))?;
    critical_section::with(|cs| {
        let t = SCAN_TABLE.borrow_ref(cs);
        tdongle_saved::strongest_bss(ssid.as_bytes(), t.rows[..t.count].iter().map(|r| (&r.ssid[..usize::from(r.ssid_len)], r.bss.bssid, r.bss.channel, r.bss.rssi)))
    })
}

/// A copy of an SSID (up to 32 bytes) that can leave a lock.
mod heapless_ssid {
    #[derive(Clone, Copy)]
    pub struct Ssid {
        b: [u8; 32],
        n: usize,
    }
    impl From<&[u8]> for Ssid {
        fn from(s: &[u8]) -> Self {
            let n = s.len().min(32);
            let mut b = [0; 32];
            b[..n].copy_from_slice(&s[..n]);
            Self { b, n }
        }
    }
    impl Ssid {
        pub fn as_bytes(&self) -> &[u8] {
            &self.b[..self.n]
        }
    }
}

fn bssid_text(b: Option<Bss>, out: &mut String) {
    match b {
        Some(b) => {
            let x = b.bssid;
            let _ = write!(out, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} channel={} rssi={}", x[0], x[1], x[2], x[3], x[4], x[5], b.channel, b.rssi);
        }
        None => out.push_str("none channel=0 rssi=0"),
    }
}

/// `pm`: the power line, one line per burst lock.
fn write_pm(out: &mut String) {
    let st = pm::status();
    let power = tdongle_serial::pm_report::Power {
        scaling: st.scaling,
        configure_error: st.configure_error,
        cpu_mhz: st.cpu_mhz,
        max_mhz: st.max_mhz,
        min_mhz: st.min_mhz,
        lock_create_failures: st.lock_create_failures,
    };
    let mut locks: alloc::vec::Vec<tdongle_serial::pm_report::Lock<'_>> = alloc::vec::Vec::new();
    for b in st.bursts() {
        locks.push(tdongle_serial::pm_report::Lock {
            name: b.name.as_str(),
            depth: b.depth,
            acquires: b.acquires,
            releases: b.releases,
            held_us: b.held_us,
            max_depth: b.max_depth,
            underflows: b.underflows,
            forced_releases: b.forced_releases,
            backend_failures: b.backend_failures,
            isr_rejects: b.isr_rejects,
        });
    }
    let _ = tdongle_serial::pm_report::write_report(out, &power, &locks, None);
}

fn build_status(bridge: &Bridge<FwEnv>, out: &mut String) {
    l2::HEAP_MIN.fetch_min(esp_alloc::HEAP.free() as u32, Ordering::Relaxed);
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
    let setup_name_bytes = setup::ap_name();
    let setup_name = core::str::from_utf8(&setup_name_bytes).unwrap_or("").trim_end_matches('\0');
    let snap = Snapshot {
        mode: if setup::ACTIVE.load(Ordering::Relaxed) { Mode::Setup } else { Mode::Adapter },
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
            let mut info = critical_section::with(|cs| LINK_SNAPSHOT.borrow(cs).get());
            let selected = SELECTED.load(Ordering::Relaxed);
            info.selected_slot = if linked && (0..8).contains(&selected) { selected as u8 + 1 } else { 0 };
            info
        },
        events: Events {
            connects: CONNECTS.load(Ordering::Relaxed),
            disconnects: DISCONNECTS.load(Ordering::Relaxed),
            last_reason: LAST_REASON.load(Ordering::Relaxed) as u16,
            roams: ROAMS.load(Ordering::Relaxed),
            ..Default::default()
        },
        prefs: Prefs { saved: saved_count, preferred: preferred, priorities: &priorities[..saved_count as usize], roaming_assist: true },
        display: {
            let d = critical_section::with(|cs| STORED.borrow(cs).get()).map(|x| x.display).unwrap_or_default();
            DisplayState { brightness: d.brightness, rotation: d.rotation, dim_seconds: d.dim_seconds, page: 0 }
        },
        setup_ap_name: &setup_name,
        setup_seconds_left: if setup::ACTIVE.load(Ordering::Relaxed) { setup::session().seconds_left(Instant::now().as_millis() as u32) } else { 0 },
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
        ring_bytes: RING_CAP.load(Ordering::Relaxed) * MTU as u32,
        high_water_slabs: RING_HIGH.load(Ordering::Relaxed),
        enqueued_frames: RING_ENQ.load(Ordering::Relaxed),
        sent_frames: RING_SENT.load(Ordering::Relaxed),
        dropped_full: RING_FULL.load(Ordering::Relaxed),
        dropped_link_down: RING_NOT_READY.load(Ordering::Relaxed),
        flushed_link_down: RING_FLUSHED.load(Ordering::Relaxed),
        max_bytes: RING_MAX.load(Ordering::Relaxed) * MTU as u32,
        grow_events: RING_GROWS.load(Ordering::Relaxed),
        shrink_events: RING_SHRINKS.load(Ordering::Relaxed),
        grow_denied_heap: RING_GROW_DENIED.load(Ordering::Relaxed),
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
    let stored_mode = critical_section::with(|cs| STORED.borrow(cs).get()).map_or("unknown", |x| x.mode.map_or("invalid", |m| m.name()));
    let _ = write!(out, "rust_port phase=1 stored_mode={} running={}\r\n", stored_mode, if tailnet_active() { "tailnet_gateway" } else { "wifi_bridge" });
    let _ = write!(
        out,
        "rust_heap size={} used={} free_internal={} minimum_internal={}\r\n",
        esp_alloc::HEAP.stats().size,
        esp_alloc::HEAP.used(),
        esp_alloc::HEAP.free(),
        l2::HEAP_MIN.load(Ordering::Relaxed)
    );
    heap_line(out);
    let _ = write!(
        out,
        "s3 ring_write_err={} wifi_room_no={} ntb_tx={} usb_resets={} cpu_mhz={} tx_queue={} rx_queue={} usb={} out={} sink_frames={} sink_bytes={} source_frames={} source_bytes={} rx_cb={} rx_ignored={} tx_drv_err={} tx_last_err={:#x} scan_seen={}\r\n",
        RING_WRITE_ERR.load(Ordering::Relaxed),
        WIFI_TX_ROOM_NO.load(Ordering::Relaxed),
        ncm::TX_NTBS.load(Ordering::Relaxed),
        RESETS.load(Ordering::Relaxed),
        pm::status().cpu_mhz,
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
    // the download path: ring depth, Wi-Fi burst shape and IN NTB aggregation (explain TCP-down retransmits with these)
    let (used, cap) = critical_section::with(|cs| {
        let r = RING.borrow_ref(cs);
        (r.count, r.cap)
    });
    let ntbs = NTB_IN_COUNT.load(Ordering::Relaxed);
    let frames = NTB_IN_FRAMES.load(Ordering::Relaxed);
    let _ = write!(
        out,
        "s3_ring max={} heap_min={} cap={} used={} high={} full={} grows={} shrinks={} grow_denied={} rx_gap_hist={}/{}/{}/{}/{} rx_burst_max={} rx_bursts_ge4={} ntb_in={} ntb_in_frames={} ntb_in_frames_max={} ntb_hist_1_2_4_8={}/{}/{}/{} avg_x100={}\r\n",
        RING_MAX.load(Ordering::Relaxed),
        l2::HEAP_MIN.load(Ordering::Relaxed),
        cap,
        used,
        RING_HIGH.load(Ordering::Relaxed),
        RING_FULL.load(Ordering::Relaxed),
        RING_GROWS.load(Ordering::Relaxed),
        RING_SHRINKS.load(Ordering::Relaxed),
        RING_GROW_DENIED.load(Ordering::Relaxed),
        RX_GAP_HIST[0].load(Ordering::Relaxed),
        RX_GAP_HIST[1].load(Ordering::Relaxed),
        RX_GAP_HIST[2].load(Ordering::Relaxed),
        RX_GAP_HIST[3].load(Ordering::Relaxed),
        RX_GAP_HIST[4].load(Ordering::Relaxed),
        RX_BURST_MAX.load(Ordering::Relaxed),
        RX_BURSTS_GE4.load(Ordering::Relaxed),
        ntbs,
        frames,
        NTB_IN_FRAMES_MAX.load(Ordering::Relaxed),
        NTB_IN_HIST[0].load(Ordering::Relaxed),
        NTB_IN_HIST[1].load(Ordering::Relaxed),
        NTB_IN_HIST[2].load(Ordering::Relaxed),
        NTB_IN_HIST[3].load(Ordering::Relaxed),
        if ntbs == 0 { 0 } else { frames * 100 / ntbs }
    );
    // where the radio is: the access point it joined and the strongest one the scan saw for the chosen SSID (they must agree unless the driver chose otherwise)
    let (joined, best) = critical_section::with(|cs| (*BSS_JOINED.borrow_ref(cs), *BSS_BEST.borrow_ref(cs)));
    // `best` while connected: the strongest access point of the joined SSID in the LATEST scan (`scan` refreshes it); the one computed before the join is only what the
    // first, possibly partial scan saw (it once read -90 dBm while the joined BSS was -59)
    let best = if CONNECTED_NOW.load(Ordering::Relaxed) { best_from_latest_scan().or(best) } else { best };
    out.push_str("s3_bss joined=");
    bssid_text(if CONNECTED_NOW.load(Ordering::Relaxed) { joined } else { None }, out);
    out.push_str(" best=");
    bssid_text(best, out);
    let _ = write!(
        out,
        " match={} pin={} scan_method=all_channel\r\n",
        u8::from(joined.is_some() && best.is_some() && joined.map(|j| j.bssid) == best.map(|b| b.bssid)),
        u8::from(PIN_BSS.load(Ordering::Relaxed))
    );
    ui::write_status_line(out);
    supervise::write_usb_live(out);
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
async fn console_task(mut rd: AcmReader, wr: &'static Mutex<CriticalSectionRawMutex, AcmWriter>, bridge: &'static Bridge<FwEnv>, state: &'static guard::State) -> ! {
    let mut reader = LineReader::new();
    loop {
        // every wait has a 500 ms timer so the loop proves it is being polled (`supervise::console_alive`) even with no host attached
        supervise::console_alive().await;
        if matches!(select(rd.wait_connection(), Timer::after_millis(500)).await, Either::Second(())) {
            continue;
        }
        loop {
            supervise::console_alive().await;
            let mut pkt = [0u8; 64];
            supervise::READER_WAITING.store(true, Ordering::Relaxed);
            let read = select(rd.read_packet(&mut pkt), Timer::after_millis(500)).await;
            supervise::READER_WAITING.store(false, Ordering::Relaxed);
            let len = match read {
                Either::First(Ok(len)) => len,
                Either::First(Err(_)) => break,
                Either::Second(()) => continue,
            };
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

async fn handle(wr: &'static Mutex<CriticalSectionRawMutex, AcmWriter>, bridge: &'static Bridge<FwEnv>, state: &'static guard::State, line: &str) {
    let mut s = String::new();
    #[cfg(feature = "tailnet")]
    if let Some(reply) = tailnet::console(line).await {
        // a command the tailnet gateway owns (route, members, memory, inbound, member ..., tn-mem, tailnet-status)
        out(wr, &reply, 3000).await;
        return;
    }
    match line {
        "heap" => heap_line(&mut s),
        "boot-status" => {
            guard::boot_status(&mut s, FIRMWARE, ESP_APP_DESC.app_elf_sha256(), state, Instant::now().as_millis(), Some(esp_alloc::HEAP.free() as u32));
            s.push_str("\r\n");
        }
        #[cfg(feature = "diagnostics")]
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
        "scan" => {
            SCAN_DONE.reset();
            SCAN_REQ.signal(());
            if with_timeout(Duration::from_secs(20), SCAN_DONE.wait()).await.is_err() {
                s.push_str("ERR scan did not finish (radio not started?)\r\n");
            } else {
                scan_text(&mut s);
            }
        }
        #[cfg(feature = "diagnostics")]
        b if b == "bss pin on" || b == "bss pin off" => {
            PIN_BSS.store(b.ends_with("on"), Ordering::Relaxed);
            let _ = write!(s, "bss pin {} (applies to the next join)\r\n", if b.ends_with("on") { "on: BSSID and channel of the strongest usable access point" } else { "off: all-channel scan, join by signal (C)" });
        }
        st if st.starts_with("selftest ") => match tdongle_rescue::Selftest::parse(&st["selftest ".len()..]) {
            Some(kind) => {
                out(wr, "selftest: breaking this image on purpose; the rescue must reset it (two in a row: ROM download mode)\r\n", 300).await;
                supervise::selftest(kind);
            }
            None => s.push_str("usage: selftest spin|irqoff|panic|console\r\n"),
        },
        #[cfg(feature = "diagnostics")]
        u if u.starts_with("ui press ") => match &u["ui press ".len()..] {
            "short" => {
                ui::INJECT_MS.store(120, Ordering::Relaxed);
                s.push_str("ui press short injected\r\n");
            }
            "long" => {
                ui::INJECT_MS.store(1700, Ordering::Relaxed);
                s.push_str("ui press long injected\r\n");
            }
            _ => s.push_str("usage: ui press short|long\r\n"),
        },
        #[cfg(feature = "diagnostics")]
        r if r.starts_with("ring max ") => match r["ring max ".len()..].trim().parse::<u32>() {
            Ok(n) if (8..=tdongle_usb_out::elastic::STORAGE_SLOTS as u32).contains(&n) => {
                RING_MAX.store(n, Ordering::Relaxed);
                let _ = write!(s, "ring max {} slots (the C: 28); the housekeeping task grows or shrinks to it\r\n", n);
            }
            _ => s.push_str("usage: ring max 8..48\r\n"),
        },
        "init" => {
            let note = critical_section::with(|cs| *INIT_NOTE.borrow_ref(cs));
            let _ = write!(s, "init stage={} note={}\r\n", guard::current_stage().name(), note.as_str());
        }
        "normal" => {
            guard::leave_safe_mode();
            out(wr, "leaving safe mode: resetting\r\n", 500).await;
            Timer::after(Duration::from_millis(200)).await;
            crate::guard::planned_reset()
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
            Command::Status => {
                build_status(bridge, &mut s);
                #[cfg(feature = "tailnet")]
                if let Some(extra) = tailnet::status_extra().await {
                    s.push_str(&extra);
                }
            }
            Command::Help => {
                let _ = reply::write_help_implemented(&mut s, "T-Dongle Wi-Fi bridge", reply::PHASE1_FIRMWARE_COMMANDS);
            }
            Command::Capabilities => {
                let _ = reply::write_capabilities_implemented(&mut s, &["boot_diagnostics", "power_report"]);
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
            Command::Pm => write_pm(&mut s),
            Command::Display(DisplayArgs::Show) => {
                let d = critical_section::with(|cs| STORED.borrow(cs).get()).map(|x| x.display).unwrap_or_default();
                let _ = reply::write_display(&mut s, d.brightness, d.rotation, d.dim_seconds);
            }
            Command::Use(SlotArg::Number(_)) if setup::ACTIVE.load(Ordering::Relaxed) => s.push_str(reply::USE_SETUP_OPEN),
            Command::Use(SlotArg::Number(n)) => {
                let count = SAVED.lock(|c| c.borrow().as_ref().map_or(0, |l| l.saved.list().len())) as i32;
                if (1..=count).contains(&n) {
                    PINNED.store(n - 1, Ordering::Relaxed);
                    USE_REQ.signal(());
                    // v0.1.1: `use N` also makes N the preferred network, kept across restarts (a failed write only costs the preference)
                    s.push_str(&settings::call(settings::Req::Use(n)).await.0);
                } else {
                    s.push_str(reply::USE_INVALID);
                }
            }
            Command::Del(SlotArg::Number(n)) => s.push_str(&settings::call(settings::Req::Del(n)).await.0),
            Command::Del(SlotArg::TrailingGarbage) => s.push_str(reply::DEL_FAILED),
            Command::Profile(json) => s.push_str(&settings::call(settings::Req::Profile(String::from(json))).await.0),
            Command::Display(DisplayArgs::Set(d)) => s.push_str(&settings::call(settings::Req::Display(d)).await.0),
            Command::Display(DisplayArgs::Invalid) => s.push_str(reply::DISPLAY_USAGE),
            Command::Reset => s.push_str(&settings::call(settings::Req::Reset).await.0),
            Command::ConfirmReset => {
                let (text, restart) = settings::call(settings::Req::ConfirmReset).await;
                if restart {
                    out(wr, &text, 500).await;
                    Timer::after(Duration::from_millis(300)).await;
                    setup::restart(tdongle_setup::boot::Request::Enter, 0)
                }
                s.push_str(&text);
            }
            Command::Use(SlotArg::TrailingGarbage) => s.push_str(reply::USE_INVALID),
            Command::Mode(None) => s.push_str(reply::MODE_INVALID),
            Command::Mode(Some(StoredMode::TailnetGateway)) if !cfg!(feature = "tailnet") => s.push_str("ERR Tailnet gateway mode is not part of this firmware build\r\n"),
            Command::Mode(Some(StoredMode::TailnetGateway)) if state.boot.safe_mode => s.push_str("ERR Tailnet gateway mode is not available in safe mode (`normal` and a reset first)\r\n"),
            Command::Mode(Some(mode)) => {
                let (text, restart) = settings::call(settings::Req::Mode(mode)).await;
                if restart {
                    out(wr, &text, 500).await;
                    Timer::after(Duration::from_millis(300)).await;
                    crate::guard::planned_reset()
                }
                s.push_str(&text);
            }
            Command::Setup(arg) => {
                use tdongle_serial::command::SetupArg;
                let slot = match arg {
                    SetupArg::Open => Some(0u8),
                    SetupArg::Slot(n) => Some(n),
                    SetupArg::Invalid => None,
                };
                match slot {
                    None => s.push_str(reply::SETUP_USAGE),
                    Some(_) if guard::safe_mode_now() => s.push_str(reply::SETUP_RECOVERY),
                    Some(n) if setup::ACTIVE.load(Ordering::Relaxed) => {
                        setup::preselect(n);
                        s.push_str(reply::SETUP_ALREADY_OPEN);
                    }
                    Some(n) => {
                        out(wr, reply::SETUP_RESTARTING, 500).await;
                        Timer::after(Duration::from_millis(300)).await;
                        setup::restart(tdongle_setup::boot::Request::Enter, u32::from(n))
                    }
                }
            }
            Command::Cancel => {
                if setup::ACTIVE.load(Ordering::Relaxed) {
                    out(wr, reply::CANCEL_LEAVING, 500).await;
                    Timer::after(Duration::from_millis(300)).await;
                    setup::restart(tdongle_setup::boot::Request::Leave, 0)
                }
                s.push_str(reply::CANCEL_NOOP);
            }
            Command::Reboot => {
                guard::leave_safe_mode();
                out(wr, reply::REBOOT_OK, 500).await;
                Timer::after(Duration::from_millis(200)).await;
                crate::guard::planned_reset()
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
async fn heap_task(wr: &'static Mutex<CriticalSectionRawMutex, AcmWriter>) -> ! {
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
