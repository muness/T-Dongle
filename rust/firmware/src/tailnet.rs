//! Tailnet gateway mode (Phase 3, ADR 0002): everything the image adds to run `tdongle_tailnet_runtime` when the stored mode is `tailnet_gateway`.
//!
//! The runtime owns the protocol; this file owns the hardware seam (`tdongle_tailnet_fw`): the platform, NVS storage, the NCM data interface as Ethernet frames,
//! the Wi-Fi data path as an `embassy-net` driver (over `l2`, the C's `esp_wifi_internal_*` path, not esp-radio's token API), the SNTP wall clock, the heap probe
//! admission reads, the serial and LCD hooks. `main.rs` carries only small hooks into this module (each marked `tailnet::`), so the rest of the image is the bridge
//! image unchanged.
//!
//! # Threading
//!
//! Every task that touches [`Shared`] runs in the **thread executor**: the runtime, the settings worker, the serial worker ([`console`]) and the LCD task. The
//! console and the USB device run in the interrupt-mode executor and reach the gateway only through channels, so the shared state needs no interrupt-masking
//! lock. [`TaskLock`] is that lock: it never masks interrupts (an engine call is a WireGuard handshake, tens of milliseconds) and **panics** if it is ever
//! contended, which can only happen if a second executor (or an interrupt) used the shared state, a bug the guard's panic record then names.
//!
//! # Memory
//!
//! The runtime's big state is on the heap, and only when tailnet mode starts ([`SHARED_INIT`] copied from flash, the receive ring); the NAT, the mux, the stack's
//! socket table and the tasks' futures are statics; the socket windows, TLS records and the control workspace come from the pool while they are used.
//! `tn-mem` on the console prints the linker's view (`.data`, `.bss`, the stack) and the heap.

use alloc::string::String;
use core::cell::RefCell;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use embassy_executor::Spawner;
use embassy_net::{Config as NetConfig, Runner, Stack, StackResources};
use embassy_net_driver::{Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, RawMutex};
use embassy_sync::channel::Channel;
use embassy_sync::once_lock::OnceLock;
use embassy_sync::signal::Signal;
use embassy_sync::waitqueue::AtomicWaker;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use static_cell::{ConstStaticCell, StaticCell};
use tdongle_bridge::{Env, RingSend};
use tdongle_tailnet_engine::RamDirectory;
use tdongle_tailnet_fw::{HeapProbe, MemberCounts, Platform, Storage, StorageError, TailnetApi, UsbFrames};
use tdongle_tailnet_runtime::net_embassy::{EmbassyNet, LinkGen, Windows};
use tdongle_tailnet_admission::heap::{ML_HB_FLOOR, hb_ok};
use tdongle_tailnet_sockmem::HeapSockMem;
use tdongle_tailnet_runtime::shared::{Config as RtConfig, MAX_RUN, PlatformRng, SlotState};
use tdongle_tailnet_runtime::wifi_mux::MuxWifi;
use tdongle_tailnet_runtime::control::control_slot;
use tdongle_tailnet_runtime::net::Net;
use tdongle_tailnet_runtime::derp::{derp_extra, derp_slot};
use tdongle_tailnet_runtime::members::supervisor;
use tdongle_tailnet_runtime::sizes::{FUT_CONTROL, FUT_DERP, FUT_DNS, FUT_LINK, FUT_SUPERVISOR, FUT_TIMER, FUT_UDP, FUT_USB};
use tdongle_tailnet_runtime::tasks::{dns_upstream, engine_timer, link_watch};
use tdongle_tailnet_runtime::udp::udp_slot;
use tdongle_tailnet_runtime::usb::usb_pump;
use tdongle_tailnet_runtime::Shared;
use tdongle_tailnet_usbnet::napt::NaptConfig;
use tdongle_tailnet_wifimux::tap::{NaptTap, SharedNapt};
use tdongle_tailnet_wifimux::{StackDriver, WifiMux};

use crate::{ALT, CONFIGURED, CONNECTS, FIRMWARE, FwEnv, USB_GEN};

/// Memberships that can run at once in this build (the `members-N` features).
pub const MEMBERS: usize = MAX_RUN;
/// NAT flows (the C's `IP_NAPT_MAX` is 512; see the memory notes in the report).
pub const NAPT_FLOWS: usize = 512;
/// Mux queue slots (1,500 bytes each): towards the radio (NAT traffic) and towards the USB host.
pub const MUX_TXQ: usize = 4;
/// See [`MUX_TXQ`].
pub const MUX_RXQ: usize = 4;
/// Frames the radio's receive callback can hold for the stack (the mux pulls up to `RX_BURST` = 8 per poll; more than that so one pull never empties it).
pub const RX_RING: usize = 32;
/// Bytes of received frames the radio callback may hold in the ring whatever the elastic floor says (ADR 0022 exception: the receive ring is the driver's own
/// buffering, which the C pins under no floor either). Bounded: a flood costs at most this much of the floor, for the milliseconds a frame waits. Above it,
/// frames need the heap above the floor like every other consumer. 16 KB is ten full frames, held only for the milliseconds before the stack takes them.
pub const RX_RESERVE: usize = 14 * 1024;
/// Bytes of frames now in the ring.
static RX_BYTES: AtomicU32 = AtomicU32::new(0);
/// The most bytes the radio's receive ring held, and the minimum free heap while no control workspace was held.
static RX_BYTES_PEAK: AtomicU32 = AtomicU32::new(0);
static HEAP_MIN_NO_NEG: AtomicU32 = AtomicU32::new(u32::MAX);
/// Ethernet frames the USB side can hold between the NCM receiver task and the runtime (backpressure beyond that: the OUT endpoint is not re-armed).
pub const USB_RX_FRAMES: usize = 2;
/// Peer records per membership of the in-RAM directory (the C keeps the directory in flash; see the report).
pub const DIR_PEERS: usize = 24;
/// Staged directory updates per membership.
pub const DIR_STAGED: usize = 32;
/// Sockets of the embassy-net stack: 3 per membership (control, DERP, UDP) + the DNS forwarder + SNTP + DHCP + the DNS client + one for the lookup in flight (the dials and SNTP take turns on it) + 1 spare.
const STACK_SOCKETS: usize = 3 * MEMBERS + 6;

/// The stack's interrupt-free lock (see the module docs).
#[derive(Debug)]
pub struct TaskLock(core::sync::atomic::AtomicBool);

// SAFETY: `lock` is a try-acquire that panics on contention, so the closure never runs concurrently with another holder; the state is one atomic. All users are
// tasks of the single thread executor, which never preempts one another between `.await`s (the closure never awaits).
unsafe impl RawMutex for TaskLock {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: Self = TaskLock(AtomicBool::new(false));
    fn lock<R>(&self, f: impl FnOnce() -> R) -> R {
        if self.0.swap(true, Ordering::Acquire) {
            panic!("tailnet lock contended");
        }
        struct Release<'a>(&'a AtomicBool);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _release = Release(&self.0);
        f()
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// The DRAM budget
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/// What the image's DRAM is divided into, and the inequalities that must hold (each a build error, like the C's `_Static_assert`s on the heap budget).
pub mod budget {
    use super::{Sh, TAILNET_HEAP_BYTES};
    use tdongle_tailnet_admission::heap::ML_HB_FLOOR;

    /// All of dram2, given to the heap (the bridge image uses 64 KB of it).
    pub const HEAP_RECLAIMED: usize = 73_728;
    /// The data cache the build gives back (`ESP_HAL_CONFIG_DATA_CACHE_SIZE=32KB`: `0x3FCF0000..0x3FCF8000`); without that setting the section does not fit and the link fails.
    pub const HEAP_DCACHE: usize = 32 * 1024;
    /// The regular region: DRAM is 341,760 bytes (`0x3FC88000..0x3FCDB700`); 42,860 of it is the IRAM overlap (`.rwdata_dummy`: the Wi-Fi blobs' IRAM code and the
    /// vectors), the statics are measured by the linker (`tn-mem` prints them), and the stack gets what this leaves: the link asserts at least 40 KB.
    pub const HEAP_REGULAR: usize = 137 * 1024;
    /// Heap in all.
    pub const HEAP_TOTAL: usize = HEAP_RECLAIMED + HEAP_DCACHE + HEAP_REGULAR;
    /// What the Wi-Fi driver, the USB device and the settings keep on the heap besides the ring's permanent slots: 48 KB from the bridge's board run (heap minimum
    /// 102 KB of 192 KB with the ring grown to its 42 KB maximum, which includes the permanent slots), plus 12 KB of margin (a 62 KB try measured heap_min 29,284 B, 600 B under the floor, with the UDP receive ring at 9,600 B; the 4 KB came back from the NAT table: 384 flows, 4.8 KB less static, given to the regular heap). `tn_in heap_min_over_floor` on the board settles it.
    pub const WIFI_AND_USB: usize = 64 * 1024;
    /// The bridge's permanent ring slots (8 x 1,514 + header), allocated at boot.
    pub const RING_BASE: usize = 8 * 1_536;

    const _: () = assert!(
        HEAP_TOTAL >= WIFI_AND_USB + RING_BASE + TAILNET_HEAP_BYTES + ML_HB_FLOOR,
        "the heap cannot hold the Wi-Fi driver, the USB side, tailnet mode's own state and the elastic floor (ADR 0022)"
    );
    const _: () = assert!(core::mem::size_of::<Sh>() < HEAP_REGULAR, "the shared state is one block and only the regular region can hold it");
    /// The heap's share of the total that is left for the tailnet's own steady use, for `tn-mem`.
    pub const HEADROOM: usize = HEAP_TOTAL - (WIFI_AND_USB + RING_BASE + TAILNET_HEAP_BYTES + ML_HB_FLOOR);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/// Unix seconds at boot (`unix - uptime_s` when SNTP last answered), 0 = never set.
static CLOCK_BASE: AtomicU32 = AtomicU32::new(0);
/// Lowest free heap seen by the probe.
static HEAP_MIN: AtomicU32 = AtomicU32::new(u32::MAX);
/// The last largest-block measurement and when it was taken (ms).
static LARGEST: AtomicU32 = AtomicU32::new(0);
static LARGEST_AT: AtomicU32 = AtomicU32::new(0);

/// The heap as admission reads it: the `esp-alloc` regions (all internal RAM on this board).
#[derive(Debug)]
pub struct FwHeap;

/// Largest single allocation the heap can serve right now, by trial (binary search over `try_reserve_exact`: a block is taken and given straight back). Cached for
/// a second: the engine reads it with every input.
fn probe_largest(free: usize) -> usize {
    let (mut lo, mut hi) = (0usize, free);
    while hi - lo > 256 {
        let mid = lo + (hi - lo) / 2;
        let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        if v.try_reserve_exact(mid).is_ok() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

impl HeapProbe for FwHeap {
    fn free(&self) -> usize {
        let f = esp_alloc::HEAP.free();
        HEAP_MIN.fetch_min(f as u32, Ordering::Relaxed);
        // the margin the elastic consumers really have: the minimum while no control workspace is held (that one is allowed below the floor)
        if tdongle_tailnet_runtime::shared::NEG_HOLDERS.load(Ordering::Relaxed) == 0 {
            HEAP_MIN_NO_NEG.fetch_min(f as u32, Ordering::Relaxed);
        }
        f
    }
    fn largest_block(&self) -> usize {
        let now = Instant::now().as_millis() as u32;
        let at = LARGEST_AT.load(Ordering::Relaxed);
        if at != 0 && now.wrapping_sub(at) < 1000 {
            return LARGEST.load(Ordering::Relaxed) as usize;
        }
        let l = probe_largest(esp_alloc::HEAP.free());
        LARGEST.store(l as u32, Ordering::Relaxed);
        LARGEST_AT.store(now | 1, Ordering::Relaxed);
        l
    }
    fn minimum_free(&self) -> usize {
        HEAP_MIN.load(Ordering::Relaxed) as usize
    }
}

/// One serial line the runtime wants on the console (the Android app parses the `tailnet` / `route` lines).
type Line = heapless_line::Line;
mod heapless_line {
    /// A console line of up to 240 bytes.
    #[derive(Clone, Copy)]
    pub struct Line {
        pub len: u8,
        pub data: [u8; 240],
    }
}
static LINES: Channel<CriticalSectionRawMutex, Line, 4> = Channel::new();

/// What the image can tell the runtime about the board.
#[derive(Debug)]
pub struct FwPlatform;

impl Platform for FwPlatform {
    fn now_ms(&self) -> u64 {
        Instant::now().as_millis()
    }
    fn unix_seconds(&self) -> Option<u64> {
        let base = CLOCK_BASE.load(Ordering::Relaxed);
        (base != 0).then(|| u64::from(base) + Instant::now().as_secs())
    }
    fn fill_random(&self, buf: &mut [u8]) {
        esp_hal::rng::Rng::new().read(buf);
    }
    fn sta_mac(&self) -> [u8; 6] {
        esp_hal::efuse::base_mac_address().as_bytes().try_into().unwrap_or([0; 6])
    }
    fn heap(&self) -> &dyn HeapProbe {
        &FwHeap
    }
    fn console_line(&self, line: &str) {
        let b = line.as_bytes();
        let n = b.len().min(240);
        let mut l = Line { len: n as u8, data: [0; 240] };
        l.data[..n].copy_from_slice(&b[..n]);
        let _ = LINES.try_send(l); // a full queue drops the line: the console is a convenience, never a reason to wait
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// Storage: the NVS store of `settings.rs`
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/// The `tn_settings/members` string and the per-membership blobs, over the same mounted store the settings commands use.
#[derive(Debug)]
pub struct FwStorage;

fn is_string_key(key: &str) -> bool {
    key == "members"
}

impl Storage for FwStorage {
    fn get(&mut self, namespace: &str, key: &str, out: &mut [u8]) -> Result<usize, StorageError> {
        let mut g = crate::settings::STORE.try_lock().map_err(|_| StorageError::Failed)?;
        let store = g.as_mut().ok_or(StorageError::Failed)?;
        let r = if is_string_key(key) { store.nvs().get_str(namespace, key, out) } else { store.nvs().get_blob(namespace, key, out) };
        match r {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Err(StorageError::NotFound),
            Err(tdongle_nvs_write::Error::TooSmall) => Err(StorageError::TooSmall),
            Err(_) => Err(StorageError::Failed),
        }
    }
    fn set(&mut self, namespace: &str, key: &str, data: &[u8]) -> Result<(), StorageError> {
        let mut g = crate::settings::STORE.try_lock().map_err(|_| StorageError::Failed)?;
        let store = g.as_mut().ok_or(StorageError::Failed)?;
        crate::guard::op("nvs_write");
        let r = if is_string_key(key) {
            match core::str::from_utf8(data) {
                Ok(s) => store.nvs().set_str(namespace, key, s),
                Err(_) => return Err(StorageError::Failed),
            }
        } else {
            store.nvs().set_blob(namespace, key, data)
        };
        crate::guard::op("");
        if r.is_err() {
            let _ = store.remount();
            return Err(StorageError::Failed);
        }
        Ok(())
    }
    fn erase_namespace(&mut self, namespace: &str) -> Result<(), StorageError> {
        let mut g = crate::settings::STORE.try_lock().map_err(|_| StorageError::Failed)?;
        let store = g.as_mut().ok_or(StorageError::Failed)?;
        crate::guard::op("nvs_erase");
        let r = store.nvs().erase_namespace(namespace);
        crate::guard::op("");
        if r.is_err() {
            let _ = store.remount();
            return Err(StorageError::Failed);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// USB frames (the NCM data interface)
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/// Frames from the host waiting for the runtime: each a heap block of its own length, taken above the elastic floor ("USB receive frames", ADR 0022). Full or
/// short of heap, [`usb_rx`] waits, which leaves the OUT endpoint un-armed: the host's driver sees NAKs.
static USB_RX: Channel<CriticalSectionRawMutex, alloc::vec::Vec<u8>, USB_RX_FRAMES> = Channel::new();
static CARRIER: AtomicBool = AtomicBool::new(false);

/// Called by the NCM receiver task for every datagram while tailnet mode owns the data path: hand it to the runtime, waiting (and so not re-arming the OUT
/// endpoint: the host's driver sees NAKs) while the runtime cannot take it. `false`: the host left the data interface while we waited.
pub async fn usb_rx(datagram: &[u8]) -> bool {
    crate::pm::note_activity(); // the tunnel's encrypt runs next: hold the CPU at 240 MHz (the bridge path does the same through `FwEnv`)
    let n = datagram.len().min(crate::MTU);
    loop {
        if ALT.load(Ordering::Relaxed) == 0 {
            return false;
        }
        let mut block: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let heap_ok = hb_ok(FwHeap.free(), n + 16) && block.try_reserve_exact(n).is_ok();
        if heap_ok {
            block.extend_from_slice(&datagram[..n]);
            match USB_RX.try_send(block) {
                Ok(()) => return true,
                Err(embassy_sync::channel::TrySendError::Full(_)) => {}
            }
        } else {
            USB_RX_WAITS.fetch_add(1, Ordering::Relaxed);
        }
        // short of heap the channel has room, so waiting on it returns at once: a bounded sleep instead (see `wait_for_frame_room`)
        tdongle_tailnet_runtime::usb::wait_for_frame_room(heap_ok, core::future::poll_fn(|cx| USB_RX.poll_ready_to_send(cx))).await;
    }
}

/// Frames for the USB-side stack ([`usb_stack`]), and its waker.
static LOCAL_RX: Channel<CriticalSectionRawMutex, alloc::vec::Vec<u8>, 4> = Channel::new();
static LOCAL_WAKER: AtomicWaker = AtomicWaker::new();

/// The USB netif's own TCP stack: embassy-net over the NCM data interface at 192.168.77.1/24, serving `GET /status` (the JSON the Android app reads) as the C does in
/// tailnet mode. It sees only what the runtime hands it ([`UsbFrames::local_frame`]: ARP replies and TCP to the dongle); everything else on that interface is the
/// runtime's. Frames to the host go through the same ring as the runtime's.
#[derive(Debug)]
pub struct UsbStackDriver;

/// A frame for the USB stack.
#[derive(Debug)]
pub struct UsbRx(alloc::vec::Vec<u8>);
/// Permission to send one frame to the host.
#[derive(Debug)]
pub struct UsbTx;

impl RxToken for UsbRx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}

impl TxToken for UsbTx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = [0u8; crate::MTU];
        let n = len.min(crate::MTU);
        let r = f(&mut buf[..n]);
        let _ = FwEnv.usb_ring_send(&buf[..n]);
        r
    }
}

impl Driver for UsbStackDriver {
    type RxToken<'a> = UsbRx;
    type TxToken<'a> = UsbTx;
    fn receive(&mut self, cx: &mut core::task::Context<'_>) -> Option<(UsbRx, UsbTx)> {
        LOCAL_WAKER.register(cx.waker());
        LOCAL_RX.try_receive().ok().map(|f| (UsbRx(f), UsbTx))
    }
    fn transmit(&mut self, _cx: &mut core::task::Context<'_>) -> Option<UsbTx> {
        Some(UsbTx)
    }
    fn link_state(&mut self, cx: &mut core::task::Context<'_>) -> LinkState {
        LOCAL_WAKER.register(cx.waker());
        if ALT.load(Ordering::Relaxed) != 0 && CONFIGURED.load(Ordering::Relaxed) { LinkState::Up } else { LinkState::Down }
    }
    fn capabilities(&self) -> Capabilities {
        let mut c = Capabilities::default();
        c.max_transmission_unit = crate::MTU;
        c
    }
    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet(tdongle_tailnet_runtime::usb::derive_usb_mac(FwPlatform.sta_mac()))
    }
}

#[embassy_executor::task]
async fn usb_net_task(mut runner: Runner<'static, UsbStackDriver>) -> ! {
    runner.run().await
}

/// The USB side's HTTP server on port 80 (tailnet mode only; nothing of it exists in a setup boot, and the setup access point has no route to it). `tdongle_setup::usb`
/// decides every request (peer and local address, `Host`, `Origin`, method, content type, command allowlist): `GET /` the controller page, `GET /status` the gateway JSON,
/// `POST /serial` one console command, run by the **same dispatcher** as the serial console, answered with its reply bytes unchanged. One connection at a time per task,
/// small windows (heap, once); a request's own buffer is heap that lives only for the request.
#[embassy_executor::task(pool_size = 2)]
async fn http_status_task(stack: Stack<'static>) -> ! {
    use embassy_net::tcp::TcpSocket;
    use tdongle_setup::router::Conn;
    let rx: &'static mut [u8] = alloc::boxed::Box::leak(alloc::vec![0u8; 1024].into_boxed_slice());
    let tx: &'static mut [u8] = alloc::boxed::Box::leak(alloc::vec![0u8; 2048].into_boxed_slice());
    let mut sock = TcpSocket::new(stack, rx, tx);
    sock.set_timeout(Some(Duration::from_secs(10)));
    loop {
        if sock.accept(80).await.is_err() {
            sock.abort();
            Timer::after_millis(50).await;
            continue;
        }
        let v4 = |e: Option<embassy_net::IpEndpoint>| match e?.addr {
            embassy_net::IpAddress::Ipv4(a) => Some(u32::from_be_bytes(a.octets())),
        };
        let conn = Conn { peer: v4(sock.remote_endpoint()), local: v4(sock.local_endpoint()) };
        serve_one(&mut sock, &conn).await;
        sock.close();
        let _ = with_timeout(Duration::from_secs(2), sock.flush()).await;
        sock.abort();
    }
}

/// Serialises `POST /serial`: the console task runs one command at a time and its reply pieces are not tagged.
static SERIAL_CALL: embassy_sync::mutex::Mutex<CriticalSectionRawMutex, ()> = embassy_sync::mutex::Mutex::new(());

async fn send_all(sock: &mut embassy_net::tcp::TcpSocket<'_>, bytes: &[u8]) -> bool {
    use embedded_io_async::Write as _;
    sock.write_all(bytes).await.is_ok()
}

async fn refuse(sock: &mut embassy_net::tcp::TcpSocket<'_>, status: &str, message: &str) {
    use tdongle_setup::usb;
    let mut h = String::new();
    let _ = usb::write_head(&mut h, status, usb::TEXT, Some(message.len() + 1), usb::Kind::Refusal);
    let _ = send_all(sock, h.as_bytes()).await && send_all(sock, message.as_bytes()).await && send_all(sock, b"\n").await;
}

async fn serve_one(sock: &mut embassy_net::tcp::TcpSocket<'_>, conn: &tdongle_setup::router::Conn) {
    use tdongle_setup::usb::{self, Answer, HeadError, Kind};
    // the request (head and body) lives in one heap buffer for the length of the request
    const BUF: usize = usb::HEAD_MAX + usb::BODY_MAX;
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    if buf.try_reserve_exact(BUF).is_err() {
        refuse(sock, "503 Service Unavailable", "Out of memory").await;
        return;
    }
    buf.resize(BUF, 0);
    let mut n = 0;
    let (head_len, ready) = loop {
        match usb::parse_head(&buf[..n]).map(|(h, used)| (used, h.content_len.unwrap_or(0).min(usb::BODY_MAX))) {
            Ok((used, body)) if n >= used + body => break (used, true),
            Ok(_) | Err(HeadError::Incomplete) => {}
            Err(HeadError::TooLarge) => return refuse(sock, "431 Request Header Fields Too Large", "Header fields are too long").await,
            Err(HeadError::Bad) => return refuse(sock, "400 Bad Request", "Bad request").await,
        }
        if n == buf.len() {
            break (0, false);
        }
        match with_timeout(Duration::from_secs(3), sock.read(&mut buf[n..])).await {
            Ok(Ok(k)) if k > 0 => n += k,
            _ => break (0, false), // closed or too slow: nothing to answer
        }
    };
    if !ready {
        return;
    }
    let Ok((head, _)) = usb::parse_head(&buf[..n]) else { return };
    enum Job {
        Page,
        Status,
        Serial(String),
    }
    let job = match usb::route(conn, &head, &buf[head_len..n]) {
        Answer::Refuse(r) => return refuse(sock, r.status, r.message).await,
        Answer::Page => Job::Page,
        Answer::Status => Job::Status,
        Answer::Serial(line) => Job::Serial(String::from(line)),
    };
    drop(buf); // the buffer (and the auth key or Wi-Fi password in it) is not kept while the reply is produced
    let mut h = String::new();
    let ok = match job {
        Job::Page => {
            let _ = usb::write_head(&mut h, "200 OK", "text/html; charset=utf-8", Some(usb::PAGE.len()), Kind::Page);
            send_all(sock, h.as_bytes()).await && send_all(sock, usb::PAGE).await
        }
        Job::Status => {
            let mut body = alloc::vec::Vec::new();
            let status = match api() {
                Some(api) => {
                    let mut sink = |chunk: &[u8]| body.try_reserve(chunk.len()).is_ok() && {
                        body.extend_from_slice(chunk);
                        true
                    };
                    let _ = api.render_status(&mut sink);
                    "200 OK"
                }
                None => "503 Service Unavailable",
            };
            let _ = usb::write_head(&mut h, status, usb::JSON, Some(body.len()), Kind::Text);
            send_all(sock, h.as_bytes()).await && send_all(sock, &body).await
        }
        Job::Serial(line) => serial_call(sock, line).await,
    };
    HTTP_SERVED.fetch_add(u32::from(ok), Ordering::Relaxed);
    let _ = sock.flush().await;
}

/// `POST /serial`: hand the line to the console task and stream what its dispatcher emits. A command that restarts the chip emits its answer, waits 300 ms and resets: the
/// answer is on the wire by then and the connection ends with the reset (the page treats that as success for those commands).
async fn serial_call(sock: &mut embassy_net::tcp::TcpSocket<'_>, line: String) -> bool {
    use tdongle_setup::usb::{self, Kind};
    let Ok(_one) = with_timeout(Duration::from_secs(30), SERIAL_CALL.lock()).await else {
        refuse(sock, "503 Service Unavailable", "Busy").await;
        return false;
    };
    while crate::HTTP_OUT.try_receive().is_ok() {} // stale pieces of an abandoned call
    if with_timeout(Duration::from_secs(3), crate::HTTP_LINE.send(line)).await.is_err() {
        refuse(sock, "503 Service Unavailable", "Console busy").await;
        return false;
    }
    let mut started = false;
    let mut wait = Duration::from_secs(25); // `scan` is the slowest command
    loop {
        let Ok(piece) = with_timeout(wait, crate::HTTP_OUT.receive()).await else {
            if !started {
                refuse(sock, "504 Gateway Timeout", "ERR The dongle did not answer").await;
            }
            return started;
        };
        if piece.is_empty() {
            return true;
        }
        if !started {
            started = true;
            let mut h = String::new();
            let _ = usb::write_head(&mut h, "200 OK", usb::TEXT, None, Kind::Text);
            if !send_all(sock, h.as_bytes()).await {
                return false;
            }
        }
        if !send_all(sock, piece.as_bytes()).await {
            return false;
        }
        wait = Duration::from_millis(1500);
    }
}

/// `/status` answers sent.
pub static HTTP_SERVED: AtomicU32 = AtomicU32::new(0);

/// Times a host frame had to wait for heap above the floor.
pub static USB_RX_WAITS: AtomicU32 = AtomicU32::new(0);

/// The runtime's USB side. Frames to the host go through the bridge's Wi-Fi to host ring (`usb_tx_task` drains it into NTBs), frames from it come from [`usb_rx`].
#[derive(Debug)]
pub struct FwUsb;

impl UsbFrames for FwUsb {
    async fn recv(&mut self, buf: &mut [u8]) -> usize {
        let f = USB_RX.receive().await;
        let n = f.len().min(buf.len());
        buf[..n].copy_from_slice(&f[..n]);
        n
    }
    fn send(&mut self, frame: &[u8]) -> bool {
        crate::pm::note_activity();
        FwEnv.usb_ring_send(frame) == RingSend::Accepted
    }
    fn host_ready(&self) -> bool {
        ALT.load(Ordering::Relaxed) != 0 && CONFIGURED.load(Ordering::Relaxed)
    }
    fn link_generation(&self) -> u32 {
        USB_GEN.load(Ordering::Relaxed)
    }
    fn local_frame(&mut self, frame: &[u8]) {
        // an ARP reply or TCP to 192.168.77.1: the USB-side stack (the `/status` page) takes it; full or short of heap, it is dropped (TCP retransmits)
        let mut block: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        if hb_ok(FwHeap.free(), frame.len() + 16) && block.try_reserve_exact(frame.len()).is_ok() {
            block.extend_from_slice(frame);
            if LOCAL_RX.try_send(block).is_ok() {
                LOCAL_WAKER.wake();
            }
        }
    }
    fn set_carrier(&mut self, up: bool) {
        // Deviation shared with bridge mode: no NETWORK_CONNECTION notification on a carrier change (the NCM receiver sends it once when the host selects alt 1).
        CARRIER.store(up, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// Wi-Fi data path: an embassy-net driver over `l2`
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/// The tailnet runtime owns the radio's receive callback (`l2::rx_cb` hands it every frame).
static RX_ON: AtomicBool = AtomicBool::new(false);
static LINK_UP: AtomicBool = AtomicBool::new(false);
static RX_WAKER: AtomicWaker = AtomicWaker::new();
static TX_WAKER: AtomicWaker = AtomicWaker::new();
static LINK_WAKER: AtomicWaker = AtomicWaker::new();
/// Frames the callback dropped because the ring was full, and frames the stack's transmit refused (budget or driver).
pub static RX_DROPPED: AtomicU32 = AtomicU32::new(0);
/// See [`RX_DROPPED`].
pub static TX_REFUSED: AtomicU32 = AtomicU32::new(0);
/// Frames handed to the stack.
pub static RX_FRAMES: AtomicU32 = AtomicU32::new(0);

/// The radio's received frames waiting for the stack: each is a heap block of exactly its length (an ACK is 66 bytes, not 1,514), taken only above the elastic
/// floor like every consumer of ADR 0022 (the C pins the driver's buffer in a pbuf under the same budget). The ring itself is ten words.
struct RxRing {
    slots: [Option<alloc::vec::Vec<u8>>; RX_RING],
    head: usize,
    count: usize,
}
impl RxRing {
    const EMPTY: RxRing = RxRing { slots: [const { None }; RX_RING], head: 0, count: 0 };
}
/// The receive ring exists only in tailnet mode (`start` fills it before the callback is enabled).
static RING: critical_section::Mutex<RefCell<Option<alloc::boxed::Box<RxRing>>>> = critical_section::Mutex::new(RefCell::new(None));
/// Frames the callback refused because the free heap was at the elastic floor (or the allocator had no block).
pub static RX_HEAP_REFUSED: AtomicU32 = AtomicU32::new(0);

/// DHCP and ARP frames seen on the station interface, each way (the `tn_sta` line): the first thing to read when the station has no address.
static DHCP_RX: AtomicU32 = AtomicU32::new(0);
static DHCP_TX: AtomicU32 = AtomicU32::new(0);
static ARP_RX: AtomicU32 = AtomicU32::new(0);
static ARP_TX: AtomicU32 = AtomicU32::new(0);
/// UDP frames by well-known port seen at the driver, each way: DNS (53) and NTP (123), and the driver's polls (`tn_dns` line).
static DNS_FRAMES: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4]; // dns tx, dns rx, ntp tx, ntp rx
/// The first 48 bytes of the last DNS query frame the stack sent (Ethernet header, IP header, UDP header: addresses, ports, checksum), for comparing with a capture.
static LAST_DNS_TX: critical_section::Mutex<RefCell<[u8; 48]>> = critical_section::Mutex::new(RefCell::new([0; 48]));
/// The resolver candidates for `tn_dns`: `addr:answers/timeouts`, a star on the one that answered last.
fn resolver_list() -> String {
    let mut s = String::new();
    tdongle_tailnet_runtime::resolver::RESOLVERS.snapshot(|_, a, ok, fail, last| {
        let o = a.to_be_bytes();
        let _ = write!(s, "{}.{}.{}.{}:{}/{}{} ", o[0], o[1], o[2], o[3], ok, fail, if last { "*" } else { "" });
    });
    s
}
fn last_dns_tx_hex() -> String {
    let h = critical_section::with(|cs| *LAST_DNS_TX.borrow_ref(cs));
    let mut s = String::new();
    for b in h {
        let _ = write!(s, "{b:02x}");
    }
    s
}
static DRV_TX_POLLS: AtomicU32 = AtomicU32::new(0);
static DRV_TX_NOROOM: AtomicU32 = AtomicU32::new(0);
static DRV_RX_POLLS: AtomicU32 = AtomicU32::new(0);
/// DNS lookups of the SNTP task: started, answered with an address, answered empty or with an error, no answer in 5 s.
static SNTP_DNS: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
/// The stack handle for the diagnostics. `Stack` is not `Sync` (it is a reference to a `RefCell`); it is only ever used from the thread executor (the stack's runner and the
/// console worker are both tasks of it), which is why the wrapper may be shared.
struct ThreadOnly<T>(T);
// SAFETY: see above; the value is only touched by tasks of the single thread executor, which never run concurrently.
unsafe impl<T> Sync for ThreadOnly<T> {}
static STACK_REF: OnceLock<ThreadOnly<Stack<'static>>> = OnceLock::new();
static DIAG_PORT: OnceLock<tdongle_tailnet_wifimux::RawPort<'static, MUX_TXQ, MUX_RXQ>> = OnceLock::new();

/// Count an Ethernet frame as ARP or DHCP (BOOTP ports 67 and 68) for the `tn_sta` line.
fn note_frame(frame: &[u8], rx: bool) {
    if frame.len() < 14 {
        return;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0806 => {
            (if rx { &ARP_RX } else { &ARP_TX }).fetch_add(1, Ordering::Relaxed);
        }
        0x0800 if frame.len() >= 38 && frame[23] == 17 => {
            let ihl = usize::from(frame[14] & 15) * 4;
            if frame.len() >= 14 + ihl + 4 {
                let (sp, dp) = (u16::from_be_bytes([frame[14 + ihl], frame[15 + ihl]]), u16::from_be_bytes([frame[16 + ihl], frame[17 + ihl]]));
                if (sp == 67 && dp == 68) || (sp == 68 && dp == 67) {
                    (if rx { &DHCP_RX } else { &DHCP_TX }).fetch_add(1, Ordering::Relaxed);
                }
                // a request leaves for port 53 / 123, an answer arrives from it
                let (want, i) = if rx { (sp, 1) } else { (dp, 0) };
                if want == 53 {
                    DNS_FRAMES[i].fetch_add(1, Ordering::Relaxed);
                    if !rx {
                        critical_section::with(|cs| {
                            let mut h = LAST_DNS_TX.borrow_ref_mut(cs);
                            let n = frame.len().min(h.len());
                            h[..n].copy_from_slice(&frame[..n]);
                        });
                    }
                } else if want == 123 {
                    DNS_FRAMES[i + 2].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        _ => {}
    }
}

/// The radio's receive callback (Wi-Fi task): copy the frame and return. `true`: tailnet mode took it (the bridge must not see it).
pub fn wifi_rx(frame: &[u8]) -> bool {
    if !RX_ON.load(Ordering::Acquire) {
        return false;
    }
    if frame.len() > crate::MTU {
        RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    note_frame(frame, true);
    // admitted like an elastic consumer (the frame and its allocator header must leave the floor free), then copied into a block of its own length
    let mut block: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let within_reserve = RX_BYTES.load(Ordering::Relaxed) as usize + frame.len() <= RX_RESERVE;
    if !(within_reserve || hb_ok(FwHeap.free(), frame.len() + 16)) || block.try_reserve_exact(frame.len()).is_err() {
        RX_HEAP_REFUSED.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    block.extend_from_slice(frame);
    let pushed = critical_section::with(|cs| {
        let mut guard = RING.borrow_ref_mut(cs);
        let Some(r) = guard.as_mut() else { return Err(block) };
        if r.count == RX_RING {
            return Err(block);
        }
        let at = (r.head + r.count) % RX_RING;
        let now_bytes = RX_BYTES.fetch_add(block.len() as u32, Ordering::Relaxed) + block.len() as u32;
        RX_BYTES_PEAK.fetch_max(now_bytes, Ordering::Relaxed);
        r.slots[at] = Some(block);
        r.count += 1;
        Ok(())
    });
    match pushed {
        Ok(()) => RX_WAKER.wake(),
        Err(block) => {
            // dropped outside the critical section (the free takes the allocator's lock)
            drop(block);
            RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
    true
}

fn pop_rx(out: &mut [u8; crate::MTU]) -> Option<usize> {
    let block = critical_section::with(|cs| {
        let mut guard = RING.borrow_ref_mut(cs);
        let r = guard.as_mut()?;
        if r.count == 0 {
            return None;
        }
        let h = r.head;
        r.head = (h + 1) % RX_RING;
        r.count -= 1;
        r.slots[h].take()
    })?;
    let n = block.len().min(out.len());
    out[..n].copy_from_slice(&block[..n]);
    RX_BYTES.fetch_sub(block.len() as u32, Ordering::Relaxed);
    Some(n)
}

/// The station as an Ethernet `embassy-net` driver. Receive does not need a TX credit (the S1 wedge of esp-radio's tokens): a reply the budget refuses is a
/// counted drop, which TCP retransmits.
#[derive(Debug)]
pub struct L2Driver;

/// The station's address, set by `start` before the stack is built (the mux and the driver are statics built at compile time, which cannot know it).
static STA_MAC: critical_section::Mutex<core::cell::Cell<[u8; 6]>> = critical_section::Mutex::new(core::cell::Cell::new([0; 6]));

/// A received frame.
#[derive(Debug)]
pub struct L2Rx {
    buf: [u8; crate::MTU],
    len: usize,
}
/// Permission to send one frame.
#[derive(Debug)]
pub struct L2Tx;

impl RxToken for L2Rx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.buf[..self.len])
    }
}

impl TxToken for L2Tx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = [0u8; crate::MTU];
        let n = len.min(crate::MTU);
        let r = f(&mut buf[..n]);
        note_frame(&buf[..n], false);
        if crate::l2::tx(&buf[..n]).is_err() {
            TX_REFUSED.fetch_add(1, Ordering::Relaxed);
        }
        r
    }
}

impl Driver for L2Driver {
    type RxToken<'a> = L2Rx;
    type TxToken<'a> = L2Tx;

    fn receive(&mut self, cx: &mut core::task::Context<'_>) -> Option<(L2Rx, L2Tx)> {
        RX_WAKER.register(cx.waker());
        DRV_RX_POLLS.fetch_add(1, Ordering::Relaxed);
        let mut buf = [0u8; crate::MTU];
        let len = pop_rx(&mut buf)?;
        crate::pm::note_activity(); // decrypt and routing follow
        RX_FRAMES.fetch_add(1, Ordering::Relaxed);
        Some((L2Rx { buf, len }, L2Tx))
    }
    fn transmit(&mut self, cx: &mut core::task::Context<'_>) -> Option<L2Tx> {
        TX_WAKER.register(cx.waker());
        DRV_TX_POLLS.fetch_add(1, Ordering::Relaxed);
        let room = crate::l2::room();
        if !room {
            DRV_TX_NOROOM.fetch_add(1, Ordering::Relaxed);
        }
        room.then_some(L2Tx)
    }
    fn link_state(&mut self, cx: &mut core::task::Context<'_>) -> LinkState {
        LINK_WAKER.register(cx.waker());
        if LINK_UP.load(Ordering::Acquire) { LinkState::Up } else { LinkState::Down }
    }
    fn capabilities(&self) -> Capabilities {
        let mut c = Capabilities::default();
        c.max_transmission_unit = crate::MTU;
        c
    }
    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet(critical_section::with(|cs| STA_MAC.borrow(cs).get()))
    }
}

/// The association generation the runtime restarts its sockets on: every successful join of the link task.
#[derive(Debug)]
struct Association;
impl LinkGen for Association {
    fn generation(&self) -> u32 {
        CONNECTS.load(Ordering::Relaxed)
    }
}
static ASSOCIATION: Association = Association;

/// The link task's hook (replaces `bridge.link`): the radio is associated (`true`) or not.
pub fn link(up: bool) {
    LINK_UP.store(up, Ordering::Release);
    LINK_WAKER.wake();
    if up {
        RX_WAKER.wake();
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// The statics and the types they have
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

type Dir = RamDirectory<MEMBERS, DIR_PEERS, DIR_STAGED>;
/// The shared state of the runtime.
pub type Sh = Shared<TaskLock, FwPlatform, FwStorage, Dir>;
type Tap = NaptTap<'static, NAPT_FLOWS>;
type Mux = WifiMux<L2Driver, Tap, MUX_TXQ, MUX_RXQ>;
type MuxDrv = StackDriver<'static, L2Driver, Tap, MUX_TXQ, MUX_RXQ>;
type Wifi = MuxWifi<'static, Stack<'static>, NAPT_FLOWS, MUX_TXQ, MUX_RXQ>;

/// The runtime's shared state, evaluated at compile time (every constructor under it is `const`), so there is no 88 KB value on any stack: `start` copies the
/// constant from flash into a heap block, and only when tailnet mode actually starts (a bridge-mode boot of this image keeps the 88 KB for the ring).
#[allow(clippy::declare_interior_mutable_const)]
const SHARED_INIT: Sh = Shared::new(RtConfig { firmware: FIRMWARE, ..RtConfig::tailscale() }, FwPlatform, FwStorage, Dir::new());
static NET: StaticCell<EmbassyNet> = StaticCell::new();
static WIFI: StaticCell<Wifi> = StaticCell::new();
static SOCKMEM: StaticCell<HeapSockMem> = StaticCell::new();
static STACK_RES: ConstStaticCell<StackResources<STACK_SOCKETS>> = ConstStaticCell::new(StackResources::new());
/// The NAT and the Wi-Fi mux are built at compile time like the shared state (19 KB and 14 KB values that never exist on a stack); `start` seeds the NAT and
/// gives the mux its station address.
static NAPT: SharedNapt<NAPT_FLOWS> = SharedNapt::new_const(NaptConfig::C);
static MUX: ConstStaticCell<Mux> = ConstStaticCell::new(WifiMux::new_const(L2Driver, NaptTap::new(&NAPT)));
static SNTP_BUFS: ConstStaticCell<SntpBufs> = ConstStaticCell::new(SntpBufs::new());
static SHARED_REF: OnceLock<&'static Sh> = OnceLock::new();

/// Tailnet mode is running (set by [`start`], never cleared).
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Tailnet mode is running in this boot.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// The gateway's API for the setup HTTP server (`add`/`enable`/`disable`/`remove`, `/status`): `None` outside tailnet mode, **and the HTTP server must refuse the
/// member actions on the setup access point itself** (`tdongle_tailnet_members::command::ActionKind::allowed(Origin::SetupAp)`), as the C does.
pub fn api() -> Option<&'static dyn TailnetApi> {
    SHARED_REF.try_get().map(|s| *s as &'static dyn TailnetApi)
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/// Start tailnet mode: the embassy-net stack over the mux over the radio, the runtime, SNTP and the workers. Called by the init task once the radio is up (never
/// from safe mode: the init task returns before that).
pub fn start(spawner: Spawner) -> Result<(), StartError> {
    let platform = FwPlatform;
    // Admission, as the C's `ml_admission` does for a membership: the heap must hold what tailnet mode keeps on it (the shared state, the receive ring, the
    // pool's steady use) and still leave the elastic floor. Refusing here is an answer, a panic in an allocator would be a reboot loop.
    let need = TAILNET_HEAP_BYTES;
    let free = FwHeap.free();
    if free < need + ML_HB_FLOOR {
        START_REFUSED.store(((need + ML_HB_FLOOR - free) as u32).max(1), Ordering::Relaxed);
        return Err(StartError::HeapShort { need: need + ML_HB_FLOOR, free });
    }
    // prove the allocator has the two big blocks (they are freed again at once): `Box::new` below then cannot reach the out-of-memory handler
    for len in [core::mem::size_of::<Sh>(), core::mem::size_of::<RxRing>()] {
        let mut probe: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        if probe.try_reserve_exact(len).is_err() {
            START_REFUSED.store(1, Ordering::Relaxed);
            return Err(StartError::NoBlock { len });
        }
    }
    let sh: &'static Sh = alloc::boxed::Box::leak(alloc::boxed::Box::new(SHARED_INIT));
    critical_section::with(|cs| *RING.borrow_ref_mut(cs) = Some(alloc::boxed::Box::new(RxRing::EMPTY)));
    let _ = SHARED_REF.init(sh);

    let mut rng = PlatformRng(&platform);
    NAPT.seed(&mut rng);
    // the flows take heap as they come, above the elastic floor (a refusal evicts a flow, as a full table does)
    NAPT.with(|n| n.set_grow_guard(|bytes| hb_ok(FwHeap.free(), bytes + 64)));
    let napt: &'static SharedNapt<NAPT_FLOWS> = &NAPT;
    let mux: &'static mut Mux = MUX.take();
    let mac = platform.sta_mac();
    critical_section::with(|cs| STA_MAC.borrow(cs).set(mac));
    mux.set_mac(mac);
    mux.set_heap(&FwHeap); // the NAT queues take their frames from the heap above the elastic floor
    let (driver, port) = mux.split();
    let mut seed = [0u8; 8];
    platform.fill_random(&mut seed);
    let (stack, runner) = embassy_net::new(driver, NetConfig::dhcpv4(Default::default()), STACK_RES.take(), u64::from_le_bytes(seed));
    let _ = DIAG_PORT.init(port);
    let _ = STACK_REF.init(ThreadOnly(stack));
    let wifi: &'static Wifi = WIFI.init_with(|| MuxWifi::new(port, napt, stack));
    // socket windows, TLS records and the control workspace come from the shared pool (the heap, admitted against the elastic floor), not from statics
    let sockmem: &'static HeapSockMem = SOCKMEM.init(HeapSockMem::new(sh.mem()));
    let net: &'static EmbassyNet = NET.init(EmbassyNet::new(stack, &ASSOCIATION, sockmem));
    sh.net_member_bytes.store(net.member_buffer_bytes() as u32, Ordering::Relaxed);

    // the USB netif's own stack (192.168.77.1/24) for the `/status` page; its socket table is one heap block
    {
        let usb_res: &'static mut StackResources<3> = alloc::boxed::Box::leak(alloc::boxed::Box::new(StackResources::new()));
        let usb_cfg = NetConfig::ipv4_static(embassy_net::StaticConfigV4 {
            address: embassy_net::Ipv4Cidr::new(embassy_net::Ipv4Address::new(192, 168, 77, 1), 24),
            gateway: None,
            dns_servers: Default::default(),
        });
        let (usb_stack, usb_runner) = embassy_net::new(UsbStackDriver, usb_cfg, usb_res, u64::from_le_bytes(seed) ^ 0x7573_6200);
        if let Ok(t) = usb_net_task(usb_runner) {
            spawner.spawn(t);
        }
        for _ in 0..2 {
            if let Ok(t) = http_status_task(usb_stack) {
                spawner.spawn(t);
            }
        }
    }
    RX_ON.store(true, Ordering::Release);
    ACTIVE.store(true, Ordering::Release);
    if let Ok(t) = net_task(runner) {
        spawner.spawn(t);
    }
    // The runtime's tasks run as tasks of their own, each future built in place in its own task storage: one joined future would be built on the stack first
    // (a 49 KB frame measured with `tools/check_stack.py`, on top of the 24 KB it then occupies).
    for idx in 0..MEMBERS {
        if let Ok(t) = tn_control(sh, idx, net) {
            spawner.spawn(t);
        }
        if let Ok(t) = tn_derp(sh, idx, net) {
            spawner.spawn(t);
        }
        if let Ok(t) = tn_derp_x(sh, idx, net) {
            spawner.spawn(t);
        }
        if let Ok(t) = tn_udp(sh, idx, net) {
            spawner.spawn(t);
        }
    }
    if let Ok(t) = tn_usb(sh, wifi) {
        spawner.spawn(t);
    }
    if let Ok(t) = tn_supervisor(sh) {
        spawner.spawn(t);
    }
    if let Ok(t) = tn_timer(sh) {
        spawner.spawn(t);
    }
    if let Ok(t) = tn_link(sh, net, wifi) {
        spawner.spawn(t);
    }
    if let Ok(t) = tn_dns(sh, net) {
        spawner.spawn(t);
    }
    if let Ok(t) = sntp_task(stack, SNTP_BUFS.take()) {
        spawner.spawn(t);
    }
    if let Ok(t) = tx_wake_task() {
        spawner.spawn(t);
    }
    if let Ok(t) = console_worker() {
        spawner.spawn(t);
    }
    if let Ok(t) = lines_task() {
        spawner.spawn(t);
    }
    Ok(())
}

/// Why tailnet mode did not start.
#[derive(Clone, Copy, Debug)]
pub enum StartError {
    /// The free heap is below what tailnet mode keeps on it plus the elastic floor.
    HeapShort {
        /// Bytes needed (state, ring, pool steady use, floor).
        need: usize,
        /// Free heap at the time.
        free: usize,
    },
    /// The allocator has no free block of `len` bytes.
    NoBlock {
        /// The block.
        len: usize,
    },
}

/// Non-zero: bytes tailnet mode was short of at its start (0: it started). Shown by `tn-mem`.
pub static START_REFUSED: AtomicU32 = AtomicU32::new(0);

/// What tailnet mode keeps on the heap once it runs, besides the Wi-Fi driver: the shared state, the receive ring, the pool's steady use (one membership's socket
/// windows, the DNS forwarder's rings, a record in flight). The elastic floor comes on top ([`ML_HB_FLOOR`]), and the control workspace of a join is inside it.
pub const TAILNET_HEAP_BYTES: usize = core::mem::size_of::<Sh>()
    + core::mem::size_of::<RxRing>()
    + MEMBERS * Windows::PER_MEMBER
    + Windows::GATEWAY.gateway()
    + POOL_TRANSIENT
    + DIR_LIVE_FULL
    + ELASTIC_TYPICAL;

/// What the pool holds besides windows while a membership runs: the DERP relay's write record and staging frame (3,584 per membership) and a TLS record or a control
/// workspace in flight (the workspace is inside the floor).
pub const POOL_TRANSIENT: usize = MEMBERS * 3_584 + 4_096 + USB_HTTP_BYTES;

/// The USB-side stack's socket table and the two `/status` servers' windows (1 KB + 2 KB each), all taken once at start.
pub const USB_HTTP_BYTES: usize = 3 * 640 + 2 * (1024 + 2048) + 512;

/// The directory when every membership's tailnet is as big as the directory allows (`DIR_PEERS` records of 288 bytes per membership); a smaller tailnet holds less.
/// The bank a commit builds beside it and the staged updates of a map in flight are elastic ([`ELASTIC_TYPICAL`]).
pub const DIR_LIVE_FULL: usize = MEMBERS * DIR_PEERS * core::mem::size_of::<tdongle_tailnet_peers::record::DirRecord>();

/// What the elastic frames hold in ordinary use (a few radio frames waiting for the stack, a few host frames, the mux's NAT queues, a map being applied): a tuning
/// figure; each consumer is refused at the floor, so the peak is bounded by the heap, not by this.
pub const ELASTIC_TYPICAL: usize = 10 * 1024;

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, MuxDrv>) -> ! {
    runner.run().await
}

/// Record the size of a task's future (what `tn-mem` prints as `tn_future`), without moving it.
fn note_future<F>(sh: &Sh, which: usize, f: &F) {
    sh.fut_bytes[which].store(core::mem::size_of_val(f) as u32, Ordering::Relaxed);
}

#[embassy_executor::task(pool_size = MEMBERS)]
async fn tn_control(sh: &'static Sh, idx: usize, net: &'static EmbassyNet) {
    let f = core::pin::pin!(control_slot(sh, idx, net));
    note_future(sh, FUT_CONTROL, &*f);
    f.await
}

#[embassy_executor::task(pool_size = MEMBERS)]
async fn tn_derp(sh: &'static Sh, idx: usize, net: &'static EmbassyNet) {
    let f = core::pin::pin!(derp_slot(sh, idx, net));
    note_future(sh, FUT_DERP, &*f);
    f.await
}

#[embassy_executor::task(pool_size = MEMBERS)]
async fn tn_derp_x(sh: &'static Sh, idx: usize, net: &'static EmbassyNet) {
    // the extra relay link's manager: a small future; the link it runs is a heap block while it exists
    derp_extra(sh, idx, net).await
}

#[embassy_executor::task(pool_size = MEMBERS)]
async fn tn_udp(sh: &'static Sh, idx: usize, net: &'static EmbassyNet) {
    let f = core::pin::pin!(udp_slot(sh, idx, net));
    note_future(sh, FUT_UDP, &*f);
    f.await
}

#[embassy_executor::task]
async fn tn_usb(sh: &'static Sh, wifi: &'static Wifi) {
    let mut usb = FwUsb;
    let f = core::pin::pin!(usb_pump(sh, &mut usb, wifi));
    note_future(sh, FUT_USB, &*f);
    f.await
}

#[embassy_executor::task]
async fn tn_supervisor(sh: &'static Sh) {
    let f = core::pin::pin!(supervisor(sh));
    note_future(sh, FUT_SUPERVISOR, &*f);
    f.await
}

#[embassy_executor::task]
async fn tn_timer(sh: &'static Sh) {
    let f = core::pin::pin!(engine_timer(sh));
    note_future(sh, FUT_TIMER, &*f);
    f.await
}

#[embassy_executor::task]
async fn tn_link(sh: &'static Sh, net: &'static EmbassyNet, wifi: &'static Wifi) {
    let f = core::pin::pin!(link_watch(sh, net, wifi));
    note_future(sh, FUT_LINK, &*f);
    f.await
}

#[embassy_executor::task]
async fn tn_dns(sh: &'static Sh, net: &'static EmbassyNet) {
    let f = core::pin::pin!(dns_upstream(sh, net));
    note_future(sh, FUT_DNS, &*f);
    f.await
}

/// `l2::tx_done` (the Wi-Fi task, IRAM) signals one `Signal`; this task turns it into the stack's TX waker so the IRAM callback calls nothing new.
#[embassy_executor::task]
async fn tx_wake_task() -> ! {
    loop {
        crate::l2::TX_DONE_SIG.wait().await;
        TX_WAKER.wake();
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// SNTP (the C's clock_sync: pool.ntp.org, time.cloudflare.com, time.google.com in turn)
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/// Socket buffers of the SNTP client.
pub struct SntpBufs {
    rx_meta: [embassy_net::udp::PacketMetadata; 1],
    tx_meta: [embassy_net::udp::PacketMetadata; 1],
    rx: [u8; 128],
    tx: [u8; 64],
}
impl SntpBufs {
    const fn new() -> Self {
        Self { rx_meta: [embassy_net::udp::PacketMetadata::EMPTY; 1], tx_meta: [embassy_net::udp::PacketMetadata::EMPTY; 1], rx: [0; 128], tx: [0; 64] }
    }
}

/// Seconds between 1900-01-01 and 1970-01-01.

/// The SNTP state as `status` prints it (`clock=`, `valid=`, `sntp_restarts=`, `server=`): the real clock of this mode, not a default.
pub fn clock_snapshot() -> (tdongle_serial::clock::Clock, bool) {
    let mut c = tdongle_serial::clock::Clock::default();
    c.restarts = SNTP_TRIES.load(Ordering::Relaxed).saturating_sub(SNTP_OK.load(Ordering::Relaxed).max(1)).min(SNTP_TRIES.load(Ordering::Relaxed));
    c.set_server(SNTP_SERVER.load(Ordering::Relaxed) as u8);
    (c, CLOCK_BASE.load(Ordering::Relaxed) != 0)
}

/// SNTP counters for the `tn_sntp` line: tries, successes, the server index in use and why the last try failed (1 no A record / DNS, 2 send, 3 no answer in 4 s,
/// 4 not a server answer or stratum 0, 5 time before 2023).
static SNTP_TRIES: AtomicU32 = AtomicU32::new(0);
static SNTP_OK: AtomicU32 = AtomicU32::new(0);
static SNTP_SERVER: AtomicU32 = AtomicU32::new(0);
static SNTP_FAIL: AtomicU32 = AtomicU32::new(0);
/// The address DNS gave the last try (big endian), for the `tn_sntp` line.
static SNTP_IP: AtomicU32 = AtomicU32::new(0);
/// The local port of the last try.
static SNTP_PORT: AtomicU32 = AtomicU32::new(0);

async fn sntp_once(stack: Stack<'static>, sock: &mut embassy_net::udp::UdpSocket<'_>, host: &str) -> Result<u64, u32> {
    use embassy_net::dns::DnsQueryType;
    SNTP_DNS[0].fetch_add(1, Ordering::Relaxed);
    let answer = with_timeout(Duration::from_secs(12), tdongle_tailnet_runtime::net_embassy::resolve_a(stack, host)).await;
    SNTP_DNS[match &answer {
        Ok(Ok(_)) => 1,
        Ok(Err(_)) => 2,
        Err(_) => 3,
    }]
    .fetch_add(1, Ordering::Relaxed);
    let a = answer.ok().and_then(Result::ok).ok_or(1u32)?;
    let ip = embassy_net::Ipv4Address::new(a[0], a[1], a[2], a[3]);
    SNTP_IP.store(u32::from_be_bytes(ip.octets()), Ordering::Relaxed);
    tdongle_tailnet_runtime::sntp::exchange(sock, ip, Duration::from_secs(4)).await
}

#[embassy_executor::task]
async fn sntp_task(stack: Stack<'static>, bufs: &'static mut SntpBufs) -> ! {
    let SntpBufs { rx_meta, tx_meta, rx, tx } = bufs;
    let mut sock = embassy_net::udp::UdpSocket::new(stack, rx_meta, rx, tx_meta, tx);
    let mut clock = tdongle_serial::clock::Clock::default();
    // the C's `clock_sync`: `pool.ntp.org`, `time.cloudflare.com`, `time.google.com` in turn, each failure moving on to the next; started as soon as the station has an
    // address (the control connection and DERP are TLS and wait for this clock)
    let mut server = 0usize;
    loop {
        let up = LINK_UP.load(Ordering::Acquire) && stack.config_v4().is_some();
        let valid = CLOCK_BASE.load(Ordering::Relaxed) != 0;
        let now = Instant::now().as_millis();
        let _ = clock.poll(now, valid, up);
        if !up {
            Timer::after_secs(1).await;
            continue;
        }
        // a new local port every try: a port that cannot receive (a collision with a NAT mapping, a stale ARP/route state keyed on it) would otherwise fail every server
        sock.close();
        if sock.bind(0).is_err() {
            SNTP_FAIL.store(6, Ordering::Relaxed);
            Timer::after_secs(2).await;
            continue;
        }
        SNTP_PORT.store(u32::from(sock.endpoint().port), Ordering::Relaxed);
        let host = tdongle_serial::clock::SERVER_NAMES[server % tdongle_serial::clock::SERVERS];
        SNTP_SERVER.store((server % tdongle_serial::clock::SERVERS) as u32, Ordering::Relaxed);
        SNTP_TRIES.fetch_add(1, Ordering::Relaxed);
        match sntp_once(stack, &mut sock, host).await {
            Ok(unix) => {
                SNTP_OK.fetch_add(1, Ordering::Relaxed);
                SNTP_FAIL.store(0, Ordering::Relaxed);
                CLOCK_BASE.store(u32::try_from(unix.saturating_sub(Instant::now().as_secs())).unwrap_or(u32::MAX).max(1), Ordering::Relaxed);
                // resynchronise every hour (lwIP's default is the same order)
                Timer::after_secs(3600).await;
            }
            Err(why) => {
                SNTP_FAIL.store(why, Ordering::Relaxed);
                server += 1;
                Timer::after_secs(2).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// Serial: the commands the gateway owns, run in the thread executor
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

static CON_REQ: Channel<CriticalSectionRawMutex, String, 1> = Channel::new();
static CON_RESP: Signal<CriticalSectionRawMutex, Option<String>> = Signal::new();
static CON_CALL: embassy_sync::mutex::Mutex<CriticalSectionRawMutex, ()> = embassy_sync::mutex::Mutex::new(());

/// The console's hook: `Some(reply)` if the gateway owns `line` (`route`, `members`, `memory`, `inbound`, `member ...`, `tn-mem`, `tailnet-status`, ...), else `None`.
/// The console runs in the interrupt executor, so the work is done by [`console_worker`] in the thread executor.
pub async fn console(line: &str) -> Option<String> {
    if !active() {
        return None;
    }
    let _one = CON_CALL.lock().await;
    CON_RESP.reset();
    CON_REQ.send(String::from(line)).await;
    // the console must never wedge on the gateway: a worker that does not answer in 3 s is reported
    match with_timeout(Duration::from_secs(3), CON_RESP.wait()).await {
        Ok(r) => r,
        Err(_) => Some(String::from("ERR tailnet worker busy\r\n")),
    }
}

/// The extra lines of `status` (a hook after the image's own lines).
pub async fn status_extra() -> Option<String> {
    console("\u{1}status-extra").await
}

#[embassy_executor::task]
async fn console_worker() -> ! {
    loop {
        let line = CON_REQ.receive().await;
        let mut out = String::new();
        let handled = match SHARED_REF.try_get() {
            Some(sh) => handle(sh, &line, &mut out),
            None => false,
        };
        // `tn force-derp on|off` is kept in flash until `off` (see `settings::set_force_derp`), and asks the relay for the matching window mode at once (nothing is flowing yet)
        if let Some(arg) = line.strip_prefix("tn force-derp") {
            let on = match arg.trim() {
                "on" => Some(true),
                "off" => Some(false),
                _ => None,
            };
            if let Some(on) = on {
                let _ = crate::settings::call(crate::settings::Req::ForceDerp(on)).await;
                tdongle_tailnet_runtime::derp::WIN_FORCE.store(if on { 1 } else { 2 }, Ordering::Relaxed);
            }
        }
        CON_RESP.signal(handled.then_some(out));
    }
}

fn crlf(s: &mut String) {
    // the runtime's reports end in a newline; the console wants CR LF
    if s.ends_with('\n') && !s.ends_with("\r\n") {
        s.pop();
        s.push_str("\r\n");
    }
}

/// What the station's IP side is doing: the link, the stack's configuration (DHCP result), the DHCP / ARP frames each way, the mux's counters and the last control dial
/// (`tn_dial`: stage and the stack's own error). Everything a board needs to say why the control plane is not reached.
fn sta_report(sh: &Sh, out: &mut String) {
    use tdongle_tailnet_runtime::net_embassy::DIAL;
    let ld = |a: &AtomicU32| a.load(Ordering::Relaxed);
    let (up, cfg_up, v4) = match STACK_REF.try_get() {
        Some(ThreadOnly(st)) => (st.is_link_up(), st.is_config_up(), st.config_v4()),
        None => (false, false, None),
    };
    let _ = write!(out, "tn_sta link_up={} wifi_connected={} stack_link={} stack_config={}", LINK_UP.load(Ordering::Relaxed) as u8, crate::CONNECTED_NOW.load(Ordering::Relaxed) as u8, up as u8, cfg_up as u8);
    match v4 {
        Some(c) => {
            let _ = write!(out, " ip={}/{}", c.address.address(), c.address.prefix_len());
            match c.gateway {
                Some(g) => {
                    let _ = write!(out, " gw={g}");
                }
                None => out.push_str(" gw=none"),
            }
            out.push_str(" dns=");
            for (i, d) in c.dns_servers.iter().enumerate() {
                let _ = write!(out, "{}{}", if i > 0 { "," } else { "" }, d);
            }
            if c.dns_servers.is_empty() {
                out.push_str("none");
            }
        }
        None => out.push_str(" ip=none gw=none dns=none"),
    }
    let _ = write!(
        out,
        " dhcp_rx={} dhcp_tx={} arp_rx={} arp_tx={} wifi_rx={} rx_dropped={} rx_heap_refused={} tx_refused={} rx_ring_bytes={} heap_free={} heap_min={} up_ms={}\r\n",
        ld(&DHCP_RX),
        ld(&DHCP_TX),
        ld(&ARP_RX),
        ld(&ARP_TX),
        ld(&RX_FRAMES),
        ld(&RX_DROPPED),
        ld(&RX_HEAP_REFUSED),
        ld(&TX_REFUSED),
        ld(&RX_BYTES),
        FwHeap.free(),
        ld(&HEAP_MIN),
        Instant::now().as_millis()
    );
    if let Some(p) = DIAG_PORT.try_get() {
        let m = p.stats();
        let _ = write!(
            out,
            "tn_mux rx_frames={} to_stack={} to_host={} tx_stack={} gateway_mac={:?} rx_drop[runt,oversize,not_for_us,bad_src,bad_ip,tap_rej,tap_drop,tap_range,hostq]={},{},{},{},{},{},{},{},{} snooped={}\r\n",
            m.rx_frames.get(),
            m.rx_to_stack.get(),
            m.rx_to_host.get(),
            m.tx_stack.get(),
            p.gateway_mac(),
            m.rx_dropped[0].get(),
            m.rx_dropped[1].get(),
            m.rx_dropped[2].get(),
            m.rx_dropped[3].get(),
            m.rx_dropped[4].get(),
            m.rx_dropped[5].get(),
            m.rx_dropped[6].get(),
            m.rx_dropped[7].get(),
            m.rx_dropped[8].get(),
            m.snooped.get()
        );
    }
    {
        use core::sync::atomic::Ordering::Relaxed;
        use tdongle_tailnet_runtime::derp::DERP_DIAG as D;
        let (host, err) = D.text.lock(|t| {
            let t = t.borrow();
            let cut = |b: &[u8; 64]| String::from_utf8_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(64)]).into_owned();
            (cut(&t.0), cut(&t.1))
        });
        let now = Instant::now().as_millis() as u32;
        let ready_at = D.ready_at_ms.load(Relaxed);
        let ip = D.ip.load(Relaxed).to_be_bytes();
        for (i, sl) in sh.slots.iter().enumerate() {
            let st = sl.status();
            let d = &st.derp;
            let _ = write!(
                out,
                "tn_derp slot={} state={} region={} host={} port={} ip={}.{}.{}.{} stage={} (1 dial,2 tcp,3 tls,4 relaying) uptime_ms={} connects={} connect_failures={} frames_rx={} frames_tx={} last_rx_frame_type={:#04x} \
keepalives={} pings_answered={} pings_dropped={} pongs={} unknown={} malformed={} rx_timeouts={} tx_stalls={} stale={} protocol_errors={} server_info_bad={} \
last_end={} (1 wait,2 lease,3 tls_read,4 write,5 link_close) last_end_after_ms={} ends[wait,lease,tls_read,write,link]={},{},{},{},{} last_error=\"{}\" tls_untrusted={}\r\n",
                i,
                st.derp_state.name(),
                D.region.load(Relaxed),
                host,
                D.port.load(Relaxed),
                ip[0], ip[1], ip[2], ip[3],
                D.stage.load(Relaxed),
                if ready_at == 0 { 0 } else { now.wrapping_sub(ready_at) },
                d.connects.get(),
                d.connect_failures.get(),
                d.frames_rx.get(),
                d.frames_tx.get(),
                tdongle_tailnet_runtime::derp::LAST_RX_FRAME_TYPE.load(Relaxed),
                d.keepalives.get(),
                d.pings_answered.get(),
                d.pings_dropped.get(),
                d.pongs_rx.get(),
                d.unknown_frames.get(),
                d.malformed_frames.get(),
                d.rx_timeouts.get(),
                d.tx_stalls.get(),
                d.stale.get(),
                d.protocol_errors.get(),
                d.server_info_bad.get(),
                D.end.load(Relaxed),
                D.end_after_ms.load(Relaxed),
                D.ends[1].load(Relaxed),
                D.ends[2].load(Relaxed),
                D.ends[3].load(Relaxed),
                D.ends[4].load(Relaxed),
                D.ends[5].load(Relaxed),
                err,
                st.tls_untrusted
            );
        }
        {
            use tdongle_tailnet_runtime::derp::WIN_STATS;
            let _ = write!(
                out,
                "tn_derp_windows big_now={} (idle rx/tx {}/{} B, big {}/{} B) to_big={} to_small={} refused_by_pool={} waited_for_lull={} waited_for_heap={} force_derp={} dynamic_windows_enabled={}\r\n",
                WIN_STATS[3].load(Relaxed),
                tdongle_tailnet_runtime::net_embassy::Windows::GATEWAY.derp_rx,
                tdongle_tailnet_runtime::net_embassy::Windows::GATEWAY.derp_tx,
                tdongle_tailnet_runtime::net_embassy::DERP_RX_BIG,
                tdongle_tailnet_runtime::net_embassy::DERP_TX_BIG,
                WIN_STATS[0].load(Relaxed),
                WIN_STATS[1].load(Relaxed),
                WIN_STATS[2].load(Relaxed),
                WIN_STATS[4].load(Relaxed),
                WIN_STATS[5].load(Relaxed),
                tdongle_tailnet_engine::shared::FORCE_DERP.load(Relaxed) as u8,
                tdongle_tailnet_runtime::derp::WIN_ENABLED.load(Relaxed) as u8
            );
        }
        {
            // where the heap is: the free heap and its minimum with and without a control workspace held (the workspace may take the heap below the floor: it is what the floor
            // reserves), the pool, the radio ring, the waiting packets, the relay queue
            use tdongle_tailnet_runtime::shared::{NEG_DEFERRED, NEG_HOLDERS};
            let p = sh.pool.stats();
            let floor = ML_HB_FLOOR as i64;
            let no_neg = ld(&HEAP_MIN_NO_NEG);
            let _ = write!(
                out,
                "tn_heap free={} min={} (over_floor {}) min_without_negotiation={} (over_floor {}) floor={} negotiations_held_now={} bulk_max_holders={} deferred_for_relay[count,ms]={},{} pool[in_use,high,takes_socket_record_neg,denied_floor_heap_cap]={},{},{}/{}/{},{}/{}/{} rx_ring[now,peak]={},{} visit_queue[now,peak]={},{} relay_queue[now,high]={},{} usb_rx_waits={} bulk_leases={}\r\n",
                FwHeap.free(),
                ld(&HEAP_MIN),
                ld(&HEAP_MIN) as i64 - floor,
                no_neg,
                if no_neg == u32::MAX { 0 } else { no_neg as i64 - floor },
                ML_HB_FLOOR,
                NEG_HOLDERS.load(Ordering::Relaxed),
                sh.bulk.max_holders(),
                NEG_DEFERRED[0].load(Ordering::Relaxed),
                NEG_DEFERRED[1].load(Ordering::Relaxed),
                p.in_use,
                p.high_water,
                p.takes[0],
                p.takes[1],
                p.takes[2],
                p.denied_floor,
                p.denied_heap,
                p.denied_cap,
                ld(&RX_BYTES),
                ld(&RX_BYTES_PEAK),
                tdongle_tailnet_runtime::derp::xq_bytes(),
                ld(&tdongle_tailnet_runtime::derp::XQ_PEAK),
                sh.slots.iter().map(|s| s.derp_q.len_bytes()).sum::<usize>(),
                sh.slots.iter().map(|s| s.derp_q.stats().high_water as usize).max().unwrap_or(0),
                ld(&USB_RX_WAITS),
                sh.bulk.leases()
            );
        }
        {
            // where a download loses packets: the relay window and the reader's hold-back, then the host queue, the USB ring and the engine's own receive fates (`tn_eng rx`)
            use tdongle_tailnet_runtime::derp::RELAY_RX;
            let h = sh.host_q.stats();
            let _ = write!(
                out,
                "tn_dl relay_rx_window={} rx_window_peak_relay={} control={} records={} record_bytes={} reader_held[times,ms]={},{} relay_frames_in={} relay_rx_refused={} host_q[pushed,refused,high]={},{},{}/{} usb_ring[enq,full,high]={},{},{} usb_tx_refused={}\r\n",
                tdongle_tailnet_runtime::net_embassy::Windows::GATEWAY.derp_rx,
                tdongle_tailnet_runtime::net_embassy::TCP_RX_PEAK[1].load(Relaxed),
                tdongle_tailnet_runtime::net_embassy::TCP_RX_PEAK[0].load(Relaxed),
                RELAY_RX[0].load(Relaxed),
                RELAY_RX[1].load(Relaxed),
                RELAY_RX[2].load(Relaxed),
                RELAY_RX[3].load(Relaxed),
                sh.slots[0].status().derp.frames_rx.get(),
                sh.slots[0].status().derp.rx_refused.get(),
                h.pushed,
                h.refused,
                h.high_water,
                tdongle_tailnet_runtime::shared::HOST_Q,
                ld(&crate::RING_ENQ),
                ld(&crate::RING_FULL),
                ld(&crate::RING_HIGH),
                tdongle_tailnet_runtime::shared::RtStats::get(&sh.stats.usb_tx_refused)
            );
        }
        {
            use tdongle_tailnet_runtime::net_embassy::TCP_DIAG as T;
            let _ = write!(
                out,
                "tn_tcp_errs read={} write={} flush_on_closed={} aborted_by_us={} (control {}, relay {}; connects control {}, relay {}) last_op={} (1 read, 2 write, 3 flush) last_state={} (0 Closed, 4 Established, 7 CloseWait) send_queue={} recv_queue={} after_ms={}\r\n",
                T[0].load(Relaxed), T[1].load(Relaxed), T[2].load(Relaxed), T[3].load(Relaxed), tdongle_tailnet_runtime::net_embassy::TCP_ABORTS[0].load(Relaxed), tdongle_tailnet_runtime::net_embassy::TCP_ABORTS[1].load(Relaxed), tdongle_tailnet_runtime::net_embassy::TCP_CONNECTS[0].load(Relaxed), tdongle_tailnet_runtime::net_embassy::TCP_CONNECTS[1].load(Relaxed), T[4].load(Relaxed), T[5].load(Relaxed), T[6].load(Relaxed), T[7].load(Relaxed), T[8].load(Relaxed)
            );
        }
        {
            use tdongle_tailnet_runtime::derp::{HANDSHAKE_NOMEM, RELAY_DOWN};
            let since = RELAY_DOWN[2].load(Relaxed);
            let _ = write!(
                out,
                "tn_relay_down left_ready={} down_ms_total={} down_now_ms={} handshakes_refused_for_heap={} (the engine's no_route counts packets for the relay while it was down)\r\n",
                RELAY_DOWN[0].load(Relaxed),
                RELAY_DOWN[1].load(Relaxed),
                if since == 0 { 0 } else { (Instant::now().as_millis() as u32).wrapping_sub(since) },
                HANDSHAKE_NOMEM.load(Relaxed)
            );
        }
        // the link's visits to the regions peers are homed on, and the moves of its home region
        {
            use tdongle_tailnet_runtime::derp::{HOME_MOVES, VISITING, X_COUNTS, X_LAST_END};
            let _ = write!(
                out,
                "tn_derp_visit visiting={} queued={} sent={} dropped[queue_full,heap,region_unknown]={},{},{} visits={} refused_home_busy={} expired={} dropped_on_leave={} link_refused={} rx_to_engine={} last_leave={} (6 idle, 8 others starving) home_moves={} (last {} -> {})\r\n",
                VISITING.load(Relaxed),
                X_COUNTS[0].load(Relaxed),
                X_COUNTS[1].load(Relaxed),
                X_COUNTS[2].load(Relaxed),
                X_COUNTS[3].load(Relaxed),
                X_COUNTS[4].load(Relaxed),
                X_COUNTS[5].load(Relaxed),
                X_COUNTS[10].load(Relaxed),
                X_COUNTS[6].load(Relaxed),
                X_COUNTS[7].load(Relaxed),
                X_COUNTS[8].load(Relaxed),
                X_COUNTS[9].load(Relaxed),
                X_LAST_END.load(Relaxed),
                HOME_MOVES[0].load(Relaxed),
                HOME_MOVES[1].load(Relaxed),
                HOME_MOVES[2].load(Relaxed)
            );
        }
    }
    {
        // the host-bound path end to end: engine -> host_q -> pump -> ring -> IN NTBs (the bridge's own aggregation and interrupt-executor sender), and the UDP side that feeds it
        use tdongle_tailnet_runtime::{udp as rt_udp, usb as rt_usb};
        let ntbs = ld(&crate::NTB_IN_COUNT);
        let frames = ld(&crate::NTB_IN_FRAMES);
        let _ = write!(
            out,
            "tn_in ntb={} frames={} frames_per_ntb_x100={} frames_max={} hist_1_2_4_8={}/{}/{}/{} in_wait_us_avg={} in_wait_us_max={} in_wakes={} in_idle_timeouts={} heap_min_over_floor={} ring_enq={} ring_full={} ring_high={} pump_wakes={} pump_moved={} pump_pass_max={} udp_wakes={} udp_datagrams={} udp_batch_max={} udp_pkts={} derp_held={} derp_reconnect[lease,tls,wait,write]={},{},{},{} hold[waits,ran_out,ms_total]={},{},{}\r\n",
            ntbs,
            frames,
            if ntbs == 0 { 0 } else { frames * 100 / ntbs },
            ld(&crate::NTB_IN_FRAMES_MAX),
            ld(&crate::NTB_IN_HIST[0]),
            ld(&crate::NTB_IN_HIST[1]),
            ld(&crate::NTB_IN_HIST[2]),
            ld(&crate::NTB_IN_HIST[3]),
            if ntbs == 0 { 0 } else { ld(&crate::NTB_IN_US_SUM) / ntbs },
            ld(&crate::NTB_IN_US_MAX),
            ld(&crate::IN_WAKES),
            ld(&crate::IN_TIMEOUTS),
            ld(&HEAP_MIN) as i64 - ML_HB_FLOOR as i64,
            ld(&crate::RING_ENQ),
            ld(&crate::RING_FULL),
            ld(&crate::RING_HIGH),
            ld(&rt_usb::PUMP_WAKES),
            ld(&rt_usb::PUMP_MOVED),
            ld(&rt_usb::PUMP_PASS_MAX),
            ld(&rt_udp::UDP_WAKES),
            ld(&rt_udp::UDP_DATAGRAMS),
            ld(&rt_udp::UDP_BATCH_MAX),
            tdongle_tailnet_runtime::net_embassy::UDP_PKTS,
            ld(&tdongle_tailnet_runtime::derp::DERP_EGRESS_HELD),
            ld(&tdongle_tailnet_runtime::derp::DERP_RECONNECT[0]),
            ld(&tdongle_tailnet_runtime::derp::DERP_RECONNECT[1]),
            ld(&tdongle_tailnet_runtime::derp::DERP_RECONNECT[2]),
            ld(&tdongle_tailnet_runtime::derp::DERP_RECONNECT[3]),
            ld(&tdongle_tailnet_runtime::usb::HOLD_STATS[0]),
            ld(&tdongle_tailnet_runtime::usb::HOLD_STATS[1]),
            ld(&tdongle_tailnet_runtime::usb::HOLD_STATS[2])
        );
    }
    for (i, sl) in sh.slots.iter().enumerate() {
        let st = sl.status();
        if st.state == SlotState::Free {
            continue;
        }
        let m = st.map;
        let _ = write!(
            out,
            "tn_map slot={} maps={} authoritative={} peers[add,removed,patch]={},{},{} derp_regions={}/{} dns={} directory={}/{} directory_overflow={} staged_dropped={}/cap_staged={}\r\n",
            i,
            m.maps,
            m.authoritative as u8,
            m.peers_add,
            m.peers_removed,
            m.peers_patch,
            m.derp_regions,
            tdongle_tailnet_map::types::MAX_DERP_REGIONS,
            m.dns,
            m.dir_peers,
            DIR_PEERS,
            m.dir_overflow,
            m.stage_dropped,
            DIR_STAGED
        );
        let _ = write!(out, "tn_ctl slot={} stage={} connected={} end=\"{}\" error=\"{}\"\r\n", i, st.control_stage, st.connected as u8, st.last_end.as_str(), st.last_error.as_str());
    }
    {
        // is the DNS query leaving the driver, does the answer come back to it, and does the stack poll the driver at all
        let servers = STACK_REF.try_get().and_then(|ThreadOnly(st)| st.config_v4()).map(|c| c.dns_servers);
        let _ = write!(
            out,
            "tn_dns resolvers[addr:ok/fail*]={} forwarder={} frames[dns_tx,dns_rx,ntp_tx,ntp_rx]={},{},{},{} sntp_dns[started,answered,empty_or_error,timeout]={},{},{},{} drv[tx_polls,tx_noroom,rx_polls]={},{},{} tx_refused={} servers={:?} napt_replies[dns_host,dns_stack,ntp_host,ntp_stack]={},{},{},{} last_dns_tx={}\r\n",
            resolver_list(),
            {
                let o = tdongle_tailnet_runtime::resolver::RESOLVERS.forwarder().to_be_bytes();
                alloc::format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
            },
            ld(&DNS_FRAMES[0]),
            ld(&DNS_FRAMES[1]),
            ld(&DNS_FRAMES[2]),
            ld(&DNS_FRAMES[3]),
            ld(&SNTP_DNS[0]),
            ld(&SNTP_DNS[1]),
            ld(&SNTP_DNS[2]),
            ld(&SNTP_DNS[3]),
            ld(&DRV_TX_POLLS),
            ld(&DRV_TX_NOROOM),
            ld(&DRV_RX_POLLS),
            ld(&TX_REFUSED),
            servers,
            ld(&tdongle_tailnet_wifimux::tap::REPLY_VERDICTS[0]),
            ld(&tdongle_tailnet_wifimux::tap::REPLY_VERDICTS[1]),
            ld(&tdongle_tailnet_wifimux::tap::REPLY_VERDICTS[2]),
            ld(&tdongle_tailnet_wifimux::tap::REPLY_VERDICTS[3]),
            last_dns_tx_hex()
        );
    }
    let _ = write!(
        out,
        "tn_sntp tries={} ok={} server={} last_fail={} clock_valid={} last_ip={:#010x} last_answer_len={} last_answer_head={:#06x} local_port={}\r\n",
        ld(&SNTP_TRIES),
        ld(&SNTP_OK),
        tdongle_serial::clock::SERVER_NAMES[ld(&SNTP_SERVER) as usize % tdongle_serial::clock::SERVERS],
        ld(&SNTP_FAIL),
        (CLOCK_BASE.load(Ordering::Relaxed) != 0) as u8,
        ld(&SNTP_IP),
        ld(&tdongle_tailnet_runtime::sntp::LAST_LEN),
        ld(&tdongle_tailnet_runtime::sntp::LAST_HEAD),
        ld(&SNTP_PORT)
    );
    let stage = match ld(&DIAL.last_stage) {
        0 => "none",
        1 => "ok",
        2 => ["dns_invalid_name", "dns_name_too_long", "dns_failed", "dns_no_a_record"][(ld(&DIAL.last_detail) as usize).min(3)],
        3 => "no_memory_for_windows",
        _ => ["connect_no_route", "connect_invalid_state", "connect_reset", "connect_timed_out"][(ld(&DIAL.last_detail) as usize).min(3)],
    };
    let ip = ld(&DIAL.last_ip).to_be_bytes();
    let _ = write!(
        out,
        "tn_dial attempts={} ok={} last={} to={}.{}.{}.{}:{} dns[invalid,too_long,failed,no_a]={},{},{},{} connect[no_route,invalid_state,reset,timed_out]={},{},{},{} no_memory={}\r\n",
        ld(&DIAL.attempts),
        ld(&DIAL.ok),
        stage,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        ld(&DIAL.last_port),
        ld(&DIAL.dns[0]),
        ld(&DIAL.dns[1]),
        ld(&DIAL.dns[2]),
        ld(&DIAL.dns[3]),
        ld(&DIAL.connect[0]),
        ld(&DIAL.connect[1]),
        ld(&DIAL.connect[2]),
        ld(&DIAL.connect[3]),
        ld(&DIAL.nomem)
    );
}

fn handle(sh: &'static Sh, line: &str, out: &mut String) -> bool {
    let api: &dyn TailnetApi = sh;
    if line == "\u{1}status-extra" {
        api.serial_status_extra(out);
        sta_report(sh, out);
        let _ = write!(out, "tailnet_rust members={} napt_flows={} mux_tx={} mux_rx={} wifi_rx={} wifi_rx_dropped={} wifi_tx_refused={} usb_rx_queue={}\r\n", MEMBERS, NAPT_FLOWS, MUX_TXQ, MUX_RXQ, RX_FRAMES.load(Ordering::Relaxed), RX_DROPPED.load(Ordering::Relaxed), TX_REFUSED.load(Ordering::Relaxed), USB_RX_FRAMES);
        return true;
    }
    if let Some(arg) = line.strip_prefix("tn force-derp") {
        use tdongle_tailnet_engine::shared::{FORCE_DERP, FORCE_DERP_DROPPED};
        match arg.trim() {
            "on" => FORCE_DERP.store(true, Ordering::Relaxed),
            "off" => FORCE_DERP.store(false, Ordering::Relaxed),
            _ => {}
        }
        let _ = write!(out, "tn_force_derp on={} dropped_udp={} (peers fall back to the relay within about 10 s of `on`; `off` lets disco find the direct path again)\r\n", FORCE_DERP.load(Ordering::Relaxed) as u8, FORCE_DERP_DROPPED.load(Ordering::Relaxed));
        return true;
    }
    if line == "tn-wg" {
        // engine fates and per-peer WireGuard state (handshake time, bytes, path)
        api.serial_status_extra(out);
        return true;
    }
    if line == "tn-mem" || line == "tn-sta" {
        if line == "tn-sta" {
            sta_report(sh, out);
            return true;
        }
        memory_report(sh, out);
        return true;
    }
    if line == "tailnet-status" {
        // the `/status` JSON the setup page serves, on the console (until the setup HTTP server lands in this image)
        let mut sink = |chunk: &[u8]| {
            out.push_str(&String::from_utf8_lossy(chunk));
            true
        };
        let _ = api.render_status(&mut sink);
        out.push_str("\r\n");
        return true;
    }
    if let Some(rest) = line.strip_prefix("member ") {
        member_command(api, rest, out);
        return true;
    }
    let handled = api.serial_command(line, out);
    if handled {
        crlf(out);
    }
    handled
}

/// `member add LABEL KEY | enable ID | disable ID | remove ID`: the setup page's member actions for the USB origin, on the console. (The setup page itself goes
/// through [`api`]; this is the board-test path until the HTTP server is part of this image.)
fn member_command(api: &dyn TailnetApi, rest: &str, out: &mut String) {
    use tdongle_tailnet_fw::MemberAction;
    let mut it = rest.split_whitespace();
    let verb = it.next().unwrap_or("");
    let a = it.next().unwrap_or("");
    let b = it.next().unwrap_or("");
    let action = match verb {
        "add" if !a.is_empty() => MemberAction::add(a.as_bytes(), b.as_bytes()), // no key: browser sign-in (the login URL appears in /status)
        "enable" | "disable" | "remove" => match a.parse::<u32>() {
            Ok(id) => match verb {
                "enable" => MemberAction::Enable(id),
                "disable" => MemberAction::Disable(id),
                _ => MemberAction::Remove(id),
            },
            Err(_) => {
                out.push_str("usage: member add LABEL [KEY] | enable ID | disable ID | remove ID\r\n");
                return;
            }
        },
        _ => {
            out.push_str("usage: member add LABEL [KEY] | enable ID | disable ID | remove ID\r\n");
            return;
        }
    };
    let reply = api.member_action(&action);
    let _ = reply.write_body(out);
    out.push_str("\r\n");
}

unsafe extern "C" {
    static _data_start: u32;
    static _data_end: u32;
    static _bss_start: u32;
    static _bss_end: u32;
    static _stack_end: u32;
    static _stack_start: u32;
}

/// The linker's view of the DRAM plus the heap, and the runtime's own figures.
fn memory_report(sh: &Sh, out: &mut String) {
    // the linker defines these symbols; only their addresses are taken, nothing is read
    let (ds, de, bs, be, se, st) = {
        (
            core::ptr::addr_of!(_data_start) as usize,
            core::ptr::addr_of!(_data_end) as usize,
            core::ptr::addr_of!(_bss_start) as usize,
            core::ptr::addr_of!(_bss_end) as usize,
            core::ptr::addr_of!(_stack_end) as usize,
            core::ptr::addr_of!(_stack_start) as usize,
        )
    };
    let h = esp_alloc::HEAP.stats();
    let _ = write!(
        out,
        "tn_mem data={} bss={} stack_region={} heap_size={} heap_used={} heap_free={} heap_min={} largest={} members={}\r\n",
        de - ds,
        be - bs,
        st - se,
        h.size,
        esp_alloc::HEAP.used(),
        esp_alloc::HEAP.free(),
        HEAP_MIN.load(Ordering::Relaxed),
        FwHeap.largest_block(),
        MEMBERS
    );
    let _ = write!(
        out,
        "tn_statics shared_heap={} pooled_windows_per_member={} napt={} mux={} stack_res={} rx_ring_max={} usb_rx_max={} futures={}\r\n",
        core::mem::size_of::<Sh>(),
        Windows::PER_MEMBER,
        core::mem::size_of::<SharedNapt<NAPT_FLOWS>>(),
        core::mem::size_of::<Mux>(),
        core::mem::size_of::<StackResources<STACK_SOCKETS>>(),
        RX_RING * (crate::MTU + 2),
        USB_RX_FRAMES * (crate::MTU + 2),
        (0..tdongle_tailnet_runtime::sizes::FUT_RUN).map(|i| tdongle_tailnet_runtime::sizes::future_bytes(sh, i)).sum::<usize>()
    );
    let _ = write!(out, "tn_http served={}\r\n", HTTP_SERVED.load(Ordering::Relaxed));
    let _ = write!(
        out,
        "tn_budget heap_total={} wifi_usb_assumed={} ring_base={} tailnet_state={} floor={} headroom={} stack={} start_refused={} rx_heap_refused={} usb_rx_waits={}\r\n",
        budget::HEAP_TOTAL,
        budget::WIFI_AND_USB,
        budget::RING_BASE,
        TAILNET_HEAP_BYTES,
        ML_HB_FLOOR,
        budget::HEADROOM,
        st - se,
        START_REFUSED.load(Ordering::Relaxed),
        RX_HEAP_REFUSED.load(Ordering::Relaxed),
        USB_RX_WAITS.load(Ordering::Relaxed)
    );
    let ps = sh.pool.stats();
    let _ = write!(
        out,
        "tn_pool in_use={} high_water={} cap={} takes_socket={} takes_record={} takes_negotiation={} denied_cap={} denied_floor={} denied_heap={} waits={} record_leases={} record_timeouts={} bulk_leases={}\r\n",
        ps.in_use,
        ps.high_water,
        sh.pool.cap(),
        ps.takes[0],
        ps.takes[1],
        ps.takes[2],
        ps.denied_cap,
        ps.denied_floor,
        ps.denied_heap,
        ps.waits,
        sh.lease.leases(),
        sh.lease.timeouts(),
        sh.bulk.leases()
    );
    for (i, name) in tdongle_tailnet_runtime::sizes::FUTURE_NAMES.iter().enumerate() {
        let _ = write!(out, "tn_future {}={}\r\n", name, tdongle_tailnet_runtime::sizes::future_bytes(sh, i));
    }
}

/// Drains the runtime's console lines (`tailnet` / `route` for the Android app) to the CDC-ACM port.
#[embassy_executor::task]
async fn lines_task() -> ! {
    loop {
        let l = LINES.receive().await;
        if let (Some(wr), Ok(text)) = (WRITER.try_get(), core::str::from_utf8(&l.data[..usize::from(l.len)])) {
            let mut s = String::from(text);
            s.push_str("\r\n");
            crate::out(wr, &s, 200).await;
        }
    }
}

/// The ACM writer (set by `main` once it exists), for [`lines_task`].
pub static WRITER: OnceLock<&'static embassy_sync::mutex::Mutex<CriticalSectionRawMutex, crate::AcmWriter>> = OnceLock::new();

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// LCD
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/// What the front panel shows of the gateway (`gateway_display_state`): memberships stored / enabled / ready / waiting for a sign-in / in error.
#[derive(Clone, Copy, Debug, Default)]
pub struct Panel {
    /// Memberships stored.
    pub saved: u32,
    /// Enabled.
    pub enabled: u32,
    /// Connected and ready.
    pub ready: u32,
    /// Waiting for a sign-in.
    pub login: u32,
    /// In error.
    pub failed: u32,
    /// Peers with a live tunnel.
    pub tunnels: u32,
}

/// The counts for the panel; `None` outside tailnet mode.
pub fn panel() -> Option<Panel> {
    let sh = SHARED_REF.try_get()?;
    let c: MemberCounts = TailnetApi::counts(*sh);
    let (mut ready, mut login, mut failed) = (0, 0, 0);
    for s in sh.slots.iter() {
        let st = s.status();
        if st.state != SlotState::Running {
            continue;
        }
        if st.ready {
            ready += 1;
        } else if !st.auth_url.as_str().is_empty() {
            login += 1;
        } else if !st.last_error.as_str().is_empty() {
            failed += 1;
        }
    }
    Some(Panel { saved: u32::from(c.configured), enabled: u32::from(c.enabled), ready, login, failed, tunnels: u32::from(c.tunnels) })
}
