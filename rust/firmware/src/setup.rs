//! The setup boot (C ADR 0024): an open access point `TDongle-XXXXXX` on 192.168.4.1, a DHCP server that names the dongle as DNS, a captive DNS responder, one HTTP server,
//! the ten minute session, and nothing else: no bridge, no USB network (the typestate of `tdongle_setup::boot` has no way to produce one from a setup boot).
//!
//! Every decision (who may ask what, the page, the answers, the session timer, the DNS reply) is `tdongle-setup`; this file moves bytes between embassy-net sockets and those
//! functions and owns the radio. The boot starts the radio and the sockets only after USB and the console are up and the settings are read (rule 13).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicBool, Ordering};

use critical_section::Mutex as CsMutex;
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpEndpoint, Ipv4Address, Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_radio::wifi::ap::AccessPointConfig;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{AuthenticationMethodConfig, Config, ControllerConfig, Interface, WifiController};
use static_cell::StaticCell;
use tdongle_nvs_format::load::Loaded;
use tdongle_setup::boot::{Request, SetupBoot};
use tdongle_setup::host::SetupHost;
use tdongle_setup::http::{Reader, Step};
use tdongle_setup::response::{ErrCode, Response};
use tdongle_setup::router::{BodyIn, Conn, Portal, Tick};
use tdongle_setup::scan::ScanList;

/// This boot is the setup access point.
pub static ACTIVE: AtomicBool = AtomicBool::new(false);
/// When the session started (ms, 32 bit), for the LCD countdown.
pub static START_MS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The access point is up (`wifi_ready`).
pub static AP_UP: AtomicBool = AtomicBool::new(false);
static SESSION: CsMutex<Cell<tdongle_setup::boot::Session>> = CsMutex::new(Cell::new(tdongle_setup::boot::Session::INACTIVE));
static AP_NAME: CsMutex<Cell<[u8; tdongle_setup::boot::SSID_LEN]>> = CsMutex::new(Cell::new([0; tdongle_setup::boot::SSID_LEN]));
static PORTAL: StaticCell<Portal> = StaticCell::new();
static PORTAL_REF: CsMutex<Cell<Option<&'static Portal>>> = CsMutex::new(Cell::new(None));
static LEAVE: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static SCAN_REQ: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static SCANNING: AtomicBool = AtomicBool::new(false);
static SCANNED: AtomicBool = AtomicBool::new(false);
static SCAN_LIST: CsMutex<RefCell<ScanList>> = CsMutex::new(RefCell::new(ScanList::new()));

/// `status` and the LCD: the session clock and the access point name.
pub fn session() -> tdongle_setup::boot::Session {
    critical_section::with(|cs| SESSION.borrow(cs).get())
}

/// The access point name (`TDongle-XXXXXX`), empty outside a setup boot.
pub fn ap_name() -> [u8; tdongle_setup::boot::SSID_LEN] {
    critical_section::with(|cs| AP_NAME.borrow(cs).get())
}

/// `setup N` while setup is open: offer saved network `n`.
pub fn preselect(n: u8) {
    if let Some(p) = critical_section::with(|cs| PORTAL_REF.borrow(cs).get()) {
        p.set_preselect(n);
    }
}

/// Restart into setup (`Enter`, with an optional preselected network) or out of it (`Leave`). Does not return (`setup_restart`).
pub fn restart(request: Request, preselect: u32) -> ! {
    let (m, r, s) = tdongle_setup::boot::request_words(request, preselect);
    crate::guard::setup_set([m, r, s]);
    tdongle_rescue::deliberate_reset()
}

/// A page action or the console asked to leave setup.
pub fn request_leave() {
    LEAVE.signal(());
}

fn now_ms() -> u32 {
    Instant::now().as_millis() as u32
}

/// The portal's view of the world (`SetupHost`): the saved list (a copy, refreshed under the settings "lock"), the scan list and the store.
struct FwHost {
    loaded: Loaded,
}

impl FwHost {
    fn new() -> Self {
        Self { loaded: crate::SAVED.lock(|c| *c.borrow()).unwrap_or(Loaded { saved: Default::default(), meta: tdongle_nvs_format::wifi_meta::MetaSet::defaults(&[]) }) }
    }

    fn commit(&mut self, edited: Option<(tdongle_nvs_format::wifi_profiles::SavedNetworks, tdongle_nvs_format::wifi_meta::MetaSet)>) -> bool {
        let Some((list, meta)) = edited else { return false };
        // Nothing else uses the store in a setup boot: a busy store is a failure to report, not to wait for.
        let Ok(mut g) = crate::settings::STORE.try_lock() else { return false };
        let Some(store) = g.as_mut() else { return false };
        crate::guard::op("nvs_write");
        let r = store.save_profiles(&list, &meta);
        crate::guard::op("");
        if r.is_err() {
            let _ = store.remount();
            return false;
        }
        self.loaded = Loaded { saved: list, meta };
        crate::SAVED.lock(|c| *c.borrow_mut() = Some(self.loaded));
        true
    }
}

impl SetupHost for FwHost {
    fn wifi_ready(&self) -> bool {
        AP_UP.load(Ordering::Relaxed)
    }
    fn recovery(&self) -> bool {
        false
    }
    fn lock_settings(&mut self, _wait_ms: u32) -> bool {
        *self = Self::new();
        true
    }
    fn unlock_settings(&mut self) {}
    fn scan_kick(&mut self, again: bool) {
        if SCANNING.load(Ordering::Relaxed) || (SCANNED.load(Ordering::Relaxed) && !again) {
            return;
        }
        SCANNING.store(true, Ordering::Relaxed);
        SCAN_REQ.signal(());
    }
    fn scan_result(&mut self, out: &mut ScanList) -> bool {
        critical_section::with(|cs| *out = *SCAN_LIST.borrow_ref(cs));
        SCANNING.load(Ordering::Relaxed)
    }
    fn saved_count(&self) -> usize {
        self.loaded.saved.count
    }
    fn saved_ssid(&self, i: usize) -> &[u8] {
        self.loaded.saved.profiles[i].ssid_bytes()
    }
    fn saved_name(&self, i: usize) -> &[u8] {
        self.loaded.meta.slot[i].name_bytes()
    }
    fn saved_priority(&self, i: usize) -> u8 {
        self.loaded.meta.slot[i].priority
    }
    fn saved_preferred(&self) -> Option<usize> {
        self.loaded.meta.preferred
    }
    fn save_wifi(&mut self, ssid: &[u8], password: &[u8], name: Option<&[u8]>, priority: i32, slot: i32) -> bool {
        let edited = tdongle_saved::edit::save_with(&self.loaded.saved, &self.loaded.meta, ssid, password, name, priority, false, slot);
        self.commit(edited)
    }
    fn remove_wifi(&mut self, ssid: &[u8]) -> bool {
        let edited = tdongle_saved::edit::save_with(&self.loaded.saved, &self.loaded.meta, ssid, b"", None, -1, true, -1);
        self.commit(edited)
    }
    fn request_leave(&mut self) -> bool {
        request_leave();
        true
    }
}

fn endpoint_v4(e: Option<IpEndpoint>) -> Option<u32> {
    match e?.addr {
        embassy_net::IpAddress::Ipv4(a) => Some(u32::from_be_bytes(a.octets())),
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface>) -> ! {
    runner.run().await
}

/// Captive DNS (`setup_dns_task`): every name is the dongle.
#[embassy_executor::task]
async fn dns_task(stack: Stack<'static>) -> ! {
    let mut rx_meta = [PacketMetadata::EMPTY; 4];
    let mut tx_meta = [PacketMetadata::EMPTY; 4];
    let mut rx = [0u8; 4 * 300];
    let mut tx = [0u8; 4 * 300];
    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx, &mut tx_meta, &mut tx);
    if socket.bind(53).is_err() {
        crate::init_note("captive DNS could not start; the page is still reachable at http://192.168.4.1/");
        loop {
            Timer::after_secs(3600).await;
        }
    }
    let mut query = [0u8; tdongle_setup::dns::QUERY_MAX];
    let mut reply = [0u8; tdongle_setup::dns::REPLY_MAX];
    loop {
        let Ok((n, meta)) = socket.recv_from(&mut query).await else { continue };
        if let Some(m) = tdongle_setup::dns::reply(&query[..n], &mut reply, tdongle_setup::dns::DONGLE) {
            let _ = socket.send_to(&reply[..m], meta.endpoint).await;
        }
    }
}

/// One HTTP connection at a time per task; the request reader, the router and the response writer are `tdongle-setup`.
#[embassy_executor::task(pool_size = 2)]
async fn http_task(stack: Stack<'static>, portal: &'static Portal) -> ! {
    let mut rx = Box::new([0u8; 1536]);
    let mut tx = Box::new([0u8; 2048]);
    let mut out = Box::new([0u8; 4096]);
    let mut host = FwHost::new();
    let mut buf = Box::new([0u8; 512]);
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx[..], &mut tx[..]);
        socket.set_timeout(Some(Duration::from_secs(10)));
        if socket.accept(80).await.is_err() {
            continue;
        }
        let conn = Conn { peer: endpoint_v4(socket.remote_endpoint()), local: endpoint_v4(socket.local_endpoint()) };
        let mut reader = Box::new(Reader::new(now_ms()));
        'request: loop {
            let n = match with_timeout(Duration::from_millis(u64::from(tdongle_setup::http::RECV_TIMEOUT_MS)), socket.read(&mut buf[..])).await {
                Ok(Ok(n)) if n > 0 => n,
                Ok(_) => break 'request,
                Err(_) => {
                    // the C server's receive timeout: 408, then close
                    let _ = send(&mut socket, &Response::error(ErrCode::Timeout, None, true)).await;
                    break 'request;
                }
            };
            let mut at = 0;
            while at < n {
                let (used, step) = reader.push(&buf[at..n], now_ms());
                at += used;
                match step {
                    Step::More => {
                        if used == 0 {
                            break;
                        }
                    }
                    Step::Reject(e) => {
                        let _ = send(&mut socket, &Response::error(ErrCode::from(e), None, true)).await;
                        break 'request;
                    }
                    Step::Ready => {
                        let close = {
                            let Some(req) = reader.request() else { break 'request };
                            let body = BodyIn { bytes: reader.body(), incomplete: reader.body_incomplete() };
                            let response = portal.serve(&conn, &req, body, &mut host, &mut out[..]);
                            let close = response.close || response.silent || reader.must_close();
                            if !send(&mut socket, &response).await {
                                break 'request;
                            }
                            close
                        };
                        if close {
                            break 'request;
                        }
                        reader = Box::new(Reader::new(now_ms()));
                    }
                }
            }
        }
        let _ = with_timeout(Duration::from_secs(2), socket.flush()).await;
        socket.close();
        let _ = with_timeout(Duration::from_secs(2), socket.flush()).await;
        socket.abort();
    }
}

async fn send(socket: &mut TcpSocket<'_>, response: &Response<'_>) -> bool {
    let mut bytes: Vec<u8> = Vec::new();
    if !response.write(&mut |b| {
        bytes.extend_from_slice(b);
        true
    }) {
        return false;
    }
    let mut at = 0;
    while at < bytes.len() {
        match socket.write(&bytes[at..]).await {
            Ok(n) if n > 0 => at += n,
            _ => return false,
        }
    }
    true
}

/// The control check (`gateway_display_tick`'s setup part and the failsafe): the session is over, or the access point never came up, or the page said Done.
#[embassy_executor::task]
async fn control_task(portal: &'static Portal) -> ! {
    loop {
        match with_timeout(Duration::from_millis(20), LEAVE.wait()).await {
            Ok(()) => {
                Timer::after_millis(300).await; // the response to the page that asked is on the wire first
                restart(Request::Leave, 0)
            }
            Err(_) => {
                if portal.tick(now_ms(), AP_UP.load(Ordering::Relaxed)) == Tick::Leave {
                    restart(Request::Leave, 0)
                }
            }
        }
    }
}

/// The setup boot. Does not return: the radio and the scans stay in this task until the control task restarts the chip.
pub async fn run(
    boot: SetupBoot,
    wifi: esp_hal::peripherals::WIFI<'static>,
    rng: esp_hal::peripherals::RNG<'static>,
    adc: esp_hal::peripherals::ADC1<'static>,
    spawner: embassy_executor::Spawner,
) -> ! {
    ACTIVE.store(true, Ordering::Relaxed);
    START_MS.store(now_ms(), Ordering::Relaxed);
    // True random bytes before the radio runs (`setup_random`): the token must not be guessable.
    let mut random = [0u8; 16];
    {
        let _source = esp_hal::rng::TrngSource::new(rng, adc);
        match esp_hal::rng::Trng::try_new() {
            Ok(t) => t.read(&mut random),
            Err(_) => crate::init_note("no true random source: setup token not available"),
        }
    }
    // never an all-zero token: without randomness the portal is not served; the session ends at the end of the grace period
    let random_ok = random != [0u8; 16];
    let mac: [u8; 6] = esp_hal::efuse::base_mac_address().as_bytes().try_into().unwrap_or([0; 6]);
    let portal: &'static Portal = PORTAL.init(Portal::new(&boot, &random, &mac, now_ms()));
    critical_section::with(|cs| {
        SESSION.borrow(cs).set(*portal.session());
        AP_NAME.borrow(cs).set(*portal.ap_name());
        PORTAL_REF.borrow(cs).set(Some(portal));
    });
    spawner.spawn(control_task(portal).unwrap());
    if !random_ok {
        crate::init_note("setup token not generated; leaving setup");
        loop {
            Timer::after_secs(3600).await;
        }
    }

    crate::guard::stage(tdongle_boot_guard::Stage::RadioInit);
    let mut controller: WifiController<'static> = match WifiController::new(wifi, ControllerConfig::default().with_tx_queue_size(4).with_rx_queue_size(8)) {
        Ok(c) => c,
        Err(_) => {
            crate::init_note("setup: radio init failed");
            loop {
                Timer::after_secs(3600).await;
            }
        }
    };
    let name = portal.ap_name();
    let ssid = core::str::from_utf8(name).unwrap_or("TDongle");
    let ap = match ssid.try_into() {
        Ok(s) => AccessPointConfig::default().with_ssid(s).with_authentication(AuthenticationMethodConfig::Open).with_channel(1).with_max_connections(2),
        Err(_) => {
            crate::init_note("setup: bad access point name");
            loop {
                Timer::after_secs(3600).await;
            }
        }
    };
    if controller.set_config(&Config::AccessPointStation(StationConfig::default(), ap)).is_err() {
        crate::init_note("setup: access point did not start");
        loop {
            Timer::after_secs(3600).await;
        }
    }
    let _ = controller.set_power_saving(esp_radio::wifi::PowerSaveMode::None);

    let device = Interface::access_point();
    let ap_mac = device.mac_address();
    static RESOURCES: StaticCell<StackResources<8>> = StaticCell::new();
    let config = embassy_net::Config::ipv4_static(StaticConfigV4 { address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 4, 1), 24), gateway: None, dns_servers: Default::default() });
    let seed = u64::from(esp_hal::rng::Rng::new().random()) << 32 | u64::from(esp_hal::rng::Rng::new().random());
    let (stack, runner) = embassy_net::new(device, config, RESOURCES.init(StackResources::new()), seed);
    spawner.spawn(net_task(runner).unwrap());
    spawner.spawn(dns_task(stack).unwrap());
    spawner.spawn(crate::dhcp::task(stack, ap_mac).unwrap());
    for _ in 0..2 {
        spawner.spawn(http_task(stack, portal).unwrap());
    }
    AP_UP.store(true, Ordering::Relaxed);

    // The scans: the page asks over HTTP, the console over serial; both read the table `scan_all` fills.
    loop {
        embassy_futures::select::select(SCAN_REQ.wait(), crate::SCAN_REQ.wait()).await;
        let _ = crate::scan_all(&mut controller).await;
        let mut list = ScanList::new();
        crate::scan_rows(|ssid, rssi, secure| list.offer(ssid, rssi, secure));
        critical_section::with(|cs| *SCAN_LIST.borrow_ref_mut(cs) = list);
        SCANNED.store(true, Ordering::Relaxed);
        SCANNING.store(false, Ordering::Relaxed);
    }
}
