#![no_std]
#![no_main]
extern crate alloc;
use embassy_executor::Spawner;
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, channel::Channel};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_hal::{
    Async,
    clock::CpuClock,
    timer::timg::TimerGroup,
    usb::usb_serial_jtag::{UsbSerialJtag, UsbSerialJtagRx, UsbSerialJtagTx},
};
use esp_radio::wifi::{AuthenticationMethodConfig, Config, ControllerConfig, Interface, WifiController, sta::StationConfig};
use portable_atomic::{AtomicBool, AtomicU64, Ordering};
use static_cell::StaticCell;
use tdongle_serial_ip as wire;
use tdongle_tailnet_types::Entropy;
use tdongle_tailnet_usbnet::napt::{NaptConfig, Verdict};
use tdongle_tailnet_wifimux::{InfoHandle, NaptTap, RawPort, SharedNapt, StackDriver, WifiMux};

esp_bootloader_esp_idf::esp_app_desc!();
const QUEUE: usize = 4;
const FLOWS: usize = 64;
const SESSION_TIMEOUT_MS: u64 = 10_000;
const CONFIG: NaptConfig = NaptConfig { udp_idle_ms: 60_000, min_new_flow_port: 1, ..NaptConfig::C };
static NAPT: SharedNapt<FLOWS> = SharedNapt::new_const(CONFIG);
static SESSION: AtomicU64 = AtomicU64::new(0);
static LAST_SEEN: AtomicU64 = AtomicU64::new(0);
static WIFI_SESSION: AtomicU64 = AtomicU64::new(0);
static READY: AtomicBool = AtomicBool::new(false);
static TX: Channel<CriticalSectionRawMutex, Message, QUEUE> = Channel::new();
static CONTROL: Channel<CriticalSectionRawMutex, Message, 4> = Channel::new();
static JOIN: Channel<CriticalSectionRawMutex, Join, 1> = Channel::new();
type Mux = WifiMux<Interface, NaptTap<'static, FLOWS>, QUEUE, QUEUE>;
type Driver = StackDriver<'static, Interface, NaptTap<'static, FLOWS>, QUEUE, QUEUE>;
type Port = RawPort<'static, QUEUE, QUEUE>;
type Info = InfoHandle<'static, QUEUE, QUEUE>;
struct Message {
    kind: u8,
    session: u64,
    len: usize,
    bytes: [u8; wire::MTU],
}
struct Join {
    session: u64,
    len: usize,
    bytes: [u8; 96],
}
impl Drop for Join {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) {
        esp_hal::rng::Rng::new().read(out);
    }
}
fn now() -> u64 {
    Instant::now().as_millis()
}
fn send(kind: u8, session: u64, bytes: &[u8]) {
    if bytes.len() > wire::MTU {
        return;
    }
    let mut m = Message { kind, session, len: bytes.len(), bytes: [0; wire::MTU] };
    m.bytes[..bytes.len()].copy_from_slice(bytes);
    if kind == wire::IP {
        let _ = TX.try_send(m);
    } else {
        let _ = CONTROL.try_send(m);
    } // control cannot be starved by bulk packets
}
fn status(session: u64, code: u8, dns: [u8; 4]) {
    send(wire::STATUS, session, &[code, dns[0], dns[1], dns[2], dns[3]]);
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    esp_hal::system::software_reset()
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 160 * 1024);
    let timer = TimerGroup::new(p.TIMG0);
    esp_rtos::start(timer.timer0, p.FROM_CPU_INTR0);
    let usb = UsbSerialJtag::new(p.USB_DEVICE).into_async();
    let (rx, tx) = usb.split();
    let wifi = WifiController::new(p.WIFI, ControllerConfig::default()).unwrap();
    let interface = Interface::station();
    static MUX: StaticCell<Mux> = StaticCell::new();
    let mux = MUX.init(WifiMux::new(interface, NaptTap::new(&NAPT)).unwrap());
    let (driver, port) = mux.split();
    let info = port.info();
    static RES: StaticCell<embassy_net::StackResources<3>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(driver, embassy_net::Config::dhcpv4(Default::default()), RES.init(embassy_net::StackResources::new()), 0x54444f4e);
    NAPT.seed(&mut Random);
    spawner.spawn(net(runner).unwrap());
    spawner.spawn(write_usb(tx).unwrap());
    spawner.spawn(read_usb(rx, port, info, stack).unwrap());
    spawner.spawn(wifi_task(wifi, info).unwrap());
    let mut last_expire = now();
    loop {
        info.refresh(&stack);
        let session = SESSION.load(Ordering::Relaxed);
        let valid = session != 0 && now().saturating_sub(LAST_SEEN.load(Ordering::Relaxed)) < SESSION_TIMEOUT_MS;
        let ready = valid && WIFI_SESSION.load(Ordering::Relaxed) == session && stack.is_config_up() && stack.is_link_up();
        if READY.swap(ready, Ordering::Relaxed) && !ready {
            info.new_association();
            status(session, 0, [0; 4]);
        }
        if !valid && session != 0 {
            SESSION.store(0, Ordering::Relaxed);
            info.new_association();
        }
        if now() - last_expire >= 2000 {
            NAPT.with(|n| {
                n.expire(now());
            });
            last_expire = now();
        }
        let mut packet = [0; wire::MTU];
        for _ in 0..8 {
            let Some(n) = port.try_next_to_host(&mut packet) else {
                break;
            };
            if ready && wire::ipv4(&packet[..n], false) {
                send(wire::IP, session, &packet[..n]);
            }
        }
        Timer::after_millis(5).await;
    }
}
#[embassy_executor::task]
async fn net(mut runner: embassy_net::Runner<'static, Driver>) {
    runner.run().await
}
#[embassy_executor::task]
async fn write_usb(mut tx: UsbSerialJtagTx<'static, Async>) {
    use embedded_io_async::Write;
    let mut buf = [0; wire::MAX_WIRE];
    loop {
        let m = match embassy_futures::select::select(CONTROL.receive(), TX.receive()).await {
            embassy_futures::select::Either::First(m) | embassy_futures::select::Either::Second(m) => m,
        };
        if m.session != SESSION.load(Ordering::Relaxed) {
            continue;
        }
        if let Some(n) = wire::encode(m.kind, m.session, &m.bytes[..m.len], &mut buf) {
            let _ = with_timeout(Duration::from_secs(2), async {
                tx.write_all(&buf[..n]).await?;
                tx.flush().await
            })
            .await;
        }
    }
}
#[embassy_executor::task]
async fn read_usb(mut rx: UsbSerialJtagRx<'static, Async>, port: Port, info: Info, stack: embassy_net::Stack<'static>) {
    use embedded_io_async::Read;
    let mut decoder = wire::Decoder::new();
    let mut buf = [0; 256];
    loop {
        let n = match rx.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => {
                Timer::after_millis(20).await;
                continue;
            }
        };
        for &b in &buf[..n] {
            let Some(f) = decoder.feed(b) else {
                continue;
            };
            if f.kind == wire::HELLO && f.session != 0 && f.payload.is_empty() {
                WIFI_SESSION.store(0, Ordering::Relaxed);
                SESSION.store(f.session, Ordering::Relaxed);
                READY.store(false, Ordering::Relaxed);
                info.new_association();
                LAST_SEEN.store(now(), Ordering::Relaxed);
                send(wire::IDENTITY, f.session, wire::BOARD);
                continue;
            }
            if f.session == 0 || f.session != SESSION.load(Ordering::Relaxed) {
                continue;
            }
            LAST_SEEN.store(now(), Ordering::Relaxed);
            match f.kind {
                wire::JOIN => {
                    if wire::credentials(f.payload).is_none() {
                        status(f.session, 2, [0; 4]);
                        continue;
                    }
                    let mut j = Join { session: f.session, len: f.payload.len(), bytes: [0; 96] };
                    j.bytes[..j.len].copy_from_slice(f.payload);
                    if JOIN.try_send(j).is_err() {
                        status(f.session, 2, [0; 4]);
                    }
                }
                wire::PING => {
                    let cfg = stack.config_v4();
                    let dns = cfg.and_then(|c| c.dns_servers.first().copied()).unwrap_or(embassy_net::Ipv4Address::new(1, 1, 1, 1));
                    status(f.session, if READY.load(Ordering::Relaxed) { 1 } else { 0 }, dns.octets());
                }
                wire::STOP => {
                    SESSION.store(0, Ordering::Relaxed);
                    READY.store(false, Ordering::Relaxed);
                    info.new_association();
                }
                wire::IP if READY.load(Ordering::Relaxed) && wire::ipv4(f.payload, true) => {
                    let mut packet = [0; wire::MTU];
                    packet[..f.payload.len()].copy_from_slice(f.payload);
                    if let Verdict::Forward { len, .. } = NAPT.outbound(now(), &mut packet[..f.payload.len()]) {
                        let _ = port.try_send(&packet[..usize::from(len)]);
                    }
                }
                _ => {}
            }
        }
    }
}
#[embassy_executor::task]
async fn wifi_task(mut wifi: WifiController<'static>, info: Info) {
    loop {
        let j = JOIN.receive().await;
        if j.session != SESSION.load(Ordering::Relaxed) {
            continue;
        }
        READY.store(false, Ordering::Relaxed);
        info.new_association();
        let _ = wifi.disconnect_async().await;
        let Some((ssid, pass)) = wire::credentials(&j.bytes[..j.len]) else {
            continue;
        };
        let auth = if pass.is_empty() { AuthenticationMethodConfig::Open } else { AuthenticationMethodConfig::Wpa2Personal(pass.try_into().unwrap()) };
        let cfg = StationConfig::default().with_ssid(ssid.try_into().unwrap()).with_authentication(auth);
        if wifi.set_config(&Config::Station(cfg)).is_err() {
            status(j.session, 2, [0; 4]);
            continue;
        }
        let mut failures: u32 = 0;
        while j.session == SESSION.load(Ordering::Relaxed) {
            if !wifi.is_connected() {
                info.new_association();
                match with_timeout(Duration::from_secs(20), wifi.connect_async()).await {
                    Ok(Ok(_)) => {
                        failures = 0;
                        WIFI_SESSION.store(j.session, Ordering::Relaxed);
                    }
                    _ => {
                        status(j.session, 3, [0; 4]);
                        // Reuse the bounded retry policy from the shared S3 codebase.
                        let delay = tdongle_wifi_policy::retry::retry_delay_ms(failures);
                        failures = failures.saturating_add(1);
                        // A fresh Android session must not wait out the previous one's backoff.
                        let retry_at = now() + u64::from(delay);
                        while j.session == SESSION.load(Ordering::Relaxed) && now() < retry_at {
                            Timer::after_millis(retry_at.saturating_sub(now()).min(250)).await;
                        }
                    }
                }
            }
            Timer::after_millis(250).await;
        }
        let _ = wifi.disconnect_async().await;
    }
}
