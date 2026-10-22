//! Multiplexed IP and management over C5 USB Serial/JTAG. Every packet uses the shared gateway runtime.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, channel::Channel, mutex::Mutex};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_hal::usb::usb_serial_jtag::{UsbSerialJtag, UsbSerialJtagRx, UsbSerialJtagTx};
use portable_atomic::AtomicU64;
use tdongle_serial_ip as wire;
use tdongle_tailnet_usbnet::wire::{ETHERTYPE_ARP, ETHERTYPE_IPV4, write_eth};
use wire::{COMMAND, REPLY};
pub static FROZEN: AtomicBool = AtomicBool::new(false);
static SESSION: AtomicU64 = AtomicU64::new(0);
static CONSOLE_SESSION: AtomicU64 = AtomicU64::new(0);
static SEEN: AtomicU64 = AtomicU64::new(0);
static CONTROL: Channel<CriticalSectionRawMutex, (u8, u64, Vec<u8>), 8> = Channel::new();
static DATA: Channel<CriticalSectionRawMutex, (u8, u64, Vec<u8>), 4> = Channel::new();
static CONSOLE: Channel<CriticalSectionRawMutex, (u64, Vec<u8>), 2> = Channel::new();
const HOST_MAC: [u8; 6] = [2, 0, 0, 0, 0x77, 2];
pub struct Reader {
    pending: Vec<u8>,
    offset: usize,
    session: u64,
}
pub struct Writer;
impl Reader {
    pub async fn wait_connection(&mut self) {
        while SESSION.load(Ordering::Relaxed) == 0 {
            Timer::after_millis(100).await;
        }
    }
    pub async fn read_packet(&mut self, out: &mut [u8]) -> Result<usize, ()> {
        if self.offset != self.pending.len() && self.session != SESSION.load(Ordering::Relaxed) {
            self.pending.clear();
            self.offset = 0;
            return Err(());
        }
        if self.offset == self.pending.len() {
            loop {
                let (session, bytes) = CONSOLE.receive().await;
                if session == SESSION.load(Ordering::Relaxed) && session != 0 {
                    CONSOLE_SESSION.store(session, Ordering::Relaxed);
                    self.pending = bytes;
                    self.session = session;
                    break;
                }
            }
            self.offset = 0;
        }
        let n = out.len().min(self.pending.len() - self.offset);
        out[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}
impl Writer {
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), ()> {
        for b in bytes.chunks(wire::MTU) {
            CONTROL.send((REPLY, CONSOLE_SESSION.load(Ordering::Relaxed), b.to_vec())).await;
        }
        Ok(())
    }
}
pub fn start(p: esp_hal::peripherals::USB_DEVICE<'static>, spawner: embassy_executor::Spawner) -> (Reader, &'static Mutex<CriticalSectionRawMutex, Writer>) {
    let (rx, tx) = UsbSerialJtag::new(p).into_async().split();
    static WRITER: static_cell::StaticCell<Mutex<CriticalSectionRawMutex, Writer>> = static_cell::StaticCell::new();
    let w = WRITER.init(Mutex::new(Writer));
    let _ = crate::tailnet::WRITER.init(w);
    spawner.spawn(read(rx).unwrap());
    spawner.spawn(write(tx).unwrap());
    spawner.spawn(lease().unwrap());
    (Reader { pending: Vec::new(), offset: 0, session: 0 }, w)
}
pub fn connected() -> bool {
    SESSION.load(Ordering::Relaxed) != 0
}
pub fn disconnect() {
    CONSOLE_SESSION.store(0, Ordering::Relaxed);
    SESSION.store(0, Ordering::Relaxed);
    crate::supervise::USB_CONFIGURED.store(false, Ordering::Relaxed);
    if !super::mode::wireless() {
        crate::tailnet::clear_host_queue();
        crate::USB_GEN.fetch_add(1, Ordering::Relaxed);
        crate::ALT.store(0, Ordering::Relaxed);
        crate::CONFIGURED.store(false, Ordering::Relaxed);
    }
}
pub fn send_frame(frame: &[u8]) -> tdongle_bridge::RingSend {
    if super::mode::wireless() {
        return if crate::l2::tx_ap(frame) {
            crate::DOWN_BYTES.fetch_add(frame.len() as u32, Ordering::Relaxed);
            crate::DOWN_FRAMES.fetch_add(1, Ordering::Relaxed);
            tdongle_bridge::RingSend::Accepted
        } else {
            tdongle_bridge::RingSend::NotReady
        };
    }
    if SESSION.load(Ordering::Relaxed) == 0 {
        return tdongle_bridge::RingSend::NotReady;
    }
    if frame.len() < 14 {
        return tdongle_bridge::RingSend::Invalid;
    }
    if frame[12..14] == ETHERTYPE_ARP.to_be_bytes() {
        if frame.len() >= 42 && frame[20..22] == [0, 1] && frame[38..42] == wire::HOST {
            let mut reply = [0; 42];
            write_eth(&mut reply, local_mac(), HOST_MAC, ETHERTYPE_ARP);
            reply[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
            reply[22..28].copy_from_slice(&HOST_MAC);
            reply[28..32].copy_from_slice(&wire::HOST);
            reply[32..38].copy_from_slice(&local_mac());
            reply[38..42].copy_from_slice(&wire::GATEWAY);
            let _ = crate::tailnet::try_host_rx(&reply);
        }
        return tdongle_bridge::RingSend::Accepted;
    }
    if frame[12..14] != ETHERTYPE_IPV4.to_be_bytes() || !wire::ipv4(&frame[14..], false) {
        return tdongle_bridge::RingSend::Invalid;
    }
    if DATA.try_send((wire::IP, SESSION.load(Ordering::Relaxed), frame[14..].to_vec())).is_ok() {
        crate::DOWN_BYTES.fetch_add((frame.len() - 14) as u32, Ordering::Relaxed);
        crate::DOWN_FRAMES.fetch_add(1, Ordering::Relaxed);
        tdongle_bridge::RingSend::Accepted
    } else {
        tdongle_bridge::RingSend::NotReady
    }
}
fn local_mac() -> [u8; 6] {
    tdongle_tailnet_runtime::usb::derive_usb_mac(esp_hal::efuse::base_mac_address().as_bytes().try_into().unwrap())
}
async fn learn_host() {
    let mut arp = [0; 42];
    write_eth(&mut arp, local_mac(), HOST_MAC, ETHERTYPE_ARP);
    arp[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    arp[22..28].copy_from_slice(&HOST_MAC);
    arp[28..32].copy_from_slice(&wire::HOST);
    arp[38..42].copy_from_slice(&wire::GATEWAY);
    let _ = crate::tailnet::usb_rx(&arp).await;
}
#[embassy_executor::task]
async fn read(mut rx: UsbSerialJtagRx<'static, esp_hal::Async>) {
    use embedded_io_async::Read;
    let mut input = [0; 256];
    let mut decoder = wire::Decoder::new();
    loop {
        if FROZEN.load(Ordering::Relaxed) {
            Timer::after_secs(1).await;
            continue;
        }
        let n = match rx.read(&mut input).await {
            Ok(n) => n,
            Err(_) => {
                Timer::after_millis(20).await;
                continue;
            }
        };
        for b in &input[..n] {
            let Some(f) = decoder.feed(*b) else { continue };
            if f.kind == wire::HELLO && f.session != 0 && f.payload.is_empty() {
                disconnect();
                SESSION.store(f.session, Ordering::Relaxed);
                SEEN.store(Instant::now().as_millis(), Ordering::Relaxed);
                if !super::mode::wireless() {
                    crate::ALT.store(1, Ordering::Relaxed);
                    crate::CONFIGURED.store(true, Ordering::Relaxed);
                }
                crate::supervise::USB_CONFIGURED.store(true, Ordering::Relaxed);
                let _ = CONTROL.try_send((wire::IDENTITY, f.session, wire::BOARD.to_vec()));
                continue;
            }
            if f.session == 0 || f.session != SESSION.load(Ordering::Relaxed) {
                continue;
            }
            SEEN.store(Instant::now().as_millis(), Ordering::Relaxed);
            match f.kind {
                COMMAND
                    if !f.payload.is_empty()
                        && f.payload.len() <= tdongle_serial::console::LINE_CHARS_MAX
                        && f.payload.iter().all(|b| (32..=126).contains(b)) =>
                {
                    let mut command = f.payload.to_vec();
                    command.push(b'\n');
                    let _ = CONSOLE.try_send((f.session, command));
                }
                wire::PING => {
                    // Local gateway readiness is independent of upstream reachability.
                    let ready = crate::tailnet::active() && !super::mode::wireless();
                    let _ = CONTROL.try_send((wire::STATUS, f.session, alloc::vec![u8::from(ready), 192, 168, 77, 1]));
                }
                wire::JOIN => {
                    if let Some((ssid, pass)) = wire::credentials(f.payload) {
                        let save = crate::settings::WifiSave {
                            ssid: ssid.as_bytes().to_vec(),
                            password: pass.as_bytes().to_vec(),
                            name: None,
                            priority: 50,
                            slot: -1,
                        };
                        let _ = crate::settings::call(crate::settings::Req::Wifi(alloc::boxed::Box::new(save))).await;
                    }
                }
                wire::IP if crate::tailnet::active() && !super::mode::wireless() && wire::ipv4(f.payload, true) => {
                    learn_host().await;
                    let mut frame = [0; 1514];
                    write_eth(&mut frame, local_mac(), HOST_MAC, ETHERTYPE_IPV4);
                    frame[14..14 + f.payload.len()].copy_from_slice(f.payload);
                    if crate::tailnet::usb_rx(&frame[..14 + f.payload.len()]).await {
                        crate::UP_BYTES.fetch_add(f.payload.len() as u32, Ordering::Relaxed);
                        crate::UP_FRAMES.fetch_add(1, Ordering::Relaxed);
                    }
                }
                wire::STOP => disconnect(),
                _ => {}
            }
        }
    }
}
#[embassy_executor::task]
async fn write(mut tx: UsbSerialJtagTx<'static, esp_hal::Async>) {
    use embedded_io_async::Write;
    let mut buffer = [0; wire::MAX_WIRE];
    loop {
        let (kind, session, bytes) = match embassy_futures::select::select(CONTROL.receive(), DATA.receive()).await {
            embassy_futures::select::Either::First(m) | embassy_futures::select::Either::Second(m) => m,
        };
        if session == 0 || session != SESSION.load(Ordering::Relaxed) {
            continue;
        }
        if let Some(n) = wire::encode(kind, session, &bytes, &mut buffer) {
            let _ = with_timeout(Duration::from_secs(2), async {
                tx.write_all(&buffer[..n]).await?;
                tx.flush().await
            })
            .await;
        }
    }
}
#[embassy_executor::task]
async fn lease() {
    loop {
        if SESSION.load(Ordering::Relaxed) != 0 && Instant::now().as_millis().saturating_sub(SEEN.load(Ordering::Relaxed)) > 10_000 {
            disconnect();
        }
        Timer::after_millis(250).await;
    }
}
