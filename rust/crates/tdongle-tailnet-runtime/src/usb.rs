//! The USB task: Ethernet frames from the host through `tdongle_tailnet_usbnet` (ARP, DHCP) to the engine (alias traffic, DNS queries) and the NAT
//! (everything else), and everything bound for the host (tunnel packets, DNS answers, NAT replies) back out as frames.
//!
//! The Ethernet side of the C's lwIP netif is `UsbNet` (192.168.77.1/24, the host gets 192.168.77.2+ from its DHCP server); its NAT table is **not** used
//! here: the table belongs to `tdongle-tailnet-wifimux` (shared with the Wi-Fi receive tap), reached through [`WifiRaw`]. So this module replays the
//! dispatch of `UsbNet::host_frame` with that one substitution (the dispatch is 30 lines and its order is the C's: alias, then local, then NAT).
//!
//! Back-pressure (ADR 0023): a frame is read from the host only when the loop is back at `usb.recv`, and everything the loop does between two reads is
//! bounded and never waits (every queue is non-blocking). A frame for a tailnet peer is held until its membership's egress queues have room for a full
//! packet (at most [`HOLD_MAX_MS`]: one congested relay must not stall the others for ever), and the loop does not call `usb.recv` while it holds one, so a
//! slow relay makes the host's driver see NAKs (its queue, not ours, absorbs the burst) instead of the dongle dropping what it already accepted. What the
//! queues still refuse after the hold is counted (`RtStats::out_refused`, the engine's `TxRefused`).

use crate::shared::{HOST_DNS, HOST_IP, RtStats, Shared};
use crate::wifi::WifiRaw;
use embassy_futures::select::{Either4, select4};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Timer;
use tdongle_tailnet_dns::Client;
use tdongle_tailnet_engine::{Input, PeerDirectory};
use tdongle_tailnet_fw::{Platform, Storage, UsbFrames};
use tdongle_tailnet_usbnet::UsbNet;
use tdongle_tailnet_usbnet::arp::ArpOutcome;
use tdongle_tailnet_usbnet::csum::{fill_header, l4_checksum};
use tdongle_tailnet_usbnet::dhcp::DhcpOutcome;
use tdongle_tailnet_usbnet::eth::Rx;
use tdongle_tailnet_usbnet::napt::Verdict;
use tdongle_tailnet_usbnet::reply::{ICMP_ERROR_MAX, RST_LEN, build_icmp_error};
use tdongle_tailnet_usbnet::wire::{ETHERTYPE_ARP, ETHERTYPE_IPV4, Mac, USB_IP, USB_MASK, is_alias, rd16, rd32, wr16, wr32, write_eth};

/// The longest a frame waits for room in its membership's egress queues before the engine is allowed to refuse it.
pub const HOLD_MAX_MS: u64 = 100;
/// Room a membership's queues must have before a host frame for it is handed to the engine: one full tunnel packet and its relay framing.
pub const ROOM_BYTES: usize = 1700;

/// The USB side's state (ARP, DHCP, Ethernet filter; the NAT table slot is the smallest legal one and unused).
pub type UsbSide = UsbNet<1, 8, 4>;

/// Largest frame handled (the NCM MTU of 1,500 plus Ethernet).
pub const FRAME_MAX: usize = 1536;

/// The netif's Ethernet address derived from the station MAC (locally administered, never equal to it).
pub fn derive_usb_mac(sta: [u8; 6]) -> Mac {
    let mut m = sta;
    m[0] = (m[0] | 0x02) & !0x01;
    m[5] ^= 0x01;
    m
}

/// Build `frame` = Ethernet header (to the host) + `ip`; returns the length, or `None` if the host's address is not known yet.
fn frame_to_host(un: &UsbSide, ip: &[u8], out: &mut [u8]) -> Option<usize> {
    let (_, host_mac) = un.arp.host()?;
    if out.len() < 14 + ip.len() {
        return None;
    }
    write_eth(out, host_mac, un.eth.local(), ETHERTYPE_IPV4);
    out[14..14 + ip.len()].copy_from_slice(ip);
    Some(14 + ip.len())
}

/// An IPv4/UDP packet from `src:sport` to `dst:dport` with both checksums; returns the length.
pub fn build_udp(src: u32, sport: u16, dst: u32, dport: u16, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = 28 + payload.len();
    if total > out.len() || total > 1500 {
        return None;
    }
    out[..28].fill(0);
    out[0] = 0x45;
    wr16(out, 2, total as u16);
    out[6] = 0x40;
    out[8] = 64;
    out[9] = 17;
    wr32(out, 12, src);
    wr32(out, 16, dst);
    fill_header(out, 20);
    wr16(out, 20, sport);
    wr16(out, 22, dport);
    wr16(out, 24, (8 + payload.len()) as u16);
    out[28..total].copy_from_slice(payload);
    let c = l4_checksum(src, dst, 17, &out[20..total]);
    wr16(out, 26, if c == 0 { 0xffff } else { c });
    Some(total)
}

/// What the USB task does with one frame, for tests: the verdict at the level of the runtime's own actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbAction {
    /// A frame to send back to the host is in the reply buffer.
    Reply(usize),
    /// Handed to the engine as a host packet.
    ToEngine,
    /// Handed to the engine as a DNS query.
    Dns,
    /// Answered an ICMP echo to the dongle in the reply buffer.
    Echo(usize),
    /// Sent to Wi-Fi.
    Napt,
    /// An ICMP error for the host is in the reply buffer.
    Icmp(usize),
    /// Counted and dropped.
    Dropped,
}

/// ICMP echo request to the dongle -> echo reply (in place), as lwIP's `icmp_input` does.
fn echo_reply(pkt: &mut [u8], ihl: usize, total: usize) -> bool {
    if total < ihl + 8 || pkt[ihl] != 8 || pkt[ihl + 1] != 0 {
        return false;
    }
    let (src, dst) = (rd32(pkt, 12), rd32(pkt, 16));
    wr32(pkt, 12, if dst == u32::MAX || dst | !USB_MASK == u32::MAX && dst != USB_IP { USB_IP } else { dst });
    wr32(pkt, 16, src);
    pkt[8] = 64;
    pkt[ihl] = 0;
    wr16(pkt, ihl + 2, 0);
    let c = tdongle_tailnet_usbnet::csum::finish(tdongle_tailnet_usbnet::csum::sum(&pkt[ihl..total], 0));
    wr16(pkt, ihl + 2, c);
    fill_header(pkt, ihl);
    true
}

/// Handle one frame from the host. `reply` receives frames for the host (ARP, DHCP, ICMP); the engine and the Wi-Fi side are called directly.
pub fn host_frame<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory, W: WifiRaw>(
    sh: &Shared<R, P, S, D>,
    un: &mut UsbSide,
    wifi: &W,
    now: u64,
    frame: &mut [u8],
    reply: &mut [u8],
) -> UsbAction {
    let off = match un.eth.ingress(frame) {
        Rx::Dropped(_) => return UsbAction::Dropped,
        Rx::Arp { payload } => {
            return match un.arp.handle(now, payload, reply) {
                ArpOutcome::Replied { len } => UsbAction::Reply(len),
                ArpOutcome::Learned | ArpOutcome::Ignored(_) => UsbAction::Dropped,
            };
        }
        Rx::Ipv4 { .. } => 14usize,
    };
    let pkt = &frame[off..];
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return UsbAction::Dropped;
    }
    let ihl = usize::from(pkt[0] & 15) * 4;
    let total = usize::from(rd16(pkt, 2));
    if ihl < 20 || total < ihl || total > pkt.len() {
        return UsbAction::Dropped;
    }
    let dst = rd32(pkt, 16);
    if is_alias(dst) {
        RtStats::bump(&sh.stats.to_engine);
        let _ = sh.feed(Input::HostPacket { buf: &mut frame[off..], len: total });
        return UsbAction::ToEngine;
    }
    let for_us = dst == USB_IP || dst == (USB_IP | !USB_MASK) || dst == u32::MAX;
    if for_us {
        if pkt[9] == 17 && total >= ihl + 8 && rd16(pkt, ihl + 2) == 67 {
            return match un.dhcp.handle_frame(now, frame, reply) {
                DhcpOutcome::Reply { len, .. } => UsbAction::Reply(len),
                DhcpOutcome::Silent(_) => UsbAction::Dropped,
            };
        }
        return local(sh, un, off, ihl, total, frame, reply);
    }
    let verdict = wifi.nat_outbound(now, &mut frame[off..]);
    match verdict {
        Verdict::Forward { len, .. } => {
            if wifi.try_send(&frame[off..off + usize::from(len)]) {
                RtStats::bump(&sh.stats.napt_forwarded);
            } else {
                RtStats::bump(&sh.stats.wifi_refused);
            }
            UsbAction::Napt
        }
        Verdict::Reject(r) => {
            RtStats::bump(&sh.stats.napt_refused);
            let mut ip = [0u8; ICMP_ERROR_MAX];
            match build_icmp_error(r.icmp, &frame[off..off + total], USB_IP, &mut ip) {
                Some(n) => match frame_to_host(un, &ip[..n], reply) {
                    Some(m) => UsbAction::Icmp(m),
                    None => UsbAction::Dropped,
                },
                None => UsbAction::Dropped,
            }
        }
        Verdict::Local(_) => local(sh, un, off, ihl, total, frame, reply),
        Verdict::Drop(_) => {
            RtStats::bump(&sh.stats.napt_refused);
            UsbAction::Dropped
        }
    }
}

/// A packet for the dongle's own address: DNS (the engine's responder), ICMP echo, anything else is counted.
fn local<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(
    sh: &Shared<R, P, S, D>,
    un: &UsbSide,
    off: usize,
    ihl: usize,
    total: usize,
    frame: &mut [u8],
    reply: &mut [u8],
) -> UsbAction {
    let (proto, src) = (frame[off + 9], rd32(&frame[off..], 12));
    if proto == 17 && total >= ihl + 8 && rd16(&frame[off..], ihl + 2) == 53 {
        let sport = rd16(&frame[off..], ihl);
        RtStats::bump(&sh.stats.dns_in);
        let (a, b) = (off + ihl + 8, off + total);
        let before = sh.with_engine(|e, _| e.aliases().len());
        let _ = sh.feed(Input::Dns { client: Client { addr: src, port: sport }, data: &frame[a..b] });
        if sh.with_engine(|e, _| e.aliases().len()) != before {
            crate::members::persist_aliases(sh);
        }
        return UsbAction::Dns;
    }
    if proto == 1 {
        let pkt = &mut frame[off..off + total];
        if echo_reply(pkt, ihl, total) {
            return match frame_to_host(un, pkt, reply) {
                Some(n) => UsbAction::Echo(n),
                None => UsbAction::Dropped,
            };
        }
    }
    RtStats::bump(&sh.stats.local_other);
    UsbAction::Dropped
}

/// Frame an engine record for the host (`HOST_IP`: a tunnel packet; `HOST_DNS`: a DNS answer) into `out`.
fn host_record(un: &UsbSide, kind: u8, rec: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut ip = [0u8; 1500];
    match kind {
        HOST_IP => {
            let n = rec.len().min(1500);
            ip[..n].copy_from_slice(&rec[..n]);
            frame_to_host(un, &ip[..n], out)
        }
        HOST_DNS => {
            let (meta, data) = (rec.get(..6)?, rec.get(6..)?);
            let client = u32::from_be_bytes([meta[0], meta[1], meta[2], meta[3]]);
            let port = u16::from_be_bytes([meta[4], meta[5]]);
            let n = build_udp(USB_IP, 53, client, port, data, &mut ip)?;
            frame_to_host(un, &ip[..n], out)
        }
        _ => None,
    }
}

fn send_frame<U: UsbFrames, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, usb: &mut U, frame: &[u8]) {
    if usb.send(frame) {
        RtStats::bump(&sh.stats.usb_tx);
    } else {
        RtStats::bump(&sh.stats.usb_tx_refused);
    }
}

/// The reply frame's place in the shared scratch.
const REPLY: core::ops::Range<usize> = 0..FRAME_MAX;
/// The host-queue record sits behind it (`FRAME_MAX + 16` bytes).
const _: () = assert!(2 * FRAME_MAX + 16 <= crate::shared::SCRATCH);

/// Pump wakeups out of the wait, host-queue records and Wi-Fi frames moved to USB, and the most one drain pass moved (`tn_in` line).
pub static PUMP_WAKES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// See [`PUMP_WAKES`].
pub static PUMP_MOVED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// See [`PUMP_WAKES`].
pub static PUMP_PASS_MAX: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The USB task. Never returns.
pub async fn usb_pump<R, P, S, D, U, W>(sh: &Shared<R, P, S, D>, usb: &mut U, wifi: &W)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    U: UsbFrames,
    W: WifiRaw,
{
    let mac = sh.cfg.usb_mac.unwrap_or_else(|| derive_usb_mac(sh.platform.sta_mac()));
    let mut rng = crate::shared::PlatformRng(&sh.platform);
    let mut un = UsbSide::new(mac, &mut rng);
    // `rx` and `wbuf` are waited into (a read pending on them holds them across an await); the reply frame and the host-queue record are only ever
    // in use inside synchronous code, so they live in the shared scratch (the reply at its start, the record behind it) and cost this future nothing.
    let mut rx = [0u8; FRAME_MAX];
    let mut wbuf = [0u8; FRAME_MAX];
    let mut generation = usb.link_generation();
    let mut carrier = false;
    let mut next_tick = sh.now() + 1000;
    loop {
        // ---- everything that is ready for the host, bounded
        PUMP_WAKES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let mut pass = 0u32;
        for _ in 0..16 {
            let more = sh.with_scratch(|s| {
                let (reply, rec) = s.split_at_mut(FRAME_MAX);
                let rec = &mut rec[..FRAME_MAX + 16];
                let Some((kind, n)) = sh.host_q.try_pop(rec) else { return false };
                if let Some(len) = host_record(&un, kind, &rec[..n], reply) {
                    send_frame(sh, usb, &reply[..len]);
                }
                true
            });
            if !more {
                break;
            }
            pass += 1;
        }
        PUMP_MOVED.fetch_add(pass, core::sync::atomic::Ordering::Relaxed);
        PUMP_PASS_MAX.fetch_max(pass, core::sync::atomic::Ordering::Relaxed);
        for _ in 0..16 {
            let Some(n) = wifi.try_next_to_host(&mut wbuf) else { break };
            sh.with_scratch(|s| {
                if let Some(len) = frame_to_host(&un, &wbuf[..n], &mut s[REPLY]) {
                    send_frame(sh, usb, &s[REPLY][..len]);
                }
            });
        }
        // ---- housekeeping
        let now = sh.now();
        if now >= next_tick {
            next_tick = now + 1000;
            let _ = un.tick(now);
            let _ = wifi.nat_tick(now);
            let g = usb.link_generation();
            if g != generation {
                generation = g;
                let _ = sh.feed(Input::UsbDetach);
            }
            let want = sh.ready_count.load(core::sync::atomic::Ordering::Acquire) != 0 && usb.host_ready();
            if want != carrier {
                carrier = want;
                usb.set_carrier(carrier);
            }
            while let Some(r) = wifi.pop_rst() {
                let mut p = [0u8; RST_LEN];
                r.to_host(&mut p);
                sh.with_scratch(|s| {
                    if let Some(len) = frame_to_host(&un, &p, &mut s[REPLY]) {
                        send_frame(sh, usb, &s[REPLY][..len]);
                    }
                });
                if let Some(v4) = sh.link.try_get().and_then(|l| l.v4) {
                    r.to_remote(v4.addr_u32(), &mut p);
                    let _ = wifi.try_send(&p);
                }
            }
        }
        // ---- wait
        let wait = next_tick.saturating_sub(sh.now()).max(1);
        match select4(usb.recv(&mut rx), sh.host_q.wait_nonempty(), wifi.next_to_host(&mut wbuf), async {
            futures_either(sh.carrier_kick.wait(), Timer::after_millis(wait)).await
        })
        .await
        {
            Either4::First(n) => {
                RtStats::bump(&sh.stats.usb_rx);
                let n = n.min(rx.len());
                if wants_local_stack(&rx[..n]) {
                    usb.local_frame(&rx[..n]);
                }
                hold_for_room(sh, &rx[..n]).await;
                sh.with_scratch(|s| {
                    if let UsbAction::Reply(len) | UsbAction::Echo(len) | UsbAction::Icmp(len) = host_frame(sh, &mut un, wifi, sh.now(), &mut rx[..n], &mut s[REPLY]) {
                        send_frame(sh, usb, &s[REPLY][..len]);
                    }
                });
            }
            Either4::Second(()) => {}
            Either4::Third(n) => {
                sh.with_scratch(|s| {
                    if let Some(len) = frame_to_host(&un, &wbuf[..n], &mut s[REPLY]) {
                        send_frame(sh, usb, &s[REPLY][..len]);
                    }
                });
            }
            Either4::Fourth(()) => {}
        }
    }
}

/// Frames the image's own TCP stack on the USB side must see: ARP replies (it resolves the host's address itself) and TCP segments to the dongle's address.
fn wants_local_stack(frame: &[u8]) -> bool {
    if frame.len() < 34 {
        return false;
    }
    match rd16(frame, 12) {
        ETHERTYPE_ARP => frame.len() >= 22 && rd16(frame, 20) == 2,
        ETHERTYPE_IPV4 => frame[14 + 9] == 6 && rd32(frame, 14 + 16) == USB_IP,
        _ => false,
    }
}

/// Hold a frame destined to a tailnet peer until its membership's queues have room (bounded by [`HOLD_MAX_MS`]).
async fn hold_for_room<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, frame: &[u8]) {
    if frame.len() < 34 || rd16(frame, 12) != ETHERTYPE_IPV4 {
        return;
    }
    let dst = rd32(frame, 14 + 16);
    if !is_alias(dst) {
        return;
    }
    let Some(member) = sh.with_engine(|e, _| e.aliases().owner(dst)).map(|(m, _)| m) else { return };
    let Some((_, slot)) = sh.slot_of(member) else { return };
    let start = sh.now();
    // the relay's queue is elastic: room means room in its byte bound and heap above the floor for a block of this size
    while (!slot.derp_q.has_room(ROOM_BYTES, sh.mem().heap.free()) || slot.udp_q.free_bytes() < ROOM_BYTES) && sh.now().saturating_sub(start) < HOLD_MAX_MS {
        Timer::after_millis(1).await;
    }
}

async fn futures_either<A: core::future::Future<Output = ()>, B: core::future::Future<Output = ()>>(a: A, b: B) {
    let _ = embassy_futures::select::select(a, b).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Sh, shared};
    use core::cell::{Cell, RefCell};
    use std::vec::Vec;
    use tdongle_tailnet_types::Millis;
    use tdongle_tailnet_usbnet::csum;
    use tdongle_tailnet_usbnet::napt::{DropReason, Reject, RejectReason};
    use tdongle_tailnet_usbnet::reply::IcmpKind;
    use tdongle_tailnet_usbnet::wire::{BROADCAST_MAC, ETHERTYPE_ARP, ip4};

    const HOST_MAC: Mac = [0x02, 0, 0, 0, 0x77, 0x02];
    const HOST_IP: u32 = ip4(192, 168, 77, 2);

    struct FakeWifi {
        verdict: Cell<Verdict>,
        sent: RefCell<Vec<Vec<u8>>>,
        accept: Cell<bool>,
    }

    impl FakeWifi {
        fn new(v: Verdict) -> Self {
            FakeWifi { verdict: Cell::new(v), sent: RefCell::new(Vec::new()), accept: Cell::new(true) }
        }
    }

    impl WifiRaw for FakeWifi {
        fn nat_outbound(&self, _: Millis, _: &mut [u8]) -> Verdict {
            self.verdict.get()
        }
        fn try_send(&self, l3: &[u8]) -> bool {
            self.sent.borrow_mut().push(l3.to_vec());
            self.accept.get()
        }
        async fn next_to_host(&self, _: &mut [u8]) -> usize {
            core::future::pending().await
        }
        fn try_next_to_host(&self, _: &mut [u8]) -> Option<usize> {
            None
        }
        fn nat_tick(&self, _: Millis) -> usize {
            0
        }
        fn stack_config_changed(&self) {}
        fn new_association(&self) {}
    }

    fn side(sh: &Sh) -> UsbSide {
        let mut rng = crate::shared::PlatformRng(&sh.platform);
        UsbSide::new(derive_usb_mac(sh.platform.sta_mac()), &mut rng)
    }

    fn ip_frame(dst_mac: Mac, ip: &[u8]) -> Vec<u8> {
        let mut f = std::vec![0u8; 14];
        write_eth(&mut f, dst_mac, HOST_MAC, ETHERTYPE_IPV4);
        f.extend_from_slice(ip);
        f
    }

    fn arp_request(for_ip: u32) -> Vec<u8> {
        let mut f = std::vec![0u8; 42];
        write_eth(&mut f, BROADCAST_MAC, HOST_MAC, ETHERTYPE_ARP);
        let a = &mut f[14..];
        wr16(a, 0, 1);
        wr16(a, 2, 0x0800);
        a[4] = 6;
        a[5] = 4;
        wr16(a, 6, 1);
        a[8..14].copy_from_slice(&HOST_MAC);
        wr32(a, 14, HOST_IP);
        wr32(a, 24, for_ip);
        f
    }

    fn icmp_echo(src: u32, dst: u32, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = std::vec![0u8; total];
        p[0] = 0x45;
        wr16(&mut p, 2, total as u16);
        p[8] = 64;
        p[9] = 1;
        wr32(&mut p, 12, src);
        wr32(&mut p, 16, dst);
        fill_header(&mut p, 20);
        p[20] = 8;
        wr16(&mut p, 24, 0x1234);
        wr16(&mut p, 26, 1);
        p[28..].copy_from_slice(payload);
        let c = csum::finish(csum::sum(&p[20..], 0));
        wr16(&mut p, 22, c);
        p
    }

    fn dongle_mac(un: &UsbSide) -> Mac {
        un.eth.local()
    }

    /// Teach the USB side the host's MAC the way a real host does: it ARPs for the gateway.
    fn learn_host(sh: &Sh, un: &mut UsbSide, wifi: &FakeWifi) {
        let mut f = arp_request(USB_IP);
        let mut reply = [0u8; FRAME_MAX];
        assert!(matches!(host_frame(sh, un, wifi, 1, &mut f, &mut reply), UsbAction::Reply(42)));
        assert_eq!(un.arp.host().map(|h| h.1), Some(HOST_MAC));
    }

    #[test]
    fn arp_request_for_the_gateway_is_answered() {
        let sh = shared();
        let mut un = side(&sh);
        let wifi = FakeWifi::new(Verdict::Drop(DropReason::NoWifiAddress));
        let mut f = arp_request(USB_IP);
        let mut reply = [0u8; FRAME_MAX];
        assert_eq!(host_frame(&sh, &mut un, &wifi, 0, &mut f, &mut reply), UsbAction::Reply(42));
        assert_eq!(&reply[..6], &HOST_MAC, "to the asker");
        assert_eq!(&reply[6..12], &dongle_mac(&un), "from the netif");
        assert_eq!(rd16(&reply, 12), ETHERTYPE_ARP);
        assert_eq!(rd16(&reply, 20), 2, "an ARP reply");
        assert_eq!(&reply[22..28], &dongle_mac(&un));
    }

    #[test]
    fn echo_request_to_the_dongle_is_answered_and_a_bad_one_is_not() {
        let sh = shared();
        let mut un = side(&sh);
        let wifi = FakeWifi::new(Verdict::Drop(DropReason::NoWifiAddress));
        learn_host(&sh, &mut un, &wifi);
        let mut f = ip_frame(dongle_mac(&un), &icmp_echo(HOST_IP, USB_IP, b"ping me"));
        let mut reply = [0u8; FRAME_MAX];
        let UsbAction::Echo(n) = host_frame(&sh, &mut un, &wifi, 2, &mut f, &mut reply) else { panic!("no echo reply") };
        assert_eq!(n, 14 + 20 + 8 + 7);
        let ip = &reply[14..n];
        assert!(csum::header_ok(ip, 20), "IP checksum");
        assert_eq!((rd32(ip, 12), rd32(ip, 16), ip[9], ip[20]), (USB_IP, HOST_IP, 1, 0), "from the dongle to the host, an echo reply");
        assert_eq!(csum::finish(csum::sum(&ip[20..], 0)), 0, "ICMP checksum");
        assert_eq!(&ip[28..], b"ping me");
        // an echo request to the dongle is local; any other ICMP type is counted and dropped
        let mut other = icmp_echo(HOST_IP, USB_IP, b"x");
        other[20] = 13;
        let mut f = ip_frame(dongle_mac(&un), &other);
        assert_eq!(host_frame(&sh, &mut un, &wifi, 3, &mut f, &mut reply), UsbAction::Dropped);
        assert_eq!(RtStats::get(&sh.stats.local_other), 1);
    }

    #[test]
    fn dns_queries_go_to_the_engine_and_answers_are_framed_for_the_host() {
        let sh = shared();
        let mut un = side(&sh);
        let wifi = FakeWifi::new(Verdict::Drop(DropReason::NoWifiAddress));
        learn_host(&sh, &mut un, &wifi);
        let mut q = std::vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["nobody", "lab", "tailnet"] {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let mut udp = std::vec![0u8; 1500];
        let n = build_udp(HOST_IP, 40_000, USB_IP, 53, &q, &mut udp).unwrap();
        let mut f = ip_frame(dongle_mac(&un), &udp[..n]);
        let mut reply = [0u8; FRAME_MAX];
        assert_eq!(host_frame(&sh, &mut un, &wifi, 4, &mut f, &mut reply), UsbAction::Dns);
        assert_eq!(RtStats::get(&sh.stats.dns_in), 1);
        // the engine answered (no such member: an error answer, never a forward): the record is framed with valid checksums, port 53 to the asker
        let mut rec = [0u8; 1700];
        let (kind, k) = sh.host_q.try_pop(&mut rec).expect("an answer was queued");
        assert_eq!(kind, HOST_DNS);
        let len = host_record(&un, kind, &rec[..k], &mut reply).expect("framed");
        let ip = &reply[14..len];
        assert!(csum::header_ok(ip, 20));
        assert_eq!((rd32(ip, 12), rd32(ip, 16), rd16(ip, 20), rd16(ip, 22)), (USB_IP, HOST_IP, 53, 40_000));
        let c = csum::l4_checksum(USB_IP, HOST_IP, 17, &ip[20..]);
        assert!(c == 0 || c == 0xffff, "UDP checksum verifies: {c:#x}");
        assert_eq!(&ip[28..30], &[0x12, 0x34], "the transaction id");
    }

    #[test]
    fn non_alias_traffic_follows_the_nat_verdict() {
        let sh = shared();
        let mut un = side(&sh);
        let wifi = FakeWifi::new(Verdict::Forward { len: 0, mapped: 49_200, new_flow: true });
        learn_host(&sh, &mut un, &wifi);
        let ip = icmp_echo(HOST_IP, ip4(93, 184, 216, 34), b"internet");
        let mut reply = [0u8; FRAME_MAX];
        wifi.verdict.set(Verdict::Forward { len: ip.len() as u16, mapped: 49_200, new_flow: true });
        let mut f = ip_frame(dongle_mac(&un), &ip);
        assert_eq!(host_frame(&sh, &mut un, &wifi, 5, &mut f, &mut reply), UsbAction::Napt);
        assert_eq!(wifi.sent.borrow().len(), 1);
        assert_eq!(wifi.sent.borrow()[0].len(), ip.len());
        assert_eq!(RtStats::get(&sh.stats.napt_forwarded), 1);
        // the Wi-Fi side refuses (queue full): counted, not forwarded
        wifi.accept.set(false);
        let mut f = ip_frame(dongle_mac(&un), &ip);
        assert_eq!(host_frame(&sh, &mut un, &wifi, 6, &mut f, &mut reply), UsbAction::Napt);
        assert_eq!(RtStats::get(&sh.stats.wifi_refused), 1);
        // a rejected packet: an ICMP error for the host
        wifi.verdict.set(Verdict::Reject(Reject { reason: RejectReason::NoPort, icmp: IcmpKind::PortUnreachable }));
        let mut f = ip_frame(dongle_mac(&un), &ip);
        let UsbAction::Icmp(n) = host_frame(&sh, &mut un, &wifi, 7, &mut f, &mut reply) else { panic!("no ICMP error") };
        assert_eq!((reply[14 + 20], reply[14 + 21]), (3, 3), "destination unreachable, port");
        assert_eq!(rd32(&reply[14..], 12), USB_IP);
        assert!(n > 14 + 28);
        // a dropped one: counted
        wifi.verdict.set(Verdict::Drop(DropReason::Multicast));
        let mut f = ip_frame(dongle_mac(&un), &ip);
        assert_eq!(host_frame(&sh, &mut un, &wifi, 8, &mut f, &mut reply), UsbAction::Dropped);
        assert_eq!(RtStats::get(&sh.stats.napt_refused), 2);
    }

    #[test]
    fn junk_frames_never_panic() {
        let sh = shared();
        let mut un = side(&sh);
        let wifi = FakeWifi::new(Verdict::Drop(DropReason::NoWifiAddress));
        let mut reply = [0u8; FRAME_MAX];
        let mut x = 0x1234_5678_9abc_def0u64;
        for round in 0..2000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let n = (x % 120) as usize;
            let mut f: Vec<u8> = (0..n).map(|i| (x >> ((i % 8) * 8)) as u8 ^ (i as u8)).collect();
            if round % 3 == 0 && f.len() > 14 {
                write_eth(&mut f, dongle_mac(&un), HOST_MAC, ETHERTYPE_IPV4);
            }
            let _ = host_frame(&sh, &mut un, &wifi, round, &mut f, &mut reply);
        }
    }

    #[test]
    fn built_udp_packets_carry_valid_checksums_and_refuse_oversize() {
        let mut out = [0u8; 1600];
        let n = build_udp(USB_IP, 53, HOST_IP, 4000, b"payload", &mut out).unwrap();
        assert_eq!(n, 35);
        assert!(csum::header_ok(&out, 20));
        assert_eq!(csum::l4_checksum(USB_IP, HOST_IP, 17, &out[20..n]), 0, "a segment with its checksum in place sums to zero");
        assert!(build_udp(USB_IP, 53, HOST_IP, 4000, &[0; 1500], &mut out).is_none(), "above the MTU");
    }

    #[test]
    fn the_usb_mac_is_local_unicast_and_not_the_station_mac() {
        for sta in [[0x00, 1, 2, 3, 4, 5], [0xfc, 0xff, 0xff, 0xff, 0xff, 0xff], [0x02, 0, 0, 0, 0, 0]] {
            let m = derive_usb_mac(sta);
            assert_eq!((m[0] & 1, m[0] & 2), (0, 2));
            assert_ne!(m, sta);
        }
    }

    #[test]
    fn only_arp_replies_and_tcp_to_the_dongle_reach_the_local_stack() {
        let mut arp = [0u8; 42];
        wr16(&mut arp, 12, ETHERTYPE_ARP);
        wr16(&mut arp, 20, 2);
        assert!(wants_local_stack(&arp), "an ARP reply: the stack resolves the host itself");
        wr16(&mut arp, 20, 1);
        assert!(!wants_local_stack(&arp), "a who-has is the runtime's to answer");
        let mut tcp = [0u8; 60];
        wr16(&mut tcp, 12, ETHERTYPE_IPV4);
        tcp[14] = 0x45;
        tcp[14 + 9] = 6;
        wr32(&mut tcp, 14 + 16, USB_IP);
        assert!(wants_local_stack(&tcp));
        wr32(&mut tcp, 14 + 16, 0x0808_0808);
        assert!(!wants_local_stack(&tcp), "TCP to the Internet is the NAT's");
        wr32(&mut tcp, 14 + 16, USB_IP);
        tcp[14 + 9] = 17;
        assert!(!wants_local_stack(&tcp), "UDP to the dongle (DNS, DHCP) is the runtime's");
    }
}
