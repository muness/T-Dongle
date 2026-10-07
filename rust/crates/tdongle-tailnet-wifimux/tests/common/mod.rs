//! Test bench: a scripted radio, packet builders, a one-segment LAN with a gateway that speaks ARP/DHCP/"the Internet", and a manual poller.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use embassy_net_driver::{Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken};
use tdongle_tailnet_usbnet::csum::{fill_header, l4_checksum};

pub type Mac = [u8; 6];
pub const STA_MAC: Mac = [2, 0, 0, 0, 0, 0x50];
pub const GW_MAC: Mac = [2, 0, 0, 0, 0, 0x01];
pub const PEER_MAC: Mac = [2, 0, 0, 0, 0, 0x10];
pub const BCAST: Mac = [0xff; 6];
pub const STA_IP: u32 = ip(192, 168, 1, 50);
pub const GW_IP: u32 = ip(192, 168, 1, 1);
pub const PEER_IP: u32 = ip(192, 168, 1, 10);
pub const HOST_IP: u32 = ip(192, 168, 77, 2);

pub const fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

// ---------------------------------------------------------------- the scripted radio

#[derive(Default)]
pub struct RadioState {
    pub rx: VecDeque<Vec<u8>>,
    pub tx_log: Vec<Vec<u8>>,
    /// Frames the radio can still accept (the esp-radio TX credit); `None` = unlimited.
    pub credit: Option<usize>,
    /// esp-radio's coupling: `receive` yields only when a TX credit is free.
    pub coupled: bool,
    pub link_up: bool,
    pub rx_waker: Option<Waker>,
    pub tx_waker: Option<Waker>,
    pub link_waker: Option<Waker>,
    pub tx_total: usize,
}

#[derive(Clone)]
pub struct RadioHandle(pub Arc<Mutex<RadioState>>);

impl RadioHandle {
    pub fn new() -> Self {
        RadioHandle(Arc::new(Mutex::new(RadioState { link_up: true, ..Default::default() })))
    }
    pub fn push_rx(&self, f: Vec<u8>) {
        let w = {
            let mut s = self.0.lock().unwrap();
            s.rx.push_back(f);
            s.rx_waker.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
    pub fn take_tx(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.0.lock().unwrap().tx_log)
    }
    pub fn set_credit(&self, c: Option<usize>) {
        let w = {
            let mut s = self.0.lock().unwrap();
            s.credit = c;
            s.tx_waker.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }
    pub fn set_link(&self, up: bool) {
        let ws = {
            let mut s = self.0.lock().unwrap();
            s.link_up = up;
            [s.link_waker.take(), s.tx_waker.take(), s.rx_waker.take()]
        };
        for w in ws.into_iter().flatten() {
            w.wake();
        }
    }
    pub fn set_coupled(&self, c: bool) {
        self.0.lock().unwrap().coupled = c;
    }
    pub fn rx_pending(&self) -> usize {
        self.0.lock().unwrap().rx.len()
    }
}

pub struct FakeRadio {
    pub h: RadioHandle,
    pub mac: Mac,
}

pub struct FakeRx(Vec<u8>);
pub struct FakeTx(RadioHandle);

impl RxToken for FakeRx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}
impl TxToken for FakeTx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        let mut s = self.0.0.lock().unwrap();
        if let Some(c) = &mut s.credit {
            *c = c.saturating_sub(1);
        }
        s.tx_total += 1;
        s.tx_log.push(buf);
        r
    }
}

impl FakeRadio {
    fn can_tx(s: &RadioState) -> bool {
        s.link_up && s.credit.is_none_or(|c| c > 0)
    }
}

impl Driver for FakeRadio {
    type RxToken<'a> = FakeRx;
    type TxToken<'a> = FakeTx;

    fn receive(&mut self, cx: &mut Context<'_>) -> Option<(FakeRx, FakeTx)> {
        let mut s = self.h.0.lock().unwrap();
        s.rx_waker = Some(cx.waker().clone());
        s.tx_waker = Some(cx.waker().clone());
        if !s.link_up || (s.coupled && !Self::can_tx(&s)) {
            return None;
        }
        let f = s.rx.pop_front()?;
        Some((FakeRx(f), FakeTx(self.h.clone())))
    }
    fn transmit(&mut self, cx: &mut Context<'_>) -> Option<FakeTx> {
        let mut s = self.h.0.lock().unwrap();
        s.tx_waker = Some(cx.waker().clone());
        if Self::can_tx(&s) { Some(FakeTx(self.h.clone())) } else { None }
    }
    fn link_state(&mut self, cx: &mut Context<'_>) -> LinkState {
        let mut s = self.h.0.lock().unwrap();
        s.link_waker = Some(cx.waker().clone());
        if s.link_up { LinkState::Up } else { LinkState::Down }
    }
    fn capabilities(&self) -> Capabilities {
        let mut c = Capabilities::default();
        c.max_transmission_unit = 1514;
        c
    }
    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet(self.mac)
    }
}

// ---------------------------------------------------------------- packet builders

pub fn eth(dst: Mac, src: Mac, ty: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&ty.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

pub fn ipv4(proto: u8, src: u32, dst: u32, l4: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src.to_be_bytes());
    p[16..20].copy_from_slice(&dst.to_be_bytes());
    fill_header(&mut p, 20);
    p.extend_from_slice(l4);
    p
}

pub fn udp_l4(src: u32, dst: u32, sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + data.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(data);
    let c = l4_checksum(src, dst, 17, &u);
    u[6..8].copy_from_slice(&(if c == 0 { 0xffff } else { c }).to_be_bytes());
    u
}

pub fn udp_packet(src: u32, dst: u32, sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    ipv4(17, src, dst, &udp_l4(src, dst, sport, dport, data))
}

pub fn udp_frame(dm: Mac, sm: Mac, src: u32, dst: u32, sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
    eth(dm, sm, 0x0800, &udp_packet(src, dst, sport, dport, data))
}

pub fn arp(op: u16, sha: Mac, spa: u32, tha: Mac, tpa: u32) -> Vec<u8> {
    let mut a = vec![0, 1, 8, 0, 6, 4];
    a.extend_from_slice(&op.to_be_bytes());
    a.extend_from_slice(&sha);
    a.extend_from_slice(&spa.to_be_bytes());
    a.extend_from_slice(&tha);
    a.extend_from_slice(&tpa.to_be_bytes());
    a
}

pub fn udp_ports(l3: &[u8]) -> (u16, u16) {
    let ihl = usize::from(l3[0] & 15) * 4;
    (u16::from_be_bytes([l3[ihl], l3[ihl + 1]]), u16::from_be_bytes([l3[ihl + 2], l3[ihl + 3]]))
}
pub fn ip_src(l3: &[u8]) -> u32 {
    u32::from_be_bytes([l3[12], l3[13], l3[14], l3[15]])
}
pub fn ip_dst(l3: &[u8]) -> u32 {
    u32::from_be_bytes([l3[16], l3[17], l3[18], l3[19]])
}

// ---------------------------------------------------------------- the gateway

#[derive(Default)]
pub struct Gateway {
    pub arp_requests_seen: usize,
    pub internet_udp: Vec<Vec<u8>>,
    pub dhcp_acks: usize,
    /// Answer ARP who-has for the gateway's address.
    pub answer_arp: bool,
    /// Echo UDP datagrams that were sent to the gateway's MAC for off-link addresses back (the "Internet").
    pub echo_internet: bool,
    /// Answer UDP datagrams sent to the gateway's MAC for an off-link address with this function of the request payload instead of echoing it (an NTP server, say).
    pub internet_reply: Option<fn(&[u8]) -> Vec<u8>>,
    /// Datagrams to these destination addresses get no answer (a resolver that drops this client's queries).
    pub silent_dsts: Vec<u32>,
    pub frames_from_sta: Vec<Vec<u8>>,
}

impl Gateway {
    pub fn new() -> Self {
        Gateway { answer_arp: true, echo_internet: true, ..Default::default() }
    }

    fn dhcp_reply(&mut self, req: &[u8]) -> Option<Vec<u8>> {
        // req is the UDP payload of a BOOTP request.
        if req.len() < 241 || req[0] != 1 {
            return None;
        }
        let mut msg_type = 0;
        let mut i = 240;
        while i + 1 < req.len() && req[i] != 255 {
            if req[i] == 0 {
                i += 1;
                continue;
            }
            if req[i] == 53 {
                msg_type = req[i + 2];
            }
            i += 2 + usize::from(req[i + 1]);
        }
        let reply_type = match msg_type {
            1 => 2,
            3 => 5,
            _ => return None,
        };
        let mut b = vec![0u8; 240];
        b[0] = 2;
        b[1] = 1;
        b[2] = 6;
        b[4..8].copy_from_slice(&req[4..8]);
        b[16..20].copy_from_slice(&STA_IP.to_be_bytes());
        b[20..24].copy_from_slice(&GW_IP.to_be_bytes());
        b[28..34].copy_from_slice(&req[28..34]);
        b[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        b.extend_from_slice(&[53, 1, reply_type, 54, 4]);
        b.extend_from_slice(&GW_IP.to_be_bytes());
        b.extend_from_slice(&[51, 4, 0, 0, 0x0e, 0x10, 1, 4, 255, 255, 255, 0, 3, 4]);
        b.extend_from_slice(&GW_IP.to_be_bytes());
        b.extend_from_slice(&[6, 4]);
        b.extend_from_slice(&GW_IP.to_be_bytes());
        b.push(255);
        if reply_type == 5 {
            self.dhcp_acks += 1;
        }
        let udp = udp_l4(GW_IP, u32::MAX, 67, 68, &b);
        Some(eth(BCAST, GW_MAC, 0x0800, &ipv4(17, GW_IP, u32::MAX, &udp)))
    }

    /// A frame the station transmitted (destination MAC the gateway's or broadcast); returns frames to put back on the air.
    pub fn handle(&mut self, f: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if f.len() < 14 {
            return out;
        }
        self.frames_from_sta.push(f.to_vec());
        let ty = u16::from_be_bytes([f[12], f[13]]);
        let src: Mac = f[6..12].try_into().unwrap();
        if ty == 0x0806 && f.len() >= 42 {
            let op = u16::from_be_bytes([f[20], f[21]]);
            let tpa = u32::from_be_bytes([f[38], f[39], f[40], f[41]]);
            if op == 1 && tpa == GW_IP {
                self.arp_requests_seen += 1;
                if self.answer_arp {
                    let spa = u32::from_be_bytes([f[28], f[29], f[30], f[31]]);
                    out.push(eth(src, GW_MAC, 0x0806, &arp(2, GW_MAC, GW_IP, src, spa)));
                }
            }
        } else if ty == 0x0800 && f.len() >= 34 && f[23] == 17 {
            let l3 = &f[14..];
            let (sport, dport) = udp_ports(l3);
            if dport == 67 {
                if let Some(r) = self.dhcp_reply(&l3[28..]) {
                    out.push(r);
                }
            } else if f[0..6] == GW_MAC {
                self.internet_udp.push(l3.to_vec());
                if self.echo_internet && !self.silent_dsts.contains(&ip_dst(l3)) {
                    let dst = ip_dst(l3);
                    let src_ip = ip_src(l3);
                    let data = &l3[28..usize::from(u16::from_be_bytes([l3[2], l3[3]]))];
                    let reply = match self.internet_reply {
                        Some(f) => f(data),
                        None => data.to_vec(),
                    };
                    out.push(udp_frame(src, GW_MAC, dst, src_ip, dport, sport, &reply));
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------- the LAN and the poller

struct Flag(std::sync::atomic::AtomicUsize);
impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Counts wakes.
pub struct CountingWaker(Arc<Flag>);
impl CountingWaker {
    pub fn new() -> (Self, Waker) {
        let f = Arc::new(Flag(Default::default()));
        (CountingWaker(f.clone()), Waker::from(f))
    }
    pub fn count(&self) -> usize {
        self.0.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub type Task = Pin<Box<dyn Future<Output = ()>>>;

pub struct Lan {
    pub sta: RadioHandle,
    pub peer: Option<RadioHandle>,
    pub gw: Gateway,
    pub tasks: Vec<Task>,
    /// Frames from the station the gateway/peer saw, by destination class (for assertions).
    pub steps: usize,
}

impl Lan {
    pub fn new(sta: RadioHandle) -> Self {
        Lan { sta, peer: None, gw: Gateway::new(), tasks: Vec::new(), steps: 0 }
    }

    fn deliver(&mut self, from_sta: bool, f: Vec<u8>) {
        if f.len() < 14 {
            return;
        }
        let dst: Mac = f[0..6].try_into().unwrap();
        let to_gw = dst == GW_MAC || dst == BCAST;
        let to_peer = dst == PEER_MAC || dst == BCAST;
        let to_sta = dst == STA_MAC || dst == BCAST;
        if from_sta {
            if to_gw {
                for r in self.gw.handle(&f) {
                    self.sta.push_rx(r);
                }
            }
            if to_peer && let Some(p) = &self.peer {
                p.push_rx(f.clone());
            }
        } else {
            // from the peer
            if to_sta {
                self.sta.push_rx(f.clone());
            }
            if to_gw {
                for r in self.gw.handle(&f) {
                    if let Some(p) = &self.peer {
                        p.push_rx(r);
                    }
                }
            }
        }
    }

    /// Move every frame the radios transmitted to its destination.
    pub fn switch(&mut self) {
        for f in self.sta.take_tx() {
            self.deliver(true, f);
        }
        if let Some(p) = self.peer.clone() {
            for f in p.take_tx() {
                self.deliver(false, f);
            }
        }
    }

    /// Poll every task once, switch frames, let a little real time pass (smoltcp's timers).
    pub fn step(&mut self) {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut i = 0;
        while i < self.tasks.len() {
            if self.tasks[i].as_mut().poll(&mut cx) == Poll::Ready(()) {
                drop(self.tasks.remove(i));
            } else {
                i += 1;
            }
        }
        self.switch();
        self.steps += 1;
        std::thread::sleep(std::time::Duration::from_micros(300));
    }

    pub fn run_until(&mut self, mut cond: impl FnMut(&mut Lan) -> bool, max_steps: usize) -> bool {
        for _ in 0..max_steps {
            self.step();
            if cond(self) {
                return true;
            }
        }
        false
    }
}
