//! The shared, lock-protected state of the mux: queues, next-hop resolution, configuration, counters, wakers. No driver and no clock in here:
//! every method takes `now`, so the tests run it on a scripted timeline.

use core::task::Waker;

use embassy_sync::waitqueue::{MultiWakerRegistration, WakerRegistration};
use tdongle_tailnet_types::{Counter, Millis};
use tdongle_tailnet_usbnet::arp::{ARP_FRAME, ArpConfig, ArpIgnore, ArpStats, Neighbors, RETRY_MS, Resolve};
use tdongle_tailnet_usbnet::wire::{BROADCAST_MAC, ETHERTYPE_IPV4, Mac, rd16, rd32, wr16, wr32, write_eth};

use crate::info::Ipv4Cfg;
use crate::ring::Ring;
use crate::rx::{RxClass, RxDrop, classify_rx};
use crate::{ETH_HDR, L3_MAX};

/// Why a packet offered to [`crate::RawPort::send`] (or queued earlier) was not sent on the radio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxDrop {
    /// Shorter than an IPv4 header.
    Runt,
    /// Longer than [`crate::L3_MAX`].
    Oversize,
    /// Not an IPv4 packet with a consistent header.
    NotIpv4,
    /// The source address is not the station's (the NAT's output always is).
    WrongSource,
    /// The queue is full ([`crate::RawPort::try_send`]).
    QueueFull,
    /// The stack has no IPv4 configuration.
    NoConfig,
    /// The Wi-Fi link is down.
    LinkDown,
    /// Off-link destination and no gateway in the lease.
    NoGateway,
    /// The next hop is not on the station's subnet (a lease whose gateway is outside its prefix).
    NoRoute,
    /// Five ARP requests for the next hop went unanswered.
    ArpFailed,
    /// Queued when the link or the association changed (stale NAT mappings).
    Flushed,
}

impl TxDrop {
    /// Number of variants.
    pub const COUNT: usize = 11;
    /// Dense index (exhaustive).
    pub const fn index(self) -> usize {
        match self {
            TxDrop::Runt => 0,
            TxDrop::Oversize => 1,
            TxDrop::NotIpv4 => 2,
            TxDrop::WrongSource => 3,
            TxDrop::QueueFull => 4,
            TxDrop::NoConfig => 5,
            TxDrop::LinkDown => 6,
            TxDrop::NoGateway => 7,
            TxDrop::NoRoute => 8,
            TxDrop::ArpFailed => 9,
            TxDrop::Flushed => 10,
        }
    }
}

/// Every counter of the mux. A snapshot is `Copy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuxStats {
    /// Frames the radio delivered.
    pub rx_frames: Counter,
    /// Frames handed to the stack.
    pub rx_to_stack: Counter,
    /// Packets queued for the USB host.
    pub rx_to_host: Counter,
    /// Fragments seen (they are classified like other packets, not dropped).
    pub rx_fragments: Counter,
    /// Frames dropped, by [`RxDrop::index`].
    pub rx_dropped: [Counter; RxDrop::COUNT],
    /// Next-hop MACs learned or refreshed by snooping (ARP and IPv4 from the gateway).
    pub snooped: Counter,
    /// Frames the stack sent.
    pub tx_stack: Counter,
    /// NAT packets framed and sent.
    pub tx_napt: Counter,
    /// ARP requests the mux sent for its own resolutions.
    pub tx_arp: Counter,
    /// NAT packets accepted into the queue.
    pub tx_queued: Counter,
    /// NAT packets not sent, by [`TxDrop::index`].
    pub tx_dropped: [Counter; TxDrop::COUNT],
    /// Packets the USB side read.
    pub host_delivered: Counter,
    /// Packets the USB side could not read because its buffer was shorter than the packet.
    pub host_buf_too_small: Counter,
    /// Radio link went down.
    pub link_downs: Counter,
    /// Association generation or address changed (state cleared).
    pub resets: Counter,
    /// The ARP table's counters (requests, learned, gave up).
    pub arp: ArpStats,
}

impl MuxStats {
    /// Frames dropped on receive for one reason.
    pub fn rx_dropped(&self, r: RxDrop) -> u32 {
        self.rx_dropped[r.index()].get()
    }
    /// NAT packets dropped on transmit for one reason.
    pub fn tx_dropped(&self, r: TxDrop) -> u32 {
        self.tx_dropped[r.index()].get()
    }
}

const NEIGHBORS: usize = 4;
/// Re-check interval while an ARP request is outstanding (the table itself spaces the requests [`RETRY_MS`] apart).
pub(crate) const ARP_POLL_MS: u64 = RETRY_MS / 4;

/// What the transmit side should do next, decided by [`Core::tx_plan`] while the caller already holds a radio token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TxPlan {
    /// Nothing queued.
    Idle,
    /// Head of the queue waits for an ARP answer; look again at this time.
    Wait(Millis),
    /// Send this ARP frame (already counted).
    Arp([u8; ARP_FRAME]),
    /// Send the head packet to this MAC with [`Core::pop_frame`].
    Frame(Mac),
}

/// What [`Core::take_sync`] tells the stack side to do to its tap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SyncAct {
    pub(crate) cfg: Option<Ipv4Cfg>,
    pub(crate) reset: bool,
}

pub(crate) struct Core<const TXQ: usize, const RXQ: usize> {
    mac: Mac,
    cfg: Option<Ipv4Cfg>,
    want: Option<Ipv4Cfg>,
    want_seq: u32,
    applied_seq: u32,
    generation: u32,
    applied_gen: u32,
    link_up: bool,
    neigh: Neighbors<NEIGHBORS>,
    tx: Ring<TXQ>,
    host: Ring<RXQ>,
    pending_arp: Option<[u8; ARP_FRAME]>,
    pub(crate) stats: MuxStats,
    pub(crate) stack_waker: WakerRegistration,
    host_waker: WakerRegistration,
    space_wakers: MultiWakerRegistration<2>,
}

const ZERO_STATS: MuxStats = MuxStats {
    rx_frames: Counter(0),
    rx_to_stack: Counter(0),
    rx_to_host: Counter(0),
    rx_fragments: Counter(0),
    rx_dropped: [Counter(0); RxDrop::COUNT],
    snooped: Counter(0),
    tx_stack: Counter(0),
    tx_napt: Counter(0),
    tx_arp: Counter(0),
    tx_queued: Counter(0),
    tx_dropped: [Counter(0); TxDrop::COUNT],
    host_delivered: Counter(0),
    host_buf_too_small: Counter(0),
    link_downs: Counter(0),
    resets: Counter(0),
    arp: ArpStats {
        packets: Counter(0),
        replies: Counter(0),
        learned: Counter(0),
        learn_refused: Counter(0),
        requests: Counter(0),
        gave_up: Counter(0),
        expired: Counter(0),
        ignored: [Counter(0); ArpIgnore::COUNT],
    },
};

impl<const TXQ: usize, const RXQ: usize> Core<TXQ, RXQ> {
    pub(crate) const fn new(mac: Mac) -> Self {
        Core {
            mac,
            cfg: None,
            want: None,
            want_seq: 0,
            applied_seq: 0,
            generation: 0,
            applied_gen: 0,
            link_up: false,
            neigh: Neighbors::new(ArpConfig { mac, ip: 0, mask: 0 }),
            tx: Ring::new(),
            host: Ring::new(),
            pending_arp: None,
            stats: ZERO_STATS,
            stack_waker: WakerRegistration::new(),
            host_waker: WakerRegistration::new(),
            space_wakers: MultiWakerRegistration::new(),
        }
    }

    pub(crate) fn snapshot(&self) -> MuxStats {
        let mut s = self.stats;
        s.arp = *self.neigh.stats();
        s
    }

    // ---- configuration ----

    pub(crate) fn set_want(&mut self, cfg: Option<Ipv4Cfg>) {
        if cfg != self.want {
            self.want = cfg;
            self.want_seq = self.want_seq.wrapping_add(1);
            self.stack_waker.wake();
        }
    }
    pub(crate) fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.stack_waker.wake();
    }
    pub(crate) fn want(&self) -> Option<Ipv4Cfg> {
        self.want
    }

    /// Apply a pending configuration or association change. The caller (the stack side) then tells its tap.
    pub(crate) fn take_sync(&mut self) -> Option<SyncAct> {
        if self.want_seq == self.applied_seq && self.generation == self.applied_gen {
            return None;
        }
        let addr_changed = self.want.map(|c| c.addr) != self.cfg.map(|c| c.addr);
        let reset = self.generation != self.applied_gen || addr_changed;
        self.applied_seq = self.want_seq;
        self.applied_gen = self.generation;
        self.cfg = self.want;
        if reset || self.cfg.map(|c| c.mask()) != Some(self.neigh.config().mask) {
            self.clear_link_state();
        }
        if reset {
            self.stats.resets.bump();
        }
        Some(SyncAct { cfg: self.cfg, reset })
    }

    /// Neighbour state and the packets waiting for it (their NAT mappings are stale after a bounce).
    fn clear_link_state(&mut self) {
        let n = self.tx.clear();
        for _ in 0..n {
            self.stats.tx_dropped[TxDrop::Flushed.index()].bump();
        }
        self.pending_arp = None;
        self.neigh = Neighbors::new(ArpConfig { mac: self.mac, ip: self.cfg.map_or(0, |c| c.addr), mask: self.cfg.map_or(0, |c| c.mask()) });
        self.space_wakers.wake();
    }

    /// The radio's link state, seen by the stack side. Returns true on a fall (the tap must reset too).
    pub(crate) fn set_link(&mut self, up: bool) -> bool {
        let fell = self.link_up && !up;
        if self.link_up != up {
            self.link_up = up;
            if !up {
                self.stats.link_downs.bump();
                self.clear_link_state();
                self.stats.resets.bump();
            }
        }
        fell
    }

    pub(crate) fn gateway_mac(&self) -> Option<Mac> {
        self.cfg.and_then(|c| c.gateway).and_then(|g| self.neigh.peek(g))
    }

    // ---- receive ----

    /// Look at one received frame: sanity, counters, snooping. Returns the class; the driver then consults the tap for unicast IPv4.
    pub(crate) fn rx_pre(&mut self, now: Millis, frame: &[u8]) -> RxClass {
        self.stats.rx_frames.bump();
        let c = classify_rx(frame, &self.mac);
        match c {
            RxClass::Drop(r) => self.count_rx_drop(r),
            RxClass::Arp => self.snoop_arp(now, &frame[ETH_HDR..]),
            RxClass::Ipv4 { src_mac, src_ip, fragment, .. } => {
                if fragment {
                    self.stats.rx_fragments.bump();
                }
                self.snoop_ip(now, src_mac, src_ip);
            }
            RxClass::Other => {}
        }
        c
    }

    fn learn_via_table(&mut self, now: Millis, payload: &[u8]) {
        // A zero-length output buffer: the table learns but never builds a reply (the stack answers who-has for our address).
        let before = self.neigh.stats().learned.get();
        let _ = self.neigh.handle(now, payload, &mut []);
        if self.neigh.stats().learned.get() != before {
            self.stats.snooped.bump();
        }
    }

    fn snoop_arp(&mut self, now: Millis, payload: &[u8]) {
        if self.cfg.is_some() {
            self.learn_via_table(now, payload);
        }
    }

    /// An IPv4 frame whose source address is the gateway's tells the gateway's MAC.
    fn snoop_ip(&mut self, now: Millis, src_mac: Mac, src_ip: u32) {
        let Some(c) = self.cfg else { return };
        if c.gateway != Some(src_ip) {
            return;
        }
        // Reuse the table's own validation by presenting the observation as an ARP reply addressed to us.
        let mut a = [0u8; 28];
        wr16(&mut a, 0, 1);
        wr16(&mut a, 2, 0x0800);
        a[4] = 6;
        a[5] = 4;
        wr16(&mut a, 6, 2);
        a[8..14].copy_from_slice(&src_mac);
        wr32(&mut a, 14, src_ip);
        a[18..24].copy_from_slice(&self.mac);
        wr32(&mut a, 24, c.addr);
        self.learn_via_table(now, &a);
    }

    pub(crate) fn count_rx_drop(&mut self, r: RxDrop) {
        self.stats.rx_dropped[r.index()].bump();
    }
    pub(crate) fn count_to_stack(&mut self) {
        self.stats.rx_to_stack.bump();
    }

    /// Queue a packet for the USB side; false (counted) when full.
    pub(crate) fn host_push(&mut self, pkt: &[u8]) -> bool {
        if pkt.len() > L3_MAX || !self.host.push(pkt) {
            self.count_rx_drop(RxDrop::HostQueueFull);
            return false;
        }
        self.stats.rx_to_host.bump();
        self.host_waker.wake();
        true
    }

    /// Pop the next packet for the host into `buf`. A packet longer than `buf` is dropped and counted. With `waker`, registers it when empty.
    pub(crate) fn host_pop(&mut self, buf: &mut [u8], waker: Option<&Waker>) -> Option<usize> {
        loop {
            let Some(p) = self.host.front() else {
                if let Some(w) = waker {
                    self.host_waker.register(w);
                }
                return None;
            };
            if p.len() > buf.len() {
                self.stats.host_buf_too_small.bump();
                self.host.pop();
                continue;
            }
            let n = p.len();
            buf[..n].copy_from_slice(p);
            self.host.pop();
            self.stats.host_delivered.bump();
            return Some(n);
        }
    }

    // ---- transmit ----

    fn count_tx_drop(&mut self, r: TxDrop) {
        self.stats.tx_dropped[r.index()].bump();
    }

    /// Queue an L3 packet from the runtime. With `waker`, a full queue registers it instead of counting a drop.
    pub(crate) fn tx_push(&mut self, l3: &[u8], waker: Option<&Waker>) -> Result<(), TxDrop> {
        let total = match self.tx_check(l3) {
            Ok(t) => t,
            Err(e) => {
                self.count_tx_drop(e);
                return Err(e);
            }
        };
        if self.tx.is_full() {
            if let Some(w) = waker {
                self.space_wakers.register(w);
            } else {
                self.count_tx_drop(TxDrop::QueueFull);
            }
            return Err(TxDrop::QueueFull);
        }
        let _ = self.tx.push(&l3[..total]);
        self.stats.tx_queued.bump();
        self.stack_waker.wake();
        Ok(())
    }

    fn tx_check(&self, l3: &[u8]) -> Result<usize, TxDrop> {
        if l3.len() < 20 {
            return Err(TxDrop::Runt);
        }
        if l3.len() > L3_MAX {
            return Err(TxDrop::Oversize);
        }
        let ihl = usize::from(l3[0] & 15) * 4;
        let total = usize::from(rd16(l3, 2));
        if l3[0] >> 4 != 4 || ihl < 20 || total < ihl || total > l3.len() {
            return Err(TxDrop::NotIpv4);
        }
        let Some(c) = self.cfg else { return Err(TxDrop::NoConfig) };
        if !self.link_up {
            return Err(TxDrop::LinkDown);
        }
        if rd32(l3, 12) != c.addr {
            return Err(TxDrop::WrongSource);
        }
        Ok(total)
    }

    pub(crate) fn tx_has_work(&self) -> bool {
        self.pending_arp.is_some() || !self.tx.is_empty()
    }
    pub(crate) fn tx_len(&self) -> usize {
        self.tx.len()
    }
    pub(crate) fn host_len(&self) -> usize {
        self.host.len()
    }

    /// Decide the next transmission. Only called while the caller holds a radio token, so everything it counts is sent.
    pub(crate) fn tx_plan(&mut self, now: Millis) -> TxPlan {
        if let Some(f) = self.pending_arp.take() {
            self.stats.tx_arp.bump();
            return TxPlan::Arp(f);
        }
        loop {
            let Some(head) = self.tx.front() else { return TxPlan::Idle };
            let dst = rd32(head, 16);
            let Some(c) = self.cfg else {
                self.drop_head(TxDrop::NoConfig);
                continue;
            };
            if dst == u32::MAX || (c.on_link(dst) && dst | c.mask() == u32::MAX) {
                return TxPlan::Frame(BROADCAST_MAC);
            }
            if dst >> 28 == 14 {
                let b = dst.to_be_bytes();
                return TxPlan::Frame([0x01, 0x00, 0x5e, b[1] & 0x7f, b[2], b[3]]);
            }
            let target = if c.on_link(dst) {
                dst
            } else if let Some(g) = c.gateway {
                g
            } else {
                self.drop_head(TxDrop::NoGateway);
                continue;
            };
            let mut req = [0u8; ARP_FRAME];
            match self.neigh.resolve(now, target, &mut req) {
                Resolve::Hit(mac) => return TxPlan::Frame(mac),
                Resolve::HitRefresh { mac, .. } => {
                    self.pending_arp = Some(req);
                    return TxPlan::Frame(mac);
                }
                Resolve::Request { .. } => {
                    self.stats.tx_arp.bump();
                    return TxPlan::Arp(req);
                }
                Resolve::Pending => return TxPlan::Wait(now + ARP_POLL_MS),
                Resolve::Failed => self.drop_head(TxDrop::ArpFailed),
                Resolve::OffLink => self.drop_head(TxDrop::NoRoute),
            }
        }
    }

    fn drop_head(&mut self, r: TxDrop) {
        self.tx.pop();
        self.count_tx_drop(r);
        self.space_wakers.wake();
    }

    /// Length of the Ethernet frame the head packet becomes.
    pub(crate) fn head_frame_len(&self) -> Option<usize> {
        self.tx.front().map(|p| ETH_HDR + p.len())
    }

    /// Write the head packet as an Ethernet frame to `dst` into `out` (exactly [`Core::head_frame_len`] bytes) and pop it.
    pub(crate) fn pop_frame(&mut self, out: &mut [u8], dst: Mac) {
        if let Some(p) = self.tx.front()
            && out.len() == ETH_HDR + p.len()
        {
            write_eth(out, dst, self.mac, ETHERTYPE_IPV4);
            out[ETH_HDR..].copy_from_slice(p);
            self.tx.pop();
            self.stats.tx_napt.bump();
            self.space_wakers.wake();
        }
    }

    pub(crate) fn count_tx_stack(&mut self) {
        self.stats.tx_stack.bump();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const MAC: Mac = [2, 0, 0, 0, 0, 0x50];
    const GWM: Mac = [2, 0, 0, 0, 0, 1];
    const STA: u32 = 0xC0A8_0132;
    const GW: u32 = 0xC0A8_0101;

    fn cfg() -> Ipv4Cfg {
        Ipv4Cfg { addr: STA, gateway: Some(GW), prefix: 24 }
    }
    fn up() -> Core<2, 2> {
        let mut c = Core::<2, 2>::new(MAC);
        c.set_want(Some(cfg()));
        assert!(c.take_sync().is_some());
        let _ = c.set_link(true);
        c
    }
    fn pkt(src: u32, dst: u32, len: usize) -> Vec<u8> {
        let mut p = std::vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        wr32(&mut p, 12, src);
        wr32(&mut p, 16, dst);
        p
    }
    fn eth_frame(dst: Mac, src: Mac, ty: u16, body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ty.to_be_bytes());
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn send_validation_names_every_refusal() {
        let mut c = Core::<2, 2>::new(MAC);
        let ok = pkt(STA, 0x0808_0808, 40);
        assert_eq!(c.tx_push(&ok, None), Err(TxDrop::NoConfig));
        c.set_want(Some(cfg()));
        let _ = c.take_sync();
        assert_eq!(c.tx_push(&ok, None), Err(TxDrop::LinkDown));
        let _ = c.set_link(true);
        assert_eq!(c.tx_push(&[0; 10], None), Err(TxDrop::Runt));
        assert_eq!(c.tx_push(&std::vec![0x45; 1501], None), Err(TxDrop::Oversize));
        let mut bad = ok.clone();
        bad[0] = 0x65;
        assert_eq!(c.tx_push(&bad, None), Err(TxDrop::NotIpv4));
        let mut bad = ok.clone();
        bad[2..4].copy_from_slice(&41u16.to_be_bytes());
        assert_eq!(c.tx_push(&bad, None), Err(TxDrop::NotIpv4));
        assert_eq!(c.tx_push(&pkt(STA + 1, 0x0808_0808, 40), None), Err(TxDrop::WrongSource));
        assert_eq!(c.tx_push(&ok, None), Ok(()));
        assert_eq!(c.tx_push(&ok, None), Ok(()));
        assert_eq!(c.tx_push(&ok, None), Err(TxDrop::QueueFull));
        let s = c.snapshot();
        for r in [TxDrop::NoConfig, TxDrop::LinkDown, TxDrop::Runt, TxDrop::Oversize, TxDrop::WrongSource, TxDrop::QueueFull] {
            assert_eq!(s.tx_dropped(r), 1, "{r:?}");
        }
        assert_eq!(s.tx_dropped(TxDrop::NotIpv4), 2);
        assert_eq!(s.tx_queued.get(), 2);
        // trailing bytes beyond the IP total length are not queued
        let mut c = up();
        let mut padded = pkt(STA, 0x0808_0808, 40);
        padded.extend_from_slice(&[9; 10]);
        c.tx_push(&padded, None).unwrap();
        assert_eq!(c.head_frame_len(), Some(54));
    }

    #[test]
    fn arp_timeline_request_wait_retry_give_up() {
        let mut c = up();
        c.tx_push(&pkt(STA, 0x0808_0808, 40), None).unwrap();
        // t=0: the first request goes out; then the head waits
        let TxPlan::Arp(f) = c.tx_plan(0) else { panic!() };
        assert_eq!(&f[0..6], &[0xff; 6]);
        assert_eq!(&f[6..12], &MAC);
        assert_eq!(rd32(&f, 38), GW);
        assert_eq!(rd32(&f, 28), STA);
        assert!(matches!(c.tx_plan(10), TxPlan::Wait(260)));
        assert!(matches!(c.tx_plan(900), TxPlan::Wait(_)));
        // requests 2..5 one second apart (rate limited by the table)
        for t in [1_000, 2_000, 3_000, 4_000] {
            assert!(matches!(c.tx_plan(t), TxPlan::Arp(_)), "t={t}");
            assert!(matches!(c.tx_plan(t + 1), TxPlan::Wait(_)));
        }
        // after the fifth is unanswered for a second, the packet is dropped and counted
        assert_eq!(c.tx_plan(5_000), TxPlan::Idle);
        let s = c.snapshot();
        assert_eq!(s.tx_arp.get(), 5);
        assert_eq!(s.tx_dropped(TxDrop::ArpFailed), 1);
        assert_eq!(s.arp.gave_up.get(), 1);
        assert_eq!(c.tx_len(), 0);
    }

    #[test]
    fn arp_reply_resolves_and_the_packet_is_framed() {
        let mut c = up();
        c.tx_push(&pkt(STA, 0x0808_0808, 40), None).unwrap();
        assert!(matches!(c.tx_plan(0), TxPlan::Arp(_)));
        // the gateway answers
        let mut a = std::vec![0, 1, 8, 0, 6, 4, 0, 2];
        a.extend_from_slice(&GWM);
        a.extend_from_slice(&GW.to_be_bytes());
        a.extend_from_slice(&MAC);
        a.extend_from_slice(&STA.to_be_bytes());
        let f = eth_frame(MAC, GWM, 0x0806, &a);
        assert_eq!(c.rx_pre(100, &f), RxClass::Arp);
        assert_eq!(c.gateway_mac(), Some(GWM));
        assert_eq!(c.snapshot().snooped.get(), 1);
        let TxPlan::Frame(mac) = c.tx_plan(100) else { panic!() };
        assert_eq!(mac, GWM);
        let n = c.head_frame_len().unwrap();
        let mut out = std::vec![0u8; n];
        c.pop_frame(&mut out, mac);
        assert_eq!(&out[0..6], &GWM);
        assert_eq!(&out[6..12], &MAC);
        assert_eq!(&out[12..14], &[8, 0]);
        assert_eq!(rd32(&out, 14 + 12), STA);
        assert_eq!(c.snapshot().tx_napt.get(), 1);
        assert_eq!(c.tx_plan(101), TxPlan::Idle);
    }

    #[test]
    fn snooping_needs_the_gateways_address_and_ignores_the_rest() {
        let mut c = up();
        // an IPv4 frame from another IP with the gateway's MAC teaches nothing (the remote's MAC is not the gateway's address)
        let f = eth_frame(MAC, GWM, 0x0800, &pkt(0x0808_0808, STA, 28));
        let _ = c.rx_pre(0, &f);
        assert_eq!(c.gateway_mac(), None);
        // from the gateway's own IP it does
        let f = eth_frame(MAC, GWM, 0x0800, &pkt(GW, STA, 28));
        let _ = c.rx_pre(1, &f);
        assert_eq!(c.gateway_mac(), Some(GWM));
        // a spoof from a group MAC is dropped before snooping
        let mut c = up();
        let f = eth_frame(MAC, [1, 0, 0x5e, 0, 0, 1], 0x0800, &pkt(GW, STA, 28));
        assert_eq!(c.rx_pre(0, &f), RxClass::Drop(RxDrop::BadSource));
        assert_eq!(c.gateway_mac(), None);
        // an ARP request for another host teaches nothing new either
        let mut a = std::vec![0, 1, 8, 0, 6, 4, 0, 1];
        a.extend_from_slice(&GWM);
        a.extend_from_slice(&GW.to_be_bytes());
        a.extend_from_slice(&[0; 6]);
        a.extend_from_slice(&0xC0A8_0164u32.to_be_bytes());
        let f = eth_frame([0xff; 6], GWM, 0x0806, &a);
        let _ = c.rx_pre(0, &f);
        assert_eq!(c.gateway_mac(), None);
        // and the mux never builds an ARP reply for the station's address (the stack does)
        assert_eq!(c.snapshot().arp.replies.get(), 0);
    }

    #[test]
    fn on_link_broadcast_and_multicast_next_hops() {
        let mut c = up();
        let send = |c: &mut Core<2, 2>, dst: u32| {
            c.tx_push(&pkt(STA, dst, 28), None).unwrap();
            c.tx_plan(0)
        };
        assert_eq!(send(&mut c, u32::MAX), TxPlan::Frame([0xff; 6]));
        let _ = c.tx.pop();
        assert_eq!(send(&mut c, 0xC0A8_01FF), TxPlan::Frame([0xff; 6]));
        let _ = c.tx.pop();
        assert_eq!(send(&mut c, 0xE000_00FB), TxPlan::Frame([1, 0, 0x5e, 0, 0, 0xfb]));
        let _ = c.tx.pop();
        // an on-link host is resolved itself, not via the gateway
        let TxPlan::Arp(f) = send(&mut c, 0xC0A8_010A) else { panic!() };
        assert_eq!(rd32(&f, 38), 0xC0A8_010A);
        // no gateway in the lease: off-link is refused
        let mut c = Core::<2, 2>::new(MAC);
        c.set_want(Some(Ipv4Cfg { gateway: None, ..cfg() }));
        let _ = c.take_sync();
        let _ = c.set_link(true);
        c.tx_push(&pkt(STA, 0x0808_0808, 28), None).unwrap();
        assert_eq!(c.tx_plan(0), TxPlan::Idle);
        assert_eq!(c.snapshot().tx_dropped(TxDrop::NoGateway), 1);
        // a gateway outside the subnet
        let mut c = Core::<2, 2>::new(MAC);
        c.set_want(Some(Ipv4Cfg { gateway: Some(0x0A00_0001), ..cfg() }));
        let _ = c.take_sync();
        let _ = c.set_link(true);
        c.tx_push(&pkt(STA, 0x0808_0808, 28), None).unwrap();
        assert_eq!(c.tx_plan(0), TxPlan::Idle);
        assert_eq!(c.snapshot().tx_dropped(TxDrop::NoRoute), 1);
    }

    #[test]
    fn refresh_sends_the_packet_and_a_request() {
        let mut c = up();
        let f = eth_frame(MAC, GWM, 0x0800, &pkt(GW, STA, 28));
        let _ = c.rx_pre(0, &f);
        c.tx_push(&pkt(STA, 0x0808_0808, 28), None).unwrap();
        c.tx_push(&pkt(STA, 0x0808_0808, 28), None).unwrap();
        assert_eq!(c.tx_plan(1_000), TxPlan::Frame(GWM));
        let mut out = std::vec![0u8; 42];
        c.pop_frame(&mut out, GWM);
        // at 290 s the entry is close to expiry: the packet goes, then the refresh request
        let _ = c.rx_pre(0, &f);
        c.tx_push(&pkt(STA, 0x0808_0808, 28), None).unwrap();
        assert!(matches!(c.tx_plan(290_000), TxPlan::Frame(_)));
        assert!(matches!(c.tx_plan(290_000), TxPlan::Arp(_)));
    }

    #[test]
    fn host_queue_is_bounded_and_counts() {
        let mut c = up();
        assert!(c.host_push(&pkt(1, 2, 100)));
        assert!(c.host_push(&pkt(1, 2, 200)));
        assert!(!c.host_push(&pkt(1, 2, 300)));
        assert_eq!(c.snapshot().rx_dropped(RxDrop::HostQueueFull), 1);
        let mut small = [0u8; 150];
        // the first fits, the second does not: dropped and counted, never truncated
        assert_eq!(c.host_pop(&mut small, None), Some(100));
        assert_eq!(c.host_pop(&mut small, None), None);
        assert_eq!(c.snapshot().host_buf_too_small.get(), 1);
        assert_eq!(c.host_len(), 0);
    }

    #[test]
    fn config_and_association_changes_flush() {
        let mut c = up();
        let f = eth_frame(MAC, GWM, 0x0800, &pkt(GW, STA, 28));
        let _ = c.rx_pre(0, &f);
        c.tx_push(&pkt(STA, 0x0808_0808, 28), None).unwrap();
        // same configuration again: nothing
        c.set_want(Some(cfg()));
        assert!(c.take_sync().is_none());
        // a new gateway only (same address and mask) keeps the neighbours but the table is looked up by the new gateway address
        c.set_want(Some(Ipv4Cfg { gateway: Some(GW + 1), ..cfg() }));
        let a = c.take_sync().unwrap();
        assert!(!a.reset);
        assert_eq!(c.gateway_mac(), None);
        // a new address resets and flushes
        c.set_want(Some(Ipv4Cfg { addr: STA + 1, ..cfg() }));
        let a = c.take_sync().unwrap();
        assert!(a.reset);
        assert_eq!(c.snapshot().tx_dropped(TxDrop::Flushed), 1);
        // a new association with the same address resets as well
        let _ = c.rx_pre(0, &f);
        c.bump_generation();
        assert!(c.take_sync().unwrap().reset);
        assert_eq!(c.gateway_mac(), None);
        // link down: counted once, flushed, tap told to reset
        c.tx_push(&pkt(STA + 1, 0x0808_0808, 28), None).unwrap();
        assert!(c.set_link(false));
        assert!(!c.set_link(false));
        assert_eq!(c.snapshot().link_downs.get(), 1);
        assert_eq!(c.tx_len(), 0);
        // unconfigured: the address goes away
        c.set_want(None);
        assert_eq!(c.take_sync().unwrap().cfg, None);
        assert_eq!(c.tx_push(&pkt(STA, 1, 28), None), Err(TxDrop::NoConfig));
    }

    #[test]
    fn every_rx_drop_and_tx_drop_has_a_distinct_dense_index() {
        let rx = [
            RxDrop::Runt,
            RxDrop::Oversize,
            RxDrop::NotForUs,
            RxDrop::BadSource,
            RxDrop::BadIpv4,
            RxDrop::TapRejected,
            RxDrop::TapDropped,
            RxDrop::TapBadRange,
            RxDrop::HostQueueFull,
        ];
        for (i, r) in rx.iter().enumerate() {
            assert_eq!(r.index(), i);
        }
        assert_eq!(rx.len(), RxDrop::COUNT);
        let tx = [
            TxDrop::Runt,
            TxDrop::Oversize,
            TxDrop::NotIpv4,
            TxDrop::WrongSource,
            TxDrop::QueueFull,
            TxDrop::NoConfig,
            TxDrop::LinkDown,
            TxDrop::NoGateway,
            TxDrop::NoRoute,
            TxDrop::ArpFailed,
            TxDrop::Flushed,
        ];
        for (i, r) in tx.iter().enumerate() {
            assert_eq!(r.index(), i);
        }
        assert_eq!(tx.len(), TxDrop::COUNT);
    }
}
