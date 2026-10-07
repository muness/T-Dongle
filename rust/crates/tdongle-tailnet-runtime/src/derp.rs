//! The DERP task of a membership slot: the relay link's sans-IO state machine (`tdongle_tailnet_derp::Link`) driven over the slot's TCP handle and the
//! shared-lease TLS connection, with the negotiation token held around the handshake.
//!
//! # How the pieces meet
//!
//! * **The link is owned by this future** (no lock): the engine never touches it. The engine's `DerpSend` outputs arrive through the slot's egress queue
//!   and `DerpConnect` / `DerpClose` through its command cell; both are taken here and handed to the link. Everything the link reports (a relayed packet, ready
//!   or not) goes to the engine **inline** (`Shared::feed`), which is safe because the engine's outputs never call back into a link.
//! * **Token (phase B)**: the link asks (`Action::WantToken`) and wants a timer every 50 ms; the timer handler polls `Token::request` and reports the grant.
//!   The token is released when the link says so (`ReleaseToken`: at ready or on any teardown), on `Close`, and when this future is dropped.
//! * **TLS**: `LeasedTlsDerp` pins no read buffer: the future waits for the next record's header without any lease (`wait_record`), then takes the one shared
//!   16,640-byte buffer for that record only. Packets are delivered to the engine while the lease is held (as the C delivers under its lock), so a handshake
//!   response (two X25519) delays other memberships' relay reads by a few tens of milliseconds, once per handshake.
//! * **Cancellation**: a write that is cancelled may have written a prefix; a TLS handshake that is cancelled is unusable. Either way the connection is
//!   closed and the link told (`Reconnect` / `Close`), never reused.
//! * A `Send` action is copied into the slot's one staging buffer and written by this future; the link allows exactly one outstanding send.

use crate::net::{Net, TcpConn, TcpRole};
use crate::shared::{ALIVE_DERP, DerpCmd, Shared};
use crate::taskutil::{Alive, wait_active, wait_changed};
use crate::token::key_derp;
use core::cell::RefCell;
use core::future::{Future, pending};
use core::pin::pin;
use embassy_futures::select::{Either, Either3, select, select3};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Timer;
use tdongle_tailnet_admission::negotiation::{Grant, Phase, Prio};
use tdongle_tailnet_derp::{Action, Event, Link, LinkEvent, MAX_FRAME, MAX_PACKET, MAX_SEND_FRAME, Sink, State, Target, Timing};
use tdongle_tailnet_engine::{DerpNote, Input, PeerDirectory};
use tdongle_tailnet_fw::{Platform, Storage};
use tdongle_tailnet_tls::lease::{LeasedTlsDerp, ReadError};
use tdongle_tailnet_tls::transport::{ConnectError, TlsParams};
use tdongle_tailnet_pool::{Class, PoolBuf};
use tdongle_tailnet_tls::{DEFAULT_ANCHORS, WRITE_RECORD_BYTES};
use tdongle_tailnet_types::{FixedStr, Key32};

/// Times a relay packet stayed in the egress queue because the link's ring was full (it is sent after the one being written), and link restarts by cause:
/// lease timeout, TLS error, record wait error, write error (`tn_in` line).
pub static DERP_EGRESS_HELD: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// See [`DERP_EGRESS_HELD`]: `[lease_timeout, tls, wait_record, write]`.
pub static DERP_RECONNECT: [core::sync::atomic::AtomicU32; 4] = [const { core::sync::atomic::AtomicU32::new(0) }; 4];

/// What the relay connection is doing, for the `tn_derp` line: the region and port of the target, its address, the stage reached (1 dial, 2 connected, 3 TLS done, 4 relaying), when
/// the current link became ready, how the last one ended (`END_*`) after how long, and the text of the transport error that ended it.
pub struct DerpDiag {
    /// Region id and port of the last target.
    pub region: core::sync::atomic::AtomicU32,
    /// See `region`.
    pub port: core::sync::atomic::AtomicU32,
    /// Address dialed (big endian).
    pub ip: core::sync::atomic::AtomicU32,
    /// Stage reached by the current attempt.
    pub stage: core::sync::atomic::AtomicU32,
    /// Milliseconds clock at the current link's ready, 0 when it is not ready.
    pub ready_at_ms: core::sync::atomic::AtomicU32,
    /// How the last link ended (see `END_*`) and how long it had been ready, ms.
    pub end: core::sync::atomic::AtomicU32,
    /// See `end`.
    pub end_after_ms: core::sync::atomic::AtomicU32,
    /// Links ended by each cause: `[wait_record, lease, tls_read, write, link_asked_close, other]`.
    pub ends: [core::sync::atomic::AtomicU32; 6],
    /// Host name and the last transport error text.
    pub text: embassy_sync::blocking_mutex::Mutex<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, core::cell::RefCell<([u8; 64], [u8; 64])>>,
}
pub use tdongle_tailnet_derp::link::LAST_RX_FRAME_TYPE;
/// See [`DerpDiag`].
pub const END_WAIT: u32 = 1;
/// See [`DerpDiag`].
pub const END_LEASE: u32 = 2;
/// See [`DerpDiag`].
pub const END_TLS_READ: u32 = 3;
/// See [`DerpDiag`].
pub const END_WRITE: u32 = 4;
/// See [`DerpDiag`].
pub const END_LINK: u32 = 5;
/// The relay's diagnostics (one membership's relay; a second membership overwrites it).
impl DerpDiag {
    const fn new() -> DerpDiag {
        DerpDiag {
    region: core::sync::atomic::AtomicU32::new(0),
    port: core::sync::atomic::AtomicU32::new(0),
    ip: core::sync::atomic::AtomicU32::new(0),
    stage: core::sync::atomic::AtomicU32::new(0),
    ready_at_ms: core::sync::atomic::AtomicU32::new(0),
    end: core::sync::atomic::AtomicU32::new(0),
    end_after_ms: core::sync::atomic::AtomicU32::new(0),
    ends: [const { core::sync::atomic::AtomicU32::new(0) }; 6],
    text: embassy_sync::blocking_mutex::Mutex::new(core::cell::RefCell::new(([0; 64], [0; 64]))),
        }
    }
}
/// The relay's diagnostics (the member's home link).
pub static DERP_DIAG: DerpDiag = DerpDiag::new();
/// The same for the member's extra link (the region a peer is homed on, when it is not the member's home).
pub static X_DIAG: DerpDiag = DerpDiag::new();

fn diag_text(dg: &DerpDiag, slot: usize, s: &str) {
    dg.text.lock(|t| {
        let mut t = t.borrow_mut();
        let dst = if slot == 0 { &mut t.0 } else { &mut t.1 };
        dst.fill(0);
        let n = s.len().min(dst.len());
        dst[..n].copy_from_slice(&s.as_bytes()[..n]);
    });
}

fn diag_end(dg: &DerpDiag, sh_now: u64, cause: u32, err: Option<&dyn core::fmt::Debug>) {
    use core::sync::atomic::Ordering::Relaxed;
    let ready_at = dg.ready_at_ms.swap(0, Relaxed);
    dg.end.store(cause, Relaxed);
    dg.end_after_ms.store(if ready_at == 0 { 0 } else { (sh_now as u32).wrapping_sub(ready_at) }, Relaxed);
    dg.ends[(cause as usize).min(5)].fetch_add(1, Relaxed);
    if let Some(e) = err {
        let mut b = [0u8; 64];
        let mut w = Cursor(&mut b, 0);
        let _ = core::fmt::write(&mut w, format_args!("{e:?}"));
        let n = w.1;
        diag_text(dg, 1, core::str::from_utf8(&b[..n]).unwrap_or(""));
    }
}

struct Cursor<'a>(&'a mut [u8], usize);
impl core::fmt::Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.0.len() - self.1);
        self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
        self.1 += n;
        Ok(())
    }
}


/// Relay packets for peers homed on a region other than the member's home one, waiting for the member's extra link: heap blocks (a packet is up to 1.5 KB), at most
/// [`XQ_MAX`], admitted above the elastic floor like every other consumer.
struct XPacket {
    slot: u8,
    region: u16,
    dst: [u8; 32],
    data: alloc::vec::Vec<u8>,
}
/// See [`XPacket`].
static XQ: embassy_sync::blocking_mutex::Mutex<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, RefCell<alloc::vec::Vec<XPacket>>> =
    embassy_sync::blocking_mutex::Mutex::new(RefCell::new(alloc::vec::Vec::new()));
static X_SIG: embassy_sync::signal::Signal<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, ()> = embassy_sync::signal::Signal::new();
/// Packets the extra link may hold waiting.
pub const XQ_MAX: usize = 8;
/// How long the extra link stays up with nothing to send before it is closed and its memory given back.
pub const X_IDLE_MS: u32 = 60_000;
/// The extra link's last activity (a packet queued for it or sent by it), ms clock.
static X_LAST_MS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// `[queued, sent, dropped (queue full), dropped (heap), dropped (region not in the map), link starts]`.
pub static X_COUNTS: [core::sync::atomic::AtomicU32; 6] = [const { core::sync::atomic::AtomicU32::new(0) }; 6];
/// State and counts of the extra link's last run, for `tn_derp`.
pub static X_STATS: embassy_sync::blocking_mutex::Mutex<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, RefCell<(State, tdongle_tailnet_derp::link::Stats)>> =
    embassy_sync::blocking_mutex::Mutex::new(RefCell::new((State::Idle, tdongle_tailnet_derp::link::Stats::new())));

fn push_x<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, idx: usize, region: u16, dst: &[u8], data: &[u8]) {
    use core::sync::atomic::Ordering::Relaxed;
    let mut v = alloc::vec::Vec::new();
    if !tdongle_tailnet_admission::heap::hb_ok(sh.mem().heap.free(), data.len() + 64) || v.try_reserve_exact(data.len()).is_err() {
        X_COUNTS[3].fetch_add(1, Relaxed);
        return;
    }
    v.extend_from_slice(data);
    let mut key = [0u8; 32];
    key.copy_from_slice(&dst[..32]);
    let ok = XQ.lock(|q| {
        let mut q = q.borrow_mut();
        if q.len() >= XQ_MAX {
            return false;
        }
        q.push(XPacket { slot: idx as u8, region, dst: key, data: v });
        true
    });
    if ok {
        X_COUNTS[0].fetch_add(1, Relaxed);
        X_LAST_MS.store((sh.now() as u32).max(1), Relaxed);
        X_SIG.signal(());
    } else {
        X_COUNTS[2].fetch_add(1, Relaxed);
    }
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Drv<'_, '_, R, P, S, D> {
    /// The extra link's egress: the packets queued for its region, handed to the link while it has room.
    fn pump_x(&mut self, region: u16) {
        use core::sync::atomic::Ordering::Relaxed;
        let idx = self.idx as u8;
        loop {
            let Some(pkt) = XQ.lock(|q| {
                let mut q = q.borrow_mut();
                let i = q.iter().position(|p| p.slot == idx && p.region == region)?;
                Some(q.remove(i))
            }) else {
                break;
            };
            let now = self.sh.now();
            let Drv { sh, idx, member, link, acts, stage, x, .. } = self;
            let mut sink = DrvSink { sh, idx: *idx, member: *member, acts, stage, x: x.is_some() };
            match link.send_packet(now, &pkt.dst, &pkt.data, &mut sink) {
                Err(tdongle_tailnet_derp::txq::TxDrop::NoSpace | tdongle_tailnet_derp::txq::TxDrop::OverBudget) => {
                    // the link's ring is full: back to the front, sent after the frame being written
                    XQ.lock(|q| q.borrow_mut().insert(0, pkt));
                    break;
                }
                Ok(()) => {
                    X_COUNTS[1].fetch_add(1, Relaxed);
                    X_LAST_MS.store((now as u32).max(1), Relaxed);
                }
                Err(_) => {}
            }
        }
        self.after();
    }
}

/// The member's extra relay link, for peers homed on a region other than the member's home: not started until a packet needs it, closed after [`X_IDLE_MS`] without
/// one, one region at a time. The link future is a heap block (about 10 KB) for as long as the link exists: nothing of it is static. Never returns.
pub async fn derp_extra<R, P, S, D, N>(sh: &Shared<R, P, S, D>, idx: usize, net: &N)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
{
    use core::sync::atomic::Ordering::Relaxed;
    let slot = &sh.slots[idx];
    let mut tcp = net.tcp(crate::net::TcpRole::DerpExtra, idx).expect("the Net has no extra DERP TCP handle for this slot");
    loop {
        // the region of the first packet waiting for this slot
        let region = loop {
            if let Some(r) = XQ.lock(|q| q.borrow().iter().find(|p| p.slot == idx as u8).map(|p| p.region)) {
                break r;
            }
            X_SIG.wait().await;
        };
        let member = slot.id.load(core::sync::atomic::Ordering::Acquire);
        let Some((host, port)) = sh.with_engine(|e, _| e.derp_target(member, region)) else {
            // a region the member's map does not have: nothing to dial
            let n = XQ.lock(|q| {
                let mut q = q.borrow_mut();
                let before = q.len();
                q.retain(|p| !(p.slot == idx as u8 && p.region == region));
                before - q.len()
            });
            X_COUNTS[4].fetch_add(n as u32, Relaxed);
            continue;
        };
        // the link future is a heap block of about the size of the home link's (measured at start-up): admitted above the elastic floor, or the packets wait for the next try
        let fut_bytes = sh.fut_bytes[crate::sizes::FUT_DERP].load(Relaxed) as usize;
        if !tdongle_tailnet_admission::heap::hb_ok(sh.mem().heap.free(), fut_bytes + 4096) {
            X_COUNTS[3].fetch_add(1, Relaxed);
            XQ.lock(|q| q.borrow_mut().retain(|p| p.slot != idx as u8));
            Timer::after_secs(2).await;
            continue;
        }
        X_COUNTS[5].fetch_add(1, Relaxed);
        X_LAST_MS.store((sh.now() as u32).max(1), Relaxed);
        let key = slot.ident.lock(|i| i.borrow().wg.clone());
        // the link runs as a heap future; the watcher ends it when the home link is gone or the link has been idle
        let link = alloc::boxed::Box::pin(async {
            let mem = sh.mem();
            let wbuf = mem.alloc_wait(Class::Socket, WRITE_RECORD_BYTES).await;
            let stage = mem.alloc_wait(Class::Socket, MAX_SEND_FRAME).await;
            let (mut wbuf, stage) = (wbuf, RefCell::new(stage));
            relay(sh, idx, member, key, &mut tcp, &stage, &mut wbuf[..], Some((region, host, port))).await;
        });
        let watch = async {
            loop {
                Timer::after_secs(5).await;
                let idle = (sh.now() as u32).wrapping_sub(X_LAST_MS.load(Relaxed)) > X_IDLE_MS;
                let home_gone = slot.status().derp_state != State::Ready;
                // another region's packets are waiting and this one has had its turn (two seconds idle): switch
                let other = XQ.lock(|q| q.borrow().iter().any(|p| p.slot == idx as u8 && p.region != region));
                let quiet = (sh.now() as u32).wrapping_sub(X_LAST_MS.load(Relaxed)) > 2000 && !XQ.lock(|q| q.borrow().iter().any(|p| p.slot == idx as u8 && p.region == region));
                if idle || home_gone || (other && quiet) {
                    break;
                }
            }
        };
        select(link, watch).await;
        // the link future is dropped: its socket's windows go back to the pool, the reset reaches the server
        tcp.release().await;
        X_STATS.lock(|c| c.borrow_mut().0 = State::Idle);
        X_DIAG.ready_at_ms.store(0, Relaxed);
        if slot.status().derp_state != State::Ready {
            XQ.lock(|q| q.borrow_mut().retain(|p| p.slot != idx as u8));
        }
    }
}

/// Room the host queue must have before a relay record is read (see `stream`).
pub const HOST_ROOM: usize = 4096;

/// Transmit-ring bytes of a membership's relay link. The engine's ledger charges `status::DERP_TXQ` (4,096) for its own accounting; the runtime runs
/// smaller: in front of the link sits the slot's egress queue ([`crate::shared::DERP_Q`]) and the USB side holds frames that would not fit (see `usb`),
/// so the link needs room for the frame it is writing and one behind it.
pub const DERP_TXQ: usize = 2048;

/// What the link's last call asked the driver to do.
#[derive(Debug, Default)]
struct Acts {
    dial: Option<(FixedStr<64>, u16)>,
    tls: Option<FixedStr<64>>,
    send: Option<usize>,
    close: bool,
    want_token: bool,
    release: bool,
}

/// The link and everything around it.
struct Drv<'a, 'p, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> {
    sh: &'a Shared<R, P, S, D>,
    idx: usize,
    member: u32,
    link: Link<DERP_TXQ>,
    acts: Acts,
    stage: &'a RefCell<PoolBuf<'p>>,
    holds_token: bool,
    clock_fed: Option<bool>,
    /// `Some(region)`: this is the member's extra link to that region, not its home link (no engine link events, no commands, its packets come from [`XQ`]).
    x: Option<u16>,
}

struct DrvSink<'a, 'p, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> {
    sh: &'a Shared<R, P, S, D>,
    idx: usize,
    member: u32,
    acts: &'a mut Acts,
    stage: &'a RefCell<PoolBuf<'p>>,
    x: bool,
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Sink for DrvSink<'_, '_, R, P, S, D> {
    fn action(&mut self, a: Action<'_>) {
        let member = self.member;
        match a {
            Action::Notify(LinkEvent::Connected) => {
                let dg = if self.x { &X_DIAG } else { &DERP_DIAG };
                dg.stage.store(4, core::sync::atomic::Ordering::Relaxed);
                dg.ready_at_ms.store((self.sh.now() as u32).max(1), core::sync::atomic::Ordering::Relaxed);
                // the engine's `derp_ready` is about the home link only
                if !self.x {
                    let _ = self.sh.feed(Input::DerpLinkEvent { member, event: DerpNote::Connected });
                }
            }
            Action::Notify(LinkEvent::Disconnected | LinkEvent::RxStale) => {
                if !self.x {
                    self.sh.slots[self.idx].derp_q.clear();
                    let _ = self.sh.feed(Input::DerpLinkEvent { member, event: DerpNote::Disconnected });
                }
            }
            Action::Notify(LinkEvent::ConnectFailed) => {
                if !self.x {
                    self.sh.slots[self.idx].derp_q.clear();
                    let _ = self.sh.feed(Input::DerpLinkEvent { member, event: DerpNote::ConnectFailed });
                }
            }
            Action::Notify(LinkEvent::ClockDeferred) => self.sh.slots[self.idx].update(|st| st.tls_deferred = st.tls_deferred.wrapping_add(1)),
            Action::WantToken => self.acts.want_token = true,
            Action::ReleaseToken => self.acts.release = true,
            Action::Dial { host, port, .. } => {
                let mut h = FixedStr::new();
                h.set(host);
                self.acts.dial = Some((h, port));
            }
            Action::StartTls { host } => {
                let mut h = FixedStr::new();
                h.set(host);
                self.acts.tls = Some(h);
            }
            Action::Send(b) => match self.stage.try_borrow_mut() {
                Ok(mut st) if b.len() <= st.len() => {
                    st[..b.len()].copy_from_slice(b);
                    self.acts.send = Some(b.len());
                }
                // cannot happen (one send outstanding, frames bounded); the link's stall timer ends a link that would hit it
                _ => {}
            },
            Action::Close => self.acts.close = true,
            Action::DeliverPacket { src_key, payload } => {
                // the engine takes the packet in a buffer it may change: the shared scratch, for this call only
                let sh = self.sh;
                sh.with_scratch(|buf| {
                    let n = payload.len().min(MAX_FRAME).min(buf.len());
                    buf[..n].copy_from_slice(&payload[..n]);
                    let _ = sh.feed(Input::DerpPacket { member, src: src_key, data: &mut buf[..n] });
                });
            }
            Action::PeerGone { .. } | Action::Health(_) | Action::ServerRestarting { .. } => {}
        }
    }
}

impl<'a, 'p, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Drv<'a, 'p, R, P, S, D> {
    fn new(sh: &'a Shared<R, P, S, D>, idx: usize, member: u32, key: Key32, stage: &'a RefCell<PoolBuf<'p>>) -> Self {
        Drv {
            sh,
            idx,
            member,
            link: Link::new(key, Target::new(0, "", 443), Timing::DEFAULT),
            acts: Acts::default(),
            stage,
            holds_token: false,
            clock_fed: None,
            x: None,
        }
    }

    fn dg(&self) -> &'static DerpDiag {
        if self.x.is_some() { &X_DIAG } else { &DERP_DIAG }
    }

    fn call(&mut self, ev: Event<'_>) {
        let now = self.sh.now();
        let mut rng = crate::shared::PlatformRng(&self.sh.platform);
        {
            let Drv { sh, idx, member, link, acts, stage, x, .. } = self;
            let mut sink = DrvSink { sh, idx: *idx, member: *member, acts, stage, x: x.is_some() };
            link.handle(now, ev, &mut rng, &mut sink);
        }
        self.after();
    }

    fn after(&mut self) {
        let now = self.sh.now();
        if self.acts.release || self.acts.close {
            self.acts.release = false;
            self.release_token(now);
        }
        let (state, stats) = (self.link.state(), *self.link.stats());
        if self.x.is_some() {
            X_STATS.lock(|c| *c.borrow_mut() = (state, stats));
            return;
        }
        self.sh.slots[self.idx].update(|st| {
            st.derp_state = state;
            st.derp = stats;
        });
    }

    fn release_token(&mut self, now: u64) {
        // idempotent: also takes a waiting (not yet granted) request out of the queue (the extra link does not use the token: it would take the home link's)
        if self.x.is_none() {
            self.sh.token.release(now, key_derp(self.member));
        }
        self.holds_token = false;
    }

    /// Tell the link whether the wall clock is set, when that changed.
    fn sync_clock(&mut self) {
        let v = self.sh.platform.unix_seconds().is_some();
        if self.clock_fed != Some(v) {
            self.clock_fed = Some(v);
            self.call(Event::ClockValid(v));
        }
    }

    fn on_cmd(&mut self, cmd: DerpCmd) {
        match cmd {
            DerpCmd::Connect { region, host, port } => {
                let moved = self.link.target().region != region || self.link.target().host.as_str() != host.as_str();
                let was_ready = self.link.state() == State::Ready;
                self.link.set_target(Target::new(region, host.as_str(), port));
                if was_ready && moved {
                    self.call(Event::Reconnect);
                } else {
                    self.call(Event::Connect);
                }
            }
            DerpCmd::Close => self.call(Event::Close),
        }
    }

    fn on_timer(&mut self) {
        self.sync_clock();
        self.call(Event::Timer);
        if self.x.is_some() && self.link.state() == State::Token && self.link.want_token() && !self.holds_token {
            // the extra link takes no turn at the negotiation token (the home link's key is the member's); its TLS handshake is admitted by the pool and the lease like any other
            self.holds_token = true;
            self.call(Event::TokenGranted);
        } else if self.link.state() == State::Token && self.link.want_token() && !self.holds_token {
            let now = self.sh.now();
            match self.sh.token.request(now, key_derp(self.member), Prio::Relay, Phase::Derp) {
                Grant::Granted => {
                    self.holds_token = true;
                    self.call(Event::TokenGranted);
                }
                Grant::Queued | Grant::Full => {}
            }
        }
    }

    /// Move the engine's relay packets into the link (which counts the ones it cannot send).
    fn pump_egress(&mut self) {
        if let Some(region) = self.x {
            return self.pump_x(region);
        }
        let mut eg = [0u8; 32 + MAX_PACKET + 32];
        // a packet leaves the egress queue only when the link took it: the link's ring holds the frame being written and little else, so the rest waits here (before, every
        // packet after the first was popped, refused by the link and lost, which TCP in the tunnel cannot live with)
        while let Some((_k, n)) = self.sh.slots[self.idx].derp_q.try_peek(&mut eg) {
            if n < 34 {
                self.sh.slots[self.idx].derp_q.discard_front();
                continue;
            }
            // a packet for a peer homed on another region: a relay server only forwards to clients connected to it, so it goes to the member's link to that region
            let region = u16::from_be_bytes([eg[32], eg[33]]);
            if region != 0 && region != self.link.target().region {
                push_x(self.sh, self.idx, region, &eg[..32], &eg[34..n]);
                self.sh.slots[self.idx].derp_q.discard_front();
                continue;
            }
            let now = self.sh.now();
            let mut dst = [0u8; 32];
            dst.copy_from_slice(&eg[..32]);
            let Drv { sh, idx, member, link, acts, stage, x, .. } = self;
            let mut sink = DrvSink { sh, idx: *idx, member: *member, acts, stage, x: x.is_some() };
            match link.send_packet(now, &dst, &eg[34..n], &mut sink) {
                Err(tdongle_tailnet_derp::txq::TxDrop::NoSpace | tdongle_tailnet_derp::txq::TxDrop::OverBudget) => {
                    DERP_EGRESS_HELD.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    break;
                }
                _ => self.sh.slots[self.idx].derp_q.discard_front(),
            }
        }
        self.after();
    }

    /// Wait for the next thing the link needs attention for and handle it: an engine command, the link's own timer, or (when `egress`) a relay packet.
    /// Cancel-safe up to the moment it returns.
    async fn wait(&mut self, egress: bool) {
        let now = self.sh.now();
        let deadline = self.link.next_deadline_ms(now);
        let sh = self.sh;
        let slot = &sh.slots[self.idx];
        let timer = async {
            match deadline {
                Some(ms) => Timer::after_millis(u64::from(ms.max(1))).await,
                None => pending::<()>().await,
            }
        };
        let is_x = self.x.is_some();
        let eg = async {
            if egress && is_x {
                X_SIG.wait().await;
            } else if egress {
                slot.derp_q.wait_nonempty().await;
            } else {
                pending::<()>().await;
            }
        };
        let cmd = async {
            if is_x {
                pending::<DerpCmd>().await
            } else {
                slot.derp_cmd.wait().await
            }
        };
        match select3(cmd, timer, eg).await {
            Either3::First(cmd) => self.on_cmd(cmd),
            Either3::Second(()) => self.on_timer(),
            Either3::Third(()) => self.pump_egress(),
        }
    }

    fn must_abort(&self) -> bool {
        self.acts.close
    }
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Drop for Drv<'_, '_, R, P, S, D> {
    fn drop(&mut self) {
        if self.x.is_none() && (self.holds_token || self.link.want_token()) {
            self.sh.token.release(self.sh.now(), key_derp(self.member));
        }
    }
}

/// Run `work` while serving the link; `None` if the link asked for the transport to be closed first (the work is dropped).
///
/// `work` is passed **already pinned** (`pin!` at the call site): a future moved into this function and pinned here lives twice in the caller's frame
/// (as the argument and as the pinned local), and the TLS handshake future is 3 KB.
async fn drive<T, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(
    d: &mut Drv<'_, '_, R, P, S, D>,
    egress: bool,
    mut work: core::pin::Pin<&mut impl Future<Output = T>>,
) -> Option<T> {
    loop {
        match select(&mut work, d.wait(egress)).await {
            Either::First(v) => return Some(v),
            Either::Second(()) => {
                if d.must_abort() {
                    return None;
                }
            }
        }
    }
}

/// The DERP task of slot `idx`. Never returns.
pub async fn derp_slot<R, P, S, D, N>(sh: &Shared<R, P, S, D>, idx: usize, net: &N)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
{
    let slot = &sh.slots[idx];
    let mut tcp = net.tcp(TcpRole::Derp, idx).expect("the Net has no DERP TCP handle for this slot");
    let mut run_rx = slot.run.receiver().expect("slot run receivers");
    loop {
        let run = wait_active(&mut run_rx).await;
        let alive = Alive::new(&slot.alive, ALIVE_DERP);
        let key = slot.ident.lock(|i| i.borrow().wg.clone());
        // the TLS write record and the staging frame (3.6 KB) are taken from the pool for as long as the membership runs, not held by every idle slot; waiting for them
        // does not hide a stop (the run state is watched meanwhile), and a pool that says no is a counted wait, not a failure
        let mem = sh.mem();
        let taken = select(
            async {
                let wbuf = mem.alloc_wait(Class::Socket, WRITE_RECORD_BYTES).await;
                let stage = mem.alloc_wait(Class::Socket, MAX_SEND_FRAME).await;
                (wbuf, stage)
            },
            wait_changed(&mut run_rx, run),
        )
        .await;
        if let Either::First((mut wbuf, stage)) = taken {
            let stage = RefCell::new(stage);
            select(relay(sh, idx, run.id, key, &mut tcp, &stage, &mut wbuf[..], None), wait_changed(&mut run_rx, run)).await;
        }
        // the membership stopped (or changed): the socket's windows go back to the pool, the reset reaches the server
        tcp.release().await;
        sh.token.release(sh.now(), key_derp(run.id));
        slot.derp_q.clear();
        slot.update(|st| {
            st.derp_state = State::Idle;
        });
        drop(alive);
    }
}

/// The membership's relay for as long as it runs: one connect cycle after another, as the link decides.
async fn relay<'p, R, P, S, D, T>(
    sh: &Shared<R, P, S, D>,
    idx: usize,
    member: u32,
    key: Key32,
    tcp: &mut T,
    stage: &RefCell<PoolBuf<'p>>,
    wbuf: &mut [u8],
    x: Option<(u16, FixedStr<64>, u16)>,
) where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    T: TcpConn,
{
    let mut d = Drv::new(sh, idx, member, key, stage);
    if let Some((region, host, port)) = x {
        // an extra link knows its target from the start and asks to connect at once
        d.x = Some(region);
        d.link.set_target(Target::new(region, host.as_str(), port));
        d.sync_clock();
        d.call(Event::Connect);
    }
    d.sync_clock();
    loop {
        // ---- down: serve the link until it asks for a connection
        let (host, port) = loop {
            if let Some(x) = d.acts.dial.take() {
                d.acts.close = false;
                break x;
            }
            d.acts.close = false;
            d.wait(true).await;
        };
        // ---- dial: resolve and connect in one
        d.dg().stage.store(1, core::sync::atomic::Ordering::Relaxed);
        d.dg().region.store(u32::from(d.link.target().region), core::sync::atomic::Ordering::Relaxed);
        d.dg().port.store(u32::from(port), core::sync::atomic::Ordering::Relaxed);
        diag_text(d.dg(), 0, host.as_str());
        let connected = drive(&mut d, true, pin!(tcp.connect(host.as_str(), port))).await;
        match connected {
            Some(Ok(())) => {
                d.dg().stage.store(2, core::sync::atomic::Ordering::Relaxed);
                d.dg().ip.store(tcp.remote_ip(), core::sync::atomic::Ordering::Relaxed);
                d.call(Event::Dns(true));
                d.call(Event::Connected(true));
            }
            Some(Err(crate::net::NetError::Dns)) => {
                tcp.close();
                d.call(Event::Dns(false));
                continue;
            }
            Some(Err(_)) => {
                tcp.close();
                d.call(Event::Dns(true));
                d.call(Event::Connected(false));
                continue;
            }
            None => {
                tcp.close();
                continue;
            }
        }
        let Some(tls_host) = d.acts.tls.take() else {
            tcp.close();
            continue;
        };
        // ---- TLS and the relay protocol
        stream(&mut d, tcp, wbuf, tls_host.as_str()).await;
        tcp.close();
        d.acts.send = None;
        d.acts.tls = None;
        d.acts.dial = None;
        let now = sh.now();
        d.release_token(now);
    }
}

async fn stream<R, P, S, D, T>(d: &mut Drv<'_, '_, R, P, S, D>, tcp: &mut T, wbuf: &mut [u8], host: &str)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    T: TcpConn,
{
    let sh = d.sh;
    let slot = &sh.slots[d.idx];
    let cert = slot.status().certs.of(d.link.target().region);
    let now_unix = sh.platform.unix_seconds().unwrap_or(0);
    let params = TlsParams { hostname: host, cert: &cert, anchors: DEFAULT_ANCHORS, now_unix };
    let mut rng = crate::shared::PlatformRng(&sh.platform);
    let handshake = LeasedTlsDerp::connect(&mut *tcp, &mut wbuf[..], &sh.lease, sh.mem(), &params, &mut rng);
    let neg = sh.stats.negotiation();
    let outcome = drive(d, true, pin!(handshake)).await;
    drop(neg);
    let mut conn = match outcome {
        None => return,
        Some(Ok(c)) => {
            slot.update(|st| st.tls_ok = st.tls_ok.wrapping_add(1));
            c
        }
        Some(Err(e)) => {
            if matches!(e, ConnectError::Untrusted(_)) {
                slot.update(|st| st.tls_untrusted = st.tls_untrusted.wrapping_add(1));
            }
            d.call(Event::TlsDone(false));
            return;
        }
    };
    d.dg().stage.store(3, core::sync::atomic::Ordering::Relaxed);
    d.call(Event::TlsDone(true));
    loop {
        // transmit what the link staged (the upgrade request, ClientInfo, a relay frame, a pong)
        while let Some(n) = d.acts.send.take() {
            let write = async {
                let st = stage_bytes(d.stage, n);
                conn.write_all(&st).await?;
                conn.flush().await
            };
            match drive(d, false, pin!(write)).await {
                Some(Ok(())) => d.call(Event::TxDone),
                Some(Err(e)) => {
                    diag_end(d.dg(),sh.now(), END_WRITE, Some(&e));
                    DERP_RECONNECT[3].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    d.call(Event::Reconnect);
                    return;
                }
                None => return,
            }
        }
        if d.acts.close {
            diag_end(d.dg(),sh.now(), END_LINK, None);
            return;
        }
        d.pump_egress();
        if d.acts.send.is_some() {
            continue;
        }
        // back-pressure towards the network: a record (the relay's writes are about 2 KB, up to 16 KB) is read only when the host queue can take what it
        // carries, so a slow USB side slows the TCP connection instead of dropping packets the relay already delivered
        // (not in the middle of a relay frame: the link's 5 s record timer runs from its first byte, and a full host queue during a download held it past that)
        if !d.link.rx_in_frame() && sh.host_q.free_bytes() < crate::derp::HOST_ROOM {
            if let Either::Second(()) = select(Timer::after_millis(2), d.wait(true)).await
                && d.must_abort()
            {
                return;
            }
            continue;
        }
        // wait for the server or for the link
        match select(conn.wait_record(), d.wait(true)).await {
            Either::First(Ok(())) => {
                let stall = d.link_timing_rx_frame();
                let r = conn
                    .read_with(
                        || Timer::after_millis(stall),
                        |chunk| {
                            d.call(Event::Bytes(chunk));
                        },
                    )
                    .await;
                match r {
                    Ok(_) => {}
                    Err(e) => {
                        diag_end(d.dg(),sh.now(), if matches!(e, ReadError::Tls(_)) { END_TLS_READ } else { END_LEASE }, Some(&e));
                        DERP_RECONNECT[usize::from(matches!(e, ReadError::Tls(_)))].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                        d.call(Event::Reconnect);
                        return;
                    }
                }
            }
            Either::First(Err(e)) => {
                diag_end(d.dg(),sh.now(), END_WAIT, Some(&e));
                DERP_RECONNECT[2].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                d.call(Event::Reconnect);
                return;
            }
            Either::Second(()) => {
                if d.must_abort() {
                    return;
                }
            }
        }
    }
}

/// A copy of the staged bytes (the write future must not hold the staging buffer's `RefCell` borrow across the link's calls).
fn stage_bytes<'s, 'p>(stage: &'s RefCell<PoolBuf<'p>>, n: usize) -> StagedRef<'s, 'p> {
    StagedRef { guard: stage.borrow(), n }
}

struct StagedRef<'s, 'p> {
    guard: core::cell::Ref<'s, PoolBuf<'p>>,
    n: usize,
}

impl core::ops::Deref for StagedRef<'_, '_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.guard[..self.n]
    }
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Drv<'_, '_, R, P, S, D> {
    fn link_timing_rx_frame(&self) -> u64 {
        u64::from(Timing::DEFAULT.rx_frame_ms)
    }
}
