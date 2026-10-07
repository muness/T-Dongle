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
}

struct DrvSink<'a, 'p, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> {
    sh: &'a Shared<R, P, S, D>,
    idx: usize,
    member: u32,
    acts: &'a mut Acts,
    stage: &'a RefCell<PoolBuf<'p>>,
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Sink for DrvSink<'_, '_, R, P, S, D> {
    fn action(&mut self, a: Action<'_>) {
        let member = self.member;
        match a {
            Action::Notify(LinkEvent::Connected) => {
                let _ = self.sh.feed(Input::DerpLinkEvent { member, event: DerpNote::Connected });
            }
            Action::Notify(LinkEvent::Disconnected | LinkEvent::RxStale) => {
                self.sh.slots[self.idx].derp_q.clear();
                let _ = self.sh.feed(Input::DerpLinkEvent { member, event: DerpNote::Disconnected });
            }
            Action::Notify(LinkEvent::ConnectFailed) => {
                self.sh.slots[self.idx].derp_q.clear();
                let _ = self.sh.feed(Input::DerpLinkEvent { member, event: DerpNote::ConnectFailed });
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
        }
    }

    fn call(&mut self, ev: Event<'_>) {
        let now = self.sh.now();
        let mut rng = crate::shared::PlatformRng(&self.sh.platform);
        {
            let Drv { sh, idx, member, link, acts, stage, .. } = self;
            let mut sink = DrvSink { sh, idx: *idx, member: *member, acts, stage };
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
        self.sh.slots[self.idx].update(|st| {
            st.derp_state = state;
            st.derp = stats;
        });
    }

    fn release_token(&mut self, now: u64) {
        // idempotent: also takes a waiting (not yet granted) request out of the queue
        self.sh.token.release(now, key_derp(self.member));
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
        if self.link.state() == State::Token && self.link.want_token() && !self.holds_token {
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
        let mut eg = [0u8; 32 + MAX_PACKET + 32];
        while let Some((_k, n)) = self.sh.slots[self.idx].derp_q.try_pop(&mut eg) {
            if n < 32 {
                continue;
            }
            let now = self.sh.now();
            let mut dst = [0u8; 32];
            dst.copy_from_slice(&eg[..32]);
            let Drv { sh, idx, member, link, acts, stage, .. } = self;
            let mut sink = DrvSink { sh, idx: *idx, member: *member, acts, stage };
            let _ = link.send_packet(now, &dst, &eg[32..n], &mut sink);
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
        let eg = async {
            if egress {
                slot.derp_q.wait_nonempty().await;
            } else {
                pending::<()>().await;
            }
        };
        match select3(slot.derp_cmd.wait(), timer, eg).await {
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
        if self.holds_token || self.link.want_token() {
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
            select(relay(sh, idx, run.id, key, &mut tcp, &stage, &mut wbuf[..]), wait_changed(&mut run_rx, run)).await;
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
) where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    T: TcpConn,
{
    let mut d = Drv::new(sh, idx, member, key, stage);
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
        let connected = drive(&mut d, true, pin!(tcp.connect(host.as_str(), port))).await;
        match connected {
            Some(Ok(())) => {
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
                Some(Err(_)) => {
                    d.call(Event::Reconnect);
                    return;
                }
                None => return,
            }
        }
        if d.acts.close {
            return;
        }
        d.pump_egress();
        if d.acts.send.is_some() {
            continue;
        }
        // back-pressure towards the network: a record (the relay's writes are about 2 KB, up to 16 KB) is read only when the host queue can take what it
        // carries, so a slow USB side slows the TCP connection instead of dropping packets the relay already delivered
        if sh.host_q.free_bytes() < crate::derp::HOST_ROOM {
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
                    Err(ReadError::LeaseTimeout) | Err(ReadError::Tls(_)) => {
                        d.call(Event::Reconnect);
                        return;
                    }
                }
            }
            Either::First(Err(_)) => {
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
