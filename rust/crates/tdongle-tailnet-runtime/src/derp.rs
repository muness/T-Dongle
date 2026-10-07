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
use embassy_futures::select::{Either, Either4, select, select4};
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


/// Relay packets for peers homed on a region other than the one the member's link is on, waiting for the link to visit that region (see [`derp_extra`]): heap blocks (a packet is
/// up to 1.5 KB), at most [`XQ_MAX`], admitted above the elastic floor like every other consumer.
struct XPacket {
    slot: u8,
    region: u16,
    dst: [u8; 32],
    data: alloc::vec::Vec<u8>,
    /// When it was queued (ms clock): a packet that waited longer than [`X_EXPIRE_MS`] is dropped, counted.
    at_ms: u32,
}
/// See [`XPacket`].
static XQ: embassy_sync::blocking_mutex::Mutex<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, RefCell<alloc::vec::Vec<XPacket>>> =
    embassy_sync::blocking_mutex::Mutex::new(RefCell::new(alloc::vec::Vec::new()));
/// A packet was queued: wakes the visit manager, and (second signal: a signal has one waiter) the link's loop, which pumps what waits for its region.
static X_SIG: embassy_sync::signal::Signal<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, ()> = embassy_sync::signal::Signal::new();
static X_PUMP: embassy_sync::signal::Signal<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, ()> = embassy_sync::signal::Signal::new();
/// Packets that may wait for a visit (TCP sends a window of them while the link switches).
pub const XQ_MAX: usize = 6;
/// How long a packet waits for the link to reach its region before it is dropped (TCP in the tunnel retransmits).
pub const X_EXPIRE_MS: u32 = 10_000;
/// Visit timing in ms, `[idle, minimum, hold-off]`: the link leaves a region it visited after `idle` without a packet for it, never before `minimum` (control has to push the
/// new home to the peer, and the peer's answers must find us), and starts no new visit for `hold-off` after leaving (the real home is advertised again, and settles). Tests
/// shorten them.
pub static VISIT_TIMING: [core::sync::atomic::AtomicU32; 3] = [core::sync::atomic::AtomicU32::new(30_000), core::sync::atomic::AtomicU32::new(15_000), core::sync::atomic::AtomicU32::new(10_000)];
/// The link starts a visit only when no packet for its own home region went out in this long: a visit takes the link away from the home region.
pub const X_HOME_QUIET_MS: u32 = 10_000;
/// A visit ends when packets for the home region (or another region) have waited this long: the visit is not worth starving them.
pub const X_STARVE_MS: u32 = 10_000;
/// The last time a data packet was handed to the link (for the region it is on), and when the oldest packet for the home region that had to wait (the link being away) was
/// queued (0: none), ms clock.
static HOME_LAST_MS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static HOME_WAITING_SINCE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// The region the member's engine homes the link on (its last `Connect` command), and the region the link is visiting (0: none).
static HOME_REGION: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// See [`HOME_REGION`].
pub static VISITING: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// `[queued, sent, dropped (queue full), dropped (heap), dropped (region not in the map), visits, expired waiting, dropped when the visit ended, refused by the link,
/// relayed packets received while visiting, visits refused (home busy)]`.
pub static X_COUNTS: [core::sync::atomic::AtomicU32; 11] = [const { core::sync::atomic::AtomicU32::new(0) }; 11];
/// Changes of the region the engine homes the link on (a new map, a netcheck), the region it left and the one it went to.
pub static HOME_MOVES: [core::sync::atomic::AtomicU32; 3] = [const { core::sync::atomic::AtomicU32::new(0) }; 3];
/// The certificate policy of the region being visited (its map entry's).
static X_CERT: embassy_sync::blocking_mutex::Mutex<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, RefCell<Option<tdongle_tailnet_tls::DerpCert>>> =
    embassy_sync::blocking_mutex::Mutex::new(RefCell::new(None));

/// What the visit manager asks of the link.
#[derive(Clone, Debug)]
enum Visit {
    /// Dial this region instead of the home one.
    Region { region: u16, host: FixedStr<64>, port: u16 },
    /// Back to the region the engine homes the link on.
    Home,
}
static VISIT: embassy_sync::signal::Signal<embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex, Visit> = embassy_sync::signal::Signal::new();

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
    let now = (sh.now() as u32).max(1);
    let ok = XQ.lock(|q| {
        let mut q = q.borrow_mut();
        if q.len() >= XQ_MAX {
            return false;
        }
        q.push(XPacket { slot: idx as u8, region, dst: key, data: v, at_ms: now });
        true
    });
    if ok {
        X_COUNTS[0].fetch_add(1, Relaxed);
        if u32::from(region) == HOME_REGION.load(Relaxed) && HOME_WAITING_SINCE.load(Relaxed) == 0 {
            HOME_WAITING_SINCE.store(now, Relaxed);
        }
        X_SIG.signal(());
        X_PUMP.signal(());
    } else {
        X_COUNTS[2].fetch_add(1, Relaxed);
    }
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Drv<'_, '_, R, P, S, D> {
    /// The packets queued for the region the link is on now, handed to the link while it has room. Nothing leaves for a link that is not relaying yet (it would refuse and count
    /// them): they wait, and the loop of `stream` pumps again as soon as the link is ready. Packets that have waited too long are dropped, counted.
    fn pump_xq(&mut self) {
        use core::sync::atomic::Ordering::Relaxed;
        let region = self.link.target().region;
        let idx = self.idx as u8;
        let now_ms = self.sh.now() as u32;
        let expired = XQ.lock(|q| {
            let mut q = q.borrow_mut();
            let before = q.len();
            q.retain(|p| !(p.slot == idx && now_ms.wrapping_sub(p.at_ms) > X_EXPIRE_MS));
            before - q.len()
        });
        X_COUNTS[6].fetch_add(expired as u32, Relaxed);
        if self.link.state() != State::Ready {
            return;
        }
        loop {
            let Some(pkt) = XQ.lock(|q| {
                let mut q = q.borrow_mut();
                let i = q.iter().position(|p| p.slot == idx && p.region == region)?;
                Some(q.remove(i))
            }) else {
                break;
            };
            let now = self.sh.now();
            let Drv { sh, idx, member, link, acts, stage, .. } = self;
            let mut sink = DrvSink { sh, idx: *idx, member: *member, acts, stage };
            match link.send_packet(now, &pkt.dst, &pkt.data, &mut sink) {
                Err(tdongle_tailnet_derp::txq::TxDrop::NoSpace | tdongle_tailnet_derp::txq::TxDrop::OverBudget) => {
                    // the link's ring is full: back to the front, sent after the frame being written
                    XQ.lock(|q| q.borrow_mut().insert(0, pkt));
                    break;
                }
                Ok(()) => {
                    X_COUNTS[1].fetch_add(1, Relaxed);
                    HOME_LAST_MS.store((now as u32).max(1), Relaxed);
                    HOME_WAITING_SINCE.store(0, Relaxed);
                }
                Err(_) => {
                    X_COUNTS[8].fetch_add(1, Relaxed);
                }
            }
        }
        self.after();
    }

    /// The visit manager's request: dial another region, or come home.
    fn on_visit(&mut self, v: Visit) {
        match v {
            Visit::Region { region, host, port } => {
                self.visiting = Some(region);
                self.link.set_target(Target::new(region, host.as_str(), port));
            }
            Visit::Home => {
                self.visiting = None;
                let t = self.home_target.clone();
                self.link.set_target(t);
            }
        }
        // a link that is up is cut and dialled again; one that was waiting to connect picks the new target at its next attempt
        if self.link.state() == State::Idle {
            self.call(Event::Connect);
        } else {
            self.call(Event::Reconnect);
        }
    }
}

/// The relay connection's big windows (receive, transmit) while it carries data.
pub const RELAY_RX_BIG: usize = 6144;
/// See [`RELAY_RX_BIG`].
pub const RELAY_TX_BIG: usize = 6144;
/// The idle relay windows' bytes (`Windows::GATEWAY.derp_rx + derp_tx`).
const IDLE_WINDOW_BYTES: usize = 5760 + 6144;

/// The relay link's time out of the ready state: `[times it left ready (or failed to connect), milliseconds not ready in all, since when it is not ready (0: ready)]`. The
/// engine's `no_route` (a packet for the relay while the link is down) is read against it.
pub static RELAY_DOWN: [core::sync::atomic::AtomicU32; 3] = [const { core::sync::atomic::AtomicU32::new(0) }; 3];

fn relay_down(now: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    if RELAY_DOWN[2].load(Relaxed) == 0 {
        RELAY_DOWN[2].store((now as u32).max(1), Relaxed);
        RELAY_DOWN[0].fetch_add(1, Relaxed);
    }
}

/// Move `f` to the heap if the heap above the floor admits a block of its size (counted in [`HANDSHAKE_NOMEM`] if not). A plain function: `f` is not part of the caller's future,
/// only the box is (a future moved into an `async fn` or held across a check stays in the state machine).
#[inline(never)]
pub fn admit_box<F: core::future::Future>(heap: &dyn tdongle_tailnet_admission::probe::HeapProbe, f: F) -> Option<core::pin::Pin<alloc::boxed::Box<F>>> {
    if !tdongle_tailnet_admission::heap::hb_ok(heap.free(), core::mem::size_of::<F>() + 64) {
        HANDSHAKE_NOMEM.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return None;
    }
    Some(alloc::boxed::Box::pin(f))
}

/// TLS handshakes (relay and control) that were not started for want of heap for their boxed state.
pub static HANDSHAKE_NOMEM: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Relay window mode, `[window ms, frames per window that make it big, quiet windows that make it small again]`. Tests shorten them.
pub static WIN_TIMING: [core::sync::atomic::AtomicU32; 3] = [core::sync::atomic::AtomicU32::new(2000), core::sync::atomic::AtomicU32::new(50), core::sync::atomic::AtomicU32::new(15)];
/// Switches to the big windows, switches back, falls back because the pool refused the big ones, whether the connection has them now, and windows in which big ones were wanted
/// but the relay was busy (no lull).
pub static WIN_STATS: [core::sync::atomic::AtomicU32; 6] = [const { core::sync::atomic::AtomicU32::new(0) }; 6];
/// Dynamic relay windows are **parked** (off): the board's heap does not afford them (ADR 0002). The code and its host tests stay; the tests enable it.
pub static WIN_ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// A request for a window mode from outside the traffic (`tn force-derp`): 1 big, 2 idle, 0 none.
pub static WIN_FORCE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Drv<'_, '_, R, P, S, D> {
    /// Bytes of the idle windows (the figures of `net_embassy::Windows::GATEWAY`).
    fn idle_window_bytes(&self) -> usize {
        // the idle relay windows: receive + transmit (kept in step with `Windows::GATEWAY` by the const assert below)
        IDLE_WINDOW_BYTES
    }

    /// Does the connection need other windows? The relay's windows are small while it idles (the heap is short) and big while it carries data: judged on the relay frames
    /// (both ways) of each [`WIN_TIMING`] window, with hysteresis. `true`: reconnect to get them.
    fn window_mode(&mut self) -> bool {
        use core::sync::atomic::Ordering::Relaxed;
        // parked: this heap cannot afford the big windows (board: the floor was broken underneath them); the host tests switch it on
        if !WIN_ENABLED.load(Relaxed) {
            WIN_FORCE.store(0, Relaxed);
            return false;
        }
        let now = self.sh.now();
        let win = u64::from(WIN_TIMING[0].load(Relaxed));
        if now.saturating_sub(self.act_t0) < win {
            return false;
        }
        let st = self.link.stats();
        let frames = st.frames_rx.get().wrapping_add(st.frames_tx.get());
        let delta = frames.wrapping_sub(self.act_frames);
        let first = self.act_t0 == 0;
        self.act_t0 = now;
        self.act_frames = frames;
        if first {
            return false;
        }
        let busy = delta >= WIN_TIMING[1].load(Relaxed);
        // what the traffic wants: big windows once it is busy, idle ones again after a long quiet; a switch is a reconnect (a TLS handshake: seconds of CPU), so it is made when the
        // relay is in a lull, not in the middle of a transfer, and not within a few windows of the last one. `force-derp on/off` asks for it directly (nothing is flowing yet).
        let forced = WIN_FORCE.swap(0, Relaxed);
        if forced != 0 {
            self.want_big = forced == 1;
        } else if !self.win_big && busy {
            self.want_big = true;
        } else if self.win_big {
            self.quiet_windows = if delta < WIN_TIMING[1].load(Relaxed) / 8 { self.quiet_windows + 1 } else { 0 };
            if self.quiet_windows >= WIN_TIMING[2].load(Relaxed) {
                self.want_big = false;
            }
        }
        if self.want_big == self.win_big || now.saturating_sub(self.last_switch) < 4 * win {
            return false;
        }
        if self.want_big {
            // the big windows are taken from the heap above the floor and must not take it to the floor (everything else that is elastic starves there): only with the extra
            // memory and 6 KB to spare, otherwise they stay idle and the next window asks again
            let extra = (RELAY_RX_BIG + RELAY_TX_BIG).saturating_sub(self.idle_window_bytes());
            if self.sh.mem().heap.free() < tdongle_tailnet_admission::heap::ML_HB_FLOOR + extra + 6 * 1024 {
                WIN_STATS[5].fetch_add(1, Relaxed);
                return false;
            }
        }
        let lull = delta <= 4;
        if !lull && forced == 0 && self.want_big {
            // wanted, but the relay is busy: wait for a lull (counted, to see on the board whether one ever comes)
            WIN_STATS[4].fetch_add(1, Relaxed);
            return false;
        }
        self.win_big = self.want_big;
        self.quiet_windows = 0;
        self.last_switch = now;
        if self.win_big {
            WIN_STATS[0].fetch_add(1, Relaxed);
        } else {
            WIN_STATS[1].fetch_add(1, Relaxed);
        }
        WIN_STATS[3].store(u32::from(self.win_big), Relaxed);
        true
    }
}


/// The member's relay link visits the region a peer is homed on when that is not the one the link is on. A relay server forwards only to clients connected to it, so a packet
/// for a peer homed on region 27 is lost on a link to region 12; and a second link costs about 17 KB of heap (a 10 KB future, the TLS write record and the windows), which
/// this image does not have, so there is one link: it **moves**. Reduced capability, by design:
///
/// * a visit starts when packets for a foreign region wait and no packet for the home region went out in the last [`X_HOME_QUIET_MS`] (the link is not taken from a peer that
///   is using it);
/// * it ends when no packet for the visited region went out in [`X_VISIT_IDLE_MS`], or when packets for the home region (or another one) have waited [`X_STARVE_MS`];
/// * while the link is away, peers that send to the member's home region are not heard on it, and the packets for the home region wait (and expire after
///   [`X_EXPIRE_MS`]). Peers answer a packet by the region it came in on, so the peer being visited is heard.
///
/// Never returns. `net` is not needed (the visit reuses the member's relay connection) and is kept for the signature of the other tasks.
pub async fn derp_extra<R, P, S, D, N>(sh: &Shared<R, P, S, D>, idx: usize, _net: &N)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
{
    use core::sync::atomic::Ordering::Relaxed;
    let slot = &sh.slots[idx];
    let mut switched_at = 0u32;
    loop {
        // a packet waits for a region other than the one the link is on (the link's own region is never foreign)
        let region = loop {
            let cur = match VISITING.load(Relaxed) {
                0 => HOME_REGION.load(Relaxed),
                v => v,
            };
            if let Some(r) = XQ.lock(|q| q.borrow().iter().find(|p| p.slot == idx as u8 && u32::from(p.region) != cur).map(|p| p.region)) {
                break r;
            }
            X_SIG.wait().await;
        };
        let now = || (sh.now() as u32).max(1);
        let t = now();
        let oldest = XQ.lock(|q| q.borrow().iter().filter(|p| p.slot == idx as u8 && p.region == region).map(|p| p.at_ms).min()).unwrap_or(t);
        let starved = t.wrapping_sub(oldest) > X_STARVE_MS;
        // the link stays where it is until real traffic needs another region: the region it is on is quiet (no packet for it went out for a while), or the packets that wait
        // have waited too long; and not before it has been there for the minimum (a switch is a reconnect, and the new home needs time to reach the peers)
        let quiet = t.wrapping_sub(HOME_LAST_MS.load(Relaxed)) >= X_HOME_QUIET_MS;
        let dwelled = switched_at == 0 || t.wrapping_sub(switched_at) >= VISIT_TIMING[1].load(Relaxed);
        if !dwelled || !(quiet || starved) || slot.status().derp_state != State::Ready {
            X_COUNTS[10].fetch_add(1, Relaxed);
            Timer::after_secs(1).await;
            continue;
        }
        let member = slot.id.load(core::sync::atomic::Ordering::Acquire);
        let back_home = u32::from(region) == HOME_REGION.load(Relaxed);
        let target = if back_home { None } else { sh.with_engine(|e, _| e.derp_target(member, region)) };
        if !back_home && target.is_none() {
            // a region the member's map does not have: nothing to dial
            let n = XQ.lock(|q| {
                let mut q = q.borrow_mut();
                let before = q.len();
                q.retain(|p| !(p.slot == idx as u8 && p.region == region));
                before - q.len()
            });
            X_COUNTS[4].fetch_add(n as u32, Relaxed);
            continue;
        }
        X_COUNTS[5].fetch_add(1, Relaxed);
        HOME_LAST_MS.store(t, Relaxed);
        HOME_WAITING_SINCE.store(0, Relaxed);
        switched_at = t;
        // a node sends to the destination's home relay, so for the peer to answer us while we are on `region` our home has to be `region`: advertised to the control plane
        // (`PreferredDERP` of the next endpoint update), which pushes it to the peers. The link then stays there.
        advertise_home(slot, region);
        match target {
            Some((host, port, cert)) => {
                X_CERT.lock(|c| {
                    *c.borrow_mut() = Some(match cert {
                        tdongle_tailnet_map::types::IndexCert::Hostname => tdongle_tailnet_tls::DerpCert::Hostname,
                        tdongle_tailnet_map::types::IndexCert::Pin(p) => tdongle_tailnet_tls::DerpCert::Pin(p),
                        tdongle_tailnet_map::types::IndexCert::Invalid => tdongle_tailnet_tls::DerpCert::Invalid,
                    })
                });
                VISITING.store(u32::from(region), Relaxed);
                VISIT.signal(Visit::Region { region, host, port });
            }
            None => {
                VISITING.store(0, Relaxed);
                VISIT.signal(Visit::Home);
            }
        }
        X_LAST_END.store(if back_home { 8 } else { 6 }, Relaxed);
        // time for the new home to settle before the next switch
        Timer::after_millis(u64::from(VISIT_TIMING[2].load(Relaxed))).await;
    }
}

/// Forget the visit state (the region the link visits, the home it was told, what waits): for a runtime that starts again in the same process (the host tests; on the device a
/// reset does it).
pub fn reset_visit_state() {
    use core::sync::atomic::Ordering::Relaxed;
    VISITING.store(0, Relaxed);
    HOME_REGION.store(0, Relaxed);
    HOME_LAST_MS.store(0, Relaxed);
    HOME_WAITING_SINCE.store(0, Relaxed);
    XQ.lock(|q| q.borrow_mut().clear());
    VISIT.reset();
    for c in &X_COUNTS {
        c.store(0, Relaxed);
    }
}

/// Make `region` the home the member tells the control plane (the next endpoint update carries it as `PreferredDERP`).
fn advertise_home<R: RawMutex>(slot: &crate::shared::Slot<R>, region: u16) {
    if region == 0 {
        return;
    }
    slot.update(|st| {
        if st.home_derp != region {
            st.home_derp = region;
            st.eps_gen = st.eps_gen.wrapping_add(1);
        }
    });
    slot.ctl_kick.signal(());
}
/// Why the last visit ended: 6 the region went idle, 8 other packets were starving.
pub static X_LAST_END: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

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
    /// The region the link is visiting (see [`derp_extra`]), and the target the engine last commanded (where it returns to).
    visiting: Option<u16>,
    home_target: Target,
    /// The connection has the big windows, and the bookkeeping of the traffic that decides it (see `window_mode`).
    win_big: bool,
    want_big: bool,
    act_t0: u64,
    act_frames: u32,
    quiet_windows: u32,
    last_switch: u64,
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
                {
                    use core::sync::atomic::Ordering::Relaxed;
                    let since = RELAY_DOWN[2].swap(0, Relaxed);
                    if since != 0 {
                        RELAY_DOWN[1].fetch_add((self.sh.now() as u32).wrapping_sub(since), Relaxed);
                    }
                }
                DERP_DIAG.stage.store(4, core::sync::atomic::Ordering::Relaxed);
                DERP_DIAG.ready_at_ms.store((self.sh.now() as u32).max(1), core::sync::atomic::Ordering::Relaxed);
                let _ = self.sh.feed(Input::DerpLinkEvent { member, event: DerpNote::Connected });
            }
            Action::Notify(LinkEvent::Disconnected | LinkEvent::RxStale) => {
                relay_down(self.sh.now());
                self.sh.slots[self.idx].derp_q.clear();
                let _ = self.sh.feed(Input::DerpLinkEvent { member, event: DerpNote::Disconnected });
            }
            Action::Notify(LinkEvent::ConnectFailed) => {
                relay_down(self.sh.now());
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
                if VISITING.load(core::sync::atomic::Ordering::Relaxed) != 0 {
                    X_COUNTS[9].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
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
            visiting: None,
            home_target: Target::new(0, "", 443),
            win_big: false,
            want_big: false,
            act_t0: 0,
            act_frames: 0,
            quiet_windows: 0,
            last_switch: 0,
        }
    }

    fn dg(&self) -> &'static DerpDiag {
        &DERP_DIAG
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
                // the engine moved the home region (a new map, a netcheck): counted, and remembered as where a visit returns to
                let old = HOME_REGION.swap(u32::from(region), core::sync::atomic::Ordering::Relaxed);
                if old != 0 && old != u32::from(region) {
                    HOME_MOVES[0].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    HOME_MOVES[1].store(old, core::sync::atomic::Ordering::Relaxed);
                    HOME_MOVES[2].store(u32::from(region), core::sync::atomic::Ordering::Relaxed);
                }
                self.home_target = Target::new(region, host.as_str(), port);
                if self.visiting.is_some() {
                    return;
                }
                let moved = self.link.target().region != region || self.link.target().host.as_str() != host.as_str();
                let was_ready = self.link.state() == State::Ready;
                self.link.set_target(Target::new(region, host.as_str(), port));
                if was_ready && moved {
                    self.call(Event::Reconnect);
                } else {
                    self.call(Event::Connect);
                }
            }
            DerpCmd::Close => {
                self.visiting = None;
                VISITING.store(0, core::sync::atomic::Ordering::Relaxed);
                self.call(Event::Close)
            }
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
        crate::optag::set(crate::optag::RELAY_PUMP);
        // packets that waited for the link to reach their region (a visit, see `derp_extra`)
        self.pump_xq();
        let mut eg = [0u8; 32 + MAX_PACKET + 32];
        // a packet leaves the egress queue only when the link took it: the link's ring holds the frame being written and little else, so the rest waits here (before, every
        // packet after the first was popped, refused by the link and lost, which TCP in the tunnel cannot live with)
        while let Some((_k, n)) = self.sh.slots[self.idx].derp_q.try_peek(&mut eg) {
            if n < 34 {
                self.sh.slots[self.idx].derp_q.discard_front();
                continue;
            }
            // a packet for a peer homed on another region: a relay server only forwards to clients connected to it, so it goes to the member's link to that region
            let raw_region = u16::from_be_bytes([eg[32], eg[33]]);
            // background packets (DISCO, `REGION_BACKGROUND`) go out on the link wherever it is and do not count as traffic for the home region
            let background = raw_region == u16::MAX;
            let region = if background { 0 } else { raw_region };
            if region != 0 && region != self.link.target().region {
                push_x(self.sh, self.idx, region, &eg[..32], &eg[34..n]);
                self.sh.slots[self.idx].derp_q.discard_front();
                continue;
            }
            let now = self.sh.now();
            let mut dst = [0u8; 32];
            dst.copy_from_slice(&eg[..32]);
            let Drv { sh, idx, member, link, acts, stage, .. } = self;
            let mut sink = DrvSink { sh, idx: *idx, member: *member, acts, stage };
            match link.send_packet(now, &dst, &eg[34..n], &mut sink) {
                Err(tdongle_tailnet_derp::txq::TxDrop::NoSpace | tdongle_tailnet_derp::txq::TxDrop::OverBudget) => {
                    DERP_EGRESS_HELD.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    break;
                }
                _ => {
                    self.sh.slots[self.idx].derp_q.discard_front();
                    if !background {
                        HOME_LAST_MS.store((now as u32).max(1), core::sync::atomic::Ordering::Relaxed);
                    }
                }
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
        let eg = async {
            if egress {
                // the home queue, and the packets that waited for the link to reach their region
                select(slot.derp_q.wait_nonempty(), X_PUMP.wait()).await;
            } else {
                pending::<()>().await;
            }
        };
        match select4(slot.derp_cmd.wait(), timer, eg, VISIT.wait()).await {
            Either4::First(cmd) => self.on_cmd(cmd),
            Either4::Second(()) => self.on_timer(),
            Either4::Third(_) => self.pump_egress(),
            Either4::Fourth(v) => self.on_visit(v),
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
            crate::optag::set(crate::optag::RELAY_DOWN);
            d.wait(true).await;
        };
        // ---- dial: resolve and connect in one
        d.dg().stage.store(1, core::sync::atomic::Ordering::Relaxed);
        d.dg().region.store(u32::from(d.link.target().region), core::sync::atomic::Ordering::Relaxed);
        d.dg().port.store(u32::from(port), core::sync::atomic::Ordering::Relaxed);
        diag_text(d.dg(), 0, host.as_str());
        crate::optag::set(crate::optag::RELAY_DIAL);
        tcp.set_big_windows(d.win_big);
        let connected = drive(&mut d, true, pin!(tcp.connect(host.as_str(), port))).await;
        crate::optag::set(crate::optag::RELAY_TLS);
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
            Some(Err(e)) => {
                tcp.close();
                if d.win_big && matches!(e, crate::net::NetError::NoMem) {
                    // the pool would not take the big windows (heap short): back to the idle ones
                    d.win_big = false;
                    d.want_big = false;
                    WIN_STATS[2].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    WIN_STATS[3].store(0, core::sync::atomic::Ordering::Relaxed);
                }
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
    let cert = if d.visiting.is_some() {
        X_CERT.lock(|c| c.borrow().clone()).unwrap_or(tdongle_tailnet_tls::DerpCert::Invalid)
    } else {
        slot.status().certs.of(d.link.target().region)
    };
    let now_unix = sh.platform.unix_seconds().unwrap_or(0);
    let params = TlsParams { hostname: host, cert: &cert, anchors: DEFAULT_ANCHORS, now_unix };
    let mut rng = crate::shared::PlatformRng(&sh.platform);
    let handshake = LeasedTlsDerp::connect(&mut *tcp, &mut wbuf[..], &sh.lease, sh.mem(), &params, &mut rng);
    // the handshake's state (about 2.8 KB) is a heap block for the length of the handshake, not part of this task's static future: admitted above the floor, or this attempt fails
    // (counted) and the link tries again later
    let Some(mut handshake) = admit_box(sh.mem().heap, handshake) else {
        d.call(Event::TlsDone(false));
        return;
    };
    let neg = sh.stats.negotiation();
    let outcome = drive(d, true, handshake.as_mut()).await;
    drop(neg);
    drop(handshake);
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
        crate::optag::set(crate::optag::RELAY_STREAM);
        // the connection's windows follow the relay's traffic: a reconnect when they should change
        if d.window_mode() {
            crate::optag::set(crate::optag::RELAY_WINDOWS);
            d.call(Event::Reconnect);
            return;
        }
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
