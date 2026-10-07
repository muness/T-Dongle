//! The control task of a membership slot: `tdongle_tailnet_ctl::run_session` (key fetch, ts2021, register, streaming map) in the loop the C's coordinator
//! runs (`ml_coord.c`), for one membership, on the slot's own TCP handle and control workspace.
//!
//! * **Gate**: the negotiation token, phase A. The supervisor takes it when it starts the membership (admission measures the heap with it held) and the key is
//!   the same as the control task's, so `begin_negotiation` finds the holder and the join is not interrupted (the C's hand-over). Every later session asks
//!   for it again at `Rejoin` priority. It is released after the first map was applied, on any failure before that, and (as a backstop) when the future is
//!   dropped.
//! * **Map events** go into the engine through `NetmapSink` -> [`MapTee`] -> `Shared::feed`: a refusal (staging full, unknown member) fails the map.
//! * **Endpoints** (`EndpointSource`): the slot's local endpoints and the STUN-learned one, plus the home DERP region the engine settled on (carried in the
//!   `Hostinfo` of the next endpoint update; see `EndpointSource::preferred_derp`).
//! * **Backoff** is the C's: `1000 << min(attempts, 4)` ms, at most 30 s (`ML_CTRL_BACKOFF_MAX_MS`); `attempts` restarts at 0 after a session that applied
//!   a map. A link change (reassociation) cancels the session at once and starts a new one.

use crate::net::{Net, NetError, TcpConn, TcpRole};
use crate::shared::{ALIVE_CONTROL, MapTee, Shared};
use crate::taskutil::{Alive, wait_active, wait_changed, wait_link_change, wait_link_up};
use crate::token::key_control;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::mutex::Mutex as AsyncMutex;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_io_async::{ErrorType, Read, Write};
use tdongle_tailnet_admission::negotiation::{Phase, Prio};
use tdongle_tailnet_control::requests::{ENDPOINT_LOCAL, ENDPOINT_STUN, Endpoint, EndpointAddr, Hostinfo};
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_ctl::{Clock, Connect, EndpointSource, Gate, RegisterFailure, SessionConfig, SessionEnd, run_session_leased};
use tdongle_tailnet_engine::{NetmapSink, PeerDirectory};
use tdongle_tailnet_fw::{Platform, Storage};
use tdongle_tailnet_members::CText;
use tdongle_tailnet_types::{FixedStr, Key32, Millis};

/// A provisioning key held in a frame: zeroed when it goes out of scope (the registry's `CText` is `Copy`, so it cannot do that itself).
struct Secret(CText<159>);

impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Bytes of one TLS write record of the control connection (the DERP's is 2,048; requests here are a few hundred bytes to about 1.5 KB, split into records).
const TLS_WRITE_RECORD: usize = 1024;

/// The longest wait between sessions (`ML_CTRL_BACKOFF_MAX_MS`).
pub const BACKOFF_MAX_MS: u64 = 30_000;

/// The C's reconnect delay for `attempts` consecutive failures.
pub const fn backoff_ms(attempts: u32) -> u64 {
    let e = if attempts > 4 { 4 } else { attempts };
    let ms = 1000u64 << e;
    if ms > BACKOFF_MAX_MS { BACKOFF_MAX_MS } else { ms }
}

/// A session that applied a map counts as a success (the backoff starts again from one second) only if it also lasted this long (ms). Before, any applied map reset the
/// backoff: a session that applied its first map and then failed (a directory commit that kept failing on flash errors, a map that broke right after) reconnected every
/// second, a TLS handshake, a negotiation workspace and a map each time, for as long as the fault lasted, churning and fragmenting the heap until an allocation failed.
pub const STABLE_SESSION_MS: u64 = 60_000;

/// Consecutive failures to count after a session: back to zero after a stable session, otherwise unchanged (the caller waits `backoff_ms` of it and adds one).
#[must_use]
pub const fn attempts_after(attempts: u32, first_map_applied: bool, session_ms: u64) -> u32 {
    if first_map_applied && session_ms >= STABLE_SESSION_MS { 0 } else { attempts }
}

/// The control connection's two transports, as the control driver's `Connect`: plain TCP (an explicit `http://` control address) or **verified TLS** over the same
/// TCP handle (the default: Tailscale answers a plaintext `/key` with a 302 to https; the C's `use_tls`, `ctrl_key_auth = CTRL_KEY_TLS_VERIFIED`). The handle is
/// shared through an async mutex because `Connect::Stream` cannot borrow `&mut self`; the driver keeps at most one stream alive at a time (its contract), so the
/// lock never waits. TLS records are read through per-record leases from the pool (no static buffer), the two write records (one per stream: the `/key` fetch
/// and the ts2021 connection) come from one pool block the session owns.
struct CtlConnect<'a, T: TcpConn, P: Platform> {
    tcp: &'a AsyncMutex<NoopRawMutex, T>,
    host: &'a str,
    port: u16,
    io_ms: u32,
    tls: Option<TlsSide<'a, P>>,
}

struct TlsSide<'a, P: Platform> {
    platform: &'a P,
    lease: &'a tdongle_tailnet_tls::lease::LeasePool,
    mem: tdongle_tailnet_pool::Mem<'a>,
    /// The trust anchors the chain must end in (the ISRG roots of the DERP policy).
    anchors: &'a [tdongle_tailnet_tls::TrustAnchor<'a>],
    /// The write records, one per stream; taken by `connect`.
    wbufs: [Option<&'a mut [u8]>; 2],
}

/// How long a TLS connect waits for the wall clock (SNTP): certificates are judged against it, as the C's `ml_derp_clock_valid()` gate.
const CLOCK_WAIT_MS: u64 = 60_000;

struct CtlTcp<'a, T: TcpConn> {
    tcp: &'a AsyncMutex<NoopRawMutex, T>,
}

impl<T: TcpConn> ErrorType for CtlTcp<'_, T> {
    type Error = NetError;
}

impl<T: TcpConn> Read for CtlTcp<'_, T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.tcp.lock().await.read(buf).await.map_err(|e| net_err::<T>(&e))
    }
}

impl<T: TcpConn> Write for CtlTcp<'_, T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        self.tcp.lock().await.write(buf).await.map_err(|e| net_err::<T>(&e))
    }
    async fn flush(&mut self) -> Result<(), NetError> {
        self.tcp.lock().await.flush().await.map_err(|e| net_err::<T>(&e))
    }
}

/// TLS as a byte stream: reads hand out a record's plaintext and keep the rest (a pool block) for the next read; the peer's close is end of stream.
struct TlsStream<'a, T: TcpConn> {
    conn: tdongle_tailnet_tls::lease::LeasedTlsDerp<'a, CtlTcp<'a, T>>,
    carry: Option<(tdongle_tailnet_tls::lease::OwnedRecord<'a>, usize)>,
    record_deadline: Option<Instant>,
}

enum CtlStream<'a, T: TcpConn> {
    Plain(CtlTcp<'a, T>),
    Tls(alloc::boxed::Box<TlsStream<'a, T>>),
}

impl<T: TcpConn> ErrorType for CtlStream<'_, T> {
    type Error = NetError;
}

impl<T: TcpConn> Read for CtlStream<'_, T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        match self {
            CtlStream::Plain(t) => t.read(buf).await,
            CtlStream::Tls(t) => t.read(buf).await,
        }
    }
}

impl<T: TcpConn> Write for CtlStream<'_, T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        match self {
            CtlStream::Plain(t) => t.write(buf).await,
            CtlStream::Tls(t) => t.write(buf).await,
        }
    }
    async fn flush(&mut self) -> Result<(), NetError> {
        match self {
            CtlStream::Plain(t) => t.flush().await,
            CtlStream::Tls(t) => t.flush().await,
        }
    }
}

impl<T: TcpConn> TlsStream<'_, T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some((c, at)) = self.carry.as_mut() {
                let n = (c.len() - *at).min(buf.len());
                buf[..n].copy_from_slice(&c[*at..*at + n]);
                *at += n;
                if *at == c.len() {
                    self.carry = None;
                }
                return Ok(n);
            }
            let deadline = &mut self.record_deadline;
            let r = self.conn.read_owned(|| Timer::at(*deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(10)))).await;
            self.record_deadline = None;
            match r {
                Ok(record) if !record.is_empty() => self.carry = Some((record, 0)),
                Ok(_) => {}
                Err(e) if e.is_closed() => return Ok(0),
                Err(_) => return Err(NetError::Io),
            }
        }
    }
    async fn write(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        self.conn.write_all(buf).await.map_err(|_| NetError::Io)?;
        Ok(buf.len())
    }
    async fn flush(&mut self) -> Result<(), NetError> {
        self.conn.flush().await.map_err(|_| NetError::Io)
    }
}

fn net_err<T: ErrorType>(_: &T::Error) -> NetError {
    NetError::Io
}

impl<'a, T: TcpConn, P: Platform> Connect for CtlConnect<'a, T, P> {
    type Stream = CtlStream<'a, T>;
    async fn connect(&mut self) -> Result<Self::Stream, ()> {
        let io = Duration::from_millis(u64::from(self.io_ms));
        {
            let mut g = self.tcp.lock().await;
            if !matches!(with_timeout(io, g.connect(self.host, self.port)).await, Ok(Ok(()))) {
                g.close();
                return Err(());
            }
        }
        let tcp = self.tcp;
        let fail = || {
            // a half-made TLS connection is unusable: the TCP one goes with it
            Err(())
        };
        let Some(t) = self.tls.as_mut() else { return Ok(CtlStream::Plain(CtlTcp { tcp })) };
        // certificates are judged against the wall clock: wait for SNTP (the C's `ml_derp_clock_valid()` gate), bounded
        let start = Instant::now();
        while t.platform.unix_seconds().is_none() {
            if start.elapsed().as_millis() > CLOCK_WAIT_MS {
                tcp.lock().await.close();
                return Err(());
            }
            Timer::after_millis(250).await;
        }
        let Some(wbuf) = t.wbufs.iter_mut().find_map(Option::take) else {
            tcp.lock().await.close();
            return fail();
        };
        let cert = tdongle_tailnet_tls::parse_cert_name(Some(self.host), None);
        let params = tdongle_tailnet_tls::transport::TlsParams {
            hostname: self.host,
            cert: &cert,
            anchors: t.anchors,
            now_unix: t.platform.unix_seconds().unwrap_or(0),
        };
        let mut rng = crate::shared::PlatformRng(t.platform);
        // the handshake's state is a heap block for the length of the handshake, not part of this task's static future (see the relay's)
        let Some(handshake) =
            crate::derp::admit_box(t.mem.heap, tdongle_tailnet_tls::lease::LeasedTlsDerp::connect(CtlTcp { tcp }, wbuf, t.lease, t.mem, &params, &mut rng))
        else {
            tcp.lock().await.close();
            return fail();
        };
        let r = with_timeout(io, handshake).await;
        match r {
            Ok(Ok(conn)) => match crate::fallible::try_box(TlsStream { conn, carry: None, record_deadline: None }) {
                Ok(b) => Ok(CtlStream::Tls(b)),
                Err(s) => {
                    drop(s);
                    tcp.lock().await.close();
                    fail()
                }
            },
            _ => {
                tcp.lock().await.close();
                fail()
            }
        }
    }
}

/// Monotonic clock and `with_timeout` from embassy-time.
#[derive(Debug)]
pub struct RtClock<'a, P: Platform>(pub &'a P);

impl<P: Platform> Clock for RtClock<'_, P> {
    fn now(&self) -> Millis {
        self.0.now_ms()
    }
    async fn timeout<F: core::future::Future>(&mut self, ms: u32, fut: F) -> Option<F::Output> {
        with_timeout(Duration::from_millis(u64::from(ms)), fut).await.ok()
    }
}

/// The token as the driver's gate.
struct TokenGate<'a, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> {
    sh: &'a Shared<R, P, S, D>,
    idx: usize,
    member: u32,
    prio: Prio,
    neg: Option<crate::shared::NegGuard<'a>>,
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> Gate for TokenGate<'_, R, P, S, D> {
    async fn begin_negotiation(&mut self) {
        // the supervisor already holds it for a first start (same key): granted at once. A full queue (six waiters) is retried.
        loop {
            match self.sh.token.acquire(&self.sh.platform, key_control(self.member), self.prio, Phase::Control, None).await {
                Ok(()) => {
                    self.neg = Some(self.sh.stats.negotiation());
                    return;
                }
                Err(_) => Timer::after_millis(500).await,
            }
        }
    }
    async fn end_negotiation(&mut self, ok: bool) {
        self.neg = None;
        self.sh.token.release(self.sh.now(), key_control(self.member));
        if ok {
            self.sh.slots[self.idx].update(|st| {
                st.connected = true;
                st.joined = true;
            });
            self.sh.supervisor_kick.signal(());
        }
    }
}

/// The slot's endpoints and home region as the driver's source.
struct SlotEndpoints<'a, R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> {
    sh: &'a Shared<R, P, S, D>,
    idx: usize,
    seen: Option<u32>,
    derp_sent: u16,
}

impl<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory> EndpointSource for SlotEndpoints<'_, R, P, S, D> {
    fn poll_endpoints(&mut self, out: &mut [Endpoint]) -> Option<usize> {
        let (gen_, local, learned) = self.sh.slots[self.idx].st.lock(|s| {
            let s = s.borrow();
            (s.eps_gen, s.local_eps, s.learned_ep)
        });
        if self.seen == Some(gen_) {
            return None;
        }
        let mut n = 0;
        let mut put = |ip: [u8; 4], port: u16, kind: u8| {
            if n < out.len() {
                out[n] = Endpoint { addr: EndpointAddr::V4 { ip, port }, kind };
                n += 1;
            }
        };
        for ep in local.iter().flatten() {
            if let Some(ip) = ep.v4_octets() {
                put(ip, ep.port(), ENDPOINT_LOCAL);
            }
        }
        if let Some(ep) = learned
            && let Some(ip) = ep.v4_octets()
        {
            put(ip, ep.port(), ENDPOINT_STUN);
        }
        self.seen = Some(gen_);
        // nothing known yet: say nothing (the driver does not send an update without endpoints)
        Some(n)
    }

    fn preferred_derp(&mut self) -> Option<u16> {
        let home = self.sh.slots[self.idx].st.lock(|s| s.borrow().home_derp);
        if home != 0 && home != self.derp_sent {
            self.derp_sent = home;
            return Some(home);
        }
        None
    }
}

/// The control task of slot `idx`. Never returns.
pub async fn control_slot<R, P, S, D, N>(sh: &Shared<R, P, S, D>, idx: usize, net: &N)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
{
    let slot = &sh.slots[idx];
    let tcp = AsyncMutex::<NoopRawMutex, _>::new(net.tcp(TcpRole::Control, idx).expect("the Net has no control TCP handle for this slot"));
    let mut run_rx = slot.run.receiver().expect("slot run receivers");
    let mut link_rx = sh.link.receiver().expect("link receivers");
    loop {
        let run = wait_active(&mut run_rx).await;
        let alive = Alive::new(&slot.alive, ALIVE_CONTROL);
        select(member_control(sh, idx, run.id, &tcp, &mut link_rx), wait_changed(&mut run_rx, run)).await;
        tcp.lock().await.release().await;
        sh.token.release(sh.now(), key_control(run.id));
        slot.update(|st| {
            st.connected = false;
            st.control_stage = 0;
        });
        drop(alive);
    }
}

async fn member_control<R, P, S, D, T>(
    sh: &Shared<R, P, S, D>,
    idx: usize,
    member: u32,
    tcp: &AsyncMutex<NoopRawMutex, T>,
    link_rx: &mut crate::taskutil::LinkRx<'_, R>,
) where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    T: TcpConn,
{
    let slot = &sh.slots[idx];
    // the secrets live in this frame for as long as the membership runs; `Key32` zeroizes on drop
    let (machine, node, disco, hostname, mut auth_key): (Key32, Key32, Key32, CText<47>, Secret) = slot.ident.lock(|i| {
        let i = i.borrow();
        (i.machine.clone(), i.wg.clone(), i.disco.clone(), i.hostname, Secret(i.auth_key))
    });
    let disco_pub = x25519::public(&disco);
    let mut host_header = crate::util::Buf::<96>::new();
    crate::control_url::ControlUrl { host: sh.cfg.control_host, port: sh.cfg.control_port, tls: sh.cfg.control_tls }.host_header(&mut host_header);
    let control_pub = sh.cfg.control_pub.map(Key32);
    let mut attempts = 0u32;
    let mut first = true;
    let mut clock = RtClock(&sh.platform);
    let mut rng = crate::shared::PlatformRng(&sh.platform);
    loop {
        let view = wait_link_up(link_rx).await;
        let home = slot.st.lock(|s| s.borrow().home_derp);
        let followup = slot.st.lock(|s| s.borrow().auth_url.clone());
        slot.update(|st| {
            st.sessions = st.sessions.wrapping_add(1);
            st.control_stage = 1;
            st.connected = false;
        });
        let mut ws = slot.ws.lock().await;
        let session_start = Instant::now();
        let hostinfo = Hostinfo::new(hostname.as_str().unwrap_or("tdongle"), u32::from(home));
        let cfg = SessionConfig {
            host_header: host_header.as_str(),
            machine_priv: &machine,
            node_priv: &node,
            disco_pub: &disco_pub,
            hostinfo,
            auth_key: auth_key.0.as_str().unwrap_or(""),
            followup: followup.as_str(),
            control_pub: control_pub.as_ref(),
            home_derp: home,
            timeouts: sh.cfg.timeouts,
        };
        // two TLS write records (the key fetch's stream and the control stream) from one pool block, held for the session
        let mut wblock = if sh.cfg.control_tls { Some(sh.mem().alloc_wait(tdongle_tailnet_pool::Class::Record, 2 * TLS_WRITE_RECORD).await) } else { None };
        let tls = wblock.as_mut().map(|b| {
            let (x, y) = b.split_at_mut(TLS_WRITE_RECORD);
            TlsSide { platform: &sh.platform, lease: &sh.lease, mem: sh.mem(), anchors: tdongle_tailnet_tls::DEFAULT_ANCHORS, wbufs: [Some(x), Some(y)] }
        });
        let mut connect = CtlConnect { tcp, host: sh.cfg.control_host, port: sh.cfg.control_port, io_ms: sh.cfg.timeouts.io_ms, tls };
        let mut gate = TokenGate { sh, idx, member, prio: if first { Prio::Start } else { Prio::Rejoin }, neg: None };
        let mut eps = SlotEndpoints { sh, idx, seen: None, derp_sent: home };
        let mut sink = NetmapSink::new(MapTee { sh, slot: idx, member, expired: false, cur: Default::default() });
        let end = {
            let bulk = crate::shared::BulkSource { stats: &sh.bulk, mem: sh.mem() };
            let session = run_session_leased(&mut connect, &mut clock, &cfg, &mut ws, &bulk, &mut sink, &mut gate, &mut eps, &mut rng);
            match select(session, wait_link_change(link_rx, view)).await {
                Either::First(e) => Some(e),
                Either::Second(_) => None,
            }
        };
        first = false;
        let stats = ws.stats;
        // (the big buffers went back to `sh.bulk` when the session ended)
        drop(ws);
        // the session may have been cancelled with the token held
        sh.token.release(sh.now(), key_control(member));
        tcp.lock().await.close();
        slot.update(|st| {
            st.ctl = stats;
            st.connected = false;
            st.control_stage = 0;
        });
        let Some(end) = end else {
            // link changed: a new session at once
            attempts = 0;
            continue;
        };
        attempts = attempts_after(attempts, stats.first_map_applied, session_start.elapsed().as_millis());
        note_end(sh, idx, &end);
        if matches!(end, SessionEnd::Register(RegisterFailure::NodeKeyExpired)) {
            slot.update(|st| st.key_expired = true);
        }
        // the provisioning key is spent once a map was applied (the supervisor also drops it from the registry); a re-register uses the stored one
        if stats.first_map_applied {
            auth_key = Secret(slot.ident.lock(|i| i.borrow().auth_key));
        }
        let wait = backoff_ms(attempts);
        attempts = attempts.saturating_add(1);
        Timer::after_millis(wait).await;
    }
}

/// Record how a session ended: the C's `noise_error` / `map_error`, the text the setup page shows, the login URL.
fn note_end<R: RawMutex, P: Platform, S: Storage, D: PeerDirectory>(sh: &Shared<R, P, S, D>, idx: usize, end: &SessionEnd) {
    let slot = &sh.slots[idx];
    let mut text = FixedStr::<96>::new();
    match end {
        SessionEnd::Register(RegisterFailure::AuthUrl(u)) => {
            slot.update(|st| st.auth_url = u.clone());
            text.set("Waiting for browser authorization");
        }
        SessionEnd::Register(RegisterFailure::Refused(m)) => {
            text.set(m.as_str());
        }
        SessionEnd::Register(RegisterFailure::NodeKeyExpired) => {
            text.set("authorization_expired");
        }
        SessionEnd::Register(_) => {
            text.set("Control server registration failed");
        }
        _ => {
            text.set("Control-plane transport failed; retrying");
        }
    }
    let mut detail = crate::util::Buf::<120>::new();
    {
        use core::fmt::Write as _;
        let _ = write!(detail, "{end:?}");
    }
    slot.update(|st| {
        st.last_end = detail;
        st.noise_error = end.noise_error();
        st.map_error = end.map_error();
        st.last_error = text;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::shared;
    use tdongle_tailnet_disco::Ep;

    /// The retry storm behind the board's out-of-memory panic: every session applies its first map and fails a few seconds later. The waits must grow to the cap, not stay
    /// at one second; a session that stays up a minute is a success and starts again from one second.
    #[test]
    fn short_sessions_that_applied_a_map_still_back_off() {
        let mut attempts = 0u32;
        let mut waits = std::vec::Vec::new();
        for _ in 0..8 {
            attempts = attempts_after(attempts, true, 4_000);
            waits.push(backoff_ms(attempts));
            attempts = attempts.saturating_add(1);
        }
        assert_eq!(waits, [1_000, 2_000, 4_000, 8_000, 16_000, 16_000, 16_000, 16_000]);
        assert_eq!(attempts_after(attempts, true, STABLE_SESSION_MS), 0);
        assert_eq!(attempts_after(attempts, false, 10 * STABLE_SESSION_MS), attempts, "no map, no success");
    }

    /// The reserve check before a handshake or a workspace: the floor, and one block that can hold it.
    #[test]
    fn reserve_needs_the_floor_and_one_block() {
        use tdongle_tailnet_admission::heap::ML_HB_FLOOR;
        let need = 3_000;
        assert!(crate::derp::reserve_ok(ML_HB_FLOOR + need, need, need));
        assert!(!crate::derp::reserve_ok(ML_HB_FLOOR + need - 1, need, need), "below the floor");
        assert!(!crate::derp::reserve_ok(ML_HB_FLOOR * 2, need - 1, need), "plenty free, but in pieces");
    }

    #[test]
    fn backoff_is_the_cs() {
        let v: std::vec::Vec<u64> = (0..8).map(backoff_ms).collect();
        assert_eq!(v, [1000, 2000, 4000, 8000, 16_000, 16_000, 16_000, 16_000]);
        assert!(v.iter().all(|&x| x <= BACKOFF_MAX_MS));
        assert_eq!(backoff_ms(u32::MAX), 16_000);
    }

    #[test]
    fn the_endpoint_source_reports_changes_once_and_the_home_region_once() {
        let sh = shared();
        let mut src = SlotEndpoints { sh: &sh, idx: 0, seen: None, derp_sent: 0 };
        let mut out = [Endpoint { addr: EndpointAddr::V4 { ip: [0; 4], port: 0 }, kind: 0 }; 8];
        // nothing known yet: an empty set is still "changed" the first time (the driver sends nothing for it)
        assert_eq!(src.poll_endpoints(&mut out), Some(0));
        assert_eq!(src.poll_endpoints(&mut out), None);
        sh.slots[0].update(|st| {
            st.local_eps = [Some(Ep::v4([192, 168, 1, 7], 41641)), None];
            st.learned_ep = Some(Ep::v4([203, 0, 113, 9], 5555));
            st.eps_gen += 1;
        });
        assert_eq!(src.poll_endpoints(&mut out), Some(2));
        assert_eq!((out[0].kind, out[1].kind), (ENDPOINT_LOCAL, ENDPOINT_STUN));
        assert_eq!(out[0].addr, EndpointAddr::V4 { ip: [192, 168, 1, 7], port: 41641 });
        assert_eq!(src.poll_endpoints(&mut out), None);
        assert_eq!(src.preferred_derp(), None);
        sh.slots[0].update(|st| st.home_derp = 4);
        assert_eq!(src.preferred_derp(), Some(4));
        assert_eq!(src.preferred_derp(), None, "reported once");
    }

    #[test]
    fn session_ends_become_the_texts_and_numbers_the_setup_page_shows() {
        let sh = shared();
        let mut url = FixedStr::new();
        url.set("https://login.example/a/abc");
        note_end(&sh, 0, &SessionEnd::Register(RegisterFailure::AuthUrl(url)));
        let st = sh.slots[0].status();
        assert_eq!(st.auth_url.as_str(), "https://login.example/a/abc");
        assert_eq!(st.last_error.as_str(), "Waiting for browser authorization");
        note_end(&sh, 0, &SessionEnd::Register(RegisterFailure::NodeKeyExpired));
        assert_eq!(sh.slots[0].status().last_error.as_str(), "authorization_expired");
        note_end(&sh, 0, &SessionEnd::Connect(tdongle_tailnet_ctl::Stage::Connect));
        assert_eq!(sh.slots[0].status().last_error.as_str(), "Control-plane transport failed; retrying");
        note_end(&sh, 0, &SessionEnd::Idle);
        assert_eq!(sh.slots[0].status().map_error, 2);
    }

    /// The control key over verified TLS, through the runtime's own stream: a rustls server with the DERP test chain answers `GET /key` and closes, the way
    /// controlplane.tailscale.com does now that it refuses plaintext. A clock that is not set must not connect (certificates are judged against it).
    mod over_tls {
        use super::*;
        use core::future::poll_fn;
        use core::task::Poll;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::io::{Read as _, Write as _};
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use tdongle_tailnet_ctl::fetch_control_key;
        use tdongle_tailnet_tls::TrustAnchor;

        const HOST: &str = "derp1.test.example";
        const KEYHEX: &str = "7d2792f9c98d753d204247153680194910 4c247f95eac770f8fb321595e2173b";

        fn fixture(name: &str) -> std::vec::Vec<u8> {
            std::fs::read(std::format!("{}/../tdongle-tailnet-tls/tests/fixtures/{name}.der", env!("CARGO_MANIFEST_DIR"))).unwrap()
        }

        /// Subject and SPKI of the fixture root, as the DERP tests derive them.
        fn anchor() -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
            fn tlv(b: &[u8]) -> (usize, usize) {
                let l = b[1] as usize;
                if l < 0x80 { (2, l) } else { (2 + (l & 0x7f), b[2..2 + (l & 0x7f)].iter().fold(0, |a, &x| a << 8 | x as usize)) }
            }
            let d = fixture("x2");
            let (h, _) = tlv(&d);
            let cert = &d[h..];
            let (h, _) = tlv(cert);
            let mut c = &cert[h..];
            if c[0] == 0xa0 {
                let (h, l) = tlv(c);
                c = &c[h + l..];
            }
            let next = |c: &mut &[u8]| {
                let (h, l) = tlv(c);
                let t = c[..h + l].to_vec();
                *c = &c[h + l..];
                t
            };
            for _ in 0..4 {
                next(&mut c);
            }
            (next(&mut c), next(&mut c))
        }

        fn serve(reply: &'static str) -> u16 {
            let certs: std::vec::Vec<CertificateDer<'static>> =
                ["leaf_ok", "ye2", "ye", "x2_cross", "derpkey"].iter().map(|n| CertificateDer::from(fixture(n))).collect();
            let provider = rustls::crypto::ring::default_provider();
            let signer = provider.key_provider.load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture("key_leafk")))).unwrap();
            #[derive(Debug)]
            struct Fixed(Arc<rustls::sign::CertifiedKey>);
            impl rustls::server::ResolvesServerCert for Fixed {
                fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
                    Some(self.0.clone())
                }
            }
            let ck = Arc::new(rustls::sign::CertifiedKey { cert: certs, key: signer, ocsp: None });
            let cfg = Arc::new(
                rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .unwrap()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(Fixed(ck))),
            );
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            std::thread::spawn(move || {
                let Ok((mut s, _)) = l.accept() else { return };
                let mut c = rustls::ServerConnection::new(cfg).unwrap();
                let mut tls = rustls::Stream::new(&mut c, &mut s);
                let mut req = [0u8; 512];
                let mut n = 0;
                loop {
                    match tls.read(&mut req[n..]) {
                        Ok(0) | Err(_) => return,
                        Ok(k) => n += k,
                    }
                    if req[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                assert!(
                    req[..n].starts_with(b"GET /key?v=131 HTTP/1.1\r\nHost: derp1.test.example\r\n"),
                    "{:?}",
                    std::string::String::from_utf8_lossy(&req[..n])
                );
                tls.write_all(reply.as_bytes()).unwrap();
                tls.flush().unwrap();
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
            port
        }

        struct StdTcp {
            port: u16,
            s: Option<TcpStream>,
        }
        impl ErrorType for StdTcp {
            type Error = NetError;
        }
        impl Read for StdTcp {
            async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
                poll_fn(|cx| match self.s.as_mut().ok_or(NetError::Closed)?.read(buf) {
                    Ok(n) => Poll::Ready(Ok(n)),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(_) => Poll::Ready(Err(NetError::Io)),
                })
                .await
            }
        }
        impl Write for StdTcp {
            async fn write(&mut self, buf: &[u8]) -> Result<usize, NetError> {
                poll_fn(|cx| match self.s.as_mut().ok_or(NetError::Closed)?.write(buf) {
                    Ok(n) => Poll::Ready(Ok(n)),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(_) => Poll::Ready(Err(NetError::Io)),
                })
                .await
            }
            async fn flush(&mut self) -> Result<(), NetError> {
                Ok(())
            }
        }
        impl TcpConn for StdTcp {
            async fn connect(&mut self, _host: &str, _port: u16) -> Result<(), NetError> {
                let s = TcpStream::connect(("127.0.0.1", self.port)).map_err(|_| NetError::Connect)?;
                s.set_nonblocking(true).unwrap();
                self.s = Some(s);
                Ok(())
            }
            fn close(&mut self) {
                self.s = None;
            }
        }

        // Keep the production session error intact so these tests inspect its variants.
        #[allow(clippy::result_large_err)]
        fn run(reply: &'static str, clock_set: bool) -> Result<Key32, tdongle_tailnet_ctl::SessionEnd> {
            let sh = shared();
            if !clock_set {
                // the test platform's clock is always set; a platform without it is the case below
            }
            let tcp = AsyncMutex::<NoopRawMutex, _>::new(StdTcp { port: serve(reply), s: None });
            let (subject, spki) = anchor();
            let anchors = [TrustAnchor { subject: &subject, spki: &spki }];
            let mut wb = std::vec![0u8; 2 * TLS_WRITE_RECORD];
            let (x, y) = wb.split_at_mut(TLS_WRITE_RECORD);
            let tls = TlsSide { platform: &sh.platform, lease: &sh.lease, mem: sh.mem(), anchors: &anchors, wbufs: [Some(x), Some(y)] };
            let mut connect = CtlConnect { tcp: &tcp, host: HOST, port: 443, io_ms: 5_000, tls: Some(tls) };
            let mut clock = RtClock(&sh.platform);
            let mut buf = std::vec![0u8; 4096];
            let r = futures::executor::block_on(fetch_control_key(&mut connect, &mut clock, HOST, &mut buf, 5_000));
            assert_eq!((sh.pool.in_use(), sh.lease.holders()), (0, 0), "every pool byte of the TLS stream went back");
            r
        }

        #[test]
        fn large_tls_records_drain_without_copy_allocation_and_refund_on_drop() {
            use core::sync::atomic::Ordering;
            let reply: &'static str = std::boxed::Box::leak("x".repeat(32_768).into_boxed_str());
            let sh = shared();
            let tcp = AsyncMutex::<NoopRawMutex, _>::new(StdTcp { port: serve(reply), s: None });
            let (subject, spki) = anchor();
            let anchors = [TrustAnchor { subject: &subject, spki: &spki }];
            let mut wb = std::vec![0u8; 2 * TLS_WRITE_RECORD];
            let (x, y) = wb.split_at_mut(TLS_WRITE_RECORD);
            let tls = TlsSide { platform: &sh.platform, lease: &sh.lease, mem: sh.mem(), anchors: &anchors, wbufs: [Some(x), Some(y)] };
            let mut connect = CtlConnect { tcp: &tcp, host: HOST, port: 443, io_ms: 5_000, tls: Some(tls) };
            futures::executor::block_on(async {
                let mut stream = connect.connect().await.unwrap();
                stream.write(b"GET /key?v=131 HTTP/1.1\r\nHost: derp1.test.example\r\n\r\n").await.unwrap();
                stream.flush().await.unwrap();
                sh.platform.heap.free.store(54_000, Ordering::Relaxed);
                let before = sh.pool.stats().takes[1];
                let mut buf = [0u8; 128];
                let n = with_timeout(Duration::from_secs(2), stream.read(&mut buf)).await.unwrap().unwrap();
                assert_eq!(n, 128);
                assert_eq!(&buf, &[b'x'; 128]);
                let after_first = sh.pool.stats().takes[1];
                assert!(after_first > before); // rustls may send a session ticket before application data.
                assert_eq!(sh.lease.holders(), 1);
                assert!(sh.pool.in_use() <= 16_640);
                sh.platform.heap.free.store(39_000, Ordering::Relaxed);
                // No fresh admission is needed while the retained record drains below floor+record.
                let n = with_timeout(Duration::from_secs(2), stream.read(&mut buf)).await.unwrap().unwrap();
                assert_eq!(n, 128);
                assert_eq!(sh.pool.stats().takes[1], after_first);
                sh.platform.heap.free.store(54_000, Ordering::Relaxed);
                let mut total = 256;
                while total < reply.len() {
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    assert!(buf[..n].iter().all(|&b| b == b'x'));
                    total += n;
                }
                assert_eq!(total, reply.len());
                assert_eq!(sh.pool.stats().takes[1] - after_first, 1);
                drop(stream);
                assert_eq!((sh.pool.in_use(), sh.lease.holders()), (0, 0));
            });
            // Dropping with a partial plaintext carry also refunds its original lease.
            let tcp = AsyncMutex::<NoopRawMutex, _>::new(StdTcp { port: serve(reply), s: None });
            let mut wb = std::vec![0u8; 2 * TLS_WRITE_RECORD];
            let (x, y) = wb.split_at_mut(TLS_WRITE_RECORD);
            let tls = TlsSide { platform: &sh.platform, lease: &sh.lease, mem: sh.mem(), anchors: &anchors, wbufs: [Some(x), Some(y)] };
            let mut connect = CtlConnect { tcp: &tcp, host: HOST, port: 443, io_ms: 5_000, tls: Some(tls) };
            futures::executor::block_on(async {
                let mut stream = connect.connect().await.unwrap();
                stream.write(b"GET /key?v=131 HTTP/1.1\r\nHost: derp1.test.example\r\n\r\n").await.unwrap();
                stream.flush().await.unwrap();
                stream.read(&mut [0u8; 128]).await.unwrap();
                assert_eq!(sh.lease.holders(), 1);
                drop(stream);
                assert_eq!((sh.pool.in_use(), sh.lease.holders()), (0, 0));
            });
        }

        #[test]
        fn the_key_is_fetched_over_verified_tls_and_the_close_is_the_end_of_the_response() {
            let body = std::format!("{{\"publicKey\":\"mkey:{}\"}}", KEYHEX.replace(' ', ""));
            let reply: &'static str =
                std::boxed::Box::leak(std::format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}").into_boxed_str());
            let k = run(reply, true).expect("key over TLS");
            assert_eq!(k.0[0], 0x7d);
        }

        #[test]
        fn a_redirect_to_https_is_what_plaintext_gets_and_over_tls_it_is_still_refused_not_followed() {
            let r = run("HTTP/1.1 302 Found\r\nLocation: http://evil/\r\n\r\n", true);
            assert!(matches!(r, Err(tdongle_tailnet_ctl::SessionEnd::KeyFetch(tdongle_tailnet_control::http::KeyError::Status))), "{r:?}");
        }
    }
}
