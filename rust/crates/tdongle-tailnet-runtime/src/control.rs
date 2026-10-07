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
use embassy_time::{Duration, Timer, with_timeout};
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

/// The longest wait between sessions (`ML_CTRL_BACKOFF_MAX_MS`).
pub const BACKOFF_MAX_MS: u64 = 30_000;

/// The C's reconnect delay for `attempts` consecutive failures.
pub const fn backoff_ms(attempts: u32) -> u64 {
    let e = if attempts > 4 { 4 } else { attempts };
    let ms = 1000u64 << e;
    if ms > BACKOFF_MAX_MS { BACKOFF_MAX_MS } else { ms }
}

/// The TCP handle as the control driver's `Connect`. The handle is shared through an async mutex because `Connect::Stream` cannot borrow `&mut self`;
/// the driver keeps at most one stream alive at a time (its contract), so the lock never waits.
struct CtlConnect<'a, T: TcpConn> {
    tcp: &'a AsyncMutex<NoopRawMutex, T>,
    host: &'a str,
    port: u16,
    io_ms: u32,
}

struct CtlStream<'a, T: TcpConn> {
    tcp: &'a AsyncMutex<NoopRawMutex, T>,
}

impl<T: TcpConn> ErrorType for CtlStream<'_, T> {
    type Error = NetError;
}

impl<T: TcpConn> Read for CtlStream<'_, T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.tcp.lock().await.read(buf).await.map_err(|e| net_err::<T>(&e))
    }
}

impl<T: TcpConn> Write for CtlStream<'_, T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, NetError> {
        self.tcp.lock().await.write(buf).await.map_err(|e| net_err::<T>(&e))
    }
    async fn flush(&mut self) -> Result<(), NetError> {
        self.tcp.lock().await.flush().await.map_err(|e| net_err::<T>(&e))
    }
}

fn net_err<T: ErrorType>(_: &T::Error) -> NetError {
    NetError::Io
}

impl<'a, T: TcpConn> Connect for CtlConnect<'a, T> {
    type Stream = CtlStream<'a, T>;
    async fn connect(&mut self) -> Result<Self::Stream, ()> {
        let mut g = self.tcp.lock().await;
        let r = with_timeout(Duration::from_millis(u64::from(self.io_ms)), g.connect(self.host, self.port)).await;
        match r {
            Ok(Ok(())) => Ok(CtlStream { tcp: self.tcp }),
            _ => {
                g.close();
                Err(())
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
        tcp.lock().await.close();
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
    {
        use core::fmt::Write as _;
        let _ = if sh.cfg.control_port == 80 {
            write!(host_header, "{}", sh.cfg.control_host)
        } else {
            write!(host_header, "{}:{}", sh.cfg.control_host, sh.cfg.control_port)
        };
    }
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
        let mut connect = CtlConnect { tcp, host: sh.cfg.control_host, port: sh.cfg.control_port, io_ms: sh.cfg.timeouts.io_ms };
        let mut gate = TokenGate { sh, idx, member, prio: if first { Prio::Start } else { Prio::Rejoin }, neg: None };
        let mut eps = SlotEndpoints { sh, idx, seen: None, derp_sent: home };
        let mut sink = NetmapSink::new(MapTee { sh, slot: idx, member, expired: false });
        let end = {
            let session = run_session_leased(&mut connect, &mut clock, &cfg, &mut ws, &sh.bulk, &mut sink, &mut gate, &mut eps, &mut rng);
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
        if stats.first_map_applied {
            attempts = 0;
        }
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
    slot.update(|st| {
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
}
