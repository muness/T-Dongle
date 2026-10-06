//! The small shared tasks: the engine's one timer, the link watcher, and the DNS upstream socket.

use crate::net::{Net, UdpConn, UdpRole};
use crate::shared::{LinkView, RtStats, Shared};
use crate::wifi::WifiRaw;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Timer;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_engine::{Input, PeerDirectory};
use tdongle_tailnet_fw::{Platform, Storage};

/// The engine's timer: **exactly one** `Timer` exists at any moment, armed for the one deadline of the engine's last `Out::Wake`. A new `Wake` (signalled
/// by the output sink when the deadline changed) re-arms it; reaching the deadline feeds `Input::Tick`, whose own `Wake` arms the next.
pub async fn engine_timer<R, P, S, D>(sh: &Shared<R, P, S, D>)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
{
    loop {
        let Some(at) = sh.wake_at() else {
            sh.wake.wait().await;
            continue;
        };
        let now = sh.now();
        if at > now {
            match select(Timer::after_millis(at - now), sh.wake.wait()).await {
                Either::First(()) => {}
                Either::Second(()) => continue,
            }
        }
        RtStats::bump(&sh.stats.ticks);
        let _ = sh.feed(Input::Tick);
        // a deadline that is still due (the engine did not move it) must not spin the executor
        if sh.wake_at().is_some_and(|w| w <= sh.now()) {
            Timer::after_millis(1).await;
        }
    }
}

/// Publishes the station link (association generation, address) to every task, tells the Wi-Fi side and the engine what changed, and keeps the engine's
/// clock flag current. Polls every 250 ms: neither embassy-net nor the radio offer an "association changed" future.
pub async fn link_watch<R, P, S, D, N, W>(sh: &Shared<R, P, S, D>, net: &N, wifi: &W)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
    W: WifiRaw,
{
    let tx = sh.link.sender();
    let mut last: Option<LinkView> = None;
    let mut clock: Option<bool> = None;
    loop {
        let v = LinkView { generation: net.link_generation(), up: net.link_up(), v4: net.ipv4() };
        if last != Some(v) {
            if last.map(|l| l.generation) != Some(v.generation) {
                wifi.new_association();
                RtStats::bump(&sh.stats.link_changes);
            }
            if last.and_then(|l| l.v4) != v.v4 {
                wifi.stack_config_changed();
            }
            let dns = v.v4.and_then(|c| c.dns).map(u32::from_be_bytes);
            if last.and_then(|l| l.v4).and_then(|c| c.dns).map(u32::from_be_bytes) != dns || last.is_none() {
                let _ = sh.feed(Input::DnsUpstream(dns));
            }
            tx.send(v);
            last = Some(v);
        }
        let c = sh.platform.unix_seconds().is_some();
        if clock != Some(c) {
            clock = Some(c);
            sh.clock_valid.store(c, core::sync::atomic::Ordering::Relaxed);
            let _ = sh.feed(Input::ClockValid(c));
        }
        Timer::after_millis(250).await;
    }
}

/// The USB host's DNS forwarder: queries the engine wants answered by the Wi-Fi resolver go out on one UDP socket, replies come back into the engine.
pub async fn dns_upstream<R, P, S, D, N>(sh: &Shared<R, P, S, D>, net: &N)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
{
    let mut sock = net.udp(UdpRole::DnsUpstream, 0).expect("the Net has no DNS upstream UDP handle");
    let mut link_rx = sh.link.receiver().expect("link receivers");
    let mut buf = [0u8; 1500];
    let mut rec = [0u8; 1508];
    let mut bound = false;
    let mut gen_seen = u32::MAX;
    loop {
        // a new association invalidates the socket
        let view = crate::taskutil::wait_link_up(&mut link_rx).await;
        if view.generation != gen_seen {
            gen_seen = view.generation;
            sock.close();
            bound = false;
        }
        if !bound {
            bound = sock.bind(0).is_ok();
            if !bound {
                Timer::after_millis(500).await;
                continue;
            }
        }
        let sock_ref = &sock;
        match select(sock_ref.recv_from(&mut buf), select(sh.dns_q.pop(&mut rec), crate::taskutil::wait_link_change(&mut link_rx, view))).await {
            Either::First(Ok((n, _src))) => {
                RtStats::bump(&sh.stats.dns_replies);
                let _ = sh.feed(Input::DnsUpstreamReply { data: &mut buf[..n] });
            }
            Either::First(Err(_)) => {
                sock.close();
                bound = false;
            }
            Either::Second(Either::First((kind, n))) => {
                if n < 5 {
                    continue;
                }
                if kind == 1 {
                    // the resolver changed: the engine forgot the pending queries; start from a fresh socket
                    sock.close();
                    bound = sock.bind(0).is_ok();
                }
                let upstream = Ep::v4([rec[0], rec[1], rec[2], rec[3]], 53);
                if bound && sock.send_to(&rec[4..n], upstream).await.is_ok() {
                    RtStats::bump(&sh.stats.dns_fwd);
                }
            }
            Either::Second(Either::Second(_)) => {}
        }
    }
}
