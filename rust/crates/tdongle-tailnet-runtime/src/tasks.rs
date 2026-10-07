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

enum DnsStep {
    Done,
    Sent,
    Full,
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
    let mut bound = false;
    let mut gen_seen = u32::MAX;
    loop {
        // a new association invalidates the socket
        let view = crate::taskutil::wait_link_up(&mut link_rx).await;
        if view.generation != gen_seen {
            gen_seen = view.generation;
            sock.close();
            bound = false;
            crate::resolver::RESOLVERS.new_network();
        }
        if let Some(v4) = view.v4 {
            // the candidates of the dial path's resolver list, so a silent DHCP server is not the forwarder's only choice either
            if let Some(d) = v4.dns {
                crate::resolver::RESOLVERS.add(u32::from_be_bytes(d), false);
            }
            if let Some(g) = v4.gateway {
                crate::resolver::RESOLVERS.add(u32::from_be_bytes(g), true);
            }
        }
        if !bound {
            bound = sock.bind(0).is_ok();
            if !bound {
                Timer::after_millis(500).await;
                continue;
            }
        }
        let sock_ref = &sock;
        match select(sock_ref.wait_readable(), select(sh.dns_q.wait_nonempty(), crate::taskutil::wait_link_change(&mut link_rx, view))).await {
            Either::First(Ok(())) => {
                // the shared scratch, for the moment the reply is copied out and handed to the engine
                let r = sh.with_scratch(|buf| match sock.try_recv_from(&mut buf[..1500]) {
                    Ok(Some((n, src))) => {
                        RtStats::bump(&sh.stats.dns_replies);
                        if let Some(o) = src.v4_octets() {
                            crate::resolver::RESOLVERS.forward_reply(u32::from_be_bytes(o));
                        }
                        let _ = sh.feed(Input::DnsUpstreamReply { data: &mut buf[..n] });
                        Ok(())
                    }
                    Ok(None) => Ok(()),
                    Err(e) => Err(e),
                });
                if r.is_err() {
                    sock.close();
                    bound = false;
                }
            }
            Either::First(Err(_)) => {
                sock.close();
                bound = false;
            }
            Either::Second(Either::First(())) => {
                // one query: it stays queued until the socket takes it (no buffer of this task's own holds it across a wait)
                let mut spins = 0u32;
                loop {
                    let step = sh.with_scratch(|rec| {
                        let Some((kind, n)) = sh.dns_q.try_peek(&mut rec[..1508]) else { return DnsStep::Done };
                        if n < 5 {
                            sh.dns_q.discard_front();
                            return DnsStep::Done;
                        }
                        if kind == 1 && spins == 0 {
                            // the resolver changed: the engine forgot the pending queries; start from a fresh socket
                            sock.close();
                            bound = sock.bind(0).is_ok();
                        }
                        // the engine's choice (the DHCP server) unless it has been silent for a timeout: then the next candidate (the gateway, the public resolvers)
                        let requested = u32::from_be_bytes([rec[0], rec[1], rec[2], rec[3]]);
                        let target = crate::resolver::RESOLVERS.forward_target(requested, sh.now() as u32);
                        let upstream = Ep::v4(target.to_be_bytes(), 53);
                        if !bound {
                            sh.dns_q.discard_front();
                            return DnsStep::Done;
                        }
                        match sock.try_send_to(&rec[4..n], upstream) {
                            Ok(false) => DnsStep::Full,
                            Ok(true) => {
                                sh.dns_q.discard_front();
                                RtStats::bump(&sh.stats.dns_fwd);
                                DnsStep::Sent
                            }
                            Err(_) => {
                                sh.dns_q.discard_front();
                                DnsStep::Sent
                            }
                        }
                    });
                    match step {
                        DnsStep::Done => break,
                        DnsStep::Sent => spins = 0,
                        DnsStep::Full => {
                            if spins == 0 {
                                let _ = sock.wait_writable().await;
                            } else {
                                Timer::after_millis(1).await;
                            }
                            spins += 1;
                        }
                    }
                }
            }
            Either::Second(Either::Second(_)) => {}
        }
    }
}
