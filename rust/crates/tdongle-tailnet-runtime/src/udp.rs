//! The UDP task of a membership slot: its one socket (DISCO, WireGuard and STUN share it, as the C's disco socket does), demultiplexed by the engine
//! (`Input::Udp`), and the egress queue the engine's `SendUdp` / `SendStun` outputs fill.
//!
//! One future per slot, all of them part of the joined `run` future; a slot with no membership waits on its run state and costs nothing but the frame.
//! The socket handle is taken once from the `Net` and bound whenever the slot has a membership and the link is up; a change of the link (generation or
//! address) closes and rebinds it, because the address the control plane knows is the old one.

use crate::net::{Net, NetV4, UdpConn, UdpRole};
use crate::shared::{ALIVE_UDP, LinkView, Shared, ep_from_meta};
use crate::taskutil::{Alive, wait_active, wait_changed, wait_link_change, wait_link_up};
use embassy_futures::select::{Either3, select3};
use crate::shared::SCRATCH;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_time::Timer;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_engine::{Input, PeerDirectory};
use tdongle_tailnet_fw::{Platform, Storage};

/// Largest datagram handled (a WireGuard data message of 1,500 bytes padded, plus headers; DISCO and STUN are smaller).
pub const DATAGRAM_MAX: usize = 1600;
/// Room the host queue must have before a datagram is read: one tunnel packet and its record header.
pub const HOST_ROOM: usize = 1600;
/// Times the UDP task had to wait for the host queue to drain before reading the next datagram (the socket's own buffer is what absorbs the burst).
pub static BACKPRESSURE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Bytes of the egress staging buffer (a record is `ep meta (18) + datagram`).
pub const STAGE_MAX: usize = 18 + DATAGRAM_MAX;
const _: () = assert!(STAGE_MAX <= SCRATCH);

/// One step of the egress loop.
enum Egress {
    /// Nothing queued.
    Empty,
    /// A record was handed to the socket (or dropped as the engine addressed it wrongly).
    Sent,
    /// The socket has no room now; the record stays queued.
    Full,
}

/// Why the socket loop ended.
enum Exit {
    /// The link changed or the socket failed: bind again.
    Rebind,
}

/// The UDP task of slot `idx`. Never returns.
pub async fn udp_slot<R, P, S, D, N>(sh: &Shared<R, P, S, D>, idx: usize, net: &N)
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
{
    let slot = &sh.slots[idx];
    let mut sock = net.udp(UdpRole::Member, idx).expect("the Net has no UDP handle for this slot");
    let mut run_rx = slot.run.receiver().expect("slot run receivers");
    let mut link_rx = sh.link.receiver().expect("link receivers");
    loop {
        let run = wait_active(&mut run_rx).await;
        let alive = Alive::new(&slot.alive, ALIVE_UDP);
        embassy_futures::select::select(
            async {
                loop {
                    let view = wait_link_up(&mut link_rx).await;
                    match member_socket(sh, idx, run.id, net, &mut sock, &mut link_rx, view).await {
                        Exit::Rebind => {
                            sock.close();
                            publish_endpoints(sh, idx, run.id, &[]);
                            // a socket that fails at once must not spin the executor
                            Timer::after_millis(200).await;
                        }
                    }
                }
            },
            wait_changed(&mut run_rx, run),
        )
        .await;
        sock.close();
        publish_endpoints(sh, idx, run.id, &[]);
        slot.udp_q.clear();
        drop(alive);
    }
}

fn publish_endpoints<R, P, S, D>(sh: &Shared<R, P, S, D>, idx: usize, member: u32, eps: &[Ep])
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
{
    let slot = &sh.slots[idx];
    let mut arr = [None, None];
    for (i, e) in eps.iter().take(2).enumerate() {
        arr[i] = Some(*e);
    }
    let changed = slot.update(|st| {
        let changed = st.local_eps != arr;
        st.local_eps = arr;
        if changed {
            st.eps_gen = st.eps_gen.wrapping_add(1);
        }
        changed
    });
    if changed {
        slot.ctl_kick.signal(());
    }
    // the engine keeps at most four local endpoints and the STUN-learned one on its own
    let _ = sh.feed(Input::EndpointsChanged { member, endpoints: eps });
}

#[allow(clippy::too_many_arguments)]
async fn member_socket<R, P, S, D, N>(
    sh: &Shared<R, P, S, D>,
    idx: usize,
    member: u32,
    net: &N,
    sock: &mut N::Udp,
    link_rx: &mut crate::taskutil::LinkRx<'_, R>,
    view: LinkView,
) -> Exit
where
    R: RawMutex,
    P: Platform,
    S: Storage,
    D: PeerDirectory,
    N: Net,
{
    let slot = &sh.slots[idx];
    let want = if sh.cfg.udp_port_base == 0 { 0 } else { sh.cfg.udp_port_base.wrapping_add(idx as u16) };
    let port = match sock.bind(want) {
        Ok(p) => p,
        Err(_) if want != 0 => match sock.bind(0) {
            Ok(p) => p,
            Err(_) => return Exit::Rebind,
        },
        Err(_) => return Exit::Rebind,
    };
    let v4: NetV4 = match view.v4.or_else(|| net.ipv4()) {
        Some(v) => v,
        None => return Exit::Rebind,
    };
    slot.update(|st| st.udp_port = port);
    publish_endpoints(sh, idx, member, &[Ep::v4(v4.addr, port)]);
    let sock = &*sock;
    loop {
        // egress first, so a flood of arrivals cannot starve what the engine wants sent. The record is copied into the shared scratch only for the
        // moment it is handed to the socket; if the socket has no room it stays in the queue and this task waits for room (no buffer of its own).
        let mut spins = 0u32;
        loop {
            let step = sh.with_scratch(|buf| {
                let Some((_kind, n)) = slot.udp_q.try_peek(&mut buf[..STAGE_MAX]) else { return Egress::Empty };
                let sent = match ep_from_meta(&buf[..n]) {
                    Some(dst) => sock.try_send_to(&buf[18..n], dst),
                    None => Ok(true),
                };
                match sent {
                    Ok(false) => Egress::Full,
                    Ok(true) => {
                        slot.udp_q.discard_front();
                        if ep_from_meta(&buf[..n]).is_some() {
                            slot.update(|st| st.udp_tx = st.udp_tx.wrapping_add(1));
                        }
                        Egress::Sent
                    }
                    Err(_) => {
                        slot.udp_q.discard_front();
                        slot.update(|st| st.udp_tx_err = st.udp_tx_err.wrapping_add(1));
                        Egress::Sent
                    }
                }
            });
            match step {
                Egress::Empty => break,
                Egress::Sent => spins = 0,
                Egress::Full => {
                    // "may have room" is a hint (the stack counts a ring with any free byte as writable): the second time round, poll
                    if spins == 0 {
                        let _ = sock.wait_writable().await;
                    } else {
                        Timer::after_millis(1).await;
                    }
                    spins += 1;
                }
            }
        }
        // back-pressure towards the network: no datagram is read while the host queue cannot take the packet it may turn into (ADR 0023)
        let recv = async {
            if sh.host_q.free_bytes() < HOST_ROOM {
                BACKPRESSURE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                sh.host_q.wait_free(HOST_ROOM).await;
            }
            sock.wait_readable().await
        };
        match select3(recv, slot.udp_q.wait_nonempty(), wait_link_change(link_rx, view)).await {
            Either3::First(Ok(())) => {
                let got = sh.with_scratch(|buf| match sock.try_recv_from(&mut buf[..DATAGRAM_MAX]) {
                    Ok(Some((n, src))) => {
                        slot.update(|st| st.udp_rx = st.udp_rx.wrapping_add(1));
                        if sh.rx_admit(n) {
                            let _ = sh.feed(Input::Udp { member, src, data: &mut buf[..n] });
                            sh.rx_done(n);
                        }
                        Ok(())
                    }
                    Ok(None) => Ok(()),
                    Err(e) => Err(e),
                });
                if got.is_err() {
                    return Exit::Rebind;
                }
            }
            Either3::First(Err(_)) => return Exit::Rebind,
            Either3::Second(()) => {}
            Either3::Third(_) => return Exit::Rebind,
        }
    }
}
