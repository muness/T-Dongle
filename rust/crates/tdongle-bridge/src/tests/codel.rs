//! CoDel at the hand-to-radio, the hold-evidenced busy period and the ECN counters (ADR 0023 amendments 4 to 7).

use super::*;

/// An Ethernet/IPv4 frame with the given ECN bits, protocol and payload size (`ipv4_frame` of the C test): checksum valid.
fn ipv4_frame(ecn: u8, proto: u8, payload: usize, syn: bool) -> Vec<u8> {
    let mut f = vec![0u8; 200];
    f[..6].copy_from_slice(&PEER);
    f[6..12].copy_from_slice(&MAC);
    f[12] = 0x08;
    f[13] = 0x00;
    f[14] = 0x45;
    f[15] = ecn;
    let total = 20 + payload;
    f[16] = (total >> 8) as u8;
    f[17] = total as u8;
    f[22] = 64;
    f[23] = proto;
    f[26] = 10;
    f[29] = 1;
    f[30] = 10;
    f[33] = 2;
    if proto == 6 {
        f[14 + 20 + 12] = 0x50;
        f[14 + 20 + 13] = if syn { 0x02 } else { 0x10 };
    }
    let mut sum: u32 = 0;
    for i in (14..34).step_by(2) {
        sum += (u32::from(f[i]) << 8) | u32::from(f[i + 1]);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    f[24] = (!sum >> 8) as u8;
    f[25] = !sum as u8;
    f.truncate(14 + total);
    f
}

fn ipv4_checksum_ok(f: &[u8]) -> bool {
    let mut sum: u32 = 0;
    for i in (14..34).step_by(2) {
        sum += (u32::from(f[i]) << 8) | u32::from(f[i + 1]);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16 == 0xffff
}

fn codel_on(w: &W, target_us: u32, interval_ms: u32) {
    let t = Tuning { codel: true, codel_target_us: target_us, codel_interval_ms: interval_ms, ..w.b.tuning() };
    assert_eq!(w.b.set_tuning(&t), Ok(()));
}

/// Saturate the pipe with real holds: each iteration the host offers one more frame than the queue takes (the last offer is answered HOLD),
/// time passes, and the worker drains (and resumes). `iterations` of `step_us` each.
fn saturate(w: &mut W, iterations: u32, step_us: u32, f: &[u8]) {
    for _ in 0..iterations {
        for _ in 0..=HOST_QUEUE_LIMIT {
            w.host_in(f);
        }
        w.advance_us(step_us);
        w.pump();
    }
}

fn steady_flow(w: &mut W, frames: u32, spacing_us: u32, f: &[u8]) {
    for _ in 0..frames {
        w.host_in(f);
        w.pump();
        w.advance_us(spacing_us);
    }
}

#[test]
fn codel_off_touches_nothing() {
    let mut w = W::linked();
    let d = w.b.tuning();
    assert!(d.codel && d.codel_target_us == 5000 && d.codel_interval_ms == 100, "the defaults are RFC 8289's, on");
    assert_eq!(w.b.set_tuning(&Tuning { codel: false, ..d }), Ok(()));
    let f = ipv4_frame(2, 17, 100, false);
    saturate(&mut w, 200, 2000, &f);
    let s = w.stats();
    assert_eq!((s.h2w_codel_signals, s.h2w_ce_marked, s.h2w_codel_drop), (0, 0, 0));
    assert_eq!(*w.env().tx_seen.borrow(), f);
}

#[test]
fn codel_marks_ect_frames_and_keeps_the_checksum() {
    let mut w = W::linked();
    codel_on(&w, 5000, 100);
    let f = ipv4_frame(2, 17, 100, false);
    saturate(&mut w, 30, 2000, &f); // 60 ms: below the interval
    assert_eq!(w.stats().h2w_codel_signals, 0);
    saturate(&mut w, 150, 2000, &f); // 300 ms more
    let s = w.stats();
    assert!(s.h2w_ce_marked > 3 && s.h2w_codel_drop == 0 && s.h2w_codel_signals == s.h2w_ce_marked, "{s:#?}");
    assert!(s.h2w_sent == s.h2w_queued && s.h2w_codel_count > 0, "a marked frame is a sent frame");
    w.env().ce_seen.borrow_mut().clear();
    for _ in 0..400 {
        if !w.env().ce_seen.borrow().is_empty() {
            break;
        }
        saturate(&mut w, 1, 2000, &f);
    }
    let ce = w.env().ce_seen.borrow().clone();
    assert_eq!(ce.len(), f.len());
    assert_eq!(ce[15] & 3, 3);
    assert!(ipv4_checksum_ok(&ce));
    assert_eq!(ce[..15], f[..15]);
    assert_eq!(ce[16..24], f[16..24]);
    assert_eq!(ce[26..], f[26..], "only TOS and the header checksum changed");
    w.check_identities();
}

#[test]
fn codel_drops_not_ect_frames_at_the_same_rate() {
    let mut w = W::linked();
    codel_on(&w, 5000, 100);
    let f = ipv4_frame(0, 17, 100, false);
    saturate(&mut w, 300, 2000, &f);
    let s = w.stats();
    assert!(s.h2w_codel_drop > 3 && s.h2w_ce_marked == 0 && s.h2w_codel_signals == s.h2w_codel_drop, "{s:#?}");
    assert_eq!(s.h2w_sent + s.h2w_codel_drop, s.h2w_queued - s.h2w_queue_depth);
    w.check_identities();
}

#[test]
fn codel_never_touches_arp_syn_dhcp_and_ends_with_the_holds() {
    let mut w = W::linked();
    codel_on(&w, 5000, 100);
    let f = ipv4_frame(0, 17, 100, false);
    saturate(&mut w, 300, 2000, &f); // a dropping state
    let (dropped, signals) = (w.stats().h2w_codel_drop, w.stats().h2w_codel_signals);
    let mut arp = vec![0u8; 60];
    arp[..6].copy_from_slice(&PEER);
    arp[6..12].copy_from_slice(&MAC);
    arp[12] = 0x08;
    arp[13] = 0x06;
    saturate(&mut w, 20, 2000, &arp);
    let syn = ipv4_frame(0, 6, 20, true);
    saturate(&mut w, 20, 2000, &syn);
    let mut dhcp = ipv4_frame(0, 17, 20, false);
    dhcp[14 + 20 + 2] = 0;
    dhcp[14 + 20 + 3] = 67;
    saturate(&mut w, 20, 2000, &dhcp);
    let s = w.stats();
    assert_eq!((s.h2w_codel_drop, s.h2w_codel_signals), (dropped, signals), "ARP, SYN, DHCP: never marked, never dropped, whatever the signal");
    w.check_identities();
    // The holds stop: after an interval without one the signal is zero, CoDel leaves its dropping state, and nothing more is signalled.
    w.advance_us(150_000);
    let before = w.stats().h2w_codel_drop + w.stats().h2w_ce_marked;
    for _ in 0..400 {
        w.host_in(&f);
        w.pump();
        w.advance_us(2500); // 4 Mbit/s of 100 B: a steady unheld flow
    }
    let s = w.stats();
    assert_eq!((s.h2w_codel_drop + s.h2w_ce_marked, s.h2w_codel_count), (before, 0));
    // Retuning restarts the controller.
    codel_on(&w, 1000, 50);
    saturate(&mut w, 10, 2000, &f);
    w.check_identities();
}

/// The hold-evidenced busy period (ADR 0023 amendment 7). A sender below the pipe's rate is never held and is never signalled, whatever its
/// rate; a sender that saturates the pipe is held again and again and is signalled once the holds have lasted target + interval; holds that
/// stop for an interval end it.
#[test]
fn hold_evidenced_period() {
    // 1. The case the board found: a steady non-responsive UDP flow at about 5 Mbit/s (1,400 B every 2.2 ms), below the pipe, no holds: ZERO
    //    signals in 4 s.
    let mut w = W::linked();
    codel_on(&w, 5000, 100);
    let f = ipv4_frame(0, 17, 1300, false); // not-ECT UDP: the worst case, a drop if it is ever signalled
    steady_flow(&mut w, 1800, 2200, &f);
    let s = w.stats();
    assert!(
        s.h2w_held == 0 && s.h2w_codel_signals == 0 && s.h2w_codel_drop == 0 && s.h2w_ce_marked == 0 && s.h2w_sent == 1800 && s.h2w_signal_us_max < 5000,
        "{s:#?}"
    );
    // ... and the same at 2.2 ms spacing with 6.5 ms gaps mixed in (the old gap-based signal restarted on those; this one never started).
    let mut w = W::linked();
    codel_on(&w, 5000, 100);
    for i in 0..1000u32 {
        w.host_in(&f);
        w.pump();
        w.advance_us(if i % 7 == 0 { 6500 } else { 2200 });
    }
    assert!(w.stats().h2w_held == 0 && w.stats().h2w_codel_signals == 0);
    // 2. A saturating flow with holds recurring every 2 ms: no signal for target + interval, then they start and speed up.
    let mut w = W::linked();
    codel_on(&w, 5000, 100);
    let f = ipv4_frame(0, 17, 100, false);
    let t0 = w.env().now.get();
    let mut first_us = 0;
    for _ in 0..400 {
        if first_us != 0 {
            break;
        }
        saturate(&mut w, 1, 2000, &f);
        if w.stats().h2w_codel_signals != 0 {
            first_us = w.env().now.get() - t0;
        }
    }
    assert!(
        w.stats().h2w_held > 20 && (100_000..=112_000).contains(&first_us),
        "first signal after {first_us} us: the first hold started the period; one interval of excess later"
    );
    saturate(&mut w, 300, 2000, &f);
    assert!(w.stats().h2w_codel_signals >= 6 && w.stats().h2w_codel_count >= 2, "{:#?}", w.stats());
    // 3. The holds stop for an interval: the signal is zero, CoDel leaves its dropping state (count 0), and a steady unheld flow is never
    //    signalled again.
    w.advance_us(120_000);
    let acts = w.stats().h2w_codel_signals;
    steady_flow(&mut w, 600, 2200, &f);
    assert_eq!((w.stats().h2w_codel_signals, w.stats().h2w_codel_count), (acts, 0));
    // 4. Isolated holds (one burst every 150 ms, an interval and a half apart) never form a period: no signal in 6 s.
    let mut w = W::linked();
    codel_on(&w, 5000, 100);
    for _ in 0..40 {
        saturate(&mut w, 1, 2000, &f); // one hold
        steady_flow(&mut w, 70, 2200, &f); // then 150 ms of unheld traffic
    }
    assert!(w.stats().h2w_held >= 40 && w.stats().h2w_codel_signals == 0, "{:#?}", w.stats());
    // 5. Holds that DO recur within the interval (every 90 ms) are a standing backlog, however light the rest of the traffic is.
    let mut w = W::linked();
    codel_on(&w, 5000, 100);
    for _ in 0..40 {
        saturate(&mut w, 1, 2000, &f);
        steady_flow(&mut w, 40, 2200, &f);
    }
    assert!(w.stats().h2w_codel_signals > 0);
    // 6. The interval is CoDel's: a tuned interval moves the horizon.
    let mut w = W::linked();
    codel_on(&w, 5000, 400);
    let t0 = w.env().now.get();
    let mut first_us = 0;
    for _ in 0..400 {
        if first_us != 0 {
            break;
        }
        saturate(&mut w, 1, 2000, &f);
        if w.stats().h2w_codel_signals != 0 {
            first_us = w.env().now.get() - t0;
        }
    }
    assert!((400_000..=412_000).contains(&first_us), "{first_us}");
    // A link change forgets the period.
    w.b.link(false);
    w.b.link(true);
    assert_eq!(w.b.hold_period_age(w.env().now.get()), 0);
    w.check_identities();
}

/// What the ingress counts about ECN, always, and what a real stack's frames look like. These are assembled from the RFC 793/3168 field layouts
/// and the header shapes macOS and Linux emit (IP options absent, TCP data offset 8 with timestamps; SYN carrying ECE|CWR; ECT(0) on data,
/// not-ECT on SYN and pure ACK), not a capture from a machine.
fn tcp_frame(v6: bool, tos: u8, flags: u8, payload: usize) -> Vec<u8> {
    let mut f = vec![0u8; 1600];
    f[..6].copy_from_slice(&PEER);
    f[6..12].copy_from_slice(&MAC);
    let l4;
    if v6 {
        f[12] = 0x86;
        f[13] = 0xdd;
        f[14] = 0x60 | (tos >> 4);
        f[15] = (tos & 15) << 4;
        l4 = 14 + 40;
        let n = 32 + payload;
        f[18] = (n >> 8) as u8;
        f[19] = n as u8;
        f[20] = 6;
        f[21] = 64;
    } else {
        f[12] = 0x08;
        f[13] = 0x00;
        f[14] = 0x45;
        f[15] = tos;
        l4 = 14 + 20;
        let total = 20 + 32 + payload;
        f[16] = (total >> 8) as u8;
        f[17] = total as u8;
        f[20] = 0x40;
        f[22] = 64;
        f[23] = 6;
    }
    f[l4] = 0xc3;
    f[l4 + 1] = 0x50;
    f[l4 + 2] = 0x14;
    f[l4 + 3] = 0x51;
    f[l4 + 12] = 0x80; // data offset 8 words
    f[l4 + 13] = flags;
    f.truncate(l4 + 32 + payload);
    f
}

#[test]
fn ecn_counters() {
    use tdongle_aqm::{EcnClass, TcpEcnSyn, classify, tcp_ecn_syn};
    let mut w = W::linked();
    let offer = |w: &mut W, f: &[u8]| {
        w.host_in(f);
        w.pump();
    };
    let f = tcp_frame(false, 0x00, 0xc2, 0); // SYN, ECE, CWR: an ECN-setup SYN, itself not-ECT, exempt (setup)
    assert_eq!((classify(&f), tcp_ecn_syn(&f)), (EcnClass::Exempt, TcpEcnSyn::SynEcnSetup));
    offer(&mut w, &f);
    let f = tcp_frame(false, 0x02, 0x18, 1000); // data: PSH|ACK, ECT(0)
    assert_eq!(classify(&f), EcnClass::Capable);
    offer(&mut w, &f);
    let f = tcp_frame(false, 0x00, 0x10, 0); // pure ACK: not-ECT
    assert_eq!(classify(&f), EcnClass::NotEct);
    offer(&mut w, &f);
    let f = tcp_frame(false, 0x03, 0x18, 500); // already CE
    assert_eq!(classify(&f), EcnClass::Ce);
    offer(&mut w, &f);
    let f = tcp_frame(true, 0x02, 0x18, 1000); // IPv6 data, ECT(0)
    assert_eq!(classify(&f), EcnClass::Capable);
    offer(&mut w, &f);
    let f = tcp_frame(true, 0x01, 0x18, 1000); // IPv6 data, ECT(1)
    assert_eq!(classify(&f), EcnClass::Capable);
    offer(&mut w, &f);
    let f = tcp_frame(true, 0x00, 0xc2, 0);
    assert_eq!(tcp_ecn_syn(&f), TcpEcnSyn::SynEcnSetup);
    offer(&mut w, &f);
    let mut arp = vec![0u8; 60];
    arp[..6].copy_from_slice(&PEER);
    arp[6..12].copy_from_slice(&MAC);
    arp[12] = 0x08;
    arp[13] = 0x06;
    offer(&mut w, &arp);
    let s = w.stats();
    assert_eq!((s.h2w_ecn_capable, s.h2w_ecn_not_ect, s.h2w_ecn_ce, s.h2w_ecn_exempt, s.h2w_ecn_not_ip, s.h2w_syn_ecn_setup), (3, 1, 1, 2, 1, 2));
    // A SYN-ACK from the server (ECE, no CWR) is counted on the way to the host; one with CWR is not an accept.
    let mut f = tcp_frame(false, 0x00, 0x52, 0); // SYN|ACK|ECE
    assert_eq!(tcp_ecn_syn(&f), TcpEcnSyn::SynAckEcnAccept);
    f[..6].copy_from_slice(&MAC);
    f[6..12].copy_from_slice(&PEER);
    w.wifi_in(&f);
    let f2 = tcp_frame(false, 0x00, 0xd2, 0); // SYN|ACK|ECE|CWR
    assert_eq!(tcp_ecn_syn(&f2), TcpEcnSyn::Other);
    assert_eq!(w.stats().w2h_synack_ecn, 1);
    // IPv4 with options: the TCP header starts after the longer IP header, and everything is still found.
    let mut f = tcp_frame(false, 0x02, 0x18, 100);
    let n = f.len();
    f.extend_from_slice(&[0u8; 4]);
    f.copy_within(14 + 20..n, 14 + 24);
    f[14 + 20..14 + 24].fill(0);
    f[14] = 0x46;
    assert_eq!(classify(&f), EcnClass::Capable);
    f[14 + 24 + 13] = 0xc2;
    assert_eq!(tcp_ecn_syn(&f), TcpEcnSyn::SynEcnSetup);
    w.check_identities();
}
