//! Handshake and session behaviour between two instances of this crate: both directions, with and without a preshared key, and the attack cases
//! (tamper, bad MAC, reflection, replay, old timestamp, flood, cookies).

mod common;
use common::*;
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_wg::cookie::CookieChecker;
use tdongle_tailnet_wg::msg::{KEEPALIVE_LEN, transport_len};
use tdongle_tailnet_wg::*;

fn psk() -> Key32 {
    Key32([0x5a; 32])
}

fn trim(p: &[u8], n: usize) {
    assert!(p.len() >= n && p.len().is_multiple_of(16) && p.len() - n < 16);
    assert!(p[n..].iter().all(|&x| x == 0));
}

#[test]
fn handshake_and_transport_both_directions_without_and_with_psk() {
    for p in [None, Some(psk())] {
        let (mut a, mut b) = pair(p);
        let init = a.initiate(1000).unwrap();
        assert_eq!(init.len(), 148);
        assert_eq!(a.hot.handshake_state(), HsState::InitiationSent);
        let Event::Reply(resp) = b.rx(&init, 1000) else { panic!() };
        assert_eq!(resp.len(), 92);
        // the responder's session is unconfirmed: it cannot send yet
        assert!(b.hot.next().is_some() && b.hot.current().is_none());
        assert_eq!(b.send(b"early", 1001), Err(TxError::NoSession));
        assert_eq!(a.rx(&resp, 1001), Event::Established);
        assert!(a.hot.has_session() && a.hot.current().unwrap().is_initiator());
        assert_eq!(a.hot.handshake_state(), HsState::Idle);
        // initiator -> responder confirms and promotes
        let d = a.send(b"hello wireguard", 1002).unwrap();
        assert_eq!(d.len(), transport_len(15));
        let Event::Confirmed(pt) = b.rx(&d, 1002) else { panic!() };
        trim(&pt, 15);
        assert_eq!(&pt[..15], b"hello wireguard");
        assert!(b.hot.current().is_some() && b.hot.next().is_none());
        // and back
        let d = b.send(b"and back", 1003).unwrap();
        let Event::Payload(pt) = a.rx(&d, 1003) else { panic!() };
        assert_eq!(&pt[..8], b"and back");
        // many sizes, both ways, keepalives
        for n in [0usize, 1, 15, 16, 17, 31, 32, 1399, 1400, 1401] {
            let payload: Vec<u8> = (0..n).map(|i| i as u8 ^ 0x5c).collect();
            for dir in 0..2 {
                let (x, y) = if dir == 0 { (&mut a, &mut b) } else { (&mut b, &mut a) };
                let d = x.send(&payload, 2000).unwrap();
                assert_eq!(d.len(), transport_len(n));
                match y.rx(&d, 2000) {
                    Event::Keepalive => assert_eq!(n, 0),
                    Event::Payload(pt) => {
                        trim(&pt, n);
                        assert_eq!(&pt[..n], &payload[..]);
                    }
                    e => panic!("{e:?}"),
                }
            }
        }
        assert_eq!(a.drops.total() + b.drops.total(), 0);
    }
}

#[test]
fn responder_can_initiate_the_reverse_handshake() {
    // A has a session to B; now B initiates (a rekey from the other side, or a restart of A)
    let (mut a, mut b) = pair(Some(psk()));
    handshake_confirmed(&mut a, &mut b, 1000);
    let init = b.initiate(50_000).unwrap();
    let Event::Reply(resp) = a.rx(&init, 50_000) else { panic!() };
    assert_eq!(b.rx(&resp, 50_001), Event::Established);
    // B (now initiator of the new session) confirms A's next session
    let ka = b.keepalive(50_002).unwrap();
    assert_eq!(a.rx(&ka, 50_002), Event::Confirmed(vec![]));
    // old session still in `previous` on both sides; new one current
    assert!(a.hot.previous().is_some() && b.hot.previous().is_some());
    let d = a.send(b"x", 50_003).unwrap();
    assert_eq!(header(&d).receiver, b.hot.current().unwrap().local_index());
    assert!(matches!(b.rx(&d, 50_003), Event::Payload(_)));
}

#[test]
fn psk_mismatch_fails_at_the_response() {
    let (mut a, mut b) = (Side::new(1, 2, Some(Key32([1; 32])), 0x1000), Side::new(2, 1, Some(Key32([2; 32])), 0x2000));
    let init = a.initiate(0).unwrap();
    let Event::Reply(resp) = b.rx(&init, 0) else { panic!() };
    assert_eq!(a.rx(&resp, 0), Event::Dropped(Dropped::HsAuthResponse));
    assert_eq!(a.hot.handshake_state(), HsState::InitiationSent, "a failed response leaves the outstanding initiation alone");
    assert!(!a.hot.has_session());
}

#[test]
fn unknown_peer_and_wrong_recipient() {
    let (mut a, _b) = pair(None);
    let mut c = Side::new(3, 1, None, 0x3000); // C trusts A's key but A's initiation is for B
    let init = a.initiate(0).unwrap();
    // the initiation is addressed to B's public key: C's mac1 key differs
    assert_eq!(c.rx(&init, 0), Event::Dropped(Dropped::BadMac1));
    // an initiation from a key B does not know: build with a third identity addressed to B
    let mut x = Side::new(9, 2, None, 0x9000);
    let mut b = Side::new(2, 1, None, 0x2000); // B only knows A
    let init = x.initiate(0).unwrap();
    assert_eq!(b.rx(&init, 0), Event::Dropped(Dropped::HsUnknownPeer));
    assert_eq!(b.hot.handshake_state(), HsState::Idle);
}

#[test]
fn every_byte_flip_of_an_initiation_is_refused_except_mac2() {
    let (mut a, _) = pair(None);
    let init = a.initiate(5000).unwrap();
    for i in 0..init.len() {
        let mut b = Side::new(2, 1, None, 0x2000);
        let mut bad = init;
        bad[i] ^= 0x01;
        let ev = b.rx(&bad, 5000);
        if (132..148).contains(&i) {
            // mac2 is not checked unless we are under load
            assert!(matches!(ev, Event::Reply(_)), "byte {i}: {ev:?}");
        } else {
            assert!(matches!(ev, Event::Dropped(_)), "byte {i}: {ev:?}");
            assert_eq!(b.hot.handshake_state(), HsState::Idle, "byte {i}");
        }
    }
}

#[test]
fn every_byte_flip_of_a_response_is_refused_except_mac2() {
    let (mut a, mut b) = pair(None);
    let init = a.initiate(5000).unwrap();
    let Event::Reply(resp) = b.rx(&init, 5000) else { panic!() };
    for i in 0..resp.len() {
        let mut bad = resp.clone();
        bad[i] ^= 0x80;
        // a copy of A in the same state: re-run the initiation with identical entropy
        let mut a2 = Side::new(1, 2, None, 0x1000);
        let init2 = a2.initiate(5000).unwrap();
        assert_eq!(init, init2, "deterministic harness");
        let ev = a2.rx(&bad, 5001);
        if (76..92).contains(&i) {
            assert_eq!(ev, Event::Established, "byte {i}");
        } else {
            assert!(matches!(ev, Event::Dropped(_)), "byte {i}: {ev:?}");
            assert!(!a2.hot.has_session(), "byte {i}");
            assert_eq!(a2.hot.handshake_state(), HsState::InitiationSent, "byte {i}: state untouched");
        }
    }
}

#[test]
fn transport_tamper_every_byte_and_truncation() {
    let (mut a, mut b) = pair(None);
    handshake_confirmed(&mut a, &mut b, 0);
    let d = a.send(&[0xab; 40], 10).unwrap();
    for i in 0..d.len() {
        let mut bad = d.clone();
        bad[i] ^= 0x10;
        assert!(matches!(b.rx(&bad, 10), Event::Dropped(_)), "byte {i}");
    }
    for n in 0..d.len() {
        assert!(matches!(b.rx(&d[..n], 10), Event::Dropped(_)), "len {n}");
    }
    let mut longer = d.clone();
    longer.push(0);
    assert!(matches!(b.rx(&longer, 10), Event::Dropped(Dropped::AuthFail)));
    // none of that disturbed the replay window: the genuine datagram still goes through, once
    assert!(matches!(b.rx(&d, 10), Event::Payload(_)));
    assert_eq!(b.rx(&d, 10), Event::Dropped(Dropped::ReplayDuplicate));
}

#[test]
fn reflection_is_refused() {
    let (mut a, mut b) = pair(None);
    let init = a.initiate(0).unwrap();
    // our own initiation reflected back: mac1 is keyed for the peer, not for us
    assert_eq!(a.rx(&init, 0), Event::Dropped(Dropped::BadMac1));
    let Event::Reply(resp) = b.rx(&init, 0) else { panic!() };
    // the responder's own response reflected to it
    assert_eq!(b.rx(&resp, 0), Event::Dropped(Dropped::BadMac1));
    assert_eq!(a.rx(&resp, 0), Event::Established);
    let d = a.send(b"x", 1).unwrap();
    // A's datagram reflected to A: index belongs to B
    assert_eq!(a.rx(&d, 1), Event::Dropped(Dropped::NoSession));
    // the same with colliding receiver indices on both sides (a broken allocator): the directional keys still refuse it
    let (mut a, mut b) = (Side::new(1, 2, None, 0x500), Side::new(2, 1, None, 0x500));
    handshake_confirmed(&mut a, &mut b, 0);
    assert_eq!(a.hot.current().unwrap().local_index(), b.hot.current().unwrap().local_index());
    let d = a.send(b"x", 1).unwrap();
    assert_eq!(a.rx(&d, 1), Event::Dropped(Dropped::AuthFail));
    assert!(matches!(b.rx(&d, 1), Event::Payload(_)));
}

#[test]
fn transport_replay_and_window() {
    let (mut a, mut b) = pair(None);
    handshake_confirmed(&mut a, &mut b, 0);
    let pkts: Vec<Vec<u8>> = (0..700u32).map(|i| a.send(&i.to_le_bytes(), 5).unwrap()).collect();
    // reorder inside the window: 100..200 backwards
    for p in pkts[..100].iter().chain(pkts[100..200].iter().rev()) {
        assert!(matches!(b.rx(p, 5), Event::Payload(_)));
    }
    for p in &pkts[..200] {
        assert_eq!(b.rx(p, 5), Event::Dropped(Dropped::ReplayDuplicate));
    }
    // jump far ahead; the oldest are now below the window
    assert!(matches!(b.rx(&pkts[699], 5), Event::Payload(_)));
    let w = ReplayWindow::WINDOW as usize;
    assert_eq!(b.rx(&pkts[699 - w - 1], 5), Event::Dropped(Dropped::ReplayTooOld));
    assert!(matches!(b.rx(&pkts[699 - w], 5), Event::Payload(_)));
    // pkts[0] was accepted before the jump and is now below the window: TooOld wins over Duplicate
    assert_eq!(b.rx(&pkts[0], 5), Event::Dropped(Dropped::ReplayTooOld));
}

#[test]
fn handshake_replay_old_timestamp_and_flood() {
    let (mut a, mut b) = pair(None);
    let init = a.initiate(10_000).unwrap();
    let Event::Reply(_) = b.rx(&init, 10_000) else { panic!() };
    // the same datagram again: timestamp not newer
    assert_eq!(b.rx(&init, 10_001), Event::Dropped(Dropped::HsTimestampReplay));
    // a newer initiation 5 ms later (a second instance of A): flood
    let mut a2 = Side::new(1, 2, None, 0x1100);
    let i2 = a2.hot.create_initiation(&a2.id, &a2.cold, 10_005, wall(10_005), &mut a2.rng, &mut a2.idx).unwrap();
    assert_eq!(b.rx(&i2, 10_005), Event::Dropped(Dropped::HsFlood));
    // 30 ms later it is fine (a fresh timestamp, spacing above 20 ms)
    let mut a3 = Side::new(1, 2, None, 0x1200);
    let i3 = a3.hot.create_initiation(&a3.id, &a3.cold, 10_030, wall(10_030), &mut a3.rng, &mut a3.idx).unwrap();
    assert!(matches!(b.rx(&i3, 10_030), Event::Reply(_)));
    // an initiation with an older timestamp than the greatest seen
    let mut a4 = Side::new(1, 2, None, 0x1300);
    let i4 = a4.hot.create_initiation(&a4.id, &a4.cold, 10_100, wall(5_000), &mut a4.rng, &mut a4.idx).unwrap();
    assert_eq!(b.rx(&i4, 10_100), Event::Dropped(Dropped::HsTimestampReplay));
    // the equal timestamp too
    let mut a5 = Side::new(1, 2, None, 0x1400);
    let i5 = a5.hot.create_initiation(&a5.id, &a5.cold, 10_200, wall(10_030), &mut a5.rng, &mut a5.idx).unwrap();
    assert_eq!(b.rx(&i5, 10_200), Event::Dropped(Dropped::HsTimestampReplay));
}

#[test]
fn successive_initiations_get_increasing_timestamps_even_on_a_coarse_clock() {
    // the wall clock does not advance between calls (or goes back): the timestamps still strictly increase, or a responder would drop every one after the first
    let (mut a, mut b) = pair(None);
    let mut t = 100_000u64;
    for round in 0..4 {
        let init = a.hot.create_initiation(&a.id, &a.cold, t, wall(1_000), &mut a.rng, &mut a.idx).unwrap();
        let ev = b.rx(&init, t);
        assert!(matches!(ev, Event::Reply(_)), "round {round}: {ev:?}");
        t += 6_000; // beyond REKEY_TIMEOUT so the gate is open
    }
}

#[test]
fn initiation_spacing_is_rekey_timeout() {
    let (mut a, _b) = pair(None);
    a.initiate(1000).unwrap();
    assert_eq!(a.initiate(1001).unwrap_err(), InitError::TooSoon);
    assert_eq!(a.initiate(5999).unwrap_err(), InitError::TooSoon);
    assert!(a.initiate(6000).is_ok());
}

#[test]
fn cookie_flow_under_load() {
    let (mut a, mut b) = pair(None);
    let init = a.initiate(1000).unwrap();
    let src = a.src.clone();
    // B is under load: mac2 is zero, so it answers with a cookie reply and keeps no state
    let mut p = init.to_vec();
    let Event::Reply(cr) = b.on_packet(&mut p, 1000, true, &src) else { panic!("expected a cookie reply") };
    assert_eq!(cr.len(), 64);
    assert_eq!(b.hot.handshake_state(), HsState::Idle);
    assert_eq!(a.rx(&cr, 1001), Event::CookieStored);
    // a second consumption of the same reply is unexpected
    assert_eq!(a.rx(&cr, 1002), Event::Dropped(Dropped::CookieUnexpected));
    // a new initiation too soon is refused by the spacing; after REKEY_TIMEOUT it carries mac2
    assert_eq!(a.initiate(2000).unwrap_err(), InitError::TooSoon);
    let init2 = a.initiate(6000).unwrap();
    assert_ne!(&init2[132..], &[0u8; 16]);
    let mut p = init2.to_vec();
    let Event::Reply(resp) = b.on_packet(&mut p, 6000, true, &src) else { panic!("expected a response") };
    assert_eq!(resp.len(), 92);
    // the response goes to A; under load A would need mac2 on it too: B has no cookie from A, so A (under load) answers with a cookie reply
    let mut p = resp.clone();
    let Event::Reply(cr2) = a.on_packet(&mut p, 6001, true, &b.src.clone()) else { panic!() };
    assert_eq!(cr2.len(), 64);
    assert_eq!(a.hot.handshake_state(), HsState::InitiationSent);
    assert_eq!(b.rx(&cr2, 6002), Event::Dropped(Dropped::CookieUnexpected), "B sent a response without a stored last-mac1 for A's init");
    // not under load A takes it
    assert_eq!(a.rx(&resp, 6003), Event::Established);
}

#[test]
fn cookie_is_bound_to_the_source_address_and_expires() {
    let (mut a, mut b) = pair(None);
    let init = a.initiate(0).unwrap();
    let src = a.src.clone();
    let mut p = init.to_vec();
    let Event::Reply(cr) = b.on_packet(&mut p, 0, true, &src) else { panic!() };
    assert_eq!(a.rx(&cr, 1), Event::CookieStored);
    let init2 = a.initiate(6000).unwrap();
    // from another address the same mac2 is wrong: a fresh cookie reply, not a response
    let mut p = init2.to_vec();
    let other = vec![198, 51, 100, 1, 0, 80];
    assert!(matches!(b.on_packet(&mut p, 6000, true, &other), Event::Reply(r) if r.len() == 64));
    // after the responder's secret is two minutes old, the cookie no longer verifies
    let mut p = init2.to_vec();
    assert!(matches!(b.on_packet(&mut p, 121_001, true, &src), Event::Reply(r) if r.len() == 64));
    // ... and a cookie A holds for more than two minutes is not put in new initiations
    let init3 = a.initiate(130_000).unwrap();
    assert_eq!(&init3[132..], &[0u8; 16]);
}

#[test]
fn bad_cookie_replies_are_dropped() {
    let (mut a, mut b) = pair(None);
    let init = a.initiate(0).unwrap();
    // nothing outstanding on B
    let mut p = init.to_vec();
    let Event::Reply(cr) = b.on_packet(&mut p, 0, true, &a.src.clone()) else { panic!() };
    assert_eq!(b.rx(&cr, 0), Event::Dropped(Dropped::CookieUnexpected));
    for i in 0..cr.len() {
        let mut bad = cr.clone();
        bad[i] ^= 1;
        let ev = a.rx(&bad, 1);
        assert!(matches!(ev, Event::Dropped(_)), "byte {i}: {ev:?}");
    }
    assert_eq!(a.rx(&cr, 1), Event::CookieStored, "the failed attempts did not consume the pending mac1");
}

#[test]
fn simultaneous_initiation_recovers_by_retransmit() {
    let (mut a, mut b) = pair(None);
    let ia = a.initiate(1000).unwrap();
    let ib = b.initiate(1000).unwrap();
    let Event::Reply(ra) = b.rx(&ia, 1001) else { panic!() };
    let Event::Reply(rb) = a.rx(&ib, 1001) else { panic!() };
    // each side now answered the other's initiation; the other's response finds no outstanding initiation
    assert_eq!(a.rx(&ra, 1002), Event::Dropped(Dropped::HsNoHandshake));
    assert_eq!(b.rx(&rb, 1002), Event::Dropped(Dropped::HsNoHandshake));
    assert!(!a.hot.has_session() && !b.hot.has_session());
    // A's retransmit timer fires; B answers; the exchange completes
    let acts = a.hot.poll(7000);
    assert!(acts.contains(Actions::SEND_INITIATION), "{acts:?}");
    let ia2 = a.initiate(7000).unwrap();
    let Event::Reply(ra2) = b.rx(&ia2, 7000) else { panic!() };
    assert_eq!(a.rx(&ra2, 7001), Event::Established);
    let ka = a.keepalive(7002).unwrap();
    assert!(matches!(b.rx(&ka, 7002), Event::Confirmed(_)));
}

#[test]
fn small_order_ephemeral_is_refused() {
    // an initiation whose ephemeral is the all-zero point: X25519 yields zero; refused before anything is installed (mac1 recomputed by an attacker who knows B's key)
    use tdongle_tailnet_wg::cookie::add_macs;
    use tdongle_tailnet_wg::msg::Initiation;
    let (mut a, mut b) = pair(None);
    let init = a.initiate(0).unwrap();
    let mut m = Initiation::parse(&init).unwrap();
    m.ephemeral = [0; 32];
    let mut bytes = m.encode();
    add_macs(&mut bytes, b.id.mac1_key(), None);
    assert_eq!(b.rx(&bytes, 0), Event::Dropped(Dropped::DhZero));
    assert_eq!(b.hot.handshake_state(), HsState::Idle);
}

#[test]
fn indices_come_from_the_allocator_and_are_reported_for_uniqueness() {
    let (mut a, mut b) = pair(None);
    a.idx.fail = true;
    assert_eq!(a.initiate(0).unwrap_err(), InitError::NoIndex);
    a.idx.fail = false;
    handshake_confirmed(&mut a, &mut b, 0);
    let mut seen = vec![];
    a.hot.for_each_index(|i| seen.push(i));
    assert_eq!(seen, vec![a.hot.current().unwrap().local_index()]);
    assert!(a.hot.uses_index(seen[0]) && !a.hot.uses_index(seen[0] + 1));
    // a pending handshake is reported too
    let _ = a.initiate(10_000).unwrap();
    let mut seen = vec![];
    a.hot.for_each_index(|i| seen.push(i));
    assert_eq!(seen.len(), 2);
    // an allocator that fails during the response
    let (mut a, mut b) = pair(None);
    b.idx.fail = true;
    let init = a.initiate(0).unwrap();
    assert!(matches!(b.rx(&init, 0), Event::Dropped(Dropped::HsNoHandshake)));
    assert_eq!(b.hot.handshake_state(), HsState::InitiationConsumed);
}

#[test]
fn initiation_job_commit_refuses_a_changed_handshake_and_releases_the_index() {
    let (mut a, mut b) = pair(None);
    let mut job = a.hot.initiation_begin(&a.id, &a.cold, 0, wall(0), &mut a.rng, &mut a.idx).unwrap();
    let idx = job.index();
    job.compute();
    assert!(job.ok());
    // while the crypto ran "outside the lock", B's initiation was consumed on this slot
    let ib = b.initiate(0).unwrap();
    assert!(matches!(a.rx(&ib, 1), Event::Reply(_)));
    assert_eq!(a.hot.initiation_commit(job, 2, &mut a.idx).unwrap_err(), InitError::BadState);
    assert_eq!(a.idx.released, vec![idx]);
    assert_ne!(a.hot.handshake_state(), HsState::InitiationSent);
    // an untouched slot commits
    let (mut a, mut b) = pair(None);
    let mut job = a.hot.initiation_begin(&a.id, &a.cold, 0, wall(0), &mut a.rng, &mut a.idx).unwrap();
    job.compute();
    let msg = a.hot.initiation_commit(job, 0, &mut a.idx).unwrap();
    assert!(matches!(b.rx(&msg, 0), Event::Reply(_)));
    assert!(a.idx.released.is_empty());
}

#[test]
fn keepalive_is_32_bytes_and_padding_is_zero() {
    let (mut a, mut b) = pair(None);
    handshake_confirmed(&mut a, &mut b, 0);
    assert_eq!(a.keepalive(1).unwrap().len(), KEEPALIVE_LEN);
    let d = a.send(&[7u8; 1], 2).unwrap();
    assert_eq!(d.len(), 48);
    let Event::Payload(p) = b.rx(&d, 2) else { panic!() };
    assert_eq!(p.len(), 16);
    assert_eq!(p[0], 7);
    assert!(p[1..].iter().all(|&x| x == 0));
}

#[test]
fn sizes_are_reported() {
    // Not an assertion on exact numbers (they differ per target); the bounds guard against accidental bloat. Run with --nocapture to see them.
    println!(
        "PeerHot={} B, PeerCold={} B, Identity={} B, Session={} B, ReplayWindow={} B",
        PeerHot::BYTES,
        PeerCold::BYTES,
        Identity::BYTES,
        Session::BYTES,
        ReplayWindow::BYTES
    );
    const { assert!(PeerHot::BYTES <= 1100) };
    const { assert!(PeerCold::BYTES <= 96) };
    const { assert!(ReplayWindow::BYTES == 72) };
}

/// The screen applied to relayed packets before an unknown sender may be given a trial slot (the C `test_inbound_trial.c`): it accepts exactly a 148-byte
/// initiation whose mac1 is valid for our key, and nothing else.
#[test]
fn inbound_trial_screen_accepts_exactly_a_valid_initiation() {
    use tdongle_tailnet_wg::cookie::{Screen, screen};
    let (mut a, mut b) = pair(None);
    let init = a.initiate(0).unwrap();
    let mut ck = CookieChecker::new();
    let src = [1u8, 2, 3, 4, 0, 5];
    let go = |msg: &[u8], b: &Side, ck: &mut CookieChecker| screen(&b.id, ck, msg, &src, false, 0, &mut tdongle_tailnet_types::test_util::TestRng(1));
    assert_eq!(go(&init, &b, &mut ck), Screen::Pass);
    // every other length with the same type and a valid prefix
    for n in 0..300usize {
        if n == 148 {
            continue;
        }
        let mut m = init.to_vec();
        m.resize(n, 0);
        assert!(matches!(go(&m, &b, &mut ck), Screen::Drop(_)), "len {n}");
    }
    // every single-bit flip in the first 116 bytes (what mac1 covers), and in mac1 itself
    for i in 0..132 {
        let mut m = init;
        m[i] ^= 0x01;
        assert!(matches!(go(&m, &b, &mut ck), Screen::Drop(_)), "byte {i}");
    }
    // not a handshake at all: a transport datagram of any size, a cookie reply
    let mut t = vec![0u8; 148];
    t[0] = 4;
    assert_eq!(go(&t, &b, &mut ck), Screen::Drop(Dropped::ParseType));
    let mut c = vec![0u8; 64];
    c[0] = 3;
    assert_eq!(go(&c, &b, &mut ck), Screen::Drop(Dropped::ParseType));
    // a message mac'd for somebody else's key
    let other = Side::new(5, 1, None, 1);
    assert_eq!(go(&init, &other, &mut ck), Screen::Drop(Dropped::BadMac1));
    let _ = &mut b;
}

#[test]
fn greatest_timestamp_survives_eviction_when_the_pool_saves_it() {
    let (mut a, mut b) = pair(None);
    let init = a.initiate(10_000).unwrap();
    assert!(matches!(b.rx(&init, 10_000), Event::Reply(_)));
    let saved = b.hot.greatest_timestamp();
    assert_ne!(saved, [0u8; 12]);
    // the slot is reclaimed by the pool and later reassigned to the same peer
    b.hot.reset();
    // without the restored value the replayed initiation is accepted again ...
    let mut b2 = Side::new(2, 1, None, 0x2000);
    assert!(matches!(b2.rx(&init, 20_000), Event::Reply(_)));
    // ... with it, it is the replay it is
    b.hot.set_greatest_timestamp(saved);
    assert_eq!(b.rx(&init, 20_000), Event::Dropped(Dropped::HsTimestampReplay));
}

#[test]
fn encrypt_into_a_short_buffer_is_its_own_error() {
    let (mut a, mut b) = pair(None);
    handshake_confirmed(&mut a, &mut b, 0);
    assert_eq!(a.hot.encrypt(&mut [0u8; 40], 20, 1), Err(TxError::BufferTooSmall));
}
