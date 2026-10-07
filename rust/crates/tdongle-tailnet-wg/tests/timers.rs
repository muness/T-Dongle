//! Keepalive, rekey, retransmit and expiry with virtual time (wireguard-go `timers.go` / whitepaper section 6).

mod common;
use common::*;
use tdongle_tailnet_wg::consts::*;
use tdongle_tailnet_wg::*;

const S: u64 = 1000;

fn up() -> (Side, Side) {
    let (mut a, mut b) = pair(None);
    handshake_confirmed(&mut a, &mut b, 0);
    (a, b)
}

/// Poll `side` every `step` ms from `from` to `to` (inclusive), returning the first time `want` is reported.
fn first(side: &mut Side, from: u64, to: u64, step: u64, want: Actions) -> Option<u64> {
    let mut t = from;
    while t <= to {
        if side.hot.poll(t).contains(want) {
            return Some(t);
        }
        t += step;
    }
    None
}

#[test]
fn passive_keepalive_ten_seconds_after_receiving_data() {
    let (mut a, mut b) = up();
    let d = a.send(b"data", 1000).unwrap();
    assert!(matches!(b.rx(&d, 1000), Event::Payload(_)));
    assert!(b.hot.poll(1000 + 10_000 - 1).is_empty());
    assert_eq!(b.hot.next_wake(1000), Some(1000 + 10_000));
    assert!(b.hot.poll(1000 + 10_000).contains(Actions::SEND_KEEPALIVE));
    // level triggered until acted on
    assert!(b.hot.poll(1000 + 10_000 + 5).contains(Actions::SEND_KEEPALIVE));
    let ka = b.keepalive(11_100).unwrap();
    assert_eq!(a.rx(&ka, 11_100), Event::Keepalive);
    assert!(b.hot.poll(11_200).is_empty());
}

#[test]
fn sending_data_cancels_the_passive_keepalive() {
    let (mut a, mut b) = up();
    let d = a.send(b"data", 1000).unwrap();
    b.rx(&d, 1000);
    b.send(b"reply", 5000).unwrap(); // the reply is the keepalive
    assert!(b.hot.poll(11_000).is_empty());
}

#[test]
fn receiving_keepalives_does_not_arm_the_passive_keepalive() {
    let (mut a, mut b) = up();
    let ka = a.keepalive(1000).unwrap();
    assert_eq!(b.rx(&ka, 1000), Event::Keepalive);
    assert!(b.hot.poll(20_000).is_empty());
}

#[test]
fn another_keepalive_when_data_keeps_arriving() {
    let (mut a, mut b) = up();
    let d1 = a.send(b"1", 1000).unwrap();
    let d2 = a.send(b"2", 4000).unwrap();
    b.rx(&d1, 1000);
    b.rx(&d2, 4000);
    assert!(b.hot.poll(11_000).contains(Actions::SEND_KEEPALIVE));
    b.keepalive(11_000).unwrap();
    assert!(b.hot.poll(20_999).is_empty());
    assert!(b.hot.poll(21_000).contains(Actions::SEND_KEEPALIVE), "need_another_keepalive re-armed it");
    b.keepalive(21_000).unwrap();
    assert!(b.hot.poll(40_000).is_empty());
}

#[test]
fn persistent_keepalive() {
    let (mut a, mut b) = up();
    a.hot.set_persistent_keepalive(25, 1000);
    assert!(a.hot.poll(25_999).is_empty());
    assert!(a.hot.poll(26_000).contains(Actions::SEND_KEEPALIVE));
    let ka = a.keepalive(26_000).unwrap();
    assert!(matches!(b.rx(&ka, 26_000), Event::Keepalive));
    assert!(a.hot.poll(50_999).is_empty());
    // receiving something also pushes it out
    let kb = b.keepalive(40_000).unwrap();
    a.rx(&kb, 40_000);
    assert!(a.hot.poll(64_999).is_empty());
    assert!(a.hot.poll(65_000).contains(Actions::SEND_KEEPALIVE));
    a.hot.set_persistent_keepalive(0, 65_000);
    assert!(a.hot.poll(200_000).is_empty() || !a.hot.poll(200_000).contains(Actions::SEND_KEEPALIVE));
}

#[test]
fn persistent_keepalive_without_a_session_starts_a_handshake() {
    let (mut a, _b) = pair(None);
    a.hot.set_persistent_keepalive(25, 0);
    assert!(a.hot.poll(24_999).is_empty());
    let acts = a.hot.poll(25_000);
    assert!(acts.contains(Actions::SEND_INITIATION) && !acts.contains(Actions::SEND_KEEPALIVE), "{acts:?}");
}

#[test]
fn stopped_hearing_back_starts_a_new_handshake() {
    let (mut a, _b) = up();
    a.send(b"into the void", 1000).unwrap();
    let t = first(&mut a, 1000, 40_000, 50, Actions::SEND_INITIATION).expect("a rekey attempt");
    // KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + jitter < 334 ms
    assert!((16_000..16_000 + REKEY_TIMEOUT_JITTER_MAX + 50).contains(&t), "t={t}");
    // hearing anything authenticated first cancels it
    let (mut a, mut b) = up();
    a.send(b"x", 1000).unwrap();
    let ka = b.keepalive(5000).unwrap();
    a.rx(&ka, 5000);
    assert!(first(&mut a, 5000, 60_000, 100, Actions::SEND_INITIATION).is_none());
}

#[test]
fn initiator_rekeys_when_sending_after_120_seconds() {
    let (mut a, mut b) = up();
    a.send(b"x", REKEY_AFTER_TIME - 1).ok();
    assert!(!a.hot.wants_handshake(), "not yet");
    // (the send above was within the minute: nothing armed)
    let d = a.send(b"y", REKEY_AFTER_TIME).unwrap();
    assert!(a.hot.wants_handshake());
    b.rx(&d, REKEY_AFTER_TIME);
    let acts = a.hot.poll(REKEY_AFTER_TIME);
    assert!(acts.contains(Actions::SEND_INITIATION), "{acts:?}");
    let init = a.initiate(REKEY_AFTER_TIME).unwrap();
    let Event::Reply(resp) = b.rx(&init, REKEY_AFTER_TIME) else { panic!() };
    assert_eq!(a.rx(&resp, REKEY_AFTER_TIME + 10), Event::Established);
    assert!(!a.hot.wants_handshake());
    // keys rolled: new current, old previous; the old session's datagrams are still accepted from the peer
    let old_idx = a.hot.previous().unwrap().local_index();
    let new_idx = a.hot.current().unwrap().local_index();
    assert_ne!(old_idx, new_idx);
    let ka = a.keepalive(REKEY_AFTER_TIME + 11).unwrap();
    assert!(matches!(b.rx(&ka, REKEY_AFTER_TIME + 11), Event::Confirmed(_)));
    assert_eq!(b.hot.previous().unwrap().local_index(), header_of_first_session_receiver(&b));
}

fn header_of_first_session_receiver(b: &Side) -> u32 {
    b.hot.previous().unwrap().local_index()
}

#[test]
fn only_the_initiator_rekeys_by_age() {
    let (mut a, mut b) = up();
    // B (responder of the first session) sends after two minutes: no handshake wanted by age alone
    let d = b.send(b"x", REKEY_AFTER_TIME + 1).unwrap();
    a.rx(&d, REKEY_AFTER_TIME + 1);
    assert!(!b.hot.wants_handshake());
    // ... but late in the session's life it does, as the C does (REJECT - KEEPALIVE - REKEY_TIMEOUT)
    let t = REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;
    b.send(b"y", t - 1).unwrap();
    assert!(!b.hot.wants_handshake());
    b.send(b"y", t).unwrap();
    assert!(b.hot.wants_handshake());
}

#[test]
fn initiator_rekeys_on_receiving_late_in_the_session() {
    let (mut a, mut b) = up();
    let t = REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;
    let d = b.send(b"x", t - 1).unwrap();
    // B is the responder here and sends; A (initiator) receiving late asks for a handshake
    a.rx(&d, t - 1);
    assert!(!a.hot.wants_handshake());
    let d = b.send(b"x", t).unwrap();
    a.rx(&d, t);
    assert!(a.hot.wants_handshake());
}

#[test]
fn rekey_after_messages() {
    let (mut a, _b) = up();
    a.hot.test_set_send_counter(REKEY_AFTER_MESSAGES - 1);
    a.send(b"x", 10).unwrap();
    assert!(!a.hot.wants_handshake());
    a.send(b"x", 10).unwrap();
    assert!(a.hot.wants_handshake());
}

#[test]
fn reject_after_messages_exhausts_the_session() {
    let (mut a, mut b) = up();
    a.hot.test_set_send_counter(REJECT_AFTER_MESSAGES - 1);
    let d = a.send(b"last", 10).unwrap();
    assert!(matches!(b.rx(&d, 10), Event::Payload(_)));
    assert_eq!(a.send(b"more", 10).unwrap_err(), TxError::Exhausted);
    assert!(!a.hot.has_session(), "the exhausted session is wiped");
    assert!(a.hot.wants_handshake());
    // a datagram claiming a counter at the limit is refused by the receiver before any crypto
    let mut ticket_session = Session::from_keys([1; 32], [2; 32], true, 1, 2, 0);
    ticket_session.set_send_counter(REJECT_AFTER_MESSAGES - 1);
    assert!(ticket_session.tx_reserve(0).is_ok());
    assert_eq!(ticket_session.tx_reserve(0).unwrap_err(), TxError::Exhausted);
    assert_eq!(b.hot.rx_begin(b.hot.current().unwrap().local_index(), REJECT_AFTER_MESSAGES, 10).unwrap_err(), Dropped::ReplayLimit);
}

#[test]
fn sessions_expire_at_reject_after_time() {
    let (mut a, mut b) = up();
    let d = a.send(b"x", REJECT_AFTER_TIME - 1).unwrap();
    // a datagram that arrives at exactly the limit is refused even before poll wipes the session
    assert_eq!(b.rx(&d, REJECT_AFTER_TIME), Event::Dropped(Dropped::SessionExpired));
    assert!(matches!(b.rx(&d, REJECT_AFTER_TIME - 1), Event::Payload(_)));
    assert_eq!(a.send(b"x", REJECT_AFTER_TIME).unwrap_err(), TxError::Expired);
    assert!(b.hot.poll(REJECT_AFTER_TIME).contains(Actions::KEYS_EXPIRED));
    assert!(b.hot.current().is_none() && b.hot.previous().is_none());
    assert_eq!(b.send(b"x", REJECT_AFTER_TIME + 1).unwrap_err(), TxError::NoSession);
    assert!(b.hot.next_wake(REJECT_AFTER_TIME).is_some());
}

#[test]
fn idle_slot_is_reclaimable_after_expiry() {
    let (mut a, mut b) = up();
    assert!(!a.hot.is_idle());
    let acts = a.hot.poll(REJECT_AFTER_TIME);
    assert!(acts.contains(Actions::KEYS_EXPIRED));
    // zero-key timer and arming leftovers: after the key-material deadline everything is gone
    let _ = b.hot.poll(REJECT_AFTER_TIME);
    a.hot.poll(ZERO_KEY_MATERIAL_AFTER + 1);
    assert!(a.hot.is_idle(), "{:?}", a.hot);
    assert_eq!(a.hot.next_wake(ZERO_KEY_MATERIAL_AFTER + 1), None);
}

#[test]
fn unanswered_handshake_retransmits_then_gives_up() {
    let (mut a, _b) = pair(None);
    a.hot.request_handshake(0);
    let mut sent = vec![];
    let mut gave_up = None;
    let mut t = 0u64;
    while t < 200 * S {
        let acts = a.hot.poll(t);
        if acts.contains(Actions::HANDSHAKE_GAVE_UP) {
            gave_up = Some(t);
            assert!(!acts.contains(Actions::SEND_INITIATION));
        } else if acts.contains(Actions::SEND_INITIATION) {
            a.initiate(t).unwrap();
            sent.push(t);
        }
        t += 10;
    }
    // first attempt immediately, then one every REKEY_TIMEOUT + jitter (< 334 ms)
    assert_eq!(sent[0], 0);
    for w in sent.windows(2) {
        let gap = w[1] - w[0];
        assert!((REKEY_TIMEOUT..REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX + 20).contains(&gap), "gap {gap}");
    }
    assert!((17..=MAX_HANDSHAKE_ATTEMPTS as usize).contains(&sent.len()), "{} attempts", sent.len());
    let g = gave_up.expect("gave up");
    assert!((REKEY_ATTEMPT_TIME..REKEY_ATTEMPT_TIME + REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX + 20).contains(&g), "gave up at {g}");
    assert_eq!(a.hot.handshake_state(), HsState::Idle, "the outstanding handshake is dropped");
    // nothing more happens until new traffic asks again, and then the series restarts (attempts reset)
    assert!(!a.hot.poll(g + 20 * S).contains(Actions::SEND_INITIATION));
    a.hot.request_handshake(g + 20 * S);
    assert!(a.hot.poll(g + 20 * S).contains(Actions::SEND_INITIATION));
    a.initiate(g + 20 * S).unwrap();
    assert_eq!(a.hot.handshake_attempts(), 1);
}

#[test]
fn response_stops_retransmission() {
    let (mut a, mut b) = pair(None);
    a.hot.request_handshake(0);
    assert!(a.hot.poll(0).contains(Actions::SEND_INITIATION));
    let init = a.initiate(0).unwrap();
    let Event::Reply(resp) = b.rx(&init, 100) else { panic!() };
    assert_eq!(a.rx(&resp, 200), Event::Established);
    assert!(!a.hot.poll(7 * S).contains(Actions::SEND_INITIATION));
    assert_eq!(a.hot.handshake_attempts(), 0);
    // the confirming keepalive is due right away
    assert!(a.hot.poll(200).contains(Actions::SEND_KEEPALIVE));
}

#[test]
fn request_handshake_is_idempotent_and_does_not_double_send() {
    let (mut a, _b) = pair(None);
    for _ in 0..100 {
        assert_eq!(a.send(b"x", 0).unwrap_err(), TxError::NoSession);
    }
    assert!(a.hot.poll(0).contains(Actions::SEND_INITIATION));
    a.initiate(0).unwrap();
    for t in 1..5 {
        a.send(b"x", t * S).unwrap_err();
        assert!(!a.hot.poll(t * S).contains(Actions::SEND_INITIATION), "t={t}");
    }
    assert_eq!(a.hot.handshake_attempts(), 1);
}

#[test]
fn request_handshake_now_lifts_the_spacing_for_an_idle_peer_only() {
    let (mut a, _b) = pair(None);
    a.initiate(1000).unwrap();
    // a retransmitting series keeps its spacing
    a.hot.request_handshake_now(1500);
    assert!(!a.hot.poll(1500).contains(Actions::SEND_INITIATION));
    // an idle peer (series over) does not
    let (mut a, mut b) = up();
    let init = a.initiate(10_000).unwrap();
    let Event::Reply(r) = b.rx(&init, 10_000) else { panic!() };
    a.rx(&r, 10_000);
    a.hot.request_handshake_now(10_500);
    assert!(a.hot.poll(10_500).contains(Actions::SEND_INITIATION));
}

#[test]
fn key_material_is_wiped_three_reject_times_after_the_last_session() {
    let (mut a, _b) = pair(None);
    a.initiate(0).unwrap(); // initiation outstanding, no session: no zero timer yet
    let g = first(&mut a, 0, 200 * S, 100, Actions::HANDSHAKE_GAVE_UP).unwrap();
    // giving up armed the wipe timer for residue
    assert!(a.hot.poll(g + ZERO_KEY_MATERIAL_AFTER - 1).is_empty() || !a.hot.poll(g + ZERO_KEY_MATERIAL_AFTER - 1).contains(Actions::KEYS_EXPIRED));
    assert!(a.hot.poll(g + ZERO_KEY_MATERIAL_AFTER).contains(Actions::KEYS_EXPIRED));
    assert!(a.hot.is_idle());
}

#[test]
fn next_wake_tracks_the_earliest_deadline() {
    let (mut a, mut b) = up();
    // sessions created at 0: expiry at 180 s is the only thing scheduled
    assert_eq!(a.hot.next_wake(1), Some(REJECT_AFTER_TIME.min(ZERO_KEY_MATERIAL_AFTER)));
    let d = a.send(b"x", 1000).unwrap();
    b.rx(&d, 1000);
    assert_eq!(b.hot.next_wake(1000), Some(1000 + KEEPALIVE_TIMEOUT));
    a.hot.set_persistent_keepalive(5, 1000);
    assert_eq!(a.hot.next_wake(1000), Some(6000));
}
