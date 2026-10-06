//! The lock-free packet path: `tx_prepare` / `TxTicket::seal` and `rx_begin` / `RxTicket::open` / `rx_commit` used the way the runtime uses them (the
//! expensive step in the middle running on a copy of the key while other work changes the slot), plus the C `test_wg_egress` cases that apply.

mod common;
use common::*;
use tdongle_tailnet_wg::msg::{TransportHeader, transport_len};
use tdongle_tailnet_wg::*;

fn up() -> (Side, Side) {
    let (mut a, mut b) = pair(None);
    handshake_confirmed(&mut a, &mut b, 0);
    (a, b)
}

#[test]
fn split_send_equals_the_one_call_path_byte_for_byte() {
    // two identical sessions: one sealed through tx_prepare + seal, the other through encrypt; the datagrams are identical (deterministic AEAD)
    let (mut a1, _) = up();
    let (mut a2, _) = up();
    for n in 0..=100usize {
        let payload: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
        let one = a1.send(&payload, 100).unwrap();
        let t = a2.hot.tx_prepare(100, if n == 0 { TxKind::Keepalive } else { TxKind::Data }).unwrap();
        let mut buf = vec![0xaau8; transport_len(n)];
        buf[16..16 + n].copy_from_slice(&payload);
        let len = t.seal(&mut buf, n).unwrap();
        assert_eq!(&buf[..len], &one[..], "n={n}");
        assert_eq!(t.counter(), n as u64 + 1, "counter advances by one per datagram (1 is the first: counter 0 was the confirming keepalive)");
    }
}

#[test]
fn tickets_sealed_out_of_order_and_in_parallel_all_arrive_once() {
    let (mut a, mut b) = up();
    let mut tickets: Vec<_> = (0..20).map(|_| a.hot.tx_prepare(10, TxKind::Data).unwrap()).collect();
    let ctrs: Vec<u64> = tickets.iter().map(|t| t.counter()).collect();
    let mut sorted = ctrs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 20, "no counter handed out twice");
    tickets.reverse(); // sealed in the opposite order (another task finished first)
    let mut datagrams = vec![];
    for (i, t) in tickets.iter().enumerate() {
        let mut buf = vec![0u8; 64];
        buf[16..24].copy_from_slice(&(t.counter()).to_le_bytes());
        let _ = i;
        let n = t.seal(&mut buf, 8).unwrap();
        buf.truncate(n);
        datagrams.push(buf);
    }
    for d in &datagrams {
        let Event::Payload(p) = b.rx(d, 10) else { panic!() };
        assert_eq!(u64::from_le_bytes(p[..8].try_into().unwrap()), header(d).counter);
    }
    for d in &datagrams {
        assert_eq!(b.rx(d, 10), Event::Dropped(Dropped::ReplayDuplicate));
    }
}

#[test]
fn a_dropped_ticket_burns_a_counter_but_never_reuses_one() {
    let (mut a, mut b) = up();
    drop(a.hot.tx_prepare(10, TxKind::Data).unwrap()); // never sealed
    let d = a.send(b"x", 10).unwrap();
    assert_eq!(header(&d).counter, 2);
    assert!(matches!(b.rx(&d, 10), Event::Payload(_)), "gaps are legal");
}

#[test]
fn receive_begin_open_commit_with_other_work_in_between() {
    let (mut a, mut b) = up();
    let d1 = a.send(b"one", 10).unwrap();
    let d2 = a.send(b"two", 10).unwrap();
    let h1 = TransportHeader::parse(&d1).unwrap();
    let h2 = TransportHeader::parse(&d2).unwrap();
    // begin both (the "lock" is released between steps)
    let t1 = b.hot.rx_begin(h1.receiver, h1.counter, 10).unwrap();
    let t2 = b.hot.rx_begin(h2.receiver, h2.counter, 10).unwrap();
    // begin did not record anything
    assert!(b.hot.rx_begin(h1.receiver, h1.counter, 10).is_ok());
    let (mut p1, mut p2) = (d1.clone(), d2.clone());
    let n2 = t2.open(&mut p2).unwrap(); // finished in the opposite order
    let n1 = t1.open(&mut p1).unwrap();
    assert_eq!(&p2[16..19], b"two");
    assert_eq!(&p1[16..19], b"one");
    let o2 = b.hot.rx_commit(&t2, n2, 11).unwrap();
    let o1 = b.hot.rx_commit(&t1, n1, 11).unwrap();
    assert!(!o1.keepalive && !o2.keepalive && o1.plain_len == 16);
    // after commit begin refuses
    assert_eq!(b.hot.rx_begin(h1.receiver, h1.counter, 11).unwrap_err(), Dropped::ReplayDuplicate);
}

#[test]
fn two_workers_racing_on_the_same_datagram_deliver_it_once() {
    let (mut a, mut b) = up();
    let d = a.send(b"once", 10).unwrap();
    let h = TransportHeader::parse(&d).unwrap();
    let t1 = b.hot.rx_begin(h.receiver, h.counter, 10).unwrap();
    let t2 = b.hot.rx_begin(h.receiver, h.counter, 10).unwrap(); // both passed the cheap pre-check
    let (mut p1, mut p2) = (d.clone(), d.clone());
    let n1 = t1.open(&mut p1).unwrap();
    let n2 = t2.open(&mut p2).unwrap();
    assert!(b.hot.rx_commit(&t1, n1, 11).is_ok());
    assert_eq!(b.hot.rx_commit(&t2, n2, 11).unwrap_err(), Dropped::ReplayDuplicate);
}

#[test]
fn forged_datagram_changes_nothing() {
    let (mut a, mut b) = up();
    let d = a.send(b"genuine", 10).unwrap();
    let h = TransportHeader::parse(&d).unwrap();
    let mut forged = d.clone();
    forged[20] ^= 1;
    let t = b.hot.rx_begin(h.receiver, h.counter, 10).unwrap();
    assert!(t.open(&mut forged).is_err());
    // the forger could not burn the counter: the genuine datagram is accepted afterwards
    assert!(matches!(b.rx(&d, 10), Event::Payload(_)));
}

#[test]
fn session_rolled_between_begin_and_commit_still_commits_on_the_previous_slot() {
    let (mut a, mut b) = up();
    let d = a.send(b"old session", 100).unwrap();
    let h = TransportHeader::parse(&d).unwrap();
    let t = b.hot.rx_begin(h.receiver, h.counter, 100).unwrap();
    let mut p = d.clone();
    let n = t.open(&mut p).unwrap();
    // meanwhile a rekey completes: B's current becomes previous
    let init = a.initiate(10_000).unwrap();
    let Event::Reply(resp) = b.rx(&init, 10_000) else { panic!() };
    a.rx(&resp, 10_000);
    let ka = a.keepalive(10_001).unwrap();
    assert!(matches!(b.rx(&ka, 10_001), Event::Confirmed(_)));
    assert_eq!(b.hot.previous().unwrap().local_index(), t.local_index());
    assert!(b.hot.rx_commit(&t, n, 10_002).is_ok());
}

#[test]
fn session_wiped_between_begin_and_commit_is_a_counted_drop() {
    let (mut a, mut b) = up();
    let d = a.send(b"x", 100).unwrap();
    let h = TransportHeader::parse(&d).unwrap();
    let t = b.hot.rx_begin(h.receiver, h.counter, 100).unwrap();
    let mut p = d.clone();
    let n = t.open(&mut p).unwrap();
    assert!(b.hot.poll(200_000).contains(Actions::KEYS_EXPIRED));
    assert_eq!(b.hot.rx_commit(&t, n, 200_000).unwrap_err(), Dropped::NoSession);
}

#[test]
fn first_datagram_on_a_responder_session_promotes_it_even_through_the_split_path() {
    let (mut a, mut b) = pair(None);
    handshake(&mut a, &mut b, 0);
    let d = a.send(b"first", 1).unwrap();
    let h = TransportHeader::parse(&d).unwrap();
    // before the first datagram the responder's session is only reachable through `next`, by its index
    let t = b.hot.rx_begin(h.receiver, h.counter, 1).unwrap();
    assert!(b.hot.current().is_none());
    let mut p = d.clone();
    let n = t.open(&mut p).unwrap();
    let o = b.hot.rx_commit(&t, n, 1).unwrap();
    assert!(o.confirmed);
    assert!(b.hot.current().is_some() && b.hot.next().is_none() && b.hot.previous().is_none());
    // and now B can send
    assert!(b.send(b"reply", 2).is_ok());
}

#[test]
fn seal_into_exact_and_short_buffers() {
    let (mut a, _) = up();
    for n in 0..64usize {
        let t = a.hot.tx_prepare(5, TxKind::Data).unwrap();
        let need = transport_len(n);
        assert_eq!(t.seal(&mut vec![0u8; need - 1], n), Err(SealError::BufferTooSmall), "n={n}");
        assert_eq!(t.seal(&mut vec![0u8; need], n), Ok(need));
    }
}

#[test]
fn no_session_and_expired_tx_are_distinct_outcomes_and_arm_a_handshake() {
    let (mut a, _b) = pair(None);
    assert_eq!(a.hot.tx_prepare(0, TxKind::Data).unwrap_err(), TxError::NoSession);
    assert!(a.hot.wants_handshake());
    let (mut a, mut b) = up();
    assert_eq!(a.hot.tx_prepare(180_000, TxKind::Data).unwrap_err(), TxError::Expired);
    assert!(a.hot.wants_handshake() && !a.hot.has_session());
    let _ = b.hot.poll(0);
}

#[test]
fn sessions_are_independent_of_the_slot_they_live_in() {
    // Session + tickets used alone (no PeerHot), as the pool's runtime may do for a hot path it keeps outside the slot
    let mut tx = Session::from_keys([9; 32], [8; 32], true, 1, 2, 0);
    let rx = Session::from_keys([8; 32], [9; 32], false, 2, 1, 0);
    let mut rx = rx;
    let t = tx.tx_reserve(0).unwrap();
    let mut buf = [0u8; 64];
    let len = t.seal(&mut buf, 20).unwrap();
    let h = TransportHeader::parse(&buf[..len]).unwrap();
    let r = rx.rx_peek(h.counter, 0).unwrap();
    let n = r.open(&mut buf[..len]).unwrap();
    assert_eq!(n, 32);
    rx.rx_commit(h.counter).unwrap();
    assert_eq!(rx.rx_commit(h.counter), Err(Dropped::ReplayDuplicate));
}
