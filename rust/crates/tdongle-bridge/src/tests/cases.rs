//! Every branch and counter of the forwarding logic, one case per C test function.

use core::sync::atomic::Ordering;

use super::*;

#[test]
fn to_host() {
    let w = W::new();
    // Before the link is up the callback is not registered; a frame that races the disconnect is counted.
    w.wifi_in(&frame(600, &UNICAST, &PEER, 1));
    assert_eq!(w.env().ring_calls.get(), 0);
    assert_eq!(w.stats().w2h_link_down, 1);
    w.b.link(true, &ctx());
    assert!(w.env().registered.get());
    assert_eq!((w.env().link_calls.get(), w.env().flushes.get()), (1, 1));
    // ARP, IPv4 (DHCP) and IPv6 bytes reach the ring exactly as received: no address rewriting.
    for k in 0..3u8 {
        let len = 100 + 400 * usize::from(k);
        let mut f = frame(len, if k == 0 { &BCAST } else { &UNICAST }, &PEER, 7 * k);
        f[12] = if k == 2 { 0x86 } else { 0x08 };
        f[13] = match k {
            0 => 0x06,
            1 => 0x00,
            _ => 0xdd,
        };
        w.wifi_in(&f);
        assert_eq!(*w.env().ring_seen.borrow(), f);
    }
    assert_eq!(w.stats().w2h_forwarded, 3);
    // Filters: our own MAC as the source (the host's frame echoed back), a runt, an oversize frame.
    let calls = w.env().ring_calls.get();
    w.wifi_in(&frame(600, &UNICAST, &MAC, 3));
    assert_eq!(w.env().ring_calls.get(), calls);
    assert_eq!(w.stats().w2h_own_mac, 1);
    let f = frame(1600, &UNICAST, &PEER, 4);
    w.wifi_in(&f[..13]);
    w.wifi_in(&f[..FRAME_MAX + 1]);
    w.wifi_in(&f[..0]);
    assert_eq!(w.stats().w2h_invalid, 3);
    w.wifi_in(&f[..FRAME_MAX]);
    assert_eq!(w.stats().w2h_forwarded, 4);
    assert_eq!(w.env().ring_seen.borrow().len(), FRAME_MAX);
    w.wifi_in(&f[..14]);
    assert_eq!(w.stats().w2h_forwarded, 5);
    // Ring refusals are told apart: full (backpressure) and not ready (cable out).
    let f = &f[..600];
    w.env().ring_result.set(RingSend::Full);
    w.wifi_in(f);
    w.env().ring_result.set(RingSend::NotReady);
    w.wifi_in(f);
    w.wifi_in(f);
    w.env().ring_result.set(RingSend::Invalid);
    w.wifi_in(f);
    w.env().ring_result.set(RingSend::Accepted);
    let s = w.stats();
    assert_eq!((s.w2h_ring_full, s.w2h_usb_not_ready, s.w2h_invalid, s.w2h_frames), (1, 2, 4, 14));
    w.check_identities();
    // The link goes down: the callback is unregistered, later frames are counted, and the ring is flushed.
    w.b.link(false, &ctx());
    assert!(!w.env().registered.get());
    assert_eq!(w.env().flushes.get(), 2);
    assert!(!w.stats().linked);
    w.wifi_in(f);
    assert_eq!(w.stats().w2h_link_down, 2);
    assert_eq!(w.env().notifies.get(), 0, "the receive path never wakes the worker");
    w.check_identities();
}

/// Which frames raise the clock: a unicast frame that is forwarded, in either direction; never chatter, never a frame that is dropped.
#[test]
fn pm_notes() {
    let mut w = W::linked();
    w.env().note_activity_calls.set(0);
    w.wifi_in(&frame(100, &UNICAST, &PEER, 1));
    assert_eq!(w.env().note_activity_calls.get(), 1);
    w.wifi_in(&frame(100, &BCAST, &PEER, 1));
    w.wifi_in(&frame(100, &MCAST, &PEER, 1));
    assert_eq!(w.env().note_activity_calls.get(), 1);
    assert_eq!(w.stats().w2h_forwarded, 3, "forwarded, but not a reason to hold 240 MHz");
    w.wifi_in(&frame(100, &UNICAST, &MAC, 1)); // filtered
    w.wifi_in(&[0u8; 5]); // invalid
    assert_eq!(w.env().note_activity_calls.get(), 1);
    let _ = w.host_in(&frame(100, &PEER, &MAC, 2));
    assert_eq!(w.env().note_activity_calls.get(), 2);
    assert_eq!(w.stats().h2w_queued, 1);
    let _ = w.host_in(&frame(100, &BCAST, &MAC, 2)); // DHCP discover, ARP request
    assert_eq!(w.env().note_activity_calls.get(), 2);
    assert_eq!(w.stats().h2w_queued, 2);
    let _ = w.host_in(&frame(100, &PEER, &PEER, 2)); // foreign source
    let _ = w.host_in(&[0u8; 10]); // runt
    assert_eq!(w.env().note_activity_calls.get(), 2);
    w.b.link(false, &ctx());
    let _ = w.host_in(&frame(100, &PEER, &MAC, 2)); // link down
    assert_eq!(w.env().note_activity_calls.get(), 2);
    w.pump();
    w.check_identities();
}

#[test]
fn pm_note_cost_is_recorded() {
    let w = W::linked();
    w.wifi_in(&frame(100, &UNICAST, &PEER, 1));
    let s = w.stats();
    assert_eq!((s.pm_notes, s.pm_note_us_sum, s.pm_note_us_max), (1, 0, 0), "the stand-in costs no time");
}

#[test]
fn to_wifi() {
    let mut w = W::new();
    assert_eq!(w.host_in(&frame(600, &PEER, &MAC, 1)), HostOutcome::LinkDown);
    assert_eq!(w.stats().h2w_link_down, 1, "Wi-Fi not up yet");
    w.b.link(true, &ctx());
    w.env().notifies.set(0);
    for k in 0..3u8 {
        // ARP, DHCP, IPv6: bytes untouched, source is the STA MAC.
        let len = 120 + 500 * usize::from(k);
        let f = frame(len, if k == 0 { &BCAST } else { &PEER }, &MAC, 9 * k);
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
        assert_eq!(w.env().notifies.get(), u32::from(k) + 1);
        assert_eq!(w.pump(), 1);
        assert_eq!(*w.env().tx_seen.borrow(), f);
    }
    assert_eq!((w.stats().h2w_sent, w.stats().h2w_queue_depth), (3, 0));
    // Filters.
    assert_eq!(w.host_in(&frame(600, &PEER, &PEER, 1)), HostOutcome::ForeignMac);
    assert_eq!(w.stats().h2w_foreign_mac, 1);
    let big = frame(FRAME_MAX + 1, &PEER, &MAC, 5);
    assert_eq!(w.host_in(&big[..13]), HostOutcome::Invalid);
    assert_eq!(w.host_in(&big), HostOutcome::Invalid);
    assert_eq!(w.stats().h2w_invalid, 2);
    let max = frame(FRAME_MAX, &PEER, &MAC, 5);
    assert_eq!(w.host_in(&max), HostOutcome::Queued);
    assert_eq!(w.pump(), 1);
    assert_eq!(*w.env().tx_seen.borrow(), max);
    assert_eq!(w.env().tx_calls.get(), 4, "nothing filtered reached the driver");
    // A full queue holds the offer (USB backpressure), drops nothing, keeps the old ones in order, and never blocks.
    let mut f = frame(200, &PEER, &MAC, 0);
    for i in 0..HOST_QUEUE_LIMIT {
        f[20] = i as u8;
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    let s = w.stats();
    assert_eq!((s.h2w_queue_depth, s.h2w_queue_high_water), (HOST_QUEUE_LIMIT, HOST_QUEUE_LIMIT), "the limit, not the slot count");
    f[20] = 99;
    assert!(w.host_in(&f).is_hold() && w.host_in(&f).is_hold());
    assert_eq!(w.stats().h2w_held, 2);
    let sent_before = w.stats().h2w_sent;
    for i in 0..HOST_QUEUE_LIMIT {
        // one frame at a time: it is the oldest, tx_seen proves the order
        assert!(w.drain_one());
        assert_eq!(w.env().tx_seen.borrow()[20], i as u8);
    }
    assert_eq!(w.stats().h2w_sent, sent_before + HOST_QUEUE_LIMIT);
    assert_eq!(w.stats().h2w_queue_depth, 0);
    w.check_identities();
    assert_eq!(w.env().tx_calls.get(), 4 + HOST_QUEUE_LIMIT);
}

/// USB backpressure: hold at the limit, resume exactly once when the worker drains to the resume depth, no wedge on any interleaving.
#[test]
fn backpressure() {
    let mut w = W::linked();
    let f = frame(200, &PEER, &MAC, 1);
    for _ in 0..HOST_QUEUE_LIMIT {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    assert!(w.host_in(&f).is_hold());
    assert_eq!((w.stats().h2w_held, w.stats().h2w_frames), (1, HOST_QUEUE_LIMIT));
    assert!(w.b.held.load(Ordering::SeqCst));
    assert!(w.host_in(&f).is_hold());
    assert_eq!((w.stats().h2w_held, w.env().resumes.get()), (2, 0), "nothing drained: nothing to resume");
    w.check_identities();
    // The worker drains: resume is asked for when the depth reaches RESUME_DEPTH, once, not at every frame.
    assert_eq!(w.pump(), HOST_QUEUE_LIMIT);
    assert_eq!(w.env().resumes.get(), 1);
    assert!(!w.b.held.load(Ordering::SeqCst));
    assert_eq!(w.stats().h2w_resumes, 1);
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    assert_eq!(w.pump(), 1);
    assert_eq!(w.env().resumes.get(), 1, "re-offered datagram accepted; no flag, no resume");
    w.check_identities();
    // Interleaving A: the worker drains between the callback's full check and its re-check. The callback must not strand the datagram: it sees
    // the room (and takes it) or the worker's resume covers it.
    for _ in 0..HOST_QUEUE_LIMIT {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    // simulate: the callback has set held and the worker finished everything before the callback re-reads the tail
    w.b.held.store(true, Ordering::SeqCst);
    w.pump(); // the worker sees the flag and resumes
    assert_eq!(w.env().resumes.get(), 2);
    assert!(!w.b.held.load(Ordering::SeqCst));
    assert_eq!(w.host_in(&f), HostOutcome::Queued, "the re-offer is accepted");
    w.pump();
    // Interleaving B: held is set, the worker has already taken it (resume owed), and the callback's re-check finds room: it must still say HOLD
    // (the owed resume re-offers this datagram) rather than take the room twice.
    for _ in 0..HOST_QUEUE_LIMIT {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    w.b.held.store(true, Ordering::SeqCst); // ... the callback, after storing the flag
    let _ = w.drain_one(); // the worker consumed one frame meanwhile (depth 2: no resume yet: above the resume depth)
    assert_eq!(w.host_in(&f), HostOutcome::Queued, "room: a normal enqueue (limit 3, depth 2). held was left set by the earlier store");
    w.pump();
    assert!(
        w.env().resumes.get() >= 3 && !w.b.held.load(Ordering::SeqCst),
        "the stale flag is released by the next drain: an extra resume, never a missed one"
    );
    // A link change releases a held datagram (the backlog is stale).
    let mut w = W::linked();
    for _ in 0..HOST_QUEUE_LIMIT {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    assert!(w.host_in(&f).is_hold() && w.b.held.load(Ordering::SeqCst));
    w.b.link(false, &ctx());
    assert!(w.env().resumes.get() == 1 && !w.b.held.load(Ordering::SeqCst));
    w.pump();
    w.check_identities();
    // A wedged Wi-Fi link: frames wait for the radio's allowance, the host stays held, and the sojourn limit frees the queue; the held datagram
    // resumes.
    let mut w = W::linked();
    w.env().room.set(false);
    for _ in 0..HOST_QUEUE_LIMIT {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    assert!(w.host_in(&f).is_hold());
    assert_eq!(w.pump(), HOST_QUEUE_LIMIT);
    let s = w.stats();
    assert_eq!(w.env().tx_calls.get(), 0, "the driver was never called while the allowance was full");
    assert_eq!(
        (s.h2w_tx_failed, s.h2w_sojourn_drop, w.env().resumes.get()),
        (1, HOST_QUEUE_LIMIT - 1, 1),
        "the first frame used its window, the rest had aged out behind it"
    );
    w.env().room.set(true);
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    assert_eq!(w.pump(), 1);
    assert_eq!(w.stats().h2w_sent, 1);
    w.check_identities();
}

/// The slot counters run free: the queue keeps working across the wrap of the 32-bit counters.
#[test]
fn counter_wrap() {
    let mut w = W::linked();
    w.b.queue().__set_counters(0xffff_fffc);
    for round in 0..10u8 {
        for i in 0..3u8 {
            assert_eq!(w.host_in(&frame(100, &PEER, &MAC, round * 3 + i)), HostOutcome::Queued);
        }
        for i in 0..3u8 {
            assert!(w.drain_one());
            assert_eq!(w.env().tx_seen.borrow()[20], (round * 3 + i).wrapping_add(20));
        }
    }
    assert_eq!(w.b.queue().head(Ordering::SeqCst), 0xffff_fffcu32.wrapping_add(30));
    let s = w.stats();
    assert_eq!((s.h2w_sent, s.h2w_queue_depth), (30, 0));
    w.check_identities();
}

/// A link change makes what was queued stale, in both directions; a frame is never sent into the wrong association.
#[test]
fn link_flap() {
    let mut w = W::linked();
    let f = frame(200, &PEER, &MAC, 1);
    for _ in 0..3 {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    w.b.link(false, &ctx()); // the association ended with three frames queued
    assert_eq!(w.pump(), 3);
    assert_eq!((w.env().tx_calls.get(), w.stats().h2w_link_down_queued), (0, 3));
    for _ in 0..4 {
        assert_eq!(w.host_in(&f), HostOutcome::LinkDown, "link down: refused, counted");
    }
    assert_eq!(w.stats().h2w_link_down, 4);
    w.b.link(true, &ctx());
    for _ in 0..3 {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    w.b.link(false, &ctx()); // a quick flap: down and up again before the worker ran
    w.b.link(true, &ctx());
    assert_eq!(w.pump(), 3);
    assert_eq!((w.env().tx_calls.get(), w.stats().h2w_stale), (0, 3), "queued under the first association of this link: stale");
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    assert_eq!(w.pump(), 1);
    assert_eq!(w.env().tx_calls.get(), 1, "the new association works");
    w.check_identities();
    // link() orders its steps: stop (or start) the callback, flush the ring, then tell the host.
    w.env().order.borrow_mut().clear();
    w.b.link(false, &ctx());
    assert_eq!(*w.env().order.borrow(), [0, 2, 3]);
    w.env().order.borrow_mut().clear();
    w.b.link(true, &ctx());
    assert_eq!(*w.env().order.borrow(), [2, 1, 3], "connect: flush the old association's frames, then open the callback");
    assert_eq!(w.stats().link_changes, 7);
}

/// A refused transmit is retried on the retry timer (not the RTOS tick) until the frame's sojourn limit, never forever, only when retrying can
/// help.
#[test]
fn retry() {
    let f = frame(200, &PEER, &MAC, 1);
    let limit_us = SOJOURN_MS * 1000;
    // Refused twice, then taken: two 500 us waits, not two 10 ms ticks.
    let mut w = W::linked();
    w.env().tx_script.borrow_mut().extend([Err(TxError::NoMem), Err(TxError::NoMem)]);
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    let t0 = w.env().now.get();
    assert_eq!(w.pump(), 1);
    let s = w.stats();
    assert_eq!((s.h2w_sent, s.h2w_tx_retries, w.env().waits.get()), (1, 2, 2));
    assert_eq!(w.env().now.get() - t0, 2 * RETRY_US);
    assert_eq!(s.h2w_last_tx_error, TxError::ESP_ERR_NO_MEM);
    // Always refused: it stops at the sojourn limit measured from the callback, counts one failure, and the frame behind it gets its own window.
    let mut w = W::linked();
    w.env().tx_default.set(Err(TxError::NoMem));
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    w.advance_us(5000); // it already waited 5 ms in the queue: only 15 ms of retries remain
    assert_eq!(w.pump(), 1);
    let s = w.stats();
    assert_eq!((s.h2w_tx_failed, s.h2w_tx_retries), (1, (limit_us - 5000) / RETRY_US));
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    assert_eq!(w.pump(), 1);
    let s = w.stats();
    assert_eq!((s.h2w_tx_failed, s.h2w_tx_retries), (2, (limit_us - 5000) / RETRY_US + limit_us / RETRY_US));
    // A final error is not retried.
    let mut w = W::linked();
    w.env().tx_default.set(Err(TxError::Other(-1))); // ESP_FAIL
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    assert_eq!(w.pump(), 1);
    let s = w.stats();
    assert_eq!((w.env().tx_calls.get(), w.env().waits.get(), s.h2w_tx_failed, s.h2w_last_tx_error), (1, 0, 1, -1));
    // The link drops while the worker waits: the frame is abandoned at once.
    let mut w = W::linked();
    w.env().tx_default.set(Err(TxError::NoMem));
    *w.env().wait_hook.borrow_mut() = Some(Box::new(|b: &'static Bridge<TestEnv>| b.link(false, &ctx())));
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    assert_eq!(w.pump(), 1);
    assert_eq!((w.env().tx_calls.get(), w.stats().h2w_tx_failed), (2, 1));
    w.check_identities();
}

/// The standing queue is bounded in time too: a frame older than the sojourn limit when the worker reaches it is dropped unsent.
#[test]
fn sojourn() {
    let mut w = W::linked();
    let f = frame(200, &PEER, &MAC, 1);
    for _ in 0..3 {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    w.advance_us(SOJOURN_MS * 1000 - 1); // just inside the limit: sent
    assert_eq!(w.pump(), 3);
    let s = w.stats();
    assert_eq!((s.h2w_sent, s.h2w_sojourn_drop), (3, 0));
    assert_eq!((s.h2w_wait_us_max, s.h2w_wait_us_sum), (SOJOURN_MS * 1000 - 1, 3 * (SOJOURN_MS * 1000 - 1)));
    for _ in 0..3 {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    w.advance_us(SOJOURN_MS * 1000); // at the limit: dropped, counted, never sent
    w.env().tx_calls.set(0);
    assert_eq!(w.pump(), 3);
    assert_eq!((w.env().tx_calls.get(), w.stats().h2w_sojourn_drop), (0, 3));
    w.check_identities();
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    assert_eq!(w.pump(), 1);
    assert_eq!(w.stats().h2w_sent, 4, "the queue recovers at once");
    assert_eq!(w.stats().h2w_tx_us_max, 0, "the stub's call takes no time");
    w.check_identities();
}

/// `stats` reads tail before head: a worker that finishes frames between the loads cannot make the depth negative.
#[test]
fn depth_never_wraps() {
    let w = W::linked();
    let mut w = w;
    w.b.queue().__set_counters(7);
    assert_eq!(w.stats().h2w_queue_depth, 0);
    for _ in 0..2 {
        assert_eq!(w.host_in(&frame(100, &PEER, &MAC, 1)), HostOutcome::Queued);
    }
    assert_eq!(w.stats().h2w_queue_depth, 2);
}

/// A frame in the RX callback while the association ends passes the link check, is stamped with the NEW generation by the ring, and would
/// outlive the change: the callback notices the epoch moved and flushes again.
#[test]
fn rx_race() {
    let w = W::linked();
    let f = frame(200, &UNICAST, &PEER, 1);
    let flushes_before = w.env().flushes.get();
    *w.env().ring_hook.borrow_mut() = Some(Box::new(|b: &'static Bridge<TestEnv>| b.link(false, &ctx()))); // the event task runs inside the ring send
    w.wifi_in(&f);
    let s = w.stats();
    assert_eq!((s.w2h_raced, s.w2h_forwarded), (1, 1));
    assert_eq!(w.env().flushes.get(), flushes_before + 2, "the change's own flush, and the callback's");
    w.wifi_in(&f); // link is down now: counted, no race
    let s = w.stats();
    assert_eq!((s.w2h_raced, s.w2h_link_down), (1, 1));
    w.check_identities();
}

/// Tuning: bounds are checked as a whole, a rejected set changes nothing, a set takes effect at once.
#[test]
fn tuning() {
    let mut w = W::new();
    let t = w.b.tuning();
    assert_eq!(t, Tuning::DEFAULT);
    assert_eq!(
        (t.queue_limit, t.resume_depth, t.sojourn_ms, t.codel, t.codel_target_us, t.codel_interval_ms),
        (HOST_QUEUE_LIMIT, HOST_RESUME_DEPTH, SOJOURN_MS, true, 5000, 100)
    );
    let bad = |edit: fn(&mut Tuning)| {
        let mut b = t;
        edit(&mut b);
        b
    };
    for rejected in [
        bad(|b| b.queue_limit = 0),
        bad(|b| b.queue_limit = HOST_SLOTS as u32 + 1),
        bad(|b| b.resume_depth = b.queue_limit),
        bad(|b| b.sojourn_ms = SOJOURN_MS_MIN - 1),
        bad(|b| b.sojourn_ms = SOJOURN_MS_MAX + 1),
        bad(|b| b.codel_target_us = CODEL_TARGET_US_MIN - 1),
        bad(|b| b.codel_target_us = CODEL_TARGET_US_MAX + 1),
        bad(|b| b.codel_interval_ms = CODEL_INTERVAL_MS_MIN - 1),
        bad(|b| b.codel_interval_ms = CODEL_INTERVAL_MS_MAX + 1),
        bad(|b| {
            b.queue_limit = 5;
            b.sojourn_ms = 0; // one bad field: nothing applied
        }),
    ] {
        assert_eq!(w.b.set_tuning(&rejected), Err(InvalidTuning), "{rejected:?}");
    }
    assert_eq!(w.b.tuning(), t);
    let t = Tuning { queue_limit: 5, resume_depth: 2, sojourn_ms: 40, ..t };
    assert_eq!(w.b.set_tuning(&t), Ok(()));
    assert_eq!(w.b.tuning(), t);
    let f = frame(200, &PEER, &MAC, 1);
    w.b.link(true, &ctx());
    for _ in 0..5 {
        assert_eq!(w.host_in(&f), HostOutcome::Queued);
    }
    assert!(w.host_in(&f).is_hold(), "the new limit");
    assert_eq!(w.pump(), 5);
    assert_eq!(w.env().resumes.get(), 1, "resumed at depth 2 (once)");
    w.advance_us(40_000);
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    w.advance_us(40_000);
    w.env().tx_calls.set(0);
    assert_eq!(w.pump(), 1);
    assert_eq!((w.env().tx_calls.get(), w.stats().h2w_sojourn_drop), (0, 1), "the new sojourn limit: 40 ms");
    w.check_identities();
}

/// The radio's dwell: a frame that waited for room is counted, with how long.
#[test]
fn room_wait_stats() {
    let mut w = W::linked();
    let f = frame(200, &PEER, &MAC, 1);
    w.env().room.set(false);
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    let mut calls = 0u32;
    *w.env().wait_hook.borrow_mut() = Some(Box::new(move |b: &'static Bridge<TestEnv>| {
        calls += 1;
        if calls == 3 {
            b.env().room.set(true);
        }
    }));
    assert_eq!(w.pump(), 1);
    let s = w.stats();
    assert_eq!((s.h2w_room_waits, s.h2w_room_wait_us_max, s.h2w_room_wait_us_sum, s.h2w_sent), (1, 3 * RETRY_US, 3 * RETRY_US, 1));
    w.check_identities();
}

/// The clock wraps every 71 minutes: nothing in the bridge may misbehave when the microsecond counter passes zero mid-flow.
#[test]
fn clock_wrap() {
    let mut w = W::linked();
    w.env().now.set(u32::MAX - 1000);
    let f = frame(200, &PEER, &MAC, 1);
    assert_eq!(w.host_in(&f), HostOutcome::Queued);
    w.advance_us(2000); // the clock is now 999 (wrapped)
    assert_eq!(w.pump(), 1);
    let s = w.stats();
    assert_eq!((s.h2w_sent, s.h2w_sojourn_drop, s.h2w_wait_us_max), (1, 0, 2000));
}
