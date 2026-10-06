//! The hold/resume handshake (ADR 0023 amendment 2), checked exhaustively under sequential consistency.
//!
//! loom cannot check this protocol (it models `SeqCst` as acquire/release; see `loom_hold_resume.rs`), so this test enumerates EVERY interleaving of
//! the protocol's atomic steps, with each step one sequentially consistent operation exactly as `Producer::admit` and `Worker::drain_one` perform them
//! (`SeqCst` loads and stores of `held` and `tail`, a `SeqCst` swap), and asserts that no interleaving ends with the producer waiting for a resume
//! that nobody will send while the worker is idle: the lost wake-up. The model is a transcription of the two functions; the mutation tests at the
//! bottom delete one step of the protocol at a time and require the checker to find the lost wake-up, so a transcription that checks nothing fails.

use std::collections::HashSet;

const LIMIT: u32 = 2;
const RESUME: u32 = 1;
const FRAMES: u32 = 3;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct State {
    head: u32,
    tail: u32,
    held: bool,
    /// The class driver's pending "offer the held datagram again" (set by the worker's resume, consumed by the retrying producer).
    resumed: bool,
    offered: u32,
    work: u32,
    sent: u32,
    p: P,
    w: W,
    pt: u32,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum P {
    Look,
    StoreHeld,
    LoadTail,
    SwapHeld,
    WaitResume,
    Done,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum W {
    Idle,
    Release,
    CheckDepth,
    SwapHeld,
}

#[derive(Clone, Copy)]
struct Protocol {
    /// Mutations: delete a step of the protocol.
    skip_recheck: bool,
    skip_swap_in_worker: bool,
}

fn steps(s: State, proto: Protocol) -> Vec<State> {
    let mut out = Vec::new();
    // Producer
    match s.p {
        P::Look => {
            let mut n = s;
            n.pt = s.tail; // SeqCst load of tail
            if s.head.wrapping_sub(n.pt) < LIMIT {
                n.head += 1;
                n.work += 1;
                n.offered += 1;
                n.p = if n.offered == FRAMES { P::Done } else { P::Look };
            } else {
                n.p = P::StoreHeld;
            }
            out.push(n);
        }
        P::StoreHeld => {
            let mut n = s;
            n.held = true;
            n.p = if proto.skip_recheck { P::WaitResume } else { P::LoadTail };
            out.push(n);
        }
        P::LoadTail => {
            let mut n = s;
            n.pt = s.tail;
            n.p = if s.head.wrapping_sub(n.pt) >= LIMIT { P::WaitResume } else { P::SwapHeld };
            out.push(n);
        }
        P::SwapHeld => {
            let mut n = s;
            if s.held {
                n.held = false;
                n.head += 1;
                n.work += 1;
                n.offered += 1;
                n.p = if n.offered == FRAMES { P::Done } else { P::Look };
            } else {
                n.p = P::WaitResume; // the worker took the flag and owes a resume that re-offers this datagram
            }
            out.push(n);
        }
        P::WaitResume => {
            if s.resumed {
                let mut n = s;
                n.resumed = false;
                n.p = P::Look;
                out.push(n);
            }
        }
        P::Done => {}
    }
    // Worker
    match s.w {
        W::Idle => {
            if s.head != s.tail {
                let mut n = s;
                n.work = 0;
                n.w = W::Release;
                out.push(n);
            } else if s.work > 0 {
                let mut n = s;
                n.work = 0;
                out.push(n);
            }
        }
        W::Release => {
            let mut n = s;
            n.tail += 1;
            n.sent += 1;
            n.w = W::CheckDepth;
            out.push(n);
        }
        W::CheckDepth => {
            let mut n = s;
            n.w = if s.head - s.tail <= RESUME { W::SwapHeld } else { W::Idle };
            out.push(n);
        }
        W::SwapHeld => {
            let mut n = s;
            if !proto.skip_swap_in_worker && s.held {
                n.held = false;
                n.resumed = true;
            }
            n.w = W::Idle;
            out.push(n);
        }
    }
    out
}

/// Explore every interleaving; return the first stuck state (nothing can move but the work is not finished), if any.
fn find_wedge(proto: Protocol) -> Option<State> {
    let start = State { head: 0, tail: 0, held: false, resumed: false, offered: 0, work: 0, sent: 0, p: P::Look, w: W::Idle, pt: 0 };
    let mut seen = HashSet::new();
    let mut stack = vec![start];
    while let Some(s) = stack.pop() {
        if !seen.insert(s) {
            continue;
        }
        let next = steps(s, proto);
        if next.is_empty() {
            // Nothing can move: the run is over only if every frame was offered and sent.
            if !(s.p == P::Done && s.sent == FRAMES && s.head == s.tail) {
                return Some(s);
            }
        }
        stack.extend(next);
    }
    None
}

#[test]
fn no_interleaving_loses_the_resume() {
    let proto = Protocol { skip_recheck: false, skip_swap_in_worker: false };
    assert_eq!(find_wedge(proto), None);
}

#[test]
fn deleting_the_recheck_is_caught() {
    let wedge = find_wedge(Protocol { skip_recheck: true, skip_swap_in_worker: false });
    assert!(wedge.is_some(), "the checker did not notice a missing re-check of the queue after publishing `held`");
}

#[test]
fn deleting_the_workers_swap_is_caught() {
    let wedge = find_wedge(Protocol { skip_recheck: false, skip_swap_in_worker: true });
    assert!(wedge.is_some(), "the checker did not notice a worker that never resumes");
}
