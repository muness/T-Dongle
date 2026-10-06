//! The bridge against stand-ins for its neighbours: a scripted USB transmit ring, a scripted Wi-Fi transmit, a clock the test moves. A port of
//! `components/tdongle_runtime/tests/test_l2.c` case by case (plus the threaded and randomized checks in `stress.rs`).
//!
//! Rules checked for every case, as in C:
//!  - the callbacks (the Wi-Fi RX callback and the TinyUSB receive callback) never wait, allocate or call the Wi-Fi driver: each stand-in asserts
//!    it is not entered while `in_callback` is set;
//!  - every frame that enters either callback is counted exactly once, as forwarded or as one named drop (identities after each case);
//!  - the driver's RX buffer is freed exactly once per call, by the caller of `wifi_rx` (the firmware glue): modelled by `W::wifi_in`.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
pub(crate) use std::prelude::v1::*;
use std::vec::Vec;

use crate::*;

pub(crate) fn ctx() -> TaskContext {
    TaskContext::for_tests()
}

mod cases;
mod codel;
mod stress;

pub(crate) const MAC: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(crate) const UNICAST: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
pub(crate) const BCAST: [u8; 6] = [0xff; 6];
pub(crate) const MCAST: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
pub(crate) const PEER: [u8; 6] = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

type Hook = Box<dyn FnMut(&'static Bridge<TestEnv>)>;

/// The scripted world. Single-threaded (`Cell`s): the threaded test uses its own atomic environment.
pub(crate) struct TestEnv {
    bridge: Cell<Option<&'static Bridge<TestEnv>>>,
    /// Inside the Wi-Fi RX callback or the TinyUSB receive callback: nothing here may wait or call the driver.
    pub(crate) in_callback: Cell<bool>,
    pub(crate) link_calls: Cell<u32>,
    pub(crate) flushes: Cell<u32>,
    pub(crate) notifies: Cell<u32>,
    pub(crate) note_activity_calls: Cell<u32>,
    pub(crate) ring_calls: Cell<u32>,
    pub(crate) tx_calls: Cell<u32>,
    pub(crate) waits: Cell<u32>,
    pub(crate) resumes: Cell<u32>,
    pub(crate) ring_result: Cell<RingSend>,
    pub(crate) ring_seen: RefCell<Vec<u8>>,
    pub(crate) tx_script: RefCell<VecDeque<Result<(), TxError>>>,
    pub(crate) tx_default: Cell<Result<(), TxError>>,
    pub(crate) tx_seen: RefCell<Vec<u8>>,
    pub(crate) ce_seen: RefCell<Vec<u8>>,
    pub(crate) now: Cell<u32>,
    pub(crate) room: Cell<bool>,
    pub(crate) registered: Cell<bool>,
    /// The order of `wifi_rx_register` (0/1), `usb_ring_flush` (2) and `usb_link_state` (3) in one `link()` call.
    pub(crate) order: RefCell<Vec<u8>>,
    pub(crate) wait_hook: RefCell<Option<Hook>>,
    pub(crate) ring_hook: RefCell<Option<Hook>>,
}

impl TestEnv {
    fn new() -> Self {
        Self {
            bridge: Cell::new(None),
            in_callback: Cell::new(false),
            link_calls: Cell::new(0),
            flushes: Cell::new(0),
            notifies: Cell::new(0),
            note_activity_calls: Cell::new(0),
            ring_calls: Cell::new(0),
            tx_calls: Cell::new(0),
            waits: Cell::new(0),
            resumes: Cell::new(0),
            ring_result: Cell::new(RingSend::Accepted),
            ring_seen: RefCell::new(Vec::new()),
            tx_script: RefCell::new(VecDeque::new()),
            tx_default: Cell::new(Ok(())),
            tx_seen: RefCell::new(Vec::new()),
            ce_seen: RefCell::new(Vec::new()),
            now: Cell::new(1_000_000),
            room: Cell::new(true),
            registered: Cell::new(false),
            order: RefCell::new(Vec::new()),
            wait_hook: RefCell::new(None),
            ring_hook: RefCell::new(None),
        }
    }
}

fn bump(cell: &Cell<u32>) {
    cell.set(cell.get() + 1);
}

impl Env for TestEnv {
    fn now_us(&self) -> u32 {
        self.now.get()
    }

    fn usb_ring_send(&self, frame: &[u8]) -> RingSend {
        bump(&self.ring_calls);
        let hook = self.ring_hook.borrow_mut().take();
        if let Some(mut hook) = hook {
            hook(self.bridge.get().unwrap()); // "something else happens while the callback copies"
        }
        let result = self.ring_result.get();
        if result == RingSend::Accepted {
            *self.ring_seen.borrow_mut() = frame.to_vec();
        }
        result
    }

    fn usb_ring_flush(&self) {
        bump(&self.flushes);
        self.order.borrow_mut().push(2);
    }

    fn usb_link_state(&self, _up: bool) {
        bump(&self.link_calls);
        self.order.borrow_mut().push(3);
    }

    fn wifi_rx_register(&self, on: bool) {
        self.registered.set(on);
        self.order.borrow_mut().push(u8::from(on));
    }

    fn notify_worker(&self) {
        bump(&self.notifies); // allowed in a callback: it never blocks
    }

    fn wifi_tx(&self, frame: &[u8], _context: &TaskContext) -> Result<(), TxError> {
        if frame.len() > 34 && frame[15] & 3 == 3 {
            *self.ce_seen.borrow_mut() = frame.to_vec();
        }
        assert!(!self.in_callback.get(), "the Wi-Fi driver is called by the worker only");
        let result = self.tx_script.borrow_mut().pop_front().unwrap_or_else(|| self.tx_default.get());
        bump(&self.tx_calls);
        if result.is_ok() {
            *self.tx_seen.borrow_mut() = frame.to_vec();
        }
        result
    }

    fn wifi_room(&self) -> bool {
        assert!(!self.in_callback.get());
        self.room.get()
    }

    fn wait_retry(&self, _context: &TaskContext) {
        assert!(!self.in_callback.get(), "a callback must never wait");
        bump(&self.waits);
        // The retry timer fires RETRY_US after it was armed: time passes, then the test may act.
        self.now.set(self.now.get().wrapping_add(RETRY_US));
        let hook = self.wait_hook.borrow_mut().take();
        if let Some(mut hook) = hook {
            hook(self.bridge.get().unwrap());
            *self.wait_hook.borrow_mut() = Some(hook);
        }
    }

    fn rx_resume(&self, _context: &TaskContext) {
        assert!(!self.in_callback.get());
        bump(&self.resumes);
    }

    fn note_activity(&self) {
        bump(&self.note_activity_calls);
    }

    fn worker_stack_free(&self) -> u32 {
        1234
    }
}

/// One started bridge with its two handles. Each case starts from a fresh world, as `start()` does in the C test.
pub(crate) struct W {
    pub(crate) b: &'static Bridge<TestEnv>,
    p: Producer<'static, TestEnv>,
    w: Worker<'static, TestEnv>,
}

impl W {
    pub(crate) fn new() -> Self {
        let b: &'static Bridge<TestEnv> = Box::leak(Box::new(Bridge::new(TestEnv::new(), MAC)));
        b.env().bridge.set(Some(b));
        Self { b, p: b.producer().unwrap(), w: b.worker().unwrap() }
    }

    pub(crate) fn env(&self) -> &TestEnv {
        self.b.env()
    }

    pub(crate) fn linked() -> Self {
        let w = Self::new();
        w.b.link(true, &TaskContext::for_tests());
        w
    }

    /// The driver calls the RX callback in the Wi-Fi task; the glue frees the driver buffer afterwards (once per call, by construction).
    pub(crate) fn wifi_in(&self, frame: &[u8]) {
        self.env().in_callback.set(true);
        let _ = self.b.wifi_rx(frame);
        self.env().in_callback.set(false);
    }

    /// The TinyUSB task offers a datagram.
    pub(crate) fn host_in(&mut self, frame: &[u8]) -> HostOutcome {
        self.env().in_callback.set(true);
        let outcome = self.p.host(frame);
        self.env().in_callback.set(false);
        outcome
    }

    /// One wake-up of the worker.
    pub(crate) fn pump(&mut self) -> u32 {
        self.w.drain()
    }

    pub(crate) fn drain_one(&mut self) -> bool {
        self.w.drain_one()
    }

    pub(crate) fn stats(&self) -> Stats {
        self.b.stats()
    }

    pub(crate) fn advance_us(&self, us: u32) {
        self.env().now.set(self.env().now.get().wrapping_add(us));
    }

    /// The identities the counters keep, at rest.
    pub(crate) fn check_identities(&self) {
        let s = self.stats();
        assert_eq!(s.check_identities(), Ok(()), "{s:#?}");
    }
}

/// A frame of `len` bytes: destination, source, then a byte pattern that depends on `tag` and the position.
pub(crate) fn frame(len: usize, dst: &[u8; 6], src: &[u8; 6], tag: u8) -> Vec<u8> {
    let mut f = vec![0u8; len];
    f[..6].copy_from_slice(dst);
    f[6..12].copy_from_slice(src);
    for (i, byte) in f.iter_mut().enumerate().skip(12) {
        *byte = tag.wrapping_add(i as u8);
    }
    f
}

impl Drop for W {
    fn drop(&mut self) {
        // The handles are dropped (releasing the single-producer/consumer flags); the leaked bridge is reclaimed with the process.
        self.b.env().bridge.set(None);
    }
}

#[test]
fn handles_are_single_instance() {
    let w = W::new();
    assert!(w.b.producer().is_none(), "a second producer must not exist");
    assert!(w.b.worker().is_none(), "a second worker must not exist");
    let b = w.b;
    drop(w);
    assert!(b.producer().is_some() && b.worker().is_some(), "a handle is released when dropped");
}
