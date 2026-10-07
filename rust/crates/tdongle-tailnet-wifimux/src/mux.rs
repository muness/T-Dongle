//! [`WifiMux`], its stack-facing half [`StackDriver`] and the runtime-facing half [`RawPort`].

use core::cell::RefCell;
use core::future::{Future, poll_fn};
use core::pin::pin;
use core::task::{Context, Poll};

use embassy_net_driver::{Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken};
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_time::{Instant, Timer};
use tdongle_tailnet_types::Millis;
use tdongle_tailnet_usbnet::arp::ARP_FRAME;
use tdongle_tailnet_usbnet::wire::Mac;

use crate::info::{Ipv4Cfg, StackInfo};
use crate::rx::{RxClass, RxDrop};
use crate::state::{Core, MuxStats, TxDrop, TxPlan};
use crate::tap::{RxTap, TapDrop, TapVerdict};
use crate::{FRAME_MAX, L3_MAX};

/// Frames pulled from the radio per [`Driver::receive`] call before the stack is given the CPU back (a flood of NAT traffic cannot monopolise the
/// stack's task; the mux re-wakes itself when it stops with frames left).
pub const RX_BURST: usize = 8;
/// NAT frames sent per pump (same reason, transmit side).
pub const TX_BURST: usize = 4;

/// The mux could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuxError {
    /// The radio's hardware address is not Ethernet.
    NotEthernet,
}

struct Shared<const TXQ: usize, const RXQ: usize>(Mutex<CriticalSectionRawMutex, RefCell<Core<TXQ, RXQ>>>);

impl<const TXQ: usize, const RXQ: usize> Shared<TXQ, RXQ> {
    fn with<R>(&self, f: impl FnOnce(&mut Core<TXQ, RXQ>) -> R) -> R {
        self.0.lock(|c| f(&mut c.borrow_mut()))
    }
}

/// State owned by the stack side (single context: the task that runs `embassy_net::Runner`).
struct Side<D, T> {
    driver: D,
    tap: T,
    stage: [u8; FRAME_MAX],
    stage_len: usize,
    link_up: bool,
    /// The stack asked for a transmit token and got none; NAT frames wait their turn (cleared when the stack gets one or stops asking).
    owed: bool,
    tx_asked: bool,
    /// The stack just took a token: the next NAT frame goes first.
    napt_turn: bool,
}

/// The Wi-Fi radio shared by the stack and the NAT. Build it, [`WifiMux::split`] it, give the [`StackDriver`] to `embassy_net::new` and keep the
/// [`RawPort`] for the runtime. Large (the queues are inline): put it in a `StaticCell`.
pub struct WifiMux<D: Driver, T: RxTap, const TXQ: usize, const RXQ: usize> {
    side: Side<D, T>,
    shared: Shared<TXQ, RXQ>,
}

impl<D: Driver, T: RxTap, const TXQ: usize, const RXQ: usize> core::fmt::Debug for WifiMux<D, T, TXQ, RXQ> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WifiMux").field("txq", &TXQ).field("rxq", &RXQ).finish_non_exhaustive()
    }
}

impl<D: Driver, T: RxTap, const TXQ: usize, const RXQ: usize> WifiMux<D, T, TXQ, RXQ> {
    /// Bytes of the two packet queues (the dominant part of the state).
    pub const QUEUE_BYTES: usize = (TXQ + RXQ) * L3_MAX;
    /// `size_of::<Self>()`: the queues, the staging frame, the ARP table, the counters, and the driver and tap themselves.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// A mux built at compile time (for a `static`: its queues are 14 KB). The station address is not known yet: call [`WifiMux::set_mac`] before the stack runs.
    pub const fn new_const(driver: D, tap: T) -> Self {
        WifiMux {
            side: Side { driver, tap, stage: [0; FRAME_MAX], stage_len: 0, link_up: false, owed: false, tx_asked: false, napt_turn: false },
            shared: Shared(Mutex::new(RefCell::new(Core::new([0; 6])))),
        }
    }

    /// Let the queues respect the heap's elastic floor: a packet is queued only if the free heap would still be at `ML_HB_FLOOR` afterwards (otherwise it is a
    /// counted drop). Without a probe the queues take whatever the allocator gives.
    pub fn set_heap(&self, heap: &'static dyn tdongle_tailnet_admission::probe::HeapProbe) {
        self.shared.with(|c| c.set_heap(heap));
    }

    /// Set the station's Ethernet address (what `new` reads from the driver).
    pub fn set_mac(&self, mac: [u8; 6]) {
        self.shared.with(|c| c.set_mac(mac));
    }

    /// Wrap `driver` (an Ethernet radio) and `tap`.
    pub fn new(driver: D, tap: T) -> Result<Self, MuxError> {
        let HardwareAddress::Ethernet(mac) = driver.hardware_address() else { return Err(MuxError::NotEthernet) };
        Ok(WifiMux {
            side: Side { driver, tap, stage: [0; FRAME_MAX], stage_len: 0, link_up: false, owed: false, tx_asked: false, napt_turn: false },
            shared: Shared(Mutex::new(RefCell::new(Core::new(mac)))),
        })
    }

    /// Split into the driver for `embassy_net::new` and the port for the runtime. Both borrow the mux. No task pumps the radio: the stack's own
    /// polling does (see the crate docs).
    pub fn split(&mut self) -> (StackDriver<'_, D, T, TXQ, RXQ>, RawPort<'_, TXQ, RXQ>) {
        (StackDriver { side: &mut self.side, shared: &self.shared }, RawPort { shared: &self.shared })
    }
}

fn now_ms() -> Millis {
    Instant::now().as_millis()
}

/// The `embassy_net_driver::Driver` the stack gets. See the crate docs for how the radio is shared.
pub struct StackDriver<'a, D: Driver, T: RxTap, const TXQ: usize, const RXQ: usize> {
    side: &'a mut Side<D, T>,
    shared: &'a Shared<TXQ, RXQ>,
}

impl<D: Driver, T: RxTap, const TXQ: usize, const RXQ: usize> core::fmt::Debug for StackDriver<'_, D, T, TXQ, RXQ> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StackDriver").finish_non_exhaustive()
    }
}

impl<D: Driver, T: RxTap, const TXQ: usize, const RXQ: usize> StackDriver<'_, D, T, TXQ, RXQ> {
    fn enter(&mut self, cx: &mut Context<'_>) {
        self.shared.with(|c| c.stack_waker.register(cx.waker()));
        if let Some(a) = self.shared.with(|c| c.take_sync()) {
            if a.reset {
                self.side.tap.reset();
            }
            self.side.tap.config_changed(a.cfg);
        }
    }

    /// Pull frames from the radio until a stack frame is staged, the radio is empty, or the burst is spent.
    fn pull(&mut self, cx: &mut Context<'_>) {
        let now = now_ms();
        let mut left = RX_BURST;
        while self.side.stage_len == 0 {
            if left == 0 {
                cx.waker().wake_by_ref();
                return;
            }
            left -= 1;
            let Side { driver, tap, stage, stage_len, .. } = &mut *self.side;
            let Some((rx, _tx)) = driver.receive(cx) else { return };
            let shared = self.shared;
            *stage_len = rx.consume(|frame| Self::dispatch(tap, shared, now, frame, stage));
        }
    }

    /// One frame: returns the number of bytes copied into `stage` when it is for the stack, else 0.
    fn dispatch(tap: &mut T, shared: &Shared<TXQ, RXQ>, now: Millis, frame: &mut [u8], stage: &mut [u8; FRAME_MAX]) -> usize {
        let class = shared.with(|c| c.rx_pre(now, frame));
        let unicast_ip = match class {
            RxClass::Drop(_) => return 0,
            RxClass::Ipv4 { unicast: true, .. } => true,
            RxClass::Ipv4 { .. } | RxClass::Arp | RxClass::Other => false,
        };
        if unicast_ip {
            match tap.classify(now, frame) {
                TapVerdict::Stack => {}
                TapVerdict::ToHost { offset, len } => {
                    match offset.checked_add(len).filter(|&e| e <= frame.len() && len >= 20) {
                        Some(end) => {
                            shared.with(|c| c.host_push(&frame[offset..end]));
                        }
                        None => shared.with(|c| c.count_rx_drop(RxDrop::TapBadRange)),
                    }
                    return 0;
                }
                TapVerdict::Dropped(d) => {
                    let r = match d {
                        TapDrop::Rejected => RxDrop::TapRejected,
                        TapDrop::Dropped => RxDrop::TapDropped,
                    };
                    shared.with(|c| c.count_rx_drop(r));
                    return 0;
                }
            }
        }
        // `rx_pre` guarantees `frame.len() <= FRAME_MAX`.
        stage[..frame.len()].copy_from_slice(frame);
        shared.with(|c| c.count_to_stack());
        frame.len()
    }

    /// Send queued NAT traffic (and the ARP requests it needs) through radio tokens, at most `max` frames.
    fn pump_tx(&mut self, cx: &mut Context<'_>, max: usize) {
        let now = now_ms();
        for sent in 0..=max {
            if !self.shared.with(|c| c.tx_has_work()) {
                return;
            }
            if sent == max {
                cx.waker().wake_by_ref();
                return;
            }
            let Some(tok) = self.side.driver.transmit(cx) else { return };
            match self.shared.with(|c| c.tx_plan(now)) {
                TxPlan::Idle => return,
                TxPlan::Wait(until) => {
                    // The same trick embassy-net uses for its own timers: register the waker, the timer queue keeps it.
                    let t = pin!(Timer::at(Instant::from_millis(until)));
                    if t.poll(cx).is_ready() {
                        cx.waker().wake_by_ref();
                    }
                    return;
                }
                TxPlan::Arp(frame) => tok.consume(ARP_FRAME, |b| b.copy_from_slice(&frame)),
                TxPlan::Frame(mac) => {
                    let Some(len) = self.shared.with(|c| c.head_frame_len()) else { return };
                    let shared = self.shared;
                    tok.consume(len, |b| shared.with(|c| c.pop_frame(b, mac)));
                    self.side.napt_turn = false;
                }
            }
        }
    }
}

/// The stack's receive token: the staged frame. Consuming it frees the staging slot.
#[derive(Debug)]
pub struct MuxRxToken<'a> {
    buf: &'a mut [u8],
    stage_len: &'a mut usize,
}

impl RxToken for MuxRxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, f: F) -> R {
        let r = f(self.buf);
        *self.stage_len = 0;
        r
    }
}

/// The stack's transmit token: the radio's, counted.
pub struct MuxTxToken<'a, X: TxToken, const TXQ: usize, const RXQ: usize> {
    inner: X,
    shared: &'a Shared<TXQ, RXQ>,
}

impl<X: TxToken, const TXQ: usize, const RXQ: usize> core::fmt::Debug for MuxTxToken<'_, X, TXQ, RXQ> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MuxTxToken").finish_non_exhaustive()
    }
}

impl<X: TxToken, const TXQ: usize, const RXQ: usize> TxToken for MuxTxToken<'_, X, TXQ, RXQ> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        self.shared.with(|c| c.count_tx_stack());
        self.inner.consume(len, f)
    }
}

impl<D: Driver, T: RxTap, const TXQ: usize, const RXQ: usize> Driver for StackDriver<'_, D, T, TXQ, RXQ> {
    type RxToken<'a>
        = MuxRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = MuxTxToken<'a, D::TxToken<'a>, TXQ, RXQ>
    where
        Self: 'a;

    fn receive(&mut self, cx: &mut Context<'_>) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.enter(cx);
        self.pull(cx);
        if self.side.stage_len == 0 {
            return None;
        }
        // The stack answers a received frame through the token it is given with it: take one now (registering the waker for credit if none).
        let side = &mut *self.side;
        let inner = side.driver.transmit(cx)?;
        let len = side.stage_len;
        Some((MuxRxToken { buf: &mut side.stage[..len], stage_len: &mut side.stage_len }, MuxTxToken { inner, shared: self.shared }))
    }

    fn transmit(&mut self, cx: &mut Context<'_>) -> Option<Self::TxToken<'_>> {
        self.enter(cx);
        self.side.tx_asked = true;
        if self.side.napt_turn {
            // Alternate: the NAT's frame first when it has one waiting.
            self.pump_tx(cx, 1);
        }
        let side = &mut *self.side;
        match side.driver.transmit(cx) {
            Some(inner) => {
                side.owed = false;
                side.napt_turn = true;
                Some(MuxTxToken { inner, shared: self.shared })
            }
            None => {
                side.owed = true;
                None
            }
        }
    }

    fn link_state(&mut self, cx: &mut Context<'_>) -> LinkState {
        self.enter(cx);
        let st = self.side.driver.link_state(cx);
        let up = st == LinkState::Up;
        if up != self.side.link_up {
            self.side.link_up = up;
            if self.shared.with(|c| c.set_link(up)) {
                self.side.tap.reset();
                // The tap's address survives only if the stack keeps it; the stack tells the runtime, which refreshes the config.
                let cfg = self.shared.with(|c| c.want());
                self.side.tap.config_changed(cfg);
            }
        }
        // End of a poll: a stack that did not ask for a token has no claim on the next one.
        if self.side.owed && !self.side.tx_asked {
            self.side.owed = false;
        }
        self.side.tx_asked = false;
        if !self.side.owed && up {
            self.pump_tx(cx, TX_BURST);
        }
        st
    }

    fn capabilities(&self) -> Capabilities {
        let mut c = self.side.driver.capabilities();
        c.max_transmission_unit = c.max_transmission_unit.min(FRAME_MAX);
        c
    }

    fn hardware_address(&self) -> HardwareAddress {
        self.side.driver.hardware_address()
    }
}

/// The runtime's access to the radio: NAT packets out, NAT replies in. `Copy`; any task may use it.
#[derive(Clone, Copy)]
pub struct RawPort<'a, const TXQ: usize, const RXQ: usize> {
    shared: &'a Shared<TXQ, RXQ>,
}

impl<const TXQ: usize, const RXQ: usize> core::fmt::Debug for RawPort<'_, TXQ, RXQ> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawPort").finish_non_exhaustive()
    }
}

impl<'a, const TXQ: usize, const RXQ: usize> RawPort<'a, TXQ, RXQ> {
    /// Queue an IPv4 packet (already translated by the NAT, source = the station's address) for the radio; framed with the next hop's MAC by the mux.
    /// Waits while the queue is full; every other refusal is immediate and counted ([`TxDrop`]).
    pub async fn send(&self, l3_packet: &[u8]) -> Result<(), TxDrop> {
        poll_fn(|cx| match self.shared.with(|c| c.tx_push(l3_packet, Some(cx.waker()))) {
            Err(TxDrop::QueueFull) => Poll::Pending,
            r => Poll::Ready(r),
        })
        .await
    }

    /// [`RawPort::send`] without waiting: a full queue is [`TxDrop::QueueFull`] (counted).
    pub fn try_send(&self, l3_packet: &[u8]) -> Result<(), TxDrop> {
        self.shared.with(|c| c.tx_push(l3_packet, None))
    }

    /// Wait for the next IPv4 packet the NAT translated back for the USB host and copy it into `buf` (at least [`L3_MAX`] bytes; a longer packet than
    /// `buf` is dropped and counted in `host_buf_too_small`). The packet starts at the IP header: the caller puts the USB Ethernet header on it (source
    /// = the dongle's USB MAC, destination = the host's, from its own neighbour table). Returns the length.
    pub async fn next_to_host(&self, buf: &mut [u8]) -> usize {
        poll_fn(|cx| match self.shared.with(|c| c.host_pop(buf, Some(cx.waker()))) {
            Some(n) => Poll::Ready(n),
            None => Poll::Pending,
        })
        .await
    }

    /// [`RawPort::next_to_host`] without waiting.
    pub fn try_next_to_host(&self, buf: &mut [u8]) -> Option<usize> {
        self.shared.with(|c| c.host_pop(buf, None))
    }

    /// The gateway's MAC, once learned (by snooping or by an ARP the mux sent).
    pub fn gateway_mac(&self) -> Option<Mac> {
        self.shared.with(|c| c.gateway_mac())
    }

    /// A snapshot of every counter.
    pub fn stats(&self) -> MuxStats {
        self.shared.with(|c| c.snapshot())
    }

    /// Packets waiting for the radio and packets waiting for the USB side.
    pub fn queued(&self) -> (usize, usize) {
        self.shared.with(|c| (c.tx_len(), c.host_len()))
    }

    /// The handle the runtime uses to tell the mux about the stack's configuration and the association.
    pub fn info(&self) -> InfoHandle<'a, TXQ, RXQ> {
        InfoHandle { shared: self.shared }
    }
}

/// Fills the mux's view of the station: IPv4 configuration and association generation.
#[derive(Clone, Copy)]
pub struct InfoHandle<'a, const TXQ: usize, const RXQ: usize> {
    shared: &'a Shared<TXQ, RXQ>,
}

impl<const TXQ: usize, const RXQ: usize> core::fmt::Debug for InfoHandle<'_, TXQ, RXQ> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InfoHandle").finish_non_exhaustive()
    }
}

impl<const TXQ: usize, const RXQ: usize> InfoHandle<'_, TXQ, RXQ> {
    /// Set the stack's IPv4 configuration (`None`: unconfigured). A different address clears the neighbour table, the queued packets and the tap's flows.
    pub fn set_config(&self, cfg: Option<Ipv4Cfg>) {
        self.shared.with(|c| c.set_want(cfg));
    }
    /// Pull the configuration from `stack` and set it when it changed.
    pub fn refresh<S: StackInfo>(&self, stack: &S) {
        self.set_config(stack.ipv4());
    }
    /// The radio (re)associated: clear neighbour state, queued packets and flows even when the address came back unchanged.
    pub fn new_association(&self) {
        self.shared.with(|c| c.bump_generation());
    }
    /// The configuration last set.
    pub fn config(&self) -> Option<Ipv4Cfg> {
        self.shared.with(|c| c.want())
    }
}
