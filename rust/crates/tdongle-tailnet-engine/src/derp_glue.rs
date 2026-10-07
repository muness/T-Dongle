//! The DERP links of the memberships, for runtimes that do not want to write the glue themselves.
//!
//! Why the engine does not own them: a link's [`Action`]s borrow the link, and a delivered packet has to go back *into* the engine; owning the links
//! inside `handle` would make it re-entrant. So the runtime owns one [`Link`] per membership, and this helper (`DerpLinks`) is the whole glue:
//!
//! * engine -> links: [`DerpLinks::on_out`] consumes `Out::DerpConnect` (point the link at the region's node and `Connect`), `Out::DerpClose`
//!   (`Close`) and `Out::DerpSend` (`Link::send_packet`; a packet for a link that is not ready is the link's counted `tx_drop_not_ready`);
//! * links -> engine: [`DerpLinks::event`] feeds the transport's events to the right link; the link's actions become [`LinkIo`] calls (dial, TLS, write,
//!   close), `Out::WantToken` / `Out::ReleaseToken` (the negotiation token, bridge them to `tdongle_tailnet_admission::negotiation::Negotiation`),
//!   and engine inputs through the callback: `Input::DerpLinkEvent` for ready/not ready, `Input::DerpPacket` for a relayed packet (copied into this
//!   helper's buffer first: the link's payload is immutable and the engine decrypts in place);
//! * time: [`DerpLinks::next_deadline`] and [`DerpLinks::timer`].
//!
//! The callback must not call back into `DerpLinks` (queue the input for the engine task and return).

use crate::io::{DerpNote, Input, MemberId, Out, Output, TokenPhase};
use tdongle_tailnet_derp::{Action, Event, Link, LinkEvent, MAX_FRAME, Sink, Target, Timing};
use tdongle_tailnet_types::{Entropy, Key32, Millis};

/// What the links ask the transport to do.
pub trait LinkIo {
    /// Resolve `host`, connect to `port`; report `Event::Dns` then `Event::Connected`.
    fn dial(&mut self, member: MemberId, region: u16, host: &str, port: u16);
    /// Start TLS with SNI `host`; report `Event::TlsDone`.
    fn start_tls(&mut self, member: MemberId, host: &str);
    /// Write all of `bytes` (valid until the next call into the link); report `TxProgress`/`TxDone`.
    fn send(&mut self, member: MemberId, bytes: &[u8]);
    /// Close the transport.
    fn close(&mut self, member: MemberId);
}

/// One [`Link`] per membership, `M` memberships, `TXQ` bytes of transmit ring each.
pub struct DerpLinks<const M: usize, const TXQ: usize> {
    links: [Option<(MemberId, Link<TXQ>)>; M],
    timing: Timing,
    rx: [u8; MAX_FRAME],
}

impl<const M: usize, const TXQ: usize> core::fmt::Debug for DerpLinks<M, TXQ> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DerpLinks({} links)", self.links.iter().flatten().count())
    }
}

struct Glue<'a, 'b> {
    member: MemberId,
    io: &'a mut dyn LinkIo,
    out: &'a mut dyn Output,
    input: &'a mut dyn FnMut(Input<'_>),
    rx: &'b mut [u8; MAX_FRAME],
}

impl Sink for Glue<'_, '_> {
    fn action(&mut self, a: Action<'_>) {
        let member = self.member;
        match a {
            Action::Notify(LinkEvent::Connected) => (self.input)(Input::DerpLinkEvent { member, event: DerpNote::Connected }),
            Action::Notify(LinkEvent::Disconnected | LinkEvent::RxStale) => (self.input)(Input::DerpLinkEvent { member, event: DerpNote::Disconnected }),
            Action::Notify(LinkEvent::ConnectFailed) => (self.input)(Input::DerpLinkEvent { member, event: DerpNote::ConnectFailed }),
            Action::Notify(LinkEvent::ClockDeferred) => {}
            Action::WantToken => {
                self.out.emit(Out::WantToken { member, phase: TokenPhase::Derp });
            }
            Action::ReleaseToken => {
                self.out.emit(Out::ReleaseToken { member });
            }
            Action::Dial { region, host, port } => self.io.dial(member, region, host, port),
            Action::StartTls { host } => self.io.start_tls(member, host),
            Action::Send(b) => self.io.send(member, b),
            Action::Close => self.io.close(member),
            Action::DeliverPacket { src_key, payload } => {
                let n = payload.len().min(self.rx.len());
                self.rx[..n].copy_from_slice(&payload[..n]);
                (self.input)(Input::DerpPacket { member, src: src_key, data: &mut self.rx[..n] });
            }
            Action::PeerGone { .. } | Action::Health(_) | Action::ServerRestarting { .. } => {}
        }
    }
}

impl<const M: usize, const TXQ: usize> DerpLinks<M, TXQ> {
    /// No links.
    #[inline(always)]
    pub fn new(timing: Timing) -> Self {
        Self { links: core::array::from_fn(|_| None), timing, rx: [0; MAX_FRAME] }
    }

    /// Create the link of a membership (its node key is the DERP client key). `false` when full or the id is present.
    pub fn add(&mut self, member: MemberId, node_private: Key32) -> bool {
        if self.links.iter().flatten().any(|(id, _)| *id == member) {
            return false;
        }
        match self.links.iter_mut().find(|l| l.is_none()) {
            Some(s) => {
                *s = Some((member, Link::new(node_private, Target::new(0, "", 443), self.timing)));
                true
            }
            None => false,
        }
    }

    /// Destroy the link of a membership (drop it after closing: call [`DerpLinks::on_out`] with `DerpClose` first if it is open).
    pub fn remove(&mut self, member: MemberId) -> bool {
        match self.links.iter_mut().find(|l| l.as_ref().is_some_and(|(id, _)| *id == member)) {
            Some(s) => {
                *s = None;
                true
            }
            None => false,
        }
    }

    /// The link of a membership.
    pub fn link(&self, member: MemberId) -> Option<&Link<TXQ>> {
        self.links.iter().flatten().find(|(id, _)| *id == member).map(|(_, l)| l)
    }

    /// Bytes of one link (the ADR's DERP-link line).
    pub const LINK_BYTES: usize = Link::<TXQ>::STATE_BYTES;

    /// Handle an engine output that concerns the links. Returns `true` when it did (other outputs are none of its business).
    #[allow(clippy::too_many_arguments)]
    pub fn on_out(
        &mut self,
        now: Millis,
        o: &Out<'_>,
        rng: &mut dyn Entropy,
        io: &mut dyn LinkIo,
        out: &mut dyn Output,
        input: &mut dyn FnMut(Input<'_>),
    ) -> bool {
        let (member, ev) = match o {
            Out::DerpConnect { member, region, host, port } => {
                if let Some((_, l)) = self.links.iter_mut().flatten().find(|(id, _)| id == member) {
                    l.set_target(Target::new(*region, host, *port));
                }
                (*member, Some(Event::Connect))
            }
            Out::DerpClose { member } => (*member, Some(Event::Close)),
            Out::DerpSend { member, dst, data } => {
                let Some((_, l)) = self.links.iter_mut().flatten().find(|(id, _)| id == member) else { return true };
                let mut g = Glue { member: *member, io, out, input, rx: &mut self.rx };
                let _ = l.send_packet(now, dst, data, &mut g);
                return true;
            }
            _ => return false,
        };
        if let Some(ev) = ev {
            self.event(now, member, ev, rng, io, out, input);
        }
        true
    }

    /// Feed a transport event (or `Event::Timer`) to a membership's link.
    #[allow(clippy::too_many_arguments)]
    pub fn event(
        &mut self,
        now: Millis,
        member: MemberId,
        ev: Event<'_>,
        rng: &mut dyn Entropy,
        io: &mut dyn LinkIo,
        out: &mut dyn Output,
        input: &mut dyn FnMut(Input<'_>),
    ) {
        let Some((_, l)) = self.links.iter_mut().flatten().find(|(id, _)| *id == member) else { return };
        let mut g = Glue { member, io, out, input, rx: &mut self.rx };
        l.handle(now, ev, rng, &mut g);
    }

    /// Tell every link the wall clock is (not) set.
    pub fn clock_valid(&mut self, now: Millis, v: bool, rng: &mut dyn Entropy, io: &mut dyn LinkIo, out: &mut dyn Output, input: &mut dyn FnMut(Input<'_>)) {
        for i in 0..M {
            if let Some(id) = self.links[i].as_ref().map(|(id, _)| *id) {
                self.event(now, id, Event::ClockValid(v), rng, io, out, input);
            }
        }
    }

    /// The earliest time any link needs `Event::Timer` (`None`: never).
    pub fn next_deadline(&self, now: Millis) -> Option<Millis> {
        self.links.iter().flatten().filter_map(|(_, l)| l.next_deadline_ms(now)).map(|d| now + u64::from(d)).min()
    }

    /// Run every link's timers.
    pub fn timer(&mut self, now: Millis, rng: &mut dyn Entropy, io: &mut dyn LinkIo, out: &mut dyn Output, input: &mut dyn FnMut(Input<'_>)) {
        for i in 0..M {
            if let Some(id) = self.links[i].as_ref().map(|(id, _)| *id) {
                self.event(now, id, Event::Timer, rng, io, out, input);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    use tdongle_tailnet_types::test_util::TestRng;

    #[derive(Default)]
    struct Io {
        dials: Vec<(MemberId, u16, std::string::String, u16)>,
        closes: u32,
    }
    impl LinkIo for Io {
        fn dial(&mut self, m: MemberId, r: u16, h: &str, p: u16) {
            self.dials.push((m, r, h.into(), p));
        }
        fn start_tls(&mut self, _: MemberId, _: &str) {}
        fn send(&mut self, _: MemberId, _: &[u8]) {}
        fn close(&mut self, _: MemberId) {
            self.closes += 1;
        }
    }

    #[test]
    fn connect_asks_for_the_token_then_dials_and_send_before_ready_is_a_counted_drop() {
        let mut links = DerpLinks::<2, 2048>::new(Timing::DEFAULT);
        assert!(links.add(7, Key32([9; 32])));
        assert!(!links.add(7, Key32([9; 32])));
        let (mut io, mut rng) = (Io::default(), TestRng(5));
        let outs: core::cell::RefCell<Vec<std::string::String>> = core::cell::RefCell::new(Vec::new());
        let mut out = |o: Out<'_>| {
            outs.borrow_mut().push(std::format!("{o:?}"));
            true
        };
        let mut inputs = 0;
        let mut inp = |_: Input<'_>| inputs += 1;
        links.event(0, 7, Event::ClockValid(true), &mut rng, &mut io, &mut out, &mut inp);
        assert!(links.on_out(0, &Out::DerpConnect { member: 7, region: 3, host: "derp3.example", port: 443 }, &mut rng, &mut io, &mut out, &mut inp));
        // the link wakes, asks for the negotiation token, then dials when it is granted
        for t in (0..400).step_by(50) {
            links.timer(t, &mut rng, &mut io, &mut out, &mut inp);
        }
        assert!(outs.borrow().iter().any(|s| s.contains("WantToken")), "{:?}", outs.borrow());
        links.event(400, 7, Event::TokenGranted, &mut rng, &mut io, &mut out, &mut inp);
        assert_eq!(io.dials, [(7, 3, "derp3.example".into(), 443)]);
        // not ready: the packet is the link's counted drop, not a panic
        assert!(links.on_out(500, &Out::DerpSend { member: 7, dst: &[1; 32], data: &[0; 40] }, &mut rng, &mut io, &mut out, &mut inp));
        assert_eq!(links.link(7).unwrap().stats().tx_drop_not_ready.get(), 1);
        assert!(!links.on_out(500, &Out::Wake(None), &mut rng, &mut io, &mut out, &mut inp));
        // close releases the token and closes the transport
        links.on_out(600, &Out::DerpClose { member: 7 }, &mut rng, &mut io, &mut out, &mut inp);
        assert!(outs.borrow().iter().any(|s| s.contains("ReleaseToken")));
        assert!(io.closes >= 1);
        assert!(links.remove(7) && !links.remove(7));
    }
}
