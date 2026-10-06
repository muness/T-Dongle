//! The map projector's sink for the engine: [`NetmapSink`] turns the projector's borrowed [`MapEvent`]s into owned [`NetmapEvent`]s and hands them to a
//! [`NetmapTarget`]: a channel to the engine task, or [`EngineNetmap`] which calls the engine directly.

use crate::dir::PeerDirectory;
use crate::engine::{Engine, Handled};
use crate::io::{Input, MemberId, NetmapEvent, Output};
use tdongle_tailnet_map::{MapEvent, MapSink, SinkError};
use tdongle_tailnet_types::{Entropy, FixedStr, Millis};

/// Where translated map events go. Return `false` to refuse (the map fails with `SinkRefused` / `CommitRefused` and nothing is applied).
pub trait NetmapTarget {
    /// One event.
    fn netmap(&mut self, ev: NetmapEvent) -> bool;
}

impl<F: FnMut(NetmapEvent) -> bool> NetmapTarget for F {
    fn netmap(&mut self, ev: NetmapEvent) -> bool {
        self(ev)
    }
}

/// The engine's [`MapSink`].
#[derive(Debug)]
pub struct NetmapSink<T> {
    target: T,
}

impl<T: NetmapTarget> NetmapSink<T> {
    /// A sink delivering to `target`.
    pub fn new(target: T) -> Self {
        Self { target }
    }
    /// Take the target back.
    pub fn into_inner(self) -> T {
        self.target
    }
}

impl<T: NetmapTarget> MapSink for NetmapSink<T> {
    fn event(&mut self, e: MapEvent<'_>) -> Result<(), SinkError> {
        let ev = match e {
            MapEvent::Peer(r) => NetmapEvent::Peer(r.clone()),
            // not read by the C either
            MapEvent::PeerSeen { .. } | MapEvent::CollectServices(_) | MapEvent::KeepAlive => return Ok(()),
            MapEvent::SelfNode(n) => NetmapEvent::SelfNode(n.clone()),
            MapEvent::Derp(d) => NetmapEvent::Derp(d.clone()),
            MapEvent::Dns(c) => NetmapEvent::Dns(c.clone()),
            MapEvent::Domain(s) => {
                let mut d = FixedStr::<63>::new();
                d.set(s);
                NetmapEvent::Domain(d)
            }
            MapEvent::ControlTime { secs, nanos } => NetmapEvent::ControlTime { secs, nanos },
            MapEvent::Commit(s) => NetmapEvent::Commit { authoritative: s.authoritative, self_expired: s.self_expired },
            MapEvent::Abort(_) => NetmapEvent::Abort,
        };
        if self.target.netmap(ev) { Ok(()) } else { Err(SinkError) }
    }
}

/// A [`NetmapTarget`] that calls an engine directly (single-task runtimes, tests). The clock, entropy and output are the ones of the moment.
pub struct EngineNetmap<'a, D, const M: usize, const P: usize, const K: usize, const A: usize, const F: usize, const JB: usize> {
    /// The engine.
    pub engine: &'a mut Engine<D, M, P, K, A, F, JB>,
    /// Which membership's map this is.
    pub member: MemberId,
    /// Now.
    pub now: Millis,
    /// Entropy.
    pub rng: &'a mut dyn Entropy,
    /// Outputs.
    pub out: &'a mut dyn Output,
}

impl<D, const M: usize, const P: usize, const K: usize, const A: usize, const F: usize, const JB: usize> core::fmt::Debug
    for EngineNetmap<'_, D, M, P, K, A, F, JB>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EngineNetmap(member={})", self.member)
    }
}

impl<D: PeerDirectory, const M: usize, const P: usize, const K: usize, const A: usize, const F: usize, const JB: usize> NetmapTarget
    for EngineNetmap<'_, D, M, P, K, A, F, JB>
{
    fn netmap(&mut self, ev: NetmapEvent) -> bool {
        self.engine.handle(self.now, Input::Netmap { member: self.member, event: &ev }, self.rng, self.out) != Handled::Refused
    }
}
