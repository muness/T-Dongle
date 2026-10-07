//! Netcheck-lite: which DERP region answers STUN fastest (`ml_netcheck.c`, after Go's `net/netcheck`).
//!
//! One binding request per region (the first node with a STUN port, 3478 by default), sent 50 ms apart so a local NAT does not drop a burst; every
//! region that has not answered is asked again every 5 s, up to three times, each time under a fresh transaction id (a late answer to an earlier
//! attempt is `Unmatched`); the whole run ends after 25 s, or as soon as every region has answered. The result is the region with the lowest
//! round-trip time, every region's time, and our public IPv4 address from the first answer.
//!
//! The C finishes only at the deadline, so every netcheck costs 25 s of the coordination task even when all regions answered in 50 ms; ending early is
//! the one behavioural change.
//!
//! Sans-IO: [`Netcheck::poll`] returns the next request to send (one per call) and the time to call again; [`Netcheck::on_datagram`] takes responses.
//! Region addresses come from the caller's DNS; the socket is [`crate::stun_sched::SockKind::Netcheck`] and may be the DISCO socket.

use crate::addr::Ep;
use crate::stun::{self, REQUEST_LEN, TxId};
use crate::stun_sched::{SockKind, StunSend};
use tdongle_tailnet_types::{Counter, Entropy, Millis};

/// Whole-run budget (`NETCHECK_TIMEOUT_MS`).
pub const TIMEOUT_MS: u64 = 25_000;
/// Gap between sweeps over the regions that have not answered (`NETCHECK_RETRY_GAP_MS`).
pub const RETRY_GAP_MS: u64 = 5_000;
/// Retry sweeps after the first send (`NETCHECK_MAX_RETRIES`).
pub const MAX_RETRIES: u8 = 3;
/// Spacing of sends (`NETCHECK_PROBE_GAP_MS`).
pub const PROBE_GAP_MS: u64 = 50;

#[derive(Debug, Clone, Copy)]
struct Probe {
    txid: TxId,
    sent: u64,
    to: Ep,
    region: u16,
    rtt_ms: u16,
    got: bool,
    armed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Idle,
    Initial,
    Waiting,
    Retry,
    Done,
}

/// What [`Netcheck::poll`] says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetcheckPoll {
    /// Not running (call [`Netcheck::start`]).
    Idle,
    /// Call again at this time (or earlier if a datagram arrives).
    Pending {
        /// Next time something is due.
        wake_at: Millis,
    },
    /// Finished: read the result.
    Done,
}

/// What a received datagram did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetcheckEvent {
    /// Not STUN, or not a binding success response.
    Ignored,
    /// Matches no outstanding request (a late answer to an earlier attempt, an echo, a stranger).
    Unmatched,
    /// A region answered.
    Response {
        /// Region id.
        region: u16,
        /// Round trip.
        rtt_ms: u16,
    },
}

/// Counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetcheckCounters {
    /// Requests sent (first attempts and retries).
    pub tx: Counter,
    /// Retry requests.
    pub retries: Counter,
    /// Responses accepted.
    pub rx_ok: Counter,
    /// Datagrams ignored (not STUN or not a success response).
    pub rx_ignored: Counter,
    /// Responses matching nothing.
    pub rx_unmatched: Counter,
    /// A region could not be added (the table is full, or it has no usable address).
    pub region_dropped: Counter,
    /// Regions that never answered in the last run.
    pub silent_regions: Counter,
}

/// A netcheck over up to `R` regions.
#[derive(Debug, Clone)]
pub struct Netcheck<const R: usize = 8> {
    probes: [Probe; R],
    n: u8,
    stage: Stage,
    cursor: u8,
    retries_done: u8,
    next_send_at: u64,
    next_retry_at: u64,
    deadline: u64,
    public: Option<Ep>,
    /// Counters.
    pub counters: NetcheckCounters,
}

impl<const R: usize> Default for Netcheck<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const R: usize> Netcheck<R> {
    /// Bytes of state.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// Empty.
    pub const fn new() -> Self {
        let p = Probe { txid: [0; stun::TXID_LEN], sent: 0, to: Ep::NONE, region: 0, rtt_ms: 0, got: false, armed: false };
        Netcheck {
            probes: [p; R],
            n: 0,
            stage: Stage::Idle,
            cursor: 0,
            retries_done: 0,
            next_send_at: 0,
            next_retry_at: 0,
            deadline: 0,
            public: None,
            counters: NetcheckCounters {
                tx: Counter(0),
                retries: Counter(0),
                rx_ok: Counter(0),
                rx_ignored: Counter(0),
                rx_unmatched: Counter(0),
                region_dropped: Counter(0),
                silent_regions: Counter(0),
            },
        }
    }

    /// Forget the regions and any result.
    pub fn clear(&mut self) {
        let c = self.counters;
        *self = Self::new();
        self.counters = c;
    }

    /// Add a region's STUN endpoint before [`start`](Netcheck::start). Region 0 and unusable endpoints are refused; so is a full table.
    pub fn add_region(&mut self, region: u16, to: Ep) -> bool {
        if region == 0 || !to.is_usable() || usize::from(self.n) >= R || self.probes[..usize::from(self.n)].iter().any(|p| p.region == region) {
            self.counters.region_dropped.bump();
            return false;
        }
        self.probes[usize::from(self.n)] = Probe { txid: [0; stun::TXID_LEN], sent: 0, to, region, rtt_ms: 0, got: false, armed: false };
        self.n += 1;
        true
    }

    /// Begin a run with the regions added so far.
    pub fn start(&mut self, now: Millis) {
        for p in &mut self.probes[..usize::from(self.n)] {
            p.got = false;
            p.armed = false;
            p.rtt_ms = 0;
        }
        self.public = None;
        self.cursor = 0;
        self.retries_done = 0;
        self.next_send_at = now;
        self.stage = if self.n == 0 { Stage::Done } else { Stage::Initial };
    }

    fn send_one(&mut self, i: usize, now: Millis, rng: &mut dyn Entropy, retry: bool) -> StunSend {
        let mut txid = [0u8; stun::TXID_LEN];
        rng.fill(&mut txid);
        let mut packet = [0u8; REQUEST_LEN];
        stun::build_request(&txid, &mut packet);
        let p = &mut self.probes[i];
        p.txid = txid;
        p.sent = now;
        p.armed = true;
        self.counters.tx.bump();
        if retry {
            self.counters.retries.bump();
        }
        StunSend { sock: SockKind::Netcheck, to: p.to, packet }
    }

    fn all_answered(&self) -> bool {
        self.probes[..usize::from(self.n)].iter().all(|p| p.got)
    }

    fn finish(&mut self) {
        self.stage = Stage::Done;
        for p in &self.probes[..usize::from(self.n)] {
            if !p.got {
                self.counters.silent_regions.bump();
            }
        }
    }

    /// Advance: at most one request per call, into `out`.
    pub fn poll(&mut self, now: Millis, rng: &mut dyn Entropy, out: &mut dyn FnMut(StunSend)) -> NetcheckPoll {
        match self.stage {
            Stage::Idle => NetcheckPoll::Idle,
            Stage::Done => NetcheckPoll::Done,
            Stage::Initial => {
                if now >= self.next_send_at {
                    let i = usize::from(self.cursor);
                    let s = self.send_one(i, now, rng, false);
                    out(s);
                    self.cursor += 1;
                    self.next_send_at = now + PROBE_GAP_MS;
                    if self.cursor >= self.n {
                        // The C measures its deadline and first retry from the end of the initial sends.
                        self.stage = Stage::Waiting;
                        self.deadline = now + TIMEOUT_MS;
                        self.next_retry_at = now + RETRY_GAP_MS;
                    }
                }
                NetcheckPoll::Pending { wake_at: self.next_send_at }
            }
            Stage::Waiting | Stage::Retry => {
                if self.all_answered() || now >= self.deadline {
                    self.finish();
                    return NetcheckPoll::Done;
                }
                if self.stage == Stage::Waiting {
                    if self.retries_done < MAX_RETRIES && now >= self.next_retry_at {
                        self.stage = Stage::Retry;
                        self.cursor = 0;
                    } else {
                        let wake = if self.retries_done < MAX_RETRIES { self.next_retry_at.min(self.deadline) } else { self.deadline };
                        return NetcheckPoll::Pending { wake_at: wake };
                    }
                }
                // Retry sweep: the next region that has not answered, one per PROBE_GAP_MS.
                while usize::from(self.cursor) < usize::from(self.n) && self.probes[usize::from(self.cursor)].got {
                    self.cursor += 1;
                }
                if usize::from(self.cursor) >= usize::from(self.n) {
                    self.retries_done += 1;
                    self.stage = Stage::Waiting;
                    self.next_retry_at = now + RETRY_GAP_MS;
                    return NetcheckPoll::Pending { wake_at: self.next_retry_at.min(self.deadline) };
                }
                if now >= self.next_send_at {
                    let i = usize::from(self.cursor);
                    let s = self.send_one(i, now, rng, true);
                    out(s);
                    self.cursor += 1;
                    self.next_send_at = now + PROBE_GAP_MS;
                }
                NetcheckPoll::Pending { wake_at: self.next_send_at }
            }
        }
    }

    /// A datagram arrived on the netcheck socket.
    pub fn on_datagram(&mut self, now: Millis, data: &[u8]) -> NetcheckEvent {
        if self.stage == Stage::Idle || self.stage == Stage::Done || !stun::is_stun(data) || data[0] != 0x01 || data[1] != 0x01 {
            self.counters.rx_ignored.bump();
            return NetcheckEvent::Ignored;
        }
        let Some(p) = self.probes[..usize::from(self.n)].iter_mut().find(|p| !p.got && p.armed && p.txid == data[8..20]) else {
            self.counters.rx_unmatched.bump();
            return NetcheckEvent::Unmatched;
        };
        p.got = true;
        p.rtt_ms = now.saturating_sub(p.sent).min(u64::from(u16::MAX)) as u16;
        let (region, rtt_ms) = (p.region, p.rtt_ms);
        self.counters.rx_ok.bump();
        if self.public.is_none()
            && let Ok(r) = stun::parse_response(data)
            && r.mapped.is_v4()
        {
            self.public = Some(r.mapped);
        }
        NetcheckEvent::Response { region, rtt_ms }
    }

    /// The run has ended.
    pub fn is_done(&self) -> bool {
        self.stage == Stage::Done
    }

    /// Region with the lowest round trip among those that answered (0 if none: the C then keeps the control plane's choice). Ties go to the earlier
    /// region.
    pub fn best_region(&self) -> u16 {
        let mut best: Option<&Probe> = None;
        for p in self.probes[..usize::from(self.n)].iter().filter(|p| p.got) {
            if best.is_none_or(|b| p.rtt_ms < b.rtt_ms) {
                best = Some(p);
            }
        }
        best.map_or(0, |p| p.region)
    }

    /// Each region with its round trip, `None` for one that did not answer.
    pub fn rtts(&self) -> impl Iterator<Item = (u16, Option<u16>)> + '_ {
        self.probes[..usize::from(self.n)].iter().map(|p| (p.region, p.got.then_some(p.rtt_ms)))
    }

    /// Our public IPv4 address (port included) from the first answer.
    pub fn public_endpoint(&self) -> Option<Ep> {
        self.public
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tdongle_tailnet_types::test_util::TestRng;
    extern crate std;
    use std::vec::Vec;

    fn reply(tx: &StunSend, mapped: Ep) -> Vec<u8> {
        let mut b = [0u8; 64];
        let txid: TxId = tx.packet[8..20].try_into().unwrap();
        let n = stun::build_response(&txid, &mapped, &mut b).unwrap();
        b[..n].to_vec()
    }

    fn drive(nc: &mut Netcheck<4>, rng: &mut TestRng, from: u64, to: u64) -> Vec<(u64, StunSend)> {
        let mut sent = Vec::new();
        let mut t = from;
        while t <= to {
            let mut v = Vec::new();
            let p = nc.poll(t, rng, &mut |s| v.push(s));
            sent.extend(v.into_iter().map(|s| (t, s)));
            match p {
                NetcheckPoll::Pending { wake_at } => t = wake_at.max(t + 1),
                _ => break,
            }
        }
        sent
    }

    #[test]
    fn spaced_sends_best_region_and_early_finish() {
        let mut rng = TestRng(11);
        let mut nc = Netcheck::<4>::new();
        assert!(nc.add_region(1, Ep::v4([10, 0, 0, 1], 3478)));
        assert!(nc.add_region(2, Ep::v4([10, 0, 0, 2], 3478)));
        assert!(nc.add_region(3, Ep::v4([10, 0, 0, 3], 3478)));
        assert!(!nc.add_region(3, Ep::v4([10, 0, 0, 9], 3478)));
        assert!(!nc.add_region(0, Ep::v4([10, 0, 0, 9], 3478)));
        assert!(!nc.add_region(9, Ep::v4([10, 0, 0, 9], 0)));
        nc.start(1_000);
        let sent = drive(&mut nc, &mut rng, 1_000, 1_200);
        assert_eq!(sent.iter().map(|(t, _)| *t).collect::<Vec<_>>(), [1_000, 1_050, 1_100]);
        assert_eq!(sent.iter().map(|(_, s)| s.to.port()).collect::<Vec<_>>(), [3478; 3]);
        let public = Ep::v4([198, 51, 100, 7], 41641);
        assert_eq!(nc.on_datagram(1_130, &reply(&sent[1].1, public)), NetcheckEvent::Response { region: 2, rtt_ms: 80 });
        assert_eq!(nc.on_datagram(1_140, &reply(&sent[1].1, public)), NetcheckEvent::Unmatched);
        assert_eq!(nc.on_datagram(1_160, &reply(&sent[0].1, public)), NetcheckEvent::Response { region: 1, rtt_ms: 160 });
        assert_eq!(nc.on_datagram(1_170, &reply(&sent[2].1, public)), NetcheckEvent::Response { region: 3, rtt_ms: 70 });
        assert_eq!(nc.poll(1_171, &mut rng, &mut |_| panic!()), NetcheckPoll::Done);
        assert_eq!(nc.best_region(), 3);
        assert_eq!(nc.public_endpoint(), Some(public));
        assert_eq!(nc.rtts().collect::<Vec<_>>(), [(1, Some(160)), (2, Some(80)), (3, Some(70))]);
    }

    #[test]
    fn retries_use_fresh_txids_and_the_run_ends_at_the_deadline() {
        let mut rng = TestRng(12);
        let mut nc = Netcheck::<4>::new();
        nc.add_region(1, Ep::v4([10, 0, 0, 1], 3478));
        nc.add_region(2, Ep::v4([10, 0, 0, 2], 3478));
        nc.start(0);
        let mut sent = drive(&mut nc, &mut rng, 0, 5_100);
        // the first sweep is 5 s after the last initial send, 50 ms apart
        assert_eq!(sent.iter().map(|(t, _)| *t).collect::<Vec<_>>(), [0, 50, 50 + 5_000, 50 + 5_000 + 50]);
        // txids differ between attempts, so a late answer to attempt 1 is Unmatched
        assert_ne!(sent[0].1.packet[8..20], sent[2].1.packet[8..20]);
        assert_eq!(nc.on_datagram(5_101, &reply(&sent[0].1, Ep::v4([1, 2, 3, 4], 5))), NetcheckEvent::Unmatched);
        sent.extend(drive(&mut nc, &mut rng, 5_102, 60_000));
        // 2 first sends + 3 sweeps x 2 regions: here nobody answers
        assert_eq!(sent.len(), 2 + 3 * 2);
        assert_eq!(nc.counters.retries.get(), 6);
        assert!(nc.is_done());
        assert_eq!(nc.best_region(), 0);
        assert_eq!(nc.counters.silent_regions.get(), 2);
        assert_eq!(nc.poll(70_000, &mut rng, &mut |_| panic!()), NetcheckPoll::Done);
    }

    #[test]
    fn answered_regions_are_not_retried() {
        let mut rng = TestRng(13);
        let mut nc = Netcheck::<4>::new();
        nc.add_region(1, Ep::v4([10, 0, 0, 1], 3478));
        nc.add_region(2, Ep::v4([10, 0, 0, 2], 3478));
        nc.start(0);
        let first = drive(&mut nc, &mut rng, 0, 60);
        assert_eq!(first.len(), 2);
        nc.on_datagram(20, &reply(&first[0].1, Ep::v4([1, 2, 3, 4], 5)));
        let rest = drive(&mut nc, &mut rng, 61, 60_000);
        assert!(rest.iter().all(|(_, s)| s.to == Ep::v4([10, 0, 0, 2], 3478)));
        assert_eq!(rest.len(), 3);
        assert_eq!(nc.best_region(), 1);
    }

    #[test]
    fn nothing_to_do_and_garbage() {
        let mut rng = TestRng(14);
        let mut nc = Netcheck::<2>::new();
        assert_eq!(nc.poll(0, &mut rng, &mut |_| panic!()), NetcheckPoll::Idle);
        nc.start(0);
        assert_eq!(nc.poll(0, &mut rng, &mut |_| panic!()), NetcheckPoll::Done);
        assert_eq!(nc.on_datagram(1, b"nope"), NetcheckEvent::Ignored);
        let mut nc = Netcheck::<1>::new();
        assert!(nc.add_region(1, Ep::v4([1, 1, 1, 1], 3478)));
        assert!(!nc.add_region(2, Ep::v4([1, 1, 1, 2], 3478)));
        assert_eq!(nc.counters.region_dropped.get(), 1);
    }
}
