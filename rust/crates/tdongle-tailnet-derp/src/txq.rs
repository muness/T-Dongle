//! The relay transmit queue: a byte ring of finished SendPacket frames, bounded, with counted refusals.
//!
//! Frames are stored already framed (`type, length, destination key, packet`), so the link can hand the head of the queue to the transport as one
//! contiguous slice and no copy is made at send time. The ring never splits a frame: a frame that does not fit before the end of the buffer starts again
//! at offset 0.
//!
//! Two limits apply. The storage (`N` bytes) is a hard bound. The *soft limit* of [`TxPolicy`] is a byte budget that the owner can move at run time
//! (the C ties the relay queue to the heap budget, `ML_HB_DERP_TX`). A packet of at most `small_bytes` is exempt from the soft limit while fewer than
//! `small_slots` exempt packets are queued, so a path can still be discovered and kept alive (DISCO pings, `ML_HB_RX_SMALL_BYTES` = 512) in a flood
//! of WireGuard data (`ml_heap_budget.h`). The exemption never exceeds the storage.

use crate::frame::{FrameType, encode_header};
use crate::{FRAME_HEADER_LEN, KEY_LEN, MAX_FRAME};

/// Why a packet was not queued. Each is counted by the link.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxDrop {
    /// The link is not relaying (not ready), so the packet cannot be sent and would only go stale.
    NotReady,
    /// The packet exceeds [`MAX_FRAME`].
    TooBig,
    /// The soft byte budget is exhausted and the packet is not exempt.
    OverBudget,
    /// The ring has no contiguous room for the frame (hard bound).
    NoSpace,
}

/// The queue's admission policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TxPolicy {
    /// Soft cap on queued frame bytes (headers included). `usize::MAX` = bounded by storage only.
    pub soft_limit: usize,
    /// Packets (payloads) up to this size may exceed the soft limit. 0 disables the exemption.
    pub small_bytes: usize,
    /// How many exempt packets may be queued past the soft limit at once.
    pub small_slots: u8,
}

impl TxPolicy {
    /// No soft limit, the C's 512-byte small-datagram size (`ML_HB_RX_SMALL_BYTES`) and two exempt slots.
    pub const DEFAULT: TxPolicy = TxPolicy { soft_limit: usize::MAX, small_bytes: 512, small_slots: 2 };
}

impl Default for TxPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const LEN_PREFIX: usize = 2;
const EXEMPT_BIT: u16 = 0x8000;

/// A bounded FIFO of whole frames over `N` bytes.
pub struct TxQueue<const N: usize> {
    buf: [u8; N],
    head: usize,
    tail: usize,
    /// End of valid data in the upper segment once the ring has wrapped; `N` otherwise.
    wrap_at: usize,
    count: usize,
    bytes: usize,
    exempt_queued: u8,
    policy: TxPolicy,
}

impl<const N: usize> core::fmt::Debug for TxQueue<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxQueue").field("capacity", &N).field("count", &self.count).field("bytes", &self.bytes).finish()
    }
}

impl<const N: usize> Default for TxQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TxQueue<N> {
    /// An empty queue with the default policy.
    pub const fn new() -> Self {
        Self { buf: [0; N], head: 0, tail: 0, wrap_at: N, count: 0, bytes: 0, exempt_queued: 0, policy: TxPolicy::DEFAULT }
    }

    /// Replace the policy (it applies to later pushes; queued frames stay).
    pub fn set_policy(&mut self, p: TxPolicy) {
        self.policy = p;
    }

    /// The policy.
    pub fn policy(&self) -> TxPolicy {
        self.policy
    }

    /// Frames queued.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Nothing queued?
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Queued frame bytes (headers included, ring padding not).
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Drop everything. Returns how many frames were dropped.
    pub fn clear(&mut self) -> usize {
        let n = self.count;
        self.head = 0;
        self.tail = 0;
        self.wrap_at = N;
        self.count = 0;
        self.bytes = 0;
        self.exempt_queued = 0;
        n
    }

    fn reserve(&mut self, need: usize) -> Option<usize> {
        if self.count == 0 {
            self.head = 0;
            self.tail = 0;
            self.wrap_at = N;
            return (need <= N).then_some(0);
        }
        if self.tail > self.head {
            if self.tail + need <= N {
                Some(self.tail)
            } else if need <= self.head {
                self.wrap_at = self.tail;
                Some(0)
            } else {
                None
            }
        } else if self.tail < self.head {
            (self.tail + need <= self.head).then_some(self.tail)
        } else {
            None
        }
    }

    /// Queue a SendPacket for `dest` carrying `payload`.
    pub fn push_send_packet(&mut self, dest: &[u8; KEY_LEN], payload: &[u8]) -> Result<(), TxDrop> {
        if payload.len() > MAX_FRAME {
            return Err(TxDrop::TooBig);
        }
        let body = KEY_LEN + payload.len();
        let frame = FRAME_HEADER_LEN + body;
        let exempt_class = payload.len() <= self.policy.small_bytes;
        let over = self.bytes.saturating_add(frame) > self.policy.soft_limit;
        let exempt = over && exempt_class && self.exempt_queued < self.policy.small_slots;
        if over && !exempt {
            return Err(TxDrop::OverBudget);
        }
        let need = LEN_PREFIX + frame;
        let Some(off) = self.reserve(need) else { return Err(TxDrop::NoSpace) };
        let tag = frame as u16 | if exempt { EXEMPT_BIT } else { 0 };
        self.buf[off..off + LEN_PREFIX].copy_from_slice(&tag.to_le_bytes());
        let f = off + LEN_PREFIX;
        self.buf[f..f + FRAME_HEADER_LEN].copy_from_slice(&encode_header(FrameType::SEND_PACKET, body as u32));
        self.buf[f + FRAME_HEADER_LEN..f + FRAME_HEADER_LEN + KEY_LEN].copy_from_slice(dest);
        self.buf[f + FRAME_HEADER_LEN + KEY_LEN..f + frame].copy_from_slice(payload);
        self.tail = off + need;
        self.count += 1;
        self.bytes += frame;
        if exempt {
            self.exempt_queued += 1;
        }
        Ok(())
    }

    fn head_entry(&self) -> Option<(usize, bool)> {
        if self.count == 0 {
            return None;
        }
        let tag = u16::from_le_bytes([self.buf[self.head], self.buf[self.head + 1]]);
        Some(((tag & !EXEMPT_BIT) as usize, tag & EXEMPT_BIT != 0))
    }

    /// The oldest frame, ready to write.
    pub fn front(&self) -> Option<&[u8]> {
        let (len, _) = self.head_entry()?;
        Some(&self.buf[self.head + LEN_PREFIX..self.head + LEN_PREFIX + len])
    }

    /// Remove the oldest frame (after it was written in full). Returns false when empty.
    pub fn pop(&mut self) -> bool {
        let Some((len, exempt)) = self.head_entry() else { return false };
        self.head += LEN_PREFIX + len;
        self.count -= 1;
        self.bytes -= len;
        if exempt {
            self.exempt_queued -= 1;
        }
        if self.count == 0 {
            self.head = 0;
            self.tail = 0;
            self.wrap_at = N;
        } else if self.head >= self.wrap_at {
            self.head = 0;
            self.wrap_at = N;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::VecDeque;
    use std::vec::Vec;

    fn expected(dest: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = std::vec![FrameType::SEND_PACKET.0];
        v.extend_from_slice(&((32 + payload.len()) as u32).to_be_bytes());
        v.extend_from_slice(&[dest; 32]);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn fifo_and_frame_layout() {
        let mut q: TxQueue<1024> = TxQueue::new();
        assert!(q.front().is_none());
        q.push_send_packet(&[1; 32], b"hello").unwrap();
        q.push_send_packet(&[2; 32], b"").unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.front().unwrap(), expected(1, b"hello").as_slice());
        assert!(q.pop());
        assert_eq!(q.front().unwrap(), expected(2, b"").as_slice());
        assert!(q.pop());
        assert!(!q.pop());
        assert_eq!((q.len(), q.bytes()), (0, 0));
    }

    #[test]
    fn refusals_are_distinct_and_counted_by_variant() {
        let mut q: TxQueue<512> = TxQueue::new();
        assert_eq!(q.push_send_packet(&[0; 32], &[0; MAX_FRAME + 1]), Err(TxDrop::TooBig));
        assert_eq!(q.push_send_packet(&[0; 32], &[0; 600]), Err(TxDrop::NoSpace));
        q.set_policy(TxPolicy { soft_limit: 100, small_bytes: 0, small_slots: 0 });
        q.push_send_packet(&[0; 32], &[0; 10]).unwrap();
        assert_eq!(q.push_send_packet(&[0; 32], &[0; 100]), Err(TxDrop::OverBudget));
    }

    #[test]
    fn small_exemption_is_bounded_by_slots_and_storage() {
        let mut q: TxQueue<4096> = TxQueue::new();
        q.set_policy(TxPolicy { soft_limit: 300, small_bytes: 100, small_slots: 2 });
        q.push_send_packet(&[0; 32], &[0; 200]).unwrap(); // 237 bytes queued
        assert_eq!(q.push_send_packet(&[0; 32], &[0; 150]), Err(TxDrop::OverBudget)); // big, over budget
        q.push_send_packet(&[0; 32], &[0; 100]).unwrap(); // exempt 1
        q.push_send_packet(&[0; 32], &[0; 50]).unwrap(); // exempt 2
        assert_eq!(q.push_send_packet(&[0; 32], &[0; 50]), Err(TxDrop::OverBudget)); // slots used up
        assert!(q.pop()); // the big one leaves
        assert!(q.pop()); // exempt 1 leaves: its slot is free
        q.push_send_packet(&[0; 32], &[0; 10]).unwrap();
        // a tiny storage still bounds the exemption
        let mut t: TxQueue<100> = TxQueue::new();
        t.set_policy(TxPolicy { soft_limit: 0, small_bytes: 512, small_slots: 8 });
        t.push_send_packet(&[0; 32], &[0; 20]).unwrap();
        assert_eq!(t.push_send_packet(&[0; 32], &[0; 20]), Err(TxDrop::NoSpace));
    }

    #[test]
    fn wraps_without_splitting_a_frame() {
        let mut q: TxQueue<250> = TxQueue::new();
        // each frame is 5 + 32 + 60 = 97 (+2): two fit, a third does not until one is popped
        q.push_send_packet(&[1; 32], &[1; 60]).unwrap();
        q.push_send_packet(&[2; 32], &[2; 60]).unwrap();
        assert_eq!(q.push_send_packet(&[3; 32], &[3; 60]), Err(TxDrop::NoSpace));
        assert!(q.pop());
        q.push_send_packet(&[3; 32], &[3; 60]).unwrap(); // wraps to offset 0
        assert_eq!(q.front().unwrap(), expected(2, &[2; 60]).as_slice());
        assert!(q.pop());
        assert_eq!(q.front().unwrap(), expected(3, &[3; 60]).as_slice());
        assert!(q.pop());
        assert!(q.front().is_none());
    }

    #[derive(Debug, Clone)]
    enum Op {
        Push(u8, usize),
        Pop,
        Policy(usize, usize, u8),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (any::<u8>(), 0usize..700).prop_map(|(d, l)| Op::Push(d, l)),
            3 => Just(Op::Pop),
            1 => (0usize..3000, 0usize..600, 0u8..4).prop_map(|(a, b, c)| Op::Policy(a, b, c)),
        ]
    }

    proptest! {
        /// Against a model: every accepted frame comes out once, in order, intact; refusals are exactly NoSpace or OverBudget; counters agree.
        #[test]
        fn matches_a_fifo_model(ops in proptest::collection::vec(op(), 1..400)) {
            let mut q: TxQueue<2048> = TxQueue::new();
            let mut model: VecDeque<Vec<u8>> = VecDeque::new();
            for o in ops {
                match o {
                    Op::Push(d, l) => {
                        let payload: Vec<u8> = (0..l).map(|i| (i as u8) ^ d).collect();
                        match q.push_send_packet(&[d; 32], &payload) {
                            Ok(()) => model.push_back(expected(d, &payload)),
                            Err(TxDrop::OverBudget) | Err(TxDrop::NoSpace) => {}
                            Err(e) => panic!("{e:?}"),
                        }
                    }
                    Op::Pop => {
                        let want = model.pop_front();
                        prop_assert_eq!(q.front().map(|f| f.to_vec()), want.clone());
                        prop_assert_eq!(q.pop(), want.is_some());
                    }
                    Op::Policy(a, b, c) => q.set_policy(TxPolicy { soft_limit: a, small_bytes: b, small_slots: c }),
                }
                prop_assert_eq!(q.len(), model.len());
                prop_assert_eq!(q.bytes(), model.iter().map(|f| f.len()).sum::<usize>());
                prop_assert!(q.bytes() <= 2048);
            }
            while let Some(want) = model.pop_front() {
                prop_assert_eq!(q.front().unwrap(), want.as_slice());
                prop_assert!(q.pop());
            }
            prop_assert!(q.is_empty());
        }

        /// With no soft limit, a push into a queue that is empty always succeeds when the frame fits the storage.
        #[test]
        fn empty_queue_accepts_what_fits(l in 0usize..=MAX_FRAME) {
            let mut q: TxQueue<2048> = TxQueue::new();
            prop_assert!(q.push_send_packet(&[0; 32], &std::vec![0u8; l]).is_ok());
        }
    }
}
