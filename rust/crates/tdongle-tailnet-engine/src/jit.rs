//! The bounded queue of packets parked while a peer's handshake runs (`ml_gateway_queue_packet`, `gateway_egress_packet`, `directory_flush_packets`;
//! ADR 0012, ADR 0018, `tests/test_jit_queue.c`).
//!
//! What the C pins, kept here:
//!
//! * each membership parks at most [`JIT_PENDING`] packets (the C counts queued and parked ones together; here nothing is queued: the engine is called
//!   synchronously), each waits at most [`JIT_EXPIRY_MS`] (5 s) and is dropped when its peer disappears;
//! * ordering: packets of one peer leave in arrival order, and a new packet never overtakes a parked one for the same peer;
//! * every failure path gives back what it took: nothing leaks (`Engine::check_identities` compares the queues' blocks with the arena's).
//!
//! The C parks `struct pbuf`s on the heap and the heap budget (`HbSite::Jit`) decides. Without an allocator the bytes come from a shared arena of
//! `BLOCKS` blocks of [`JIT_BLOCK`] bytes ([`JitStore`]): a packet takes `ceil(len / 256)` blocks (not necessarily adjacent), and an empty arena is the
//! same counted refusal as an empty heap.

use tdongle_tailnet_types::Millis;

/// Packets one membership may have parked (`ML_JIT_PENDING`).
pub const JIT_PENDING: usize = 8;
/// The longest a parked packet waits (5 s).
pub const JIT_EXPIRY_MS: Millis = 5_000;
/// Bytes of one arena block.
pub const JIT_BLOCK: usize = 256;
/// Largest parked packet (`ML_JIT_PACKET_MAX`).
pub const JIT_PACKET_MAX: usize = 1400;
const MAX_BLOCKS: usize = JIT_PACKET_MAX.div_ceil(JIT_BLOCK);

/// Why a packet was not parked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParkRefusal {
    /// The membership already has [`JIT_PENDING`] parked packets (or the packet is longer than [`JIT_PACKET_MAX`]).
    Budget,
    /// The arena has no room.
    NoBlocks,
}

#[derive(Clone, Copy, Debug)]
struct Blocks {
    ids: [u8; MAX_BLOCKS],
    n: u8,
}

/// The shared byte arena of parked packets.
#[derive(Debug)]
pub struct JitStore<const BLOCKS: usize> {
    store: [[u8; JIT_BLOCK]; BLOCKS],
    used: [bool; BLOCKS],
    used_n: usize,
    peak: usize,
}

impl<const BLOCKS: usize> Default for JitStore<BLOCKS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BLOCKS: usize> JitStore<BLOCKS> {
    /// Bytes of the arena.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// Empty arena.
    #[inline(always)]
    pub const fn new() -> Self {
        Self { store: [[0; JIT_BLOCK]; BLOCKS], used: [false; BLOCKS], used_n: 0, peak: 0 }
    }
    /// Blocks in use.
    pub fn used_blocks(&self) -> usize {
        self.used_n
    }
    /// Most blocks ever in use.
    pub fn peak_blocks(&self) -> usize {
        self.peak
    }
    fn alloc(&mut self, len: usize) -> Option<Blocks> {
        let need = len.div_ceil(JIT_BLOCK).max(1);
        if need > MAX_BLOCKS || BLOCKS - self.used_n < need || BLOCKS > 255 {
            return None;
        }
        let mut b = Blocks { ids: [0; MAX_BLOCKS], n: 0 };
        for (i, u) in self.used.iter_mut().enumerate() {
            if !*u {
                *u = true;
                b.ids[b.n as usize] = i as u8;
                b.n += 1;
                if b.n as usize == need {
                    break;
                }
            }
        }
        self.used_n += need;
        self.peak = self.peak.max(self.used_n);
        Some(b)
    }
    fn free(&mut self, b: &Blocks) {
        for &id in &b.ids[..b.n as usize] {
            if core::mem::replace(&mut self.used[id as usize], false) {
                self.used_n -= 1;
            }
            self.store[id as usize].fill(0);
        }
    }
    fn write(&mut self, b: &Blocks, data: &[u8]) {
        for (k, chunk) in data.chunks(JIT_BLOCK).enumerate() {
            self.store[b.ids[k] as usize][..chunk.len()].copy_from_slice(chunk);
        }
    }
    fn read(&self, b: &Blocks, len: usize, out: &mut [u8]) {
        let mut at = 0;
        for k in 0..b.n as usize {
            let n = (len - at).min(JIT_BLOCK);
            out[at..at + n].copy_from_slice(&self.store[b.ids[k] as usize][..n]);
            at += n;
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Parked {
    peer_ip: u32,
    len: u16,
    expires: Millis,
    seq: u32,
    blocks: Blocks,
}

/// One membership's parked packets.
#[derive(Debug)]
pub struct ParkQueue {
    slot: [Option<Parked>; JIT_PENDING],
    seq: u32,
}

impl Default for ParkQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl ParkQueue {
    /// Bytes of the queue's bookkeeping.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// Empty.
    #[inline(always)]
    pub const fn new() -> Self {
        Self { slot: [None; JIT_PENDING], seq: 0 }
    }
    /// Packets parked.
    pub fn len(&self) -> usize {
        self.slot.iter().flatten().count()
    }
    /// Nothing parked?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Does any parked packet wait for `peer_ip`?
    pub fn has_peer(&self, peer_ip: u32) -> bool {
        self.slot.iter().flatten().any(|p| p.peer_ip == peer_ip)
    }
    /// Park `plain` for `peer_ip` until `now + 5 s`.
    pub fn park<const B: usize>(&mut self, store: &mut JitStore<B>, peer_ip: u32, plain: &[u8], now: Millis) -> Result<(), ParkRefusal> {
        if plain.len() > JIT_PACKET_MAX {
            return Err(ParkRefusal::Budget);
        }
        let Some(free) = self.slot.iter().position(Option::is_none) else { return Err(ParkRefusal::Budget) };
        let blocks = store.alloc(plain.len()).ok_or(ParkRefusal::NoBlocks)?;
        store.write(&blocks, plain);
        self.seq = self.seq.wrapping_add(1);
        self.slot[free] = Some(Parked { peer_ip, len: plain.len() as u16, expires: now + JIT_EXPIRY_MS, seq: self.seq, blocks });
        Ok(())
    }
    /// The index of the oldest parked packet of `peer_ip` (arrival order, not slot order).
    pub fn oldest_for(&self, peer_ip: u32) -> Option<usize> {
        let mut best: Option<(usize, u32)> = None;
        for (i, p) in self.slot.iter().enumerate() {
            if let Some(p) = p
                && p.peer_ip == peer_ip
                && best.is_none_or(|(_, s)| (p.seq.wrapping_sub(s) as i32) < 0)
            {
                best = Some((i, p.seq));
            }
        }
        best.map(|b| b.0)
    }
    /// Copy packet `i` into `out` (which must hold [`JIT_PACKET_MAX`] bytes), free it and return its length.
    pub fn take<const B: usize>(&mut self, store: &mut JitStore<B>, i: usize, out: &mut [u8]) -> Option<usize> {
        let p = self.slot.get_mut(i)?.take()?;
        let len = usize::from(p.len);
        store.read(&p.blocks, len, out);
        store.free(&p.blocks);
        Some(len)
    }
    /// Drop every packet that has waited 5 s; returns how many.
    pub fn expire<const B: usize>(&mut self, store: &mut JitStore<B>, now: Millis) -> usize {
        let mut n = 0;
        for s in &mut self.slot {
            if let Some(p) = s
                && now >= p.expires
            {
                store.free(&p.blocks);
                *s = None;
                n += 1;
            }
        }
        n
    }
    /// Drop every packet parked for `peer_ip`; returns how many.
    pub fn drop_peer<const B: usize>(&mut self, store: &mut JitStore<B>, peer_ip: u32) -> usize {
        let mut n = 0;
        for s in &mut self.slot {
            if let Some(p) = s
                && p.peer_ip == peer_ip
            {
                store.free(&p.blocks);
                *s = None;
                n += 1;
            }
        }
        n
    }
    /// Drop everything; returns how many.
    pub fn drop_all<const B: usize>(&mut self, store: &mut JitStore<B>) -> usize {
        let mut n = 0;
        for s in &mut self.slot {
            if let Some(p) = s.take() {
                store.free(&p.blocks);
                n += 1;
            }
        }
        n
    }
    /// The earliest expiry (the engine's wake).
    pub fn next_expiry(&self) -> Option<Millis> {
        self.slot.iter().flatten().map(|p| p.expires).min()
    }
    /// Blocks this queue holds.
    pub fn blocks(&self) -> usize {
        self.slot.iter().flatten().map(|p| usize::from(p.blocks.n)).sum()
    }
    /// Peer addresses of parked packets (for the orphan check): calls `f` once per packet.
    pub fn for_each_peer(&self, mut f: impl FnMut(u32)) {
        for p in self.slot.iter().flatten() {
            f(p.peer_ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_arena_order_and_no_leak() {
        let mut st = JitStore::<12>::new();
        let mut q = ParkQueue::new();
        for i in 0..JIT_PENDING {
            q.park(&mut st, 1, &[i as u8; 40], 100).unwrap();
        }
        assert_eq!(q.park(&mut st, 1, &[9; 4], 100), Err(ParkRefusal::Budget));
        assert_eq!(st.used_blocks(), 8);
        // arrival order across a freed low slot
        let mut out = [0u8; JIT_PACKET_MAX];
        let i = q.oldest_for(1).unwrap();
        assert_eq!(q.take(&mut st, i, &mut out), Some(40));
        assert_eq!(out[0], 0);
        q.park(&mut st, 1, &[99; 300], 100).unwrap(); // takes the freed slot 0 and two blocks
        for want in 1..8u8 {
            let i = q.oldest_for(1).unwrap();
            q.take(&mut st, i, &mut out).unwrap();
            assert_eq!(out[0], want);
        }
        let i = q.oldest_for(1).unwrap();
        assert_eq!(q.take(&mut st, i, &mut out), Some(300));
        assert!(out[..300].iter().all(|&b| b == 99));
        assert_eq!((q.len(), st.used_blocks()), (0, 0));
        // arena exhaustion is its own refusal and leaks nothing
        q.park(&mut st, 2, &[1; 1400], 0).unwrap();
        q.park(&mut st, 2, &[1; 1400], 0).unwrap();
        assert_eq!(q.park(&mut st, 2, &[1; 1400], 0), Err(ParkRefusal::NoBlocks));
        assert_eq!(q.blocks(), st.used_blocks());
        assert_eq!(q.expire(&mut st, 4_999), 0);
        assert_eq!(q.expire(&mut st, 5_000), 2);
        assert_eq!(st.used_blocks(), 0);
        assert_eq!(q.park(&mut st, 2, &[1; 1401], 0), Err(ParkRefusal::Budget));
    }

    #[test]
    fn drop_peer_and_all() {
        let mut st = JitStore::<8>::new();
        let mut q = ParkQueue::new();
        q.park(&mut st, 1, &[1; 10], 0).unwrap();
        q.park(&mut st, 2, &[2; 10], 0).unwrap();
        q.park(&mut st, 1, &[3; 10], 0).unwrap();
        assert_eq!(q.drop_peer(&mut st, 1), 2);
        assert!(!q.has_peer(1) && q.has_peer(2));
        assert_eq!(q.drop_all(&mut st), 1);
        assert_eq!(st.used_blocks(), 0);
    }
}
