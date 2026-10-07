//! `check_invariants` and `check_pm` of the C cases: everything the ring believes, recomputed from the bytes.

use std::prelude::v1::*;

use super::world::{Rig, in_crit};
use crate::consts::{CHUNK_SLABS, FRAME_MAX, FRAME_MIN, MAX_CHUNKS, REC_HDR, SLAB_BYTES, align4};
use crate::mem;

impl Rig {
    pub fn capacity_slabs(&self) -> u32 {
        self.ring.with_state(|st| st.base_slabs + st.chunks_live * CHUNK_SLABS as u32)
    }

    pub fn chunk_present(&self, c: usize) -> bool {
        self.ring.with_state(|st| !st.chunk[c].mem.is_null())
    }

    pub fn chunks_present(&self) -> u32 {
        self.ring.with_state(|st| st.chunks_present)
    }

    pub fn fifo_n(&self) -> u32 {
        self.ring.with_state(|st| st.fifo_n)
    }

    /// The sequence numbers of the frames in the ring, oldest first, read from the bytes.
    pub fn queued_seqs(&self) -> Vec<u32> {
        self.ring.with_state(|st| {
            let mut out = Vec::new();
            for i in 0..st.fifo_n {
                let s = u32::from(st.fifo[((st.fifo_head + i) & 31) as usize]);
                let sl = st.slab[s as usize];
                let mut off = usize::from(sl.rd);
                while off < usize::from(sl.fill) {
                    let at = st.slab_ptr(s).wrapping_add(off).cast_const();
                    // SAFETY: a committed record (`off < fill`) of a slab in the FIFO, read under the lock while no producer or consumer runs
                    // (single-threaded test); the payload's first four bytes are the sequence number.
                    let (len, _) = unsafe { mem::read_header(at) };
                    // SAFETY: as above; the payload is `len >= 14` initialised bytes.
                    let p = unsafe { mem::payload(at, usize::from(len)) };
                    out.push(u32::from_le_bytes([p[0], p[1], p[2], p[3]]));
                    off += REC_HDR + align4(usize::from(len));
                }
            }
            out
        })
    }

    pub fn check_invariants(&self) {
        assert!(!in_crit());
        let max_chunks_cfg = self.ring.config().max_chunks;
        let probe = self.ring.probe();
        let blocks = self.w().heap_live_blocks.load(std::sync::atomic::Ordering::SeqCst);
        let (present, base) = self.ring.with_state(|st| {
            let base = st.base_slabs;
            let mut in_fifo = 0u32;
            let (mut frames, mut bytes) = (0u32, 0u32);
            let mut chunk_used = [0u32; MAX_CHUNKS];
            assert!(st.fifo_n <= 32 && st.reading == -1);
            for i in 0..st.fifo_n {
                let s = u32::from(st.fifo[((st.fifo_head + i) & 31) as usize]);
                assert_eq!((in_fifo >> s) & 1, 0, "a slab appears twice in the FIFO");
                in_fifo |= 1 << s;
                let sl = st.slab[s as usize];
                assert!(sl.rd <= sl.fill && sl.fill <= sl.resv && usize::from(sl.resv) <= SLAB_BYTES);
                if i + 1 < st.fifo_n {
                    assert_eq!(sl.resv, sl.fill, "sealed: nothing reserved beyond what was committed");
                }
                if s >= base {
                    let c = ((s - base) as usize) / CHUNK_SLABS;
                    assert!(!st.chunk[c].mem.is_null());
                    chunk_used[c] += 1;
                }
                let mut off = usize::from(sl.rd);
                while off < usize::from(sl.fill) {
                    // SAFETY: a committed record of a slab in the FIFO, read under the lock in a single-threaded test.
                    let (len, _) = unsafe { mem::read_header(st.slab_ptr(s).wrapping_add(off).cast_const()) };
                    assert!((FRAME_MIN..=FRAME_MAX).contains(&usize::from(len)));
                    let rec = REC_HDR + align4(usize::from(len));
                    off += rec;
                    frames += 1;
                    bytes += rec as u32;
                }
                assert_eq!(off, usize::from(sl.fill));
            }
            assert!(frames == st.frames_queued && bytes == st.used_bytes);
            assert_eq!(st.alloc_mask & in_fifo, 0);
            if st.frames_queued == 0 {
                assert!(st.fifo_n <= 1);
            }
            let (mut present, mut live) = (0, 0);
            for (c, ch) in st.chunk.iter().enumerate() {
                if ch.mem.is_null() {
                    assert!(ch.used == 0 && !ch.retiring);
                    assert_eq!(st.alloc_mask & st.chunk_mask(c as u32), 0);
                    continue;
                }
                present += 1;
                if !ch.retiring {
                    live += 1;
                }
                assert_eq!(u32::from(ch.used), chunk_used[c]);
                if ch.retiring {
                    assert_eq!(st.alloc_mask & st.chunk_mask(c as u32), 0);
                }
            }
            assert!(present == st.chunks_present && live == st.chunks_live && present <= max_chunks_cfg);
            // A slab that exists, is not queued and is not retiring must be allocatable, and nothing else is.
            for s in 0..base + (MAX_CHUNKS * CHUNK_SLABS) as u32 {
                let ci = ((s.wrapping_sub(base)) as usize) / CHUNK_SLABS;
                let exists = s < base || !st.chunk[ci].mem.is_null();
                let retiring = s >= base && st.chunk[ci].retiring;
                let queued = (in_fifo >> s) & 1 == 1;
                let allocatable = (st.alloc_mask >> s) & 1 == 1;
                assert_eq!(allocatable, exists && !retiring && !queued, "slab {s}");
            }
            assert!(base + st.chunks_live * CHUNK_SLABS as u32 <= base + max_chunks_cfg * CHUNK_SLABS as u32);
            assert_eq!(probe.pm_want, st.frames_queued > 0);
            (present, base)
        });
        let _ = base;
        assert_eq!(blocks, 1 + i64::from(present), "heap blocks held: the base plus one per present chunk");
        assert_eq!(probe.present_mirror, present);
    }

    /// After a worker wakeup, the CPU-frequency lock is held exactly while frames are queued (`check_pm`).
    pub fn check_pm(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        let w = self.w();
        let held = w.pm_held.load(SeqCst);
        let q = self.queued();
        assert_eq!(held, i32::from(q > 0), "the hold follows the queue");
        assert_eq!(w.pm_acquires.load(SeqCst) - w.pm_releases.load(SeqCst), held);
        let st = self.stats();
        assert!(w.pm_acquires.load(SeqCst) as u32 == st.pm_acquired && w.pm_releases.load(SeqCst) as u32 == st.pm_released);
    }
}
