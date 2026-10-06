//! The only raw-memory accesses of the crate: reading and writing records inside slabs.
//!
//! Every function is `unsafe` with a precise contract; every call site in `ring.rs` states which ownership rule of the ring's protocol
//! (reserve/commit for the producer, peek/advance for the consumer, "a slab in the FIFO is never freed") establishes it. Records are accessed
//! byte-wise (`copy_nonoverlapping`), so no alignment is assumed of the base block or of a chunk.

use crate::consts::REC_HDR;

/// Read the `len` field of the record at `rec`.
///
/// # Safety
///
/// `rec` points to at least [`REC_HDR`] initialised bytes of a committed record (below its slab's `fill`) that no thread writes.
pub(crate) unsafe fn read_header(rec: *const u8) -> (u16, u16) {
    let mut raw = [0u8; REC_HDR];
    // SAFETY: the caller guarantees `REC_HDR` readable, initialised, unwritten bytes at `rec`; `raw` is a distinct local array.
    unsafe { core::ptr::copy_nonoverlapping(rec, raw.as_mut_ptr(), REC_HDR) };
    (u16::from_ne_bytes([raw[0], raw[1]]), u16::from_ne_bytes([raw[2], raw[3]]))
}

/// Write `[len][gen][payload]` at `dst`.
///
/// # Safety
///
/// `dst` points to at least `REC_HDR + payload.len()` writable bytes that the caller owns exclusively (a producer's reserved range, between
/// `reserve` and `commit`: no other thread reads or writes them), and that do not overlap `payload`.
pub(crate) unsafe fn write_record(dst: *mut u8, len: u16, gen_: u16, payload: &[u8]) {
    let l = len.to_ne_bytes();
    let g = gen_.to_ne_bytes();
    let hdr = [l[0], l[1], g[0], g[1]];
    // SAFETY: the caller guarantees `REC_HDR + payload.len()` exclusively owned writable bytes at `dst` that do not overlap `payload`; the
    // header source is a local array, so the first copy cannot overlap either.
    unsafe {
        core::ptr::copy_nonoverlapping(hdr.as_ptr(), dst, REC_HDR);
        core::ptr::copy_nonoverlapping(payload.as_ptr(), dst.add(REC_HDR), payload.len());
    }
}

/// The payload of the committed record at `rec`, `len` bytes.
///
/// # Safety
///
/// `rec` points to a committed record whose payload is `len` initialised bytes; the returned slice must not outlive the consumer's ownership
/// of the record (between peek and advance), during which no thread writes it and its slab and chunk stay allocated.
pub(crate) unsafe fn payload<'a>(rec: *const u8, len: usize) -> &'a [u8] {
    // SAFETY: the caller guarantees `len` initialised, unwritten bytes after the header for the whole of `'a`.
    unsafe { core::slice::from_raw_parts(rec.add(REC_HDR), len) }
}
