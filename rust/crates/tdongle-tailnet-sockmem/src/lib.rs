//! `SockMem` over the heap and the shared pool: socket windows and packet metadata as `&'static mut` slices, reclaimed by address.
//!
//! embassy-net's sockets take their buffers as `&'a mut [..]` and store them as `'static` internally (`TcpSocket::new` transmutes); once a socket owns a
//! slice it cannot hand it back, and the runtime, which forbids `unsafe`, cannot free a leaked box. So the free path works from what the runtime kept: the
//! address and length. This crate keeps a small table of the blocks it handed out, and [`HeapSockMem::give`] reclaims a block **only if the table has it
//! with exactly that address and length** (anything else is ignored and counted), turning the pointer back into the `Box` it came from.
//!
//! # Safety contract (what makes the two `unsafe` blocks sound)
//!
//! * a block is created here by `Box::leak` of a `Box<[T]>` and recorded; it is freed at most once (the table entry is removed first);
//! * `give` is called by `EmbTcp` / `EmbUdp` only **after** the socket that owned the slice has been dropped (`EmbTcp::drop_socket`, `EmbUdp::close`), so
//!   no reference to the block is live when it is freed: the runtime's one obligation, kept by construction (the slices are moved into the socket, the
//!   handle keeps integers only).
//!
//! Every allocation is admitted by the [`tdongle_tailnet_pool::Pool`] first ([`tdongle_tailnet_pool::Class::Socket`]: after taking it the heap floor stays
//! free) and the bytes are refunded on `give`, so `Pool::in_use` is exact.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};
use embassy_net::udp::PacketMetadata;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use tdongle_tailnet_pool::{Class, Mem};
use tdongle_tailnet_runtime::net_embassy::SockMem;

/// Blocks that can be out at once: per membership 4 TCP windows + 2 UDP rings + 2 metadata arrays, three memberships, the DNS forwarder's 4, and slack.
const TABLE: usize = 40;

#[derive(Clone, Copy)]
struct Entry {
    addr: usize,
    /// Length in elements.
    len: usize,
    /// `true`: `PacketMetadata`; `false`: bytes.
    meta: bool,
}

/// The adapter. Put one in a `static` next to the shared state (it borrows the pool and the probe for `'static`).
pub struct HeapSockMem {
    mem: Mem<'static>,
    table: Mutex<CriticalSectionRawMutex, RefCell<[Option<Entry>; TABLE]>>,
    given_unknown: AtomicU32,
}

impl core::fmt::Debug for HeapSockMem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeapSockMem").field("out", &self.out()).field("given_unknown", &self.given_unknown()).finish()
    }
}

impl HeapSockMem {
    /// Over the pool and heap probe of the shared state.
    pub const fn new(mem: Mem<'static>) -> Self {
        Self { mem, table: Mutex::new(RefCell::new([None; TABLE])), given_unknown: AtomicU32::new(0) }
    }

    /// Blocks handed out and not yet given back.
    pub fn out(&self) -> usize {
        self.table.lock(|t| t.borrow().iter().flatten().count())
    }

    /// `give` calls that named no block of the table (a bug in the caller; the call was ignored).
    pub fn given_unknown(&self) -> u32 {
        self.given_unknown.load(Ordering::Relaxed)
    }

    fn record(&self, e: Entry) -> bool {
        self.table.lock(|t| {
            let mut t = t.borrow_mut();
            match t.iter_mut().find(|s| s.is_none()) {
                Some(s) => {
                    *s = Some(e);
                    true
                }
                None => false,
            }
        })
    }

    fn unrecord(&self, e: Entry) -> bool {
        self.table.lock(|t| {
            let mut t = t.borrow_mut();
            match t.iter_mut().find(|s| matches!(s, Some(x) if x.addr == e.addr && x.len == e.len && x.meta == e.meta)) {
                Some(s) => {
                    *s = None;
                    true
                }
                None => false,
            }
        })
    }
}

impl SockMem for HeapSockMem {
    fn take(&self, len: usize) -> Option<&'static mut [u8]> {
        if len == 0 || self.mem.charge(Class::Socket, len).is_err() {
            return None;
        }
        let mut v: Vec<u8> = Vec::new();
        if v.try_reserve_exact(len).is_err() {
            self.mem.refund(len);
            return None;
        }
        v.resize(len, 0);
        let leaked: &'static mut [u8] = Box::leak(v.into_boxed_slice());
        if !self.record(Entry { addr: leaked.as_ptr() as usize, len, meta: false }) {
            // the table is full: nothing may be handed out that `give` could not find again. Free it here (no reference to it exists yet).
            let p: *mut [u8] = leaked;
            // SAFETY: `p` is the pointer `Box::leak` just returned, nothing else holds it (it was not recorded and not returned), freed exactly once.
            drop(unsafe { Box::from_raw(p) });
            self.mem.refund(len);
            return None;
        }
        Some(leaked)
    }

    fn give(&self, addr: usize, len: usize) {
        if !self.unrecord(Entry { addr, len, meta: false }) {
            self.given_unknown.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let p = core::ptr::slice_from_raw_parts_mut(addr as *mut u8, len);
        // SAFETY: `(addr, len)` was in the table, so it is a block `take` leaked from a `Box<[u8]>` of this length and the entry is gone: freed once. The socket
        // that held the slice was dropped before `give` (module docs), so no reference to it is live.
        drop(unsafe { Box::from_raw(p) });
        self.mem.refund(len);
    }

    fn take_meta(&self, n: usize) -> Option<&'static mut [PacketMetadata]> {
        let bytes = n * core::mem::size_of::<PacketMetadata>();
        if n == 0 || self.mem.charge(Class::Socket, bytes).is_err() {
            return None;
        }
        let mut v: Vec<PacketMetadata> = Vec::new();
        if v.try_reserve_exact(n).is_err() {
            self.mem.refund(bytes);
            return None;
        }
        v.resize(n, PacketMetadata::EMPTY);
        let leaked: &'static mut [PacketMetadata] = Box::leak(v.into_boxed_slice());
        if !self.record(Entry { addr: leaked.as_ptr() as usize, len: n, meta: true }) {
            let p: *mut [PacketMetadata] = leaked;
            // SAFETY: as in `take`: the pointer `Box::leak` just returned, unrecorded and unreturned, freed once.
            drop(unsafe { Box::from_raw(p) });
            self.mem.refund(bytes);
            return None;
        }
        Some(leaked)
    }

    fn give_meta(&self, addr: usize, n: usize) {
        if !self.unrecord(Entry { addr, len: n, meta: true }) {
            self.given_unknown.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let p = core::ptr::slice_from_raw_parts_mut(addr as *mut PacketMetadata, n);
        // SAFETY: as in `give`, for the `Box<[PacketMetadata]>` `take_meta` leaked.
        drop(unsafe { Box::from_raw(p) });
        self.mem.refund(n * core::mem::size_of::<PacketMetadata>());
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
