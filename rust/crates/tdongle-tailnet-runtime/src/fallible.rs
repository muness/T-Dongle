//! Boxes that report allocation failure. `Box::new` and `Box::pin` call the allocator's out-of-memory handler when the heap cannot serve the block, and on the board that
//! handler is a panic and a reset (`alloc.rs:573`, the control plane retrying with the heap fragmented). Every box the runtime makes after start-up goes through here, so
//! a refused block is an error the caller handles (the attempt fails and is retried later), never a reset.
#![allow(unsafe_code)]

use alloc::boxed::Box;
use core::alloc::Layout;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};

/// Boxes refused for want of a block (`tn-mem`).
pub static BOX_REFUSED: AtomicU32 = AtomicU32::new(0);

/// `Box::new(v)`, or `Err(v)` back when the allocator has no block for it.
pub fn try_box<T>(v: T) -> Result<Box<T>, T> {
    let layout = Layout::new::<T>();
    if layout.size() == 0 {
        return Ok(Box::new(v)); // no allocation
    }
    // SAFETY: `layout` has a non-zero size (checked above).
    let p = unsafe { alloc::alloc::alloc(layout) }.cast::<T>();
    if p.is_null() {
        BOX_REFUSED.fetch_add(1, Ordering::Relaxed);
        return Err(v);
    }
    // SAFETY: `p` is a fresh, non-null allocation of `Layout::new::<T>()` from the global allocator, which is exactly what `Box::from_raw` requires; `write` moves `v` in
    // without reading or dropping the uninitialised memory.
    unsafe {
        p.write(v);
        Ok(Box::from_raw(p))
    }
}

/// A box of `make()`, or `None` (and `make` never runs) when the allocator has no block for a `T`. The block is taken first and the value written straight into it: for a
/// big `T` (the 17 KB negotiation workspace) there is no second copy of it in the caller's frame, as there would be in a `Result<Box<T>, T>`.
#[inline(always)]
pub fn try_box_with<T>(make: impl FnOnce() -> T) -> Option<Box<T>> {
    let layout = Layout::new::<T>();
    if layout.size() == 0 {
        return Some(Box::new(make()));
    }
    // SAFETY: as in `try_box`.
    let p = unsafe { alloc::alloc::alloc(layout) }.cast::<T>();
    if p.is_null() {
        BOX_REFUSED.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    // SAFETY: as in `try_box`. If `make` panics the block leaks, and a panic resets the chip anyway.
    unsafe {
        p.write(make());
        Some(Box::from_raw(p))
    }
}

/// `Box::pin(v)`, or `Err(v)` back when the allocator has no block for it.
pub fn try_box_pin<T>(v: T) -> Result<Pin<Box<T>>, T> {
    try_box(v).map(Box::into_pin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;

    #[test]
    fn a_box_holds_the_value_and_drops_it() {
        let b = try_box([7u8; 3000]).ok().unwrap();
        assert!(b.iter().all(|&x| x == 7));
        let rc = std::rc::Rc::new(());
        let b = try_box(rc.clone()).ok().unwrap();
        assert_eq!(std::rc::Rc::strong_count(&rc), 2);
        drop(b);
        assert_eq!(std::rc::Rc::strong_count(&rc), 1);
    }

    #[test]
    fn zero_sized_and_over_aligned_values() {
        assert!(try_box(()).is_ok());
        #[repr(align(64))]
        struct A(u8);
        let b = try_box(A(5)).ok().unwrap();
        assert_eq!((&*b as *const A as usize) % 64, 0);
        assert_eq!(b.0, 5);
    }

    #[test]
    fn with_builds_the_value_in_the_box() {
        let b = try_box_with(|| [3u16; 5000]).unwrap();
        assert!(b.iter().all(|&x| x == 3));
        assert!(try_box_with(|| ()).is_some());
    }

    #[test]
    fn a_pinned_future_runs() {
        let mut f = try_box_pin(async { 41 + 1 }).ok().unwrap();
        let w = futures::task::noop_waker();
        let mut cx = core::task::Context::from_waker(&w);
        assert_eq!(f.as_mut().poll(&mut cx), core::task::Poll::Ready(42));
    }
}
