//! Heap queries and the one elastic allocation the firmware makes (the USB ring's chunks). Internal RAM only: the T-Dongle-S3 has no PSRAM.

use core::ptr::NonNull;

use esp_idf_svc::sys;

const INTERNAL: u32 = sys::MALLOC_CAP_INTERNAL;

/// `heap_caps_get_free_size(MALLOC_CAP_INTERNAL)`: O(1).
#[inline]
pub fn free_internal() -> usize {
    // SAFETY: no preconditions.
    unsafe { sys::heap_caps_get_free_size(INTERNAL) }
}

/// `heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)`: walks the heap with its lock held.
#[inline]
pub fn largest_free_block() -> usize {
    // SAFETY: no preconditions.
    unsafe { sys::heap_caps_get_largest_free_block(INTERNAL) }
}

/// The lowest free internal heap since boot (`heap_caps_get_minimum_free_size`): the "heap floor" of ADR 0022 as the board measures it.
#[inline]
pub fn minimum_free_internal() -> usize {
    // SAFETY: no preconditions.
    unsafe { sys::heap_caps_get_minimum_free_size(INTERNAL) }
}

/// `esp_get_free_heap_size()`: what the serial `status` line `free_heap=` prints.
#[inline]
pub fn free_heap_size() -> u32 {
    // SAFETY: no preconditions.
    unsafe { sys::esp_get_free_heap_size() }
}

/// `heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)`. Returns `None` when the allocator refuses.
pub fn alloc_internal(size: usize) -> Option<NonNull<u8>> {
    // SAFETY: a plain allocation request; the result is either null or `size` writable bytes.
    NonNull::new(unsafe { sys::heap_caps_malloc(size, INTERNAL | sys::MALLOC_CAP_8BIT) }.cast())
}

/// `heap_caps_free`.
///
/// # Safety
/// `block` must have been returned by [`alloc_internal`] and not freed since.
pub unsafe fn free_internal_block(block: NonNull<u8>) {
    // SAFETY: forwarded to the caller.
    unsafe { sys::heap_caps_free(block.as_ptr().cast()) }
}
