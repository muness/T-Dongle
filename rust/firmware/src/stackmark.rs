//! The stack's high-water mark: what `uxTaskGetStackHighWaterMark` reports in the C (`control_stack_free_bytes`, `stack_free_bytes`).
//!
//! The Rust firmware has one stack: the thread executor and the interrupt executor's handlers run on it (embassy tasks are futures in static memory, not tasks with
//! stacks of their own). At boot, right after the rescue is armed, everything below the stack pointer is painted with a pattern; the lowest word that no longer holds it
//! is the deepest the stack has been. [`free_bytes`] scans up from the bottom of the stack for the first word that is not the pattern. A word that was written with the
//! pattern's value by the program itself would hide a few bytes; the pattern is not a value a stack holds on purpose.

use core::sync::atomic::{AtomicBool, Ordering};

const PATTERN: u32 = 0x5AC4_57AC;

unsafe extern "C" {
    static mut _stack_start: u32;
    static mut _stack_end: u32;
}

static PAINTED: AtomicBool = AtomicBool::new(false);

fn bounds() -> (usize, usize) {
    // SAFETY: only the addresses of the linker's symbols are taken.
    unsafe { (core::ptr::addr_of!(_stack_end) as usize, core::ptr::addr_of!(_stack_start) as usize) }
}

/// Paint the unused stack. Call once, early, from the thread that owns the stack (the main task before it spawns anything).
#[inline(never)]
pub fn paint() {
    let (bottom, top) = bounds();
    let sp: usize;
    // SAFETY: reads the stack pointer register.
    unsafe { core::arch::asm!("mov {0}, a1", out(reg) sp) };
    // leave a margin under the live frame (this function's own and what the caller still has to call)
    let end = sp.saturating_sub(256).min(top) & !3;
    let mut p = bottom;
    while p < end {
        // SAFETY: the range is the unused part of the stack: below the stack pointer, above the stack's end.
        unsafe { (p as *mut u32).write_volatile(PATTERN) };
        p += 4;
    }
    PAINTED.store(true, Ordering::Release);
}

/// Bytes of the stack never used so far (`u32::MAX` when the stack was not painted).
pub fn free_bytes() -> u32 {
    if !PAINTED.load(Ordering::Acquire) {
        return u32::MAX;
    }
    let (bottom, top) = bounds();
    let mut p = bottom;
    // SAFETY: reads words of the stack's own region.
    while p < top && unsafe { (p as *const u32).read_volatile() } == PATTERN {
        p += 4;
    }
    (p - bottom) as u32
}
