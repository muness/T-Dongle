//! Explicit split: driver/internal allocations remain internal, bulk application state is PSRAM.
use core::sync::atomic::{AtomicUsize, Ordering};
static EXTERNAL_START: AtomicUsize = AtomicUsize::new(0);
static EXTERNAL_BYTES: AtomicUsize = AtomicUsize::new(0);
pub fn external_bytes() -> usize {
    EXTERNAL_BYTES.load(Ordering::Relaxed)
}
pub fn external_contains(ptr: *const u8, size: usize) -> bool {
    let start = EXTERNAL_START.load(Ordering::Relaxed);
    let bytes = external_bytes();
    let address = ptr as usize;
    address >= start && size <= bytes && address - start <= bytes - size
}
use core::alloc::{GlobalAlloc, Layout};
use esp_alloc::{HEAP, HeapRegion, MemoryCapability};
pub const INTERNAL_HEAP: usize = 96 * 1024;
pub const EXTERNAL_HEAP: usize = 8 * 1024 * 1024;
const BULK_MIN: usize = 512;
const INTERNAL_RESERVE: usize = 32 * 1024;
struct ApplicationAllocator;
#[global_allocator]
static ALLOCATOR: ApplicationAllocator = ApplicationAllocator;
// SAFETY: both allocations and deallocations use HEAP, which tracks ownership of every region.
unsafe impl GlobalAlloc for ApplicationAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let internal =
            external_bytes() == 0 || (layout.size() < BULK_MIN && HEAP.free_caps(MemoryCapability::Internal.into()) >= INTERNAL_RESERVE + layout.size());
        let caps = if internal { MemoryCapability::Internal } else { MemoryCapability::External };
        unsafe { HEAP.alloc_caps(caps.into(), layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { GlobalAlloc::dealloc(&HEAP, ptr, layout) }
    }
}
pub fn init(peripheral: esp_hal::peripherals::PSRAM<'static>, recovery: bool) {
    esp_alloc::heap_allocator!(size: INTERNAL_HEAP);
    // Recovery never retries faulty PSRAM initialization; keep USB console available.
    if recovery {
        return;
    }
    // HAL initialization precedes every application allocation. Radio allocator requests Internal explicitly.
    let psram = esp_hal::psram::Psram::new(peripheral, Default::default());
    let (start, bytes) = psram.raw_parts();
    assert!(bytes >= EXTERNAL_HEAP, "C5 requires the board's 8 MB PSRAM");
    unsafe { HEAP.add_region(HeapRegion::new(start, EXTERNAL_HEAP, MemoryCapability::External.into())) };
    EXTERNAL_START.store(start as usize, Ordering::Relaxed);
    EXTERNAL_BYTES.store(EXTERNAL_HEAP, Ordering::Relaxed);
}
