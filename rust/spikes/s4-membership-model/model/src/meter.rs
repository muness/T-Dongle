//! The measuring hook. The firmware implements it with a counting allocator + stack painting; the host with a counting allocator.
pub trait Meter {
    /// Start a named phase: record heap `used` as the base, reset the peak, paint the stack.
    fn begin(&self, name: &'static str);
    /// End the phase and print `retained` (used now - base), `peak` (peak - base), alloc count, stack depth reached.
    fn end(&self);
    /// Print a free-form size fact: `SIZE <name> <bytes>`.
    fn size(&self, name: &'static str, bytes: usize);
}
pub struct Null;
impl Meter for Null {
    fn begin(&self, _: &'static str) {}
    fn end(&self) {}
    fn size(&self, _: &'static str, _: usize) {}
}
