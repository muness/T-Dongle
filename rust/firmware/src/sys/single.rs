//! A value that exactly one task ever touches, owned by a `static` because a C callback has to find it.

use core::cell::UnsafeCell;

/// A `static`-friendly cell for state that a single task owns. The TinyUSB task's receive callback is the one user: it finds the bridge's
/// producer handle here.
///
/// There is no lock: soundness rests on the owner rule stated at [`get_mut`](Self::get_mut), which the single call site documents.
#[derive(Debug)]
pub struct SingleContext<T>(UnsafeCell<Option<T>>);

// SAFETY: access is limited to one task by the contract of `get_mut`; installing happens before that task starts.
unsafe impl<T: Send> Sync for SingleContext<T> {}

impl<T> SingleContext<T> {
    /// An empty cell.
    pub const fn new() -> Self {
        Self(UnsafeCell::new(None))
    }

    /// Put the value in. Before the owning task can run.
    ///
    /// # Safety
    /// No task may be inside [`get_mut`](Self::get_mut) or call it until this returns (call it during boot, before the owning task starts).
    pub unsafe fn install(&self, value: T) {
        // SAFETY: exclusive by the caller's contract.
        unsafe { *self.0.get() = Some(value) };
    }

    /// The value, for the owning task.
    ///
    /// # Safety
    /// Only one task may ever call this, and not reentrantly: no other reference obtained from it may be alive.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut(&self) -> Option<&mut T> {
        // SAFETY: exclusive by the caller's contract.
        unsafe { (*self.0.get()).as_mut() }
    }
}

impl<T> Default for SingleContext<T> {
    fn default() -> Self {
        Self::new()
    }
}
