//! Small helpers the per-slot tasks share: waiting for a slot to be started or stopped, the "I am working for this membership" bit, and the link view.

use crate::shared::{LinkView, SlotRun};
use core::sync::atomic::{AtomicU8, Ordering};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::watch::Receiver;

/// Receiver of a slot's run state.
pub type RunRx<'a, R> = Receiver<'a, R, SlotRun, 4>;
/// Receiver of the link view.
pub type LinkRx<'a, R> = Receiver<'a, R, LinkView, 12>;

/// Wait until the slot is running a membership and return what it runs.
pub async fn wait_active<R: RawMutex>(rx: &mut RunRx<'_, R>) -> SlotRun {
    let mut v = rx.get().await;
    while v.id == 0 {
        v = rx.changed().await;
    }
    v
}

/// Wait until the slot's run state is not `current` any more (stopped, or restarted with a new epoch).
pub async fn wait_changed<R: RawMutex>(rx: &mut RunRx<'_, R>, current: SlotRun) {
    loop {
        let v = rx.changed().await;
        if v != current {
            return;
        }
    }
}

/// Wait until the link is up and return the view.
pub async fn wait_link_up<R: RawMutex>(rx: &mut LinkRx<'_, R>) -> LinkView {
    let mut v = rx.get().await;
    while !v.up || v.v4.is_none() {
        v = rx.changed().await;
    }
    v
}

/// Wait until the link view differs from `v` and return the new one.
pub async fn wait_link_change<R: RawMutex>(rx: &mut LinkRx<'_, R>, v: LinkView) -> LinkView {
    loop {
        let n = rx.changed().await;
        if n != v {
            return n;
        }
    }
}

/// Sets a bit of a slot's `alive` mask while it exists.
#[derive(Debug)]
pub struct Alive<'a> {
    mask: &'a AtomicU8,
    bit: u8,
}

impl<'a> Alive<'a> {
    /// Set `bit`.
    pub fn new(mask: &'a AtomicU8, bit: u8) -> Self {
        mask.fetch_or(bit, Ordering::AcqRel);
        Alive { mask, bit }
    }
}

impl Drop for Alive<'_> {
    fn drop(&mut self) {
        self.mask.fetch_and(!self.bit, Ordering::AcqRel);
    }
}
