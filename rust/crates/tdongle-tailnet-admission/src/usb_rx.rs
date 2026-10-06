//! Bound on USB-to-IP frames in flight (`usb_rx_budget.h`, ADR 0022).
//!
//! The USB receive task copies each frame out of the NTB (reused as soon as it returns) and hands the copy to the IP stack, which frees it when the
//! packet is done, possibly many milliseconds later. Without a bound the copies queue behind the stack's mailbox and the router queue. Past the cap the
//! frame is dropped and counted: TCP sees ordinary loss and slows down, and the heap keeps its headroom.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::heap::{ML_HB_PIN_BUF_BYTES, ML_HB_SLACK_BYTES, ROUTE_HOLD_SLOTS, ROUTE_QUEUE_DEPTH, hb_ok};

/// `GATEWAY_USB_RX_FRAME_MIN`.
pub const GATEWAY_USB_RX_FRAME_MIN: u32 = 14;
/// `GATEWAY_USB_RX_FRAME_MAX`: 1500 MTU + Ethernet header + VLAN tag.
pub const GATEWAY_USB_RX_FRAME_MAX: u32 = 1518;
/// `GATEWAY_USB_RX_INFLIGHT_MAX`: what the router can hold (queue depth + hold slots) plus 4 for everything else on the interface.
pub const GATEWAY_USB_RX_INFLIGHT_MAX: u32 = 22;
/// `GATEWAY_USB_RX_HEAP_EXEMPT`: frames admitted whatever the heap says (ARP, DHCP, DNS, a TCP ACK that frees the peer).
pub const GATEWAY_USB_RX_HEAP_EXEMPT: u32 = 2;

const _: () = assert!(
    GATEWAY_USB_RX_INFLIGHT_MAX as usize >= ROUTE_QUEUE_DEPTH + ROUTE_HOLD_SLOTS + 4,
    "USB receive slots must leave room beyond what the router can hold"
);
const _: () = assert!(
    GATEWAY_USB_RX_HEAP_EXEMPT as usize * (GATEWAY_USB_RX_FRAME_MAX as usize + 16) <= ML_HB_SLACK_BYTES + ML_HB_PIN_BUF_BYTES,
    "exempt frames must fit the budget's slack"
);

/// Outcome of [`Budget::admit`]: the caller owns one slot exactly when this is [`Admit::Admitted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Admit {
    /// The caller owns one slot and must release it exactly once.
    Admitted,
    /// Length outside 14..=1518 (counted `dropped_invalid`).
    Invalid,
    /// In-flight cap reached (counted `dropped_busy`).
    Busy,
    /// Free heap would fall below the elastic floor (counted `dropped_heap`).
    Heap,
}

/// `gateway_usb_rx_budget`.
#[derive(Debug)]
pub struct Budget {
    inflight: AtomicU32,
    dropped_busy: AtomicU32,
    dropped_nomem: AtomicU32,
    dropped_invalid: AtomicU32,
    dropped_heap: AtomicU32,
    high_water: AtomicU32,
}

impl Budget {
    /// Empty.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inflight: AtomicU32::new(0),
            dropped_busy: AtomicU32::new(0),
            dropped_nomem: AtomicU32::new(0),
            dropped_invalid: AtomicU32::new(0),
            dropped_heap: AtomicU32::new(0),
            high_water: AtomicU32::new(0),
        }
    }

    /// `gateway_usb_rx_admit`. The checks are in the C's order: length, in-flight cap, then the heap floor (not for the first
    /// [`GATEWAY_USB_RX_HEAP_EXEMPT`] frames in flight). A refused frame takes no slot.
    pub fn admit(&self, len: u32, free_internal: usize) -> Admit {
        if !(GATEWAY_USB_RX_FRAME_MIN..=GATEWAY_USB_RX_FRAME_MAX).contains(&len) {
            self.dropped_invalid.fetch_add(1, Ordering::Relaxed);
            return Admit::Invalid;
        }
        let now = self.inflight.fetch_add(1, Ordering::AcqRel) + 1;
        if now > GATEWAY_USB_RX_INFLIGHT_MAX {
            self.inflight.fetch_sub(1, Ordering::AcqRel);
            self.dropped_busy.fetch_add(1, Ordering::Relaxed);
            return Admit::Busy;
        }
        if now > GATEWAY_USB_RX_HEAP_EXEMPT && !hb_ok(free_internal, len as usize + 16) {
            self.inflight.fetch_sub(1, Ordering::AcqRel);
            self.dropped_heap.fetch_add(1, Ordering::Relaxed);
            return Admit::Heap;
        }
        self.high_water.fetch_max(now, Ordering::Relaxed);
        Admit::Admitted
    }

    /// `gateway_usb_rx_release`: the copy was freed (or never handed on). Saturates at zero instead of wrapping on a double release.
    pub fn release(&self) {
        let _ = self.inflight.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| Some(v.saturating_sub(1)));
    }

    /// Frames in flight.
    #[must_use]
    pub fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Acquire)
    }
    /// Refused: in-flight cap.
    #[must_use]
    pub fn dropped_busy(&self) -> u32 {
        self.dropped_busy.load(Ordering::Relaxed)
    }
    /// Refused: allocation failed (counted by the caller via [`Budget::note_nomem`]).
    #[must_use]
    pub fn dropped_nomem(&self) -> u32 {
        self.dropped_nomem.load(Ordering::Relaxed)
    }
    /// Refused: length outside 14..=1518.
    #[must_use]
    pub fn dropped_invalid(&self) -> u32 {
        self.dropped_invalid.load(Ordering::Relaxed)
    }
    /// Refused: the heap floor.
    #[must_use]
    pub fn dropped_heap(&self) -> u32 {
        self.dropped_heap.load(Ordering::Relaxed)
    }
    /// Highest number of frames in flight.
    #[must_use]
    pub fn high_water(&self) -> u32 {
        self.high_water.load(Ordering::Relaxed)
    }
    /// The caller's allocation of an admitted frame failed: count it (`dropped_nomem`) and give the slot back.
    pub fn note_nomem(&self) {
        self.dropped_nomem.fetch_add(1, Ordering::Relaxed);
        self.release();
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}
