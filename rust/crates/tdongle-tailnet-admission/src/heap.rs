//! One heap budget for everything that grows under traffic (`ml_heap_budget.h`, ADR 0022).
//!
//! Three kinds of consumer draw on the ~20 KB above the recovery reserve: the checked elastic ones (USB ring chunks, the WireGuard receive
//! queue, the router queue, pending packets), and the *unchecked* ones, Wi-Fi driver buffers pinned by sockets. Every checked consumer looks at
//! the free heap now and stops at its own floor, so each is correct alone; together they promised the same bytes three times (the board's 3 KB
//! minimum). The bound, with every consumer using ONE floor:
//!
//! ```text
//! ML_HB_FLOOR >= ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES
//! ```
//!
//! The `const` assertions below are the C's three `_Static_assert`s, so a change to the negotiation peak that breaks the inequality is a build
//! error. The Wi-Fi pin band logic (`wifi_pin_budget.h`) lives in `tdongle-wifi-budget` and is not ported twice.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::adm::{ML_ADM_NEG_PEAK_BYTES, ML_ADM_RECOVERY_BYTES, ROUTE_QUEUE_BYTES_MIN};

/// The recovery reserve every elastic consumer leaves free (`ML_HB_RESERVE`).
pub const ML_HB_RESERVE: usize = ML_ADM_RECOVERY_BYTES;
/// The long-lived elastic floor (`ML_HB_FLOOR`): recovery reserve plus one negotiation peak, 29,884 bytes. ONE number for the USB ring's
/// growth, the WireGuard receive queue, the router queue above its minimum, pending outbound packets, USB receive frames and the DERP relay's
/// transmit queue.
pub const ML_HB_FLOOR: usize = ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES;
/// What a pinned Wi-Fi RX buffer costs (`ML_HB_PIN_BUF_BYTES`): the frame (<= 1,514 B plus headers) rounded up, and the allocator header.
pub const ML_HB_PIN_BUF_BYTES: usize = 1664;
/// Allocators that can pass their floor check before another has allocated (`ML_HB_SLACK_BYTES`): net_io, the DERP loop, usb_rx, the USB ring
/// worker. Two full buffers.
pub const ML_HB_SLACK_BYTES: usize = 2 * ML_HB_PIN_BUF_BYTES;
/// The largest burst of Wi-Fi buffers any one socket may pin (`ML_HB_PIN_BUFFERS`): the greatest N with
/// `RESERVE + N * PIN_BUF + SLACK <= FLOOR`. Six.
pub const ML_HB_PIN_BUFFERS: u32 = ((ML_HB_FLOOR - ML_HB_RESERVE - ML_HB_SLACK_BYTES) / ML_HB_PIN_BUF_BYTES) as u32;
/// Heap those buffers can pin (`ML_HB_PIN_BYTES`).
pub const ML_HB_PIN_BYTES: usize = ML_HB_PIN_BUFFERS as usize * ML_HB_PIN_BUF_BYTES;
/// A datagram this small is taken when its destination queue is empty, whatever the heap says (`ML_HB_RX_SMALL_BYTES`).
pub const ML_HB_RX_SMALL_BYTES: usize = 512;

const _: () = assert!(ML_HB_PIN_BUFFERS >= 4, "the elastic floor leaves room for fewer than four pinned Wi-Fi buffers: the receive path cannot be sized");
const _: () = assert!(
    ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR,
    "the elastic floor must cover the recovery reserve, the pinned Wi-Fi buffers of the largest burst and the racing checkers"
);
const _: () = assert!(ML_HB_FLOOR == ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES, "one elastic floor");
const _: () = assert!(ML_HB_FLOOR == 29_884 && ML_HB_PIN_BUFFERS == 6 && ML_HB_PIN_BYTES == 9984 && ML_HB_SLACK_BYTES == 3328);

/// The check every elastic consumer makes (`ml_hb_ok`): after taking `cost` bytes, at least [`ML_HB_FLOOR`] must remain free.
#[must_use]
pub const fn hb_ok(free_internal: usize, cost: usize) -> bool {
    free_internal >= ML_HB_FLOOR + cost
}

/// `ml_hb_rx_ok`: a datagram or relay frame about to be copied into a heap block that then waits in a queue the receiver reads. The
/// elastic check with one exemption: a small datagram (<= [`ML_HB_RX_SMALL_BYTES`]) is taken when its destination queue is EMPTY, so a path can
/// still be discovered and kept alive in a flood. WireGuard data has no exemption.
#[must_use]
pub const fn hb_rx_ok(free_internal: usize, len: usize, destination_empty: bool) -> bool {
    (destination_empty && len <= ML_HB_RX_SMALL_BYTES) || hb_ok(free_internal, len + 16)
}

/// Where a heap-floor refusal happened (`ml_hb_site_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HbSite {
    /// Packet pending a peer handshake.
    Jit = 0,
    /// Relay transmit queue.
    DerpTx,
    /// DISCO or STUN datagram from the UDP socket, refused before its copy was made.
    RxCtrl,
    /// Relayed frame refused before its receive buffer was allocated.
    DerpRx,
    /// WireGuard datagram copy for a pbuf chain refused.
    WgCopy,
}

/// Number of [`HbSite`]s (`ML_HB_SITE_COUNT`).
pub const HB_SITE_COUNT: usize = 5;

/// The refusal counters (`ml_hb_refused[]`): always on, one relaxed increment on a path that is already dropping a packet.
#[derive(Debug)]
pub struct HbRefused {
    c: [AtomicU32; HB_SITE_COUNT],
}

impl HbRefused {
    /// All zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { c: [const { AtomicU32::new(0) }; HB_SITE_COUNT] }
    }
    /// `ml_hb_refuse`.
    pub fn refuse(&self, site: HbSite) {
        self.c[site as usize].fetch_add(1, Ordering::Relaxed);
    }
    /// Count at one site.
    #[must_use]
    pub fn get(&self, site: HbSite) -> u32 {
        self.c[site as usize].load(Ordering::Relaxed)
    }
}

impl Default for HbRefused {
    fn default() -> Self {
        Self::new()
    }
}

/// `ROUTE_QUEUE_BYTES`: the router queue's ceiling.
pub const ROUTE_QUEUE_BYTES: usize = 16 * 1024;
/// `ROUTE_QUEUE_DEPTH`.
pub const ROUTE_QUEUE_DEPTH: usize = 16;
/// `ROUTE_HOLD_SLOTS`.
pub const ROUTE_HOLD_SLOTS: usize = 2;
/// `ROUTE_HEAP_RESERVE`: the router queue stops at the one elastic floor.
pub const ROUTE_HEAP_RESERVE: usize = ML_HB_FLOOR;

/// `rt_queue_budget`: the bytes the router queue may hold now: the free heap above the floor, at least two packets, at most the ceiling.
#[must_use]
pub const fn rt_queue_budget(free_heap: usize) -> usize {
    let mut room = free_heap.saturating_sub(ROUTE_HEAP_RESERVE);
    if room < ROUTE_QUEUE_BYTES_MIN {
        room = ROUTE_QUEUE_BYTES_MIN;
    }
    if room > ROUTE_QUEUE_BYTES { ROUTE_QUEUE_BYTES } else { room }
}
