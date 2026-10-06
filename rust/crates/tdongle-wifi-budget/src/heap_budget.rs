//! The one heap budget for everything that grows under traffic (ADR 0022): the constants and the two checks of `ml_heap_budget.h`
//! that the Wi-Fi pin budget needs.
//!
//! Port of `alternative/tailnet/components/microlink/include/ml_heap_budget.h` (and the two `ML_ADM_*` values of `ml_admission.h` it is
//! built from). The header's long comment is the argument for the arithmetic below; the three `_Static_assert`s of it are the `const`
//! assertions at the bottom of this file.
//!
//! The bound, in one line: `ML_HB_FLOOR >= ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES`. A consumer that checks the free heap must
//! leave, in addition to the recovery reserve, whatever can still be taken from the heap after the check without a check of its own: the
//! pinned buffers of the largest burst a socket can hold, plus the allocations of the other checkers racing this check.

/// One join's transient: the DERP TLS handshake with certificate verification (`ML_ADM_NEG_PEAK_BYTES`), bytes. Measured 13,184 on the board,
/// rounded up with headroom to 13,500.
pub const ML_ADM_NEG_PEAK_BYTES: usize = 13_500;
/// Kept free for HTTP/control recovery (`ML_ADM_RECOVERY_BYTES`), bytes. The v120 panic was at 7,464 B free.
pub const ML_ADM_RECOVERY_BYTES: usize = 16_384;

/// The recovery reserve every elastic consumer leaves free (`ML_HB_RESERVE`), 16,384 bytes.
pub const ML_HB_RESERVE: usize = ML_ADM_RECOVERY_BYTES;
/// The long-lived elastic floor (`ML_HB_FLOOR`): ONE number for the USB ring's growth, the WireGuard receive queue, the router queue above
/// its two-packet minimum, pending outbound packets, USB receive frames and the DERP relay's transmit queue. Recovery reserve plus one
/// negotiation peak: 29,884 bytes.
pub const ML_HB_FLOOR: usize = ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES;
/// What a pinned Wi-Fi buffer costs (`ML_HB_PIN_BUF_BYTES`): the frame (<= 1,514 B plus the 802.11 and driver headers) rounded up, and the
/// allocator header, 1,664 bytes.
pub const ML_HB_PIN_BUF_BYTES: usize = 1664;
/// Allocators that can pass their floor check before another has allocated (`ML_HB_SLACK_BYTES`): net_io, the DERP loop, usb_rx, the USB ring
/// worker. Two full buffers, 3,328 bytes.
pub const ML_HB_SLACK_BYTES: usize = 2 * ML_HB_PIN_BUF_BYTES;
/// The largest burst of Wi-Fi buffers any one socket may pin (`ML_HB_PIN_BUFFERS`): the greatest N with
/// `ML_HB_RESERVE + N * ML_HB_PIN_BUF_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR`. Six.
pub const ML_HB_PIN_BUFFERS: u32 = ((ML_HB_FLOOR - ML_HB_RESERVE - ML_HB_SLACK_BYTES) / ML_HB_PIN_BUF_BYTES) as u32;
/// Heap those buffers can pin (`ML_HB_PIN_BYTES`): 9,984 bytes.
pub const ML_HB_PIN_BYTES: usize = ML_HB_PIN_BUFFERS as usize * ML_HB_PIN_BUF_BYTES;
/// A datagram this small is taken when its destination queue is empty, whatever the heap says (`ML_HB_RX_SMALL_BYTES`).
pub const ML_HB_RX_SMALL_BYTES: usize = 512;

// `_Static_assert(ML_HB_PIN_BUFFERS >= 4, ...)`: the elastic floor leaves room for fewer than four pinned Wi-Fi buffers: the receive path
// cannot be sized.
const _: () = assert!(ML_HB_PIN_BUFFERS >= 4, "the elastic floor leaves room for fewer than four pinned Wi-Fi buffers");
// `_Static_assert(ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR, ...)`
const _: () = assert!(
    ML_HB_RESERVE + ML_HB_PIN_BYTES + ML_HB_SLACK_BYTES <= ML_HB_FLOOR,
    "the elastic floor must cover the recovery reserve, the pinned Wi-Fi buffers of the largest burst and the racing checkers"
);
// `_Static_assert(ML_HB_FLOOR == ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES, ...)`
const _: () = assert!(ML_HB_FLOOR == ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES && ML_HB_FLOOR == 29_884);
const _: () = assert!(ML_HB_PIN_BUFFERS == 6 && ML_HB_PIN_BYTES == 9984 && ML_HB_SLACK_BYTES == 3328);

/// The check every elastic consumer makes (`ml_hb_ok`): after taking `cost` bytes, at least [`ML_HB_FLOOR`] must remain free.
#[must_use]
pub const fn hb_ok(free_internal: usize, cost: usize) -> bool {
    free_internal >= ML_HB_FLOOR + cost
}

/// The check for a datagram or relay frame about to be copied into a heap block that then waits in a queue the receiver reads (`ml_hb_rx_ok`):
/// the elastic check, with one exemption so a path can still be discovered and kept alive in a flood. A small datagram (DISCO pings and pongs,
/// STUN responses, CallMeMaybe: up to [`ML_HB_RX_SMALL_BYTES`]) is taken when its destination queue is EMPTY, which costs at most one such
/// block per queue below the floor. WireGuard data has no exemption.
#[must_use]
pub const fn hb_rx_ok(free_internal: usize, len: usize, destination_empty: bool) -> bool {
    (destination_empty && len <= ML_HB_RX_SMALL_BYTES) || hb_ok(free_internal, len + 16)
}
