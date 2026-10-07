//! The last thing a runtime task started, for the supervisor: when the thread executor stalls, the task that never returned from its poll is the one that tagged last (every
//! other task tags only when it starts running, and none runs while one hogs the thread), so the firmware's reset record names it (`previous_op`).

use core::sync::atomic::{AtomicU8, Ordering};

/// Nothing tagged yet.
pub const NONE: u8 = 0;
/// The relay waits for its link to ask for a connection.
pub const RELAY_DOWN: u8 = 1;
/// The relay dials (resolve, socket windows, connect).
pub const RELAY_DIAL: u8 = 2;
/// The relay's TLS handshake.
pub const RELAY_TLS: u8 = 3;
/// The relay's stream loop (a poll of it).
pub const RELAY_STREAM: u8 = 4;
/// The relay changes its window mode (reconnects).
pub const RELAY_WINDOWS: u8 = 5;
/// The relay's egress pump.
pub const RELAY_PUMP: u8 = 6;
/// The USB pump's loop.
pub const USB_PUMP: u8 = 7;
/// A frame held for room.
pub const HOLD: u8 = 8;
/// The UDP task of a membership.
pub const UDP: u8 = 9;
/// The control task.
pub const CONTROL: u8 = 10;
/// The engine's timer.
pub const ENGINE_TIMER: u8 = 11;

static OP: AtomicU8 = AtomicU8::new(NONE);

/// Note that the calling task starts (or resumes) `op`.
#[inline]
pub fn set(op: u8) {
    OP.store(op, Ordering::Relaxed);
}

/// The last tag, as a short name (it goes into a 16-byte record).
pub fn name() -> &'static str {
    match OP.load(Ordering::Relaxed) {
        RELAY_DOWN => "rdown",
        RELAY_DIAL => "rdial",
        RELAY_TLS => "rtls",
        RELAY_STREAM => "rstream",
        RELAY_WINDOWS => "rwin",
        RELAY_PUMP => "rpump",
        USB_PUMP => "usb",
        HOLD => "hold",
        UDP => "udp",
        CONTROL => "ctl",
        ENGINE_TIMER => "timer",
        _ => "none",
    }
}
