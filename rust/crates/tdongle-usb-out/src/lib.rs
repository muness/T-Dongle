//! Multi-packet bulk OUT transfers on a Synopsys/DWC2 OTG core in slave mode: the pure logic of the vendored `embassy-usb-synopsys-otg` patch and of the
//! class code that sits on it, so that both can be tested on the host against a model of the core.
//!
//! The stock driver arms an OUT endpoint for one packet (`PKTCNT = 1`, `XFRSIZ = MPS`), copies it out of the RX FIFO in the interrupt, and re-arms from the task
//! that read it: at full speed that is a NAK for every packet the task has not yet got to, and it capped the bridge's host-to-device direction at 4.6 Mbit/s (S2 on
//! the board: `sink` 4.62 Mbit/s at any offered rate, against 7.41 Mbit/s for IN). The patch arms the endpoint for a whole NTB:
//!
//! * [`Transfer::arm`]: `PKTCNT = cap / MPS`, `XFRSIZ = cap` (the NTB buffer, 3,200 bytes for the NCM data endpoint).
//! * The interrupt appends each packet the core pushes into the RX FIFO ([`Transfer::packet`]) and, on the core's "OUT transfer completed" status
//!   (`PKTSTS = 3`, which the core raises when `PKTCNT` reaches 0 **or** on a short packet or ZLP), ends the chunk ([`Transfer::done`]).
//! * The task reads the chunk and re-arms (nothing is armed while the class is holding the endpoint, so the host is NAKed: backpressure is kept).
//!
//! A chunk therefore ends with a packet shorter than MPS (an NTB is complete) or exactly `cap` bytes (the buffer filled with no short packet: more follows).
//! [`NtbCollector`] is the class side of that rule.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod elastic;
pub mod ntb_in;

/// A packet did not fit the transfer buffer: it is discarded and the transfer is dropped when it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overflow;

/// What one completed hardware transfer delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    /// Bytes received.
    pub len: u16,
    /// The transfer ended because a packet shorter than MPS arrived (a short packet, or a zero-length packet that adds no bytes), not because the buffer filled. This
    /// cannot be recovered from `len`: an NTB of exactly 64 bytes plus its ZLP is a 64-byte chunk. It is what ends an NTB.
    pub short: bool,
}

/// One armed OUT transfer, as seen by the interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    mps: u16,
    cap: u16,
    fill: u16,
    last_short: bool,
    overflowed: bool,
}

impl Transfer {
    /// A transfer of at most `cap` bytes on an endpoint with packet size `mps`. `cap` is rounded down to a multiple of `mps` (the core requires `XFRSIZ` to be one)
    /// and is at least one packet.
    #[must_use]
    pub const fn new(mps: u16, cap: u16) -> Self {
        let cap = if cap < mps { mps } else { cap - cap % mps };
        Self { mps, cap, fill: 0, last_short: false, overflowed: false }
    }

    /// What to program into `DOEPTSIZ` for this transfer: `(XFRSIZ, PKTCNT)`.
    #[must_use]
    pub const fn arm(&self) -> (u32, u32) {
        (self.cap as u32, (self.cap / self.mps) as u32)
    }

    /// The transfer buffer size in bytes.
    #[must_use]
    pub const fn capacity(&self) -> u16 {
        self.cap
    }

    /// The core pushed a packet of `len` bytes into the RX FIFO for this endpoint. Returns the offset in the transfer buffer at which the interrupt must copy it.
    ///
    /// # Errors
    /// [`Overflow`]: the packet does not fit (a core that exceeds its programmed `XFRSIZ`, or a driver bug); the interrupt must still drain `len` bytes from
    /// the FIFO, and [`done`](Self::done) will report the chunk as dropped.
    pub fn packet(&mut self, len: u16) -> Result<usize, Overflow> {
        if self.overflowed || len > self.mps || u32::from(self.fill) + u32::from(len) > u32::from(self.cap) {
            self.overflowed = true;
            return Err(Overflow);
        }
        let at = usize::from(self.fill);
        self.fill += len;
        self.last_short = len < self.mps;
        Ok(at)
    }

    /// The core reported the transfer completed. Returns the chunk, `Err` if a packet overflowed; the transfer is empty again either way.
    ///
    /// # Errors
    /// [`Overflow`] if any packet of this transfer was discarded.
    pub fn done(&mut self) -> Result<Chunk, Overflow> {
        let chunk = Chunk { len: self.fill, short: self.last_short };
        let bad = self.overflowed;
        self.fill = 0;
        self.last_short = false;
        self.overflowed = false;
        if bad { Err(Overflow) } else { Ok(chunk) }
    }

    /// Bytes received so far in the transfer in progress.
    #[must_use]
    pub const fn filled(&self) -> u16 {
        self.fill
    }
}

/// What [`NtbCollector::chunk`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Step {
    /// The NTB is not complete: read the next chunk into [`NtbCollector::room`].
    More,
    /// The NTB is complete: `len` bytes are in the buffer.
    Complete(usize),
    /// The NTB is invalid (it outgrew the buffer, or the endpoint dropped a transfer): it is discarded, start over.
    Dropped,
}

/// The class side of multi-packet OUT: accumulates chunks into one NTB buffer and finds its end by the USB short-packet rule: a chunk that ended on a packet
/// shorter than MPS ends the NTB, a zero-length packet (which the host sends after an NTB whose length is a multiple of MPS) included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NtbCollector {
    mps: usize,
    max: usize,
    len: usize,
}

impl NtbCollector {
    /// A collector for NTBs of at most `max` bytes on an endpoint with packet size `mps`.
    #[must_use]
    pub const fn new(mps: usize, max: usize) -> Self {
        Self { mps, max, len: 0 }
    }

    /// The buffer range the next `read` may fill: `len..max`. Empty once the NTB has reached `max` without ending: the next chunk can then only be the
    /// terminating ZLP (which fits an empty slice) or an oversized NTB (which the endpoint drops, reporting a buffer overflow).
    #[must_use]
    pub const fn room(&self) -> core::ops::Range<usize> {
        self.len..self.max
    }

    /// A `read_transfer` returned a chunk of `n` bytes (written at [`room`](Self::room)`.start`); `short` is [`Chunk::short`].
    pub fn chunk(&mut self, n: usize, short: bool) -> Step {
        self.len += n;
        debug_assert!(self.mps != 0);
        if short {
            let len = self.len;
            self.len = 0;
            return Step::Complete(len);
        }
        Step::More
    }

    /// `read` failed with a buffer overflow: the endpoint dropped an oversized chunk. The NTB is invalid; whatever is left of it until its short packet is read as a
    /// new NTB and fails validation, so the stream re-synchronises at the next NTB.
    pub fn overflow(&mut self) -> Step {
        self.len = 0;
        Step::Dropped
    }
}
