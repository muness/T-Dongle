//! The device-to-host NTB (CDC NCM, NTB-16, no CRC): several datagrams per transfer, the way TinyUSB packs them (`CFG_TUD_NCM_IN_NTB_MAX_DATAGRAMS`), so one bulk IN
//! transfer carries a Wi-Fi burst instead of one frame.
//!
//! Layout (offsets from the start of the NTB): the 12-byte NTH at 0; the datagrams from [`FIRST_DATAGRAM`] (12), each at a 4-byte aligned offset (`wNdpInDivisor` = 4, remainder 0,
//! alignment 4 in the NTB parameters); the NDP after the last datagram, 4-byte aligned, with exactly the entries in use and the zero terminator. A one-datagram NTB is therefore
//! 12 + the frame + 16 bytes, as small as the one-frame NTB the first spike sent (28 + the frame), so a single frame costs nothing extra on the wire, and a burst shares the headers.

/// Datagrams an NTB may carry. TinyUSB's default is 8.
pub const MAX_DATAGRAMS: usize = 8;
/// Bytes of the NTH.
pub const NTH_LEN: usize = 12;
/// Offset of the first datagram (4-byte aligned).
pub const FIRST_DATAGRAM: usize = NTH_LEN;

const SIG_NTH: u32 = 0x484d_434e;
const SIG_NDP_NO_FCS: u32 = 0x304d_434e;

/// An NTB under construction in a buffer of `N` bytes (`N` is the host's `dwNtbInMaxSize`, 3,200 here).
#[derive(Clone, Debug)]
pub struct NtbBuilder<const N: usize> {
    buf: [u8; N],
    /// `(offset, length)` of each datagram.
    entries: [(u16, u16); MAX_DATAGRAMS],
    count: usize,
    tail: usize,
}

/// The NDP's length with `datagrams` entries: header 8, the entries and the terminator.
const fn ndp_len(datagrams: usize) -> usize {
    8 + 4 * (datagrams + 1)
}

impl<const N: usize> NtbBuilder<N> {
    /// An empty NTB.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: [0; N], entries: [(0, 0); MAX_DATAGRAMS], count: 0, tail: FIRST_DATAGRAM }
    }

    /// Datagrams in the NTB so far.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Bytes the NTB would have now (without its NDP).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.tail
    }

    /// No datagram yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether a datagram of `len` bytes still fits: the count, and the size including the NDP that will follow it.
    #[must_use]
    pub const fn fits(&self, len: usize) -> bool {
        let after = (self.tail + len + 3) & !3;
        self.count < MAX_DATAGRAMS && len != 0 && after + ndp_len(self.count + 1) <= N
    }

    /// The room for the next datagram: write the frame here, then call [`commit`](Self::commit). `None` when it does not fit.
    pub fn slot(&mut self, len: usize) -> Option<&mut [u8]> {
        if !self.fits(len) {
            return None;
        }
        Some(&mut self.buf[self.tail..self.tail + len])
    }

    /// Append `frame`; `false` (and nothing changes) if it does not fit.
    pub fn push(&mut self, frame: &[u8]) -> bool {
        match self.slot(frame.len()) {
            Some(room) => {
                room.copy_from_slice(frame);
                self.commit(frame.len());
                true
            }
            None => false,
        }
    }

    /// Record that `len` bytes were written at [`slot`](Self::slot).
    pub fn commit(&mut self, len: usize) {
        self.entries[self.count] = (self.tail as u16, len as u16);
        self.count += 1;
        self.tail = (self.tail + len + 3) & !3;
    }

    /// Write the NDP and the NTH and return the bytes to send. The NTB is not reset: call [`clear`](Self::clear) after the transfer.
    pub fn finish(&mut self, sequence: u16) -> &[u8] {
        let ndp = self.tail;
        let end = ndp + ndp_len(self.count);
        let b = &mut self.buf;
        b[0..4].copy_from_slice(&SIG_NTH.to_le_bytes());
        b[4..6].copy_from_slice(&(NTH_LEN as u16).to_le_bytes());
        b[6..8].copy_from_slice(&sequence.to_le_bytes());
        b[8..10].copy_from_slice(&(end as u16).to_le_bytes());
        b[10..12].copy_from_slice(&(ndp as u16).to_le_bytes());
        b[ndp..ndp + 4].copy_from_slice(&SIG_NDP_NO_FCS.to_le_bytes());
        b[ndp + 4..ndp + 6].copy_from_slice(&(ndp_len(self.count) as u16).to_le_bytes());
        b[ndp + 6..ndp + 8].copy_from_slice(&0u16.to_le_bytes()); // no next NDP
        for (i, (at, len)) in self.entries[..self.count].iter().enumerate() {
            let e = ndp + 8 + 4 * i;
            b[e..e + 2].copy_from_slice(&at.to_le_bytes());
            b[e + 2..e + 4].copy_from_slice(&len.to_le_bytes());
        }
        let t = ndp + 8 + 4 * self.count;
        b[t..t + 4].copy_from_slice(&[0; 4]); // terminator entry
        &self.buf[..end]
    }

    /// The first `len` bytes of the buffer (what [`finish`](Self::finish) returned, for a writer that cannot keep the borrow).
    #[must_use]
    pub fn as_bytes(&self, len: usize) -> &[u8] {
        &self.buf[..len.min(N)]
    }

    /// Start a new NTB.
    pub fn clear(&mut self) {
        self.count = 0;
        self.tail = FIRST_DATAGRAM;
    }
}

impl<const N: usize> Default for NtbBuilder<N> {
    fn default() -> Self {
        Self::new()
    }
}
