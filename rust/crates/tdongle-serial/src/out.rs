//! Console output that is never silently cut. The first spike consoles formatted every reply into a fixed 320 or 400 byte buffer whose `write_str` quietly dropped the rest, so a
//! `boot-status` of about 600 bytes lost its tail (`rescue`, `sup`) on every call. Here an overflow is recorded and made visible, the buffer is sized for the longest reply, and the
//! bytes go out in USB packets with the zero-length packet that ends a transfer which is a multiple of the packet size ([`packets`], the one routine the ACM writers use).

use core::fmt;

/// The marker that replaces the tail of a reply that did not fit its buffer: a client can see that something was lost.
pub const TRUNCATED: &[u8] = b"...[output truncated]\r\n";

/// A fixed buffer for one reply. Overflow is not silent: [`write_str`](fmt::Write::write_str) returns an error, [`overflowed`](Self::overflowed) says so, and
/// [`finish`](Self::finish) ends a cut reply with [`TRUNCATED`].
#[derive(Clone, Debug)]
pub struct LineBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
    overflow: bool,
}

impl<const N: usize> LineBuf<N> {
    /// An empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: [0; N], len: 0, overflow: false }
    }

    /// What was written (cut at the buffer's end if it overflowed).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// More was written than fits.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflow
    }

    /// The bytes to send: the reply, and if it was cut, [`TRUNCATED`] in place of its last bytes.
    pub fn finish(&mut self) -> &[u8] {
        if self.overflow {
            let keep = N.saturating_sub(TRUNCATED.len());
            self.len = keep.min(self.len);
            self.buf[self.len..self.len + TRUNCATED.len().min(N - self.len)].copy_from_slice(&TRUNCATED[..TRUNCATED.len().min(N - self.len)]);
            self.len += TRUNCATED.len().min(N - self.len);
        }
        &self.buf[..self.len]
    }
}

impl<const N: usize> Default for LineBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for LineBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = N - self.len;
        let n = s.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        if n < s.len() {
            self.overflow = true;
            return Err(fmt::Error);
        }
        Ok(())
    }
}

/// The USB packets of one bulk IN transfer of `data`: `mps`-byte packets, the last one shorter, and a zero-length packet after a transfer whose length is a nonzero multiple of
/// `mps` (without it the host waits for more). Empty data sends nothing.
pub fn packets(data: &[u8], mps: usize) -> impl Iterator<Item = &[u8]> {
    let zlp = !data.is_empty() && data.len().is_multiple_of(mps);
    data.chunks(mps).chain(zlp.then_some(&data[..0]))
}
