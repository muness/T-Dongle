//! The DERP frame: a type byte, a big-endian `u32` body length, the body. Encoder and streaming decoder.

use crate::{FRAME_HEADER_LEN, KEY_LEN, MAX_FRAME, MAX_RECV_BODY, MAX_SEND_BODY};

/// A frame type byte. Unknown values are legal (a newer server may send them; the client skips them), so this is a newtype, not an enum.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct FrameType(pub u8);

impl FrameType {
    /// 8B magic, 32B public key, 0+ bytes for future use.
    pub const SERVER_KEY: FrameType = FrameType(0x01);
    /// 32B public key, 24B nonce, NaCl box of JSON.
    pub const CLIENT_INFO: FrameType = FrameType(0x02);
    /// 24B nonce, NaCl box of JSON.
    pub const SERVER_INFO: FrameType = FrameType(0x03);
    /// 32B destination key, packet.
    pub const SEND_PACKET: FrameType = FrameType(0x04);
    /// 32B source key, packet.
    pub const RECV_PACKET: FrameType = FrameType(0x05);
    /// No payload.
    pub const KEEP_ALIVE: FrameType = FrameType(0x06);
    /// One byte: 1 if this server is the client's home.
    pub const NOTE_PREFERRED: FrameType = FrameType(0x07);
    /// 32B key of the peer that is gone, one reason byte.
    pub const PEER_GONE: FrameType = FrameType(0x08);
    /// 32B key, optional 16B address and 2B port, flags, app name.
    pub const PEER_PRESENT: FrameType = FrameType(0x09);
    /// 32B source, 32B destination, packet (mesh servers only).
    pub const FORWARD_PACKET: FrameType = FrameType(0x0a);
    /// Mesh watch request.
    pub const WATCH_CONNS: FrameType = FrameType(0x10);
    /// 32B key of a peer to close (mesh servers only).
    pub const CLOSE_PEER: FrameType = FrameType(0x11);
    /// 8B payload, echoed in a pong.
    pub const PING: FrameType = FrameType(0x12);
    /// 8B payload, the contents of the ping being answered.
    pub const PONG: FrameType = FrameType(0x13);
    /// Problem text, empty when healthy.
    pub const HEALTH: FrameType = FrameType(0x14);
    /// Two big-endian `u32` milliseconds: reconnect in, try for.
    pub const RESTARTING: FrameType = FrameType(0x15);

    /// A short name for logs.
    pub fn name(self) -> &'static str {
        match self {
            Self::SERVER_KEY => "server_key",
            Self::CLIENT_INFO => "client_info",
            Self::SERVER_INFO => "server_info",
            Self::SEND_PACKET => "send_packet",
            Self::RECV_PACKET => "recv_packet",
            Self::KEEP_ALIVE => "keep_alive",
            Self::NOTE_PREFERRED => "note_preferred",
            Self::PEER_GONE => "peer_gone",
            Self::PEER_PRESENT => "peer_present",
            Self::FORWARD_PACKET => "forward_packet",
            Self::WATCH_CONNS => "watch_conns",
            Self::CLOSE_PEER => "close_peer",
            Self::PING => "ping",
            Self::PONG => "pong",
            Self::HEALTH => "health",
            Self::RESTARTING => "restarting",
            _ => "unknown",
        }
    }
}

/// The 5-byte header for a frame of `body_len` bytes (`derp.WriteFrameHeader`).
pub fn encode_header(ty: FrameType, body_len: u32) -> [u8; FRAME_HEADER_LEN] {
    let l = body_len.to_be_bytes();
    [ty.0, l[0], l[1], l[2], l[3]]
}

/// Split a header into its type and body length (`derp.ReadFrameHeader`).
pub fn parse_header(h: &[u8; FRAME_HEADER_LEN]) -> (FrameType, u32) {
    (FrameType(h[0]), u32::from_be_bytes([h[1], h[2], h[3], h[4]]))
}

/// Why a frame was not encoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EncodeError {
    /// `out` is smaller than the frame.
    OutputTooSmall,
    /// The body exceeds what this client sends ([`MAX_SEND_BODY`]).
    BodyTooLarge,
}

/// Encode a frame whose body is the concatenation of `parts`. Returns the frame length (header included).
pub fn encode_frame(ty: FrameType, parts: &[&[u8]], out: &mut [u8]) -> Result<usize, EncodeError> {
    let body: usize = parts.iter().map(|p| p.len()).sum();
    if body > MAX_SEND_BODY {
        return Err(EncodeError::BodyTooLarge);
    }
    let total = FRAME_HEADER_LEN + body;
    if out.len() < total {
        return Err(EncodeError::OutputTooSmall);
    }
    out[..FRAME_HEADER_LEN].copy_from_slice(&encode_header(ty, body as u32));
    let mut at = FRAME_HEADER_LEN;
    for p in parts {
        out[at..at + p.len()].copy_from_slice(p);
        at += p.len();
    }
    Ok(total)
}

/// Encode a SendPacket: destination key then the packet.
pub fn encode_send_packet(dest: &[u8; KEY_LEN], packet: &[u8], out: &mut [u8]) -> Result<usize, EncodeError> {
    encode_frame(FrameType::SEND_PACKET, &[dest, packet], out)
}

/// Why the stream cannot be read on. The stream is desynchronised or hostile: the caller drops the connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadError {
    /// The length field exceeds what this firmware can carry: [`MAX_RECV_BODY`] for a RecvPacket, [`MAX_FRAME`] for everything else.
    Oversize {
        /// The frame type.
        ty: FrameType,
        /// The claimed body length.
        len: u32,
    },
    /// A RecvPacket too short to carry a source key and at least one byte.
    ShortRecvPacket {
        /// The claimed body length.
        len: u32,
    },
}

/// A frame the reader has completed; its body is [`FrameReader::body`] until the next `feed`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FrameInfo {
    /// The type.
    pub ty: FrameType,
    /// Body length in bytes.
    pub len: usize,
}

/// What one [`FrameReader::feed`] call produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Poll {
    /// All offered bytes were consumed and no frame is complete.
    NeedMore,
    /// A frame is complete (not all offered bytes need have been consumed).
    Frame(FrameInfo),
    /// The stream is unusable. Sticky until [`FrameReader::reset`].
    Error(ReadError),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Header,
    Body,
    Done,
    Failed(ReadError),
}

/// A streaming frame decoder with one fixed buffer. No allocation; any chunking of the byte stream, including one byte at a time, yields the same
/// frames. A frame longer than the bounds above is an error, never skipped (a hostile length cannot make the client read on).
pub struct FrameReader {
    hdr: [u8; FRAME_HEADER_LEN],
    hdr_used: u8,
    ty: FrameType,
    len: usize,
    used: usize,
    phase: Phase,
    buf: [u8; MAX_RECV_BODY],
}

impl core::fmt::Debug for FrameReader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameReader").field("phase", &self.phase).field("used", &self.used).field("len", &self.len).finish()
    }
}

impl Default for FrameReader {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameReader {
    /// Size of the struct in bytes (the ADR's bytes per membership).
    pub const STATE_BYTES: usize = core::mem::size_of::<FrameReader>();

    /// An empty reader.
    pub const fn new() -> Self {
        Self { hdr: [0; FRAME_HEADER_LEN], hdr_used: 0, ty: FrameType(0), len: 0, used: 0, phase: Phase::Header, buf: [0; MAX_RECV_BODY] }
    }

    /// Forget any partial frame and any error.
    pub fn reset(&mut self) {
        self.hdr_used = 0;
        self.used = 0;
        self.len = 0;
        self.phase = Phase::Header;
    }

    /// True while a frame has started (at least one header byte) and not finished: the span the receive deadline covers.
    pub fn in_frame(&self) -> bool {
        matches!(self.phase, Phase::Body) || (matches!(self.phase, Phase::Header) && self.hdr_used > 0)
    }

    /// The body of the frame the last `feed` completed. Empty at any other time.
    pub fn body(&self) -> &[u8] {
        if self.phase == Phase::Done { &self.buf[..self.len] } else { &[] }
    }

    /// Mutable view of the completed frame's body (the ServerInfo box is opened in place).
    pub fn body_mut(&mut self) -> &mut [u8] {
        if self.phase == Phase::Done { &mut self.buf[..self.len] } else { &mut [] }
    }

    /// Consume bytes from `data` up to the end of the next frame. Returns how many bytes were consumed and what happened. After `Frame`, call again
    /// with the unconsumed rest; after `NeedMore` everything was consumed.
    pub fn feed(&mut self, data: &[u8]) -> (usize, Poll) {
        if self.phase == Phase::Done {
            self.reset();
        }
        if let Phase::Failed(e) = self.phase {
            return (0, Poll::Error(e));
        }
        let mut at = 0;
        if self.phase == Phase::Header {
            let want = FRAME_HEADER_LEN - self.hdr_used as usize;
            let n = want.min(data.len());
            self.hdr[self.hdr_used as usize..self.hdr_used as usize + n].copy_from_slice(&data[..n]);
            self.hdr_used += n as u8;
            at = n;
            if (self.hdr_used as usize) < FRAME_HEADER_LEN {
                return (at, Poll::NeedMore);
            }
            let (ty, len) = parse_header(&self.hdr);
            self.hdr_used = 0;
            let relayed = ty == FrameType::RECV_PACKET;
            let err = if relayed {
                if len as usize <= KEY_LEN {
                    Some(ReadError::ShortRecvPacket { len })
                } else if len as usize > MAX_RECV_BODY {
                    Some(ReadError::Oversize { ty, len })
                } else {
                    None
                }
            } else if len as usize > MAX_FRAME {
                Some(ReadError::Oversize { ty, len })
            } else {
                None
            };
            if let Some(e) = err {
                self.phase = Phase::Failed(e);
                return (at, Poll::Error(e));
            }
            self.ty = ty;
            self.len = len as usize;
            self.used = 0;
            self.phase = Phase::Body;
        }
        let want = self.len - self.used;
        let n = want.min(data.len() - at);
        self.buf[self.used..self.used + n].copy_from_slice(&data[at..at + n]);
        self.used += n;
        at += n;
        if self.used == self.len {
            self.phase = Phase::Done;
            (at, Poll::Frame(FrameInfo { ty: self.ty, len: self.len }))
        } else {
            (at, Poll::NeedMore)
        }
    }

    /// Convenience over [`feed`](Self::feed): call `f(type, body)` for every frame completed by `data`. Stops at the first error and returns it.
    pub fn feed_all(&mut self, mut data: &[u8], mut f: impl FnMut(FrameType, &[u8])) -> Result<(), ReadError> {
        while !data.is_empty() {
            let (n, p) = self.feed(data);
            data = &data[n..];
            match p {
                Poll::NeedMore => {}
                Poll::Frame(info) => f(info.ty, self.body()),
                Poll::Error(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// `derp_test.go` `TestReadFrameHeader` / `TestWriteFrameHeader` vectors.
    #[test]
    fn go_header_vectors() {
        let cases: [(FrameType, u32, [u8; 5]); 3] = [
            (FrameType::SEND_PACKET, 1024, [0x04, 0x00, 0x00, 0x04, 0x00]),
            (FrameType::KEEP_ALIVE, 0, [0x06, 0, 0, 0, 0]),
            (FrameType::RECV_PACKET, 0xffff_ffff, [0x05, 0xff, 0xff, 0xff, 0xff]),
        ];
        for (ty, len, bytes) in cases {
            assert_eq!(encode_header(ty, len), bytes);
            assert_eq!(parse_header(&bytes), (ty, len));
        }
    }

    /// `client_test.go` `TestClientSendPing` and `TestClientSendPong`.
    #[test]
    fn go_ping_pong_frames() {
        let mut out = [0u8; 13];
        let n = encode_frame(FrameType::PING, &[&[1, 2, 3, 4, 5, 6, 7, 8]], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x12, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        let n = encode_frame(FrameType::PONG, &[&[1, 2, 3, 4, 5, 6, 7, 8]], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x13, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn frame_type_numbers_match_go() {
        let want = [
            (FrameType::SERVER_KEY, 0x01),
            (FrameType::CLIENT_INFO, 0x02),
            (FrameType::SERVER_INFO, 0x03),
            (FrameType::SEND_PACKET, 0x04),
            (FrameType::RECV_PACKET, 0x05),
            (FrameType::KEEP_ALIVE, 0x06),
            (FrameType::NOTE_PREFERRED, 0x07),
            (FrameType::PEER_GONE, 0x08),
            (FrameType::PEER_PRESENT, 0x09),
            (FrameType::FORWARD_PACKET, 0x0a),
            (FrameType::WATCH_CONNS, 0x10),
            (FrameType::CLOSE_PEER, 0x11),
            (FrameType::PING, 0x12),
            (FrameType::PONG, 0x13),
            (FrameType::HEALTH, 0x14),
            (FrameType::RESTARTING, 0x15),
        ];
        for (t, n) in want {
            assert_eq!(t.0, n);
            assert_ne!(t.name(), "unknown");
        }
        assert_eq!(FrameType(0x77).name(), "unknown");
    }

    #[test]
    fn encode_bounds() {
        let mut out = [0u8; 8];
        assert_eq!(encode_frame(FrameType::KEEP_ALIVE, &[], &mut out), Ok(5));
        assert_eq!(encode_frame(FrameType::PING, &[&[0; 8]], &mut out), Err(EncodeError::OutputTooSmall));
        let big = [0u8; MAX_SEND_BODY + 1];
        let mut huge = [0u8; 8];
        assert_eq!(encode_frame(FrameType::SEND_PACKET, &[&big], &mut huge), Err(EncodeError::BodyTooLarge));
    }

    fn stream(frames: &[(FrameType, Vec<u8>)]) -> Vec<u8> {
        let mut v = Vec::new();
        for (t, b) in frames {
            v.extend_from_slice(&encode_header(*t, b.len() as u32));
            v.extend_from_slice(b);
        }
        v
    }

    fn collect(chunks: impl Iterator<Item = usize>, data: &[u8]) -> Result<Vec<(FrameType, Vec<u8>)>, ReadError> {
        let mut r = FrameReader::new();
        let mut out = Vec::new();
        let mut at = 0;
        for c in chunks.chain(core::iter::repeat(7)) {
            if at >= data.len() {
                break;
            }
            let end = (at + c.max(1)).min(data.len());
            r.feed_all(&data[at..end], |t, b| out.push((t, b.to_vec())))?;
            at = end;
        }
        Ok(out)
    }

    #[test]
    fn any_chunking_same_frames() {
        let frames = std::vec![
            (FrameType::KEEP_ALIVE, Vec::new()),
            (FrameType::PING, (1..=8).collect()),
            (FrameType::RECV_PACKET, (0..40u8).collect()),
            (FrameType::RECV_PACKET, std::vec![0xAB; MAX_RECV_BODY]),
            (FrameType::HEALTH, std::vec![b'x'; MAX_FRAME]),
        ];
        let data = stream(&frames);
        for chunk in [1usize, 2, 3, 5, 6, 31, 64, 1000, data.len()] {
            let got = collect(core::iter::repeat(chunk), &data).unwrap();
            assert_eq!(got, frames, "chunk {chunk}");
        }
    }

    #[test]
    fn oversize_and_short_are_sticky_errors() {
        let mut r = FrameReader::new();
        let h = encode_header(FrameType::KEEP_ALIVE, 0x0010_0000);
        let (n, p) = r.feed(&h);
        assert_eq!(n, 5);
        assert_eq!(p, Poll::Error(ReadError::Oversize { ty: FrameType::KEEP_ALIVE, len: 0x0010_0000 }));
        assert!(matches!(r.feed(&[1, 2, 3]), (0, Poll::Error(_))));
        r.reset();
        // a RecvPacket that cannot carry a source key and a byte
        for len in [0u32, 1, 32] {
            let mut r = FrameReader::new();
            assert_eq!(r.feed(&encode_header(FrameType::RECV_PACKET, len)).1, Poll::Error(ReadError::ShortRecvPacket { len }));
        }
        // the limits are inclusive
        let mut r = FrameReader::new();
        assert!(matches!(r.feed(&encode_header(FrameType::RECV_PACKET, MAX_RECV_BODY as u32)).1, Poll::NeedMore));
        let mut r = FrameReader::new();
        assert!(matches!(r.feed(&encode_header(FrameType::RECV_PACKET, MAX_RECV_BODY as u32 + 1)).1, Poll::Error(_)));
        let mut r = FrameReader::new();
        assert!(matches!(r.feed(&encode_header(FrameType::PING, MAX_FRAME as u32 + 1)).1, Poll::Error(_)));
    }

    #[test]
    fn in_frame_tracks_partial_frames() {
        let mut r = FrameReader::new();
        assert!(!r.in_frame());
        r.feed(&[0x05]);
        assert!(r.in_frame());
        r.feed(&[0, 0, 0, 40]);
        assert!(r.in_frame());
        let (_, p) = r.feed(&[0u8; 40]);
        assert!(matches!(p, Poll::Frame(_)));
        assert!(!r.in_frame());
        assert_eq!(r.body().len(), 40);
        r.feed(&[]);
        assert!(r.body().is_empty());
    }
}
