//! A minimal, bounded, sans-IO HTTP/2 client over the decrypted control stream.
//!
//! Three layers, each usable alone:
//!
//! * [`FrameReader`] tokenises the byte stream into [`FrameEvent`]s. DATA, HEADERS, CONTINUATION and SETTINGS payload is handed out as slices of the caller's
//!   input (nothing is buffered: a map message of a megabyte costs the same as a byte); RST_STREAM, PING, GOAWAY and WINDOW_UPDATE payload is kept in the C's
//!   56-byte "special" buffer; padding is stripped; a frame larger than the limit is refused at its header. Memory: the 9-byte header and a few counters.
//! * [`Session`] is the connection: preface, SETTINGS (and the exact-once ACK rule: a surplus ACK is a connection error answered with GOAWAY), PING
//!   answers, GOAWAY and RST_STREAM, receive flow control (WINDOW_UPDATE on the connection and the stream for every DATA frame, as the C does), send flow
//!   control for requests, and an HPACK decoder for the response headers. Replies go to a 96-byte outbox the runtime drains with [`Session::poll_output`].
//! * The free `build_*` functions are the C's `ml_h2_build_*` (preface, SETTINGS ACK, WINDOW_UPDATE, HEADERS, DATA) for callers that want raw frames.
//!
//! Driving it: `let (used, event) = session.on_input(bytes); bytes = &bytes[used..];` until the input is empty and the event is [`Event::Idle`]; after every
//! call send what `poll_output` yields. [`Event::Blocked`] means the outbox is nearly full: drain it and call again with the unconsumed tail.

use crate::hpack::{self, HpackDecoder, HpackError};
use crate::http::{BuildError, Out};
use tdongle_tailnet_types::{Counter, FixedStr};

/// The 24-byte client connection preface.
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Frame header length.
pub const FRAME_HEADER_LEN: usize = 9;
/// Bytes of RST_STREAM / PING / GOAWAY / WINDOW_UPDATE payload kept (the C's `stream_special`).
pub const SPECIAL_BYTES: usize = 56;
/// Default and advertised maximum frame size (RFC 9113 6.5.2: we never raise it).
pub const DEFAULT_MAX_FRAME_LEN: u32 = 16384;
/// The flow-control window the C advertises (`CONFIG_ML_H2_BUFFER_SIZE_KB=64`): credit only, no buffer of this size exists.
pub const DEFAULT_RECV_WINDOW: u32 = 65536;
/// Outbox capacity in bytes.
pub const OUT_CAP: usize = 96;
/// Free outbox space required before another input step (the largest single reply is the two WINDOW_UPDATEs, 26 bytes).
const GUARD: usize = 32;
/// Bytes of GOAWAY debug text kept (`h2_debug[49]`).
pub const DEBUG_BYTES: usize = 48;

/// Frame type codes.
pub mod kind {
    /// DATA.
    pub const DATA: u8 = 0;
    /// HEADERS.
    pub const HEADERS: u8 = 1;
    /// PRIORITY.
    pub const PRIORITY: u8 = 2;
    /// RST_STREAM.
    pub const RST_STREAM: u8 = 3;
    /// SETTINGS.
    pub const SETTINGS: u8 = 4;
    /// PUSH_PROMISE.
    pub const PUSH_PROMISE: u8 = 5;
    /// PING.
    pub const PING: u8 = 6;
    /// GOAWAY.
    pub const GOAWAY: u8 = 7;
    /// WINDOW_UPDATE.
    pub const WINDOW_UPDATE: u8 = 8;
    /// CONTINUATION.
    pub const CONTINUATION: u8 = 9;
}

/// Frame flags.
pub mod flag {
    /// END_STREAM (DATA, HEADERS) / ACK (SETTINGS, PING).
    pub const END_STREAM: u8 = 0x01;
    /// ACK.
    pub const ACK: u8 = 0x01;
    /// END_HEADERS.
    pub const END_HEADERS: u8 = 0x04;
    /// PADDED.
    pub const PADDED: u8 = 0x08;
    /// PRIORITY (HEADERS).
    pub const PRIORITY: u8 = 0x20;
}

/// HTTP/2 error codes (RFC 9113 7).
pub mod code {
    /// NO_ERROR.
    pub const NO_ERROR: u32 = 0;
    /// PROTOCOL_ERROR (what a Go server answers a duplicate SETTINGS ACK with).
    pub const PROTOCOL_ERROR: u32 = 1;
    /// FLOW_CONTROL_ERROR.
    pub const FLOW_CONTROL_ERROR: u32 = 3;
    /// FRAME_SIZE_ERROR.
    pub const FRAME_SIZE_ERROR: u32 = 6;
    /// COMPRESSION_ERROR.
    pub const COMPRESSION_ERROR: u32 = 9;
}

/// A frame header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length as sent (padding included).
    pub length: u32,
    /// Frame type ([`kind`]).
    pub kind: u8,
    /// Flags.
    pub flags: u8,
    /// Stream identifier (reserved bit cleared).
    pub stream: u32,
}

impl FrameHeader {
    /// Parse nine bytes.
    pub fn parse(h: &[u8; 9]) -> Self {
        Self {
            length: ((h[0] as u32) << 16) | ((h[1] as u32) << 8) | h[2] as u32,
            kind: h[3],
            flags: h[4],
            stream: u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]),
        }
    }
    /// Encode (the reserved bit is written as 0, as the C does).
    pub fn encode(&self) -> [u8; 9] {
        let s = (self.stream & 0x7fff_ffff).to_be_bytes();
        [(self.length >> 16) as u8, (self.length >> 8) as u8, self.length as u8, self.kind, self.flags, s[0], s[1], s[2], s[3]]
    }
}

/// Why the frame reader gave up (it stays failed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A frame longer than the limit.
    TooLarge {
        /// The declared length.
        length: u32,
    },
    /// PADDED with no room for the pad length byte, or padding as long as the payload (C `map_error` 4).
    BadPadding,
    /// A HEADERS frame too short for its PADDED/PRIORITY fields.
    ShortHeaders,
}

/// What the reader saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameEvent<'a> {
    /// A frame header was completed.
    Header(FrameHeader),
    /// Payload bytes (DATA, HEADERS, CONTINUATION and SETTINGS only), padding and priority fields removed.
    Payload(&'a [u8]),
    /// The frame is complete.
    End(FrameHeader),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rs {
    Header,
    PadLen,
    Prefix,
    Body,
    Padding,
    Done,
    Failed,
}

fn emits_payload(k: u8) -> bool {
    matches!(k, kind::DATA | kind::HEADERS | kind::CONTINUATION | kind::SETTINGS)
}
fn collects(k: u8) -> bool {
    matches!(k, kind::RST_STREAM | kind::PING | kind::GOAWAY | kind::WINDOW_UPDATE)
}

/// The streaming frame tokeniser. Feed it any split of the stream.
#[derive(Clone, Debug)]
pub struct FrameReader {
    hdr: [u8; 9],
    hdr_used: u8,
    st: Rs,
    cur: FrameHeader,
    body_left: u32,
    pad_left: u32,
    prefix_left: u8,
    special: [u8; SPECIAL_BYTES],
    special_used: u8,
    max_frame: u32,
    /// Special-frame payload bytes that did not fit [`SPECIAL_BYTES`].
    pub special_truncated: Counter,
}

impl FrameReader {
    /// A reader refusing frames longer than `max_frame`.
    pub const fn new(max_frame: u32) -> Self {
        Self {
            hdr: [0; 9],
            hdr_used: 0,
            st: Rs::Header,
            cur: FrameHeader { length: 0, kind: 0, flags: 0, stream: 0 },
            body_left: 0,
            pad_left: 0,
            prefix_left: 0,
            special: [0; SPECIAL_BYTES],
            special_used: 0,
            max_frame,
            special_truncated: Counter(0),
        }
    }

    /// The special-frame payload of the frame being read (complete at its [`FrameEvent::End`]).
    pub fn special(&self) -> &[u8] {
        &self.special[..self.special_used as usize]
    }

    /// Bytes of payload still to come in the current frame (0 between frames).
    pub fn remaining(&self) -> u32 {
        self.body_left + self.pad_left
    }

    /// Consume input until one event is ready. Returns the bytes consumed and the event; `(0, None)` with input left is impossible, `(n, None)` means
    /// "keep going". With empty input this still returns a pending [`FrameEvent::End`].
    pub fn push<'a>(&mut self, input: &'a [u8]) -> Result<(usize, Option<FrameEvent<'a>>), FrameError> {
        match self.st {
            Rs::Failed => Err(FrameError::BadPadding),
            Rs::Done => {
                self.st = Rs::Header;
                self.hdr_used = 0;
                Ok((0, Some(FrameEvent::End(self.cur))))
            }
            Rs::Header => {
                let mut n = 0;
                while self.hdr_used < 9 && n < input.len() {
                    self.hdr[self.hdr_used as usize] = input[n];
                    self.hdr_used += 1;
                    n += 1;
                }
                if self.hdr_used < 9 {
                    return Ok((n, None));
                }
                let h = FrameHeader::parse(&self.hdr);
                self.cur = h;
                self.special_used = 0;
                if h.length > self.max_frame {
                    self.st = Rs::Failed;
                    return Err(FrameError::TooLarge { length: h.length });
                }
                let padded = matches!(h.kind, kind::DATA | kind::HEADERS) && h.flags & flag::PADDED != 0;
                let prio = h.kind == kind::HEADERS && h.flags & flag::PRIORITY != 0;
                let fixed = padded as u32 + if prio { 5 } else { 0 };
                if h.length < fixed {
                    self.st = Rs::Failed;
                    return Err(if h.kind == kind::DATA { FrameError::BadPadding } else { FrameError::ShortHeaders });
                }
                self.body_left = h.length - fixed;
                self.pad_left = 0;
                self.prefix_left = if prio { 5 } else { 0 };
                self.st = if padded {
                    Rs::PadLen
                } else if prio {
                    Rs::Prefix
                } else {
                    self.after_prefix()
                };
                Ok((n, Some(FrameEvent::Header(h))))
            }
            Rs::PadLen => {
                let Some(&b) = input.first() else { return Ok((0, None)) };
                if b as u32 > self.body_left {
                    self.st = Rs::Failed;
                    return Err(FrameError::BadPadding);
                }
                self.pad_left = b as u32;
                self.body_left -= b as u32;
                self.st = if self.prefix_left > 0 { Rs::Prefix } else { self.after_prefix() };
                Ok((1, None))
            }
            Rs::Prefix => {
                let n = input.len().min(self.prefix_left as usize);
                self.prefix_left -= n as u8;
                if self.prefix_left == 0 {
                    self.st = self.after_prefix();
                }
                Ok((n, None))
            }
            Rs::Body => {
                let n = input.len().min(self.body_left as usize);
                if n == 0 {
                    return Ok((0, None));
                }
                let chunk = &input[..n];
                self.body_left -= n as u32;
                if self.body_left == 0 {
                    self.st = if self.pad_left > 0 { Rs::Padding } else { Rs::Done };
                }
                if emits_payload(self.cur.kind) {
                    return Ok((n, Some(FrameEvent::Payload(chunk))));
                }
                if collects(self.cur.kind) {
                    let room = SPECIAL_BYTES - self.special_used as usize;
                    let take = room.min(n);
                    self.special[self.special_used as usize..self.special_used as usize + take].copy_from_slice(&chunk[..take]);
                    self.special_used += take as u8;
                    self.special_truncated.0 = self.special_truncated.0.saturating_add((n - take) as u32);
                }
                Ok((n, None))
            }
            Rs::Padding => {
                let n = input.len().min(self.pad_left as usize);
                self.pad_left -= n as u32;
                if self.pad_left == 0 {
                    self.st = Rs::Done;
                }
                Ok((n, None))
            }
        }
    }

    fn after_prefix(&self) -> Rs {
        if self.body_left > 0 {
            Rs::Body
        } else if self.pad_left > 0 {
            Rs::Padding
        } else {
            Rs::Done
        }
    }
}

/// Session configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// `SETTINGS_INITIAL_WINDOW_SIZE` advertised, and the connection window raised to match (the C: 65536).
    pub recv_window: u32,
    /// Largest frame accepted (we never advertise more than the 16384 default).
    pub max_frame_len: u32,
    /// Also advertise `SETTINGS_HEADER_TABLE_SIZE = 0` so a server never indexes headers we could not resolve. Off by default: the C's preface carries
    /// only INITIAL_WINDOW_SIZE.
    pub zero_header_table: bool,
    /// Longest header block (HEADERS + CONTINUATION) accepted.
    pub max_header_block: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self { recv_window: DEFAULT_RECV_WINDOW, max_frame_len: DEFAULT_MAX_FRAME_LEN, zero_header_table: false, max_header_block: 16384 }
    }
}

/// A connection error (the session answers with GOAWAY and goes dead). Every refusal is a variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H2Error {
    /// A frame beyond the size limit.
    FrameTooLarge,
    /// A frame with the wrong length for its type.
    FrameSize,
    /// Bad DATA/HEADERS padding.
    BadPadding,
    /// A stream-0-only frame on a stream, or a stream frame on stream 0.
    WrongStream,
    /// CONTINUATION without a HEADERS to continue.
    UnexpectedContinuation,
    /// Another frame in the middle of a header block.
    ExpectedContinuation,
    /// A SETTINGS ACK we were not waiting for (the duplicate-ACK rule).
    DuplicateSettingsAck,
    /// An invalid SETTINGS value.
    BadSettings,
    /// The peer overran a flow-control window, or a window overflowed.
    FlowControl,
    /// A WINDOW_UPDATE of zero on the connection.
    ZeroWindowIncrement,
    /// PUSH_PROMISE (never enabled).
    PushPromise,
    /// The header block is longer than the bound.
    HeaderBlockTooLarge,
    /// A malformed HPACK block.
    Compression(HpackError),
}

impl H2Error {
    /// The GOAWAY code for this error.
    pub fn code(self) -> u32 {
        match self {
            H2Error::FrameTooLarge | H2Error::FrameSize => code::FRAME_SIZE_ERROR,
            H2Error::FlowControl => code::FLOW_CONTROL_ERROR,
            H2Error::Compression(_) | H2Error::HeaderBlockTooLarge => code::COMPRESSION_ERROR,
            _ => code::PROTOCOL_ERROR,
        }
    }
}

impl From<FrameError> for H2Error {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::TooLarge { .. } => H2Error::FrameTooLarge,
            FrameError::BadPadding | FrameError::ShortHeaders => H2Error::BadPadding,
        }
    }
}

/// What [`Session::on_input`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// All input consumed; nothing to report.
    Idle,
    /// The outbox is nearly full: drain [`Session::poll_output`] and call again with the unconsumed tail.
    Blocked,
    /// The session is dead (after [`Event::Fatal`]); input is discarded.
    Closed,
    /// A SETTINGS frame was handled (an ACK was queued for a non-ACK one).
    Settings {
        /// This was the peer's ACK of our SETTINGS.
        ack: bool,
    },
    /// A response header block ended.
    Headers {
        /// Stream.
        stream: u32,
        /// `:status`, if it could be read.
        status: Option<u16>,
        /// Fields in the block.
        fields: u16,
    },
    /// A chunk of DATA payload (never empty, padding removed). Flow-control credit is returned when the frame ends.
    Data {
        /// Stream.
        stream: u32,
        /// Bytes.
        bytes: &'a [u8],
    },
    /// END_STREAM on `stream` (after its last DATA or HEADERS).
    StreamEnd {
        /// Stream.
        stream: u32,
    },
    /// RST_STREAM.
    Reset {
        /// Stream.
        stream: u32,
        /// Error code.
        code: u32,
    },
    /// GOAWAY (details in [`Session::close_info`]); no new requests are accepted.
    GoAway {
        /// Last stream the peer processed.
        last_stream: u32,
        /// Error code.
        code: u32,
    },
    /// PING (a non-ACK was answered) or its ACK.
    Ping {
        /// This is an ACK.
        ack: bool,
        /// The opaque data.
        opaque: [u8; 8],
    },
    /// The peer's WINDOW_UPDATE (connection-level ones are applied).
    WindowUpdate {
        /// Stream (0 = connection).
        stream: u32,
        /// Increment.
        increment: u32,
    },
    /// A connection error; GOAWAY was queued.
    Fatal(H2Error),
}

/// Why a request could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The output slice is too small (nothing written).
    TooSmall,
    /// The body exceeds the peer's connection or stream window (nothing written).
    FlowControl,
    /// The session is dead or the peer sent GOAWAY.
    Closed,
    /// A stream id that is even, zero or not greater than the last one used.
    BadStream,
    /// A field with control characters.
    BadField,
}

/// The sanitised close reason (`map_h2_error`, `map_h2_last_stream`, `h2_debug`): GOAWAY debug text is kept only when it is plain prose (letters, space,
/// `.-_`) and mentions no key, token, password or auth.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CloseInfo {
    /// A GOAWAY or RST_STREAM was received.
    pub valid: bool,
    /// Error code.
    pub error: u32,
    /// GOAWAY last stream, or the RST_STREAM stream.
    pub last_stream: u32,
    /// Sanitised debug text (empty if refused).
    pub debug: FixedStr<DEBUG_BYTES>,
}

fn sanitize_debug(raw: &[u8]) -> FixedStr<DEBUG_BYTES> {
    let mut out = FixedStr::new();
    let n = raw.len().min(DEBUG_BYTES);
    let raw = &raw[..n];
    if !raw.iter().all(|&c| c.is_ascii_alphabetic() || matches!(c, b' ' | b'.' | b'-' | b'_')) {
        return out;
    }
    let mut lower = [0u8; DEBUG_BYTES];
    for (i, &c) in raw.iter().enumerate() {
        lower[i] = c.to_ascii_lowercase();
    }
    let l = &lower[..n];
    for bad in [&b"key"[..], b"token", b"password", b"auth"] {
        if l.windows(bad.len()).any(|w| w == bad) {
            return out;
        }
    }
    out.set(core::str::from_utf8(raw).unwrap_or(""));
    out
}

/// Counters: every refusal and every reply is counted (ADR 0001 rule 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Frames completed.
    pub frames_in: Counter,
    /// DATA payload bytes delivered.
    pub data_bytes_in: Counter,
    /// SETTINGS ACKs sent.
    pub settings_acks_sent: Counter,
    /// WINDOW_UPDATE frames sent.
    pub window_updates_sent: Counter,
    /// PING ACKs sent.
    pub ping_acks_sent: Counter,
    /// Frames of a type we ignore (PRIORITY, unknown).
    pub ignored_frames: Counter,
    /// Stream-level WINDOW_UPDATEs received (ignored; requests are one-shot).
    pub stream_window_updates_ignored: Counter,
    /// Connection errors.
    pub fatal: Counter,
    /// Replies that did not fit the outbox (the caller did not drain it).
    pub outbox_overflow: Counter,
}

/// The connection.
#[derive(Clone, Debug)]
pub struct Session {
    reader: FrameReader,
    hpack: HpackDecoder,
    out: [u8; OUT_CAP],
    out_len: u8,
    dead: bool,
    goaway_received: bool,
    unacked_settings: u8,
    peer_initial_window: u32,
    peer_max_frame: u32,
    conn_send_window: i64,
    conn_recv_window: i64,
    last_local_stream: u32,
    cur: FrameHeader,
    settings_acc: [u8; 6],
    settings_used: u8,
    headers_end_stream: bool,
    expect_continuation: u32,
    pending_end: u32,
    close: CloseInfo,
    /// Counters.
    pub counters: Counters,
}

/// `size_of::<Session>()` on this target.
pub const SESSION_BYTES: usize = core::mem::size_of::<Session>();
/// `size_of::<FrameReader>()` on this target.
pub const FRAME_READER_BYTES: usize = core::mem::size_of::<FrameReader>();

impl Session {
    /// A session with the preface (client magic, SETTINGS, connection WINDOW_UPDATE) already queued: send it first.
    pub fn new(cfg: Config) -> Self {
        let mut s = Self {
            reader: FrameReader::new(cfg.max_frame_len),
            hpack: HpackDecoder::new(if cfg.zero_header_table { 0 } else { hpack::DEFAULT_TABLE_SIZE }, cfg.max_header_block),
            out: [0; OUT_CAP],
            out_len: 0,
            dead: false,
            goaway_received: false,
            unacked_settings: 1,
            peer_initial_window: 65535,
            peer_max_frame: DEFAULT_MAX_FRAME_LEN,
            conn_send_window: 65535,
            conn_recv_window: 65535 + cfg.recv_window.saturating_sub(65535) as i64,
            last_local_stream: 0,
            cur: FrameHeader::default(),
            settings_acc: [0; 6],
            settings_used: 0,
            headers_end_stream: false,
            expect_continuation: 0,
            pending_end: 0,
            close: CloseInfo::default(),
            counters: Counters::default(),
        };
        let mut tmp = [0u8; 64];
        if let Ok(n) = build_preface(&mut tmp, cfg.recv_window, cfg.zero_header_table) {
            s.q(&tmp[..n]);
        }
        let delta = cfg.recv_window.saturating_sub(65535);
        if delta > 0 {
            let mut f = [0u8; 13];
            if let Ok(n) = build_window_update(&mut f, 0, delta) {
                s.q(&f[..n]);
            }
        }
        s
    }

    fn q(&mut self, b: &[u8]) -> bool {
        if OUT_CAP - self.out_len as usize >= b.len() {
            self.out[self.out_len as usize..self.out_len as usize + b.len()].copy_from_slice(b);
            self.out_len += b.len() as u8;
            true
        } else {
            self.counters.outbox_overflow.bump();
            false
        }
    }

    /// Bytes queued for the peer.
    pub fn pending_output(&self) -> usize {
        self.out_len as usize
    }

    /// Move queued bytes into `buf` (oldest first); returns how many. Send them as one or more Noise records, in order.
    pub fn poll_output(&mut self, buf: &mut [u8]) -> usize {
        let n = (self.out_len as usize).min(buf.len());
        buf[..n].copy_from_slice(&self.out[..n]);
        self.out.copy_within(n..self.out_len as usize, 0);
        self.out_len -= n as u8;
        n
    }

    /// Queue a SETTINGS ACK (the answer to a SETTINGS frame is queued by the session itself; this exists for tests that inject a duplicate).
    pub fn queue_settings_ack(&mut self) -> bool {
        let mut f = [0u8; 9];
        build_settings_ack(&mut f).ok();
        self.counters.settings_acks_sent.bump();
        self.q(&f)
    }

    /// Queue a PING (keepalive; the C sends one every 5 s with the time as the opaque data).
    pub fn queue_ping(&mut self, opaque: [u8; 8]) -> bool {
        let mut f = [0u8; 17];
        f[..9].copy_from_slice(&FrameHeader { length: 8, kind: kind::PING, flags: 0, stream: 0 }.encode());
        f[9..].copy_from_slice(&opaque);
        self.q(&f)
    }

    /// The last GOAWAY or RST_STREAM received.
    pub fn close_info(&self) -> &CloseInfo {
        &self.close
    }

    /// True after a connection error.
    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// True once the peer sent GOAWAY.
    pub fn goaway_received(&self) -> bool {
        self.goaway_received
    }

    /// The peer's connection-level send window left for our DATA.
    pub fn send_window(&self) -> i64 {
        self.conn_send_window
    }

    /// Write a request (HEADERS, then DATA frames with END_STREAM on the last) for `stream` into `out`. Checks the peer's windows and frame size; nothing
    /// is written on error. HPACK is literals only.
    #[allow(clippy::too_many_arguments)]
    pub fn write_request(
        &mut self,
        out: &mut [u8],
        stream: u32,
        method: &str,
        path: &str,
        authority: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<usize, SendError> {
        if self.dead || self.goaway_received {
            return Err(SendError::Closed);
        }
        if stream == 0 || stream.is_multiple_of(2) || stream <= self.last_local_stream {
            return Err(SendError::BadStream);
        }
        if body.len() as i64 > self.conn_send_window || body.len() as u64 > self.peer_initial_window as u64 {
            return Err(SendError::FlowControl);
        }
        let mut o = Out::new(out);
        let end_on_headers = body.is_empty();
        write_headers(&mut o, stream, method, path, authority, Some(content_type), end_on_headers).map_err(map_build)?;
        let mut rest = body;
        while !rest.is_empty() {
            let n = rest.len().min(self.peer_max_frame as usize);
            let last = n == rest.len();
            o.put(&FrameHeader { length: n as u32, kind: kind::DATA, flags: if last { flag::END_STREAM } else { 0 }, stream }.encode()).map_err(map_build)?;
            o.put(&rest[..n]).map_err(map_build)?;
            rest = &rest[n..];
        }
        self.conn_send_window -= body.len() as i64;
        self.last_local_stream = stream;
        Ok(o.len())
    }

    fn fatal(&mut self, e: H2Error) -> Event<'static> {
        if !self.dead {
            let mut f = [0u8; 17];
            f[..9].copy_from_slice(&FrameHeader { length: 8, kind: kind::GOAWAY, flags: 0, stream: 0 }.encode());
            f[13..17].copy_from_slice(&e.code().to_be_bytes());
            self.q(&f);
            self.counters.fatal.bump();
        }
        self.dead = true;
        Event::Fatal(e)
    }

    /// Feed bytes from the peer. Returns how many were consumed and what happened; call again with the rest until the input is empty and the event is
    /// [`Event::Idle`]. After [`Event::Fatal`] every call returns [`Event::Closed`] and consumes everything.
    pub fn on_input<'a>(&mut self, input: &'a [u8]) -> (usize, Event<'a>) {
        if self.dead {
            return (input.len(), Event::Closed);
        }
        if self.pending_end != 0 {
            let stream = core::mem::take(&mut self.pending_end);
            return (0, Event::StreamEnd { stream });
        }
        let mut pos = 0;
        loop {
            if OUT_CAP - (self.out_len as usize) < GUARD {
                return (pos, Event::Blocked);
            }
            let (n, ev) = match self.reader.push(&input[pos..]) {
                Ok(x) => x,
                Err(e) => return (pos, self.fatal(e.into())),
            };
            pos += n;
            match ev {
                None if n == 0 => return (pos, Event::Idle),
                None => {}
                Some(fe) => {
                    if let Some(e) = self.handle(fe) {
                        return (pos, e);
                    }
                }
            }
        }
    }

    fn handle<'a>(&mut self, fe: FrameEvent<'a>) -> Option<Event<'a>> {
        match fe {
            FrameEvent::Header(h) => self.on_header(h),
            FrameEvent::Payload(b) => self.on_payload(b),
            FrameEvent::End(h) => {
                self.counters.frames_in.bump();
                self.on_end(h)
            }
        }
    }

    fn on_header<'a>(&mut self, h: FrameHeader) -> Option<Event<'a>> {
        self.cur = h;
        if self.expect_continuation != 0 && h.kind != kind::CONTINUATION {
            return Some(self.fatal(H2Error::ExpectedContinuation));
        }
        let stream_zero = h.stream == 0;
        let bad = |s: &mut Self, e| Some(s.fatal(e));
        match h.kind {
            kind::DATA => {
                if stream_zero {
                    return bad(self, H2Error::WrongStream);
                }
                if h.length as i64 > self.conn_recv_window {
                    return bad(self, H2Error::FlowControl);
                }
                self.conn_recv_window -= h.length as i64;
            }
            kind::HEADERS => {
                if stream_zero {
                    return bad(self, H2Error::WrongStream);
                }
                self.hpack.start_block();
                self.headers_end_stream = h.flags & flag::END_STREAM != 0;
                self.expect_continuation = if h.flags & flag::END_HEADERS == 0 { h.stream } else { 0 };
            }
            kind::CONTINUATION => {
                if self.expect_continuation == 0 || self.expect_continuation != h.stream {
                    return bad(self, H2Error::UnexpectedContinuation);
                }
                if h.flags & flag::END_HEADERS != 0 {
                    self.expect_continuation = 0;
                }
            }
            kind::PRIORITY => {
                if stream_zero {
                    return bad(self, H2Error::WrongStream);
                }
                if h.length != 5 {
                    return bad(self, H2Error::FrameSize);
                }
                self.counters.ignored_frames.bump();
            }
            kind::RST_STREAM => {
                if stream_zero {
                    return bad(self, H2Error::WrongStream);
                }
                if h.length != 4 {
                    return bad(self, H2Error::FrameSize);
                }
            }
            kind::SETTINGS => {
                if !stream_zero {
                    return bad(self, H2Error::WrongStream);
                }
                self.settings_used = 0;
                if h.flags & flag::ACK != 0 {
                    if h.length != 0 {
                        return bad(self, H2Error::FrameSize);
                    }
                    if self.unacked_settings == 0 {
                        return bad(self, H2Error::DuplicateSettingsAck);
                    }
                    self.unacked_settings -= 1;
                } else if !h.length.is_multiple_of(6) {
                    return bad(self, H2Error::FrameSize);
                }
            }
            kind::PUSH_PROMISE => return bad(self, H2Error::PushPromise),
            kind::PING => {
                if !stream_zero {
                    return bad(self, H2Error::WrongStream);
                }
                if h.length != 8 {
                    return bad(self, H2Error::FrameSize);
                }
            }
            kind::GOAWAY => {
                if !stream_zero {
                    return bad(self, H2Error::WrongStream);
                }
                if h.length < 8 {
                    return bad(self, H2Error::FrameSize);
                }
            }
            kind::WINDOW_UPDATE => {
                if h.length != 4 {
                    return bad(self, H2Error::FrameSize);
                }
            }
            _ => self.counters.ignored_frames.bump(),
        }
        None
    }

    fn on_payload<'a>(&mut self, b: &'a [u8]) -> Option<Event<'a>> {
        let h = self.cur;
        match h.kind {
            kind::DATA => {
                self.counters.data_bytes_in.0 = self.counters.data_bytes_in.0.saturating_add(b.len() as u32);
                Some(Event::Data { stream: h.stream, bytes: b })
            }
            kind::HEADERS | kind::CONTINUATION => {
                for &x in b {
                    if let Err(e) = self.hpack.feed(x) {
                        return Some(self.fatal(if e == HpackError::TooLong { H2Error::HeaderBlockTooLarge } else { H2Error::Compression(e) }));
                    }
                }
                None
            }
            kind::SETTINGS if h.flags & flag::ACK == 0 => {
                for &x in b {
                    self.settings_acc[self.settings_used as usize] = x;
                    self.settings_used += 1;
                    if self.settings_used == 6 {
                        self.settings_used = 0;
                        let id = u16::from_be_bytes([self.settings_acc[0], self.settings_acc[1]]);
                        let v = u32::from_be_bytes([self.settings_acc[2], self.settings_acc[3], self.settings_acc[4], self.settings_acc[5]]);
                        match id {
                            2 if v > 1 => return Some(self.fatal(H2Error::BadSettings)),
                            4 if v > 0x7fff_ffff => return Some(self.fatal(H2Error::FlowControl)),
                            4 => self.peer_initial_window = v,
                            5 if !(16384..=16_777_215).contains(&v) => return Some(self.fatal(H2Error::BadSettings)),
                            5 => self.peer_max_frame = v,
                            _ => {}
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn on_end<'a>(&mut self, h: FrameHeader) -> Option<Event<'a>> {
        match h.kind {
            kind::DATA => {
                self.conn_recv_window += h.length as i64;
                if h.length > 0 {
                    let mut f = [0u8; 26];
                    // The C returns the credit for the whole frame on the connection and on the stream.
                    let a = build_window_update(&mut f, 0, h.length).unwrap_or(0);
                    let b = build_window_update(&mut f[a..], h.stream, h.length).unwrap_or(0);
                    if self.q(&f[..a + b]) {
                        self.counters.window_updates_sent.0 += 2;
                    }
                }
                if h.flags & flag::END_STREAM != 0 {
                    return Some(Event::StreamEnd { stream: h.stream });
                }
                None
            }
            kind::HEADERS | kind::CONTINUATION => {
                if h.flags & flag::END_HEADERS == 0 {
                    return None;
                }
                match self.hpack.end_block() {
                    Ok(s) => {
                        if self.headers_end_stream {
                            self.pending_end = h.stream;
                        }
                        Some(Event::Headers { stream: h.stream, status: s.status, fields: s.fields })
                    }
                    Err(e) => Some(self.fatal(H2Error::Compression(e))),
                }
            }
            kind::SETTINGS => {
                if h.flags & flag::ACK == 0 {
                    let mut f = [0u8; 9];
                    build_settings_ack(&mut f).ok();
                    if self.q(&f) {
                        self.counters.settings_acks_sent.bump();
                    }
                }
                Some(Event::Settings { ack: h.flags & flag::ACK != 0 })
            }
            kind::PING => {
                let mut opaque = [0u8; 8];
                let sp = self.reader.special();
                let n = sp.len().min(8);
                opaque[..n].copy_from_slice(&sp[..n]);
                let ack = h.flags & flag::ACK != 0;
                if !ack {
                    let mut f = [0u8; 17];
                    f[..9].copy_from_slice(&FrameHeader { length: 8, kind: kind::PING, flags: flag::ACK, stream: 0 }.encode());
                    f[9..].copy_from_slice(&opaque);
                    if self.q(&f) {
                        self.counters.ping_acks_sent.bump();
                    }
                }
                Some(Event::Ping { ack, opaque })
            }
            kind::GOAWAY => {
                let sp = self.reader.special();
                let last_stream = u32::from_be_bytes([sp[0], sp[1], sp[2], sp[3]]) & 0x7fff_ffff;
                let code = u32::from_be_bytes([sp[4], sp[5], sp[6], sp[7]]);
                self.close = CloseInfo { valid: true, error: code, last_stream, debug: sanitize_debug(&sp[8..]) };
                self.goaway_received = true;
                Some(Event::GoAway { last_stream, code })
            }
            kind::RST_STREAM => {
                let sp = self.reader.special();
                let code = u32::from_be_bytes([sp[0], sp[1], sp[2], sp[3]]);
                self.close = CloseInfo { valid: true, error: code, last_stream: h.stream, debug: FixedStr::new() };
                Some(Event::Reset { stream: h.stream, code })
            }
            kind::WINDOW_UPDATE => {
                let sp = self.reader.special();
                let inc = u32::from_be_bytes([sp[0], sp[1], sp[2], sp[3]]) & 0x7fff_ffff;
                if h.stream == 0 {
                    if inc == 0 {
                        return Some(self.fatal(H2Error::ZeroWindowIncrement));
                    }
                    self.conn_send_window += inc as i64;
                    if self.conn_send_window > 0x7fff_ffff {
                        return Some(self.fatal(H2Error::FlowControl));
                    }
                } else {
                    self.counters.stream_window_updates_ignored.bump();
                }
                Some(Event::WindowUpdate { stream: h.stream, increment: inc })
            }
            _ => None,
        }
    }
}

fn map_build(e: BuildError) -> SendError {
    match e {
        BuildError::TooSmall => SendError::TooSmall,
        BuildError::BadField => SendError::BadField,
    }
}

/// `ml_h2_build_preface`: the client magic and a SETTINGS frame carrying `INITIAL_WINDOW_SIZE = window` (and `HEADER_TABLE_SIZE = 0` if asked). 39 bytes
/// for the C-compatible form. The connection WINDOW_UPDATE is a separate frame ([`build_window_update`]).
pub fn build_preface(out: &mut [u8], window: u32, zero_header_table: bool) -> Result<usize, BuildError> {
    let mut o = Out::new(out);
    o.put(PREFACE)?;
    let entries = 1 + zero_header_table as u32;
    o.put(&FrameHeader { length: 6 * entries, kind: kind::SETTINGS, flags: 0, stream: 0 }.encode())?;
    if zero_header_table {
        o.put(&[0, 1, 0, 0, 0, 0])?;
    }
    o.put(&[0, 4])?;
    o.put(&window.to_be_bytes())?;
    Ok(o.len())
}

/// `ml_h2_build_settings_ack`: 9 bytes.
pub fn build_settings_ack(out: &mut [u8]) -> Result<usize, BuildError> {
    let mut o = Out::new(out);
    o.put(&FrameHeader { length: 0, kind: kind::SETTINGS, flags: flag::ACK, stream: 0 }.encode())?;
    Ok(o.len())
}

/// `ml_h2_build_window_update`: 13 bytes.
pub fn build_window_update(out: &mut [u8], stream: u32, increment: u32) -> Result<usize, BuildError> {
    let mut o = Out::new(out);
    o.put(&FrameHeader { length: 4, kind: kind::WINDOW_UPDATE, flags: 0, stream }.encode())?;
    o.put(&(increment & 0x7fff_ffff).to_be_bytes())?;
    Ok(o.len())
}

fn write_headers(
    o: &mut Out<'_>,
    stream: u32,
    method: &str,
    path: &str,
    authority: &str,
    content_type: Option<&str>,
    end_stream: bool,
) -> Result<(), BuildError> {
    for s in [method, path, authority].into_iter().chain(content_type) {
        if s.bytes().any(|c| c < 0x20 || c == 0x7f) {
            return Err(BuildError::BadField);
        }
    }
    // Build the block in a bounded scratch first: the frame header needs its length.
    let mut block = [0u8; 512];
    let n = {
        let mut b = Out::new(&mut block);
        match method {
            "POST" => b.put(&[0x83])?,
            "GET" => b.put(&[0x82])?,
            m => hpack::put_literal_indexed_name(&mut b, 2, m)?,
        }
        if path == "/" {
            b.put(&[0x84])?;
        } else {
            hpack::put_literal_indexed_name(&mut b, 4, path)?;
        }
        b.put(&[0x86])?; // :scheme http: Noise over raw TCP, not TLS
        if !authority.is_empty() {
            hpack::put_literal_indexed_name(&mut b, 1, authority)?;
        }
        if let Some(ct) = content_type {
            hpack::put_literal_indexed_name(&mut b, 31, ct)?;
        }
        b.len()
    };
    let flags = flag::END_HEADERS | if end_stream { flag::END_STREAM } else { 0 };
    o.put(&FrameHeader { length: n as u32, kind: kind::HEADERS, flags, stream }.encode())?;
    o.put(&block[..n])
}

/// `ml_h2_build_headers_frame`: HEADERS with `:method`, `:path`, `:scheme http`, `:authority` and `content-type` as HPACK literals (never indexed).
pub fn build_headers(
    out: &mut [u8],
    method: &str,
    path: &str,
    authority: &str,
    content_type: Option<&str>,
    stream: u32,
    end_stream: bool,
) -> Result<usize, BuildError> {
    let mut o = Out::new(out);
    write_headers(&mut o, stream, method, path, authority, content_type, end_stream)?;
    Ok(o.len())
}

/// `ml_h2_build_data_frame`.
pub fn build_data(out: &mut [u8], data: &[u8], stream: u32, end_stream: bool) -> Result<usize, BuildError> {
    let mut o = Out::new(out);
    o.put(&FrameHeader { length: data.len() as u32, kind: kind::DATA, flags: if end_stream { flag::END_STREAM } else { 0 }, stream }.encode())?;
    o.put(data)?;
    Ok(o.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::{format, string::String, string::ToString, vec, vec::Vec};

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = FrameHeader { length: payload.len() as u32, kind, flags, stream }.encode().to_vec();
        v.extend_from_slice(payload);
        v
    }

    fn drain(s: &mut Session) -> Vec<u8> {
        let mut all = vec![];
        let mut b = [0u8; 40];
        loop {
            let n = s.poll_output(&mut b);
            if n == 0 {
                return all;
            }
            all.extend_from_slice(&b[..n]);
        }
    }

    /// Run `bytes` through a session in `piece`-sized chunks; returns a compact trace of events and everything the session sent.
    fn trace(bytes: &[u8], piece: usize) -> (Vec<String>, Vec<u8>) {
        let mut s = Session::new(Config::default());
        let mut out = drain(&mut s);
        let mut t = vec![];
        let mut data: Vec<u8> = vec![];
        for chunk in bytes.chunks(piece.max(1)) {
            let mut rest = chunk;
            loop {
                let (n, ev) = s.on_input(rest);
                rest = &rest[n..];
                out.extend(drain(&mut s));
                match ev {
                    Event::Idle => break,
                    Event::Blocked => {}
                    Event::Data { stream, bytes } => data.extend(bytes.iter().map(|b| b ^ stream as u8)),
                    e => t.push(format!("{e:?}")),
                }
                if matches!(ev, Event::Closed) {
                    break;
                }
            }
        }
        t.push(format!("data={data:?}"));
        (t, out)
    }

    #[test]
    fn preface_matches_the_c_bytes() {
        let mut b = [0u8; 64];
        let n = build_preface(&mut b, 65536, false).unwrap();
        assert_eq!(n, 39);
        let mut expect = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        expect.extend_from_slice(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0]);
        assert_eq!(&b[..n], &expect[..]);
        let mut s = Session::new(Config::default());
        let out = drain(&mut s);
        // preface 39 + connection WINDOW_UPDATE of 65536 - 65535 = 1
        assert_eq!(out.len(), 52);
        assert_eq!(&out[39..], &[0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // No ACK frame in the preface (test_h2_handshake.c's noise_send assertion).
        let mut p = 24;
        while p + 9 <= out.len() {
            assert!(!(out[p + 3] == 4 && out[p + 4] == 1));
            p += 9 + ((out[p] as usize) << 16 | (out[p + 1] as usize) << 8 | out[p + 2] as usize);
        }
        let z = build_preface(&mut b, 65536, true).unwrap();
        assert_eq!(z, 24 + 9 + 12);
        assert!(build_preface(&mut b[..38], 65536, false).is_err());
    }

    #[test]
    fn frame_builders_match_the_c() {
        let mut b = [0u8; 256];
        assert_eq!(build_settings_ack(&mut b), Ok(9));
        assert_eq!(&b[..9], &[0, 0, 0, 4, 1, 0, 0, 0, 0]);
        assert_eq!(build_window_update(&mut b, 5, 0x1234), Ok(13));
        assert_eq!(&b[..13], &[0, 0, 4, 8, 0, 0, 0, 0, 5, 0, 0, 0x12, 0x34]);
        let n = build_headers(&mut b, "POST", "/machine/register", "localhost", Some("application/json"), 1, false).unwrap();
        assert_eq!(b[3], 1);
        assert_eq!(b[4], flag::END_HEADERS);
        assert_eq!(&b[5..9], &[0, 0, 0, 1]);
        assert_eq!(((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize) + 9, n);
        assert_eq!(&b[9..13], &[0x83, 0x04, 17, b'/']); // :method POST indexed; :path literal, static name 4
        assert!(b[9..n].windows(2).any(|w| w == [0x86, 0x01]) || b[9..n].contains(&0x86)); // :scheme http
        // The block decodes: five fields, no dynamic references.
        let mut d = HpackDecoder::new(4096, 1024);
        d.start_block();
        for &x in &b[9..n] {
            d.feed(x).unwrap();
        }
        let sum = d.end_block().unwrap();
        assert_eq!((sum.fields, sum.dynamic_refs), (5, 0));
        let n = build_data(&mut b, b"{}", 1, true).unwrap();
        assert_eq!(&b[..n], &[0, 0, 2, 0, 1, 0, 0, 0, 1, b'{', b'}']);
        assert_eq!(build_headers(&mut b, "GET\r\n", "/", "h", None, 1, true), Err(BuildError::BadField));
        // A path longer than 127 bytes needs a multi-byte HPACK length, which the C's single byte would have corrupted.
        let long = format!("/{}", "a".repeat(200));
        let n = build_headers(&mut b, "GET", &long, "h", None, 3, true).unwrap();
        let mut d = HpackDecoder::new(4096, 1024);
        d.start_block();
        for &x in &b[9..n] {
            d.feed(x).unwrap();
        }
        assert_eq!(d.end_block().unwrap().fields, 4);
    }

    #[test]
    fn server_settings_are_acked_exactly_once() {
        let mut s = Session::new(Config::default());
        drain(&mut s);
        let mut input = frame(kind::SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100, 0, 4, 0, 1, 0, 0]);
        input.extend(frame(kind::SETTINGS, flag::ACK, 0, &[]));
        let (n, ev) = s.on_input(&input);
        assert!(matches!(ev, Event::Settings { ack: false }));
        let (m, ev2) = s.on_input(&input[n..]);
        assert!(matches!(ev2, Event::Settings { ack: true }));
        assert_eq!(n + m, input.len());
        assert_eq!(drain(&mut s), [0, 0, 0, 4, 1, 0, 0, 0, 0]);
        assert_eq!(s.counters.settings_acks_sent.get(), 1);
        assert_eq!(s.send_window(), 65535);
    }

    #[test]
    fn duplicate_ack_is_a_connection_error_with_goaway() {
        let mut s = Session::new(Config::default());
        drain(&mut s);
        let ack = frame(kind::SETTINGS, flag::ACK, 0, &[]);
        assert!(matches!(s.on_input(&ack).1, Event::Settings { ack: true })); // the one we are owed
        let (_, ev) = s.on_input(&ack);
        assert_eq!(ev, Event::Fatal(H2Error::DuplicateSettingsAck));
        let out = drain(&mut s);
        assert_eq!(out, [0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // GOAWAY, last stream 0, PROTOCOL_ERROR
        assert!(s.is_dead());
        assert_eq!(s.on_input(&[1, 2, 3]), (3, Event::Closed));
        assert!(drain(&mut s).is_empty());
        assert_eq!(s.write_request(&mut [0; 200], 1, "GET", "/", "h", "t", b""), Err(SendError::Closed));
    }

    #[test]
    fn data_returns_credit_on_both_windows_and_strips_padding() {
        let mut s = Session::new(Config::default());
        drain(&mut s);
        let payload = [3, b'a', b'b', b'c', b'd', 0, 0, 0]; // pad length 3, data "abcd"
        let input = frame(kind::DATA, flag::PADDED | flag::END_STREAM, 5, &payload);
        let (n, ev) = s.on_input(&input);
        assert_eq!(ev, Event::Data { stream: 5, bytes: b"abcd" });
        let (n2, ev) = s.on_input(&input[n..]);
        assert_eq!(ev, Event::StreamEnd { stream: 5 });
        assert_eq!(n + n2, input.len());
        // The C returns the whole frame length (padding included) on stream 0 and the stream.
        let mut want = vec![];
        want.extend([0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        want.extend([0, 0, 4, 8, 0, 0, 0, 0, 5, 0, 0, 0, 8]);
        assert_eq!(drain(&mut s), want);
        assert_eq!(s.counters.data_bytes_in.get(), 4);
        // An empty DATA frame returns no credit but still ends the stream.
        let e = frame(kind::DATA, flag::END_STREAM, 5, &[]);
        assert_eq!(s.on_input(&e).1, Event::StreamEnd { stream: 5 });
        assert!(drain(&mut s).is_empty());
    }

    #[test]
    fn bad_padding_is_refused_like_the_c() {
        for (payload, flags) in [(vec![], flag::PADDED), (vec![5, 1, 2], flag::PADDED), (vec![3, 1, 2], flag::PADDED)] {
            let mut s = Session::new(Config::default());
            let f = frame(kind::DATA, flags, 1, &payload);
            let (_, ev) = s.on_input(&f);
            assert_eq!(ev, Event::Fatal(H2Error::BadPadding), "{payload:?}");
        }
        // pad == length - 1 leaves no data and is legal.
        let mut s = Session::new(Config::default());
        drain(&mut s);
        let f = frame(kind::DATA, flag::PADDED, 1, &[2, 0, 0]);
        let (_, ev) = s.on_input(&f);
        assert_eq!(ev, Event::Idle);
    }

    #[test]
    fn ping_goaway_reset() {
        let mut s = Session::new(Config::default());
        drain(&mut s);
        let id = [1, 2, 3, 4, 5, 6, 7, 8];
        let f = frame(kind::PING, 0, 0, &id);
        let (_, ev) = s.on_input(&f);
        assert_eq!(ev, Event::Ping { ack: false, opaque: id });
        let mut want = vec![0, 0, 8, 6, 1, 0, 0, 0, 0];
        want.extend(id);
        assert_eq!(drain(&mut s), want);
        assert_eq!(s.on_input(&frame(kind::PING, flag::ACK, 0, &id)).1, Event::Ping { ack: true, opaque: id });
        assert!(drain(&mut s).is_empty());
        assert_eq!(s.on_input(&frame(kind::PING, 0, 0, &id[..4])).1, Event::Fatal(H2Error::FrameSize));

        let mut s = Session::new(Config::default());
        let mut g = vec![0, 0, 0, 5, 0, 0, 0, 1];
        g.extend(b"too many streams");
        assert_eq!(s.on_input(&frame(kind::GOAWAY, 0, 0, &g)).1, Event::GoAway { last_stream: 5, code: 1 });
        assert!(s.goaway_received());
        let ci = s.close_info();
        assert_eq!((ci.valid, ci.error, ci.last_stream, ci.debug.as_str()), (true, 1, 5, "too many streams"));
        assert_eq!(s.write_request(&mut [0; 200], 1, "GET", "/", "h", "t", b""), Err(SendError::Closed));
        // Debug text with digits, secrets or keywords is dropped; the codes stay.
        for text in ["has digit 5", "bad key here", "TOKEN expired", "your password", "AuThOrIzAtIoN failed", "bin\u{1}ary"] {
            let mut s = Session::new(Config::default());
            let mut g = vec![0x80, 0, 0, 7, 0, 0, 0, 2];
            g.extend(text.as_bytes());
            assert_eq!(s.on_input(&frame(kind::GOAWAY, 0, 0, &g)).1, Event::GoAway { last_stream: 7, code: 2 });
            assert_eq!(s.close_info().debug.as_str(), "", "{text}");
        }
        // 60 bytes of debug text: only the first 48 are kept.
        let mut s = Session::new(Config::default());
        let mut g = vec![0, 0, 0, 1, 0, 0, 0, 0];
        g.extend(std::iter::repeat_n(b'z', 60));
        s.on_input(&frame(kind::GOAWAY, 0, 0, &g));
        assert_eq!(s.close_info().debug.len(), 48);
        // Truncated GOAWAY / RST are connection errors (C: "Truncated HTTP/2 close frame").
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::GOAWAY, 0, 0, &[0, 0, 0, 1])).1, Event::Fatal(H2Error::FrameSize));
        let mut s = Session::new(Config::default());
        assert_eq!(s.on_input(&frame(kind::RST_STREAM, 0, 5, &[0, 0, 0, 8])).1, Event::Reset { stream: 5, code: 8 });
        assert_eq!((s.close_info().error, s.close_info().last_stream), (8, 5));
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::RST_STREAM, 0, 5, &[0, 0])).1, Event::Fatal(H2Error::FrameSize));
    }

    #[test]
    fn headers_with_continuation_status_and_end_stream() {
        let mut s = Session::new(Config::default());
        drain(&mut s);
        let mut input = frame(kind::HEADERS, flag::END_STREAM, 1, &[0x88]);
        // Rewrite as an unfinished block continued: HEADERS(no END_HEADERS) carrying 0x48 0x03 '4', CONTINUATION "0" "4".
        input.clear();
        input.extend(frame(kind::HEADERS, flag::END_STREAM, 3, &[0x48, 0x03, b'4']));
        input.extend(frame(kind::CONTINUATION, flag::END_HEADERS, 3, b"04"));
        let mut events = vec![];
        let mut rest = &input[..];
        loop {
            let (n, ev) = s.on_input(rest);
            rest = &rest[n..];
            if ev == Event::Idle {
                break;
            }
            events.push(ev);
        }
        assert_eq!(events, [Event::Headers { stream: 3, status: Some(404), fields: 1 }, Event::StreamEnd { stream: 3 }]);
        // A HEADERS frame with padding and priority fields.
        let mut s = Session::new(Config::default());
        let mut p = vec![2, 0, 0, 0, 7, 15]; // pad 2, dependency 4 bytes, weight, then the block
        p.push(0x88);
        p.extend([0, 0]);
        let f = frame(kind::HEADERS, flag::END_HEADERS | flag::PADDED | flag::PRIORITY, 1, &p);
        let (_, ev) = s.on_input(&f);
        assert_eq!(ev, Event::Headers { stream: 1, status: Some(200), fields: 1 });
        // Interleaving anything between HEADERS and CONTINUATION is an error; so is a stray CONTINUATION.
        let mut s = Session::new(Config::default());
        let mut i = frame(kind::HEADERS, 0, 1, &[0x88]);
        i.extend(frame(kind::PING, 0, 0, &[0; 8]));
        assert_eq!(s.on_input(&i).1, Event::Fatal(H2Error::ExpectedContinuation));
        assert_eq!(
            Session::new(Config::default()).on_input(&frame(kind::CONTINUATION, flag::END_HEADERS, 1, &[0x88])).1,
            Event::Fatal(H2Error::UnexpectedContinuation)
        );
        // Compression errors.
        assert_eq!(
            Session::new(Config::default()).on_input(&frame(kind::HEADERS, flag::END_HEADERS, 1, &[0x80])).1,
            Event::Fatal(H2Error::Compression(HpackError::BadInteger))
        );
        assert_eq!(
            Session::new(Config::default()).on_input(&frame(kind::HEADERS, flag::END_HEADERS, 1, &[0x40])).1,
            Event::Fatal(H2Error::Compression(HpackError::Truncated))
        );
        // A header block above the bound.
        let mut s = Session::new(Config { max_header_block: 4, ..Config::default() });
        assert_eq!(s.on_input(&frame(kind::HEADERS, 0, 1, &[0x88; 5])).1, Event::Fatal(H2Error::HeaderBlockTooLarge));
    }

    #[test]
    fn frame_and_stream_rules() {
        let big = FrameHeader { length: 16385, kind: kind::DATA, flags: 0, stream: 1 }.encode();
        assert_eq!(Session::new(Config::default()).on_input(&big).1, Event::Fatal(H2Error::FrameTooLarge));
        let ok = FrameHeader { length: 16384, kind: kind::DATA, flags: 0, stream: 1 }.encode();
        assert_eq!(Session::new(Config::default()).on_input(&ok).1, Event::Idle);
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::DATA, 0, 0, b"x")).1, Event::Fatal(H2Error::WrongStream));
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::SETTINGS, 0, 1, &[])).1, Event::Fatal(H2Error::WrongStream));
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::SETTINGS, 0, 0, &[0; 5])).1, Event::Fatal(H2Error::FrameSize));
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::SETTINGS, flag::ACK, 0, &[0; 6])).1, Event::Fatal(H2Error::FrameSize));
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::PUSH_PROMISE, flag::END_HEADERS, 1, &[0; 4])).1, Event::Fatal(H2Error::PushPromise));
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::SETTINGS, 0, 0, &[0, 4, 0x80, 0, 0, 0])).1, Event::Fatal(H2Error::FlowControl));
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::SETTINGS, 0, 0, &[0, 5, 0, 0, 0, 1])).1, Event::Fatal(H2Error::BadSettings));
        assert_eq!(Session::new(Config::default()).on_input(&frame(kind::SETTINGS, 0, 0, &[0, 2, 0, 0, 0, 2])).1, Event::Fatal(H2Error::BadSettings));
        // Unknown types and PRIORITY are skipped and counted; GOAWAY codes map as RFC 9113 says.
        let mut s = Session::new(Config::default());
        let mut i = frame(0xfa, 0, 0, &[1, 2, 3]);
        i.extend(frame(kind::PRIORITY, 0, 3, &[0, 0, 0, 0, 9]));
        i.extend(frame(kind::PING, flag::ACK, 0, &[0; 8]));
        assert!(matches!(s.on_input(&i).1, Event::Ping { ack: true, .. }));
        assert_eq!(s.counters.ignored_frames.get(), 2);
        assert_eq!(H2Error::FrameTooLarge.code(), 6);
        assert_eq!(H2Error::FlowControl.code(), 3);
        assert_eq!(H2Error::Compression(HpackError::TooLong).code(), 9);
        assert_eq!(H2Error::DuplicateSettingsAck.code(), 1);
    }

    #[test]
    fn sustained_download_keeps_the_receive_window_whole() {
        // 8 full frames (128 KiB, twice the 64 KiB window): credit returned at each frame end means the connection window is never exhausted.
        let mut s = Session::new(Config::default());
        drain(&mut s);
        let f = frame(kind::DATA, 0, 1, &[0u8; 16384]);
        let mut total = 0;
        let mut credit = 0u64;
        for _ in 0..8 {
            let mut rest = &f[..];
            loop {
                let (n, ev) = s.on_input(rest);
                rest = &rest[n..];
                total += n;
                let out = drain(&mut s);
                for w in out.chunks(13) {
                    credit += u32::from_be_bytes([w[9], w[10], w[11], w[12]]) as u64;
                }
                if matches!(ev, Event::Idle) {
                    break;
                }
            }
        }
        assert_eq!(total, 8 * f.len());
        assert!(!s.is_dead());
        assert_eq!(credit, 8 * 2 * 16384);
    }

    #[test]
    fn write_request_checks_windows_and_stream_ids() {
        let mut s = Session::new(Config::default());
        let mut out = [0u8; 512];
        let n = s.write_request(&mut out, 1, "POST", "/machine/register", "localhost", "application/json", b"{}").unwrap();
        let hl = ((out[0] as usize) << 16 | (out[1] as usize) << 8 | out[2] as usize) + 9;
        assert_eq!(&out[hl..n], &[0, 0, 2, 0, 1, 0, 0, 0, 1, b'{', b'}']);
        assert_eq!(s.write_request(&mut out, 1, "POST", "/p", "h", "t", b"x"), Err(SendError::BadStream));
        assert_eq!(s.write_request(&mut out, 2, "POST", "/p", "h", "t", b"x"), Err(SendError::BadStream));
        assert_eq!(s.write_request(&mut out, 3, "POST", "/p", "h", "t", &[0; 40]).map(|_| ()), Ok(()));
        assert_eq!(s.write_request(&mut out[..10], 5, "POST", "/p", "h", "t", b"x"), Err(SendError::TooSmall));
        assert_eq!(s.send_window(), 65535 - 2 - 40);
        // Larger than the connection window: refused, nothing consumed.
        let mut big = [0u8; 70000];
        assert_eq!(s.write_request(&mut big, 5, "POST", "/p", "h", "t", &[0; 65535]), Err(SendError::FlowControl));
        // The peer's WINDOW_UPDATE and SETTINGS change what is allowed.
        let mut i = frame(kind::WINDOW_UPDATE, 0, 0, &[0, 0, 0x10, 0]);
        i.extend(frame(kind::SETTINGS, 0, 0, &[0, 5, 0, 0, 0x80, 0]));
        let mut rest = &i[..];
        while !rest.is_empty() {
            let (n, _) = s.on_input(rest);
            rest = &rest[n..];
        }
        assert_eq!(s.send_window(), 65535 - 42 + 4096);
        let body = vec![7u8; 40000];
        let mut big = vec![0u8; 40100];
        let n = s.write_request(&mut big, 5, "POST", "/p", "h", "t", &body).unwrap();
        // 32768-byte frames: the body is split across two DATA frames, END_STREAM on the last.
        let hl = ((big[0] as usize) << 16 | (big[1] as usize) << 8 | big[2] as usize) + 9;
        assert_eq!(big[hl + 3], kind::DATA);
        assert_eq!(big[hl + 4], 0);
        let first = (big[hl] as usize) << 16 | (big[hl + 1] as usize) << 8 | big[hl + 2] as usize;
        assert_eq!(first, 32768);
        assert_eq!(big[hl + 9 + first + 4], flag::END_STREAM);
        assert_eq!(n, hl + 9 + 32768 + 9 + 7232);
        // Zero-length body: END_STREAM on the HEADERS frame.
        let mut s = Session::new(Config::default());
        let n = s.write_request(&mut out, 1, "GET", "/", "h", "t", b"").unwrap();
        assert_eq!(out[4], flag::END_HEADERS | flag::END_STREAM);
        assert_eq!(n, 9 + ((out[0] as usize) << 16 | (out[1] as usize) << 8 | out[2] as usize));
        // Zero WINDOW_UPDATE on the connection is an error; stream ones are ignored.
        assert_eq!(s.on_input(&frame(kind::WINDOW_UPDATE, 0, 0, &[0, 0, 0, 0])).1, Event::Fatal(H2Error::ZeroWindowIncrement));
        let mut s = Session::new(Config::default());
        assert_eq!(s.on_input(&frame(kind::WINDOW_UPDATE, 0, 0, &[0x7f, 0xff, 0xff, 0xff])).1, Event::Fatal(H2Error::FlowControl));
        let mut s = Session::new(Config::default());
        assert!(matches!(s.on_input(&frame(kind::WINDOW_UPDATE, 0, 5, &[0, 0, 0, 0])).1, Event::WindowUpdate { stream: 5, .. }));
    }

    #[test]
    fn outbox_never_overflows_and_blocked_resumes() {
        let mut s = Session::new(Config::default());
        // 40 pings, never draining: the session stops consuming rather than dropping replies.
        let mut input = vec![];
        for i in 0..40u8 {
            input.extend(frame(kind::PING, 0, 0, &[i; 8]));
        }
        let mut rest = &input[..];
        let mut blocked = 0;
        let mut acks = vec![];
        let mut guard = 0;
        while !rest.is_empty() || s.pending_output() > 0 {
            guard += 1;
            assert!(guard < 1000);
            let (n, ev) = s.on_input(rest);
            rest = &rest[n..];
            assert!(s.pending_output() <= OUT_CAP);
            if ev == Event::Blocked {
                blocked += 1;
                acks.extend(drain(&mut s));
            }
            if ev == Event::Idle {
                acks.extend(drain(&mut s));
            }
        }
        assert!(blocked > 0);
        assert_eq!(s.counters.outbox_overflow.get(), 0);
        // preface (52 bytes) + 40 ACKs of 17 bytes
        assert_eq!(acks.len(), 52 + 40 * 17);
    }

    #[test]
    fn every_split_gives_the_same_trace() {
        let mut stream = vec![];
        stream.extend(frame(kind::SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100, 0, 4, 0, 1, 0, 0]));
        stream.extend(frame(kind::SETTINGS, flag::ACK, 0, &[]));
        stream.extend(frame(kind::WINDOW_UPDATE, 0, 0, &[0, 0, 0, 5]));
        stream.extend(frame(kind::HEADERS, flag::END_HEADERS | flag::PADDED, 1, &[2, 0x88, 0, 0]));
        stream.extend(frame(kind::DATA, flag::PADDED, 1, &[1, 1, 2, 3, 0]));
        stream.extend(frame(kind::PING, 0, 0, &[9; 8]));
        stream.extend(frame(kind::DATA, flag::END_STREAM, 1, &[4, 5]));
        stream.extend(frame(kind::RST_STREAM, 0, 3, &[0, 0, 0, 8]));
        let whole = trace(&stream, stream.len());
        assert!(whole.0.len() >= 8, "{:?}", whole.0);
        for piece in 1..stream.len() {
            assert_eq!(trace(&stream, piece), whole, "piece {piece}");
        }
    }

    #[test]
    fn state_sizes() {
        std::println!("size_of Session={} FrameReader={} HpackDecoder={}", SESSION_BYTES, FRAME_READER_BYTES, core::mem::size_of::<HpackDecoder>());
        const { assert!(SESSION_BYTES <= 512) };
    }
}
