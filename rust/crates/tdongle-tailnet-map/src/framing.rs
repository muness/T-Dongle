//! The map stream's message framing: a 4-byte little-endian length, then that many bytes of one MapResponse JSON document, repeated for as long as the
//! long-poll stays open (the C's prefix handling in `gateway_read_map`, `gateway_stream.inc`; the HTTP/2 and Noise layers below it are not this crate's).

use crate::project::{MapConfig, MapError, MapProjector, MapSink};

/// The largest map the C accepts (`length > 1024 * 1024` is "Invalid map length or raw map exceeds 1 MiB limit").
pub const MAX_MAP_BYTES: u32 = 1024 * 1024;

/// Why the stream failed. After any of these the framer returns the same error until [`MapFramer::reset`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The declared length is 0 or above [`MAX_MAP_BYTES`] (the C's map error 7).
    BadLength(u32),
    /// A message failed to project (the sink has had its `Abort`).
    Map(MapError),
    /// The stream ended inside a message (the C's map error 12, "Map stream ended during a message").
    EndedMidMessage,
}

impl FrameError {
    /// The C's `ml->map_error` code.
    pub fn code(&self) -> u32 {
        match self {
            FrameError::BadLength(_) => 7,
            FrameError::Map(e) => e.code(),
            FrameError::EndedMidMessage => 12,
        }
    }
}

/// Reads length-prefixed maps from a byte stream of any chunking and projects each into a [`MapSink`].
#[derive(Clone, Debug)]
pub struct MapFramer {
    projector: MapProjector,
    cfg: MapConfig,
    prefix: [u8; 4],
    prefix_len: u8,
    remaining: u32,
    declared: u32,
    maps: u32,
    failed: Option<FrameError>,
}

impl MapFramer {
    /// `size_of::<MapFramer>()` on the compiling target.
    pub const STATE_BYTES: usize = core::mem::size_of::<MapFramer>();

    /// A framer at a message boundary; every map is projected with `cfg`.
    pub fn new(cfg: MapConfig) -> Self {
        Self { projector: MapProjector::new(cfg), cfg, prefix: [0; 4], prefix_len: 0, remaining: 0, declared: 0, maps: 0, failed: None }
    }

    /// Forget any partial message and the failure (a new connection).
    pub fn reset(&mut self) {
        self.projector.reset(self.cfg);
        self.prefix_len = 0;
        self.remaining = 0;
        self.declared = 0;
        self.failed = None;
    }

    /// The configuration used for the next maps (the preferred DERP region can change between maps).
    pub fn config_mut(&mut self) -> &mut MapConfig {
        &mut self.cfg
    }

    /// The declared length of the message in progress or last seen (`ml->map_declared_bytes`).
    pub fn declared_bytes(&self) -> u32 {
        self.declared
    }

    /// Bytes of the current message not yet received.
    pub fn remaining_bytes(&self) -> u32 {
        self.remaining
    }

    /// True between messages (no byte of a prefix or body pending).
    pub fn at_boundary(&self) -> bool {
        self.remaining == 0 && self.prefix_len == 0
    }

    /// Maps completed so far (since [`MapFramer::new`], across [`MapFramer::reset`]).
    pub fn maps_completed(&self) -> u32 {
        self.maps
    }

    /// The statistics of the message in progress or last completed.
    pub fn stats(&self) -> &crate::project::MapStats {
        self.projector.stats()
    }

    /// Consume stream bytes; returns how many maps completed (each already delivered to `sink` ending in its `Commit`).
    pub fn feed<S: MapSink>(&mut self, mut bytes: &[u8], sink: &mut S) -> Result<u32, FrameError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let mut completed = 0;
        while !bytes.is_empty() {
            if self.remaining == 0 {
                let take = (4 - self.prefix_len as usize).min(bytes.len());
                self.prefix[self.prefix_len as usize..self.prefix_len as usize + take].copy_from_slice(&bytes[..take]);
                self.prefix_len += take as u8;
                bytes = &bytes[take..];
                if self.prefix_len < 4 {
                    break;
                }
                self.prefix_len = 0;
                let len = u32::from_le_bytes(self.prefix);
                self.declared = len;
                if len == 0 || len > MAX_MAP_BYTES {
                    return Err(self.fail(FrameError::BadLength(len)));
                }
                self.remaining = len;
                self.projector.reset(self.cfg);
            } else {
                let n = (self.remaining as usize).min(bytes.len());
                if let Err(e) = self.projector.feed(&bytes[..n], sink) {
                    return Err(self.fail(FrameError::Map(e)));
                }
                bytes = &bytes[n..];
                self.remaining -= n as u32;
                if self.remaining == 0 {
                    if let Err(e) = self.projector.finish(sink) {
                        return Err(self.fail(FrameError::Map(e)));
                    }
                    self.maps += 1;
                    completed += 1;
                }
            }
        }
        Ok(completed)
    }

    /// The transport reached end of stream: an error when it is inside a message.
    pub fn end_of_stream(&mut self) -> Result<(), FrameError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.at_boundary() { Ok(()) } else { Err(self.fail(FrameError::EndedMidMessage)) }
    }

    fn fail(&mut self, e: FrameError) -> FrameError {
        self.failed = Some(e);
        e
    }
}
