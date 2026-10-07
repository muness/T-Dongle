//! The tailnet control client between the Noise record layer and the map JSON.
//!
//! Everything the C firmware says and hears on the control connection once bytes are plaintext, rebuilt sans-IO and allocation free:
//!
//! | Module | What | C source |
//! |---|---|---|
//! | [`http`] | `GET /key`, the ts2021 upgrade request and the bounded `101` reader, login-server URL parsing, the key cache and its rotation policy | `ml_coord.c` key fetch, `gateway_handshake.inc` |
//! | [`early`] | the `\xff\xff\xffTS` early payload and the node-key challenge | `gateway_read_early` |
//! | [`h2`], [`hpack`] | frame reader, HTTP/2 session (SETTINGS, PING, GOAWAY, flow control), HPACK | `ml_h2.c`, `gateway_stream.inc`, `gateway_h2_close.inc` |
//! | [`requests`] | `RegisterRequest`, `MapRequest` writers, `RegisterResponse` reader | `ml_coord.c` `do_register_locked`, `do_start_long_poll` |
//! | [`map`] | the 4-byte little-endian length framing of map messages and the stream-level decisions | `gateway_stream.inc` |
//! | [`json`], [`base64`] | the bounded JSON writer/scanner and base64 they need | cJSON use |
//!
//! No clock, socket or entropy source is touched here (Millis arguments, byte slices), every buffer is a compile-time bound or the caller's slice, and every
//! refusal is an enum variant or a [`tdongle_tailnet_types::Counter`].

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod base64;
pub mod early;
pub mod h2;
pub mod hpack;
pub mod http;
pub mod json;
pub mod map;
pub mod requests;

pub use h2::{Config as H2Config, Event as H2Event, Session as H2Session};

/// Bytes of the main state structs on this target (the ADR needs bytes per membership).
pub mod sizes {
    use crate::{early, h2, hpack, http, map};
    use core::mem::size_of;
    /// `h2::Session`.
    pub const H2_SESSION: usize = size_of::<h2::Session>();
    /// `h2::FrameReader`.
    pub const FRAME_READER: usize = size_of::<h2::FrameReader>();
    /// `hpack::HpackDecoder`.
    pub const HPACK_DECODER: usize = size_of::<hpack::HpackDecoder>();
    /// `map::MapStream` (framer inside).
    pub const MAP_STREAM: usize = size_of::<map::MapStream>();
    /// `http::UpgradeReader`.
    pub const UPGRADE_READER: usize = size_of::<http::UpgradeReader>();
    /// `http::KeyCache`.
    pub const KEY_CACHE: usize = size_of::<http::KeyCache>();
    /// `early::EarlyReader` (excluding the caller's JSON buffer).
    pub const EARLY_READER: usize = size_of::<early::EarlyReader<'static>>();
}

#[cfg(test)]
extern crate std;
