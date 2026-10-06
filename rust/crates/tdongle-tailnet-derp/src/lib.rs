//! DERP relay client, sans-IO.
//!
//! The Tailscale DERP protocol (`derp/derp.go`, `derp/derp_client.go`, `derp/derphttp`) as the C firmware speaks it (`ml_derp.c`, `ml_derp_link.c`),
//! restructured so that nothing here owns a socket, a clock or a random source:
//!
//! * [`frame`]: the 5-byte frame header, a bounded encoder and a streaming [`FrameReader`] that accepts any chunking of the byte stream and holds one
//!   frame in a fixed buffer sized to the largest relayed WireGuard/DISCO packet ([`MAX_RECV_BODY`]).
//! * [`message`]: typed views of a frame body (RecvPacket, Ping, PeerGone, PeerPresent, Health, Restarting, ...), tolerant of older and newer servers
//!   exactly as Go's `Client.Recv` is.
//! * [`handshake`]: the HTTP upgrade request and 101 scanner, the ClientInfo box (NaCl, via `tdongle-tailnet-crypto`) and the ServerInfo box.
//! * [`link`]: [`Link`], one membership's relay connection as a state machine fed [`Event`]s and emitting [`Action`]s: idle, waiting (retry ladder and
//!   the wall clock), token, DNS, TCP, TLS, upgrade, ServerKey, ClientInfo, ServerInfo, ready. Every wait has a deadline kept in the link, so one dead
//!   server costs its own membership a reconnect and nobody else anything (ADR 0013).
//! * [`txq`]: the bounded relay transmit queue (byte ring of finished frames) with a soft byte budget, a small-datagram exemption and counted drops.
//! * [`pace`]: when the next connect attempt may start (`ml_derp_pace.h`).
//! * [`mux`]: the fixed-size set of links one shared task services round-robin (`ml_mux.c`).
//!
//! The idle teardown of `docs/research/derp-idle-teardown.md` is **not** implemented: that study rejects closing the home DERP connection for any
//! membership that accepts inbound traffic, and the C does not apply it.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod frame;
pub mod handshake;
pub mod link;
pub mod message;
pub mod mux;
pub mod pace;
pub mod txq;

pub use frame::{FrameInfo, FrameReader, FrameType, Poll, ReadError};
pub use link::{Action, Event, Link, LinkEvent, Sink, State, Stats, Target, Timing};
pub use message::Message;
pub use txq::{TxDrop, TxPolicy, TxQueue};

/// Bytes of a frame header: one type byte and a big-endian `u32` length (`derp.FrameHeaderLen`).
pub const FRAME_HEADER_LEN: usize = 5;
/// Length of a public key.
pub const KEY_LEN: usize = 32;
/// Length of a NaCl box nonce.
pub const NONCE_LEN: usize = 24;
/// The largest tunnel packet the gateway relays (`ML_MAX_PACKET_SIZE`).
pub const MAX_PACKET: usize = 1500;
/// Largest payload accepted in one frame after the 32-byte source key of a RecvPacket, and the cap for every other post-handshake frame
/// (`ML_DERP_MAX_FRAME`): a maximum WireGuard data message (1,500 padded to 16, plus 16 of header and 16 of tag = 1,536) fits with room to spare.
pub const MAX_FRAME: usize = MAX_PACKET + 64;
/// Largest RecvPacket body: the source key then the packet.
pub const MAX_RECV_BODY: usize = KEY_LEN + MAX_FRAME;
/// Largest SendPacket body we build: the destination key then the packet (the C's `body <= ML_DERP_MAX_FRAME + 32`).
pub const MAX_SEND_BODY: usize = KEY_LEN + MAX_FRAME;
/// Largest complete outgoing frame, header included.
pub const MAX_SEND_FRAME: usize = FRAME_HEADER_LEN + MAX_SEND_BODY;
/// Go's limit for a packet (`derp.MaxPacketSize`, 64 KiB). Reference only: this client is deliberately far stricter.
pub const GO_MAX_PACKET_SIZE: usize = 64 << 10;
/// Go's `derp.MaxInfoLen`, reference only.
pub const GO_MAX_INFO_LEN: usize = 1 << 20;
/// The DERP greeting magic, `"DERP"` and U+1F511 (`derp.Magic`).
pub const MAGIC: [u8; 8] = [0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91];
/// Server pings we echo (the protocol uses 8; `ML_DERP_PONG_MAX`).
pub const PONG_MAX: usize = 64;
/// Upgrade response header bytes accepted before the link gives up (`ML_DERP_HTTP_MAX`).
pub const HTTP_MAX: usize = 512;
/// The protocol version we announce in ClientInfo (`derp.ProtocolVersion`).
pub const PROTOCOL_VERSION: u32 = 2;

const _: () = assert!(MAX_FRAME >= MAX_PACKET.div_ceil(16) * 16 + 32, "a maximum-size WireGuard data message must fit one DERP frame");

#[cfg(test)]
extern crate std;
