//! Bounded streaming JSON tokenizer and Tailscale MapResponse projector.
//!
//! The control plane answers a long-poll `MapRequest` with a stream of length-prefixed JSON documents (`tailcfg.MapResponse`) that can be hundreds of
//! kilobytes, while the device has a few kilobytes to spend. The C firmware solves that with a hand-written validating projector and a 4 KiB record
//! view (`gateway_project*.inc`, `gateway_stage.inc`); this crate is the same behaviour as two layers with no allocation and a fixed-size state:
//!
//! * [`json`]: [`json::Tokenizer`], a push tokenizer for arbitrary-sized chunks. Depth, key, number and string lengths are bounded; invalid JSON is an
//!   error; the result never depends on where the input is split.
//! * [`project`]: [`project::MapProjector`], which reads the token stream as a MapResponse and emits typed [`project::MapEvent`]s
//!   ([`PeerRecord`], [`SelfNode`], [`DerpMap`], [`DnsConfig`], ...) to a [`project::MapSink`], counting every drop in [`project::MapStats`].
//!
//! [`framing`] adds the 4-byte length prefix the map stream uses, so a transport can hand over whatever bytes it has.
//!
//! Supporting modules: [`types`] (the records and their bounds), [`derp_cert`] (`CertName` handling), [`directory`] (the pure merge rules of a peer
//! directory), [`name`] (the published self name), [`util`] (strict `sscanf` replacements, RFC 3339).
//!
//! Sans-IO like every tailnet crate: bytes in, events out; no clock, socket, entropy or allocation.
//!
//! # Deliberate differences from the C
//!
//! The C is the specification; where the port is stricter or exact where the C was accidental, it is listed here and counted in [`MapStats`]:
//!
//! * `Addresses[0]`, endpoints and `AllowedIPs` are parsed strictly (octets <= 255, ports <= 65535, prefix <= 32); the C's `sscanf` accepted out-of-range
//!   octets and trailing junk. Rejected entries are counted (`addresses_bad`, `endpoints_bad`, `routes_bad`).
//! * A key must be exactly 64 hex digits (optional `nodekey:` / `discokey:` / `mkey:` prefix); the C also accepted a shorter even-length string and
//!   left the rest zero. Either way the field stays zero and the record is still delivered ([`MapStats::keys_bad`]).
//! * A `Peers` / `PeersChanged` element that is not an object is dropped and counted; the C staged an all-zero record for it.
//! * `ID`, `NodeID` and removals are exact `i64`s when written as integers; the C went through a `double` (identical below 2^53).
//! * Retained text must be valid UTF-8 as well as free of NUL and lone surrogates; the C passed raw bytes through.
//! * DERP `IPv4`/`IPv6` are parsed to addresses (`None` when malformed) instead of being kept as strings, and a `Nodes` element that is not an object is
//!   ignored instead of becoming an unconnectable node.
//! * A DERP port outside 0..=65535 (Go sends `-1` for "disabled") is 0 and counted, not a C cast.
//! * Extra fields are read (`Machine`, `KeyExpiry`, `Tags`, `Cap`, `CanPort80`, `DNSConfig`, `Domain`, `ControlTime`, `KeepAlive`, `CollectServices`,
//!   `PeerSeenChange`, `OnlineChange`); they never count against the C's per-record bounds.
//!
//! ```
//! use tdongle_tailnet_map::project::{MapConfig, MapEvent, MapProjector, MapSink, SinkError};
//!
//! #[derive(Default)]
//! struct Count { peers: u32, committed: bool }
//! impl MapSink for Count {
//!     fn event(&mut self, e: MapEvent<'_>) -> Result<(), SinkError> {
//!         match e {
//!             MapEvent::Peer(_) => self.peers += 1,
//!             MapEvent::Commit(_) => self.committed = true,
//!             _ => {}
//!         }
//!         Ok(())
//!     }
//! }
//!
//! let mut sink = Count::default();
//! let mut p = MapProjector::new(MapConfig::new(1));
//! for chunk in br#"{"Peers":[{"ID":1,"Addresses":["100.64.0.2/32"]}],"Ignored":{"a":[1,2]}}"#.chunks(7) {
//!     p.feed(chunk, &mut sink).unwrap();
//! }
//! p.finish(&mut sink).unwrap();
//! assert!(sink.committed && sink.peers == 1);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod derp_cert;
pub mod directory;
pub mod framing;
pub mod json;
pub mod name;
pub mod project;
pub mod types;
pub mod util;

pub use derp_cert::DerpCert;
pub use framing::{FrameError, MAX_MAP_BYTES, MapFramer};
pub use name::PublishedName;
pub use project::{MapConfig, MapError, MapEvent, MapLimits, MapProjector, MapSink, MapStats, MapSummary, SinkError};
pub use types::{DerpMap, DerpNode, DerpRegion, DnsConfig, DnsResolver, DnsRoute, Endpoint, Group, ML_MAX_PEERS, PeerAction, PeerRecord, Route, SelfNode};

/// `size_of` of the records and the machines, on the compiling target (the ADR's "bytes per membership" figures: a map in flight costs
/// [`PROJECTOR_STATE_BYTES`], everything else is transient).
pub const PEER_RECORD_BYTES: usize = core::mem::size_of::<PeerRecord>();
/// `size_of::<SelfNode>()`.
pub const SELF_NODE_BYTES: usize = core::mem::size_of::<SelfNode>();
/// `size_of::<DerpRegion>()`.
pub const DERP_REGION_BYTES: usize = core::mem::size_of::<DerpRegion>();
/// `size_of::<DerpMap>()`.
pub const DERP_MAP_BYTES: usize = core::mem::size_of::<DerpMap>();
/// `size_of::<DnsConfig>()`.
pub const DNS_CONFIG_BYTES: usize = core::mem::size_of::<DnsConfig>();
/// `size_of::<MapEvent>()`: events carry references, so this is small.
pub const MAP_EVENT_BYTES: usize = core::mem::size_of::<MapEvent<'static>>();
/// `size_of::<json::Tokenizer>()`.
pub const TOKENIZER_STATE_BYTES: usize = core::mem::size_of::<json::Tokenizer>();
/// `size_of::<MapFramer>()`: projector plus the length-prefix state.
pub const FRAMER_STATE_BYTES: usize = core::mem::size_of::<MapFramer>();
/// `size_of::<MapProjector>()`: the whole state of one projection.
pub const PROJECTOR_STATE_BYTES: usize = core::mem::size_of::<MapProjector>();
