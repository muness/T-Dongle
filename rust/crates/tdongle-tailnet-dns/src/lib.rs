//! DNS for the USB host of the T-Dongle tailnet gateway.
//!
//! # What the C does (and therefore what this crate does)
//!
//! The dongle offers the USB host exactly one resolver: **192.168.77.1, UDP port 53** (DHCP option 6). There is no 100.100.100.100, no DNS
//! over TCP, no split-DNS routes and no answer cache for forwarded names. The responder:
//!
//! * answers `A` queries for **`<peer>.<label>.tailnet`** and for **MagicDNS names `<peer>.<tailnet-domain>`** (the domain of a membership is its
//!   own published DNS name minus the first label) with the peer's *alias* (198.18.x.y, TTL 30) from the USB router;
//! * answers any other type/class inside those names with NODATA (rcode 0, no answer), an unknown or ambiguous name with NXDOMAIN, and any name
//!   that cannot be resolved right now (member disconnected, directory read failed or changed, lock busy, alias store failure) with SERVFAIL, but
//!   never forwards a name that belongs to a tailnet domain;
//! * treats a MagicDNS domain claimed by two memberships, and a name matching two peers, as ambiguous (NXDOMAIN);
//! * forwards everything else, as is, to the **Wi-Fi-provided resolver** with a rewritten transaction ID (at most four in flight, 2 s timeout,
//!   replies matched by ID and by a hash of the question), and relays the reply to the asking host; when four are in flight it answers SERVFAIL.
//!
//! Queries are accepted only from 192.168.77.0/24, with exactly one question, not a response; anything else is dropped silently. Compression
//! pointers in a question are invalid (a legal query has none), names are limited to 255 text bytes and labels to 63.
//!
//! # Sans-IO
//!
//! [`Responder::handle_query`] takes the datagram, the sender, `now`, a [`Directory`] view and the upstream resolver address, and returns an
//! [`Action`]: `Answer` (reply to the sender with `out[..len]`), `Forward` (send `out[..len]` to the upstream resolver on the pinned upstream
//! socket) or `Drop(reason)`. [`Responder::handle_upstream`] maps an upstream reply back to the asking host and [`Responder::expire`] times out
//! pending forwards. No clock, socket or lock inside; all state is inline ([`Responder::STATE_BYTES`]).

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod directory;
pub mod responder;
pub mod wire;

pub use directory::{Directory, MemberView, NoDirectory, PeerView};
pub use responder::{Action, Client, DropReason, Reply, Responder, Stat, Stats};
pub use wire::{ParseError, Question};

/// The resolver address offered to the USB host (192.168.77.1).
pub const RESOLVER_ADDR: u32 = 0xc0a8_4d01;
/// The USB network (192.168.77.0/24); only hosts in it may ask.
pub const USB_NET: u32 = 0xc0a8_4d00;
/// TTL of an alias answer, seconds.
pub const ANSWER_TTL: u32 = 30;
/// Forwarded queries in flight (`pending[4]`).
pub const PENDING: usize = 4;
/// How long a forwarded query waits for its reply.
pub const UPSTREAM_TIMEOUT_MS: u64 = 2_000;
/// Lifetime of an entry of the four-entry local answer cache.
pub const CACHE_TTL_MS: u64 = 30_000;
/// Entries of the local answer cache.
pub const CACHE_ENTRIES: usize = 4;
/// Longest name the cache keeps (the C's `cache[].name[128]`).
pub const CACHE_NAME_MAX: usize = 127;
/// Replies accepted from the upstream socket per poll (bounded draining keeps the service fair).
pub const UPSTREAM_DRAIN: usize = 4;
