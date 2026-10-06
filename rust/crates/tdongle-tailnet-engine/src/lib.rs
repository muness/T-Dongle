//! The sans-IO gateway engine of the T-Dongle tailnet gateway.
//!
//! One value, [`Engine`], composes the finished protocol crates into the behaviour of the C runtime (`microlink.c`, `ml_wg_mgr.c`, `ml_runtime.c`,
//! `ml_rt_core.c`, `ml_mux.c`, `ml_net_io.c`, `ml_zerocopy.c`, the member and netmap glue of `gateway_main.c`; ADRs 0013 to 0022) without owning a socket,
//! a clock or an entropy source:
//!
//! ```text
//! Engine::handle(now, Input, &mut dyn Entropy, &mut dyn Output) -> Handled
//! ```
//!
//! # Interface
//!
//! * [`Input`]: a host packet (IPv4 from USB, already de-framed), a datagram on a member's UDP socket (DISCO, WireGuard or STUN, told apart by the first
//!   bytes as `net_io` does), a packet from the member's DERP link, the link's state changes, netmap events ([`NetmapEvent`], produced by [`NetmapSink`]
//!   from the control task's map projector), DNS queries and upstream replies, membership add/enable/disable/remove, the member's local endpoints, the
//!   clock-valid flag, USB detach and `Tick`.
//! * [`Output`] receives [`Out`]: UDP and STUN datagrams, DERP packets, packets for the host, DNS answers and forwards, DERP connect/close requests,
//!   the home-region announcement, STUN-learned endpoints, membership readiness, and, last in every call, [`Out::Wake`]: **the one time** the runtime
//!   must call `handle(.., Input::Tick, ..)` next. [`Engine::next_deadline`] computes the same value.
//! * `Output::emit` may refuse (a full queue): the packet then ends as a counted `TxRefused` / `HostTxRefused`.
//!
//! **The DERP links are not owned by the engine.** The runtime (or the [`derp_glue::DerpLinks`] helper in this crate) owns one
//! `tdongle_tailnet_derp::Link` per membership, because a link's actions borrow the link and a delivered packet must come back into the engine: owning
//! the links inside would make `handle` re-entrant. The engine says *what* the links should do (`DerpConnect`, `DerpClose`, `DerpSend`) and is told what
//! they report (`DerpLinkEvent`, `DerpPacket`). The negotiation-token hooks (`WantToken`, `ReleaseToken`) are surfaced through the glue as the same [`Out`]
//! variants, for the runtime to bridge to `tdongle_tailnet_admission::negotiation`.
//!
//! # What it does
//!
//! * **Packet path** (`ml_wg_mgr.c`): host -> `Router::host_packet` -> `Forwarded{member, peer}` -> activate the peer from the directory if it is not
//!   resident (the activation rules of `tdongle_tailnet_peers::membership`: own table, the shared pool and its arbiter) -> WireGuard seal -> a trusted
//!   direct UDP path or DERP. No session: the packet is parked in a bounded queue ([`jit`]: 8 per membership, 5 s, in order, heap-gated) and the handshake
//!   starts. Inbound: UDP/DERP -> demux -> WireGuard decrypt -> AllowedIPs check -> `Router::tunnel_packet` -> `Out::HostPacket`.
//! * **Handshakes**: initiator driven by `PeerHot::poll`; responder with cookie screening ([`UNDER_LOAD_INITIATIONS`] per second or a heap below the
//!   floor puts it "under load": valid initiations get a cookie reply), the trial activation of unauthenticated claims (ADR 0012), receiver indices
//!   unique pool-wide, TAI64N from the control plane's clock.
//! * **DISCO**: per-peer `PathState`, outstanding probes, CallMeMaybe over DERP, one-second tick, STUN schedule and netcheck (DERP home region).
//! * **Netmap** ([`dir`]): staged peer updates go to a [`PeerDirectory`] (the flash directory in the firmware, [`RamDirectory`] in tests) and are applied
//!   at commit; resident peers follow.
//! * **DNS** (`tdongle_tailnet_dns`): MagicDNS names answer with aliases from the [`alias::AliasBook`]; the router's alias cache is filled from it.
//! * **Memory** (ADR 0022): one floor, `ML_HB_FLOOR`; the elastic sites (parked packets, DERP transmit, receive) refuse below it and count per site; the
//!   parked packets live in a static arena, so exhausting it is the same counted refusal as an empty heap.
//! * **Life cycle**: add, enable, disable, remove in the order ADR 0013 fixes (suspend the router, stop what feeds it, destroy); later packets for a
//!   removed membership are counted `NoMember`.
//!
//! Every packet ends in exactly one counted outcome ([`stats`]); [`Engine::check_identities`] proves it, plus the pool and receiver-index invariants.
//!
//! # Configuration (const generics)
//!
//! `Engine<D, M, P, K, A, F, JB>`: `M` memberships (3), `P` resident peers per membership (8), `K` pool slots shared by all (12), `A` router alias-cache
//! entries (64), `F` router flow slots (64), `JB` 256-byte blocks of the parked-packet arena (24). [`GatewayEngine`] is that configuration. Sizes:
//! [`Engine::per_member_bytes`], `tests/sizes.rs`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod alias;
pub mod derp_glue;
pub mod dir;
pub mod engine;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz;
pub mod io;
pub mod jit;
pub mod member;
pub mod netmap;
mod rx;
pub mod shared;
pub mod slot;
pub mod stats;
pub mod status;
#[cfg(feature = "status")]
pub mod status_map;
mod tx;

pub use alias::AliasBook;
pub use dir::{DirError, PeerDirectory, RamDirectory};
pub use engine::{ActFail, Engine, GatewayEngine, Handled};
pub use io::{DerpNote, Input, MemberConfig, MemberId, NetmapEvent, NullOutput, Out, Output, TokenPhase};
pub use netmap::{EngineNetmap, NetmapSink, NetmapTarget};
pub use rx::From;
pub use shared::UNDER_LOAD_INITIATIONS;
pub use stats::{HostFate, IdentityError, ParkEnd, RxFate, Stats, TxFate};
pub use status::{MemberBytes, MemberStatus, PoolStatus, StatusSnapshot};

// Layout guard, checked by `cargo +esp check --target xtensa-esp32s3-none-elf`: the 32-bit sizes of the state types (host sizes in `tests/sizes.rs`).
// A growth past these fails the build of the firmware, so the memory ledger and this crate cannot drift apart unnoticed.
#[cfg(target_arch = "xtensa")]
const _: () = {
    assert!(core::mem::size_of::<member::Member<8>>() == 9560);
    assert!(core::mem::size_of::<slot::WgSlot>() == 944);
    assert!(core::mem::size_of::<jit::ParkQueue>() == 328);
    assert!(core::mem::size_of::<jit::JitStore<24>>() == 6176);
    assert!(core::mem::size_of::<alias::AliasBook>() == 1544);
    assert!(core::mem::size_of::<tdongle_tailnet_peers::pool::Pool<slot::WgSlot, 12>>() == 11472);
    assert!(core::mem::size_of::<Engine<RamDirectory<1, 1, 1>, 3, 8, 12, 64, 64, 24>>() - core::mem::size_of::<RamDirectory<1, 1, 1>>() == 58960);
};
