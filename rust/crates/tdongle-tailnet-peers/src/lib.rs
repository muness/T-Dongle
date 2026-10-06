//! The peer table, the global WireGuard peer-slot pool policy and the flash directory of the tailnet gateway.
//!
//! No cryptography, no clocks, no allocator: time is a [`Millis`] argument, randomness an [`Entropy`] argument, flash a trait.
//!
//! * [`record`]: [`record::DirRecord`] (the C's `ml_peer_update_t`) and its parts;
//! * [`table`]: [`table::PeerTable`], one membership's eight-peer working set (`ml_peer_t[ML_MAX_PEERS]`), looked up by node key, tailnet IP,
//!   disco key, node id and WireGuard slot, each in at most eight comparisons;
//! * [`policy`]: which resident peer gives up its WireGuard slot (`ml_peer_policy.h`);
//! * [`pool`]: the global slot pool, `Pool<S, K>`, static, generic over the slot payload through [`pool::SlotMeta`]
//!   (`wireguard_pool.c` plus the pool-wide receiver-index rules and commit guards of `wireguard.c`);
//! * [`arbiter`]: eviction across memberships when the pool is full (`peer_pool_reserve`), with the `/status` counters;
//! * [`trial`], [`membership`]: activation on demand, including the unauthenticated-claim trial of ADR 0012's amendment;
//! * [`directory`]: the flash directory's two-bank image codec, delta application and alias log (`ml_directory.c`);
//! * [`nvs_cache`]: the NVS peer cache blob (`ml_peer_nvs.c`), byte-compatible;
//! * [`status`]: the `"wg_pool"` fragment of `/status`.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod arbiter;
pub mod directory;
pub mod membership;
pub mod nvs_cache;
pub mod policy;
pub mod pool;
pub mod record;
pub mod status;
pub mod table;
pub mod trial;

pub use record::PubKey;
pub use tdongle_tailnet_types::{Entropy, Millis};

#[cfg(target_arch = "xtensa")]
const _: () = {
    assert!(core::mem::size_of::<table::Peer>() == 456);
    assert!(core::mem::size_of::<table::PeerTable<8>>() == 3648);
    assert!(core::mem::size_of::<membership::Membership<8>>() == 3720);
    assert!(core::mem::size_of::<record::DirRecord>() == 288);
    assert!(core::mem::size_of::<nvs_cache::PeerCache<64>>() == 7940);
};
