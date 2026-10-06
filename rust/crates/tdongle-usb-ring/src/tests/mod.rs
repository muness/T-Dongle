//! Host tests: the C cases and threads test ported to Rust over a strict mock environment, plus a model-based test.

use std::prelude::v1::*;

mod bridge;
mod cases_a;
mod cases_b;
mod cases_c;
mod check;
mod model;
mod rng;
mod soak;
mod threads;
mod world;

use crate::consts::*;

/// The slab arithmetic the rest of the crate relies on, as run-time tests besides the `const` assertions in `consts`.
#[test]
fn slab_arithmetic() {
    assert_eq!(REC_HDR + align4(FRAME_MAX), SLAB_BYTES);
    assert_eq!(REC_MAX, SLAB_BYTES);
    assert_eq!(CHUNK_BYTES, 3048);
    assert_eq!(MAX_SLABS, 32);
    assert_eq!(align4(14), 16);
    assert_eq!(align4(1518), 1520);
    assert_eq!(align4(1520), 1520);
    // One maximum frame fills a slab exactly, and 64-byte frames pack 22 to a slab (68-byte records).
    assert_eq!(SLAB_BYTES / (REC_HDR + align4(64)), 22);
    // 1004 + 520 fills a slab to the last byte (the C packing case).
    assert_eq!((REC_HDR + align4(1000)) + (REC_HDR + align4(516)), SLAB_BYTES);
    assert_eq!(BRIDGE_MAX_SLABS, 28);
}
