//! The tailnet gateway's `/status` JSON, byte-compatible with the C firmware (`status()` in `alternative/tailnet/main/gateway_main.c`,
//! `runtime_status.inc`, `json_writer.inc`).
//!
//! * [`jw`]: the bounded serializer (`jw_*`) with its 256-byte staging buffer and a chunk sink (`status_chunk`);
//! * [`input`]: the data `/status` reports, typed, with the C's field names (the integration glue maps the other crates onto them);
//! * [`status`]: [`write_status`], the same keys in the same order as the C.
//!
//! The Android app and `setup.html` parse this output: key names, key order, number formatting and the chunking are checked against the real C
//! (`tools/gen_golden.py` compiles the C writer; `tools/key_order.py` extracts the key sequence from the C source).

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod diag;
pub mod glue;
pub mod input;
pub mod jw;
pub mod status;

pub use input::*;
pub use jw::{ChunkSink, JsonWriter};
pub use status::{status_into, write_status};
