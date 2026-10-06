//! The tailnet gateway's memberships: the registry, the stored `members` JSON and the setup page's member API, byte-compatible with the C firmware
//! (`alternative/tailnet/main/gateway_main.c`: `save_members`, `load_members`, `identify`, `command`).
//!
//! * [`registry`]: [`Registry`] (bounded, static storage, newest first like the C list), `encode`/`load` of the NVS string;
//! * [`json_in`]: the cJSON-compatible reader it loads with (and `/command` bodies are read with);
//! * [`command`]: [`MemberAction`] -> [`Reply`] with the C's HTTP statuses and error texts; the firmware implements [`MemberIo`] and does the I/O.
//!
//! Auth keys are secrets: they live in zeroize-on-drop storage, never print in `Debug`, and the encode scratch buffer is zeroed after each save.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod command;
pub mod json_in;
pub mod json_out;
pub mod registry;
pub mod text;

pub use command::{ActionKind, MAX_BODY, MemberAction, MemberIo, Origin, Parsed, Reply, Status, apply, parse_request};
pub use registry::{AddError, ENCODE_BUFFER, EncodeError, KEY_MAX, LABEL_MAX, LoadError, MAX_JSON_BYTES, MAX_MEMBERS, Member, MemberRegistry, Registry};
pub use text::CText;
