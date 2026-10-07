//! The serial console of the T-Dongle firmware: the pure parts of `console.c`, `control.c`, `serial_setup.inc`, `bridge_status.inc`,
//! `wifi_link.h`, `clock_sync.h` and the heap record ring of `tdongle_runtime`.
//!
//! **Byte compatibility with the C firmware is a hard requirement**: the Android app parses the serial `status` text. Every text this crate
//! produces is checked against golden files generated from the *real* C sources (`tools/gen_golden.py`, run through `tools/regen.sh`),
//! never against a transcription.
//!
//! * [`console`]: the line discipline (`LineReader`), `mgmt_write` chunking, the prompt/overflow replies and the greeting
//! * [`command`]: [`command::Command::parse`], the dispatch order of `command_task` with C `strcmp`/`strncmp`/`strtol` semantics
//! * [`reply`]: every fixed reply text, `help`, `capabilities`, `list`, `display`, `scan` lines
//! * [`status`]: the `status` report, [`bridge_report`]: the `bridge_*` lines, [`pm_report`]: the `pm` command
//! * [`wifi_link`], [`clock`], [`memory_log`]: the data the report reads, with their own logic
//!
//! All output goes to a `core::fmt::Write` sink (or a caller supplied fixed buffer): nothing allocates, and the line buffers have the sizes
//! the C code uses, so a truncated line is truncated at the same byte.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bridge_report;
pub mod clock;
pub mod command;
pub mod console;
pub mod memory_log;
pub mod out;
pub mod pm_report;
pub mod reply;
pub mod status;
mod text;
pub mod wifi_link;
