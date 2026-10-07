//! The serial line discipline and command parser take whatever a host sends over the CDC port.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_serial::command::Command;
use tdongle_serial::console::{Event, LineReader};

fuzz_target!(|data: &[u8]| {
    let mut reader = LineReader::new();
    for &byte in data {
        if let Some(Event::Line(line)) = reader.feed(byte) {
            let _ = Command::parse(line);
            let _ = Command::parse_with_diagnostics(line);
        }
    }
});
