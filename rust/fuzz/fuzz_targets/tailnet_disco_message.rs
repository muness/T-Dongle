//! DISCO plaintext parser: any bytes never panic; a parsed ping re-encodes to a message that parses to the same ping, a parsed pong re-encodes byte for byte (modulo the ignored version), a CallMeMaybe walks exactly its endpoint count.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    tdongle_tailnet_disco::fuzz::message(data);
});
