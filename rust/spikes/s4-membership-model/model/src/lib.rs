//! S4 memory model of ONE tailnet membership. no_std + alloc. Real crates, synthetic data, no network.
//! Everything here is shared by the firmware (xtensa) and the host harness, so struct sizes are of the same types.
#![no_std]
extern crate alloc;

pub mod coord;
pub mod disco;
pub mod meter;
pub mod rng;
pub mod scenario;
pub mod tls;
pub mod wg;

/// Fixtures recorded by `host gen` (a real rustls TLS 1.3 server, a snow Noise IK responder). See host/src/main.rs.
pub mod fixtures {
    pub static NOISE_REPLY: &[u8] = include_bytes!("../../fixtures/noise_reply.bin");
    pub static NOISE_RECORD: &[u8] = include_bytes!("../../fixtures/noise_record.bin");
    pub static TLS_SERVER_BYTES: &[u8] = include_bytes!("../../fixtures/tls_server.bin");
    pub static TLS_CLIENT_BYTES: &[u8] = include_bytes!("../../fixtures/tls_client.bin");
    pub static CA_DER: &[u8] = include_bytes!("../../fixtures/ca.der");
    /// u32 LE lengths: [first-flight server bytes = ServerHello..Finished][after client Finished: reply to app data]
    pub static TLS_SPLIT: &[u8] = include_bytes!("../../fixtures/tls_split.bin");
}
