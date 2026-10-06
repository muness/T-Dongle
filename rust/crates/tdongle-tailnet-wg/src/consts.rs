//! Protocol constants (WireGuard whitepaper section 6, wireguard-go `device/constants.go`, the C `wireguard.h`). Times are milliseconds.

use tdongle_tailnet_types::Millis;

/// A session is rekeyed (by its initiator) after it has sent this many messages.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// No message with a counter at or above this is sent or accepted: the session is finished (`2^64 - 2^13 - 1`; the C's `REJECT_AFTER_MESSAGES`).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
/// The initiator of a session rekeys when sending on it after this age.
pub const REKEY_AFTER_TIME: Millis = 120_000;
/// No message is sent or accepted on a session of this age or older.
pub const REJECT_AFTER_TIME: Millis = 180_000;
/// Minimum spacing of initiations to one peer, and the base of the handshake retransmit timer.
pub const REKEY_TIMEOUT: Millis = 5_000;
/// Upper bound (exclusive) of the random jitter added to the retransmit and "stopped hearing back" timers.
pub const REKEY_TIMEOUT_JITTER_MAX: u64 = 334;
/// Passive keepalive delay: after receiving data and sending nothing for this long, send an empty message.
pub const KEEPALIVE_TIMEOUT: Millis = 10_000;
/// A handshake series is abandoned this long after its first initiation.
pub const REKEY_ATTEMPT_TIME: Millis = 90_000;
/// The C's cap on consecutive initiations without a session (`REKEY_ATTEMPT_TIME / REKEY_TIMEOUT`, matching wireguard-go's `MaxTimerHandshakes`).
pub const MAX_HANDSHAKE_ATTEMPTS: u8 = 18;
/// All key material of a peer is wiped this long after its last session was derived (3 x `REJECT_AFTER_TIME`).
pub const ZERO_KEY_MATERIAL_AFTER: Millis = 3 * REJECT_AFTER_TIME;
/// A cookie, and the responder's cookie secret, live this long.
pub const COOKIE_LIFETIME: Millis = 120_000;
/// Initiations from one peer closer together than this are dropped as a flood (wireguard-go `HandshakeInitationRate`, 1/50 s). The C wanted two per
/// second but its expression (`last - now` on unsigned values) never fired; this is the implemented, interoperable value.
pub const MIN_INITIATION_INTERVAL: Millis = 20;
/// Transport plaintext is zero padded to a multiple of this.
pub const PADDING_MULTIPLE: usize = 16;

/// `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// `WireGuard v1 zx2c4 Jason@zx2c4.com`.
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
/// Label of the mac1 key derivation.
pub const LABEL_MAC1: &[u8] = b"mac1----";
/// Label of the cookie encryption key derivation.
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// `Hash(Construction)`: the initial chaining key (precomputed; a test checks it against the hash).
pub const INITIAL_CHAIN_KEY: [u8; 32] = [
    0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0, 0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38,
    0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
];
/// `Hash(InitialChainKey || Identifier)`: the initial handshake hash (precomputed; a test checks it).
pub const INITIAL_HASH: [u8; 32] = [
    0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32, 0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1,
    0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3,
];

#[cfg(test)]
mod tests {
    use super::*;
    use tdongle_tailnet_crypto::blake::{hash, hash2};

    #[test]
    fn initial_state_constants_are_the_hashes() {
        assert_eq!(hash(CONSTRUCTION), INITIAL_CHAIN_KEY);
        assert_eq!(hash2(&INITIAL_CHAIN_KEY, IDENTIFIER), INITIAL_HASH);
        assert_eq!(CONSTRUCTION.len(), 37);
        assert_eq!(IDENTIFIER.len(), 34);
    }

    #[test]
    fn timing_relationships() {
        const { assert!(REKEY_AFTER_TIME < REJECT_AFTER_TIME) };
        assert_eq!(REKEY_ATTEMPT_TIME / REKEY_TIMEOUT, MAX_HANDSHAKE_ATTEMPTS as u64);
        assert_eq!(REJECT_AFTER_MESSAGES, 0xFFFF_FFFF_FFFF_FFFF - (1 << 13));
        assert_eq!(ZERO_KEY_MATERIAL_AFTER, 540_000);
    }
}
