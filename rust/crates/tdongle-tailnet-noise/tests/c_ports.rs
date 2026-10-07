//! Ports of the C tests `test_noise_inplace.c` and `test_control_send.c` (the parts that are about the Noise layer, not the socket).
mod common;
use common::*;
use tdongle_tailnet_noise::{HEADROOM, MAX_PLAINTEXT, OpenError, SealError, TAILROOM, wire_len};

/// `test_control_send.c::check`: 257 bytes of plaintext at nonce 7 become a 276-byte record `04 01 11 ...` and the nonce moves to 8.
#[test]
fn send_owned_257_bytes_at_nonce_7() {
    for seed in 1..=31u64 {
        let (mut tx, mut rx) = pair(seed, 131);
        tx.set_nonces_for_test(7, 0);
        rx.set_nonces_for_test(0, 7);
        let plain: Vec<u8> = (0..257).map(|i| (i as u64 * seed) as u8).collect();
        let mut owned = vec![0u8; HEADROOM + 257 + TAILROOM];
        owned[HEADROOM..HEADROOM + 257].copy_from_slice(&plain);
        let n = tx.seal_record(&mut owned, 257).unwrap();
        assert_eq!(n, 276);
        assert_eq!(&owned[..3], &[4, 1, 17]);
        assert_eq!(tx.tx_nonce(), 8);
        let r = rx.open_record(&mut owned[..n]).unwrap();
        assert_eq!(&owned[r], &plain[..]);
        assert_eq!(rx.rx_nonce(), 8);
    }
}

/// `noise_send_owned` failure paths: no tailroom, or encryption refused, leave the nonce alone and emit nothing.
#[test]
fn send_owned_refusals_leave_nonce_alone() {
    let (mut tx, _rx) = pair(3, 131);
    tx.set_nonces_for_test(8, 0);
    let mut owned = [0u8; 64];
    // C: length 64, capacity 64 (no room for the tag)
    assert_eq!(tx.seal_record(&mut owned, 64), Err(SealError::BufferTooSmall));
    assert_eq!(tx.tx_nonce(), 8);
    // C: length above the limit (here the record limit is 4077, not the C's 65519)
    let mut big = vec![0u8; 5000];
    assert_eq!(tx.seal_record(&mut big, MAX_PLAINTEXT + 1), Err(SealError::TooLong));
    assert_eq!(tx.tx_nonce(), 8);
    assert_eq!(tx.stats().buffer_too_small.get(), 1);
    assert_eq!(tx.stats().oversize.get(), 1);
    // and a good one afterwards still works with the next nonce
    assert_eq!(tx.seal_record(&mut owned, 16), Ok(wire_len(16)));
    assert_eq!(tx.tx_nonce(), 9);
}

/// `test_noise_inplace.c`: in-place round trips at the C's lengths (those that fit one record), tamper the tag, nothing leaks.
#[test]
fn inplace_roundtrip_and_tamper() {
    for &len in &[0usize, 1, 15, 16, 17, 1024, 4077] {
        let (mut tx, mut rx) = pair(len as u64 + 11, 131);
        let plain: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let mut wire = vec![0u8; wire_len(len)];
        wire[HEADROOM..HEADROOM + len].copy_from_slice(&plain);
        let n = tx.seal_record(&mut wire, len).unwrap();
        assert_eq!(n, wire.len());
        let sealed = wire.clone();
        // decrypt in place
        let r = rx.open_record(&mut wire).unwrap();
        assert_eq!(&wire[r], &plain[..]);

        // tamper: flip a tag bit; the failed in-place open leaves zeros, not plaintext (C asserts wire[j] == 0)
        let (mut tx, mut rx) = pair(len as u64 + 11, 131);
        let mut w2 = vec![0u8; wire_len(len)];
        w2[HEADROOM..HEADROOM + len].copy_from_slice(&plain);
        tx.seal_record(&mut w2, len).unwrap();
        assert_eq!(w2, sealed);
        w2[HEADROOM + len] ^= 1;
        assert_eq!(rx.open_record(&mut w2), Err(OpenError::AuthFailed));
        assert!(w2[HEADROOM..HEADROOM + len].iter().all(|&b| b == 0));
        assert!(rx.rx_dead());
        assert_eq!(rx.stats().auth_failures.get(), 1);
        assert_eq!(rx.rx_nonce(), 0, "a failed open does not advance the counter");
    }
}

/// The C test also seals 20480 bytes; the ts2021 framing caps a record at 4096, so those are split by the caller and one record refuses.
#[test]
fn twenty_kib_needs_chunking() {
    let (mut tx, mut rx) = pair(5, 131);
    let plain: Vec<u8> = (0..20480).map(|i| (i * 7) as u8).collect();
    let mut buf = vec![0u8; 4096];
    assert_eq!(tx.seal_into(&plain, &mut buf), Err(SealError::TooLong));
    let mut got = Vec::new();
    for chunk in plain.chunks(MAX_PLAINTEXT) {
        let n = tx.seal_into(chunk, &mut buf).unwrap();
        let r = rx.open_record(&mut buf[..n]).unwrap();
        got.extend_from_slice(&buf[r]);
    }
    assert_eq!(got, plain);
}
