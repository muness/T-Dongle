//! Known-answer tests from outside this crate: the wireguard-go KDF vectors (`device/kdf_test.go`), RFC 8439 (the C `test_wg_crypto.c` vectors, extracted from the
//! RFC text), the XChaCha20-Poly1305 draft vector WireGuard's cookie reply uses, and the Noise/WireGuard constants.

use hex_literal::hex;
use tdongle_tailnet_crypto::aead::{open_detached, seal_detached, xopen_detached, xseal_detached};
use tdongle_tailnet_crypto::blake::{hash, hash2, hmac, kdf1, kdf2, kdf3};
use tdongle_tailnet_wg::consts::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// wireguard-go `TestKDF`: HKDF-BLAKE2s outputs for keys of 8, 9 and 0 bytes (so HMAC key padding is exercised, not only 32-byte chaining keys).
#[test]
fn wireguard_go_kdf_vectors() {
    let tests = [
        (
            "746573742d6b6579",
            "746573742d696e707574",
            "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
            "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
            "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24",
        ),
        (
            "776972656775617264",
            "776972656775617264",
            "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
            "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
            "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160",
        ),
        (
            "",
            "",
            "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
            "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
            "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e",
        ),
    ];
    for (key, input, o0, o1, o2) in tests {
        let (key, input) = (unhex(key), unhex(input));
        // the KDF written out from the whitepaper with the crate's HMAC (arbitrary key lengths)
        let t0 = hmac(&key, &input);
        let r0 = hmac(&t0, &[1]);
        let mut m = r0.to_vec();
        m.push(2);
        let r1 = hmac(&t0, &m);
        let mut m = r1.to_vec();
        m.push(3);
        let r2 = hmac(&t0, &m);
        assert_eq!(r0.to_vec(), unhex(o0));
        assert_eq!(r1.to_vec(), unhex(o1));
        assert_eq!(r2.to_vec(), unhex(o2));
    }
    // and the kdf1/2/3 helpers (32-byte chaining key) agree with that construction on a vector of their own shape
    let ck = [0x42u8; 32];
    let t0 = hmac(&ck, b"input");
    let o0 = hmac(&t0, &[1]);
    let mut m = o0.to_vec();
    m.push(2);
    let o1 = hmac(&t0, &m);
    let mut m = o1.to_vec();
    m.push(3);
    let o2 = hmac(&t0, &m);
    assert_eq!(kdf1(&ck, b"input"), o0);
    assert_eq!(kdf2(&ck, b"input"), (o0, o1));
    assert_eq!(kdf3(&ck, b"input"), (o0, o1, o2));
}

/// RFC 8439 section 2.8.2 and A.5 from the C test's vector file. The WireGuard nonce is four zero bytes then a little-endian counter, so only vectors of that
/// shape (A.5) go through the crate's AEAD; the 2.8.2 vector's nonce is checked at the cipher level by the crypto crate's own tests.
#[test]
fn rfc8439_aead_vectors() {
    let text = include_str!("fixtures/rfc8439_aead.txt");
    let mut checked = 0;
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let f: Vec<&str> = line.split(' ').collect();
        let (key, nonce, aad, pt, ct, tag) = (unhex(f[1]), unhex(f[2]), unhex(f[3]), unhex(f[4]), unhex(f[5]), unhex(f[6]));
        if nonce[..4] != [0; 4] {
            assert_eq!(f[0], "e282", "only RFC 8439 2.8.2 has a nonce outside the WireGuard layout");
            continue;
        }
        let key: [u8; 32] = key.try_into().unwrap();
        let counter = u64::from_le_bytes(nonce[4..].try_into().unwrap());
        let mut buf = pt.clone();
        let t = seal_detached(&key, counter, &aad, &mut buf);
        assert_eq!(buf, ct, "{} ciphertext", f[0]);
        assert_eq!(t.to_vec(), tag, "{} tag", f[0]);
        let tag: [u8; 16] = tag.try_into().unwrap();
        open_detached(&key, counter, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open_detached(&key, counter, &aad, &mut bad, &tag).is_err());
        checked += 1;
    }
    assert_eq!(checked, 1, "RFC 8439 A.5 was exercised");
}

/// draft-irtf-cfrg-xchacha-03 appendix A.3.1 (the AEAD WireGuard's cookie reply is built on).
#[test]
fn xchacha20_poly1305_draft_vector() {
    let key = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex!("404142434445464748494a4b4c4d4e4f5051525354555657");
    let aad = hex!("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ct = hex!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"
    );
    let tag = hex!("c0875924c1c7987947deafd8780acf49");
    let mut buf = *pt;
    let t = xseal_detached(&key, &nonce, &aad, &mut buf);
    assert_eq!(&buf[..], &ct[..]);
    assert_eq!(t, tag);
    assert!(xopen_detached(&key, &nonce, &aad, &mut buf, &tag).is_ok());
    assert_eq!(&buf, pt);
}

/// The two constants every WireGuard implementation hard codes (whitepaper 5.4: `Hash(Construction)` and `Hash(Hash(Construction) || Identifier)`), as printed by
/// wireguard-go's `InitialChainKey` / `InitialHash` and the kernel's `noise_init`.
#[test]
fn well_known_initial_state() {
    assert_eq!(hash(CONSTRUCTION), hex!("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"));
    assert_eq!(hash2(&INITIAL_CHAIN_KEY, IDENTIFIER), hex!("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"));
    assert_eq!(INITIAL_CHAIN_KEY, hex!("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36"));
    assert_eq!(INITIAL_HASH, hex!("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"));
}
