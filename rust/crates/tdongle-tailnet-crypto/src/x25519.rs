//! X25519 (RFC 7748) over `x25519-dalek`, with the checks WireGuard and Noise need.

use tdongle_tailnet_types::Key32;
use x25519_dalek::{PublicKey, StaticSecret};

/// The public key for a private key (clamping is the library's).
pub fn public(secret: &Key32) -> Key32 {
    let s = StaticSecret::from(secret.0);
    Key32(PublicKey::from(&s).to_bytes())
}

/// Diffie-Hellman. `None` when the result is the all-zero point (a small-order peer key), which WireGuard and Noise both treat as failure.
pub fn shared(secret: &Key32, their_public: &Key32) -> Option<Key32> {
    let s = StaticSecret::from(secret.0);
    let out = Key32(s.diffie_hellman(&PublicKey::from(their_public.0)).to_bytes());
    if out.is_zero() { None } else { Some(out) }
}

/// A fresh private key from `rng`, clamped as RFC 7748 requires (WireGuard stores clamped keys).
pub fn generate(rng: &mut dyn tdongle_tailnet_types::Entropy) -> Key32 {
    let mut k = Key32::ZERO;
    rng.fill(&mut k.0);
    k.0[0] &= 248;
    k.0[31] &= 127;
    k.0[31] |= 64;
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// RFC 7748 section 6.1.
    #[test]
    fn rfc7748_6_1() {
        let a = Key32(hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        let b = Key32(hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
        let apub = public(&a);
        let bpub = public(&b);
        assert_eq!(apub.0, hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        assert_eq!(bpub.0, hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
        let k1 = shared(&a, &bpub).unwrap();
        let k2 = shared(&b, &apub).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.0, hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    }

    #[test]
    fn small_order_point_is_rejected() {
        let a = Key32(hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        assert!(shared(&a, &Key32::ZERO).is_none());
        // the other order-1/2/4/8 points the RFC lists
        let low = [
            hex!("0100000000000000000000000000000000000000000000000000000000000000"),
            hex!("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex!("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        ];
        for p in low {
            assert!(shared(&a, &Key32(p)).is_none());
        }
    }

    #[test]
    fn generated_keys_are_clamped() {
        let mut r = tdongle_tailnet_types::test_util::TestRng(1);
        let k = generate(&mut r);
        assert_eq!(k.0[0] & 7, 0);
        assert_eq!(k.0[31] & 0xc0, 0x40);
    }
}
