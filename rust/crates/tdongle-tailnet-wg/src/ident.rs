//! The long-lived keys: our identity (device level, shared by every peer of a membership) and a peer's cold record (public key, preshared key and the
//! precomputed static-static Diffie-Hellman). Neither holds any session or handshake state; that is [`PeerHot`](crate::peer::PeerHot), so a global pool of
//! hot slots can serve several memberships' cold records.

use crate::consts::{LABEL_COOKIE, LABEL_MAC1};
use tdongle_tailnet_crypto::{blake, x25519};
use tdongle_tailnet_types::Key32;

/// Our static key pair and the two keys derived from our public key (the C's `device->label_mac1_key` and `label_cookie_key`).
pub struct Identity {
    private: Key32,
    public: Key32,
    mac1_key: [u8; 32],
    cookie_key: [u8; 32],
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity({:?})", self.public.short())
    }
}

/// `Hash(label || public_key)`: the mac1 key (label `mac1----`) or the cookie encryption key (`cookie--`) of the holder of `public`.
pub fn label_key(label: &[u8], public: &Key32) -> [u8; 32] {
    blake::hash2(label, &public.0)
}

impl Identity {
    /// `size_of::<Identity>()`.
    pub const BYTES: usize = core::mem::size_of::<Identity>();

    /// From a private key (clamped as RFC 7748 requires). `None` for the all-zero key.
    pub fn new(private: &Key32) -> Option<Identity> {
        if private.is_zero() {
            return None;
        }
        let mut k = private.clone();
        k.0[0] &= 248;
        k.0[31] = (k.0[31] & 127) | 64;
        let public = x25519::public(&k);
        if public.is_zero() {
            return None;
        }
        Some(Identity { mac1_key: label_key(LABEL_MAC1, &public), cookie_key: label_key(LABEL_COOKIE, &public), private: k, public })
    }

    /// Our public key.
    pub fn public(&self) -> &Key32 {
        &self.public
    }

    /// `DH(our private, their public)`; `None` for a small-order point.
    pub fn dh(&self, their: &Key32) -> Option<Key32> {
        x25519::shared(&self.private, their)
    }

    /// The key peers use for the mac1 of messages sent to us.
    pub fn mac1_key(&self) -> &[u8; 32] {
        &self.mac1_key
    }

    /// The key under which our cookie replies are encrypted.
    pub fn cookie_key(&self) -> &[u8; 32] {
        &self.cookie_key
    }
}

/// A peer's rarely changing record. The runtime keeps one per configured peer (all of them, resident or not); only the active ones get a hot slot.
#[derive(Clone)]
pub struct PeerCold {
    public: Key32,
    psk: Key32,
    static_dh: Key32,
}

impl core::fmt::Debug for PeerCold {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PeerCold({:?})", self.public.short())
    }
}

impl PeerCold {
    /// `size_of::<PeerCold>()`: public key, preshared key, precomputed `DH(Spriv_us, Spub_them)`.
    pub const BYTES: usize = core::mem::size_of::<PeerCold>();

    /// A peer record; `psk` all zero (or `None`) means no preshared key. `None` if the public key is of small order (the static DH is zero).
    pub fn new(id: &Identity, public: Key32, psk: Option<Key32>) -> Option<PeerCold> {
        let static_dh = id.dh(&public)?;
        Some(PeerCold { public, psk: psk.unwrap_or(Key32::ZERO), static_dh })
    }

    /// The peer's public key.
    pub fn public(&self) -> &Key32 {
        &self.public
    }

    /// Replace the preshared key.
    pub fn set_psk(&mut self, psk: Key32) {
        self.psk = psk;
    }

    pub(crate) fn psk(&self) -> &Key32 {
        &self.psk
    }
    pub(crate) fn static_dh(&self) -> &Key32 {
        &self.static_dh
    }

    /// The key for mac1 of messages we send to this peer.
    pub fn mac1_key(&self) -> [u8; 32] {
        label_key(LABEL_MAC1, &self.public)
    }

    /// The key under which this peer's cookie replies to us are encrypted.
    pub fn cookie_key(&self) -> [u8; 32] {
        label_key(LABEL_COOKIE, &self.public)
    }
}

/// A wall-clock reading, for the TAI64N timestamp of an initiation. It only has to be non-decreasing across calls and across reboots *of this peer's
/// view*: a responder drops an initiation whose timestamp is not newer than the greatest it has seen (whitepaper 5.1 "Silence is a virtue").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallClock {
    /// Seconds since the Unix epoch.
    pub unix_secs: u64,
    /// Nanoseconds within the second.
    pub nanos: u32,
}

/// The 12-byte TAI64N label (big endian: byte-wise comparison is time order). Same epoch arithmetic as wireguard-go (`0x400000000000000a + unix`).
pub fn tai64n(w: WallClock) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&(0x4000_0000_0000_000au64.wrapping_add(w.unix_secs)).to_be_bytes());
    out[8..].copy_from_slice(&w.nanos.min(999_999_999).to_be_bytes());
    out
}

/// `t + 1 ns` as a 96-bit big-endian counter (saturating at the top).
pub(crate) fn tai_succ(t: &[u8; 12]) -> [u8; 12] {
    let mut o = *t;
    for b in o.iter_mut().rev() {
        let (v, carry) = b.overflowing_add(1);
        *b = v;
        if !carry {
            return o;
        }
    }
    *t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tai64n_layout_and_order() {
        let t = tai64n(WallClock { unix_secs: 0, nanos: 0 });
        assert_eq!(t, [0x40, 0, 0, 0, 0, 0, 0, 0x0a, 0, 0, 0, 0]);
        let a = tai64n(WallClock { unix_secs: 1_700_000_000, nanos: 999_999_999 });
        let b = tai64n(WallClock { unix_secs: 1_700_000_001, nanos: 0 });
        assert!(a < b, "byte order is time order");
        assert_eq!(&a[8..], &999_999_999u32.to_be_bytes());
    }

    #[test]
    fn successor_carries() {
        assert_eq!(tai_succ(&[0; 12])[11], 1);
        let mut x = [0u8; 12];
        x[11] = 0xff;
        x[10] = 0xff;
        let y = tai_succ(&x);
        assert_eq!(&y[9..], &[1, 0, 0]);
        assert_eq!(tai_succ(&[0xff; 12]), [0xff; 12], "saturates");
    }

    #[test]
    fn identity_clamps_and_rejects_zero() {
        assert!(Identity::new(&Key32::ZERO).is_none());
        let id = Identity::new(&Key32([0xff; 32])).unwrap();
        assert_eq!(
            x25519::public(&{
                let mut k = [0xffu8; 32];
                k[0] &= 248;
                k[31] = (k[31] & 127) | 64;
                Key32(k)
            }),
            *id.public()
        );
        assert!(PeerCold::new(&id, Key32::ZERO, None).is_none(), "small-order peer key");
    }
}
