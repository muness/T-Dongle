//! A membership's identity: the 96-byte `identity_v1` blob in its own NVS namespace `tn_%08x`, exactly as the C (`load_or_generate_keys` in
//! `microlink.c`): the machine, WireGuard and DISCO private keys, 32 bytes each in that order, X25519-clamped, generated and committed when absent.

use tdongle_tailnet_fw::{Storage, StorageError};
use tdongle_tailnet_types::{Entropy, Key32};
use zeroize::Zeroize;

/// The blob's key in the membership's namespace.
pub const IDENTITY_KEY: &str = "identity_v1";
/// The blob's length.
pub const IDENTITY_BYTES: usize = 96;

/// Why an identity could not be had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// A blob exists with another length (the C: `ESP_ERR_INVALID_SIZE`).
    BadSize,
    /// Storage failed (read or commit).
    Storage(StorageError),
}

/// The three private keys.
#[derive(Debug)]
pub struct Identity {
    /// Noise machine key.
    pub machine: Key32,
    /// WireGuard (node) key.
    pub wg: Key32,
    /// DISCO key.
    pub disco: Key32,
    /// The blob did not exist and was generated and saved now.
    pub generated: bool,
}

/// `generate_keypair`: random bytes clamped as X25519 requires.
pub fn clamp(k: &mut [u8]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// Load the identity of namespace `ns`, generating and saving it when there is none. Nothing is generated when the read fails for another reason.
pub fn load_or_generate<S: Storage + ?Sized>(storage: &mut S, ns: &str, rng: &mut dyn Entropy) -> Result<Identity, IdentityError> {
    let mut blob = [0u8; IDENTITY_BYTES + 1];
    let mut generated = false;
    let n = match storage.get(ns, IDENTITY_KEY, &mut blob) {
        Ok(n) => n,
        Err(StorageError::NotFound) => {
            let mut keys = [0u8; IDENTITY_BYTES];
            rng.fill(&mut keys);
            let (a, rest) = keys.split_at_mut(32);
            let (b, c) = rest.split_at_mut(32);
            for k in [a, b, c] {
                clamp(k);
            }
            let r = storage.set(ns, IDENTITY_KEY, &keys);
            blob[..IDENTITY_BYTES].copy_from_slice(&keys);
            keys.zeroize();
            r.map_err(IdentityError::Storage)?;
            generated = true;
            IDENTITY_BYTES
        }
        // the C reads into 96 bytes and treats a larger blob as a size error
        Err(StorageError::TooSmall) => return Err(IdentityError::BadSize),
        Err(e) => return Err(IdentityError::Storage(e)),
    };
    let r = if n != IDENTITY_BYTES {
        Err(IdentityError::BadSize)
    } else {
        let key = |i: usize| {
            let mut k = [0u8; 32];
            k.copy_from_slice(&blob[32 * i..32 * i + 32]);
            Key32(k)
        };
        Ok(Identity { machine: key(0), wg: key(1), disco: key(2), generated })
    };
    blob.zeroize();
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::string::{String, ToString};
    use std::vec;
    use std::vec::Vec;
    use tdongle_tailnet_types::test_util::TestRng;

    #[derive(Default)]
    struct Mem(BTreeMap<(String, String), Vec<u8>>, bool);
    impl Storage for Mem {
        fn get(&mut self, ns: &str, key: &str, out: &mut [u8]) -> Result<usize, StorageError> {
            let v = self.0.get(&(ns.into(), key.into())).ok_or(StorageError::NotFound)?;
            if v.len() > out.len() {
                return Err(StorageError::TooSmall);
            }
            out[..v.len()].copy_from_slice(v);
            Ok(v.len())
        }
        fn set(&mut self, ns: &str, key: &str, data: &[u8]) -> Result<(), StorageError> {
            if self.1 {
                return Err(StorageError::Failed);
            }
            self.0.insert((ns.into(), key.into()), data.to_vec());
            Ok(())
        }
        fn erase_namespace(&mut self, ns: &str) -> Result<(), StorageError> {
            self.0.retain(|(n, _), _| n != ns);
            Ok(())
        }
    }

    #[test]
    fn generated_once_clamped_and_stable() {
        let mut st = Mem::default();
        let mut rng = TestRng(7);
        let a = load_or_generate(&mut st, "tn_00000001", &mut rng).unwrap();
        assert!(a.generated);
        for k in [&a.machine, &a.wg, &a.disco] {
            let b = k.as_bytes();
            assert_eq!((b[0] & 7, b[31] & 0x80, b[31] & 0x40), (0, 0, 0x40), "clamped");
        }
        assert!(a.machine != a.wg && a.wg != a.disco);
        let stored = &st.0[&("tn_00000001".to_string(), "identity_v1".to_string())];
        assert_eq!(stored.len(), 96);
        assert_eq!(&stored[32..64], a.wg.as_bytes(), "order: machine, wireguard, disco");
        let b = load_or_generate(&mut st, "tn_00000001", &mut rng).unwrap();
        assert!(!b.generated && b.wg == a.wg && b.machine == a.machine && b.disco == a.disco);
        let c = load_or_generate(&mut st, "tn_00000002", &mut rng).unwrap();
        assert!(c.wg != a.wg, "a namespace per membership");
    }

    #[test]
    fn bad_size_and_failed_commit_are_errors_and_nothing_is_kept() {
        let mut st = Mem::default();
        st.0.insert(("tn_00000003".into(), "identity_v1".into()), vec![1; 95]);
        assert_eq!(load_or_generate(&mut st, "tn_00000003", &mut TestRng(1)).unwrap_err(), IdentityError::BadSize);
        st.0.insert(("tn_00000004".into(), "identity_v1".into()), vec![1; 97]);
        assert_eq!(load_or_generate(&mut st, "tn_00000004", &mut TestRng(1)).unwrap_err(), IdentityError::BadSize);
        let mut full = Mem(BTreeMap::new(), true);
        assert_eq!(load_or_generate(&mut full, "tn_00000005", &mut TestRng(1)).unwrap_err(), IdentityError::Storage(StorageError::Failed));
        assert!(full.0.is_empty());
    }
}
