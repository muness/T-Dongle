//! Arbitrary bytes must never make the parser panic, loop forever, or hand back unverified data.

use proptest::prelude::*;
use tdongle_nvs_read::{Nvs, SliceFlash};

const MAIN_V2: &[u8] = include_bytes!("fixtures/main_v2.bin");
const BIG_V2: &[u8] = include_bytes!("fixtures/big_v2.bin");
const MANY: &[u8] = include_bytes!("fixtures/many_v2.bin");

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

const NAMES: &[(&str, &str)] = &[
    ("tn_settings", "mode"),
    ("tn_settings", "members"),
    ("tn_settings", "wifi_profiles"),
    ("tn_settings", "wifi_meta"),
    ("tn_settings", "display"),
    ("adapter", "config"),
    ("big", "blob8000"),
    ("big", "blob6000"),
    ("many", "k1"),
    ("second", "b"),
    ("", ""),
    ("x", "y"),
];

/// Run every getter on every name; the results do not matter, only that nothing panics.
fn exercise(img: &[u8], size: u32) {
    let mut n = Nvs::new(SliceFlash(img), size);
    let mut out = [0u8; 8192];
    for &(ns, key) in NAMES {
        let _ = n.get_u8(ns, key);
        let _ = n.blob_len(ns, key);
        let _ = n.get_blob(ns, key, &mut out);
        let _ = n.get_blob(ns, key, &mut out[..3]);
        let _ = n.has_str(ns, key);
    }
}

fn scale() -> u64 {
    if cfg!(miri) { 1 } else { 40 }
}

#[test]
fn random_garbage() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    for _ in 0..scale() {
        let mut img = vec![0u8; 0x10000];
        for chunk in img.chunks_mut(8) {
            let r = rng.next().to_le_bytes();
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
        exercise(&img, 0x10000);
    }
}

/// Garbage that passes the CRC checks is the dangerous case, so also fuzz the interesting bytes of valid images: flips, 0x00/0xff
/// runs, and truncation.
#[test]
fn mutated_valid_images() {
    let mut rng = XorShift(0x1234_5678_9ABC_DEF1);
    for base in [MAIN_V2, BIG_V2, MANY] {
        for _ in 0..scale() * 10 {
            let mut img = base.to_vec();
            for _ in 0..1 + rng.next() % 12 {
                let at = (rng.next() % img.len() as u64) as usize;
                match rng.next() % 4 {
                    0 => img[at] ^= 1 << (rng.next() % 8),
                    1 => img[at] = rng.next() as u8,
                    2 => img[at..].iter_mut().take(1 + (rng.next() % 64) as usize).for_each(|b| *b = 0xff),
                    _ => img[at..].iter_mut().take(1 + (rng.next() % 64) as usize).for_each(|b| *b = 0),
                }
            }
            exercise(&img, 0x10000);
        }
    }
}

/// Mutations of item headers with a fixed-up CRC reach the span/length checks that random flips almost never get past.
#[test]
fn recrc_mutations_reach_the_bounds_checks() {
    fn crc32(data: &[u8], mut crc: u32) -> u32 {
        crc = !crc;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }
    let mut rng = XorShift(0xDEAD_BEEF_CAFE_F00D);
    for base in [MAIN_V2, BIG_V2] {
        for _ in 0..scale() * 25 {
            let mut img = base.to_vec();
            for _ in 0..4 {
                let page = (rng.next() % 3) as usize;
                let entry = (rng.next() % 126) as usize;
                let at = page * 4096 + 64 + entry * 32;
                let field = rng.next() % 32;
                img[at + field as usize] = rng.next() as u8;
                if rng.next().is_multiple_of(4) {
                    img[at + 2] = (rng.next() % 256) as u8; // span
                }
                let c = crc32(&img[at + 8..at + 32], crc32(&img[at..at + 4], 0xffff_ffff));
                img[at + 4..at + 8].copy_from_slice(&c.to_le_bytes());
            }
            exercise(&img, 0x10000);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: if cfg!(miri) { 2 } else { 256 }, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes_any_size(bytes in proptest::collection::vec(any::<u8>(), 0..9000), size in 0u32..0x20000) {
        exercise(&bytes, size);
    }

    #[test]
    fn arbitrary_page_with_valid_shape(
        body in proptest::collection::vec(any::<u8>(), 4096),
        seq in any::<u32>(),
    ) {
        // A page whose header passes its CRC, so the entry walk is reached with arbitrary entries.
        let mut img = body;
        img[..4].copy_from_slice(&0xffff_fffeu32.to_le_bytes());
        img[4..8].copy_from_slice(&seq.to_le_bytes());
        img[8..28].fill(0xff);
        let crc = {
            let mut c = !0xffff_ffffu32;
            for &b in &img[4..28] {
                c ^= u32::from(b);
                for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 }; }
            }
            !c
        };
        img[28..32].copy_from_slice(&crc.to_le_bytes());
        exercise(&img, 4096);
    }
}
