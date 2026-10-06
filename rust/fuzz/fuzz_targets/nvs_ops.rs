//! The NVS writer on arbitrary flash contents and arbitrary operations: mount, set, get, erase, remount, power cuts.
//!
//! Input: byte 0 = mode, byte 1 = partition size (3 to 18 pages), then the mode's payload, then the operation script.
//!
//! * mode 0: the payload is the raw flash image (everything after byte 1, padded with 0xFF). Arbitrary bytes are almost always rejected
//!   page by page, which is the point: mounting garbage must never panic, loop or index out of range.
//! * mode 1: a valid image made by the engine from a fixed script, then `n` patches (offset u16, xor mask u8): a damaged but plausible
//!   partition (flipped bits in headers, states, data).
//! * mode 2: a valid image and a *model*: every operation is checked against a map, a power cut is injected into some operations, and what
//!   a cold start finds must be the old or the new value of the key (the invariant of `tests/power_loss.rs` on a random sequence).
//!
//! In every mode the engine must not panic; in mode 2 it must also agree with the model and never ask the flash to set a bit.
#![no_main]
use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use tdongle_nvs_write::{Error, Nvs, SimFlash, Tear};

const NS: [&str; 2] = ["tn_settings", "adapter"];
const KEYS: [&str; 5] = ["wifi_profiles", "wifi_meta", "mode", "k", "0123456789abcde"];

type Model = BTreeMap<(usize, usize), (u8, Vec<u8>)>;

struct Script<'a>(&'a [u8]);

impl Script<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
}

fn blob(len_byte: u8, seed: u8) -> Vec<u8> {
    let len = match len_byte % 8 {
        0 => 0,
        1 => 1,
        2 => 8,
        3 => 31 + usize::from(len_byte >> 3),
        4 => 784,
        5 => 516,
        6 => 3990 + usize::from(len_byte >> 3),
        _ => 5000 + usize::from(len_byte) * 20,
    };
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn base_image(pages: usize) -> Vec<u8> {
    let mut nvs = Nvs::open(SimFlash::new(pages * 4096), (pages * 4096) as u32).unwrap();
    nvs.set_blob("tn_settings", "wifi_profiles", &blob(4, 1)).unwrap();
    nvs.set_blob("tn_settings", "wifi_meta", &blob(5, 2)).unwrap();
    nvs.set_u8("tn_settings", "mode", 1).unwrap();
    nvs.set_str("tn_settings", "members", "alice,bob").unwrap();
    nvs.set_blob("adapter", "config", &blob(7, 3)).unwrap();
    nvs.set_blob("tn_settings", "wifi_profiles", &blob(4, 9)).unwrap();
    nvs.into_flash().data
}

fn read_all(nvs: &mut Nvs<SimFlash>) -> Model {
    let mut m = Model::new();
    for (n, ns) in NS.iter().enumerate() {
        for (k, key) in KEYS.iter().enumerate() {
            if let Ok(Some(len)) = nvs.value_len(ns, key) {
                let mut b = vec![0u8; len];
                if matches!(nvs.get_blob(ns, key, &mut b), Ok(Some(_))) {
                    m.insert((n, k), (1, b));
                }
            } else if let Ok(Some(v)) = nvs.get_u8(ns, key) {
                m.insert((n, k), (0, vec![v]));
            }
        }
    }
    m
}

fn run_ops(nvs: &mut Nvs<SimFlash>, script: &mut Script<'_>, mut model: Option<Model>, size: u32) {
    let mut steps = 0;
    while let Some(op) = script.byte() {
        steps += 1;
        if steps > 40 {
            break;
        }
        let (n, k) = (usize::from(script.byte().unwrap_or(0)) % NS.len(), usize::from(script.byte().unwrap_or(0)) % KEYS.len());
        let (ns, key) = (NS[n], KEYS[k]);
        let cut = (op & 0x80 != 0).then(|| (u64::from(script.byte().unwrap_or(0)) * 37 + u64::from(script.byte().unwrap_or(0)), op & 0x40 != 0));
        let before = model.clone();
        let value = match op % 6 {
            0 | 1 | 2 => Some((1u8, blob(script.byte().unwrap_or(0), op))),
            3 => Some((0u8, vec![script.byte().unwrap_or(0)])),
            _ => None,
        };
        if let Some((budget, bits)) = cut {
            nvs.flash_mut().arm(budget, if bits { Tear::Bits(budget ^ 0x5555) } else { Tear::Prefix });
        }
        let r = match (&value, op % 6) {
            (Some((1, b)), _) => nvs.set_blob(ns, key, b),
            (Some((_, b)), _) => nvs.set_u8(ns, key, b[0]),
            (None, 4) => match nvs.erase_key(ns, key) {
                Err(Error::NotFound) => Ok(()),
                r => r,
            },
            (None, _) => {
                // a reboot
                let flash = std::mem::replace(nvs.flash_mut(), SimFlash::new(0));
                match Nvs::open(flash, size) {
                    Ok(n2) => {
                        *nvs = n2;
                        Ok(())
                    }
                    Err(_) => return,
                }
            }
        };
        if nvs.flash().is_dead() {
            let image = nvs.flash().data.clone();
            let Ok(mut again) = Nvs::open(SimFlash::from_image(image), size) else { return };
            let found = read_all(&mut again);
            if let (Some(old), Some(_)) = (&before, &model) {
                let mut new = old.clone();
                match (&value, op % 6) {
                    (Some(v), _) => {
                        new.insert((n, k), v.clone());
                    }
                    (None, 4) => {
                        new.remove(&(n, k));
                    }
                    _ => {}
                }
                for key in found.keys().chain(old.keys()) {
                    assert!(found.get(key) == old.get(key) || found.get(key) == new.get(key), "power cut left a third value for {key:?}");
                }
            }
            model = model.map(|_| found);
            *nvs = again;
            continue;
        }
        match r {
            Ok(()) => {
                if let Some(m) = model.as_mut() {
                    match (&value, op % 6) {
                        (Some(v), _) => {
                            m.insert((n, k), v.clone());
                        }
                        (None, 4) => {
                            m.remove(&(n, k));
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => {}
        }
        if let Some(m) = &model {
            // mode 2 only: strings and other keys are not in the model, but every modelled key must read back exactly
            let got = read_all(nvs);
            for (key, v) in m {
                assert_eq!(got.get(key), Some(v), "model mismatch for {key:?}");
            }
        }
    }
    if model.is_some() {
        assert_eq!(nvs.flash().violations, 0, "the engine asked the flash to set a bit");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let Some((&pages, rest)) = rest.split_first() else { return };
    let pages = 3 + usize::from(pages) % 16;
    let size = (pages * 4096) as u32;
    match mode % 3 {
        0 => {
            let mut image = vec![0xffu8; pages * 4096];
            let n = rest.len().min(image.len());
            image[..n].copy_from_slice(&rest[..n]);
            let Ok(mut nvs) = Nvs::open(SimFlash::from_image(image), size) else { return };
            // after the first operation nothing about the image is known; the script must simply not panic
            run_ops(&mut nvs, &mut Script(&rest[n..]), None, size);
            let _ = nvs.stats();
        }
        1 => {
            let mut image = base_image(pages);
            let Some((&patches, mut rest)) = rest.split_first() else { return };
            for _ in 0..patches % 24 {
                let [a, b, m, tail @ ..] = rest else { break };
                let at = (usize::from(*a) << 8 | usize::from(*b)) % image.len();
                image[at] ^= *m;
                rest = tail;
            }
            let Ok(mut nvs) = Nvs::open(SimFlash::from_image(image), size) else { return };
            run_ops(&mut nvs, &mut Script(rest), None, size);
        }
        _ => {
            let Ok(mut nvs) = Nvs::open(SimFlash::from_image(base_image(pages)), size) else { return };
            let model = read_all(&mut nvs);
            run_ops(&mut nvs, &mut Script(rest), Some(model), size);
        }
    }
});
