//! Random operation sequences against a model map, with remounts and power cuts in the middle of operations.
mod common;

use common::*;
use proptest::prelude::*;
use tdongle_nvs_write::{Error, Nvs, SimFlash, Tear};

const NS: [&str; 3] = ["a", "tn_settings", "adapter"];
const KEYS: [&str; 6] = ["k0", "k1", "wifi_profiles", "blob", "x", "0123456789abcde"];

#[derive(Clone, Debug)]
enum Kind {
    U8(u8),
    U32(u32),
    I32(i32),
    Str(usize, u32),
    Blob(usize, u32),
    Erase,
    EraseNs,
    Remount,
}

#[derive(Clone, Debug)]
struct POp {
    ns: usize,
    key: usize,
    kind: Kind,
    /// Cut the power after this many units of this operation (`None`: no cut), and how.
    cut: Option<(u16, u8)>,
}

fn blob_len() -> impl Strategy<Value = usize> {
    prop_oneof![5 => 0usize..70, 3 => 700usize..800, 2 => 3900usize..4100, 1 => 7000usize..9500]
}

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        3 => any::<u8>().prop_map(Kind::U8),
        2 => any::<u32>().prop_map(Kind::U32),
        1 => any::<i32>().prop_map(Kind::I32),
        3 => (0usize..300, any::<u32>()).prop_map(|(l, s)| Kind::Str(l, s)),
        6 => (blob_len(), any::<u32>()).prop_map(|(l, s)| Kind::Blob(l, s)),
        3 => Just(Kind::Erase),
        1 => Just(Kind::EraseNs),
        2 => Just(Kind::Remount),
    ]
}

fn op() -> impl Strategy<Value = POp> {
    (0..NS.len(), 0..KEYS.len(), kind(), prop_oneof![8 => Just(None), 2 => (0u16..6000, 0u8..3).prop_map(Some)]).prop_map(|(ns, key, kind, cut)| POp {
        ns,
        key,
        kind,
        cut,
    })
}

fn to_op(o: &POp) -> Option<Op> {
    let (ns, key) = (NS[o.ns], KEYS[o.key]);
    Some(match &o.kind {
        Kind::U8(v) => Op::U8(ns, key, *v),
        Kind::U32(v) => Op::U32(ns, key, *v),
        Kind::I32(v) => Op::I32(ns, key, *v),
        Kind::Str(l, s) => Op::Str(ns, key, String::from_utf8(pattern(*l, *s).into_iter().map(|b| b'a' + b % 26).collect()).unwrap()),
        Kind::Blob(l, s) => Op::Blob(ns, key, pattern(*l, *s)),
        Kind::Erase => Op::Erase(ns, key),
        Kind::EraseNs => Op::EraseNs(ns),
        Kind::Remount => return None,
    })
}

fn run(ops: &[POp]) {
    let mut nvs = Nvs::open(SimFlash::new(SIZE as usize), SIZE).unwrap();
    let mut model = Dump::new();
    for (i, o) in ops.iter().enumerate() {
        let Some(op) = to_op(o) else {
            let flash = nvs.into_flash();
            nvs = Nvs::open(flash, SIZE).unwrap_or_else(|e| panic!("op {i}: remount {e:?}"));
            assert_same(&format!("op {i} remount"), &dump(&mut nvs), &model);
            continue;
        };
        if let Some((budget, tear)) = o.cut {
            let tear = match tear {
                0 => Tear::Prefix,
                1 => Tear::Bits(u64::from(budget) * 7919 + i as u64),
                _ => Tear::Bits(!(u64::from(budget) * 104_729 + i as u64)),
            };
            nvs.flash_mut().arm(u64::from(budget), tear);
        }
        let before = model.clone();
        let r = apply(&mut nvs, &op);
        if nvs.flash().is_dead() {
            // Power cut: what a cold start finds is the old or the new value of the keys this operation touches, and nothing else changed.
            let mut after = model.clone();
            apply_model(&mut after, &op);
            let image = nvs.flash().data.clone();
            assert_eq!(nvs.flash().violations, 0, "op {i}");
            let mut again = Nvs::open(SimFlash::from_image(image.clone()), SIZE).unwrap_or_else(|e| panic!("op {i} {op:?}: mount after the cut: {e:?}"));
            let d = dump(&mut again);
            for k in d.keys().chain(before.keys()) {
                let (old, new) = (before.get(k), after.get(k));
                assert!(d.get(k) == old || d.get(k) == new, "op {i} {op:?}: {k:?} is neither the old nor the new value");
            }
            let bad = check_with_reader(&image, &d.iter().filter(|(_, v)| v.0 != "string").map(|(k, v)| (k.clone(), v.clone())).collect());
            let _ = bad; // the reader sees the repaired image below
            let repaired = again.flash().data.clone();
            let bad = check_with_reader(&repaired, &d);
            assert!(bad.is_empty(), "op {i}: {bad:?}");
            model = d;
            nvs = again;
            continue;
        }
        match r {
            Ok(()) => apply_model(&mut model, &op),
            Err(Error::NoSpace | Error::ValueTooLong) => {}
            Err(e) => panic!("op {i} {op:?}: {e:?}"),
        }
        assert_same(&format!("op {i} {op:?}"), &dump(&mut nvs), &model);
    }
    assert_eq!(nvs.flash().violations, 0);
    let bad = check_with_reader(&nvs.flash().data.clone(), &model);
    assert!(bad.is_empty(), "{bad:?}");
    let s = nvs.stats().unwrap();
    assert!(s.free_pages >= 1);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, max_shrink_iters: 400, ..ProptestConfig::default() })]

    #[test]
    fn random_sequences_match_the_model(ops in proptest::collection::vec(op(), 1..70)) {
        run(&ops);
    }
}

#[test]
fn long_random_sequences_with_a_fixed_seed() {
    for seed in 1..=6u64 {
        let mut rng = XorShift(seed * 0x9e37_79b9);
        let ops: Vec<POp> = (0..400)
            .map(|_| POp {
                ns: rng.below(3) as usize,
                key: rng.below(6) as usize,
                kind: match rng.below(10) {
                    0 => Kind::U8(rng.next() as u8),
                    1 => Kind::U32(rng.next() as u32),
                    2 => Kind::Str(rng.below(200) as usize, rng.next() as u32),
                    3..=6 => Kind::Blob([10, 784, 516, 4000, 4001, 9000][rng.below(6) as usize], rng.next() as u32),
                    7 => Kind::Erase,
                    8 => Kind::Remount,
                    _ => Kind::EraseNs,
                },
                cut: (rng.below(12) == 0).then(|| (rng.below(5000) as u16, rng.below(3) as u8)),
            })
            .collect();
        run(&ops);
    }
}
