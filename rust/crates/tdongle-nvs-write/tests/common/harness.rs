//! The power-loss harness shared by `power_loss.rs` (this crate's writer cut at every point) and `c_writer.rs` (ESP-IDF's writer cut at
//! every point, this crate's mount on what it leaves).
#![allow(dead_code, unused_imports)]
use super::*;
use tdongle_nvs_format::mode::Mode;
use tdongle_nvs_format::ui_settings::UiSettings;
use tdongle_nvs_format::wifi_meta::MetaSet;
use tdongle_nvs_format::wifi_profiles::{SavedNetworks, SavedProfile};
use tdongle_nvs_read::{Nvs as Reader, SliceFlash};
use tdongle_nvs_write::{Error, Nvs, SimError, SimFlash, Store, Tear};

pub type St = Store<SimFlash>;
pub type Step = Box<dyn Fn(&mut St) -> Result<(), Error<SimError>>>;

pub struct Scenario {
    pub name: &'static str,
    pub base: Vec<u8>,
    pub steps: Vec<Step>,
    /// `(namespace, first, second)`: the two keys are written one after the other (first, then second).
    pub pair: Option<(&'static str, &'static str, &'static str)>,
    pub rerun: bool,
    /// Run the compaction-churn check on every n-th cut (0: never).
    pub churn: u64,
}

pub fn fresh_store() -> St {
    Store::mount(SimFlash::new(SIZE as usize), SIZE).unwrap()
}

pub fn net(i: usize, tag: u8) -> SavedProfile {
    let mut p = SavedProfile::EMPTY;
    let ssid = format!("Net{tag}-{i}");
    let pw = format!("password-{tag}-{i}-{}", "x".repeat(i * 3));
    p.ssid[..ssid.len()].copy_from_slice(ssid.as_bytes());
    p.password[..pw.len()].copy_from_slice(pw.as_bytes());
    p
}

pub fn list(n: usize, tag: u8) -> (SavedNetworks, MetaSet) {
    let mut saved = SavedNetworks::default();
    for i in 0..n {
        saved.profiles[i] = net(i, tag);
    }
    saved.count = n;
    let mut meta = MetaSet::defaults(&saved.ssids()[..n]);
    for (i, s) in meta.slot.iter_mut().enumerate().take(n) {
        s.priority = (30 + 10 * i as u8 + tag) % 101;
    }
    meta.preferred = (n > 1).then_some(1);
    (saved, meta)
}

pub fn save(n: usize, tag: u8) -> Step {
    Box::new(move |s: &mut St| {
        let (l, m) = list(n, tag);
        s.save_profiles(&l, &m)
    })
}

/// A device with a saved list, display, mode and the v0.1.1 blob.
pub fn board() -> St {
    let mut s = fresh_store();
    save(3, 1)(&mut s).unwrap();
    s.save_display(&UiSettings { brightness: 40, rotation: 1, dim_seconds: 120 }).unwrap();
    s.save_mode(Mode::TailnetGateway).unwrap();
    s.nvs().set_blob("adapter", "config", &legacy_blob()).unwrap();
    s.nvs().set_str("tn_settings", "members", "alice,bob").unwrap();
    s.nvs().set_blob("tailnet", "identity", &pattern(300, 1)).unwrap();
    s
}

pub fn legacy_blob() -> Vec<u8> {
    // u32 version 1, 8 x {name[25], ssid[33], pass[65], priority}, preferred, brightness, rotation, pad, dim_seconds, pad (1004 bytes)
    let mut b = 1u32.to_le_bytes().to_vec();
    for i in 0..8 {
        if i < 2 {
            let mut p = vec![0u8; 124];
            p[..4].copy_from_slice(b"Home");
            let ssid = format!("Old{i}");
            p[25..25 + ssid.len()].copy_from_slice(ssid.as_bytes());
            p[58..58 + 6].copy_from_slice(b"oldpw1");
            p[123] = 60 + i as u8;
            b.extend(p);
        } else {
            b.extend([0u8; 124]);
        }
    }
    b.extend([0, 70, 1, 0]);
    b.extend(45u16.to_le_bytes());
    b.extend([0, 0]);
    assert_eq!(b.len(), 1004);
    b
}

/// Run steps on `base` until one of them compacts a page; return the image just before that step (so the sweep covers the compaction).
pub fn base_before_compaction(mut store: St, make: impl Fn(u8) -> Step, probe: Step) -> Vec<u8> {
    for tag in 0..200u8 {
        let image = store.nvs().flash().data.clone();
        let mut trial = Store::mount(SimFlash::from_image(image.clone()), SIZE).unwrap();
        probe(&mut trial).unwrap();
        if trial.nvs().flash().erases > 0 {
            return image;
        }
        make(tag)(&mut store).unwrap();
    }
    panic!("no compaction after 200 saves");
}

pub fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

pub fn keys(states: &[&Dump]) -> Vec<(String, String)> {
    let mut k: Vec<_> = states.iter().flat_map(|d| d.keys().cloned()).collect();
    k.sort();
    k.dedup();
    k
}

pub fn check_value(what: &str, key: &(String, String), got: Option<&(String, Vec<u8>)>, allowed: &[Option<&(String, Vec<u8>)>]) {
    assert!(
        allowed.iter().any(|a| match (a, got) {
            (None, None) => true,
            (Some(a), Some(g)) => a.0 == g.0 && a.1 == g.1,
            _ => false,
        }),
        "{what}: {key:?} is {:?}, expected one of {:?}",
        got.map(|g| (&g.0, g.1.len(), g.1.iter().take(6).collect::<Vec<_>>())),
        allowed.iter().map(|a| a.map(|a| (&a.0, a.1.len(), a.1.iter().take(6).collect::<Vec<_>>()))).collect::<Vec<_>>()
    );
}

/// What the read-only parser reports for `key` of type `ty` ("string" is only checked for presence).
pub fn reader_value(image: &[u8], key: &(String, String), ty: &str, expect_len: usize) -> Result<Option<Vec<u8>>, String> {
    let mut r = Reader::new(SliceFlash(image), image.len() as u32);
    let (ns, k) = (key.0.as_str(), key.1.as_str());
    match ty {
        "blob" => {
            let Some(n) = r.blob_len(ns, k).map_err(|e| format!("{e:?}"))? else { return Ok(None) };
            let mut b = vec![0u8; n.max(expect_len)];
            r.get_blob(ns, k, &mut b).map_err(|e| format!("blob {e:?}"))?;
            b.truncate(n);
            Ok(Some(b))
        }
        "uint8_t" => Ok(r.get_u8(ns, k).map_err(|e| format!("{e:?}"))?.map(|v| vec![v])),
        "string" => Ok(r.has_str(ns, k).map_err(|e| format!("string {e:?}"))?.then(|| vec![1])),
        _ => Ok(None),
    }
}

pub struct Run<'a> {
    pub sc: &'a Scenario,
    pub states: Vec<Dump>,
    pub ends: Vec<u64>,
}

impl Run<'_> {
    pub fn open(&self) -> St {
        Store::mount(SimFlash::from_image(self.sc.base.clone()), SIZE).unwrap()
    }

    pub fn allowed<'d>(&'d self, k: usize, key: &(String, String)) -> Vec<Option<&'d (String, Vec<u8>)>> {
        let mut v = vec![self.states[k].get(key)];
        if k + 1 < self.states.len() {
            v.push(self.states[k + 1].get(key));
        }
        v
    }

    pub fn check_pair(&self, k: usize, d: &Dump, what: &str) {
        let Some((ns, a, b)) = self.sc.pair else { return };
        let get = |s: &Dump, key: &str| s.get(&(ns.to_string(), key.to_string())).cloned();
        let got = (get(d, a), get(d, b));
        let ok = (k..=k + 1).any(|i| i < self.states.len() && (get(&self.states[i], a), get(&self.states[i], b)) == got)
            || (k + 1 < self.states.len() && (get(&self.states[k + 1], a), get(&self.states[k], b)) == got);
        assert!(ok, "{what}: {a} and {b} are in a combination the C does not allow after a cut in step {k}");
    }

    /// Checks 1 and 2 on the crash image; returns the repaired image. A failure says which cut it was.
    pub fn check_image(&self, image: &[u8], k: usize, what: &str) -> Vec<u8> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check_image_inner(image, k, what))) {
            Ok(v) => v,
            Err(e) => {
                let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string())).unwrap_or_default();
                panic!("{what} (step {k}): {msg}")
            }
        }
    }

    fn check_image_inner(&self, image: &[u8], k: usize, what: &str) -> Vec<u8> {
        let all: Vec<&Dump> = self.states.iter().collect();
        let universe = keys(&all);
        // 1. the read-only parser, no repair
        for key in &universe {
            let allowed = self.allowed(k, key);
            let ty = allowed.iter().flatten().next().map_or("", |a| a.0.as_str()).to_string();
            if ty.is_empty() || allowed.iter().flatten().any(|a| a.0 != ty) {
                continue; // absent in both states, or the key changes type in this step (the reader's getters are typed)
            }
            let expect_len = allowed.iter().flatten().map(|a| a.1.len()).max().unwrap_or(0);
            let got = reader_value(image, key, &ty, expect_len).unwrap_or_else(|e| panic!("{what}: reader on {key:?}: {e}"));
            let got = got.map(|v| (ty.clone(), v));
            let ok = allowed.iter().any(|a| match (a, &got) {
                (None, None) => true,
                (Some(a), Some(g)) => a.0 == g.0 && (a.0 == "string" || a.1 == g.1),
                _ => false,
            });
            assert!(ok, "{what}: reader sees {:?} for {key:?} (a cut in step {k})", got.as_ref().map(|g| (&g.0, g.1.len())));
        }
        // 2. the engine's mount
        let mut nvs = Nvs::open(SimFlash::from_image(image.to_vec()), SIZE).unwrap_or_else(|e| panic!("{what}: mount failed: {e:?}"));
        let d = dump_strict(&mut nvs);
        for key in &universe {
            check_value(what, key, d.get(key), &self.allowed(k, key));
        }
        for key in d.keys() {
            assert!(universe.contains(key), "{what}: key {key:?} appeared out of nowhere");
        }
        self.check_pair(k, &d, what);
        assert_eq!(nvs.flash().violations, 0, "{what}: mount tried to set a bit");
        let repaired = nvs.flash().data.clone();
        // the repaired image is what the reader sees too
        let mut want = d.clone();
        want.retain(|_, v| v.0 == "blob" || v.0 == "uint8_t");
        let bad = check_with_reader(&repaired, &want);
        assert!(bad.is_empty(), "{what}: reader on the repaired image: {bad:?}");
        repaired
    }

    /// One cut at budget `n`; returns (crash image, step, died).
    pub fn cut(&self, n: u64, tear: Tear) -> (Vec<u8>, usize, bool) {
        let mut s = self.open();
        s.nvs().flash_mut().arm(n, tear);
        let mut done = 0;
        for step in &self.sc.steps {
            if step(&mut s).is_err() {
                break;
            }
            done += 1;
        }
        let died = s.nvs().flash().is_dead();
        assert_eq!(died, done < self.sc.steps.len(), "a step failed without a power cut");
        assert_eq!(s.nvs().flash().violations, 0, "n={n}: a write tried to set a bit");
        assert_eq!(s.nvs().flash().misaligned, 0);
        (s.nvs().flash().data.clone(), done, died)
    }
}

pub fn prepare(sc: &Scenario) -> Run<'_> {
    let mut s = Store::mount(SimFlash::from_image(sc.base.clone()), SIZE).unwrap();
    let start = s.nvs().flash().spent;
    let mut states = vec![dump(s.nvs())];
    let mut ends = Vec::new();
    for (i, step) in sc.steps.iter().enumerate() {
        step(&mut s).unwrap_or_else(|e| panic!("{}: step {i}: {e:?}", sc.name));
        ends.push(s.nvs().flash().spent - start);
        states.push(dump(s.nvs()));
    }
    assert_eq!(s.nvs().flash().violations, 0);
    Run { sc, states, ends }
}

/// The sweep. `stride` 1 is "every N"; `NVS_SWEEP_STRIDE` overrides it (set it to 1 for the exhaustive run).
pub fn sweep(sc: Scenario, stride: u64) {
    let stride = env_u64("NVS_SWEEP_STRIDE", stride).max(1);
    let run = prepare(&sc);
    let total = *run.ends.last().unwrap();
    let idf_samples = env_u64("NVS_IDF_SAMPLES", 24) as usize;
    let mut sampled = Vec::new();
    let c_samples = env_u64("NVS_C_SAMPLES", 150) as usize;
    let mut c_images: Vec<(String, Vec<u8>, usize)> = Vec::new();
    let mut cuts = 0u64;
    let mut mount_cuts = 0u64;
    let exhaustive = std::env::var_os("NVS_SWEEP_STRIDE").is_some();
    // Every cut point for the clean-prefix model; the two half-programmed models use every third / fourth point (all of them when
    // NVS_SWEEP_STRIDE is set).
    let mount_cut_every = env_u64("NVS_MOUNT_CUT_EVERY", if exhaustive { 1 } else { (total / stride / 40).max(1) });
    for (tear, step) in [(Tear::Prefix, stride), (Tear::Bits(0x1234_5678_9abc_def1), stride * 3), (Tear::Bits(0x0fed_cba9_8765_4321), stride * 4 + 1)] {
        let step = if exhaustive { stride } else { step };
        let mut n = 0;
        while n <= total {
            let (image, done, died) = run.cut(n, tear);
            assert_eq!(died, n < total, "{}: n={n}", sc.name);
            let what = format!("{} n={n}/{total} {tear:?}", sc.name);
            let k = if died { done } else { sc.steps.len() };
            if died && c_images.len() < c_samples && cuts.is_multiple_of(total / stride * 3 / c_samples as u64 + 1) {
                c_images.push((what.clone(), image.clone(), k));
            }
            // when the sequence completed every key has its final value; a cut leaves old or new
            let repaired = if died { run.check_image(&image, k, &what) } else { run.check_image(&image, k.saturating_sub(1), &what) };
            // 3. still a working partition
            let mut again = Store::mount(SimFlash::from_image(repaired.clone()), SIZE).unwrap();
            if sc.churn > 0 && cuts.is_multiple_of(sc.churn) {
                // Compaction moves pages around: an item that mount left behind in a stale page (a duplicate) would change places with
                // the live one and come back. The content must not change under churn.
                let want = dump(again.nvs());
                for i in 0..60 {
                    again.nvs().set_blob("scratch", "churn", &pattern(1000, i)).unwrap_or_else(|e| panic!("{what}: churn {e:?}"));
                }
                again.nvs().erase_key("scratch", "churn").unwrap();
                assert!(again.nvs().flash().erases > 0, "churn must compact");
                assert_same(&format!("{what}: after compaction churn"), &dump(again.nvs()), &want);
                again = Store::mount(SimFlash::from_image(repaired.clone()), SIZE).unwrap();
            }
            if sc.rerun {
                for (i, step) in sc.steps.iter().enumerate() {
                    step(&mut again).unwrap_or_else(|e| panic!("{what}: rerun step {i}: {e:?}"));
                }
                assert_same(&format!("{what}: after running the sequence again"), &dump(again.nvs()), run.states.last().unwrap());
                assert_eq!(again.nvs().flash().violations, 0);
            }
            cuts += 1;
            // 4. a cut during the mounting repair
            let mut probe = Nvs::new(SimFlash::from_image(image.clone()), SIZE);
            probe.mount().unwrap();
            let repair_cost = probe.flash().spent;
            if repair_cost > 0 && cuts.is_multiple_of(mount_cut_every) {
                let mut m = 0;
                while m <= repair_cost + 1 {
                    let mut f = SimFlash::from_image(image.clone());
                    f.arm(m, tear);
                    let mut nvs = Nvs::new(f, SIZE);
                    let r = nvs.mount();
                    let img2 = nvs.flash().data.clone();
                    assert_eq!(r.is_err(), nvs.flash().is_dead());
                    assert_eq!(nvs.flash().violations, 0);
                    run.check_image(&img2, k.min(sc.steps.len() - if died { 0 } else { 1 }), &format!("{what} mount-cut m={m}"));
                    mount_cuts += 1;
                    m += if exhaustive || m < 64 { 1 } else { 29 };
                }
            }
            if sampled.len() < idf_samples && cuts.is_multiple_of(total / stride / idf_samples as u64 + 1) {
                let mut nvs = Nvs::open(SimFlash::from_image(repaired), SIZE).unwrap();
                nvs.scrub().unwrap();
                let d = dump(&mut nvs);
                sampled.push((format!("pl_{}_{n}", sc.name), nvs.flash().data.clone(), d));
            }
            n += step;
        }
    }
    eprintln!("{}: {} cuts, {} cuts during mounting, total cost {} units", sc.name, cuts, mount_cuts, total);
    // 6. ESP-IDF's own C++ NVS engine, compiled for the host, mounts the raw crash images (with all its repairs), resolves each key to the
    //    old or the new value, and can write and compact on them
    let mut hazards = 0;
    for chunk in c_images.chunks(60) {
        let imgs: Vec<Vec<u8>> = chunk.iter().map(|c| c.1.clone()).collect();
        let Some(runs) = idf_c_run(&imgs, true) else { break };
        for ((what, img, k), r) in chunk.iter().zip(&runs) {
            assert_eq!(r.mount, 0, "{what}: ESP-IDF's mount fails: {}", r.mount);
            assert!(r.errors.is_empty(), "{what}: {:?}", r.errors);
            assert_eq!(r.violations, 0, "{what}");
            let universe = keys(&run.states.iter().collect::<Vec<_>>());
            let hazard = idf_hazard(img);
            for key in &universe {
                let mut allowed = run.allowed(*k, key);
                if hazard.contains(key) {
                    allowed.push(None); // ESP-IDF's own mount loses this key here, see `idf_hazard`
                    hazards += 1;
                }
                check_value(&format!("{what}: ESP-IDF resolves"), key, r.rows.get(key), &allowed);
            }
            for key in r.rows.keys() {
                assert!(universe.contains(key), "{what}: ESP-IDF sees {key:?} out of nowhere");
            }
            if hazard.is_empty() {
                run.check_pair(*k, &r.rows, &format!("{what}: ESP-IDF"));
            }
            assert_eq!(r.churn, Some(0), "{what}: ESP-IDF cannot write to the crash image");
            assert_same(&format!("{what}: ESP-IDF after writing and compacting"), r.after_churn.as_ref().unwrap(), &r.rows);
        }
    }
    eprintln!("{}: {} crash images checked with ESP-IDF's C++ engine ({hazards} keys in its own last-chunk hazard)", sc.name, c_images.len());
    // 5. IDF accepts the repaired images
    for (name, image, d) in sampled {
        verify_with_idf(&name, &image, &d, true);
    }
}
