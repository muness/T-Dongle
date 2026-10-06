//! Shared test support: dumps of what an engine or an image holds, a model map, an operation type, and the export used by the IDF check.
#![allow(dead_code)]

pub mod harness;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tdongle_nvs_read::{Nvs as Reader, SliceFlash};
use tdongle_nvs_write::{Cursor, Flash, Kind, Nvs, SimFlash};

pub const SIZE: u32 = 0x10000;

/// `(namespace, key) -> (IDF type name, bytes)`; strings include their NUL, as in IDF's own dump.
pub type Dump = BTreeMap<(String, String), (String, Vec<u8>)>;

pub fn type_name(kind: Kind) -> &'static str {
    match kind {
        Kind::U8 => "uint8_t",
        Kind::I8 => "int8_t",
        Kind::U16 => "uint16_t",
        Kind::I16 => "int16_t",
        Kind::U32 => "uint32_t",
        Kind::I32 => "int32_t",
        Kind::U64 => "uint64_t",
        Kind::I64 => "int64_t",
        Kind::Str => "string",
        Kind::Blob => "blob",
    }
}

fn kind_width(k: Kind) -> usize {
    match k {
        Kind::U8 | Kind::I8 => 1,
        Kind::U16 | Kind::I16 => 2,
        Kind::U32 | Kind::I32 => 4,
        _ => 8,
    }
}

fn name(b: &[u8; 16]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(16);
    String::from_utf8_lossy(&b[..n]).into_owned()
}

/// Everything the engine holds (namespace table excluded), read through the engine's own getters.
pub fn dump<F: Flash>(nvs: &mut Nvs<F>) -> Dump {
    dump_impl(nvs, false)
}

/// As [`dump`], and a key that is stored twice (a stale version left behind) is an error: a mounted partition must be canonical.
pub fn dump_strict<F: Flash>(nvs: &mut Nvs<F>) -> Dump {
    dump_impl(nvs, true)
}

fn dump_impl<F: Flash>(nvs: &mut Nvs<F>, strict: bool) -> Dump {
    let mut out = Dump::new();
    let mut cur = Cursor::default();
    let mut items = Vec::new();
    while let Some(i) = nvs.next_item(&mut cur).unwrap() {
        items.push(i);
    }
    for i in items {
        if i.namespace == 0 {
            continue;
        }
        let ns = name(&nvs.namespace_name(i.namespace).unwrap().expect("namespace of an item"));
        let key = name(&i.key);
        // An image can hold several versions of a key (the generator's "overwrite" fixtures): the newest is what every reader returns, and
        // it is what the getters return, so values are read through them and a repeated key just reads the same value again.
        let val = match i.kind {
            Kind::Blob => {
                let n = nvs.value_len(&ns, &key).unwrap().unwrap();
                let mut b = vec![0u8; n];
                assert_eq!(nvs.get_blob(&ns, &key, &mut b).unwrap(), Some(n), "{ns}/{key}");
                b
            }
            Kind::Str => {
                let n = nvs.value_len(&ns, &key).unwrap().unwrap() + 1;
                let mut b = vec![0u8; n];
                assert_eq!(nvs.get_str(&ns, &key, &mut b).unwrap(), Some(n - 1), "{ns}/{key}");
                b
            }
            k => {
                let (kind, raw) = nvs.get_raw(&ns, &key).unwrap().unwrap();
                let _ = k;
                raw[..i.size.min(kind_width(kind))].to_vec()
            }
        };
        let ty = type_name(i.kind);
        let prev = out.insert((ns.clone(), key.clone()), (ty.to_string(), val));
        assert!(!strict || prev.is_none(), "{ns}/{key} is stored twice after mount");
    }
    out
}

/// The same dump of a raw image through the engine (mounting repairs a copy, the original is untouched).
pub fn dump_image(image: &[u8]) -> Dump {
    let mut nvs = Nvs::open(SimFlash::from_image(image.to_vec()), image.len() as u32).expect("mount");
    dump(&mut nvs)
}

/// Check every key of `want` with the read-only parser. Returns the differences.
pub fn check_with_reader(image: &[u8], want: &Dump) -> Vec<String> {
    let mut r = Reader::new(SliceFlash(image), image.len() as u32);
    let mut bad = Vec::new();
    for ((ns, key), (ty, val)) in want {
        match ty.as_str() {
            "blob" => {
                let mut b = vec![0u8; val.len()];
                match r.get_blob(ns, key, &mut b) {
                    Ok(Some(n)) if n == val.len() && b == *val => {}
                    other => bad.push(format!("reader {ns}/{key}: {other:?}")),
                }
            }
            "string" => match r.has_str(ns, key) {
                Ok(true) => {}
                other => bad.push(format!("reader {ns}/{key}: {other:?}")),
            },
            "uint8_t" => match r.get_u8(ns, key) {
                Ok(Some(v)) if val == &[v] => {}
                other => bad.push(format!("reader {ns}/{key}: {other:?}")),
            },
            _ => {}
        }
    }
    bad
}

/// Compare, then explain.
pub fn assert_same(what: &str, got: &Dump, want: &Dump) {
    let mut diffs = Vec::new();
    for k in got.keys().chain(want.keys()) {
        match (got.get(k), want.get(k)) {
            (Some(a), Some(b)) if a == b => {}
            (a, b) => diffs.push(format!(
                "{k:?}: got {:?} want {:?}",
                a.map(|x| (&x.0, x.1.len(), x.1.iter().take(8).collect::<Vec<_>>())),
                b.map(|x| (&x.0, x.1.len(), x.1.iter().take(8).collect::<Vec<_>>()))
            )),
        }
    }
    diffs.dedup();
    assert!(diffs.is_empty(), "{what}: {}", diffs.join("\n"));
}

pub fn tsv(d: &Dump) -> String {
    let mut s = String::new();
    for ((ns, key), (ty, val)) in d {
        let hex: String = val.iter().map(|b| format!("{b:02x}")).collect();
        s.push_str(&format!("{ns}\t{key}\t{ty}\t{}\t{hex}\n", val.len()));
    }
    s
}

/// Parse an `.expected` file of `tdongle-nvs-read/tests/fixtures` (`ns key type len offset hex`).
pub fn parse_expected(text: &str) -> Dump {
    let mut d = Dump::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        let ty = if f[2] == "blob_index" { "blob" } else { f[2] };
        let val: Vec<u8> = (0..f[5].len() / 2).map(|i| u8::from_str_radix(&f[5][2 * i..2 * i + 2], 16).unwrap()).collect();
        d.insert((f[0].to_string(), f[1].to_string()), (ty.to_string(), val));
    }
    d
}

pub fn pattern(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761).wrapping_add(1);
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
            (x >> 16) as u8
        })
        .collect()
}

pub struct XorShift(pub u64);

impl XorShift {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// One mutation, applied to both an engine and a model.
#[derive(Clone, Debug)]
pub enum Op {
    U8(&'static str, &'static str, u8),
    U32(&'static str, &'static str, u32),
    I32(&'static str, &'static str, i32),
    Str(&'static str, &'static str, String),
    Blob(&'static str, &'static str, Vec<u8>),
    Erase(&'static str, &'static str),
    EraseNs(&'static str),
}

pub fn apply_model(m: &mut Dump, op: &Op) {
    match op {
        Op::U8(ns, k, v) => {
            m.insert((ns.to_string(), k.to_string()), ("uint8_t".into(), vec![*v]));
        }
        Op::U32(ns, k, v) => {
            m.insert((ns.to_string(), k.to_string()), ("uint32_t".into(), v.to_le_bytes().to_vec()));
        }
        Op::I32(ns, k, v) => {
            m.insert((ns.to_string(), k.to_string()), ("int32_t".into(), v.to_le_bytes().to_vec()));
        }
        Op::Str(ns, k, v) => {
            let mut b = v.clone().into_bytes();
            b.push(0);
            m.insert((ns.to_string(), k.to_string()), ("string".into(), b));
        }
        Op::Blob(ns, k, v) => {
            m.insert((ns.to_string(), k.to_string()), ("blob".into(), v.clone()));
        }
        Op::Erase(ns, k) => {
            m.remove(&(ns.to_string(), k.to_string()));
        }
        Op::EraseNs(ns) => m.retain(|(n, _), _| n != ns),
    }
}

pub fn apply<F: Flash>(nvs: &mut Nvs<F>, op: &Op) -> Result<(), tdongle_nvs_write::Error<F::Error>> {
    match op {
        Op::U8(ns, k, v) => nvs.set_u8(ns, k, *v),
        Op::U32(ns, k, v) => nvs.set_u32(ns, k, *v),
        Op::I32(ns, k, v) => nvs.set_i32(ns, k, *v),
        Op::Str(ns, k, v) => nvs.set_str(ns, k, v),
        Op::Blob(ns, k, v) => nvs.set_blob(ns, k, v),
        Op::Erase(ns, k) => match nvs.erase_key(ns, k) {
            Err(tdongle_nvs_write::Error::NotFound) => Ok(()),
            r => r,
        },
        Op::EraseNs(ns) => nvs.erase_namespace(ns),
    }
}

/// Where `export` writes: `$NVS_EXPORT_DIR`, else a directory under the test binary's target dir.
pub fn export_dir() -> PathBuf {
    let dir = std::env::var_os("NVS_EXPORT_DIR").map_or_else(|| Path::new(env!("CARGO_TARGET_TMPDIR")).join("nvs-export"), PathBuf::from);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write `name.bin` and `name.tsv` (and `name.nocheck` when the image is not expected to pass IDF's integrity checker).
pub fn export(name: &str, image: &[u8], d: &Dump, integrity: bool) {
    let dir = export_dir();
    std::fs::write(dir.join(format!("{name}.bin")), image).unwrap();
    std::fs::write(dir.join(format!("{name}.tsv")), tsv(d)).unwrap();
    let nocheck = dir.join(format!("{name}.nocheck"));
    if integrity {
        let _ = std::fs::remove_file(nocheck);
    } else {
        std::fs::write(nocheck, b"").unwrap();
    }
}

/// IDF's python and checkout, when available. `TDONGLE_REQUIRE_IDF=1` turns "not available" into a failure.
pub fn idf_python() -> Option<(PathBuf, PathBuf)> {
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let py = std::env::var_os("TDONGLE_IDF_PYTHON").map_or_else(|| home.join(".espressif/python_env/idf5.5_py3.12_env/bin/python"), PathBuf::from);
    let idf = std::env::var_os("IDF_PATH").map_or_else(|| home.join(".cache/tdongle/esp-idf-v5.5.5"), PathBuf::from);
    if py.exists() && idf.join("components/nvs_flash/nvs_partition_tool/nvs_parser.py").exists() {
        Some((py, idf))
    } else {
        assert!(std::env::var_os("TDONGLE_REQUIRE_IDF").is_none(), "TDONGLE_REQUIRE_IDF is set but IDF's python or checkout is missing");
        eprintln!("SKIPPED: ESP-IDF python/checkout not found (set TDONGLE_IDF_PYTHON and IDF_PATH)");
        None
    }
}

/// Export `name` and run `tools/verify_with_idf.py` on it; panics with IDF's complaints.
pub fn verify_with_idf(name: &str, image: &[u8], d: &Dump, integrity: bool) {
    export(name, image, d, integrity);
    let Some((py, idf)) = idf_python() else { return };
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/verify_with_idf.py");
    let out = std::process::Command::new(py).arg(script).arg("--idf").arg(idf).arg(export_dir().join(format!("{name}.bin"))).output().expect("run python");
    assert!(out.status.success(), "IDF rejects {name}:\n{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert_idf_c_agrees(name, image, d);
}

// ---- ESP-IDF's own C++ NVS engine, compiled for the host (tools/idf_c_check) --------------------------------------------------------

/// What `idf_c_check` reports for one image.
#[derive(Debug)]
pub struct CRun {
    /// `esp_err_t` of `Storage::init`, i.e. IDF's mount with all its repairs (0 = ESP_OK).
    pub mount: i32,
    /// The keys IDF resolves and their values.
    pub rows: Dump,
    /// Rows that IDF could not read (`READERR` / `ROWERR`).
    pub errors: Vec<String>,
    /// Result of IDF writing 60 blobs and erasing them on this image (0 = OK); `None` if not asked.
    pub churn: Option<i32>,
    /// The rows after that churn (the scratch namespace excluded).
    pub after_churn: Option<Dump>,
    /// Writes that tried to set a bit.
    pub violations: u32,
}

fn c_check_binary() -> Option<PathBuf> {
    static BIN: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let (_, idf) = idf_python()?;
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/idf_c_check");
        let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("idf_c_check");
        let newest_src =
            ["main.cpp", "build.sh", "stubs/esp_log.h"].iter().filter_map(|f| std::fs::metadata(dir.join(f)).and_then(|m| m.modified()).ok()).max();
        let fresh = std::fs::metadata(&out).and_then(|m| m.modified()).ok().zip(newest_src).is_some_and(|(b, s)| b > s);
        if !fresh {
            let tmp = out.with_extension(format!("tmp{}", std::process::id()));
            let ok = std::process::Command::new("sh").arg(dir.join("build.sh")).arg(&tmp).env("IDF_PATH", idf).status().is_ok_and(|s| s.success());
            if !ok {
                assert!(std::env::var_os("TDONGLE_REQUIRE_IDF").is_none(), "cannot build tools/idf_c_check (needs a C++17 compiler as `c++`)");
                eprintln!("SKIPPED: cannot build tools/idf_c_check");
                return None;
            }
            std::fs::rename(&tmp, &out).unwrap();
        }
        Some(out)
    })
    .clone()
}

/// Run ESP-IDF's C++ NVS on each image (in one process); `None` when it cannot be built here.
pub fn idf_c_run(images: &[Vec<u8>], churn: bool) -> Option<Vec<CRun>> {
    let bin = c_check_binary()?;
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = export_dir().join(format!("c_run_{}_{}", std::process::id(), COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cmd = std::process::Command::new(bin);
    if churn {
        cmd.arg("--churn");
    }
    for (i, img) in images.iter().enumerate() {
        let p = dir.join(format!("{i:06}.bin"));
        std::fs::write(&p, img).unwrap();
        cmd.arg(p);
    }
    let out = cmd.output().expect("run idf_c_check");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "idf_c_check crashed: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    let mut runs: Vec<CRun> = Vec::new();
    let mut after = false;
    for line in text.lines() {
        if line.starts_with("== ") {
            runs.push(CRun { mount: -1, rows: Dump::new(), errors: vec![], churn: None, after_churn: None, violations: 0 });
            after = false;
        } else if let Some(rc) = line.strip_prefix("MOUNT ") {
            runs.last_mut().unwrap().mount = rc.parse().unwrap_or(-2);
        } else if let Some(rc) = line.strip_prefix("CHURN ") {
            runs.last_mut().unwrap().churn = Some(rc.parse().unwrap());
        } else if line == "AFTER_CHURN" {
            after = true;
            runs.last_mut().unwrap().after_churn = Some(Dump::new());
        } else if let Some(n) = line.strip_prefix("VIOLATION ") {
            runs.last_mut().unwrap().violations = n.parse().unwrap();
        } else if line.starts_with("ROWERR") || line.contains("\tREADERR\t") {
            runs.last_mut().unwrap().errors.push(line.to_string());
        } else {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 5, "bad idf_c_check line {line:?}");
            let val: Vec<u8> = (0..f[4].len() / 2).map(|i| u8::from_str_radix(&f[4][2 * i..2 * i + 2], 16).unwrap()).collect();
            let r = runs.last_mut().unwrap();
            let target = if after { r.after_churn.as_mut().unwrap() } else { &mut r.rows };
            target.insert((f[0].to_string(), f[1].to_string()), (f[2].to_string(), val));
        }
    }
    assert_eq!(runs.len(), images.len());
    Some(runs)
}

/// IDF's C++ engine mounts `image`, resolves exactly the keys of `want`, and keeps working (writes, compacts) on it.
pub fn assert_idf_c_agrees(what: &str, image: &[u8], want: &Dump) {
    let Some(runs) = idf_c_run(&[image.to_vec()], true) else { return };
    let r = &runs[0];
    assert_eq!(r.mount, 0, "{what}: ESP-IDF's mount fails with {}", r.mount);
    assert!(r.errors.is_empty(), "{what}: {:?}", r.errors);
    assert_same(&format!("{what}: ESP-IDF's C++ engine"), &r.rows, want);
    assert_eq!(r.churn, Some(0), "{what}: ESP-IDF cannot write to the image");
    assert_same(&format!("{what}: ESP-IDF after writing and compacting"), r.after_churn.as_ref().unwrap(), want);
    assert_eq!(r.violations, 0, "{what}: ESP-IDF tried to set a bit");
}

/// Keys for which ESP-IDF's own mount destroys the stored value when the power went out between the last chunk of a blob write and its index.
///
/// `Page::mLoadEntryTable` ends with "check that last item is not duplicate": it looks the *last* item of the active page up again with
/// `findItem(ns, type, key)`, and for a `BLOB_DATA` chunk that call has no chunk index, so it returns the page's *first* chunk of that key
/// and erases it if it is earlier than the last item. When the previous version's chunk sits on the same page as the new chunk, that
/// erases the previous version's chunk (the index then fails its size check and ESP-IDF erases it too, and the new chunk is an orphan):
/// the key is gone. It needs a cut in the window after a chunk is complete and before the index entry is, in ESP-IDF's own `nvs_set_blob`
/// as in this crate's (same order); this crate's own mount does not have the problem. Returns the `(namespace, key)` pairs at risk in `image`.
pub fn idf_hazard(image: &[u8]) -> Vec<(String, String)> {
    const PAGE: usize = 4096;
    let mut best: Option<(u32, usize)> = None;
    for p in 0..image.len() / PAGE {
        let h = &image[p * PAGE..p * PAGE + 32];
        let state = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
        let crc_ok = tdongle_nvs_write::crc32(0xffff_ffff, &h[4..28]) == u32::from_le_bytes([h[28], h[29], h[30], h[31]]);
        if crc_ok && matches!(state, 0xffff_fffe | 0xffff_fffc | 0xffff_fff8) {
            let seq = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
            if best.is_none_or(|(s, _)| seq >= s) {
                best = Some((seq, p));
            }
        }
    }
    let Some((_, p)) = best else { return vec![] };
    let page = &image[p * PAGE..(p + 1) * PAGE];
    if u32::from_le_bytes([page[0], page[1], page[2], page[3]]) != 0xffff_fffe {
        return vec![]; // only an active page gets the check
    }
    let st = |i: usize| (page[32 + i / 4] >> ((i % 4) * 2)) & 3;
    let entry = |i: usize| &page[64 + i * 32..64 + (i + 1) * 32];
    let crc_ok =
        |e: &[u8]| tdongle_nvs_write::crc32(tdongle_nvs_write::crc32(0xffff_ffff, &e[0..4]), &e[8..32]) == u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
    let mut last: Option<usize> = None;
    let mut first_chunk: Vec<(u8, [u8; 16], usize)> = Vec::new();
    let mut i = 0;
    while i < 126 {
        if st(i) != 2 {
            i += 1;
            continue;
        }
        let e = entry(i);
        if !crc_ok(e) {
            i += 1;
            continue;
        }
        let span = if matches!(e[1], 0x21 | 0x41 | 0x42) { usize::from(e[2]).max(1) } else { 1 };
        let complete = i + span <= 126 && (i..i + span).all(|j| st(j) == 2);
        if !complete {
            // an incomplete variable-length item is erased by the mount and disables the check
            last = None;
            i += span;
            continue;
        }
        last = Some(i);
        if e[1] == 0x42 {
            let mut k = [0u8; 16];
            k.copy_from_slice(&e[8..24]);
            if !first_chunk.iter().any(|c| c.0 == e[0] && c.1 == k) {
                first_chunk.push((e[0], k, i));
            }
        }
        i += span;
    }
    let Some(l) = last else { return vec![] };
    let e = entry(l);
    if e[1] != 0x42 {
        return vec![];
    }
    let mut k = [0u8; 16];
    k.copy_from_slice(&e[8..24]);
    let earlier = first_chunk.iter().any(|c| c.0 == e[0] && c.1 == k && c.2 < l);
    if !earlier {
        return vec![];
    }
    // namespace name of e[0]
    for (ns_entry, _) in (0..image.len() / PAGE).flat_map(|pg| (0..126).map(move |i| (&image[pg * PAGE + 64 + i * 32..pg * PAGE + 96 + i * 32], pg * PAGE + i)))
    {
        if ns_entry[0] == 0 && ns_entry[1] == 0x01 && ns_entry[24] == e[0] {
            let name = String::from_utf8_lossy(&ns_entry[8..24]).trim_end_matches('\0').to_string();
            let key = String::from_utf8_lossy(&k).trim_end_matches('\0').to_string();
            return vec![(name, key)];
        }
    }
    vec![]
}
