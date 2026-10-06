//! Shared test support: dumps of what an engine or an image holds, a model map, an operation type, and the export used by the IDF check.
#![allow(dead_code)]

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
        let ty = match (&val, i.kind) {
            _ => type_name(i.kind),
        };
        out.insert((ns.clone(), key.clone()), (ty.to_string(), val));
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
            (a, b) => diffs.push(format!("{k:?}: got {:?} want {:?}", a.map(|x| (&x.0, x.1.len(), x.1.iter().take(8).collect::<Vec<_>>())), b.map(|x| (&x.0, x.1.len(), x.1.iter().take(8).collect::<Vec<_>>())))),
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
    let out = std::process::Command::new(py)
        .arg(script)
        .arg("--idf")
        .arg(idf)
        .arg(export_dir().join(format!("{name}.bin")))
        .output()
        .expect("run python");
    assert!(out.status.success(), "IDF rejects {name}:\n{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}
