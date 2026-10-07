//! Tests against real images made by ESP-IDF's `nvs_partition_gen.py`, with expected values read back by ESP-IDF's own `nvs_parser.py`
//! (`tools/gen_fixtures.py`).

use tdongle_nvs_format::wifi_profiles::SavedNetworks;
use tdongle_nvs_read::{Error, Flash, Nvs, OutOfRange, SliceFlash};

const MAIN_V2: &[u8] = include_bytes!("fixtures/main_v2.bin");
const MAIN_V1: &[u8] = include_bytes!("fixtures/main_v1.bin");
const BIG_V2: &[u8] = include_bytes!("fixtures/big_v2.bin");
const SIZE: u32 = 0x10000;

const FIXTURES: &[(&str, &[u8], &str)] = &[
    ("main_v2", MAIN_V2, include_str!("fixtures/main_v2.expected")),
    ("main_v1", MAIN_V1, include_str!("fixtures/main_v1.expected")),
    ("prims", include_bytes!("fixtures/prims.bin"), include_str!("fixtures/prims.expected")),
    ("big_v2", BIG_V2, include_str!("fixtures/big_v2.expected")),
    ("many_v2", include_bytes!("fixtures/many_v2.bin"), include_str!("fixtures/many_v2.expected")),
    ("overwrite_v2", include_bytes!("fixtures/overwrite_v2.bin"), include_str!("fixtures/overwrite_v2.expected")),
    ("overwrite_v1", include_bytes!("fixtures/overwrite_v1.bin"), include_str!("fixtures/overwrite_v1.expected")),
    ("board_v01", include_bytes!("fixtures/board_v01.bin"), include_str!("fixtures/board_v01.expected")),
    ("board_v03", include_bytes!("fixtures/board_v03.bin"), include_str!("fixtures/board_v03.expected")),
    ("tiny_v2", include_bytes!("fixtures/tiny_v2.bin"), include_str!("fixtures/tiny_v2.expected")),
];

struct Expect {
    ns: &'static str,
    key: &'static str,
    ty: &'static str,
    len: usize,
    offset: usize,
    data: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn expected(text: &'static str) -> Vec<Expect> {
    text.lines()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Expect { ns: f[0], key: f[1], ty: f[2], len: f[3].parse().unwrap(), offset: f[4].parse().unwrap(), data: unhex(f[5]) }
        })
        .collect()
}

fn nvs(img: &[u8]) -> Nvs<SliceFlash<'_>> {
    Nvs::new(SliceFlash(img), img.len() as u32)
}

fn blob(n: &mut Nvs<SliceFlash<'_>>, ns: &str, key: &str) -> Option<Vec<u8>> {
    let len = n.blob_len(ns, key).unwrap()?;
    let mut out = vec![0u8; len];
    assert_eq!(n.get_blob(ns, key, &mut out).unwrap(), Some(len));
    Some(out)
}

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

/// Rewrite an item header's CRC after a deliberate edit.
fn fix_item_crc(img: &mut [u8], at: usize) {
    let c = crc32(&img[at + 8..at + 32], crc32(&img[at..at + 4], 0xffff_ffff));
    img[at + 4..at + 8].copy_from_slice(&c.to_le_bytes());
}

fn fix_page_crc(img: &mut [u8], page: usize) {
    let at = page * 4096;
    let c = crc32(&img[at + 4..at + 28], 0xffff_ffff);
    img[at + 28..at + 32].copy_from_slice(&c.to_le_bytes());
}

#[test]
fn every_item_matches_what_idf_parser_reads() {
    for (name, img, text) in FIXTURES {
        let mut n = nvs(img);
        // Miri is ~1000x slower: spot-check the big corpus there.
        for e in expected(text).into_iter().take(if cfg!(miri) { 4 } else { usize::MAX }) {
            // IDF's offset of the item header is where our key must be.
            assert!(img[e.offset + 8..].starts_with(e.key.as_bytes()), "{name} {}/{}", e.ns, e.key);
            match e.ty {
                "uint8_t" => assert_eq!(n.get_u8(e.ns, e.key).unwrap(), Some(e.data[0]), "{name} {}/{}", e.ns, e.key),
                "string" => assert!(n.has_str(e.ns, e.key).unwrap(), "{name} {}/{}", e.ns, e.key),
                "blob" | "blob_index" => {
                    assert_eq!(n.blob_len(e.ns, e.key).unwrap(), Some(e.len), "{name} {}/{}", e.ns, e.key);
                    assert_eq!(blob(&mut n, e.ns, e.key).unwrap(), e.data, "{name} {}/{}", e.ns, e.key);
                }
                // Other primitive types have no getter; they must at least be found and refuse to be read as something else.
                _ => assert_eq!(n.get_u8(e.ns, e.key), Err(Error::TypeMismatch), "{name} {}/{}", e.ns, e.key),
            }
        }
    }
}

#[test]
fn c_firmware_layout() {
    for img in [MAIN_V2, MAIN_V1] {
        let mut n = nvs(img);
        assert_eq!(n.get_u8("tn_settings", "mode").unwrap(), Some(2));
        assert!(n.has_str("tn_settings", "members").unwrap());
        assert_eq!(n.blob_len("tn_settings", "wifi_profiles").unwrap(), Some(784));
        assert_eq!(n.blob_len("tn_settings", "wifi_meta").unwrap(), Some(516));
        assert_eq!(n.blob_len("tn_settings", "display").unwrap(), Some(8));
        assert_eq!(n.blob_len("adapter", "config").unwrap(), Some(1004));
        assert_eq!(n.get_u8("tn_settings", "nope").unwrap(), None);
        assert_eq!(n.get_u8("nope", "mode").unwrap(), None);
        assert_eq!(n.blob_len("adapter", "wifi_profiles").unwrap(), None);
        assert!(!n.has_str("tn_settings", "nope").unwrap());
    }
    // v1 images use plain BLOB items, v2 images BLOB_IDX + BLOB_DATA.
    assert_eq!(MAIN_V1[8], 0xff);
    assert_eq!(MAIN_V2[8], 0xfe);
}

#[test]
fn golden_wifi_profiles_blob_decodes() {
    for img in [MAIN_V2, MAIN_V1] {
        let mut n = nvs(img);
        let bytes = blob(&mut n, "tn_settings", "wifi_profiles").unwrap();
        let nets = SavedNetworks::from_bytes(&bytes).unwrap();
        assert_eq!(nets.list().len(), 3);
        assert_eq!(nets.list()[0].ssid_bytes(), b"HomeNet");
        assert_eq!(nets.list()[0].password_bytes(), b"hunter2hunter2");
        assert_eq!(nets.list()[1].ssid_bytes(), b"Cafe Wi-Fi");
        assert_eq!(nets.list()[2].ssid_bytes(), &[b'x'; 32]);
        assert_eq!(nets.to_bytes()[..], bytes[..]);
    }
}

#[test]
fn chunked_blobs_span_pages() {
    let mut n = nvs(BIG_V2);
    // 8000 bytes cannot fit one page, so its chunks are on two pages; page 1 and 2 are in use.
    assert_ne!(BIG_V2[4096..4100], [0xff; 4]);
    assert_ne!(BIG_V2[8192..8196], [0xff; 4]);
    for (key, len) in [("blob4000", 4000), ("blob6000", 6000), ("blob8000", 8000), ("small", 3)] {
        assert_eq!(blob(&mut n, "big", key).unwrap().len(), len);
    }
}

#[test]
fn too_small_buffers() {
    let mut n = nvs(BIG_V2);
    let mut out = [0u8; 5999];
    assert_eq!(n.get_blob("big", "blob6000", &mut out), Err(Error::TooSmall));
    let mut out = [0u8; 6000];
    assert_eq!(n.get_blob("big", "blob6000", &mut out), Ok(Some(6000)));
    let mut out = [0u8; 9000];
    assert_eq!(n.get_blob("big", "blob6000", &mut out), Ok(Some(6000)));
    let mut n1 = nvs(MAIN_V1);
    assert_eq!(n1.get_blob("tn_settings", "display", &mut [0u8; 7]), Err(Error::TooSmall));
    assert_eq!(n1.get_blob("tn_settings", "display", &mut [0u8; 8]), Ok(Some(8)));
    assert_eq!(n1.get_blob("tn_settings", "none", &mut []), Ok(None));
}

#[test]
fn type_mismatch_and_key_limits() {
    let mut n = nvs(MAIN_V2);
    assert_eq!(n.get_u8("tn_settings", "members"), Err(Error::TypeMismatch));
    assert_eq!(n.blob_len("tn_settings", "mode"), Err(Error::TypeMismatch));
    assert_eq!(n.get_blob("tn_settings", "mode", &mut [0; 8]), Err(Error::TypeMismatch));
    assert_eq!(n.has_str("tn_settings", "mode"), Err(Error::TypeMismatch));
    assert_eq!(n.get_u8("tn_settings", "wifi_profiles"), Err(Error::TypeMismatch));
    assert_eq!(n.get_u8("tn_settings", "a_key_of_16_char"), Ok(None));
    assert_eq!(n.get_u8("tn_settings", ""), Ok(None));
    assert_eq!(n.get_u8("", "mode"), Ok(None));
    assert_eq!(n.get_u8("a_namespace_of_16", "mode"), Ok(None));
    let mut p = nvs(include_bytes!("fixtures/prims.bin"));
    assert_eq!(p.get_u8("prims", "k_exactly_15ch"), Ok(Some(15)));
    assert_eq!(p.get_u8("prims", "u8"), Ok(Some(255)));
}

#[test]
fn newest_item_wins() {
    let mut n = nvs(include_bytes!("fixtures/overwrite_v2.bin"));
    assert_eq!(n.get_u8("tn_settings", "mode").unwrap(), Some(3));
    assert_eq!(n.get_u8("other", "mode").unwrap(), Some(9));
    assert_eq!(n.blob_len("tn_settings", "big").unwrap(), Some(5000));
    assert_eq!(blob(&mut n, "tn_settings", "wifi_profiles").unwrap().len(), 784);
    let mut n = nvs(include_bytes!("fixtures/overwrite_v1.bin"));
    assert_eq!(n.get_u8("tn_settings", "mode").unwrap(), Some(3));
}

/// A copy of page 0 of the main image, with `mode` changed to `value`, placed at physical page `at` with sequence number `seq`.
fn page_copy_with_mode(img: &mut [u8], at: usize, seq: u32, value: u8) {
    let page: Vec<u8> = MAIN_V2[..4096].to_vec();
    img[at * 4096..(at + 1) * 4096].copy_from_slice(&page);
    img[at * 4096 + 4..at * 4096 + 8].copy_from_slice(&seq.to_le_bytes());
    fix_page_crc(img, at);
    let item = at * 4096 + 96; // entry 1: mode
    img[item + 24] = value;
    fix_item_crc(img, item);
}

#[test]
fn page_sequence_beats_physical_order() {
    // Old copy (seq 0, mode 2) on page 0; newer copies elsewhere with mode 9.
    for at in [1usize, 5, 15] {
        let mut img = MAIN_V2.to_vec();
        page_copy_with_mode(&mut img, at, 7, 9);
        assert_eq!(nvs(&img).get_u8("tn_settings", "mode"), Ok(Some(9)), "newer page at {at}");
    }
    // The older sequence number sits on the higher physical page: still the lower sequence number loses.
    let mut img = vec![0xffu8; 65536];
    page_copy_with_mode(&mut img, 0, 7, 9);
    page_copy_with_mode(&mut img, 4, 2, 5);
    assert_eq!(nvs(&img).get_u8("tn_settings", "mode"), Ok(Some(9)));
    // Equal sequence numbers (not produced by IDF) resolve to the higher page, deterministically.
    page_copy_with_mode(&mut img, 4, 7, 5);
    assert_eq!(nvs(&img).get_u8("tn_settings", "mode"), Ok(Some(5)));
}

#[test]
fn erased_and_unwritten_entries_are_skipped() {
    let mut img = MAIN_V2.to_vec();
    // Entry 1 (mode): state bits 2..3 of bitmap byte 0 from written (10) to erased (00).
    assert_eq!(img[32], 0xaa);
    img[32] &= !0b1100;
    assert_eq!(nvs(&img).get_u8("tn_settings", "mode"), Ok(None));
    assert_eq!(nvs(&img).get_u8("tn_settings", "nope"), Ok(None));
    assert!(nvs(&img).has_str("tn_settings", "members").unwrap());
    // Back to "empty" (11) and to the ILLEGAL pattern (01): neither counts as written.
    for bits in [0b1100u8, 0b0100] {
        let mut img = MAIN_V2.to_vec();
        img[32] = (img[32] & !0b1100) | bits;
        assert_eq!(nvs(&img).get_u8("tn_settings", "mode"), Ok(None));
    }
}

#[test]
fn page_states() {
    for (state, found) in [
        (0xffff_fffeu32, true),
        (0xffff_fffc, true),
        (0xffff_fff8, true),
        (0xffff_ffff, false),
        (0x0000_0000, false),
        (0xffff_fff0, false),
        (0xffff_fffd, false),
    ] {
        let mut img = MAIN_V2.to_vec();
        img[..4].copy_from_slice(&state.to_le_bytes());
        let r = nvs(&img).get_u8("tn_settings", "mode");
        assert_eq!(r, Ok(found.then_some(2)), "state {state:#x}");
    }
}

#[test]
fn page_header_checks() {
    // A flipped sequence number, version or reserved byte breaks the header CRC; a bad version byte is refused even with a good CRC.
    for at in [4usize, 7, 8, 9, 20, 27, 28, 31] {
        let mut img = MAIN_V2.to_vec();
        img[at] ^= 0x01;
        assert_eq!(nvs(&img).get_u8("tn_settings", "mode"), Ok(None), "byte {at}");
    }
    let mut img = MAIN_V2.to_vec();
    img[8] = 0xfd;
    fix_page_crc(&mut img, 0);
    assert_eq!(nvs(&img).get_u8("tn_settings", "mode"), Ok(None));
    img[8] = 0xff;
    fix_page_crc(&mut img, 0);
    assert_eq!(nvs(&img).get_u8("tn_settings", "mode"), Ok(Some(2)));
}

#[test]
fn corrupt_item_headers_are_skipped() {
    // entry 1 = mode (offset 96): every header byte except the unchecked-by-CRC state is covered.
    for at in 96..128 {
        let mut img = MAIN_V2.to_vec();
        img[at] ^= 0x10;
        assert_eq!(nvs(&img).get_u8("tn_settings", "mode"), Ok(None), "byte {at}");
    }
    // Corrupting `mode` must not disturb its neighbours.
    let mut img = MAIN_V2.to_vec();
    img[100] ^= 0xff;
    assert!(nvs(&img).has_str("tn_settings", "members").unwrap());
    assert_eq!(nvs(&img).blob_len("tn_settings", "display"), Ok(Some(8)));
}

#[test]
fn corrupt_data_is_reported_not_trusted() {
    // v1: wifi_profiles is a BLOB item at 192 with its data at 224.
    let mut img = MAIN_V1.to_vec();
    img[224 + 100] ^= 0x01;
    let mut n = nvs(&img);
    assert_eq!(n.get_blob("tn_settings", "wifi_profiles", &mut [0; 784]), Err(Error::Corrupt));
    assert_eq!(n.blob_len("tn_settings", "wifi_profiles"), Ok(Some(784)));
    assert_eq!(n.get_blob("tn_settings", "wifi_meta", &mut [0; 516]), Ok(Some(516)));
    // v2: wifi_profiles BLOB_DATA is entry 4 (offset 192), its data at 224.
    let mut img = MAIN_V2.to_vec();
    img[224 + 783] ^= 0x80;
    assert_eq!(nvs(&img).get_blob("tn_settings", "wifi_profiles", &mut [0; 784]), Err(Error::Corrupt));
    // A damaged BLOB_DATA header makes the chunk missing: also corrupt, not "absent".
    let mut img = MAIN_V2.to_vec();
    img[192 + 9] ^= 0x01;
    assert_eq!(nvs(&img).get_blob("tn_settings", "wifi_profiles", &mut [0; 784]), Err(Error::Corrupt));
    // A damaged BLOB_IDX header hides the blob.
    let mut img = MAIN_V2.to_vec();
    img[1024 + 9] ^= 0x01;
    assert_eq!(nvs(&img).get_blob("tn_settings", "wifi_profiles", &mut [0; 784]), Ok(None));
    // Strings.
    let mut img = MAIN_V2.to_vec();
    img[128 + 32 + 3] ^= 0x01;
    assert_eq!(nvs(&img).has_str("tn_settings", "members"), Err(Error::Corrupt));
    // Chunks of the big blobs on later pages.
    let mut img = BIG_V2.to_vec();
    img[8192 + 64 + 32 * 5] ^= 0x01;
    let r: Vec<_> = ["blob4000", "blob6000", "blob8000"].iter().map(|k| nvs(&img).get_blob("big", k, &mut [0; 8000])).collect();
    assert!(r.contains(&Err(Error::Corrupt)), "{r:?}");
}

#[test]
fn inconsistent_chunk_index_is_corrupt() {
    // BLOB_IDX of wifi_profiles at offset 1024: size @24, chunk count @28, chunk start @29.
    let edit = |f: &dyn Fn(&mut [u8])| {
        let mut img = MAIN_V2.to_vec();
        f(&mut img[1024..1056]);
        fix_item_crc(&mut img, 1024);
        nvs(&img).get_blob("tn_settings", "wifi_profiles", &mut [0; 1000])
    };
    assert_eq!(edit(&|_| {}), Ok(Some(784)));
    assert_eq!(edit(&|e| e[28] = 2), Err(Error::Corrupt)); // chunk 1 does not exist
    assert_eq!(edit(&|e| e[28] = 0), Err(Error::Corrupt)); // no chunks for 784 bytes
    assert_eq!(edit(&|e| e[28] = 200), Err(Error::Corrupt));
    assert_eq!(edit(&|e| e[29] = 0x80), Err(Error::Corrupt)); // wrong chunk version
    assert_eq!(edit(&|e| e[29] = 0x40), Err(Error::Corrupt));
    assert_eq!(edit(&|e| e[24..28].copy_from_slice(&700u32.to_le_bytes())), Err(Error::Corrupt)); // chunk larger than total
    assert_eq!(edit(&|e| e[24..28].copy_from_slice(&900u32.to_le_bytes())), Err(Error::Corrupt)); // chunks shorter than total
    assert_eq!(edit(&|e| e[24..28].copy_from_slice(&500_000u32.to_le_bytes())), Err(Error::TooSmall));
    // Above IDF's maximum blob size the index header itself is invalid, so the blob is absent.
    assert_eq!(edit(&|e| e[24..28].copy_from_slice(&u32::MAX.to_le_bytes())), Ok(None));
}

#[test]
fn empty_and_blank_partitions() {
    let erased = vec![0xffu8; 65536];
    let zeros = vec![0u8; 65536];
    for img in [&erased, &zeros] {
        let mut n = nvs(img);
        assert_eq!(n.get_u8("tn_settings", "mode"), Ok(None));
        assert_eq!(n.blob_len("tn_settings", "wifi_profiles"), Ok(None));
        assert_eq!(n.get_blob("tn_settings", "wifi_profiles", &mut [0; 784]), Ok(None));
        assert_eq!(n.has_str("tn_settings", "members"), Ok(false));
    }
    assert_eq!(Nvs::new(SliceFlash(&[]), 0).get_u8("a", "b"), Ok(None));
    assert_eq!(Nvs::new(SliceFlash(&[0u8; 100]), 100).get_u8("a", "b"), Ok(None));
}

#[test]
fn smaller_partitions_and_flash_errors() {
    let tiny = include_bytes!("fixtures/tiny_v2.bin");
    let mut n = Nvs::new(SliceFlash(tiny), 0x1000);
    assert_eq!(n.get_u8("tn_settings", "mode"), Ok(Some(2)));
    // Declared size larger than the flash behind it: a read error, not a panic or a wrong answer.
    let mut n = Nvs::new(SliceFlash(tiny), SIZE);
    assert_eq!(n.get_u8("tn_settings", "mode"), Err(Error::Flash(OutOfRange)));
    // Size below one page: no pages at all.
    assert_eq!(Nvs::new(SliceFlash(MAIN_V2), 4095).get_u8("tn_settings", "mode"), Ok(None));
    // Size not a multiple of the page: the partial page is ignored.
    assert_eq!(Nvs::new(SliceFlash(MAIN_V2), 4096 + 17).get_u8("tn_settings", "mode"), Ok(Some(2)));
    let mut out = [0u8; 4];
    assert_eq!(SliceFlash(&[1, 2, 3]).read(u32::MAX, &mut out), Err(OutOfRange));
    assert_eq!(SliceFlash(&[1, 2, 3]).read(1, &mut out[..2]), Ok(()));
    assert_eq!(out[..2], [2, 3]);
}

/// Records every read so the tests can check the access pattern: bounded reads, nothing outside the partition.
struct Spy<'a> {
    img: &'a [u8],
    max_len: std::cell::Cell<usize>,
    reads: std::cell::Cell<usize>,
}

impl Flash for Spy<'_> {
    type Error = ();
    fn read(&self, offset: u32, buf: &mut [u8]) -> Result<(), ()> {
        self.max_len.set(self.max_len.get().max(buf.len()));
        self.reads.set(self.reads.get() + 1);
        let start = offset as usize;
        buf.copy_from_slice(self.img.get(start..start + buf.len()).ok_or(())?);
        Ok(())
    }
}

#[test]
fn reads_are_piecewise_and_stay_inside_the_partition() {
    let spy = Spy { img: BIG_V2, max_len: 0.into(), reads: 0.into() };
    let mut n = Nvs::new(spy, SIZE);
    assert_eq!(n.get_u8("tn_settings", "mode"), Ok(Some(2)));
    assert!(n.has_str("tn_settings", "members").unwrap());
    // Blob data is read in one go straight into the caller's buffer; everything else in 32-byte pieces.
    let spy = n.into_inner();
    assert_eq!(spy.max_len.get(), 32);
    let mut n = Nvs::new(spy, SIZE);
    assert_eq!(n.get_blob("big", "blob8000", &mut [0; 8000]), Ok(Some(8000)));
    let spy = n.into_inner();
    assert!(spy.max_len.get() <= 4000, "{}", spy.max_len.get());
}

/// A flash that counts its reads. On the board every read is a flash-driver call with the cache and interrupts held off, so the number of reads is the cost of a
/// load, and a load must be bounded (a loop that is merely long looks like a hang to a watchdog).
struct Counting<'a> {
    inner: SliceFlash<'a>,
    reads: std::cell::Cell<u32>,
    bytes: std::cell::Cell<u64>,
}

impl Flash for Counting<'_> {
    type Error = OutOfRange;
    fn read(&self, offset: u32, buf: &mut [u8]) -> Result<(), OutOfRange> {
        self.reads.set(self.reads.get() + 1);
        self.bytes.set(self.bytes.get() + buf.len() as u64);
        self.inner.read(offset, buf)
    }
}

/// The load the spikes do at boot (profiles, meta, v0.1.x config, with absent keys looked up too) is bounded on every fixture, on an erased partition and on one full of
/// garbage; the numbers are the reason the console can come up before storage without risking a watchdog.
#[test]
fn a_boot_time_load_is_bounded_in_flash_reads() {
    let erased = vec![0xffu8; SIZE as usize];
    let garbage: Vec<u8> = (0..SIZE as usize).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
    let mut images: Vec<(&str, &[u8])> = FIXTURES.iter().map(|(n, b, _)| (*n, *b)).collect();
    images.push(("erased", &erased));
    images.push(("garbage", &garbage));
    for (name, img) in images {
        let flash = Counting { inner: SliceFlash(img), reads: 0.into(), bytes: 0.into() };
        let mut n = Nvs::new(flash, SIZE);
        let mut buf = [0u8; 1100];
        for (ns, key) in
            [("tn_settings", "wifi_profiles"), ("tn_settings", "wifi_meta"), ("adapter", "config"), ("tn_settings", "mode"), ("tn_settings", "nothing")]
        {
            let _ = n.get_blob(ns, key, &mut buf);
        }
        let f = n.into_inner();
        let (reads, bytes) = (f.reads.get(), f.bytes.get());
        eprintln!("{name}: {reads} reads, {bytes} bytes");
        // 16 pages x (header + 126 entries): five lookups plus chunk lookups stay far below this; a runaway loop would not.
        assert!(reads < 10_000, "{name}: {reads} flash reads");
        assert!(bytes < 300_000, "{name}: {bytes} bytes read");
    }
}
