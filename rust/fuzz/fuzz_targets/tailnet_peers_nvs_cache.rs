//! The NVS peer cache blob: any bytes parse to a valid table or are discarded; re-encoding never fails.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_peers::nvs_cache::PeerCache;

fuzz_target!(|data: &[u8]| {
    let (t, ok) = PeerCache::<64>::from_blob(data);
    assert!(t.len() <= 64 && (ok || t.is_empty()));
    let mut out = [0u8; PeerCache::<64>::MAX_BLOB_BYTES];
    let n = t.to_blob(&mut out).expect("fits");
    let (t2, ok2) = PeerCache::<64>::from_blob(&out[..n]);
    assert!(ok2 && t2.len() == t.len());
    for p in t.load_all(64, 0) {
        let _ = p.meta.hostname.as_str();
    }
});
