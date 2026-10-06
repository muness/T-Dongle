//! In-memory `Platform`, `Storage` and a model heap for the host harness.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tdongle_tailnet_fw::{HeapProbe, Platform, Storage, StorageError};
use tdongle_tailnet_types::Millis;

/// A heap the tests control: `free = baseline - charged`, with the low-water mark kept. The runtime holds all its memory in statics, so nothing
/// draws from it by itself; tests charge what they want to model (a handshake peak, a packet burst) and the floor checks read the minimum.
pub struct ModelHeap {
    /// Free bytes with nothing charged.
    pub baseline: usize,
    /// The largest free block with nothing charged.
    pub largest: usize,
    charged: AtomicUsize,
    min_free: AtomicUsize,
    readings: AtomicU64,
    dynamic: Mutex<Option<Box<dyn Fn() -> usize + Send + Sync>>>,
}

impl std::fmt::Debug for ModelHeap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ModelHeap(free {} of {})", self.baseline.saturating_sub(self.charged()), self.baseline)
    }
}

impl ModelHeap {
    /// A heap with `baseline` free bytes (the C's board has about 106 KB after boot).
    pub fn new(baseline: usize, largest: usize) -> Self {
        ModelHeap {
            baseline,
            largest,
            charged: AtomicUsize::new(0),
            min_free: AtomicUsize::new(baseline),
            readings: AtomicU64::new(0),
            dynamic: Mutex::new(None),
        }
    }
    /// Charge `bytes` (a transient allocation of the modelled firmware).
    pub fn charge(&self, bytes: usize) {
        let c = self.charged.fetch_add(bytes, Ordering::SeqCst) + bytes;
        self.min_free.fetch_min(self.baseline.saturating_sub(c), Ordering::SeqCst);
    }
    /// Give `bytes` back.
    pub fn release(&self, bytes: usize) {
        self.charged.fetch_sub(bytes, Ordering::SeqCst);
    }
    /// Bytes charged now: what the tests charged plus what the model function says the modelled firmware has in flight.
    pub fn charged(&self) -> usize {
        self.charged.load(Ordering::SeqCst) + self.dynamic.lock().unwrap().as_ref().map_or(0, |f| f())
    }
    /// Model transient demand as a function of the runtime's state (read on every reading of the heap).
    pub fn set_model(&self, f: impl Fn() -> usize + Send + Sync + 'static) {
        *self.dynamic.lock().unwrap() = Some(Box::new(f));
    }
    /// How many times the runtime read the heap.
    pub fn readings(&self) -> u64 {
        self.readings.load(Ordering::Relaxed)
    }
}

impl HeapProbe for ModelHeap {
    fn free(&self) -> usize {
        self.readings.fetch_add(1, Ordering::Relaxed);
        let f = self.baseline.saturating_sub(self.charged());
        self.min_free.fetch_min(f, Ordering::SeqCst);
        f
    }
    fn largest_block(&self) -> usize {
        self.largest.saturating_sub(self.charged())
    }
    fn minimum_free(&self) -> usize {
        self.min_free.load(Ordering::SeqCst)
    }
}

/// The platform: a monotonic clock from process start, the wall clock from the OS (optionally "not yet set"), OS entropy.
#[derive(Debug)]
pub struct MemPlatform {
    start: Instant,
    /// The model heap.
    pub heap: Arc<ModelHeap>,
    /// Report the wall clock as unset (SNTP has not run) until this is cleared.
    pub clock_unset: std::sync::atomic::AtomicBool,
    /// The lines the runtime wrote to the console.
    pub console: Mutex<Vec<String>>,
}

impl MemPlatform {
    /// A platform over `heap`.
    pub fn new(heap: Arc<ModelHeap>) -> Self {
        MemPlatform { start: Instant::now(), heap, clock_unset: false.into(), console: Mutex::new(Vec::new()) }
    }
}

impl Platform for MemPlatform {
    fn now_ms(&self) -> Millis {
        self.start.elapsed().as_millis() as Millis
    }
    fn unix_seconds(&self) -> Option<u64> {
        if self.clock_unset.load(Ordering::Relaxed) {
            return None;
        }
        SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
    }
    fn fill_random(&self, buf: &mut [u8]) {
        use std::io::Read;
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).expect("/dev/urandom");
    }
    fn sta_mac(&self) -> [u8; 6] {
        [0x02, 0x00, 0x5e, 0x00, 0x00, 0x01]
    }
    fn heap(&self) -> &dyn HeapProbe {
        &*self.heap
    }
    fn console_line(&self, line: &str) {
        self.console.lock().unwrap().push(line.to_string());
    }
}

type Map = BTreeMap<(String, String), Vec<u8>>;

/// NVS in memory; clones share the contents (the test keeps one to look at what was persisted, or to simulate a reboot).
#[derive(Clone, Debug, Default)]
pub struct MemStorage {
    /// The contents.
    pub map: Arc<Mutex<Map>>,
    /// Fail every write (a full or damaged partition).
    pub fail_writes: Arc<std::sync::atomic::AtomicBool>,
    /// Writes accepted.
    pub writes: Arc<AtomicU64>,
}

impl MemStorage {
    /// The stored blob.
    pub fn peek(&self, ns: &str, key: &str) -> Option<Vec<u8>> {
        self.map.lock().unwrap().get(&(ns.to_string(), key.to_string())).cloned()
    }
    /// The namespaces that hold anything.
    pub fn namespaces(&self) -> Vec<String> {
        let mut v: Vec<String> = self.map.lock().unwrap().keys().map(|(n, _)| n.clone()).collect();
        v.dedup();
        v
    }
}

impl Storage for MemStorage {
    fn get(&mut self, ns: &str, key: &str, out: &mut [u8]) -> Result<usize, StorageError> {
        let m = self.map.lock().unwrap();
        let v = m.get(&(ns.to_string(), key.to_string())).ok_or(StorageError::NotFound)?;
        if v.len() > out.len() {
            return Err(StorageError::TooSmall);
        }
        out[..v.len()].copy_from_slice(v);
        Ok(v.len())
    }
    fn set(&mut self, ns: &str, key: &str, data: &[u8]) -> Result<(), StorageError> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(StorageError::Failed);
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.map.lock().unwrap().insert((ns.to_string(), key.to_string()), data.to_vec());
        Ok(())
    }
    fn erase_namespace(&mut self, ns: &str) -> Result<(), StorageError> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(StorageError::Failed);
        }
        self.map.lock().unwrap().retain(|(n, _), _| n != ns);
        Ok(())
    }
}
