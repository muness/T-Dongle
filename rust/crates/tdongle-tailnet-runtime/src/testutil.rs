//! Test doubles for the unit tests (`cfg(test)`): a platform, storage, a shared state over a critical-section mutex.

use crate::shared::{Config, Shared};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::vec::Vec;
use tdongle_tailnet_engine::RamDirectory;
use tdongle_tailnet_fw::{HeapProbe, Platform, Storage, StorageError};
use tdongle_tailnet_types::Millis;

/// A heap whose free bytes the test sets.
#[derive(Debug)]
pub struct TestHeap {
    pub free: AtomicUsize,
    pub largest: AtomicUsize,
}

impl HeapProbe for TestHeap {
    fn free(&self) -> usize {
        self.free.load(Ordering::SeqCst)
    }
    fn largest_block(&self) -> usize {
        self.largest.load(Ordering::SeqCst)
    }
    fn minimum_free(&self) -> usize {
        self.free.load(Ordering::SeqCst)
    }
}

/// The platform of the unit tests.
#[derive(Debug)]
pub struct TestPlatform {
    start: Instant,
    pub heap: Arc<TestHeap>,
    pub console: Mutex<Vec<String>>,
}

impl Platform for TestPlatform {
    fn now_ms(&self) -> Millis {
        self.start.elapsed().as_millis() as Millis
    }
    fn unix_seconds(&self) -> Option<u64> {
        Some(1_791_244_800)
    }
    fn fill_random(&self, buf: &mut [u8]) {
        let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ self.start.elapsed().as_nanos() as u64;
        for b in buf {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
    }
    fn sta_mac(&self) -> [u8; 6] {
        [0x02, 0, 0x5e, 0, 0, 1]
    }
    fn heap(&self) -> &dyn HeapProbe {
        &*self.heap
    }
    fn console_line(&self, line: &str) {
        self.console.lock().unwrap().push(line.to_string());
    }
}

type Store = BTreeMap<(String, String), Vec<u8>>;

/// NVS in memory; clones share.
#[derive(Clone, Debug, Default)]
pub struct TestStorage {
    pub map: Arc<Mutex<Store>>,
    pub fail: Arc<std::sync::atomic::AtomicBool>,
}

impl Storage for TestStorage {
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
        if self.fail.load(Ordering::SeqCst) {
            return Err(StorageError::Failed);
        }
        self.map.lock().unwrap().insert((ns.to_string(), key.to_string()), data.to_vec());
        Ok(())
    }
    fn erase_namespace(&mut self, ns: &str) -> Result<(), StorageError> {
        self.map.lock().unwrap().retain(|(n, _), _| n != ns);
        Ok(())
    }
}

/// The directory of the tests.
pub type Dir = RamDirectory<3, 16, 32>;
/// The shared state of the tests.
pub type Sh = Shared<CriticalSectionRawMutex, TestPlatform, TestStorage, Dir>;

/// A shared state with a 106 KB heap and the given storage.
pub fn shared_with(storage: TestStorage) -> Sh {
    let heap = Arc::new(TestHeap { free: AtomicUsize::new(106_000), largest: AtomicUsize::new(24_576) });
    let platform = TestPlatform { start: Instant::now(), heap, console: Mutex::new(Vec::new()) };
    Shared::new(Config::tailscale(), platform, storage, Dir::new())
}

/// A shared state over fresh storage.
pub fn shared() -> Sh {
    shared_with(TestStorage::default())
}
