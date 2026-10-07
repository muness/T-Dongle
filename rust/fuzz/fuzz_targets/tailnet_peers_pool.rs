//! The slot pool under arbitrary operation sequences: bounds hold, indices stay unique, nothing leaks.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_peers::pool::{OwnerId, Pool, SlotMeta, Ungated};

#[derive(Clone, Copy)]
struct Slot { valid: bool, key: [u8; 32], idx: [u32; 4] }
impl SlotMeta for Slot {
    const ZEROED: Self = Slot { valid: false, key: [0; 32], idx: [0; 4] };
    fn wipe(&mut self) { self.key = [0; 32]; }
    fn reserved_indices(&self) -> [u32; 4] { self.idx }
    fn is_valid(&self) -> bool { self.valid }
    fn session_has_index(&self, i: u32) -> bool { self.idx[0] == i }
    fn handshake_has_index(&self, i: u32) -> bool { self.idx[3] == i }
    fn public_key(&self) -> &[u8; 32] { &self.key }
    fn handshake_state(&self) -> (bool, u32) { (self.idx[3] != 0, self.idx[3]) }
}

fuzz_target!(|data: &[u8]| {
    let mut pool: Pool<Slot, 12> = Pool::new();
    for c in data.chunks(3) {
        let (op, o, i) = (c[0] % 4, OwnerId(c.get(1).copied().unwrap_or(0) % 4), c.get(2).copied().unwrap_or(0) % 9);
        match op {
            0 => {
                if let Ok(r) = pool.acquire(o, &mut Ungated) {
                    if let Some(s) = pool.get_mut(o, r.index) { s.valid = true; s.key = [i; 32]; }
                }
            }
            1 => { pool.release(o, i); }
            2 => { pool.release_owner(o); }
            _ => { let _ = pool.lookup_by_receiver(o, u32::from(i)); let _ = pool.lookup_by_pubkey(o, &[i; 32]); }
        }
        assert!(pool.used() <= 12);
        assert!(pool.owner_count(o) <= 8);
    }
    for o in 0..4 { pool.release_owner(OwnerId(o)); }
    let s = pool.stats();
    assert!(s.used == 0 && s.acquired == s.released);
});
