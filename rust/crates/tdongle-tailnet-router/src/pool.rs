//! A bounded, static packet pool: `N` slabs of `SZ` bytes, handed out by value-like handles, never backed by a heap. When it is empty the
//! allocation fails with a reason and a counter moves; there is no fallback. Two classes (control traffic keeps a reserve data cannot touch)
//! and a per-owner cap so that one membership cannot take the pool from the others (design of `docs/research/forwarding-latency.md` 2.1).

/// Traffic class of an allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Handshakes, keepalives, disco: may use the reserve.
    Ctrl,
    /// Payload traffic: limited to `N - ctrl_reserve` slabs in all and to the owner cap each.
    Data,
}

/// Why an allocation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolDrop {
    /// No free slab at all.
    Empty,
    /// Data class would eat into the control reserve.
    Reserved,
    /// The owner already holds its share.
    OwnerCap,
}

/// A slab handle. Not `Clone`/`Copy`: [`Pool::free`] consumes it, so a slab is freed at most once; dropping it without freeing leaks the slab
/// until [`Pool::reset`] (the leak is visible in [`Pool::in_use`]).
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a slab that is not freed stays allocated"]
pub struct Slab {
    index: u8,
    owner: u32,
    class: Class,
}

impl Slab {
    /// Owner (membership id) the slab was charged to.
    pub fn owner(&self) -> u32 {
        self.owner
    }
}

/// Drop counters of a pool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Allocation refused: pool empty.
    pub empty: u32,
    /// Allocation refused: data class against the control reserve.
    pub reserved: u32,
    /// Allocation refused: owner cap.
    pub owner_cap: u32,
    /// Most slabs ever in use at once.
    pub high_water: u32,
}

/// The pool. `N` is at most 255; `OWNERS` bounds the per-owner accounting (owners beyond it share the last row).
pub struct Pool<const N: usize, const SZ: usize, const OWNERS: usize = 16> {
    mem: [[u8; SZ]; N],
    used: [bool; N],
    in_use: usize,
    ctrl_reserve: usize,
    owner_cap: usize,
    owner: [(u32, u16); OWNERS],
    stats: PoolStats,
}

impl<const N: usize, const SZ: usize, const OWNERS: usize> core::fmt::Debug for Pool<N, SZ, OWNERS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pool").field("in_use", &self.in_use).field("stats", &self.stats).finish()
    }
}

impl<const N: usize, const SZ: usize, const OWNERS: usize> Pool<N, SZ, OWNERS> {
    const OK: () = assert!(N > 0 && N <= 255 && OWNERS > 0, "pool needs 1..=255 slabs");
    /// Bytes of the pool in memory.
    pub const BYTES: usize = core::mem::size_of::<Self>();
    /// A pool with `ctrl_reserve` slabs reserved for [`Class::Ctrl`] and at most `owner_cap` slabs per owner (use `N` for no cap).
    pub const fn new(ctrl_reserve: usize, owner_cap: usize) -> Self {
        let () = Self::OK;
        Self {
            mem: [[0; SZ]; N],
            used: [false; N],
            in_use: 0,
            ctrl_reserve,
            owner_cap,
            owner: [(0, 0); OWNERS],
            stats: PoolStats { empty: 0, reserved: 0, owner_cap: 0, high_water: 0 },
        }
    }
    fn row(&mut self, owner: u32) -> usize {
        if let Some(i) = self.owner.iter().position(|o| o.1 > 0 && o.0 == owner) {
            return i;
        }
        self.owner.iter().position(|o| o.1 == 0).unwrap_or(OWNERS - 1)
    }
    /// Take a slab for `owner`.
    pub fn alloc(&mut self, class: Class, owner: u32) -> Result<Slab, PoolDrop> {
        if self.in_use == N {
            self.stats.empty += 1;
            return Err(PoolDrop::Empty);
        }
        if class == Class::Data && self.in_use + self.ctrl_reserve >= N {
            self.stats.reserved += 1;
            return Err(PoolDrop::Reserved);
        }
        let r = self.row(owner);
        if class == Class::Data && usize::from(self.owner[r].1) >= self.owner_cap {
            self.stats.owner_cap += 1;
            return Err(PoolDrop::OwnerCap);
        }
        let Some(i) = self.used.iter().position(|u| !u) else {
            self.stats.empty += 1;
            return Err(PoolDrop::Empty);
        };
        self.used[i] = true;
        self.in_use += 1;
        self.owner[r].0 = owner;
        self.owner[r].1 += 1;
        self.stats.high_water = self.stats.high_water.max(self.in_use as u32);
        Ok(Slab { index: i as u8, owner, class })
    }
    /// The slab's bytes.
    pub fn bytes(&mut self, s: &Slab) -> &mut [u8; SZ] {
        &mut self.mem[usize::from(s.index)]
    }
    /// Return a slab.
    pub fn free(&mut self, s: Slab) {
        let i = usize::from(s.index);
        if self.used[i] {
            self.used[i] = false;
            self.in_use -= 1;
            let r = self.row(s.owner);
            self.owner[r].1 = self.owner[r].1.saturating_sub(1);
        }
        let _ = s.class;
    }
    /// Slabs allocated.
    pub fn in_use(&self) -> usize {
        self.in_use
    }
    /// Drop counters.
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }
    /// Forget every allocation (after the runtime tears down every holder, e.g. a USB detach).
    pub fn reset(&mut self) {
        self.used = [false; N];
        self.in_use = 0;
        self.owner = [(0, 0); OWNERS];
    }
}
