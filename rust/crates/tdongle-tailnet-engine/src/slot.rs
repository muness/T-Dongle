//! The pool's slot payload: the WireGuard hot state of one resident peer plus the cold record it needs (public key, preshared key, precomputed static
//! DH), and the adapter that feeds receiver indices from the pool to the WireGuard crate.

use tdongle_tailnet_peers::pool::SlotMeta;
use tdongle_tailnet_wg::{HsState, IndexAllocator, PeerCold, PeerHot};

/// One pool slot (`struct wireguard_peer` of the C, minus the allowed IPs which live in the member's peer table).
pub struct WgSlot {
    /// Handshake, sessions, timers.
    pub hot: PeerHot,
    /// The peer's cold record (`None` in a free slot).
    pub cold: Option<PeerCold>,
    /// The peer's WireGuard public key.
    pub public: [u8; 32],
    /// The slot holds a configured peer.
    pub valid: bool,
}

impl core::fmt::Debug for WgSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WgSlot(valid={}, {:?})", self.valid, self.hot)
    }
}

impl WgSlot {
    /// `size_of::<WgSlot>()`: the cost of one pool slot.
    pub const BYTES: usize = core::mem::size_of::<WgSlot>();

    /// A slot for the peer with public key `public` and cold record `cold`.
    #[inline(always)]
    pub fn new(public: [u8; 32], cold: PeerCold) -> WgSlot {
        WgSlot { hot: PeerHot::new(), cold: Some(cold), public, valid: true }
    }

    /// The receiver index of the handshake in flight: an index the slot holds that no session owns.
    pub fn handshake_index(&self) -> Option<u32> {
        if self.hot.handshake_state() == HsState::Idle {
            return None;
        }
        let mut found = None;
        self.hot.for_each_index(|i| {
            if i != 0 && self.hot.session_by_index(i).is_none() {
                found = Some(i);
            }
        });
        found
    }
}

impl SlotMeta for WgSlot {
    const ZEROED: Self = WgSlot { hot: PeerHot::new(), cold: None, public: [0; 32], valid: false };

    fn wipe(&mut self) {
        self.hot.reset();
        self.cold = None;
        self.public = [0; 32];
        self.valid = false;
    }
    fn reserved_indices(&self) -> [u32; 4] {
        let mut a = [0u32; 4];
        let mut n = 0;
        self.hot.for_each_index(|i| {
            if n < 4 {
                a[n] = i;
                n += 1;
            }
        });
        a
    }
    fn is_valid(&self) -> bool {
        self.valid
    }
    fn session_has_index(&self, index: u32) -> bool {
        self.hot.session_by_index(index).is_some()
    }
    fn handshake_has_index(&self, index: u32) -> bool {
        self.handshake_index() == Some(index)
    }
    fn public_key(&self) -> &[u8; 32] {
        &self.public
    }
    fn handshake_state(&self) -> (bool, u32) {
        match self.handshake_index() {
            Some(i) => (true, i),
            None => (false, 0),
        }
    }
}

/// An index drawn from the pool before the slot is borrowed (`Pool::generate_unique_index` needs the whole pool; the WireGuard call needs one
/// slot): handed out once, reserved the moment the slot's handshake records it. Nothing else allocates in between (one owner, `&mut self` all the
/// way), so pool-wide uniqueness holds.
#[derive(Debug)]
pub struct PreDrawn {
    next: Option<u32>,
}

impl PreDrawn {
    /// An allocator that will return `index` (or fail when `None`).
    #[inline(always)]
    pub fn new(index: Option<u32>) -> Self {
        Self { next: index }
    }
}

impl IndexAllocator for PreDrawn {
    fn allocate(&mut self) -> Option<u32> {
        self.next.take()
    }
    fn release(&mut self, _index: u32) {}
}
