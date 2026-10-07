//! Mapping of the engine's [`StatusSnapshot`] onto the inputs of `tdongle_tailnet_status` (feature `status`). The status crate has no dependencies, so
//! there is no cycle; the mapping is a feature only so that a build without `/status` does not compile the status crate.
//!
//! Fields the engine does not own (stack watermarks, the negotiation token, DERP link counters, USB receive refusals) are the runtime's to fill.

use crate::slot::WgSlot;
use crate::status::{MemberStatus, StatusSnapshot};
use tdongle_tailnet_admission::heap::{ML_HB_FLOOR, ML_HB_PIN_BUFFERS, ML_HB_RESERVE};
use tdongle_tailnet_status::input::{Client, HeapBudget, WgPool};

/// The `"wg_pool"` fragment's input (`ml_wg_pool_status_t`). `device_bytes` is what one membership's WireGuard device state costs (the runtime knows).
pub fn wg_pool<const M: usize>(s: &StatusSnapshot<M>, device_bytes: u32) -> WgPool {
    WgPool {
        capacity: s.pool.capacity,
        used: s.pool.used,
        peak: s.pool.peak,
        refused_full: s.pool.refused_full,
        refused_nomem: 0,
        evictions_own: s.arbiter.0,
        evictions_other: s.arbiter.1,
        rejected: s.arbiter.2,
        refused_largest: s.pool.refused_largest,
        refused_heap: s.pool.refused_heap,
        largest_low: u32::MAX,
        slot_bytes: WgSlot::BYTES as u32,
        device_bytes,
    }
}

/// The heap budget's input (`ADR 0022`): the floor and the refusals per elastic site. `refused_usb_rx` belongs to the USB receive path.
pub fn heap_budget<const M: usize>(s: &StatusSnapshot<M>, refused_usb_rx: u32) -> HeapBudget {
    HeapBudget {
        floor: ML_HB_FLOOR as u32,
        reserve: ML_HB_RESERVE as u32,
        pin_buffers: ML_HB_PIN_BUFFERS,
        refused_usb_rx,
        refused_pending: s.heap_refused[0],
        refused_derp_tx: s.heap_refused[1],
        refused_rx_ctrl: s.heap_refused[2],
        refused_derp_rx: s.heap_refused[3],
        refused_wg_copy: s.heap_refused[4],
    }
}

/// Fill the fields of a membership's client entry that the engine knows: the tailnet address, the activation counters (`jit_*`) and the directory size.
pub fn fill_client(c: &mut Client<'_>, m: &MemberStatus) {
    c.vpn_ip = m.self_ip;
    c.jit_hits = m.activation.0;
    c.jit_misses = m.activation.1;
    c.jit_evictions = m.activation.2;
    c.jit_rejected = m.activation.3;
    c.directory_records = m.directory_peers;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_pool_budget_and_client() {
        let s = StatusSnapshot::<1> {
            members: [Some(MemberStatus { self_ip: 7, activation: (1, 2, 3, 4), directory_peers: 9, ..MemberStatus::default() })],
            pool: crate::status::PoolStatus { used: 3, capacity: 12, peak: 5, refused_full: 1, refused_heap: 2, refused_largest: 3, refused_device_full: 0 },
            arbiter: (4, 5, 6),
            heap_refused: [1, 2, 3, 4, 5],
            router: [0; tdongle_tailnet_router::Stat::COUNT],
            aliases: 0,
            arena: (0, 0),
            wake: None,
            clock_valid: false,
        };
        let p = wg_pool(&s, 100);
        assert_eq!((p.capacity, p.used, p.evictions_own, p.evictions_other, p.rejected, p.refused_heap), (12, 3, 4, 5, 6, 2));
        let h = heap_budget(&s, 9);
        assert_eq!((h.floor, h.refused_pending, h.refused_wg_copy, h.refused_usb_rx), (29_884, 1, 5, 9));
        let mut c = Client::default();
        fill_client(&mut c, s.members[0].as_ref().unwrap());
        assert_eq!((c.vpn_ip, c.jit_hits, c.jit_rejected, c.directory_records), (7, 1, 4, 9));
    }
}
