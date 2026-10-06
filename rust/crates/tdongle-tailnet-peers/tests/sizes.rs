//! Sizes (the ADR needs bytes per membership) and the static-pool arithmetic of the report. The slot payload here is the test double; the WireGuard
//! crate's real slot replaces it (`Pool::<WgSlot, 12>::STATE_BYTES` is the number to read).

mod common;
use common::TestSlot;
use tdongle_tailnet_admission::adm::{MemberSizes, Params, Provisional, SharedSizes};
use tdongle_tailnet_peers::arbiter::Arbiter;
use tdongle_tailnet_peers::directory::RECORD_BYTES;
use tdongle_tailnet_peers::membership::Membership;
use tdongle_tailnet_peers::nvs_cache::PeerCache;
use tdongle_tailnet_peers::pool::Pool;
use tdongle_tailnet_peers::record::DirRecord;
use tdongle_tailnet_peers::table::{Peer, PeerTable};
use tdongle_tailnet_peers::trial::Trial;

#[test]
fn print_sizes() {
    std::println!(
        "SIZES (host 64-bit; no usize/pointer fields, u64 aligned to 8 on xtensa too): Peer {} | PeerTable<8> {} | Membership<8> {} (table + Trial {} + counters) | DirRecord {} (flash record {} B) | PeerCache<64> {} (blob max {}) | Arbiter {} | test slot {} | Pool<TestSlot,12> {}",
        Peer::STATE_BYTES,
        PeerTable::<8>::STATE_BYTES,
        Membership::<8>::STATE_BYTES,
        core::mem::size_of::<Trial>(),
        DirRecord::STATE_BYTES,
        RECORD_BYTES,
        PeerCache::<64>::STATE_BYTES,
        PeerCache::<64>::MAX_BLOB_BYTES,
        core::mem::size_of::<Arbiter>(),
        core::mem::size_of::<TestSlot>(),
        Pool::<TestSlot, 12>::STATE_BYTES,
    );
    const { assert!(Membership::<8>::STATE_BYTES < 6000) };
}

/// Is a static pool of 12 right? The C argued no (ADR 0013 review, `tests/test_admission.c`): 12 resident slots pin K x slot bytes for ever against
/// a first-membership margin of ~10.6 KB. With the C's own numbers, restated:
#[test]
fn static_pool_arithmetic_with_the_c_numbers() {
    let c = Params::c_reference();
    let first = c.budget(false);
    let boot_free = 107_000i64;
    let slot = c.wg_slot as i64;
    let elastic_margin = boot_free - first.required as i64; // two slots charged, ten more elastic from free heap
    // Static: all 12 slots leave the heap at boot, so admission need not charge them: the two charged slots come out of `required`.
    let static_free = boot_free - 12 * slot;
    let static_required = first.required as i64 - 2 * slot;
    let static_margin = static_free - static_required;
    std::println!(
        "static pool, C numbers: slot {slot} B x 12 = {} B pinned; first-membership margin elastic {elastic_margin} B, static {static_margin} B (a difference of {} B = the ten uncharged slots)",
        12 * slot,
        elastic_margin - static_margin
    );
    assert_eq!(elastic_margin, 10_600);
    assert_eq!(static_margin, 10_600 - 10 * slot);
    assert!(static_margin < 0, "with the C's per-membership fixed costs a static 12 does not fit a typical boot");

    // With the Rust task model (no per-member stack or TCB, executor arena instead of three stacks) the same arithmetic. ILLUSTRATIVE sizes: the
    // real ones come from the other crates' `size_of` constants and the board.
    for wg_slot in [700usize, 900, 1100] {
        let m = MemberSizes { control: 3000, peer_table: PeerTable::<8>::STATE_BYTES, derp_link: 800, queues: 1692, wg_device: 300, misc: 300 };
        let r = Params::rust(&m, wg_slot, &SharedSizes { executor_bytes: 6000 }, &Provisional::C_MEASURED);
        let b = r.budget(false);
        let elastic = boot_free - b.required as i64;
        let static_margin = (boot_free - 12 * wg_slot as i64) - (b.required as i64 - 2 * wg_slot as i64);
        std::println!(
            "static pool, Rust model (illustrative), slot {wg_slot} B: required(N=1) {} B, margin elastic {elastic} B, static-12 {static_margin} B (pinned {} B); N=2 needs {} B more free heap",
            b.required,
            12 * wg_slot,
            r.budget(true).required
        );
        assert!(static_margin > 0, "{wg_slot}");
    }
}
