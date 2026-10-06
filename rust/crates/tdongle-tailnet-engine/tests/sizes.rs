//! The memory ledger: bytes of the engine per configuration and bytes per membership (the number the ADR needs). Run with `--nocapture` to print.

use tdongle_tailnet_derp::Link;
use tdongle_tailnet_engine::status::DERP_TXQ;
use tdongle_tailnet_engine::{DirError, Engine, MemberBytes, PeerDirectory};
use tdongle_tailnet_map::types::PeerRecord;
use tdongle_tailnet_peers::record::{DirRecord, PubKey};

/// A zero-sized directory: the engine's own bytes without the directory's.
struct NoDir;
impl PeerDirectory for NoDir {
    fn find_by_key(&mut self, _: usize, _: &PubKey) -> Option<DirRecord> {
        None
    }
    fn find_by_ip(&mut self, _: usize, _: u32) -> Option<DirRecord> {
        None
    }
    fn find_by_disco(&mut self, _: usize, _: &PubKey) -> Option<DirRecord> {
        None
    }
    fn stage(&mut self, _: usize, _: &PeerRecord) -> Result<(), DirError> {
        Err(DirError)
    }
    fn commit(&mut self, _: usize, _: bool) -> Result<(), DirError> {
        Err(DirError)
    }
    fn abort(&mut self, _: usize) {}
    fn clear(&mut self, _: usize) {}
    fn count(&self, _: usize) -> usize {
        0
    }
    fn peer_view(&self, _: usize, _: usize) -> Option<(&str, u32)> {
        None
    }
    fn generation(&self, _: usize) -> u32 {
        0
    }
}

fn engine<const M: usize, const P: usize, const K: usize, const JB: usize>() -> usize {
    core::mem::size_of::<Engine<NoDir, M, P, K, 64, 64, JB>>()
}

#[test]
fn sizes_by_configuration_and_per_member() {
    let rows = [
        ("1 member,  P 8, K  8, JB 12", engine::<1, 8, 8, 12>()),
        ("2 members, P 8, K 12, JB 16", engine::<2, 8, 12, 16>()),
        ("3 members, P 8, K 12, JB 24  (GatewayEngine)", engine::<3, 8, 12, 24>()),
        ("3 members, P 4, K  8, JB 24", engine::<3, 4, 8, 24>()),
        ("4 members, P 8, K 12, JB 24", engine::<4, 8, 12, 24>()),
    ];
    for (n, b) in rows {
        println!("{n:<48} {b:>7} bytes");
    }
    let one = engine::<1, 8, 12, 24>();
    let two = engine::<2, 8, 12, 24>();
    let three = engine::<3, 8, 12, 24>();
    let per_member_measured = three - two;
    println!("marginal bytes of one more membership (host, in Engine): {per_member_measured}");
    assert!(per_member_measured.abs_diff(two - one) <= 16, "linear in the number of memberships (up to alignment)");
    let b = MemberBytes::of::<8>();
    println!("{b:#?}");
    println!("one DERP link (TXQ {DERP_TXQ}): {}", Link::<DERP_TXQ>::STATE_BYTES);
    println!("shared (engine minus 3 memberships): {}", three - 3 * per_member_measured);
    // the ledger and the measurement agree: Member<P> is the in-engine record and the engine grows by it (plus the router's table slot)
    assert!(per_member_measured >= b.in_engine);
    assert!(per_member_measured <= b.in_engine + 64, "only small per-member slots live outside Member: {per_member_measured} vs {}", b.in_engine);
    assert_eq!(b.in_engine, core::mem::size_of::<tdongle_tailnet_engine::member::Member<8>>());
    // regression guards (host sizes, generous): a growth past these is a decision, not an accident
    assert!(b.in_engine < 14_000, "{}", b.in_engine);
    assert!(three < 70_000, "{three}");
}
