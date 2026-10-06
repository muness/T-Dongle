//! Bytes of state, for the memory ledger (ADR 0001 rule 7). `cargo test -p tdongle-tailnet-disco --test sizes -- --nocapture` prints them.
//! No struct holds a packet: the S4 model's DISCO task reserved 18,456 B for 1.5 KB inline slots; here the packet is the caller's buffer.

use tdongle_tailnet_disco::netcheck::Netcheck;
use tdongle_tailnet_disco::path::*;
use tdongle_tailnet_disco::policy::TrialGate;
use tdongle_tailnet_disco::stun_sched::StunScheduler;
use tdongle_tailnet_disco::{Ep, envelope::RxCounters};

#[test]
fn state_bytes() {
    let rows: [(&str, usize); 14] = [
        ("Ep", core::mem::size_of::<Ep>()),
        ("PathState<8> (per peer, 8 endpoints)", PathState::<8>::STATE_BYTES),
        ("PathState<4> (per peer, 4 endpoints)", PathState::<4>::STATE_BYTES),
        ("ProbeTable<16> (per membership; C: 32 slots)", ProbeTable::<16>::STATE_BYTES),
        ("ProbeTable<8>", ProbeTable::<8>::STATE_BYTES),
        ("ProbeTable<32> (the C's size)", ProbeTable::<32>::STATE_BYTES),
        ("PathCounters (per membership)", core::mem::size_of::<PathCounters>()),
        ("RxCounters", core::mem::size_of::<RxCounters>()),
        ("TrialGate (per membership)", core::mem::size_of::<TrialGate>()),
        ("StunScheduler (per membership)", StunScheduler::STATE_BYTES),
        ("Netcheck<8> (transient)", Netcheck::<8>::STATE_BYTES),
        ("AddBurst", core::mem::size_of::<AddBurst>()),
        ("Action (sink item)", core::mem::size_of::<Action>()),
        ("PathConfig (shared, can be a const)", core::mem::size_of::<PathConfig>()),
    ];
    for (n, b) in rows {
        println!("{n:<48} {b:>6} B");
    }
    // 8 peers of a membership, defaults: the number the ADR needs
    let per_membership = 8 * PathState::<8>::STATE_BYTES
        + ProbeTable::<16>::STATE_BYTES
        + core::mem::size_of::<PathCounters>()
        + core::mem::size_of::<RxCounters>()
        + core::mem::size_of::<TrialGate>()
        + StunScheduler::STATE_BYTES
        + core::mem::size_of::<AddBurst>();
    println!("{:<48} {per_membership:>6} B", "one membership, 8 peers, resident state");
    assert!(per_membership <= 3_000, "{per_membership}");
}
