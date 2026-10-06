//! The alias path: the router's small cache against the engine's alias book (fills, holds, unknown aliases).

mod common;
use common::*;
use tdongle_tailnet_engine::{Handled, HostFate};
use tdongle_tailnet_router::Stat;

#[test]
fn an_alias_evicted_from_the_router_cache_is_held_filled_from_the_book_and_released() {
    let mut s = SoloA::<2>::new(1);
    s.member(1, 5, 0);
    let aliases: Vec<u32> = (1..=4).map(|p| s.alias(1, p)).collect();
    // the cache holds two: the first alias was pushed out, but the router knows it exists (the limit was raised when it was inserted)
    assert_eq!(s.eng.router().aliases().len(), 2);
    let r = s.send(aliases[0], 40);
    assert_eq!(r, Handled::Host(HostFate::Held));
    assert_eq!(s.eng.router().stats().get(Stat::Held), 1);
    // the fill is answered straight away from the book and the held packet enters the tunnel path
    assert_eq!(s.eng.stats().alias_fills.get(), 1);
    assert_eq!(s.eng.stats().held_released.get(), 1);
    assert_eq!(s.eng.member(1).unwrap().rt.park.len(), 1, "it was parked for the handshake like any other");
    s.eng.check_identities().unwrap();
    // an address in the alias range that was never allocated is dropped at once, without asking for a fill
    let r = s.send(0xc612_0000 | 0x1_0000, 40);
    assert_eq!(r, Handled::Host(HostFate::RouterDrop));
    assert_eq!(s.eng.router().stats().get(Stat::AliasUnknown), 1);
    // addresses outside the alias range are not ours at all: left to the IP stack
    assert_eq!(s.send(0x0808_0808, 40), Handled::Host(HostFate::PassThrough));
    s.eng.check_identities().unwrap();
}

#[test]
fn aliases_are_stable_across_memberships_and_never_shared() {
    let mut s = Solo::new(2);
    s.member(1, 2, 0);
    s.member(2, 2, 0);
    let a = s.alias(1, 1);
    let b = s.alias(2, 1);
    assert_ne!(a, b);
    assert_eq!(s.alias(1, 1), a, "stable");
    // the alias selects the membership: no route table is consulted
    s.send(a, 10);
    s.send(b, 10);
    assert_eq!(s.eng.member(1).unwrap().rt.park.len(), 1);
    assert_eq!(s.eng.member(2).unwrap().rt.park.len(), 1);
    s.eng.check_identities().unwrap();
}
