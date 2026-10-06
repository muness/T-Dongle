//! The engine's own network duties: netcheck picks the DERP home region, STUN learns the public endpoint, DNS forwards what is not tailnet, and the
//! receive queue budget.

mod common;
use common::*;
use tdongle_tailnet_admission::probe::HeapSnapshot;
use tdongle_tailnet_admission::wg_rx::Verdict;
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_dns::Client;
use tdongle_tailnet_engine::{Handled, Input, Out};

const A_EP: Ep = Ep::v4([203, 0, 113, 1], 41641);

#[test]
fn netcheck_homes_on_the_nearest_region_and_stun_learns_the_public_endpoint() {
    let mut s = Sim::new(1);
    s.regions = std::vec![(1, [192, 0, 2, 1]), (2, [192, 0, 2, 2])];
    s.stun_servers.clear();
    s.stun_servers.insert([192, 0, 2, 1], 90); // far
    s.stun_servers.insert([192, 0, 2, 2], 8); // near
    let a = s.add_node("a", 1, 0x6440_0001, A_EP);
    s.netmap(a, &[]);
    s.enable(a);
    s.run_until(s.now + 3_000);
    let n = &s.nodes[a];
    // the map said region 1 is home; netcheck found region 2 faster
    assert!(
        n.outs.iter().any(|o| matches!(o, Owned::HomeDerp(2))),
        "{:?}",
        n.outs.iter().filter(|o| matches!(o, Owned::HomeDerp(_) | Owned::DerpConnect { .. })).collect::<Vec<_>>()
    );
    assert!(n.outs.iter().any(|o| matches!(o, Owned::DerpConnect { region: 2, .. })));
    assert_eq!(n.eng.status(s.now).members[0].unwrap().home_derp, 2);
    // STUN told the engine its public mapping (the sim NAT maps it to itself) and the control plane is told
    assert!(n.outs.iter().any(|o| matches!(o, Owned::Endpoint(e) if *e == A_EP)));
    assert!(n.eng.status(s.now).members[0].unwrap().has_public_ep);
    // everything the schedule needs is a wake: after the last tick nothing is scheduled but the STUN refresh and the DISCO second
    s.check();
}

#[test]
fn dns_answers_tailnet_names_and_forwards_the_rest_upstream_with_a_timeout() {
    let mut s = Solo::new(2);
    s.member(1, 2, 0);
    s.input(Input::DnsUpstream(Some(0x0808_0808)));
    let q = dns_query(0x1111, "example.org");
    let before = s.outs.len();
    s.input(Input::Dns { client: Client { addr: HOST_IP, port: 4000 }, data: &q });
    let fwd = s.outs[before..].iter().find_map(|o| if let Owned::DnsForward(d) = o { Some(d.clone()) } else { None }).expect("forwarded");
    // the id was rewritten; a reply with that id and question comes back to the asking host with its own id restored
    assert_ne!(&fwd[..2], &q[..2]);
    let mut reply = fwd.clone();
    reply[2] |= 0x80;
    let n = s.outs.len();
    s.input(Input::DnsUpstreamReply { data: &mut reply });
    let ans = s.outs[n..].iter().find_map(|o| if let Owned::Dns(d) = o { Some(d.clone()) } else { None }).expect("relayed");
    assert_eq!(&ans[..2], &q[..2]);
    // a query nobody answers times out and the wake says when
    s.input(Input::Dns { client: Client { addr: HOST_IP, port: 4001 }, data: &dns_query(0x2222, "slow.example") });
    assert!(s.wake.is_some_and(|w| w <= s.now + 2_000 + 1));
    s.advance(2_500);
    s.eng.check_identities().unwrap();
    // not from the USB network: dropped silently
    let before = s.outs.len();
    s.input(Input::Dns { client: Client { addr: 0x0a00_0001, port: 4000 }, data: &q });
    assert!(!s.outs[before..].iter().any(|o| matches!(o, Owned::Dns(_) | Owned::DnsForward(_))));
    // tailnet names are never forwarded: an unknown name inside the domain is answered NXDOMAIN
    let before = s.outs.len();
    s.input(Input::Dns { client: Client { addr: HOST_IP, port: 4002 }, data: &dns_query(3, "nobody.m1.tailnet") });
    let a = s.outs[before..].iter().find_map(|o| if let Owned::Dns(d) = o { Some(d.clone()) } else { None }).expect("answered");
    assert_eq!(a[3] & 15, 3, "NXDOMAIN");
    let _ = Out::Wake(None);
}

#[test]
fn the_receive_queue_budget_is_one_counter_and_follows_the_heap() {
    let mut s = Solo::new(3);
    s.member(1, 1, 0);
    s.eng.set_heap(HeapSnapshot { free: usize::MAX / 2, largest: 1 << 20, minimum: 0 });
    let mut queued = 0;
    while s.eng.rx_enqueue(1264) == Verdict::Ok {
        queued += 1;
    }
    assert_eq!(queued, 9, "12 KiB holds nine full datagrams");
    assert_eq!(s.eng.rx_enqueue(1264), Verdict::Bytes);
    for _ in 0..queued {
        s.eng.rx_dequeue(1264);
    }
    assert_eq!(s.eng.rx_budget().queued(), 0);
    s.eng.set_heap(HeapSnapshot { free: 1000, largest: 1000, minimum: 0 });
    assert_eq!(s.eng.rx_enqueue(1264), Verdict::Heap);
    assert_eq!(s.eng.heap_refusals().get(tdongle_tailnet_admission::heap::HbSite::WgCopy), 1);
    let _ = Handled::Done;
}

#[test]
fn a_map_without_the_home_region_reconnects_the_relay_elsewhere() {
    let mut s = Sim::new(8);
    let a = s.add_node("a", 1, 0x6440_0001, A_EP);
    s.netmap(a, &[]);
    s.enable(a);
    s.run_until(s.now + 2_000);
    assert!(s.nodes[a].outs.iter().any(|o| matches!(o, Owned::DerpConnect { region: 1, .. })));
    s.regions = std::vec![(3, [192, 0, 2, 3])];
    s.stun_servers.insert([192, 0, 2, 3], 10);
    s.netmap(a, &[]);
    assert!(
        s.nodes[a].outs.iter().any(|o| matches!(o, Owned::DerpConnect { region: 3, .. })),
        "{:?}",
        s.nodes[a].outs.iter().filter(|o| matches!(o, Owned::DerpConnect { .. })).collect::<Vec<_>>()
    );
    s.check();
}
