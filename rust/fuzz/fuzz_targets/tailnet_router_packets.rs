#![no_main]
//! Fuzz the router: the first byte picks the direction, the rest is the IPv4 packet. A router with live memberships and aliases.
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_router::tables::AliasRecord;
use tdongle_tailnet_router::{GatewayRouter, HostOutcome, Member, MemberSet, TunnelOutcome, ALIAS_BASE, ROUTE_MTU};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, pkt)) = data.split_first() else { return };
    let mut r = GatewayRouter::new();
    let mut s = MemberSet::<16>::new();
    s.insert(Member { id: 1, vpn_ip: 0x6440_0001, ready: true });
    s.insert(Member { id: 2, vpn_ip: 0x6440_0002, ready: sel & 4 != 0 });
    r.publish(s);
    for i in 0..20u32 {
        r.alias_insert(AliasRecord { id: 1 + i % 2, peer: 0x6450_0000 + i, alias: ALIAS_BASE + i });
    }
    let mut now = 1000u64;
    // a few rounds so flows exist for the tunnel direction to hit
    for round in 0..3u64 {
        let mut p = pkt.to_vec();
        let g = r.usb_generation();
        if sel & 1 == 0 || round > 0 {
            if let HostOutcome::Forwarded { len, .. } = r.host_packet(&mut p, now, g) {
                assert!(len <= ROUTE_MTU);
            }
        }
        if sel & 2 != 0 {
            let mut q = pkt.to_vec();
            if let TunnelOutcome::ToHost { len, .. } = r.tunnel_packet(1 + (sel as u32 >> 3) % 2, &mut q, now) {
                assert!(len <= q.len());
            }
        }
        let mut out = [0u8; ROUTE_MTU];
        while r.hold_service(now, &mut out).is_some() {}
        if let Some(a) = r.begin_fill(now) {
            r.fill_done(a, None, now);
        }
        now += 50;
    }
});
