#![no_main]
//! Fuzz the DNS responder: any datagram from the USB net against a populated directory, then the same bytes as an upstream reply.
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_dns::{Action, Client, Directory, MemberView, PeerView, Responder};

struct D;
impl Directory for D {
    fn member_count(&self) -> usize {
        2
    }
    fn member(&self, i: usize) -> Option<MemberView<'_>> {
        Some(MemberView { id: 1 + i as u32, label: if i == 0 { "work" } else { "home" }, self_dns_name: if i == 0 { "gw.example.ts.net." } else { "gw.corp.ts.net" }, connected: true, session_valid: true, generation: 1, peer_count: 2 })
    }
    fn peer(&self, _: usize, j: usize) -> Option<PeerView<'_>> {
        Some(PeerView { hostname: if j == 0 { "server.example.ts.net" } else { "alpha" }, vpn_ip: 0x6440_0001 + j as u32 })
    }
    fn generation(&self, _: usize) -> u32 {
        1
    }
    fn alias(&self, _: u32, p: u32) -> Option<u32> {
        Some(0xc612_0000 + (p & 0xff))
    }
}

fuzz_target!(|data: &[u8]| {
    let mut r = Responder::new();
    let mut out = [0u8; 1500];
    let a = r.handle_query(data, Client { addr: 0xc0a8_4d02, port: 5 }, 100, &D, Some(0x0808_0808), &mut out);
    if let Action::Answer { len } | Action::Forward { len, .. } = a {
        assert!(len <= out.len());
    }
    let mut resp = data.to_vec();
    let _ = r.handle_upstream(&mut resp);
    let mut name = [0u8; tdongle_tailnet_dns::wire::NAME_MAX];
    let _ = tdongle_tailnet_dns::wire::read_name(data, 0, &mut name);
    r.expire(5000);
});
