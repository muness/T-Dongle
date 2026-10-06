//! The setup access point's DHCP server takes any UDP datagram a client on the open network sends to port 67.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_dhcp::{Config, Server};

fuzz_target!(|data: &[u8]| {
    // First byte: how many millisecond-clock steps, so lease expiry and eviction are reached; the rest is split into datagrams by a 2-byte length.
    let Some((&steps, mut rest)) = data.split_first() else { return };
    let mut s = Server::new(Config::setup_ap()).unwrap();
    let mut now = u32::from(steps) << 24;
    while rest.len() >= 2 {
        let n = (usize::from(rest[0]) << 2 | usize::from(rest[1] >> 6)).min(rest.len() - 2);
        let (pkt, tail) = rest[2..].split_at(n);
        rest = tail;
        now = now.wrapping_add(u32::from(rest.first().copied().unwrap_or(0)) * 700_000);
        let mut out = [0xA5u8; 1500 + 16];
        if let Some(r) = s.handle(pkt, now, &mut out[..1500]) {
            assert!(r.len >= 548 && r.len <= 1500);
            assert_eq!(&out[236..240], &[0x63, 0x82, 0x53, 0x63]);
            assert_eq!(out[0], 2);
        }
        assert!(out[1500..].iter().all(|&b| b == 0xA5));
        assert!(s.lease_count() <= 8);
    }
});
