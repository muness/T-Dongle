//! The DHCP server takes any frame the USB host sends: no panic, at most 8 leases, every address in the pool and unique.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_usbnet::dhcp::{DhcpConfig, DhcpOutcome, DhcpServer, REPLY_BUF};

fuzz_target!(|data: &[u8]| {
    let mut s = DhcpServer::<8>::new(DhcpConfig::c([2, 1, 2, 3, 4, 5]));
    let mut out = [0u8; REPLY_BUF];
    let mut now = 0u64;
    // frames separated by a 2-byte big-endian length
    let mut rest = data;
    while rest.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        let (frame, after) = rest[2..].split_at(n);
        if let DhcpOutcome::Reply { len, .. } = s.handle_frame(now, frame, &mut out) {
            assert!((14 + 28 + 240..=REPLY_BUF).contains(&len));
        }
        now += 1000;
        rest = after;
    }
    assert!(s.lease_count() <= 8);
    let mut ips = [0u32; 8];
    for (i, (_, ip)) in s.leases().enumerate() {
        assert!((s.config().pool_start..=s.config().pool_end).contains(&ip));
        assert!(!ips[..i].contains(&ip));
        ips[i] = ip;
    }
});
