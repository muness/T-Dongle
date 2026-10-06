use tdongle_dhcp::{Config, Dest, ReplyKind, Server};

fn discover(mac: u8) -> [u8; 300] {
    let mut p = [0u8; 300];
    p[0] = 1; p[1] = 1; p[2] = 6;
    p[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    p[10] = 0x80;
    p[28..34].copy_from_slice(&[2, 0, 0, 0, 0, mac]);
    p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    p[240..243].copy_from_slice(&[53, 1, 1]);
    p[243] = 255;
    p
}

#[test]
fn first_discover_offers_pool_start() {
    let mut s = Server::new(Config::setup_ap()).unwrap();
    assert_eq!(s.pool(), ([192, 168, 4, 2], [192, 168, 4, 101]));
    let mut out = [0u8; 1500];
    let r = s.handle(&discover(1), 0, &mut out).unwrap();
    assert_eq!(r.kind, ReplyKind::Offer);
    assert_eq!(r.yiaddr, [192, 168, 4, 2]);
    assert_eq!(r.dest, Dest::Broadcast);
    assert_eq!(&out[4..8], &[0xde, 0xad, 0xbe, 0xef]);
}
