use proptest::prelude::*;
use tdongle_dhcp::*;

fn base(mac: u8, opts: Vec<u8>, flags: u16, ci: [u8; 4], gi: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 1;
    p[1] = 1;
    p[2] = 6;
    p[4..8].copy_from_slice(&[9, 8, 7, 6]);
    p[10..12].copy_from_slice(&flags.to_be_bytes());
    p[12..16].copy_from_slice(&ci);
    p[24..28].copy_from_slice(&gi);
    p[28..34].copy_from_slice(&[2, 0, 0, 0, 0, mac]);
    p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    p.extend_from_slice(&opts);
    p
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn arbitrary_bytes_never_panic_or_write_past_out(data in proptest::collection::vec(any::<u8>(), 0..1700), now in any::<u32>(), extra in 0usize..64) {
        let mut s = Server::new(Config::setup_ap()).unwrap();
        let mut buf = vec![0xA5u8; 1500 + 64];
        let outlen = (data.len().max(MIN_REPLY) + extra).min(buf.len());
        let (out, guard) = buf.split_at_mut(outlen);
        let r = s.handle(&data, now, out);
        prop_assert!(guard.iter().all(|&b| b == 0xA5));
        if let Some(r) = r { prop_assert!(r.len <= outlen); }
    }

    // Structured input reaches the reply paths; every reply keeps the framing a client checks.
    #[test]
    fn replies_keep_cookie_xid_and_chaddr(
        steps in proptest::collection::vec((1u8..14, proptest::collection::vec(any::<u8>(), 0..40), any::<u16>(), any::<[u8; 4]>(), any::<[u8; 4]>(), 0u8..9, any::<bool>(), 0u32..8000), 1..60)
    ) {
        let mut s = Server::new(Config::setup_ap()).unwrap();
        let mut now = 0u32;
        for (mac, mut opts, flags, ci, gi, ty, with_req, dt) in steps {
            now = now.wrapping_add(dt * 1000);
            let mut o = vec![53, 1, ty];
            if with_req { o.extend_from_slice(&[50, 4, 192, 168, 4, mac]); }
            o.append(&mut opts);
            let ci = if ci[0] & 1 == 0 { [0; 4] } else { ci };
            let gi = if gi[0] & 1 == 0 { [0; 4] } else { gi };
            let req = base(mac, o, flags, ci, gi);
            let mut out = [0u8; 1500];
            if let Some(r) = s.handle(&req, now, &mut out) {
                prop_assert_eq!(r.len, 548);
                prop_assert_eq!(out[0], 2);
                prop_assert_eq!(&out[4..8], &[9, 8, 7, 6]);
                prop_assert_eq!(&out[28..34], &[2, 0, 0, 0, 0, mac]);
                prop_assert_eq!(&out[236..240], &[0x63, 0x82, 0x53, 0x63]);
                prop_assert_eq!(&out[240..243][..2], &[53, 1]);
                prop_assert!(out[..r.len].contains(&255));
                if r.kind == ReplyKind::Offer || r.kind == ReplyKind::Ack {
                    prop_assert!(r.yiaddr[..3] == [192, 168, 4] && (2..=101).contains(&r.yiaddr[3]));
                }
            }
            prop_assert!(s.lease_count() <= 8);
            let mut seen = [0u8; 256];
            for i in 0..s.lease_count() {
                let l = s.lease(i).unwrap();
                prop_assert!((2..=101).contains(&l.ip[3]));
                prop_assert_eq!(seen[l.ip[3] as usize], 0, "an address leased twice");
                seen[l.ip[3] as usize] = 1;
            }
        }
    }
}
