//! Differential tests against Go: `disco/disco_test.go` and `net/stun/stun_test.go` (tailscale.com v1.104.0) and a Go program in
//! `golang.org/x/crypto/nacl/box` that sealed the very messages of `disco_test.go` under fixed keys and a fixed nonce
//! (how: see the comment on `Case`).
//!
//! This is what pins the NaCl box layout, the shared-key derivation and the whole envelope to what a Tailscale node produces and accepts.

use hex_literal::hex;
use tdongle_tailnet_crypto::{nacl, x25519};
use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_disco::envelope::{self, PeerResolver, RxOutcome, process};
use tdongle_tailnet_disco::msg::{Message, Ping, Pong};
use tdongle_tailnet_disco::stun::{self, BindingResponse, StunError};
use tdongle_tailnet_types::Key32;

const A_SEC: [u8; 32] = hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
const A_PUB: [u8; 32] = hex!("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c");
const B_SEC: [u8; 32] = hex!("808386898c8f9295989b9ea1a4a7aaadb0b3b6b9bcbfc2c5c8cbced1d4d7dadd");
const B_PUB: [u8; 32] = hex!("8a76b3762dc802d32acff174e09421787d07c347a6ce1772291f68f08e53f376");
const NONCE: [u8; 24] = hex!("00050a0f14191e23282d32373c41464b50555a5f64696e73");
const SHARED: [u8; 32] = hex!("d551b4c449bedd4bc13288b39030de98bc1dd0c43c8511a723b2375dd1e2e4f6");

/// How these were made: Go 1.23, `golang.org/x/crypto` v0.31.0, `aSec[i]=i+1; bSec[i]=0x80+3i; nonce[i]=5i`,
/// `sealed = box.Seal(nil, plaintext, &nonce, &bPub, &aSec)`, `packet = magic || aPub || nonce || sealed`; the plaintexts are the hex strings of
/// `TestMarshalAndParse`; the STUN request and response bytes come from `stun.Request` / `stun.Response` of v1.104.0 run on txid `a0 a7 ae ...`.
struct Case {
    name: &'static str,
    plain: &'static [u8],
    sealed: &'static [u8],
    packet: &'static [u8],
}

const CASES: &[Case] = &[
    Case {
        name: "ping_nodekey",
        plain: &hex!("01000102030405060708090a0b0c0001020000000000000000000000000000000000000000000000000000001e1f"),
        sealed: &hex!("e96896fcef451fd148d5c282da721cde306cec8c292b00660449b672b55133a7a89f974aa9bf7fa4e7e054956a05983551e7a5569268d30ebd950efe1619"),
        packet: &hex!(
            "5453f09f92ac07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c00050a0f14191e23282d32373c41464b50555a5f64696e73e96896fcef451fd148d5c282da721cde306cec8c292b00660449b672b55133a7a89f974aa9bf7fa4e7e054956a05983551e7a5569268d30ebd950efe1619"
        ),
    },
    Case {
        name: "ping_padding",
        plain: &hex!("01000102030405060708090a0b0c000000"),
        sealed: &hex!("2e67a0baeec9dd728e7a96cf01cf1601306cec8c292b00660449b672b55133a6aa"),
        packet: &hex!(
            "5453f09f92ac07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c00050a0f14191e23282d32373c41464b50555a5f64696e732e67a0baeec9dd728e7a96cf01cf1601306cec8c292b00660449b672b55133a6aa"
        ),
    },
    Case {
        name: "pong_v4",
        plain: &hex!("02000102030405060708090a0b0c00000000000000000000ffff0203040504d2"),
        sealed: &hex!("f3fe94945a642728128fa9ca07e93892336cec8c292b00660449b672b55133a6aa9f974aa9bf7fa4181f56966e009ce7"),
        packet: &hex!(
            "5453f09f92ac07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c00050a0f14191e23282d32373c41464b50555a5f64696e73f3fe94945a642728128fa9ca07e93892336cec8c292b00660449b672b55133a6aa9f974aa9bf7fa4181f56966e009ce7"
        ),
    },
    Case {
        name: "pong_v6",
        plain: &hex!("02000102030405060708090a0b0cfed000000000000000000000000000121a0a"),
        sealed: &hex!("a7e66b26a3933f275d58099621adfc1d336cec8c292b00660449b672b551cd76aa9f974aa9bf7fa4e7e054956a17823f"),
        packet: &hex!(
            "5453f09f92ac07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c00050a0f14191e23282d32373c41464b50555a5f64696e73a7e66b26a3933f275d58099621adfc1d336cec8c292b00660449b672b551cd76aa9f974aa9bf7fa4e7e054956a17823f"
        ),
    },
    Case {
        name: "cmm_two",
        plain: &hex!("030000000000000000000000ffff010203040237200100000000000000000000000034560315"),
        sealed: &hex!("3d0ba0ca5885f1aad16c3f3f2b68e035326ced8e2a2f05600341bf7841a232a4a99b957d89be7fa4e7e054956a05983551e79100917d"),
        packet: &hex!(
            "5453f09f92ac07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c00050a0f14191e23282d32373c41464b50555a5f64696e733d0ba0ca5885f1aad16c3f3f2b68e035326ced8e2a2f05600341bf7841a232a4a99b957d89be7fa4e7e054956a05983551e79100917d"
        ),
    },
    Case {
        name: "cmm_empty",
        plain: &hex!("0300"),
        sealed: &hex!("c1e486d90d2a5d3d7e3c7828efc9c1e7326c"),
        packet: &hex!(
            "5453f09f92ac07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c00050a0f14191e23282d32373c41464b50555a5f64696e73c1e486d90d2a5d3d7e3c7828efc9c1e7326c"
        ),
    },
];

const STUN_REQ: [u8; 40] = hex!("000100142112a4420102030405060708090a0b0c802200087461696c6e6f646580280004b32c370f");
const STUN_REQ2: [u8; 40] = hex!("000100142112a442a0a7aeb5bcc3cad1d8dfe6ed802200087461696c6e6f646580280004a34f2a9f");
const STUN_RESP_V4: [u8; 32] = hex!("0101000c2112a442a0a7aeb5bcc3cad1d8dfe6ed002000080001eb7eea12d54b");
const STUN_RESP_V6: [u8; 44] = hex!("010100182112a442a0a7aeb5bcc3cad1d8dfe6ed00200014000283bb0113a9faa0a7aeb5bcc3cad1d8dee6ef");

const STUN_GO_RESPONSES: &[(&str, &[u8], Ep)] = &[
    ("google-1", &hex!("0101000c2112a4422360b11e3ec68ffa93e08007002000080001c7866957856f"), Ep::v4([72, 69, 33, 45], 59028)),
    ("google-2", &hex!("0101000c2112a442f9f121cbde7d7c75923ce271002000080001c7876957856f"), Ep::v4([72, 69, 33, 45], 59029)),
    (
        "stun-sipgate-net-10000",
        &hex!(
            "010100442112a442482eb64715e8b28eaead6444000100080001e4ab4845212d0004000800012710d90a44980005000800012711d9747a8a802000080001c5b96957856f80220010566f766964612e6f726720302e393600"
        ),
        Ep::v4([72, 69, 33, 45], 58539),
    ),
    (
        "stun-powervoip-com-3478",
        &hex!("010100242112a4427e57966829f444609d1deaa6000100080001e9d34845212d0004000800010d964d48a9d40005000800010d974d48a9d5"),
        Ep::v4([72, 69, 33, 45], 59859),
    ),
    (
        "in-process-pion-server",
        &hex!("010100242112a442ebc2d36ef471217c4f3e308e8022000a656e64706f696e7465720000002000080001ce665e12a44380280004b699bb02010100242112a442"),
        Ep::v4([127, 0, 0, 1], 61300),
    ),
    (
        "stuntman-server-ipv6",
        &hex!(
            "010100482112a44206f56685d28af3e69ce341e200010014000290ce260200d1b4cfc10038b231fffeef96f6802b001400020d962604a880000200d10000000000c57001002000140002b1dc0710a493b23aa785ea38c219620cd714"
        ),
        Ep::v6([38, 2, 0, 209, 180, 207, 193, 0, 56, 178, 49, 255, 254, 239, 150, 246], 37070),
    ),
    ("software-a", &hex!("010100142112a442ebc2d36ef471217c4f3e308e8022000161000000002000080001ce665e12a443"), Ep::v4([127, 0, 0, 1], 61300)),
    ("software-abc", &hex!("010100142112a442ebc2d36ef471217c4f3e308e8022000361626300002000080001ce665e12a443"), Ep::v4([127, 0, 0, 1], 61300)),
    ("no-4in6", &hex!("010100182112a4424fd5d202dcb37d31fc773306002000140002cd3d2112a4424fd5d202dcb382ce2dc3fcc7"), Ep::v4([209, 180, 207, 193], 60463)),
];

fn key(b: [u8; 32]) -> Key32 {
    Key32(b)
}

#[test]
fn x25519_and_precompute_match_go() {
    assert_eq!(x25519::public(&key(A_SEC)).0, A_PUB);
    assert_eq!(x25519::public(&key(B_SEC)).0, B_PUB);
    // Go: box.Precompute(&shared, &bPub, &aSec); the other side derives the same secret.
    assert_eq!(nacl::precompute(&key(A_SEC), &key(B_PUB)).unwrap().0, SHARED);
    assert_eq!(nacl::precompute(&key(B_SEC), &key(A_PUB)).unwrap().0, SHARED);
}

#[test]
fn box_layout_matches_go_for_every_message() {
    for c in CASES {
        // Go's box.Seal output is `tag (16) || ciphertext`, which is the layout secretbox_seal produces in place.
        let mut buf = [0u8; 256];
        buf[16..16 + c.plain.len()].copy_from_slice(c.plain);
        let n = nacl::box_seal(&key(A_SEC), &key(B_PUB), &NONCE, &mut buf[..16 + c.plain.len()]).unwrap();
        assert_eq!(&buf[..n], c.sealed, "{} box", c.name);

        // The whole envelope, built by the crate's own sealer from the parsed message, equals Go's packet.
        let mut pkt = [0u8; 256];
        let shared = key(SHARED);
        let n = envelope::seal_with(&mut pkt, &key(A_PUB), &shared, &NONCE, |b| {
            b[..c.plain.len()].copy_from_slice(c.plain);
            Ok(c.plain.len())
        })
        .unwrap();
        assert_eq!(&pkt[..n], c.packet, "{} packet", c.name);
    }
}

#[test]
fn encoders_produce_go_packets() {
    let tx = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let (a_pub, shared) = (key(A_PUB), key(SHARED));
    let mut nk = [0u8; 32];
    nk[1] = 1;
    nk[2] = 2;
    nk[30] = 30;
    nk[31] = 31;
    let mut out = [0u8; 256];
    let by_name = |n: &str| CASES.iter().find(|c| c.name == n).unwrap().packet;

    let n = envelope::seal_ping(&mut out, &a_pub, &shared, &NONCE, &Ping { txid: tx, node_key: Some(&nk), padding: 0 }).unwrap();
    assert_eq!(&out[..n], by_name("ping_nodekey"));
    let n = envelope::seal_ping(&mut out, &a_pub, &shared, &NONCE, &Ping { txid: tx, node_key: None, padding: 3 }).unwrap();
    assert_eq!(&out[..n], by_name("ping_padding"));
    let n = envelope::seal_pong(&mut out, &a_pub, &shared, &NONCE, &Pong { txid: tx, src: Ep::v4([2, 3, 4, 5], 1234) }).unwrap();
    assert_eq!(&out[..n], by_name("pong_v4"));
    let v6 = Ep::v6([0xfe, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12], 6666);
    let n = envelope::seal_pong(&mut out, &a_pub, &shared, &NONCE, &Pong { txid: tx, src: v6 }).unwrap();
    assert_eq!(&out[..n], by_name("pong_v6"));
    let eps = [Ep::v4([1, 2, 3, 4], 567), Ep::v6([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x34, 0x56], 789)];
    let n = envelope::seal_call_me_maybe(&mut out, &a_pub, &shared, &NONCE, &eps).unwrap();
    assert_eq!(&out[..n], by_name("cmm_two"));
    let n = envelope::seal_call_me_maybe(&mut out, &a_pub, &shared, &NONCE, &[]).unwrap();
    assert_eq!(&out[..n], by_name("cmm_empty"));
}

/// The receiving side: B opens what Go sealed from A.
struct Bob;
impl PeerResolver for Bob {
    fn resident(&mut self, sender: &[u8; 32]) -> Option<(u8, Key32)> {
        (*sender == A_PUB).then(|| (1, nacl::precompute(&key(B_SEC), &key(A_PUB)).unwrap()))
    }
    fn candidate(&mut self, _: &[u8; 32]) -> Option<(u32, Key32)> {
        None
    }
    fn activate(&mut self, _: u32) -> Option<u8> {
        None
    }
}

#[test]
fn go_packets_open_and_parse() {
    for c in CASES {
        let mut pkt = c.packet.to_vec();
        let rx = process(&mut pkt, &mut Bob).unwrap_or_else(|e| panic!("{}: {e:?}", c.name));
        assert_eq!(rx.peer, 1);
        match (c.name, rx.message) {
            ("ping_nodekey", Message::Ping(p)) => assert!(p.node_key.is_some() && p.padding == 0),
            ("ping_padding", Message::Ping(p)) => assert!(p.node_key.is_none() && p.padding == 3),
            ("pong_v4", Message::Pong(p)) => assert_eq!(p.src, Ep::v4([2, 3, 4, 5], 1234)),
            ("pong_v6", Message::Pong(p)) => assert_eq!(p.src.port(), 6666),
            ("cmm_two", Message::CallMeMaybe { endpoints, lax }) => assert!(!lax && endpoints.len() == 2),
            ("cmm_empty", Message::CallMeMaybe { endpoints, lax }) => assert!(!lax && endpoints.is_empty()),
            (n, m) => panic!("{n}: {m:?}"),
        }
    }
}

#[test]
fn tampering_with_a_go_packet_is_always_rejected() {
    for c in CASES {
        for i in 0..c.packet.len() {
            for bit in [0x01u8, 0x80] {
                let mut pkt = c.packet.to_vec();
                pkt[i] ^= bit;
                let r = process(&mut pkt, &mut Bob);
                assert!(r.is_err(), "{} byte {i} bit {bit:#x} was accepted", c.name);
            }
        }
        // truncated at every length
        for n in 0..c.packet.len() {
            let mut pkt = c.packet[..n].to_vec();
            assert!(process(&mut pkt, &mut Bob).is_err(), "{} truncated to {n}", c.name);
        }
    }
}

#[test]
fn wrong_receiver_key_cannot_open() {
    struct Eve;
    impl PeerResolver for Eve {
        fn resident(&mut self, s: &[u8; 32]) -> Option<(u8, Key32)> {
            // Eve has A's public key in her table but her own secret.
            (*s == A_PUB).then(|| (1, nacl::precompute(&key([0x33; 32]), &key(A_PUB)).unwrap()))
        }
        fn candidate(&mut self, _: &[u8; 32]) -> Option<(u32, Key32)> {
            None
        }
        fn activate(&mut self, _: u32) -> Option<u8> {
            None
        }
    }
    for c in CASES {
        let mut pkt = c.packet.to_vec();
        assert_eq!(process(&mut pkt, &mut Eve).unwrap_err(), RxOutcome::OpenFailed);
    }
}

#[test]
fn go_stun_requests_and_responses() {
    let mut out = [0u8; stun::REQUEST_LEN];
    stun::build_request(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], &mut out);
    assert_eq!(out, STUN_REQ);
    let tx2: [u8; 12] = core::array::from_fn(|i| 0xa0 + (i as u8) * 7);
    stun::build_request(&tx2, &mut out);
    assert_eq!(out, STUN_REQ2);
    assert_eq!(stun::parse_binding_request(&STUN_REQ2), Ok(tx2));

    let mut b = [0u8; 64];
    let n = stun::build_response(&tx2, &Ep::v4([203, 0, 113, 9], 51820), &mut b).unwrap();
    assert_eq!(&b[..n], &STUN_RESP_V4);
    let n = stun::build_response(&tx2, &Ep::v6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2], 41641), &mut b).unwrap();
    assert_eq!(&b[..n], &STUN_RESP_V6);
}

/// `TestParseResponse`: every response of Go's table.
#[test]
fn go_stun_response_table() {
    for (name, data, want) in STUN_GO_RESPONSES {
        let r = stun::parse_response(data).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(r.mapped, *want, "{name}");
        assert_eq!(&r.txid[..], &data[8..20], "{name}");
    }
}

/// `TestResponse`: build and parse for v4 and v6, ports on and off the 0x2112 boundary.
#[test]
fn go_stun_response_round_trip() {
    for (n, ep) in [
        (1u8, Ep::v4([1, 2, 3, 4], 254)),
        (2, Ep::v4([1, 2, 3, 4], 257)),
        (3, Ep::v6([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4], 254)),
        (4, Ep::v6([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4], 257)),
    ] {
        let tx = [n; 12];
        let mut b = [0u8; 64];
        let len = stun::build_response(&tx, &ep, &mut b).unwrap();
        assert_eq!(stun::parse_response(&b[..len]), Ok(BindingResponse { txid: tx, mapped: ep, xor: true }));
    }
}

#[test]
fn go_stun_no_4in6_is_unmapped() {
    // "no-4in6": an IPv6-family attribute carrying ::ffff:209.180.207.193 is reported as the IPv4 address.
    let r = stun::parse_response(&hex!("010100182112a4424fd5d202dcb37d31fc773306002000140002cd3d2112a4424fd5d202dcb382ce2dc3fcc7")).unwrap();
    assert_eq!(r.mapped, Ep::v4([209, 180, 207, 193], 60463));
    assert!(r.mapped.is_v4());
}

#[test]
fn stun_malformed_variants_are_rejected_not_skipped() {
    // an attribute that claims more than the message holds, a mapped address of an unknown family, and a truncated header
    let good = STUN_RESP_V4;
    let mut b = good;
    b[23] = 0x20; // attribute length 32 > what remains
    assert_eq!(stun::parse_response(&b), Err(StunError::MalformedAttrs));
    let mut b = good;
    b[25] = 7;
    assert_eq!(stun::parse_response(&b), Err(StunError::MalformedAttrs));
    assert_eq!(stun::parse_response(&good[..19]), Err(StunError::NotStun));
    // a request is not a response
    assert_eq!(stun::parse_response(&STUN_REQ), Err(StunError::NotSuccessResponse));
}
