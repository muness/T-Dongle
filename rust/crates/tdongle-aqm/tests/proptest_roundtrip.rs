//! Property tests (rule 6 of ADR 0001): marking round-trips through the classifier, never panics on any bytes, and keeps IPv4 checksums valid.

use proptest::prelude::*;
use tdongle_aqm::{EcnClass, classify, mark_ce, tcp_ecn_syn};

fn ipv4_checksum_ok(frame: &[u8]) -> bool {
    let ihl = usize::from(frame[14] & 15) * 4;
    let mut sum = 0u32;
    for pair in frame[14..14 + ihl].chunks(2) {
        sum += (u32::from(pair[0]) << 8) | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

/// An IPv4 frame with a valid header checksum, any TOS, protocol, options length and payload.
fn ipv4_frame() -> impl Strategy<Value = Vec<u8>> {
    (any::<u8>(), prop_oneof![Just(6u8), Just(17), Just(1), any::<u8>()], 5usize..=15, prop::collection::vec(any::<u8>(), 20..200)).prop_map(
        |(tos, proto, ihl_words, payload)| {
            let ihl = ihl_words * 4;
            let mut f = vec![0u8; 14 + ihl + payload.len()];
            f[12] = 0x08;
            f[14] = 0x40 | ihl_words as u8;
            f[15] = tos;
            let total = (ihl + payload.len()) as u16;
            f[16..18].copy_from_slice(&total.to_be_bytes());
            f[22] = 64;
            f[23] = proto;
            f[14 + ihl..].copy_from_slice(&payload);
            if proto == 6 {
                f[14 + ihl + 13] = 0x10; // ACK: not SYN/FIN/RST
            }
            let mut sum = 0u32;
            for pair in f[14..14 + ihl].chunks(2) {
                sum += (u32::from(pair[0]) << 8) | u32::from(pair[1]);
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let checksum = !(sum as u16);
            f[24..26].copy_from_slice(&checksum.to_be_bytes());
            f
        },
    )
}

proptest! {
    #[test]
    fn marking_a_capable_ipv4_frame_yields_ce_and_a_valid_checksum(frame in ipv4_frame()) {
        prop_assume!(ipv4_checksum_ok(&frame));
        if classify(&frame) == EcnClass::Capable {
            let mut marked = frame.clone();
            mark_ce(&mut marked);
            prop_assert_eq!(classify(&marked), EcnClass::Ce);
            prop_assert!(ipv4_checksum_ok(&marked));
            let changed: Vec<usize> = (0..frame.len()).filter(|&i| frame[i] != marked[i]).collect();
            prop_assert!(changed.iter().all(|&i| i == 15 || i == 24 || i == 25), "{changed:?}");
        }
    }

    #[test]
    fn nothing_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..1600), v6 in any::<bool>()) {
        let mut frame = bytes;
        if frame.len() >= 14 {
            frame[12] = if v6 { 0x86 } else { 0x08 };
            frame[13] = if v6 { 0xdd } else { 0x00 };
        }
        let class = classify(&frame);
        let _ = tcp_ecn_syn(&frame);
        if class == EcnClass::Capable {
            mark_ce(&mut frame);
            prop_assert_eq!(classify(&frame), EcnClass::Ce);
        }
    }

    #[test]
    fn every_prefix_is_safe(frame in ipv4_frame()) {
        for cut in 0..=frame.len() {
            let _ = classify(&frame[..cut]);
            let _ = tcp_ecn_syn(&frame[..cut]);
        }
    }
}
