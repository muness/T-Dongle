//! The IN NTB builder against an independent parser of the layout (what a host does), and the elastic policy.

use tdongle_usb_out::elastic::{self, Step};
use tdongle_usb_out::ntb_in::*;

/// A host's reading of an NTB-16: NTH checks, then the NDP entries.
fn parse(ntb: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(&ntb[0..4], b"NCMH");
    assert_eq!(u16::from_le_bytes([ntb[4], ntb[5]]), 12);
    assert_eq!(usize::from(u16::from_le_bytes([ntb[8], ntb[9]])), ntb.len(), "wBlockLength is the transfer length");
    let ndp = usize::from(u16::from_le_bytes([ntb[10], ntb[11]]));
    assert_eq!(&ntb[ndp..ndp + 4], b"NCM0");
    let ndp_len = usize::from(u16::from_le_bytes([ntb[ndp + 4], ntb[ndp + 5]]));
    assert!(ndp_len >= 16 && ndp_len % 4 == 0);
    let mut out = Vec::new();
    let mut e = ndp + 8;
    loop {
        let idx = usize::from(u16::from_le_bytes([ntb[e], ntb[e + 1]]));
        let len = usize::from(u16::from_le_bytes([ntb[e + 2], ntb[e + 3]]));
        if idx == 0 && len == 0 {
            break;
        }
        assert_eq!(idx % 4, 0, "wNdpInDivisor 4, remainder 0");
        out.push(ntb[idx..idx + len].to_vec());
        e += 4;
    }
    assert_eq!(e + 4 - ndp, ndp_len, "the NDP length covers the entries and the terminator");
    out
}

fn frame(i: usize, len: usize) -> Vec<u8> {
    (0..len).map(|k| ((i * 31 + k) % 251) as u8).collect()
}

#[test]
fn one_datagram_and_many_round_trip() {
    for lens in [vec![60], vec![1514], vec![60, 1514, 99, 14, 1000], (0..8).map(|i| 14 + i * 3).collect::<Vec<_>>()] {
        let mut b = NtbBuilder::<3200>::new();
        let frames: Vec<_> = lens.iter().enumerate().map(|(i, &l)| frame(i, l)).collect();
        for f in &frames {
            assert!(b.push(f), "{lens:?}");
        }
        assert_eq!(parse(b.finish(7)), frames);
    }
}

#[test]
fn it_stops_at_eight_datagrams_or_at_the_size_limit_and_never_overruns() {
    let mut b = NtbBuilder::<3200>::new();
    for i in 0..MAX_DATAGRAMS {
        assert!(b.push(&frame(i, 60)));
    }
    assert!(!b.push(&frame(9, 60)), "a ninth datagram does not fit the NDP");
    assert_eq!(parse(b.finish(0)).len(), MAX_DATAGRAMS);
    let mut b = NtbBuilder::<3200>::new();
    assert!(b.push(&frame(0, 1514)));
    assert!(b.push(&frame(1, 1514)));
    assert!(!b.push(&frame(2, 1514)), "12 + 2 x 1516 + the NDP leaves too little for a third full frame");
    assert!(b.len() <= 3200);
    assert_eq!(parse(b.finish(1)).len(), 2);
    assert!(!NtbBuilder::<3200>::new().fits(0));
}

#[test]
fn clear_starts_over_and_the_sequence_is_carried() {
    let mut b = NtbBuilder::<3200>::new();
    b.push(&frame(0, 100));
    let first = b.finish(41).to_vec();
    assert_eq!(u16::from_le_bytes([first[6], first[7]]), 41);
    b.clear();
    assert!(b.is_empty());
    assert!(b.push(&frame(1, 50)));
    assert_eq!(parse(b.finish(42)), vec![frame(1, 50)]);
}

#[test]
fn unaligned_lengths_keep_every_datagram_aligned_and_the_block_length_exact() {
    let mut b = NtbBuilder::<3200>::new();
    let frames: Vec<_> = [61, 63, 65, 1501, 17].iter().enumerate().map(|(i, &l)| frame(i, l)).collect();
    for f in &frames {
        assert!(b.push(f));
    }
    let ntb = b.finish(3).to_vec();
    assert_eq!(parse(&ntb), frames);
    assert_eq!(ntb.len(), usize::from(u16::from_le_bytes([ntb[8], ntb[9]])));
}

#[test]
fn the_elastic_policy_follows_adr_0023() {
    let chunk = 2 * 1524;
    // idle ring at the base: nothing
    assert_eq!(elastic::step(0, 8, chunk, 60_000, 0), Step::None);
    // a burst fills the base: grow while the heap allows (floor 29,884 + the chunk)
    assert_eq!(elastic::step(7, 8, chunk, 60_000, 0), Step::Grow);
    assert_eq!(elastic::step(8, 8, chunk, 60_000, 0), Step::Grow);
    assert_eq!(elastic::step(7, 8, chunk, elastic::FLOOR_FREE + chunk - 1, 0), Step::DeniedHeap);
    assert_eq!(elastic::step(7, 8, chunk, elastic::FLOOR_FREE + chunk, 0), Step::Grow);
    // never past 28 slots
    assert_eq!(elastic::step(27, 28, chunk, 100_000, 0), Step::None);
    assert_eq!(elastic::MAX_SLOTS, 28);
    // idle for 2 s with room: shrink one chunk, never below the base
    assert_eq!(elastic::step(0, 12, chunk, 60_000, 2_000), Step::Shrink);
    assert_eq!(elastic::step(0, 12, chunk, 60_000, 1_999), Step::None);
    assert_eq!(elastic::step(0, 8, chunk, 60_000, 10_000), Step::None);
    assert_eq!(elastic::step(11, 12, chunk, 60_000, 5_000), Step::Grow, "busy wins over idle");
    // a chunk that is still in use is not freed
    assert_eq!(elastic::step(11, 14, chunk, 60_000, 5_000), Step::None);
}

#[test]
fn a_single_frame_costs_what_the_first_spike_sent_and_a_burst_shares_the_headers() {
    let mut b = NtbBuilder::<3200>::new();
    assert!(b.push(&frame(0, 1442)));
    let one = b.finish(0).len();
    assert_eq!(one, 12 + 1444 + 16, "NTH + the aligned frame + a one-entry NDP");
    assert!(one <= 28 + 1442 + 4, "no more than the 28-byte-header NTB it replaces, plus alignment");
    b.clear();
    for i in 0..2 {
        assert!(b.push(&frame(i, 1442)));
    }
    assert!(!b.push(&frame(2, 1442)));
    // two frames in one NTB: 12 + 2 x 1444 + (8 + 4 x 3), instead of two NTBs of 1472
    assert_eq!(b.finish(1).len(), 12 + 2 * 1444 + 20);
    assert!(12 + 2 * 1444 + 20 < 2 * one);
    b.clear();
    // small frames (ACKs, 60 bytes): eight in one NTB
    for i in 0..8 {
        assert!(b.push(&frame(i, 60)));
    }
    assert_eq!(b.finish(2).len(), 12 + 8 * 60 + 8 + 4 * 9);
}
