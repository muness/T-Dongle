//! The console writer: any length goes out whole, in packets, and an overflow is never silent.

use core::fmt::Write;
use tdongle_serial::out::{LineBuf, TRUNCATED, packets};

/// What a host sees on the IN endpoint: packets concatenated; a transfer ends at a short packet (a zero-length packet counts).
fn host_receives(packets: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in packets {
        out.extend_from_slice(p);
        if p.len() < 64 {
            return out; // the transfer is complete
        }
    }
    panic!("the transfer never ended: the host would wait for more (missing ZLP)");
}

#[test]
fn a_two_kilobyte_line_goes_out_whole() {
    let text: String = (0..2048).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    let mut line = LineBuf::<4096>::new();
    write!(line, "{text}").unwrap();
    assert!(!line.overflowed());
    let pk: Vec<&[u8]> = packets(line.finish(), 64).collect();
    assert_eq!(pk.len(), 2048 / 64 + 1, "32 full packets and the ZLP: 2048 is a multiple of 64");
    assert!(pk[..32].iter().all(|p| p.len() == 64) && pk[32].is_empty());
    assert_eq!(host_receives(&pk), text.as_bytes());
}

#[test]
fn every_length_round_trips_including_the_packet_boundaries() {
    for len in (0..=300).chain([511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096]) {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let pk: Vec<&[u8]> = packets(&data, 64).collect();
        if data.is_empty() {
            assert!(pk.is_empty());
            continue;
        }
        assert_eq!(host_receives(&pk), data, "len {len}");
        assert!(pk.iter().all(|p| p.len() <= 64));
    }
}

#[test]
fn the_boot_status_that_was_cut_at_300_characters_fits_and_arrives() {
    // the real line is about 650 bytes; the old buffers were 320 and 400
    let line = format!(
        "{{\"schema\":1,\"rwdt\":{{\"cfg0\":\"0xb007ee00\",\"hold\":771270}},\"sup\":{{\"ticks\":1,\"feeds\":1}},\"rescue\":{{\"state\":\"armed\",\"count\":0}},\"pad\":\"{}\"}}\r\n",
        "x".repeat(500)
    );
    assert!(line.len() > 600);
    let mut buf = LineBuf::<2048>::new();
    buf.write_str(&line).unwrap();
    assert!(!buf.overflowed());
    let pk: Vec<&[u8]> = packets(buf.finish(), 64).collect();
    assert_eq!(host_receives(&pk), line.as_bytes());
}

#[test]
fn an_overflow_is_reported_and_marked_never_silent() {
    let mut buf = LineBuf::<100>::new();
    let long = "y".repeat(2048);
    assert!(buf.write_str(&long).is_err());
    assert!(buf.overflowed());
    let sent = buf.finish().to_vec();
    assert!(sent.len() <= 100);
    assert!(sent.ends_with(TRUNCATED), "a client can see the reply was cut");
    // exactly full is not an overflow
    let mut exact = LineBuf::<8>::new();
    exact.write_str("12345678").unwrap();
    assert!(!exact.overflowed());
    assert_eq!(exact.finish(), b"12345678");
    // a buffer smaller than the marker still never panics
    let mut tiny = LineBuf::<4>::new();
    assert!(tiny.write_str("abcdefgh").is_err());
    assert!(tiny.finish().len() <= 4);
}
