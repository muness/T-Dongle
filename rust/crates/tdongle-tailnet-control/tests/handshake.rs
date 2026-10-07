//! Ports of the C tests that exercise the plaintext layers together: `test_h2_handshake.c` (every split of the early payload and the HTTP/2 bytes after
//! it, nothing lost between them), `test_control_send.c`'s observable (a request goes out as one contiguous byte run) and the control interop flow against
//! an in-process HTTP/2 server model.

use tdongle_tailnet_control::early::{EarlyReader, EarlyStatus};
use tdongle_tailnet_control::h2::{Config, Event, FrameHeader, Session, flag, kind};
use tdongle_tailnet_control::http::{UpgradeReader, UpgradeStatus};
use tdongle_tailnet_control::map::{MapEvent, MapStream};
use tdongle_tailnet_control::requests::{Hostinfo, MapKind, MapRequest, RegisterOutcome, STREAM_LONG_POLL, STREAM_REGISTER, parse_register_response};
use tdongle_tailnet_types::Key32;

const JSON: &str = r#"{"nodeKeyChallenge":"chalpub:0101010101010101010101010101010101010101010101010101010101010101"}"#;
const SETTINGS: [u8; 15] = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0];
const UPGRADE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n";

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = FrameHeader { length: payload.len() as u32, kind, flags, stream }.encode().to_vec();
    v.extend_from_slice(payload);
    v
}

fn early_plain() -> Vec<u8> {
    let mut v = vec![255, 255, 255, b'T', b'S', 0, 0, 0, JSON.len() as u8];
    v.extend_from_slice(JSON.as_bytes());
    v.extend_from_slice(&SETTINGS);
    v
}

/// The server side as the client sees it: HTTP upgrade answer, then (stand-in for decrypted Noise records) the early payload and a SETTINGS frame, cut
/// into pieces of `piece` bytes at every offset. The client must find the challenge, then hand the SETTINGS to HTTP/2, which ACKs it exactly once.
fn run(piece: usize, shift: usize) {
    let mut wire = UPGRADE.to_vec();
    wire.extend(early_plain());
    let mut up = UpgradeReader::new();
    let mut buf = [0u8; 1024];
    let mut early = EarlyReader::new(&mut buf);
    let mut s = Session::new(Config::default());
    let mut drained = vec![0u8; 256];
    let _ = s.poll_output(&mut drained);
    let mut switched = false;
    let mut challenge = None;
    let mut acks = 0;
    let mut early_done = false;
    let mut fed_to_h2 = 0;
    let mut first = true;
    let mut off = 0;
    while off < wire.len() {
        let len = if first { piece.min(shift.max(1)) } else { piece };
        first = false;
        let mut chunk = &wire[off..(off + len).min(wire.len())];
        off += chunk.len();
        while !chunk.is_empty() {
            if !switched {
                let (n, st) = up.push(chunk).unwrap();
                chunk = &chunk[n..];
                switched = st == UpgradeStatus::Switched;
            } else if !early_done {
                let (n, st) = early.push(chunk).unwrap();
                chunk = &chunk[n..];
                match st {
                    EarlyStatus::NeedMore => {}
                    EarlyStatus::Present { challenge: c } => {
                        challenge = c;
                        early_done = true;
                    }
                    EarlyStatus::Absent { .. } => panic!("early payload expected"),
                }
            } else {
                let (n, ev) = s.on_input(chunk);
                fed_to_h2 += n;
                chunk = &chunk[n..];
                if matches!(ev, Event::Settings { ack: false }) {
                    acks += 1;
                }
                let mut tmp = [0u8; 64];
                while s.poll_output(&mut tmp) > 0 {}
            }
        }
    }
    assert_eq!(challenge, Some(Key32([1; 32])), "piece {piece}");
    assert_eq!(fed_to_h2, SETTINGS.len());
    assert_eq!(acks, 1);
    assert_eq!(s.counters.settings_acks_sent.get(), 1);
}

#[test]
fn every_split_of_upgrade_early_and_settings() {
    for piece in 1..140 {
        for shift in 1..piece.max(2) {
            run(piece, shift);
        }
    }
}

#[test]
fn custom_coordinator_without_early_payload_replays_into_http2() {
    let mut wire = frame(kind::SETTINGS, 0, 0, &[0, 4, 0, 1, 0, 0]);
    wire.extend(frame(kind::SETTINGS, flag::ACK, 0, &[]));
    for piece in 1..wire.len() {
        let mut buf = [0u8; 1024];
        let mut early = EarlyReader::new(&mut buf);
        let mut s = Session::new(Config::default());
        let mut tmp = [0u8; 64];
        while s.poll_output(&mut tmp) > 0 {}
        let mut replay = None;
        let mut rest_after = vec![];
        for c in wire.chunks(piece) {
            if replay.is_some() {
                rest_after.extend_from_slice(c);
                continue;
            }
            let (n, st) = early.push(c).unwrap();
            if let EarlyStatus::Absent { replay: r } = st {
                replay = Some(r);
                rest_after.extend_from_slice(&c[n..]);
            }
        }
        let mut h2_bytes = replay.expect("absent").to_vec();
        h2_bytes.extend(rest_after);
        assert_eq!(h2_bytes, wire);
        let (mut settings, mut acked, mut rest) = (0, 0, &h2_bytes[..]);
        loop {
            let (n, ev) = s.on_input(rest);
            rest = &rest[n..];
            match ev {
                Event::Settings { ack: false } => settings += 1,
                Event::Settings { ack: true } => acked += 1,
                Event::Idle => break,
                _ => {}
            }
        }
        assert_eq!((settings, acked, s.counters.settings_acks_sent.get()), (1, 1, 1));
    }
}

/// The client side of `control_interop.go`'s exchange against canned server bytes (the Go server itself is exercised by `examples/interop_client.rs`).
fn client_flow(piece: usize) {
    let mut c = Session::new(Config::default());
    let mut to_server = vec![];
    let mut tmp = [0u8; 128];
    loop {
        let n = c.poll_output(&mut tmp);
        if n == 0 {
            break;
        }
        to_server.extend_from_slice(&tmp[..n]);
    }
    assert!(to_server.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    let nk = Key32([1; 32]);
    let mut req = [0u8; 1024];
    let n = c.write_request(&mut req, STREAM_REGISTER, "POST", "/machine/register", "localhost", "application/json", b"{}").unwrap();
    to_server.extend_from_slice(&req[..n]);
    // The server's answer: SETTINGS, ACK of ours, HEADERS(200), DATA("{}") + END_STREAM.
    let mut reply = frame(kind::SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 250, 0, 4, 0, 0x10, 0, 0, 0, 5, 0, 0, 0x40, 0]);
    reply.extend(frame(kind::SETTINGS, flag::ACK, 0, &[]));
    reply.extend(frame(
        kind::HEADERS,
        flag::END_HEADERS,
        1,
        &[0x88, 0x5f, 0x10, b'a', b'p', b'p', b'l', b'i', b'c', b'a', b't', b'i', b'o', b'n', b'/', b'j', b's', b'o', b'n'],
    ));
    reply.extend(frame(kind::DATA, 0, 1, b"{}"));
    reply.extend(frame(kind::DATA, flag::END_STREAM, 1, b""));
    let mut body = vec![];
    let mut status = None;
    let mut ended = false;
    for chunk in reply.chunks(piece) {
        let mut rest = chunk;
        loop {
            let (n, ev) = c.on_input(rest);
            rest = &rest[n..];
            match ev {
                Event::Headers { status: s, .. } => status = s,
                Event::Data { stream: 1, bytes } => body.extend_from_slice(bytes),
                Event::StreamEnd { stream: 1 } => ended = true,
                Event::Idle => break,
                Event::Fatal(e) => panic!("{e:?}"),
                _ => {}
            }
            while c.poll_output(&mut tmp) > 0 {}
        }
    }
    assert!(ended && status == Some(200));
    assert_eq!(parse_register_response(&body), Ok(RegisterOutcome::Registered { machine_authorized: false }));
    assert_eq!(c.counters.settings_acks_sent.get(), 1);
    // Map: write the request, then read one message delivered as DATA in awkward pieces.
    let dk = Key32([2; 32]);
    let m =
        MapRequest { node_key: &nk, disco_key: &dk, hostinfo: Hostinfo::new("localhost", 0), kind: MapKind::LongPoll { omit_peers: false }, endpoints: &[] };
    let mut json = [0u8; 512];
    let jn = m.write_json(&mut json).unwrap();
    c.write_request(&mut req, STREAM_LONG_POLL, "POST", "/machine/map", "localhost", "application/json", &json[..jn]).unwrap();
    let payload = br#"{"Node":{"Name":"fixture.ts.net","Addresses":["100.64.0.8/32"]},"Peers":[]}"#;
    let mut data = (payload.len() as u32).to_le_bytes().to_vec();
    data.extend_from_slice(payload);
    let mut wire = vec![];
    for part in data.chunks(piece.max(1)) {
        wire.extend(frame(kind::DATA, 0, STREAM_LONG_POLL, part));
    }
    wire.extend(frame(kind::DATA, flag::END_STREAM, STREAM_LONG_POLL, b""));
    let mut ms = MapStream::new(STREAM_LONG_POLL);
    let mut got = vec![];
    let mut rest = &wire[..];
    'o: loop {
        let (n, ev) = c.on_input(rest);
        rest = &rest[n..];
        while c.poll_output(&mut tmp) > 0 {}
        if let Some(bytes) = ms.data(&ev).unwrap() {
            let mut b = bytes;
            loop {
                let (k, e) = ms.framer.push(b).unwrap();
                b = &b[k..];
                match e {
                    Some(MapEvent::Json(j)) => got.extend_from_slice(j),
                    Some(MapEvent::End) => break 'o,
                    None if k == 0 => break,
                    _ => {}
                }
            }
        }
        if ev == Event::Idle {
            break;
        }
    }
    assert_eq!(got, payload);
}

#[test]
fn register_then_map_flow_in_any_chunking() {
    for piece in [1, 2, 3, 5, 7, 11, 13, 64, 1000] {
        client_flow(piece);
    }
}
