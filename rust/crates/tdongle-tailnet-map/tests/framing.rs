//! The length-prefixed stream: `test_stream.c`'s map-level cases (the HTTP/2 and Noise cases belong to the transport crates).

mod common;

use common::*;
use tdongle_tailnet_map::framing::*;
use tdongle_tailnet_map::*;

fn framed(json: &str) -> Vec<u8> {
    let mut v = (json.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(json.as_bytes());
    v
}

fn feed_all(f: &mut MapFramer, rec: &mut Rec, bytes: &[u8], chunk: usize) -> Result<u32, FrameError> {
    let mut n = 0;
    for c in bytes.chunks(chunk.max(1)) {
        n += f.feed(c, rec)?;
    }
    Ok(n)
}

#[test]
fn eighty_kb_map_in_257_byte_records() {
    let mut json = String::from("{\"Unused\":\"");
    json.push_str(&"x".repeat(80_000));
    json.push_str("\",\"Node\":{\"Name\":\"kept\"}}");
    let bytes = framed(&json);
    for chunk in [1, 3, 257, 16_000, bytes.len()] {
        let mut f = MapFramer::new(MapConfig::new(4));
        let mut rec = Rec::default();
        assert_eq!(feed_all(&mut f, &mut rec, &bytes, chunk), Ok(1), "{chunk}");
        assert_eq!(rec.self_node.as_ref().unwrap().name.as_ref().unwrap().as_str(), "kept");
        assert_eq!(f.declared_bytes() as usize, json.len());
        assert!(f.at_boundary() && f.end_of_stream().is_ok());
    }
}

#[test]
fn several_maps_in_one_read_and_split_anywhere() {
    let maps = ["{\"Node\":{\"Name\":\"a\"}}", "{\"KeepAlive\":true}", "{\"Peers\":[{\"ID\":1}]}", "{\"PeersRemoved\":[1]}"];
    let mut bytes = vec![];
    for m in maps {
        bytes.extend(framed(m));
    }
    for chunk in [1, 2, 5, 7, 31, bytes.len()] {
        let mut f = MapFramer::new(MapConfig::new(4));
        let mut rec = Rec::default();
        assert_eq!(feed_all(&mut f, &mut rec, &bytes, chunk), Ok(4));
        assert_eq!(rec.order.iter().filter(|e| **e == "commit").count(), 4, "chunk {chunk}");
        assert_eq!(f.maps_completed(), 4);
        assert_eq!(rec.staged.len(), 2);
        assert!(rec.keep_alive && rec.self_node.is_some());
    }
    // a split at every possible byte of two maps
    let two: Vec<u8> = framed(maps[0]).into_iter().chain(framed(maps[2])).collect();
    for cut in 0..two.len() {
        let mut f = MapFramer::new(MapConfig::new(4));
        let mut rec = Rec::default();
        let a = f.feed(&two[..cut], &mut rec).unwrap();
        let b = f.feed(&two[cut..], &mut rec).unwrap();
        assert_eq!(a + b, 2, "cut {cut}");
    }
}

#[test]
fn invalid_lengths_and_incomplete_messages() {
    let mut rec = Rec::default();
    let mut f = MapFramer::new(MapConfig::new(4));
    assert_eq!(f.feed(&[0, 0, 0, 0], &mut rec), Err(FrameError::BadLength(0)));
    assert_eq!(f.feed(b"{}", &mut rec), Err(FrameError::BadLength(0)), "failed until reset");
    assert_eq!(FrameError::BadLength(0).code(), 7);
    f.reset();
    let over = (MAX_MAP_BYTES + 1).to_le_bytes();
    assert_eq!(f.feed(&over, &mut rec), Err(FrameError::BadLength(MAX_MAP_BYTES + 1)));
    f.reset();
    // exactly the maximum is accepted (the length is only declared)
    assert_eq!(f.feed(&MAX_MAP_BYTES.to_le_bytes(), &mut rec), Ok(0));
    assert_eq!(f.remaining_bytes(), MAX_MAP_BYTES);
    // the stream ends inside a message / inside a prefix
    f.reset();
    let mut part = framed("{\"Peers\":[]}");
    part.truncate(10);
    assert_eq!(f.feed(&part, &mut rec), Ok(0));
    assert_eq!(f.end_of_stream(), Err(FrameError::EndedMidMessage));
    assert_eq!(FrameError::EndedMidMessage.code(), 12);
    f.reset();
    assert_eq!(f.feed(&[1, 0], &mut rec), Ok(0));
    assert_eq!(f.end_of_stream(), Err(FrameError::EndedMidMessage));
    // a clean end between messages is fine
    f.reset();
    assert_eq!(f.feed(&framed("{}"), &mut rec), Ok(1));
    assert_eq!(f.end_of_stream(), Ok(()));
}

#[test]
fn a_bad_message_aborts_and_stops_the_stream() {
    let mut f = MapFramer::new(MapConfig::new(4));
    let mut rec = Rec::default();
    let mut bytes = framed("{\"Peers\":[{\"ID\":1}],\"X\":bad}");
    bytes.extend(framed("{}"));
    let e = f.feed(&bytes, &mut rec).unwrap_err();
    assert!(matches!(e, FrameError::Map(MapError::Json(_))));
    assert_eq!(e.code(), 8);
    assert!(rec.aborted.is_some());
    assert_eq!(f.maps_completed(), 0);
    // a declared length that is shorter than the document: the document is cut and fails, not read past
    f.reset();
    let mut rec = Rec::default();
    let mut short = 5u32.to_le_bytes().to_vec();
    short.extend_from_slice(b"{\"a\":1}");
    assert!(matches!(f.feed(&short, &mut rec), Err(FrameError::Map(MapError::Incomplete))));
    // a declared length longer than the document: the rest is the next message's prefix and fails there
    f.reset();
    let mut rec = Rec::default();
    let mut long = 10u32.to_le_bytes().to_vec();
    long.extend_from_slice(b"{} ");
    assert_eq!(f.feed(&long, &mut rec), Ok(0));
    assert_eq!(f.end_of_stream(), Err(FrameError::EndedMidMessage));
}

#[test]
fn real_maps_through_the_framer_update_the_model_directory() {
    let mut f = MapFramer::new(MapConfig::new(1).with_flash_directory());
    let mut dir = Dir::default();
    let mut stream = vec![];
    for n in ["map-full.json", "map-keepalive.json", "map-delta.json"] {
        stream.extend(framed(&std::fs::read_to_string(format!("tests/fixtures/{n}")).unwrap()));
    }
    // deliver map by map, applying each commit as the firmware would
    struct Apply<'a>(&'a mut Dir, Vec<PeerRecord>);
    impl MapSink for Apply<'_> {
        fn event(&mut self, e: MapEvent<'_>) -> Result<(), SinkError> {
            match e {
                MapEvent::Peer(p) => self.1.push(p.clone()),
                MapEvent::Commit(s) => {
                    if !s.self_expired && (!self.1.is_empty() || s.authoritative) {
                        self.0.commit(&self.1, s.authoritative);
                    }
                    self.1.clear();
                }
                MapEvent::Abort(_) => self.1.clear(),
                _ => {}
            }
            Ok(())
        }
    }
    let mut sink = Apply(&mut dir, vec![]);
    let mut done = 0;
    for c in stream.chunks(997) {
        done += f.feed(c, &mut sink).unwrap();
    }
    assert_eq!(done, 3);
    assert!(dir.find_id(5).is_some() && dir.find_id(2).is_some() && dir.find_id(3).is_none());
    const { assert!(MapFramer::STATE_BYTES >= MapProjector::STATE_BYTES) };
}
