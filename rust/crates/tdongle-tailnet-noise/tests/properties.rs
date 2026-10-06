//! Property tests, tamper/truncate/oversize/reorder cases and a deterministic mini-fuzz.
mod common;
use common::*;
use proptest::prelude::*;
use tdongle_tailnet_noise::early::{EarlyError, EarlyReader, EarlyState, MAGIC, MAX_EARLY};
use tdongle_tailnet_noise::{
    Feed, HandshakeError, INITIATION_LEN, Initiator, MAX_PLAINTEXT, OpenError, RESPONSE_LEN, RecordReader, ResponseHeader, SealError, Session, responder,
};
use tdongle_tailnet_types::test_util::TestRng;

fn seal_all(tx: &mut Session, plains: &[Vec<u8>]) -> Vec<u8> {
    let mut wire = Vec::new();
    let mut buf = vec![0u8; 4096];
    for p in plains {
        let n = tx.seal_into(p, &mut buf).unwrap();
        wire.extend_from_slice(&buf[..n]);
    }
    wire
}

/// Feed `wire` in the given chunk sizes (cycled) and collect every record.
fn drain(rx: &mut Session, reader: &mut RecordReader, wire: &[u8], chunks: &[usize]) -> (Vec<Vec<u8>>, Option<OpenError>) {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut ci = 0;
    while pos < wire.len() {
        let size = chunks[ci % chunks.len()].max(1);
        ci += 1;
        let mut chunk = &wire[pos..(pos + size).min(wire.len())];
        pos += chunk.len();
        while !chunk.is_empty() {
            let (used, ev) = reader.feed(rx, chunk);
            chunk = &chunk[used..];
            match ev {
                Feed::NeedMore => assert!(chunk.is_empty()),
                Feed::Record(p) => out.push(p.to_vec()),
                Feed::Error(e) => return (out, Some(e)),
            }
        }
    }
    (out, None)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn reader_yields_exactly_the_sent_records_for_any_chunking(
        seed in 1u64..u64::MAX,
        lens in proptest::collection::vec(0usize..=MAX_PLAINTEXT, 1..6),
        chunks in proptest::collection::vec(1usize..5000, 1..12),
    ) {
        let (mut tx, mut rx) = pair(seed, 131);
        let mut rng = TestRng(seed ^ 0xabcdef);
        let plains: Vec<Vec<u8>> = lens.iter().map(|&n| rand_bytes(&mut rng, n)).collect();
        let wire = seal_all(&mut tx, &plains);
        let mut reader = RecordReader::new();
        let (got, err) = drain(&mut rx, &mut reader, &wire, &chunks);
        prop_assert_eq!(err, None);
        prop_assert_eq!(got, plains);
        prop_assert_eq!(reader.buffered(), 0);
        prop_assert_eq!(rx.stats().opened.get() as usize, lens.len());
        prop_assert_eq!(rx.stats().auth_failures.get(), 0);
    }

    #[test]
    fn a_flipped_bit_is_never_accepted(seed in 1u64..u64::MAX, len in 0usize..600, bit in 0usize..(8 * (3 + 600 + 16))) {
        let (mut tx, mut rx) = pair(seed, 131);
        let plain = vec![0x5a; len];
        let mut buf = vec![0u8; 4096];
        let n = tx.seal_into(&plain, &mut buf).unwrap();
        let bit = bit % (8 * n);
        let mut rec = buf[..n].to_vec();
        rec[bit / 8] ^= 1 << (bit % 8);
        let r = rx.open_record(&mut rec);
        prop_assert!(r.is_err());
        // also through the reader, at any chunking: never a Record
        let (_, mut rx2) = pair(seed, 131);
        let mut reader = RecordReader::new();
        let mut rec2 = buf[..n].to_vec();
        rec2[bit / 8] ^= 1 << (bit % 8);
        let (got, _err) = drain(&mut rx2, &mut reader, &rec2, &[7]);
        prop_assert!(got.is_empty());
    }

    #[test]
    fn truncated_records_are_refused_by_open_and_wait_in_the_reader(seed in 1u64..u64::MAX, len in 0usize..300, cut in 1usize..320) {
        let (mut tx, mut rx) = pair(seed, 131);
        let mut buf = vec![0u8; 4096];
        let n = tx.seal_into(&vec![1u8; len], &mut buf).unwrap();
        let keep = n.saturating_sub(cut);
        let mut rec = buf[..keep].to_vec();
        prop_assert!(rx.open_record(&mut rec).is_err());
        let (_, mut rx2) = pair(seed, 131);
        let mut reader = RecordReader::new();
        let (used, ev) = reader.feed(&mut rx2, &buf[..keep]);
        prop_assert_eq!(used, keep);
        prop_assert!(matches!(ev, Feed::NeedMore));
    }

    #[test]
    fn reader_never_panics_on_arbitrary_bytes(seed in 1u64..u64::MAX, data in proptest::collection::vec(any::<u8>(), 0..9000), chunk in 1usize..2000) {
        let (_, mut rx) = pair(seed, 131);
        let mut reader = RecordReader::new();
        let (got, _e) = drain(&mut rx, &mut reader, &data, &[chunk]);
        prop_assert!(got.is_empty()); // random bytes do not authenticate
    }
}

#[test]
fn zero_length_records_are_delivered() {
    let (mut tx, mut rx) = pair(9, 131);
    let wire = seal_all(&mut tx, &[vec![], b"a".to_vec(), vec![]]);
    assert_eq!(wire.len(), 19 + 20 + 19);
    let mut reader = RecordReader::new();
    let (got, err) = drain(&mut rx, &mut reader, &wire, &[1]);
    assert_eq!((got, err), (vec![vec![], b"a".to_vec(), vec![]], None));
}

#[test]
fn reordered_and_replayed_records_fail_and_kill_the_receiver() {
    let (mut tx, mut rx) = pair(2, 131);
    let mut buf = vec![0u8; 4096];
    let n1 = tx.seal_into(b"first", &mut buf).unwrap();
    let r1 = buf[..n1].to_vec();
    let n2 = tx.seal_into(b"second", &mut buf).unwrap();
    let r2 = buf[..n2].to_vec();
    // reorder
    let mut x = r2.clone();
    assert_eq!(rx.open_record(&mut x), Err(OpenError::AuthFailed));
    assert!(rx.rx_dead());
    let mut y = r1.clone();
    assert_eq!(rx.open_record(&mut y), Err(OpenError::Dead));
    assert_eq!((rx.stats().auth_failures.get(), rx.stats().rx_dead.get()), (1, 1));
    // replay on a fresh receiver
    let (_, mut rx) = pair(2, 131);
    let mut a = r1.clone();
    assert!(rx.open_record(&mut a).is_ok());
    let mut a = r1.clone();
    assert_eq!(rx.open_record(&mut a), Err(OpenError::AuthFailed));
}

#[test]
fn oversize_framing_is_refused_at_the_header() {
    let (_, mut rx) = pair(4, 131);
    let mut reader = RecordReader::new();
    // length 4094 > 4093
    let (used, ev) = reader.feed(&mut rx, &[4, 0x0f, 0xfe, 9, 9]);
    assert_eq!((used, ev), (3, Feed::Error(OpenError::Oversize)));
    assert_eq!(rx.stats().oversize.get(), 1);
    assert_eq!(reader.feed(&mut rx, &[1, 2, 3]), (0, Feed::Error(OpenError::Dead)));
    // 0xffff as in Tailscale's fuzz seeds
    let (_, mut rx) = pair(4, 131);
    let mut reader = RecordReader::new();
    assert_eq!(reader.feed(&mut rx, &[4, 0xff, 0xff]).1, Feed::Error(OpenError::Oversize));
    // wrong type, and a body shorter than a tag
    let (_, mut rx) = pair(4, 131);
    assert_eq!(RecordReader::new().feed(&mut rx, &[3, 0, 5]).1, Feed::Error(OpenError::BadType(3)));
    assert_eq!(RecordReader::new().feed(&mut rx, &[4, 0, 15]).1, Feed::Error(OpenError::TooShort));
    assert_eq!((rx.stats().bad_type.get(), rx.stats().bad_framing.get()), (1, 1));
    // open_record: longer than the length field, and shorter
    let mut v = vec![4, 0, 16];
    v.extend_from_slice(&[0; 20]);
    assert_eq!(rx.open_record(&mut v), Err(OpenError::LengthMismatch));
    let mut v = vec![4, 0, 40, 1, 2];
    assert_eq!(rx.open_record(&mut v), Err(OpenError::Truncated));
    let mut v = vec![4, 0];
    assert_eq!(rx.open_record(&mut v), Err(OpenError::Truncated));
    let mut v = vec![0u8; 4097];
    v[0] = 4;
    v[1] = 0x0f;
    v[2] = 0xfe;
    assert_eq!(rx.open_record(&mut v), Err(OpenError::Oversize));
}

#[test]
fn seal_limits() {
    let (mut tx, _) = pair(1, 131);
    let mut buf = vec![0u8; 4200];
    assert_eq!(tx.seal_record(&mut buf, MAX_PLAINTEXT + 1), Err(SealError::TooLong));
    assert_eq!(tx.seal_record(&mut buf, MAX_PLAINTEXT), Ok(4096));
    assert_eq!(tx.seal_record(&mut buf[..100], 90), Err(SealError::BufferTooSmall));
    tx.set_nonces_for_test(u64::MAX, 0);
    assert_eq!(tx.seal_record(&mut buf, 1), Err(SealError::Exhausted));
    assert_eq!(Session::plaintext_window(100), 3..84);
    assert!(Session::plaintext_window(5).is_empty());
    assert_eq!(Session::plaintext_window(9000), 3..4080);
}

#[test]
fn rx_counter_exhaustion_is_an_error_not_a_wrap() {
    let (mut tx, mut rx) = pair(1, 131);
    rx.set_nonces_for_test(0, u64::MAX);
    let mut buf = vec![0u8; 100];
    let n = tx.seal_into(b"x", &mut buf).unwrap();
    assert_eq!(rx.open_record(&mut buf[..n]), Err(OpenError::Exhausted));
}

#[test]
fn handshake_refusals_are_distinct() {
    let mut rng = TestRng(77);
    let mpriv = tdongle_tailnet_crypto::x25519::generate(&mut rng);
    let cpriv = tdongle_tailnet_crypto::x25519::generate(&mut rng);
    let cpub = tdongle_tailnet_crypto::x25519::public(&cpriv);
    let (init, msg1) = Initiator::new(&mpriv, &cpub, 131, &mut rng).unwrap();
    let acc = responder::accept(&cpriv, &msg1, &mut rng).unwrap();

    // server error message and wrong types
    let mut err = [0u8; 40];
    let n = responder::error_message(b"nope", &mut err);
    assert_eq!(ResponseHeader::parse(&[err[0], err[1], err[2]]), Ok(ResponseHeader::Error { len: 4 }));
    // (init is consumed by finish, so rebuild per case)
    let case = |resp: &[u8]| {
        let (i, _m) = Initiator::with_ephemeral(&mpriv, &cpub, 131, tdongle_tailnet_crypto::x25519::generate(&mut TestRng(5))).unwrap();
        i.finish(resp).map(|_| ())
    };
    assert_eq!(case(&err[..n]).unwrap_err(), HandshakeError::PeerRefused);
    assert_eq!(case(&[]).unwrap_err(), HandshakeError::Truncated);
    assert_eq!(case(&[4, 0, 48]).unwrap_err(), HandshakeError::UnexpectedType(4));
    assert_eq!(case(&[2, 0, 47]).unwrap_err(), HandshakeError::BadLength);
    assert_eq!(case(&acc.response[..50]).unwrap_err(), HandshakeError::Truncated);
    let mut long = acc.response.to_vec();
    long.push(0);
    assert_eq!(case(&long).unwrap_err(), HandshakeError::BadLength);
    // the response of another handshake does not authenticate (different ephemeral)
    assert_eq!(case(&acc.response).unwrap_err(), HandshakeError::AuthFailed);
    // the real one does
    assert!(init.finish(&acc.response).is_ok());

    // responder side
    assert_eq!(responder::accept(&cpriv, &msg1[..100], &mut rng).unwrap_err(), HandshakeError::Truncated);
    let mut bad = msg1;
    bad[2] = 2;
    assert_eq!(responder::accept(&cpriv, &bad, &mut rng).unwrap_err(), HandshakeError::UnexpectedType(2));
    let mut bad = msg1;
    bad[4] = 95;
    assert_eq!(responder::accept(&cpriv, &bad, &mut rng).unwrap_err(), HandshakeError::BadLength);
    // wrong server key
    let other = tdongle_tailnet_crypto::x25519::generate(&mut rng);
    assert_eq!(responder::accept(&other, &msg1, &mut rng).unwrap_err(), HandshakeError::AuthFailed);
    // low-order ephemeral (all zero) is refused as such
    let mut zero = msg1;
    zero[5..37].fill(0);
    assert_eq!(responder::accept(&cpriv, &zero, &mut rng).unwrap_err(), HandshakeError::LowOrderPoint);
    // and a low-order control key on the client
    assert_eq!(Initiator::new(&mpriv, &tdongle_tailnet_types::Key32::ZERO, 131, &mut rng).unwrap_err(), HandshakeError::LowOrderPoint);
}

/// Deterministic mini-fuzz: random and mutated inputs into every parser; nothing panics and nothing that is not byte-exact is accepted.
#[test]
fn mini_fuzz_handshake_and_reader() {
    let mut rng = TestRng(0xfeed_beef);
    let mpriv = tdongle_tailnet_crypto::x25519::generate(&mut rng);
    let cpriv = tdongle_tailnet_crypto::x25519::generate(&mut rng);
    let cpub = tdongle_tailnet_crypto::x25519::public(&cpriv);
    let (_, msg1) = Initiator::new(&mpriv, &cpub, 131, &mut rng).unwrap();
    let acc = responder::accept(&cpriv, &msg1, &mut rng).unwrap();
    let mut accepted_msg1 = 0;
    for i in 0..4000u32 {
        // random bytes of random length
        let len = (rand_bytes(&mut rng, 2).iter().fold(0usize, |a, &b| a * 256 + b as usize)) % 130;
        let junk = rand_bytes(&mut rng, len);
        assert!(responder::accept(&cpriv, &junk, &mut rng).is_err());
        let (init, _) = Initiator::new(&mpriv, &cpub, 131, &mut rng).unwrap();
        assert!(init.finish(&junk).is_err());
        // single-byte mutations of a valid msg1 / msg2
        let mut m = msg1;
        let pos = (i as usize) % INITIATION_LEN;
        m[pos] ^= 1 << (i % 8);
        if responder::accept(&cpriv, &m, &mut rng).is_ok() {
            accepted_msg1 += 1; // must never happen: the prologue binds the version bytes, the tags bind the rest
        }
        let (init, _) = Initiator::with_ephemeral(&mpriv, &cpub, 131, tdongle_tailnet_crypto::x25519::generate(&mut TestRng(1))).unwrap();
        let mut r = acc.response;
        r[(i as usize) % RESPONSE_LEN] ^= 1 << (i % 8);
        assert!(init.finish(&r).is_err());
    }
    assert_eq!(accepted_msg1, 0);
    // reader fed structured garbage: valid header prefixes with random bodies
    for i in 0..2000u32 {
        let (_, mut rx) = pair(u64::from(i) + 1, 131);
        let body_len = 16 + (i as usize * 37) % 400;
        let mut rec = vec![4u8, (body_len >> 8) as u8, body_len as u8];
        rec.extend_from_slice(&rand_bytes(&mut rng, body_len));
        let mut reader = RecordReader::new();
        let (got, err) = drain(&mut rx, &mut reader, &rec, &[1 + (i as usize % 13)]);
        assert!(got.is_empty() && err == Some(OpenError::AuthFailed));
    }
}

#[test]
fn early_payload_spanning_records_and_chunks() {
    let json = br#"{"nodeKeyChallenge":"chalpub:0000000000000000000000000000000000000000000000000000000000000000"}"#;
    let mut stream = MAGIC.to_vec();
    stream.extend_from_slice(&(json.len() as u32).to_be_bytes());
    stream.extend_from_slice(json);
    stream.extend_from_slice(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"); // an http/2 SETTINGS frame header follows
    for chunk in [1usize, 2, 5, 9, 10, 50, 1000] {
        let mut e = EarlyReader::new();
        let mut pos = 0;
        let mut state = EarlyState::NeedMore;
        while pos < stream.len() && state == EarlyState::NeedMore {
            let end = (pos + chunk).min(stream.len());
            let (n, s) = e.feed(&stream[pos..end]).unwrap();
            pos += n;
            state = s;
        }
        assert_eq!(state, EarlyState::Payload, "chunk {chunk}");
        assert_eq!(e.payload(), &json[..]);
        assert_eq!(&stream[pos..], b"\x00\x00\x00\x04\x00\x00\x00\x00\x00");
        assert_eq!(e.feed(b"x"), Err(EarlyError::Finished));
    }
}

#[test]
fn early_absent_returns_the_header_for_replay() {
    let h2 = [0u8, 0, 18, 4, 0, 0, 0, 0, 0, 1, 2, 3];
    for chunk in [1usize, 3, 9, 12] {
        let mut e = EarlyReader::new();
        let mut pos = 0;
        let mut state = EarlyState::NeedMore;
        while state == EarlyState::NeedMore {
            let (n, s) = e.feed(&h2[pos..(pos + chunk).min(h2.len())]).unwrap();
            pos += n;
            state = s;
        }
        assert_eq!(state, EarlyState::NotEarly);
        assert_eq!(e.header(), &h2[..9]);
        assert_eq!(pos, 9);
    }
    // a stream that looks like the magic for 4 bytes then diverges is still plain
    let mut e = EarlyReader::new();
    let s = [0xffu8, 0xff, 0xff, b'T', b'X', 0, 0, 0, 0, 7];
    assert_eq!(e.feed(&s).unwrap(), (9, EarlyState::NotEarly));
}

#[test]
fn early_cap_and_empty() {
    let mut e = EarlyReader::new();
    let mut h = MAGIC.to_vec();
    h.extend_from_slice(&(MAX_EARLY as u32 + 1).to_be_bytes());
    assert_eq!(e.feed(&h), Err(EarlyError::TooLarge(MAX_EARLY as u32 + 1)));
    let mut e = EarlyReader::new();
    let mut h = MAGIC.to_vec();
    h.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(e.feed(&h), Err(EarlyError::Empty));
    // exactly the cap is fine
    let mut e = EarlyReader::new();
    let mut h = MAGIC.to_vec();
    h.extend_from_slice(&(MAX_EARLY as u32).to_be_bytes());
    h.extend(core::iter::repeat_n(b'a', MAX_EARLY));
    assert_eq!(e.feed(&h).unwrap(), (9 + MAX_EARLY, EarlyState::Payload));
}

#[test]
fn state_sizes() {
    eprintln!(
        "sizes (host): Initiator {} B, Session {} B, RecordReader {} B, EarlyReader {} B",
        tdongle_tailnet_noise::INITIATOR_BYTES,
        tdongle_tailnet_noise::SESSION_BYTES,
        tdongle_tailnet_noise::READER_BYTES,
        tdongle_tailnet_noise::EARLY_BYTES
    );
    const { assert!(tdongle_tailnet_noise::READER_BYTES >= 4096) };
}

#[test]
fn cached_public_key_gives_identical_message() {
    let mpriv = tdongle_tailnet_types::Key32([5; 32]);
    let cpub = tdongle_tailnet_crypto::x25519::public(&tdongle_tailnet_types::Key32([6; 32]));
    let mpub = tdongle_tailnet_crypto::x25519::public(&mpriv);
    let (_, a) = Initiator::new(&mpriv, &cpub, 131, &mut TestRng(3)).unwrap();
    let (_, b) = Initiator::new_with_public(&mpriv, &mpub, &cpub, 131, &mut TestRng(3)).unwrap();
    assert_eq!(a, b);
}
