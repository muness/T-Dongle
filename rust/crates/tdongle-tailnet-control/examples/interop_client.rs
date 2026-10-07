//! The Rust twin of `alternative/tailnet/tests/test_control_interop.c`: speaks plain HTTP/2 on stdin/stdout (the Noise layer replaced by the pipe) to the
//! Go harness `alternative/tailnet/tests/control_interop.go`. Argument `duplicate` makes it send a surplus SETTINGS ACK and expect the server's GOAWAY.
//!
//! Flow: preface, (duplicate ACK), `POST /machine/register` with `{}`, read the response, `POST /machine/map` (Stream, OmitPeers false, Version 131) on
//! stream 5, read one length-prefixed map message. Prints one line to stderr; exit status 0 only if everything matched.

use std::io::{Read, Write};
use tdongle_tailnet_control::h2::{Config, Event, Session};
use tdongle_tailnet_control::map::{MapEvent, MapStream, StreamEnd};
use tdongle_tailnet_control::requests::{Hostinfo, MapKind, MapRequest, STREAM_LONG_POLL, STREAM_REGISTER};
use tdongle_tailnet_types::Key32;

enum Owned {
    Idle,
    Data(u32, Vec<u8>),
    StreamEnd(u32),
    GoAway(u32),
    Reset(u32),
    Fatal(String),
    Other,
}

struct Io {
    buf: [u8; 4096],
    pos: usize,
    len: usize,
    stdin: std::io::Stdin,
    stdout: std::io::Stdout,
}

impl Io {
    fn flush(&mut self, s: &mut Session) {
        let mut tmp = [0u8; 128];
        loop {
            let n = s.poll_output(&mut tmp);
            if n == 0 {
                break;
            }
            self.stdout.write_all(&tmp[..n]).expect("write");
        }
        self.stdout.flush().expect("flush");
    }
    fn send(&mut self, bytes: &[u8]) {
        self.stdout.write_all(bytes).expect("write");
        self.stdout.flush().expect("flush");
    }
    /// The next interesting event, reading stdin when the buffer is empty.
    fn next(&mut self, s: &mut Session) -> Owned {
        loop {
            let (n, ev) = s.on_input(&self.buf[self.pos..self.len]);
            self.pos += n;
            let owned = match ev {
                Event::Idle if self.pos == self.len => None,
                Event::Idle | Event::Blocked => Some(Owned::Other),
                Event::Data { stream, bytes } => Some(Owned::Data(stream, bytes.to_vec())),
                Event::StreamEnd { stream } => Some(Owned::StreamEnd(stream)),
                Event::GoAway { code, .. } => Some(Owned::GoAway(code)),
                Event::Reset { stream, .. } => Some(Owned::Reset(stream)),
                Event::Fatal(e) => Some(Owned::Fatal(format!("{e:?}"))),
                Event::Closed => Some(Owned::Fatal("closed".into())),
                _ => Some(Owned::Other),
            };
            self.flush(s);
            if let Some(o) = owned {
                if !matches!(o, Owned::Other) {
                    return o;
                }
                continue;
            }
            let got = self.stdin.read(&mut self.buf).expect("read");
            if got == 0 {
                return Owned::Idle;
            }
            self.pos = 0;
            self.len = got;
        }
    }
}

fn main() {
    let duplicate = std::env::args().len() > 1;
    let mut s = Session::new(Config::default());
    let mut io = Io { buf: [0; 4096], pos: 0, len: 0, stdin: std::io::stdin(), stdout: std::io::stdout() };
    io.flush(&mut s);
    if duplicate {
        assert!(s.queue_settings_ack());
        io.flush(&mut s);
    }
    let mut req = [0u8; 1024];
    let n = s.write_request(&mut req, STREAM_REGISTER, "POST", "/machine/register", "localhost", "application/json", b"{}").expect("register request");
    io.send(&req[..n]);

    // RegisterResponse: stream-1 DATA until END_STREAM.
    let mut body = Vec::new();
    loop {
        match io.next(&mut s) {
            Owned::Data(1, b) => body.extend_from_slice(&b),
            Owned::StreamEnd(1) => break,
            Owned::GoAway(code) if duplicate => {
                assert_eq!(code, 1, "GOAWAY code");
                assert_eq!(s.close_info().error, 1);
                eprintln!("Duplicate ACK rejected: GOAWAY code={code}");
                return;
            }
            Owned::Fatal(e) if duplicate => {
                eprintln!("Duplicate ACK rejected locally: {e}");
                return;
            }
            Owned::Idle => panic!("connection ended during registration"),
            Owned::GoAway(c) => panic!("GOAWAY {c} during registration"),
            Owned::Reset(st) => panic!("RST_STREAM on {st}"),
            Owned::Fatal(e) => panic!("fatal {e}"),
            _ => {}
        }
    }
    assert!(!duplicate, "duplicate ACK was not rejected");
    assert_eq!(body, b"{}");
    assert_eq!(s.counters.settings_acks_sent.get(), 1);

    // Streaming MapRequest on stream 5, then one length-prefixed message.
    let (nk, dk) = (Key32([1; 32]), Key32([2; 32]));
    let map =
        MapRequest { node_key: &nk, disco_key: &dk, hostinfo: Hostinfo::new("localhost", 0), kind: MapKind::LongPoll { omit_peers: false }, endpoints: &[] };
    let mut json = [0u8; 600];
    let jn = map.write_json(&mut json).expect("map json");
    let n = s.write_request(&mut req, STREAM_LONG_POLL, "POST", "/machine/map", "localhost", "application/json", &json[..jn]).expect("map request");
    io.send(&req[..n]);

    let mut stream = MapStream::new(STREAM_LONG_POLL);
    let mut message = Vec::new();
    let mut maps = 0;
    'outer: loop {
        let ev = match io.next(&mut s) {
            Owned::Data(st, b) if st == STREAM_LONG_POLL => b,
            Owned::StreamEnd(st) if st == STREAM_LONG_POLL => panic!("map stream ended: {:?}", stream.on_end()),
            Owned::Idle => panic!("connection ended before the map"),
            Owned::GoAway(c) => panic!("GOAWAY {c}"),
            Owned::Reset(st) => panic!("RST_STREAM {st}"),
            Owned::Fatal(e) => panic!("fatal {e}"),
            _ => continue,
        };
        let mut rest = &ev[..];
        loop {
            let (n, e) = stream.framer.push(rest).expect("map framing");
            rest = &rest[n..];
            match e {
                Some(MapEvent::Start { .. }) => message.clear(),
                Some(MapEvent::Json(j)) => message.extend_from_slice(j),
                Some(MapEvent::End) => {
                    maps += 1;
                    stream.mark_applied();
                    break 'outer;
                }
                None if n == 0 => break,
                None => {}
            }
        }
    }
    let text = std::str::from_utf8(&message).expect("utf8");
    assert!(text.contains("\"Name\":\"fixture.ts.net\"") && text.contains("100.64.0.8/32"), "{text}");
    assert_eq!((maps, s.counters.settings_acks_sent.get()), (1, 1));
    let _ = StreamEnd::Clean;
    eprintln!("Rust H2 preface, HPACK/request builders, SETTINGS handling, registration reader and map reader interoperated");
}
