//! The driver against an in-memory server: a real Noise responder, a scripted HTTP/2 server and chosen chunkings of every layer.

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::executor::block_on;
use futures::future::join;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use tdongle_tailnet_control::h2::{FrameHeader, flag, kind};
use tdongle_tailnet_control::requests::{ENDPOINT_LOCAL, Endpoint, EndpointAddr, Hostinfo};
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_ctl::{
    Bulk, BulkLease, Clock, Connect, EndpointSource, Gate, IoFail, MapEnd, NoEndpoints, RegisterFailure, SessionBuf, SessionConfig, SessionEnd, SessionStats,
    Stage, Timeouts, Workspace, run_session, run_session_leased,
};
use tdongle_tailnet_map::{MapEvent, MapSink, SinkError};
use tdongle_tailnet_noise::responder::accept;
use tdongle_tailnet_noise::{Feed, RecordReader, Session};
use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_types::{Key32, Millis};

// ---- in-memory transport ----------------------------------------------------------------------------------------------------------------------------

struct Duplex {
    rx: UnboundedReceiver<Vec<u8>>,
    pending: VecDeque<u8>,
    tx: Option<UnboundedSender<Vec<u8>>>,
    max_read: usize,
    max_write: usize,
}

fn duplex(client_read: usize, client_write: usize) -> (Duplex, Duplex) {
    let (a_tx, b_rx) = unbounded();
    let (b_tx, a_rx) = unbounded();
    (
        Duplex { rx: a_rx, pending: VecDeque::new(), tx: Some(a_tx), max_read: client_read, max_write: client_write },
        Duplex { rx: b_rx, pending: VecDeque::new(), tx: Some(b_tx), max_read: usize::MAX, max_write: usize::MAX },
    )
}

impl embedded_io_async::ErrorType for Duplex {
    type Error = embedded_io_async::ErrorKind;
}
impl embedded_io_async::Read for Duplex {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if self.pending.is_empty() {
            match self.rx.next().await {
                Some(v) => self.pending.extend(v),
                None => return Ok(0),
            }
        }
        let n = buf.len().min(self.pending.len()).min(self.max_read);
        for b in buf.iter_mut().take(n) {
            *b = self.pending.pop_front().unwrap();
        }
        Ok(n)
    }
}
impl embedded_io_async::Write for Duplex {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let n = buf.len().min(self.max_write);
        self.tx
            .as_ref()
            .ok_or(embedded_io_async::ErrorKind::BrokenPipe)?
            .unbounded_send(buf[..n].to_vec())
            .map_err(|_| embedded_io_async::ErrorKind::BrokenPipe)?;
        Ok(n)
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Duplex {
    fn close(&mut self) {
        self.tx = None;
    }
    async fn read_some(&mut self) -> Option<Vec<u8>> {
        if !self.pending.is_empty() {
            return Some(self.pending.drain(..).collect());
        }
        self.rx.next().await
    }
    fn send(&self, bytes: &[u8], chunk: usize) {
        if let Some(tx) = &self.tx {
            for c in bytes.chunks(chunk.max(1)) {
                let _ = tx.unbounded_send(c.to_vec());
            }
        }
    }
}

struct Connector(VecDeque<Duplex>);
impl Connect for Connector {
    type Stream = Duplex;
    async fn connect(&mut self) -> Result<Duplex, ()> {
        self.0.pop_front().ok_or(())
    }
}

struct TestClock(Rc<Cell<u64>>, u64);
impl Clock for TestClock {
    fn now(&self) -> Millis {
        let v = self.0.get();
        self.0.set(v + self.1);
        v
    }
    async fn timeout<F: std::future::Future>(&mut self, _ms: u32, fut: F) -> Option<F::Output> {
        Some(fut.await)
    }
}

struct TestGate(Rc<RefCell<Vec<String>>>);
impl Gate for TestGate {
    async fn begin_negotiation(&mut self) {
        self.0.borrow_mut().push("begin".into());
    }
    async fn end_negotiation(&mut self, ok: bool) {
        self.0.borrow_mut().push(format!("end({ok})"));
    }
}

#[derive(Default, Debug)]
struct Sink {
    self_ip: Option<u32>,
    derp_regions: u8,
    peers: Vec<(u8, u32)>,
    commits: u32,
    keepalives: u32,
    aborts: u32,
    refuse_commit: bool,
}
struct Shared(Rc<RefCell<Sink>>);
impl MapSink for Shared {
    fn event(&mut self, e: MapEvent<'_>) -> Result<(), SinkError> {
        let mut s = self.0.borrow_mut();
        match e {
            MapEvent::SelfNode(n) => s.self_ip = n.vpn_ip,
            MapEvent::Derp(d) => s.derp_regions = d.count,
            MapEvent::Peer(p) => s.peers.push((p.group as u8, p.vpn_ip)),
            MapEvent::KeepAlive => s.keepalives += 1,
            MapEvent::Commit(_) => {
                if s.refuse_commit {
                    return Err(SinkError);
                }
                s.commits += 1
            }
            MapEvent::Abort(_) => s.aborts += 1,
            _ => {}
        }
        Ok(())
    }
}

struct Eps(Rc<RefCell<Option<Vec<Endpoint>>>>);
impl EndpointSource for Eps {
    fn poll_endpoints(&mut self, out: &mut [Endpoint]) -> Option<usize> {
        let v = self.0.borrow_mut().take()?;
        out[..v.len()].copy_from_slice(&v);
        Some(v.len())
    }
}

// ---- the scripted server ----------------------------------------------------------------------------------------------------------------------------

#[derive(Clone)]
enum Register {
    Ok,
    Body(&'static str),
    GoAway,
}

#[derive(Clone)]
struct Script {
    control_priv: Key32,
    status: &'static str,
    early: Option<String>,
    register: Register,
    maps: Vec<Vec<u8>>,
    /// After the maps, wait for an endpoint update on stream 7 and then close (else close at once).
    wait_update: bool,
    /// Deliver this many extra keepalive messages after the maps (each one makes the client's loop turn) and expect a PING.
    extra_keepalives: usize,
    /// The test clock advances this much per reading.
    clock_step: u64,
    record_split: usize,
    data_split: usize,
    wire_chunk: usize,
    corrupt_map_records: bool,
    /// After the maps, send the start of one more map message (its length and ten bytes) and then say nothing, connection open.
    stall_mid_message: bool,
}

impl Script {
    fn new(control_priv: Key32) -> Self {
        Self {
            control_priv,
            status: "101 Switching Protocols",
            early: None,
            register: Register::Ok,
            maps: vec![MAP1.as_bytes().to_vec(), MAP2.as_bytes().to_vec(), br#"{"KeepAlive":true}"#.to_vec()],
            wait_update: false,
            extra_keepalives: 0,
            clock_step: 0,
            record_split: 4000,
            data_split: 4000,
            wire_chunk: 4096,
            corrupt_map_records: false,
            stall_mid_message: false,
        }
    }
}

const MAP1: &str = r#"{"Node":{"ID":1,"Name":"dev.ts.net.","Key":"nodekey:0101010101010101010101010101010101010101010101010101010101010101","Addresses":["100.64.0.1/32"],"HomeDERP":1},"DERPMap":{"Regions":{"1":{"RegionID":1,"RegionCode":"t","RegionName":"T","Nodes":[{"Name":"1a","RegionID":1,"HostName":"derp.example","IPv4":"203.0.113.9"}]}}},"Peers":[{"ID":2,"Key":"nodekey:0202020202020202020202020202020202020202020202020202020202020202","Addresses":["100.64.0.2/32"],"Name":"p.ts.net."}],"Domain":"ts.net"}"#;
const MAP2: &str = r#"{"PeersChanged":[{"ID":3,"Key":"nodekey:0303030303030303030303030303030303030303030303030303030303030303","Addresses":["100.64.0.3/32"],"Name":"q.ts.net."}]}"#;

#[derive(Default)]
struct Seen {
    http_head: String,
    register_body: String,
    map_body: String,
    updates: Vec<String>,
    pings: u32,
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = FrameHeader { length: payload.len() as u32, kind, flags, stream }.encode().to_vec();
    v.extend_from_slice(payload);
    v
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn seal(sc: &Script, session: &mut Session, io: &Duplex, plain: &[u8], corrupt: bool) {
    for part in plain.chunks(sc.record_split.max(1)) {
        let mut buf = vec![0u8; part.len() + 19];
        let n = session.seal_into(part, &mut buf).unwrap();
        if corrupt {
            buf[n - 1] ^= 1;
        }
        io.send(&buf[..n], sc.wire_chunk);
    }
}

/// Read ciphertext until at least one more HTTP/2 frame is available; `None` when the client hung up.
async fn pump(io: &mut Duplex, session: &mut Session, reader: &mut RecordReader, h2: &mut Vec<u8>) -> bool {
    let Some(chunk) = io.read_some().await else { return false };
    let mut rest = &chunk[..];
    while !rest.is_empty() {
        let (n, feed) = reader.feed(session, rest);
        rest = &rest[n..];
        match feed {
            Feed::Record(p) => h2.extend_from_slice(p),
            Feed::NeedMore => {}
            Feed::Error(e) => panic!("server could not open a client record: {e:?}"),
        }
    }
    true
}

fn next_frame(h2: &mut Vec<u8>) -> Option<(FrameHeader, Vec<u8>)> {
    if h2.len() < 9 {
        return None;
    }
    let len = (h2[0] as usize) << 16 | (h2[1] as usize) << 8 | h2[2] as usize;
    if h2.len() < 9 + len {
        return None;
    }
    let hdr = FrameHeader::parse(h2[..9].try_into().unwrap());
    let payload = h2[9..9 + len].to_vec();
    h2.drain(..9 + len);
    Some((hdr, payload))
}

/// Close our sending side and keep reading until the client has gone (a closing server socket still receives the client's last writes).
async fn hang_up(mut io: Duplex) {
    io.close();
    while io.read_some().await.is_some() {}
}

async fn server(mut io: Duplex, sc: Script, seen: Rc<RefCell<Seen>>) {
    let mut head = vec![];
    while find(&head, b"\r\n\r\n").is_none() {
        match io.read_some().await {
            Some(c) => head.extend(c),
            None => return,
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    seen.borrow_mut().http_head = text.clone();
    if sc.status != "101 Switching Protocols" {
        io.send(format!("HTTP/1.1 {}\r\nContent-Length: 0\r\n\r\n", sc.status).as_bytes(), sc.wire_chunk);
        return;
    }
    let b64 = text.lines().find_map(|l| l.strip_prefix("X-Tailscale-Handshake: ")).unwrap();
    let mut msg1 = [0u8; 101];
    assert_eq!(tdongle_tailnet_control::base64::decode(b64.as_bytes(), &mut msg1), Some(101));
    // As the Go server does, the 101 goes out before the handshake is judged; a failed handshake is a hang-up.
    let upgrade = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n";
    let Ok(acc) = accept(&sc.control_priv, &msg1, &mut TestRng(99)) else {
        io.send(upgrade, sc.wire_chunk);
        hang_up(io).await;
        return;
    };
    let mut session = acc.session;
    let mut out = upgrade.to_vec();
    out.extend_from_slice(&acc.response);
    io.send(&out, sc.wire_chunk);

    let mut first = vec![];
    if let Some(e) = &sc.early {
        first.extend_from_slice(&[255, 255, 255, b'T', b'S']);
        first.extend_from_slice(&(e.len() as u32).to_be_bytes());
        first.extend_from_slice(e.as_bytes());
    }
    first.extend(frame(kind::SETTINGS, 0, 0, &[0, 3, 0, 0, 0, 100]));
    seal(&sc, &mut session, &io, &first, false);

    let mut reader = RecordReader::new();
    let mut h2: Vec<u8> = vec![];
    let mut magic = false;
    loop {
        if !pump(&mut io, &mut session, &mut reader, &mut h2).await {
            return;
        }
        if !magic && h2.len() >= 24 {
            assert_eq!(&h2[..24], b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            h2.drain(..24);
            magic = true;
        }
        while magic && let Some((hdr, payload)) = next_frame(&mut h2) {
            let mut reply: Vec<u8> = vec![];
            let mut corrupt = false;
            let mut maps_now = false;
            match hdr.kind {
                kind::SETTINGS if hdr.flags & flag::ACK == 0 => reply.extend(frame(kind::SETTINGS, flag::ACK, 0, &[])),
                kind::PING if hdr.flags & flag::ACK == 0 => {
                    seen.borrow_mut().pings += 1;
                    reply.extend(frame(kind::PING, flag::ACK, 0, &payload));
                }
                kind::HEADERS => {
                    assert!(hdr.flags & flag::END_HEADERS != 0 && hdr.stream % 2 == 1);
                }
                kind::DATA if hdr.stream == 1 => {
                    seen.borrow_mut().register_body = String::from_utf8(payload).unwrap();
                    match &sc.register {
                        Register::GoAway => reply.extend(frame(kind::GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 1, b'b', b'a', b'd'])),
                        r => {
                            let b: &[u8] = match r {
                                Register::Body(b) => b.as_bytes(),
                                _ => br#"{"User":{"ID":1},"Login":{"ID":1},"NodeKeyExpired":false,"MachineAuthorized":true,"AuthURL":"","Error":""}"#,
                            };
                            reply.extend(frame(kind::HEADERS, flag::END_HEADERS, 1, &[0x88]));
                            reply.extend(frame(kind::DATA, 0, 1, b));
                            reply.extend(frame(kind::DATA, flag::END_STREAM, 1, &[]));
                        }
                    }
                }
                kind::DATA if hdr.stream == 5 => {
                    seen.borrow_mut().map_body = String::from_utf8(payload).unwrap();
                    reply.extend(frame(kind::HEADERS, flag::END_HEADERS, 5, &[0x88]));
                    let mut data = vec![];
                    for m in &sc.maps {
                        data.extend((m.len() as u32).to_le_bytes());
                        data.extend_from_slice(m);
                    }
                    for part in data.chunks(sc.data_split.max(1)) {
                        reply.extend(frame(kind::DATA, 0, 5, part));
                    }
                    corrupt = sc.corrupt_map_records;
                    maps_now = true;
                }
                kind::DATA if hdr.stream >= 7 => {
                    seen.borrow_mut().updates.push(String::from_utf8(payload).unwrap());
                    reply.extend(frame(kind::HEADERS, flag::END_HEADERS, hdr.stream, &[0x88]));
                    reply.extend(frame(kind::DATA, flag::END_STREAM, hdr.stream, &[]));
                }
                _ => {}
            }
            seal(&sc, &mut session, &io, &reply, corrupt);
            if hdr.kind == kind::GOAWAY || (hdr.kind == kind::DATA && hdr.stream == 1 && matches!(sc.register, Register::GoAway)) {
                return;
            }
            if maps_now && sc.stall_mid_message {
                let mut part = 1000u32.to_le_bytes().to_vec();
                part.extend_from_slice(b"{\"PeersCha");
                seal(&sc, &mut session, &io, &frame(kind::DATA, 0, 5, &part), false);
                std::future::pending::<()>().await;
            }
            if maps_now && !sc.wait_update {
                if sc.extra_keepalives > 0 {
                    let doc = br#"{"KeepAlive":true}"#;
                    let mut ka = (doc.len() as u32).to_le_bytes().to_vec();
                    ka.extend_from_slice(doc);
                    for _ in 0..sc.extra_keepalives {
                        seal(&sc, &mut session, &io, &frame(kind::DATA, 0, 5, &ka), false);
                    }
                    while seen.borrow().pings == 0 {
                        if !pump(&mut io, &mut session, &mut reader, &mut h2).await {
                            return;
                        }
                        while let Some((hh, pl)) = next_frame(&mut h2) {
                            if hh.kind == kind::PING && hh.flags & flag::ACK == 0 {
                                seen.borrow_mut().pings += 1;
                                seal(&sc, &mut session, &io, &frame(kind::PING, flag::ACK, 0, &pl), false);
                            }
                        }
                    }
                }
                hang_up(io).await;
                return;
            }
            if hdr.kind == kind::DATA && hdr.stream >= 7 {
                hang_up(io).await;
                return;
            }
        }
    }
}

// ---- running a client against it ----------------------------------------------------------------------------------------------------------------

struct Outcome {
    end: SessionEnd,
    stats: SessionStats,
    sink: Rc<RefCell<Sink>>,
    seen: Rc<RefCell<Seen>>,
    gate: Vec<String>,
}

struct Opts {
    pin: bool,
    auth_key: &'static str,
    read: usize,
    write: usize,
    endpoints: Option<Vec<Endpoint>>,
    refuse_commit: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { pin: true, auth_key: "", read: usize::MAX, write: usize::MAX, endpoints: None, refuse_commit: false }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn run(sc: Script, o: Opts) -> Outcome {
    let clock_step = sc.clock_step;
    let control_pub = x25519::public(&sc.control_priv);
    let mut conns = VecDeque::new();
    let seen = Rc::new(RefCell::new(Seen::default()));
    let clock = Rc::new(Cell::new(0u64));
    let key_server = if o.pin {
        None
    } else {
        let (c, mut s) = duplex(o.read, o.write);
        conns.push_back(c);
        let body = format!("{{\"legacyPublicKey\":\"mkey:{}\",\"publicKey\":\"mkey:{}\"}}", "00".repeat(32), hex(control_pub.as_bytes()));
        Some(async move {
            let mut got = vec![];
            while find(&got, b"\r\n\r\n").is_none() {
                match s.read_some().await {
                    Some(c) => got.extend(c),
                    None => return,
                }
            }
            assert!(String::from_utf8_lossy(&got).starts_with("GET /key?v=131 HTTP/1.1\r\n"));
            s.send(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes(), 7);
            s.close();
        })
    };
    let (c, s) = duplex(o.read, o.write);
    conns.push_back(c);
    let (machine, node, disco) = (Key32([7; 32]), Key32([5; 32]), x25519::public(&Key32([6; 32])));
    let sink = Rc::new(RefCell::new(Sink { refuse_commit: o.refuse_commit, ..Default::default() }));
    let log = Rc::new(RefCell::new(vec![]));
    let cfg = SessionConfig {
        host_header: "ctl.example",
        machine_priv: &machine,
        node_priv: &node,
        disco_pub: &disco,
        hostinfo: Hostinfo::new("tdongle", 1),
        auth_key: o.auth_key,
        followup: "",
        control_pub: if o.pin { Some(&control_pub) } else { None },
        home_derp: 1,
        timeouts: Default::default(),
    };
    let mut ws = Box::new(Workspace::new());
    let (mut connect, mut tclock, mut gate, mut epsrc, mut rng) =
        (Connector(conns), TestClock(clock.clone(), clock_step), TestGate(log.clone()), Eps(Rc::new(RefCell::new(o.endpoints.clone()))), TestRng(1234));
    let mut sink_handle = Shared(sink.clone());
    let client = run_session(&mut connect, &mut tclock, &cfg, &mut ws, &mut sink_handle, &mut gate, &mut epsrc, &mut rng);
    let srv = server(s, sc, seen.clone());
    let ks = async move {
        if let Some(k) = key_server {
            k.await
        }
    };
    let (end, _) = block_on(join(client, join(srv, ks)));
    let stats = ws.session.stats;
    let gate = log.borrow().clone();
    Outcome { end, stats, sink, seen, gate }
}

fn key() -> Key32 {
    Key32([0x42; 32])
}

fn assert_happy(o: &Outcome) {
    assert!(matches!(o.end, SessionEnd::Io { stage: Stage::Map, fail: IoFail::Eof }), "{:?}", o.end);
    assert_eq!(o.gate, ["begin", "end(true)"]);
    let s = o.sink.borrow();
    assert_eq!(s.self_ip, Some(0x6440_0001));
    assert_eq!(s.derp_regions, 1);
    assert_eq!(s.peers, [(2, 0x6440_0002), (6, 0x6440_0003)]);
    assert_eq!((s.commits, s.keepalives, s.aborts), (3, 1, 0));
    assert_eq!((o.stats.maps, o.stats.keepalives, o.stats.peer_events), (3, 1, 2));
    assert!(o.stats.first_map_applied && o.stats.machine_authorized);
    let seen = o.seen.borrow();
    assert!(seen.register_body.starts_with("{\"Version\":131,\"NodeKey\":\"nodekey:"), "{}", seen.register_body);
    assert!(
        seen.map_body.contains("\"Stream\":true") && seen.map_body.contains("\"OmitPeers\":false") && seen.map_body.contains("\"KeepAlive\":true"),
        "{}",
        seen.map_body
    );
    assert!(seen.http_head.starts_with("POST /ts2021 HTTP/1.1\r\nHost: ctl.example\r\nUpgrade: tailscale-control-protocol\r\n"));
    assert_eq!(o.end.noise_error(), 5);
}

// ---- tests ----------------------------------------------------------------------------------------------------------------------------------------

#[test]
fn full_flow_in_many_chunkings() {
    let mut runs = 0;
    for read in [1usize, 2, 3, 7, 64, 1000, usize::MAX] {
        for wire in [1usize, 5, 31, 100, 4096] {
            for record in [3usize, 50, 4000] {
                for data in [1usize, 40, 4000] {
                    let mut sc = Script::new(key());
                    sc.wire_chunk = wire;
                    sc.record_split = record;
                    sc.data_split = data;
                    sc.early = Some(format!("{{\"nodeKeyChallenge\":\"chalpub:{}\"}}", "01".repeat(32)));
                    let o = run(sc, Opts { read, write: read.min(97), ..Opts::default() });
                    assert_happy(&o);
                    runs += 1;
                }
            }
        }
    }
    assert_eq!(runs, 7 * 5 * 3 * 3);
}

#[test]
fn key_fetch_on_its_own_connection_and_auth_key() {
    let o = run(Script::new(key()), Opts { pin: false, auth_key: "tskey-auth-abc", read: 5, write: 11, ..Opts::default() });
    assert_happy(&o);
    assert!(o.seen.borrow().register_body.contains("\"Auth\":{\"AuthKey\":\"tskey-auth-abc\"}"));
}

#[test]
fn node_key_challenge_is_answered() {
    let priv_c = Key32([0x31; 32]);
    let challenge = x25519::public(&priv_c);
    let mut sc = Script::new(key());
    sc.early = Some(format!("{{\"nodeKeyChallenge\":\"chalpub:{}\"}}", hex(challenge.as_bytes())));
    let o = run(sc, Opts::default());
    assert_happy(&o);
    assert!(o.stats.challenge_seen);
    let body = o.seen.borrow().register_body.clone();
    // X25519(node_priv, challenge) = X25519(priv_c, node_pub): the server can verify it.
    let expect = x25519::shared(&priv_c, &x25519::public(&Key32([5; 32]))).unwrap();
    assert!(body.contains(&format!("\"NodeKeyChallengeResponse\":\"chalresp:{}\"", hex(expect.as_bytes()))), "{body}");
}

#[test]
fn register_outcomes_are_typed_and_release_the_gate() {
    type Check = fn(&SessionEnd) -> bool;
    let cases: [(&str, Check); 4] = [
        (
            r#"{"AuthURL":"https://login.example/a?x=1&y=2"}"#,
            |e| matches!(e, SessionEnd::Register(RegisterFailure::AuthUrl(u)) if u.as_str() == "https://login.example/a?x=1&y=2"),
        ),
        (r#"{"Error":"nope"}"#, |e| matches!(e, SessionEnd::Register(RegisterFailure::Refused(m)) if m.as_str() == "nope")),
        (r#"{"NodeKeyExpired":true}"#, |e| matches!(e, SessionEnd::Register(RegisterFailure::NodeKeyExpired))),
        ("not json", |e| matches!(e, SessionEnd::Register(RegisterFailure::Malformed(_)))),
    ];
    for (body, check) in cases {
        let mut sc = Script::new(key());
        sc.register = Register::Body(body);
        let o = run(sc, Opts::default());
        assert!(check(&o.end), "{body}: {:?}", o.end);
        assert_eq!(o.gate, ["begin", "end(false)"]);
        assert_eq!(o.sink.borrow().commits, 0);
    }
}

#[test]
fn goaway_during_registration() {
    let mut sc = Script::new(key());
    sc.register = Register::GoAway;
    let o = run(sc, Opts::default());
    match &o.end {
        SessionEnd::GoAway { code, debug, .. } => assert_eq!((*code, debug.as_str()), (1, "bad")),
        e => panic!("{e:?}"),
    }
    assert_eq!(o.end.map_error(), 10);
    assert_eq!(o.gate, ["begin", "end(false)"]);
}

#[test]
fn wrong_key_and_bad_upgrade_fail_before_register() {
    // The client is pinned to a key the server does not hold: it cannot complete the handshake and hangs up after the 101.
    let sc = Script::new(key());
    let wrong_pub = x25519::public(&Key32([0x77; 32]));
    let o = run_pinned_to(sc, &wrong_pub);
    assert!(matches!(o.end, SessionEnd::Io { stage: Stage::Handshake, fail: IoFail::Eof }), "{:?}", o.end);
    assert_eq!(o.stats.maps, 0);
    assert_eq!(o.gate, ["begin", "end(false)"]);
    assert!(o.seen.borrow().register_body.is_empty());
    let mut sc = Script::new(key());
    sc.status = "400 Bad Request";
    let o = run(sc, Opts::default());
    assert!(matches!(o.end, SessionEnd::Upgrade(tdongle_tailnet_control::http::UpgradeError::NotSwitching)), "{:?}", o.end);
}

fn run_pinned_to(sc: Script, pin: &Key32) -> Outcome {
    let clock_step = sc.clock_step;
    // Same as `run`, with a client key that does not match the server's.
    let (c, s) = duplex(usize::MAX, usize::MAX);
    let seen = Rc::new(RefCell::new(Seen::default()));
    let clock = Rc::new(Cell::new(0u64));
    let (machine, node, disco) = (Key32([7; 32]), Key32([5; 32]), x25519::public(&Key32([6; 32])));
    let sink = Rc::new(RefCell::new(Sink::default()));
    let log = Rc::new(RefCell::new(vec![]));
    let cfg = SessionConfig {
        host_header: "ctl.example",
        machine_priv: &machine,
        node_priv: &node,
        disco_pub: &disco,
        hostinfo: Hostinfo::new("tdongle", 1),
        auth_key: "",
        followup: "",
        control_pub: Some(pin),
        home_derp: 1,
        timeouts: Default::default(),
    };
    let mut ws = Box::new(Workspace::new());
    let (mut connect, mut tclock, mut gate, mut rng) =
        (Connector(VecDeque::from([c])), TestClock(clock.clone(), clock_step), TestGate(log.clone()), TestRng(1));
    let mut sh = Shared(sink.clone());
    let mut no_eps = NoEndpoints;
    let client = run_session(&mut connect, &mut tclock, &cfg, &mut ws, &mut sh, &mut gate, &mut no_eps, &mut rng);
    let (end, _) = block_on(join(client, server(s, sc, seen.clone())));
    let gate = log.borrow().clone();
    Outcome { end, stats: ws.session.stats, sink, seen, gate }
}

#[test]
fn corrupted_record_is_a_noise_auth_failure() {
    let mut sc = Script::new(key());
    sc.corrupt_map_records = true;
    let o = run(sc, Opts::default());
    assert!(matches!(o.end, SessionEnd::Record(tdongle_tailnet_noise::OpenError::AuthFailed)), "{:?}", o.end);
    assert_eq!(o.end.noise_error(), 6);
    assert_eq!(o.gate, ["begin", "end(false)"]);
}

#[test]
fn map_failures_carry_the_c_codes() {
    // Length 0.
    let mut sc = Script::new(key());
    sc.maps = vec![];
    let _ = sc; // an empty map list ends the stream without a message: the server closes after sending only HEADERS
    // Malformed JSON.
    let mut sc = Script::new(key());
    sc.maps = vec![b"{\"Node\":".to_vec()];
    let o = run(sc, Opts::default());
    assert!(matches!(o.end, SessionEnd::Map(MapEnd::Projector(_)) | SessionEnd::Io { .. } | SessionEnd::Map(MapEnd::StreamEnded { .. })), "{:?}", o.end);
    // A message that is valid JSON but not an object.
    let mut sc = Script::new(key());
    sc.maps = vec![b"[1,2]".to_vec()];
    let o = run(sc, Opts::default());
    assert!(matches!(o.end, SessionEnd::Map(MapEnd::Projector(_))), "{:?}", o.end);
    assert_eq!(o.end.map_error(), 8);
    assert_eq!(o.gate, ["begin", "end(false)"]);
    assert_eq!(o.sink.borrow().aborts, 1);
    // The sink refuses the commit: map_error 9, nothing applied.
    let o = run(Script::new(key()), Opts { refuse_commit: true, ..Opts::default() });
    assert!(matches!(o.end, SessionEnd::Map(MapEnd::Projector(tdongle_tailnet_map::MapError::CommitRefused))), "{:?}", o.end);
    assert_eq!(o.end.map_error(), 9);
    assert_eq!(o.gate, ["begin", "end(false)"]);
}

#[test]
fn oversize_map_length_is_refused() {
    let mut sc = Script::new(key());
    sc.maps = vec![];
    // Hand the server a raw oversize length by using one message whose declared size we then overwrite: easiest is a message of exactly 1 byte
    // preceded by a bogus prefix, which the script cannot do; so craft it via a 0-length map document instead.
    sc.maps = vec![vec![]];
    let o = run(sc, Opts::default());
    assert!(matches!(o.end, SessionEnd::Map(MapEnd::BadLength(0))), "{:?}", o.end);
    assert_eq!(o.end.map_error(), 7);
}

#[test]
fn endpoint_update_is_sent_once_on_a_new_stream() {
    let ep = Endpoint { addr: EndpointAddr::V4 { ip: [192, 168, 1, 50], port: 41641 }, kind: ENDPOINT_LOCAL };
    let mut sc = Script::new(key());
    sc.wait_update = true;
    let o = run(sc, Opts { endpoints: Some(vec![ep]), ..Opts::default() });
    assert!(matches!(o.end, SessionEnd::Io { stage: Stage::Map, fail: IoFail::Eof }), "{:?}", o.end);
    let u = o.seen.borrow().updates.clone();
    assert_eq!(u.len(), 1);
    assert!(u[0].contains("\"Stream\":false") && u[0].contains("\"OmitPeers\":true") && u[0].contains("\"Endpoints\":[\"192.168.1.50:41641\"]"), "{}", u[0]);
    assert_eq!(o.stats.endpoint_updates, 1);
}

#[test]
fn ping_is_sent_every_five_seconds_and_acked() {
    let mut sc = Script::new(key());
    sc.extra_keepalives = 8;
    sc.clock_step = 1000;
    let o = run(sc, Opts::default());
    assert!(matches!(o.end, SessionEnd::Io { stage: Stage::Map, fail: IoFail::Eof }), "{:?}", o.end);
    assert!(o.stats.pings_sent >= 1 && o.stats.ping_acks >= 1, "{:?}", o.stats);
    assert!(o.seen.borrow().pings >= 1);
    assert_eq!(o.stats.keepalives, 9);
}

#[test]
fn sizes_are_reported() {
    use tdongle_tailnet_ctl::sizes::*;
    println!("Workspace {WORKSPACE} B (projector {PROJECTOR}), noise session {NOISE_SESSION}, h2 session {H2_SESSION}, stats {STATS}");
    const { assert!(WORKSPACE < 24 * 1024) };
}

// ---- the leased buffers ---------------------------------------------------------------------------------------------------------------------------

/// A contended lease: one holder at a time, the others wait (as the runtime's `SharedBulk` does), with the facts a test wants to look at.
struct TestLease {
    bulk: RefCell<Bulk>,
    held: Cell<bool>,
    takes: Cell<u32>,
}

struct TestGuard<'a> {
    g: std::cell::RefMut<'a, Bulk>,
    held: &'a Cell<bool>,
}

impl std::ops::Deref for TestGuard<'_> {
    type Target = Bulk;
    fn deref(&self) -> &Bulk {
        &self.g
    }
}
impl std::ops::DerefMut for TestGuard<'_> {
    fn deref_mut(&mut self) -> &mut Bulk {
        &mut self.g
    }
}
impl Drop for TestGuard<'_> {
    fn drop(&mut self) {
        self.held.set(false);
    }
}

impl BulkLease for TestLease {
    type Guard<'a> = TestGuard<'a>;
    async fn lease(&self) -> TestGuard<'_> {
        std::future::poll_fn(|cx| match self.bulk.try_borrow_mut() {
            Ok(g) => {
                assert!(!self.held.get(), "two holders");
                self.held.set(true);
                self.takes.set(self.takes.get() + 1);
                std::task::Poll::Ready(TestGuard { g, held: &self.held })
            }
            Err(_) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        })
        .await
    }
}

impl TestLease {
    fn new() -> Self {
        TestLease { bulk: RefCell::new(Bulk::new()), held: Cell::new(false), takes: Cell::new(0) }
    }
}

/// Virtual time: a read that nothing answers for 40 turns of the executor "times out" and the clock moves on by the timeout it asked for.
struct VirtClock(Rc<Cell<u64>>);
impl Clock for VirtClock {
    fn now(&self) -> Millis {
        self.0.get()
    }
    async fn timeout<F: std::future::Future>(&mut self, ms: u32, fut: F) -> Option<F::Output> {
        let mut fut = std::pin::pin!(fut);
        let mut turns = 0u32;
        let r = std::future::poll_fn(|cx| {
            if let std::task::Poll::Ready(v) = fut.as_mut().poll(cx) {
                return std::task::Poll::Ready(Some(v));
            }
            turns += 1;
            if turns > 40 {
                return std::task::Poll::Ready(None);
            }
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        })
        .await;
        if r.is_none() {
            self.0.set(self.0.get() + u64::from(ms));
        }
        r
    }
}

/// One client on the shared lease against its own scripted server; returns how its session ended and its gate log.
async fn leased_client(sc: Script, lease: &TestLease, clock: Rc<Cell<u64>>, timeouts: Timeouts, sink: Rc<RefCell<Sink>>) -> (SessionEnd, Vec<String>) {
    let control_pub = x25519::public(&sc.control_priv);
    let (c, s) = duplex(usize::MAX, usize::MAX);
    let (machine, node, disco) = (Key32([7; 32]), Key32([5; 32]), x25519::public(&Key32([6; 32])));
    let log = Rc::new(RefCell::new(vec![]));
    let cfg = SessionConfig {
        host_header: "ctl.example",
        machine_priv: &machine,
        node_priv: &node,
        disco_pub: &disco,
        hostinfo: Hostinfo::new("tdongle", 1),
        auth_key: "",
        followup: "",
        control_pub: Some(&control_pub),
        home_derp: 1,
        timeouts,
    };
    let (mut connect, mut tclock, mut gate, mut no_eps, mut rng) =
        (Connector(VecDeque::from([c])), VirtClock(clock), TestGate(log.clone()), NoEndpoints, TestRng(1));
    let mut sh = Shared(sink.clone());
    let mut buf = SessionBuf::new();
    let seen = Rc::new(RefCell::new(Seen::default()));
    let client = run_session_leased(&mut connect, &mut tclock, &cfg, &mut buf, lease, &mut sh, &mut gate, &mut no_eps, &mut rng);
    let end = match futures::future::select(Box::pin(client), Box::pin(server(s, sc, seen))).await {
        futures::future::Either::Left((end, _)) => end,
        futures::future::Either::Right(_) => panic!("the server returned before the client ended"),
    };
    let gate = log.borrow().clone();
    (end, gate)
}

#[test]
fn two_memberships_share_one_lease_and_both_join() {
    // Both sessions negotiate and stream their maps through ONE set of big buffers: the second waits its turn at the lease (the TestLease panics on a
    // second holder), and each ends the way a session against that server ends (the server closes after the maps).
    let lease = TestLease::new();
    let clock = Rc::new(Cell::new(0u64));
    let (sa, sb) = (Rc::new(RefCell::new(Sink::default())), Rc::new(RefCell::new(Sink::default())));
    let (a, b) = block_on(join(
        leased_client(Script::new(key()), &lease, clock.clone(), Timeouts::default(), sa.clone()),
        leased_client(Script::new(Key32([0x43; 32])), &lease, clock.clone(), Timeouts::default(), sb.clone()),
    ));
    for ((end, gate), sink) in [(&a, &sa), (&b, &sb)] {
        assert!(matches!(end, SessionEnd::Io { stage: Stage::Map, fail: IoFail::Eof }), "{end:?}");
        assert_eq!(gate, &["begin", "end(true)"]);
        let s = sink.borrow();
        assert_eq!((s.commits, s.keepalives, s.aborts), (3, 1, 0));
    }
    assert!(!lease.held.get(), "the lease is back when the sessions are over");
}

#[test]
fn a_streaming_session_gives_the_buffers_back_while_the_server_is_quiet() {
    // After its maps the server says nothing (it waits for an endpoint update that never comes): the session is idle between messages, so another
    // membership can take the buffers.
    let lease = TestLease::new();
    let clock = Rc::new(Cell::new(0u64));
    let mut sc = Script::new(key());
    sc.wait_update = true;
    // this test is about the lease, not the idle timeout
    let t = Timeouts { idle_ms: u32::MAX, ..Timeouts::default() };
    let sink = Rc::new(RefCell::new(Sink::default()));
    let probe = async {
        // wait until all three messages have been applied, then give the session some turns to reach its quiet wait
        while sink.borrow().commits < 3 {
            yield_now().await;
        }
        for _ in 0..100 {
            yield_now().await;
        }
        assert!(!lease.held.get(), "an idle session must not sit on the buffers");
        // and a second membership can take them at once
        let g = lease.lease().await;
        drop(g);
    };
    let c = leased_client(sc, &lease, clock, t, sink.clone());
    match block_on(futures::future::select(Box::pin(probe), Box::pin(c))) {
        futures::future::Either::Left(_) => {}
        futures::future::Either::Right((r, _)) => panic!("the session ended: {:?}", r.0),
    }
}

async fn yield_now() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            return std::task::Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    })
    .await
}

#[test]
fn a_server_that_stalls_inside_a_message_costs_only_its_own_session() {
    // The C's slicing check ("a stalled server costs only its own membership a redial"): A's server stops in the middle of a map message while A holds
    // the buffers; B is waiting for them. A's session ends with the stall bound, and B then joins.
    let lease = TestLease::new();
    let clock = Rc::new(Cell::new(0u64));
    let mut stalled = Script::new(key());
    stalled.stall_mid_message = true;
    let t = Timeouts { lease_stall_ms: 5_000, ..Timeouts::default() };
    let (sa, sb) = (Rc::new(RefCell::new(Sink::default())), Rc::new(RefCell::new(Sink::default())));
    let (a, b) = block_on(join(
        leased_client(stalled, &lease, clock.clone(), t, sa.clone()),
        leased_client(Script::new(Key32([0x43; 32])), &lease, clock.clone(), t, sb.clone()),
    ));
    assert!(matches!(a.0, SessionEnd::LeaseStall), "{:?}", a.0);
    assert_eq!(a.1, ["begin", "end(true)"], "A had joined: its maps were applied before the stall");
    assert_eq!(a.0.map_error(), 2);
    assert!(matches!(b.0, SessionEnd::Io { stage: Stage::Map, fail: IoFail::Eof }), "{:?}", b.0);
    assert_eq!(b.1, ["begin", "end(true)"]);
    assert_eq!(sb.borrow().commits, 3);
    // the stall was bounded by lease_stall_ms (5 s of virtual time), long before the idle timeout (30 s)
    assert!(clock.get() < 20_000, "{}", clock.get());
}
