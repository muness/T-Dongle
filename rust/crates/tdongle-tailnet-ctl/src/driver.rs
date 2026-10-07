//! The session driver.

use crate::end::{IoFail, MapEnd, RegisterFailure, SessionEnd, SessionStats, Stage};
use crate::traits::{Clock, Connect, EndpointSource, Gate};
use core::cell::RefCell;
use core::ops::DerefMut;
use embedded_io_async::{Error as _, Read, Write};
use tdongle_tailnet_control::early::{EarlyParser, EarlyStatus};
use tdongle_tailnet_control::h2::{self, Config as H2Config, Event, Session as H2Session};
use tdongle_tailnet_control::http::{self, CAPABILITY_VERSION, KEY_REQUEST_MAX, KEY_RESPONSE_MAX, KeyResponse, UpgradeReader, UpgradeStatus};
use tdongle_tailnet_control::map::{MapEvent as FrameEvent, MapStream, StreamEnd};
use tdongle_tailnet_control::requests::{
    Endpoint, FIRST_UPDATE_STREAM, Hostinfo, MapKind, MapRequest, RegisterOutcome, RegisterRequest, STREAM_LONG_POLL, STREAM_REGISTER, fnv1a32,
    node_key_challenge_response, parse_register_response,
};
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_map::{MapConfig, MapEvent, MapProjector, MapSink, SinkError};
use tdongle_tailnet_noise::{
    Feed, HEADROOM, HandshakeError, INITIATION_LEN, Initiator, MAX_PLAINTEXT, RESPONSE_LEN, RecordReader, ResponseHeader, Session, TAILROOM,
};
use tdongle_tailnet_types::{Entropy, Key32, Millis};

/// Bytes of the raw TCP input buffer.
pub const RX_BYTES: usize = 1024;
/// Bytes of the register response / request JSON buffer (the C shared a 16 KiB one with the map; a real RegisterResponse is about 1 KiB).
pub const JSON_BYTES: usize = 4096;
/// Bytes of the early payload the driver accepts (the node-key challenge is about 100); it is read into the start of the JSON buffer, which is not
/// used before registration.
pub const EARLY_BYTES: usize = 1024;
/// Bytes of the sealed-record buffer: one whole record, so that no request that fitted a record before is refused (the `Followup` URL is server-supplied
/// and JSON-escaped on the way out: a 383-byte URL of characters that need escaping is 2.3 KB). A smaller buffer was considered and rejected for that reason.
pub const TX_BYTES: usize = 4096;
/// Maximum endpoints in one update.
pub const MAX_ENDPOINTS: usize = 8;
/// PING interval (the C: 5 s).
pub const PING_INTERVAL_MS: u64 = 5000;
/// Longest wait for a read while the map stream is open (so endpoint updates and pings are never late by more than this).
const TICK_MS: u32 = 1000;

/// Time budgets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// One read or write while connecting and handshaking, and the whole `/key` fetch (the C: 10 s).
    pub io_ms: u32,
    /// From the first byte sent to the first map applied (the C: 15 s for the first message, extended while it makes progress).
    pub first_map_ms: u32,
    /// Silence on an established stream before the session is declared dead (PINGs every 5 s are answered, so this is generous).
    pub idle_ms: u32,
    /// How long a session may sit on the leased [`Bulk`] buffers without the server sending a byte once the first map is applied (in the middle of a
    /// record or a map message, or in a write): the stall bound of the lease. It ends only that session (the C's "stalled server costs only its own
    /// membership a redial"); the other memberships' map messages wait at most this long, once.
    pub lease_stall_ms: u32,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { io_ms: 10_000, first_map_ms: 30_000, idle_ms: 30_000, lease_stall_ms: 5_000 }
    }
}

/// What the session needs to know. Secrets are borrowed, never copied.
#[derive(Clone, Copy, Debug)]
pub struct SessionConfig<'a> {
    /// `Host:` header value (and HTTP/2 `:authority`).
    pub host_header: &'a str,
    /// Machine private key (Noise static).
    pub machine_priv: &'a Key32,
    /// Node (WireGuard) private key; the public key is derived.
    pub node_priv: &'a Key32,
    /// Disco public key.
    pub disco_pub: &'a Key32,
    /// Hostinfo, identical in every message.
    pub hostinfo: Hostinfo<'a>,
    /// Pre-auth key (empty = none).
    pub auth_key: &'a str,
    /// The `AuthURL` of an interactive login in progress (empty = none).
    pub followup: &'a str,
    /// The control server's Noise public key; `None` fetches it with `GET /key?v=131` on a separate connection.
    pub control_pub: Option<&'a Key32>,
    /// Preferred DERP region for the map projector.
    pub home_derp: u16,
    /// Time budgets.
    pub timeouts: Timeouts,
}

/// The big buffers of a control session: the record reader, the sealed-record buffer, the request / response JSON (the early payload shares it) and the map
/// projector. A session **leases** them (see [`BulkLease`]) from the first byte of a record until the message it carried is applied, and while it
/// negotiates (token held), so one `Bulk` serves every membership of a gateway. `new` is not `const` (the map projector's constructor is not).
#[derive(Debug)]
pub struct Bulk {
    reader: RecordReader,
    tx: [u8; TX_BYTES],
    /// Request / response JSON; the early payload (before registration, at most [`EARLY_BYTES`]) passes through its first bytes.
    json: [u8; JSON_BYTES],
    projector: MapProjector,
}

impl Bulk {
    /// Fresh buffers.
    pub fn new() -> Self {
        Self { reader: RecordReader::new(), tx: [0; TX_BYTES], json: [0; JSON_BYTES], projector: MapProjector::new(MapConfig::new(1).with_flash_directory()) }
    }
}

impl Default for Bulk {
    fn default() -> Self {
        Self::new()
    }
}

/// What one session keeps for its whole life, leased buffers or not: the TCP input buffer and the counters. About 1.1 KiB.
#[derive(Debug)]
pub struct SessionBuf {
    rx: [u8; RX_BYTES],
    /// Counters of the last session (valid after `run_session_leased` returns, whatever the outcome).
    pub stats: SessionStats,
}

impl SessionBuf {
    /// A fresh one.
    pub const fn new() -> Self {
        Self { rx: [0; RX_BYTES], stats: SessionStats::new() }
    }
}

impl Default for SessionBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a session gets its [`Bulk`] from. `lease` may wait (another membership holds it); the guard releases on drop. The driver holds a lease while
/// it negotiates and in the middle of a record or message, never while it waits for the next one, and never across a wait longer than
/// [`Timeouts::lease_stall_ms`].
pub trait BulkLease {
    /// The held lease.
    type Guard<'a>: DerefMut<Target = Bulk>
    where
        Self: 'a;
    /// Take the buffers.
    #[allow(async_fn_in_trait)]
    async fn lease(&self) -> Self::Guard<'_>;
}

impl BulkLease for RefCell<Bulk> {
    type Guard<'a> = core::cell::RefMut<'a, Bulk>;
    async fn lease(&self) -> Self::Guard<'_> {
        self.borrow_mut()
    }
}

/// One session's buffers all in one owner (a single membership, tests, tools): [`run_session`] leases from it, uncontended.
#[derive(Debug)]
pub struct Workspace {
    /// The session's own state.
    pub session: SessionBuf,
    bulk: RefCell<Bulk>,
}

impl Workspace {
    /// A fresh workspace.
    pub fn new() -> Self {
        Self { session: SessionBuf::new(), bulk: RefCell::new(Bulk::new()) }
    }
}

impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

// ---- transport helpers -------------------------------------------------------------------------------------------------------------------------------

async fn read_some<S: Read, K: Clock>(io: &mut S, clock: &mut K, buf: &mut [u8], ms: u32) -> Result<usize, IoFail> {
    match clock.timeout(ms, io.read(buf)).await {
        None => Err(IoFail::Timeout),
        Some(Err(e)) => Err(IoFail::Error(e.kind())),
        Some(Ok(0)) => Err(IoFail::Eof),
        Some(Ok(n)) => Ok(n),
    }
}

async fn write_all<S: Write, K: Clock>(io: &mut S, clock: &mut K, data: &[u8], ms: u32) -> Result<(), IoFail> {
    let fut = async {
        io.write_all(data).await?;
        io.flush().await
    };
    match clock.timeout(ms, fut).await {
        None => Err(IoFail::Timeout),
        Some(Err(e)) => Err(IoFail::Error(e.kind())),
        Some(Ok(())) => Ok(()),
    }
}

/// `GET /key?v=131` over its own connection. `buf` must hold at least `KEY_REQUEST_MAX + KEY_RESPONSE_MAX` bytes. The connection is dropped before this
/// returns.
pub async fn fetch_control_key<C: Connect, K: Clock>(
    connect: &mut C,
    clock: &mut K,
    host_header: &str,
    buf: &mut [u8],
    io_ms: u32,
) -> Result<Key32, SessionEnd> {
    if buf.len() < KEY_REQUEST_MAX + KEY_RESPONSE_MAX {
        return Err(SessionEnd::RequestTooLarge);
    }
    let (req_buf, resp_buf) = buf.split_at_mut(KEY_REQUEST_MAX);
    let n = http::build_key_request(host_header, req_buf).map_err(|_| SessionEnd::RequestTooLarge)?;
    let mut io = connect.connect().await.map_err(|_| SessionEnd::Connect(Stage::KeyFetch))?;
    let io_err = |fail| SessionEnd::Io { stage: Stage::KeyFetch, fail };
    write_all(&mut io, clock, &req_buf[..n], io_ms).await.map_err(io_err)?;
    let mut rsp = KeyResponse::new(&mut resp_buf[..KEY_RESPONSE_MAX]);
    let mut chunk = [0u8; 256];
    let start = clock.now();
    loop {
        let left = (io_ms as u64).saturating_sub(clock.now().saturating_sub(start)).max(1) as u32;
        match read_some(&mut io, clock, &mut chunk, left).await {
            Ok(k) => rsp.push(&chunk[..k]).map_err(SessionEnd::KeyFetch)?,
            Err(IoFail::Eof) => break,
            Err(e) => return Err(io_err(e)),
        }
    }
    drop(io);
    rsp.finish().map_err(SessionEnd::KeyFetch)
}

/// The plaintext window of a record buffer: behind the header, before the tag, at most one record's worth.
fn plain_window(tx: &mut [u8]) -> &mut [u8] {
    let end = tx.len().saturating_sub(TAILROOM).min(HEADROOM + MAX_PLAINTEXT);
    &mut tx[HEADROOM.min(end)..end]
}

/// The encrypted side of the connection: stream, clock and the Noise session. The sealed-record buffer is the leased [`Bulk`]'s, passed to every call.
struct Wire<'a, S, K> {
    io: &'a mut S,
    clock: &'a mut K,
    noise: Session,
    io_ms: u32,
    bytes_out: u64,
}

impl<S: Read + Write, K: Clock> Wire<'_, S, K> {
    async fn send_sealed(&mut self, tx: &mut [u8], plain_len: usize) -> Result<(), SessionEnd> {
        let n = self.noise.seal_record(&mut tx[..], plain_len).map_err(|_| SessionEnd::RequestTooLarge)?;
        self.bytes_out += n as u64;
        write_all(self.io, self.clock, &tx[..n], self.io_ms).await.map_err(|fail| SessionEnd::Io { stage: Stage::Map, fail })
    }

    /// Send everything the HTTP/2 session has queued.
    async fn flush(&mut self, h2: &mut H2Session, tx: &mut [u8]) -> Result<(), SessionEnd> {
        loop {
            let n = h2.poll_output(plain_window(tx));
            if n == 0 {
                return Ok(());
            }
            self.send_sealed(tx, n).await?;
        }
    }

    /// Write one HTTP/2 request (HEADERS + DATA) as a single record.
    async fn request(&mut self, h2: &mut H2Session, tx: &mut [u8], stream: u32, path: &str, authority: &str, body: &[u8]) -> Result<(), SessionEnd> {
        self.flush(h2, tx).await?;
        let n = h2.write_request(plain_window(tx), stream, "POST", path, authority, "application/json", body).map_err(|_| SessionEnd::RequestTooLarge)?;
        self.send_sealed(tx, n).await
    }
}

/// Counts and forwards map events; remembers whether a map was committed.
struct Counting<'a, Sk> {
    inner: &'a mut Sk,
    stats: &'a mut SessionStats,
    committed: bool,
}

impl<Sk: MapSink> MapSink for Counting<'_, Sk> {
    fn event(&mut self, e: MapEvent<'_>) -> Result<(), SinkError> {
        match e {
            MapEvent::Peer(_) => self.stats.peer_events += 1,
            MapEvent::KeepAlive => self.stats.keepalives += 1,
            MapEvent::Commit(_) => {
                let r = self.inner.event(e);
                if r.is_ok() {
                    self.committed = true;
                }
                return r;
            }
            _ => {}
        }
        self.inner.event(e)
    }
}

/// Releases the gate exactly once.
struct GateGuard<'a, G> {
    gate: &'a mut G,
    released: bool,
}

impl<G: Gate> GateGuard<'_, G> {
    async fn release(&mut self, ok: bool) {
        if !self.released {
            self.released = true;
            self.gate.end_negotiation(ok).await;
        }
    }
}

/// Run one control session to its end, all of its buffers in `ws` (one owner). See the crate documentation for the flow, `Workspace` for memory and
/// [`SessionEnd`] for outcomes. The session only returns when it fails or the server ends it; `ws.session.stats` then says what it did.
#[allow(clippy::too_many_arguments)]
pub async fn run_session<C: Connect, K: Clock, E: Entropy, Sk: MapSink, G: Gate, P: EndpointSource>(
    connect: &mut C,
    clock: &mut K,
    cfg: &SessionConfig<'_>,
    ws: &mut Workspace,
    sink: &mut Sk,
    gate: &mut G,
    endpoints: &mut P,
    rng: &mut E,
) -> SessionEnd {
    run_session_leased(connect, clock, cfg, &mut ws.session, &ws.bulk, sink, gate, endpoints, rng).await
}

/// [`run_session`] with the big buffers leased from `lease` (shared by every membership of a gateway), and only the session's own [`SessionBuf`] owned.
///
/// The lease is taken after the TCP connect (or for the `/key` fetch), held while the session negotiates, and after the first map is applied held only
/// from the first byte of a record until the message it belongs to is applied: it is released whenever the session waits for the server with no
/// record or message in progress. A server that stalls with the lease held for [`Timeouts::lease_stall_ms`] ends its own session ([`SessionEnd::LeaseStall`]).
#[allow(clippy::too_many_arguments)]
pub async fn run_session_leased<L: BulkLease, C: Connect, K: Clock, E: Entropy, Sk: MapSink, G: Gate, P: EndpointSource>(
    connect: &mut C,
    clock: &mut K,
    cfg: &SessionConfig<'_>,
    st: &mut SessionBuf,
    lease: &L,
    sink: &mut Sk,
    gate: &mut G,
    endpoints: &mut P,
    rng: &mut E,
) -> SessionEnd {
    st.stats = SessionStats::default();
    gate.begin_negotiation().await;
    let mut guard = GateGuard { gate, released: false };
    let end = session(connect, clock, cfg, st, lease, sink, &mut guard, endpoints, rng).await;
    guard.release(false).await;
    end
}

#[allow(clippy::too_many_arguments)]
async fn session<L: BulkLease, C: Connect, K: Clock, E: Entropy, Sk: MapSink, G: Gate, P: EndpointSource>(
    connect: &mut C,
    clock: &mut K,
    cfg: &SessionConfig<'_>,
    st: &mut SessionBuf,
    lease: &L,
    sink: &mut Sk,
    guard: &mut GateGuard<'_, G>,
    endpoints: &mut P,
    rng: &mut E,
) -> SessionEnd {
    let t = cfg.timeouts;
    // 1. The control server's key.
    let fetched;
    let control_pub = match cfg.control_pub {
        Some(k) => k,
        None => {
            let r = {
                let mut g = lease.lease().await;
                fetch_control_key(connect, clock, cfg.host_header, &mut g.json, t.io_ms).await
            };
            fetched = match r {
                Ok(k) => k,
                Err(e) => return e,
            };
            &fetched
        }
    };
    let SessionBuf { rx, stats } = st;
    // 2. Connect, upgrade request.
    let mut io = match connect.connect().await {
        Ok(io) => io,
        Err(()) => return SessionEnd::Connect(Stage::Connect),
    };
    let (init, msg1) = match Initiator::new(cfg.machine_priv, control_pub, CAPABILITY_VERSION as u16, rng) {
        Ok(x) => x,
        Err(e) => return SessionEnd::Handshake(e),
    };
    debug_assert_eq!(msg1.len(), INITIATION_LEN);
    // the leased buffers, from here to the first applied map (the negotiation token is held for the same time, so this adds no waiting of its own
    // between negotiations; it makes the streaming memberships' next map message wait for the negotiation, at most the first-map deadline)
    let mut g = lease.lease().await;
    let n = match http::build_upgrade_request(cfg.host_header, &msg1, &mut g.tx[..]) {
        Ok(n) => n,
        Err(_) => return SessionEnd::RequestTooLarge,
    };
    if let Err(fail) = write_all(&mut io, clock, &g.tx[..n], t.io_ms).await {
        return SessionEnd::Io { stage: Stage::Upgrade, fail };
    }
    stats.bytes_out += n as u64;
    // 3. The 101, then Noise message 2; bytes beyond them stay in the input buffer.
    let (mut pos, mut len) = (0usize, 0usize);
    let mut up = UpgradeReader::new();
    loop {
        if pos == len {
            match read_some(&mut io, clock, &mut rx[..], t.io_ms).await {
                Ok(k) => (pos, len) = (0, k),
                Err(fail) => return SessionEnd::Io { stage: Stage::Upgrade, fail },
            }
            stats.bytes_in += len as u64;
        }
        match up.push(&rx[pos..len]) {
            Ok((k, st)) => {
                pos += k;
                if st == UpgradeStatus::Switched {
                    break;
                }
            }
            Err(e) => return SessionEnd::Upgrade(e),
        }
    }
    let mut msg2 = [0u8; RESPONSE_LEN];
    let mut got = 0;
    while got < RESPONSE_LEN {
        if pos == len {
            match read_some(&mut io, clock, &mut rx[..], t.io_ms).await {
                Ok(k) => (pos, len) = (0, k),
                Err(fail) => return SessionEnd::Io { stage: Stage::Handshake, fail },
            }
            stats.bytes_in += len as u64;
        }
        let take = (RESPONSE_LEN - got).min(len - pos);
        msg2[got..got + take].copy_from_slice(&rx[pos..pos + take]);
        got += take;
        pos += take;
        // A type 3 error message is shorter than msg2: classify as soon as the header is in.
        if got >= 3
            && let Ok(ResponseHeader::Error { .. }) = ResponseHeader::parse(&[msg2[0], msg2[1], msg2[2]])
        {
            return SessionEnd::Handshake(HandshakeError::PeerRefused);
        }
    }
    let noise = match init.finish(&msg2) {
        Ok(s) => s,
        Err(e) => return SessionEnd::Handshake(e),
    };
    g.reader = RecordReader::new();
    let mut wire = Wire { io: &mut io, clock, noise, io_ms: t.io_ms, bytes_out: 0 };
    let mut h2 = H2Session::new(H2Config::default());
    let out_base = stats.bytes_out;
    let mut bufs = Bufs { rx, stats, pos, len, out_base };
    let end = serve(cfg, lease, g, &mut bufs, &mut wire, &mut h2, sink, guard, endpoints).await;
    bufs.stats.noise = *wire.noise.stats();
    bufs.stats.h2 = h2.counters;
    bufs.stats.bytes_out = bufs.out_base + wire.bytes_out;
    end
}

/// The session's own buffers and the cursor into the input buffer.
struct Bufs<'a> {
    rx: &'a mut [u8; RX_BYTES],
    stats: &'a mut SessionStats,
    pos: usize,
    len: usize,
    out_base: u64,
}

#[allow(clippy::too_many_arguments)]
async fn serve<'l, L: BulkLease, S: Read + Write, K: Clock, Sk: MapSink, G: Gate, P: EndpointSource>(
    cfg: &SessionConfig<'_>,
    lease: &'l L,
    first: L::Guard<'l>,
    b: &mut Bufs<'_>,
    wire: &mut Wire<'_, S, K>,
    h2: &mut H2Session,
    sink: &mut Sk,
    guard: &mut GateGuard<'_, G>,
    endpoints: &mut P,
) -> SessionEnd {
    let t = cfg.timeouts;
    let mut hostinfo = cfg.hostinfo;
    let Bufs { rx, stats, pos, len, out_base } = b;
    // The leased buffers: `Some` while held. `bulk!()` takes them when they are not held (waiting its turn); the idle wait below gives them back.
    let mut g: Option<L::Guard<'l>> = Some(first);
    macro_rules! bulk {
        () => {{
            if g.is_none() {
                g = Some(lease.lease().await);
            }
            match g.as_mut() {
                Some(x) => &mut **x,
                None => unreachable!(),
            }
        }};
    }
    // 4. HTTP/2 preface, then everything else is driven by what arrives.
    {
        let w = bulk!();
        if let Err(e) = wire.flush(h2, &mut w.tx).await {
            return stage(e, Stage::Early);
        }
    }
    let node_pub = x25519::public(cfg.node_priv);
    let mut early = EarlyParser::new();
    let mut early_done = false;
    let mut challenge: Option<Key32> = None;
    let mut registered = false;
    let mut register_len = 0usize;
    let mut register_overflow = false;
    let mut register_status: Option<u16> = None;
    let mut register_end = false;
    let mut map_sent = false;
    let mut mstream = MapStream::new(STREAM_LONG_POLL);
    let start = wire.clock.now();
    let phase_deadline: Millis = start + t.first_map_ms as Millis;
    let mut last_rx = start;
    let mut last_ping = start;
    let mut ep_hash: Option<u32> = None;
    let mut next_update = FIRST_UPDATE_STREAM;
    let mut ep_buf = [Endpoint { addr: tdongle_tailnet_control::requests::EndpointAddr::V4 { ip: [0; 4], port: 0 }, kind: 0 }; MAX_ENDPOINTS];

    loop {
        // ---- send what the state calls for ----
        if early_done && !registered {
            registered = true;
            let w = bulk!();
            let mut req = RegisterRequest::new(&node_pub, cfg.hostinfo);
            req.auth_key = cfg.auth_key;
            req.followup = cfg.followup;
            let resp = challenge.as_ref().and_then(|c| node_key_challenge_response(cfg.node_priv, c));
            req.challenge_response = resp.as_ref();
            let jl = match req.write_json(&mut w.json[..]) {
                Ok(n) => n,
                Err(_) => return SessionEnd::RequestTooLarge,
            };
            if let Err(e) = wire.request(h2, &mut w.tx, STREAM_REGISTER, "/machine/register", cfg.host_header, &w.json[..jl]).await {
                return stage(e, Stage::Register);
            }
        }
        if register_end && !map_sent {
            let w = bulk!();
            // The response is complete: judge it, then ask for the stream.
            if let Some(s) = register_status
                && s != 200
            {
                return SessionEnd::Register(RegisterFailure::HttpStatus(s));
            }
            if register_overflow {
                return SessionEnd::Register(RegisterFailure::Overflow);
            }
            stats.register_bytes = register_len as u32;
            match parse_register_response(&w.json[..register_len]) {
                Ok(RegisterOutcome::Registered { machine_authorized }) => stats.machine_authorized = machine_authorized,
                Ok(RegisterOutcome::AuthUrl(u)) => return SessionEnd::Register(RegisterFailure::AuthUrl(u)),
                Ok(RegisterOutcome::Refused(m)) => return SessionEnd::Register(RegisterFailure::Refused(m)),
                Ok(RegisterOutcome::NodeKeyExpired) => return SessionEnd::Register(RegisterFailure::NodeKeyExpired),
                Err(e) => return SessionEnd::Register(RegisterFailure::Malformed(e)),
            }
            map_sent = true;
            let req = MapRequest {
                node_key: &node_pub,
                disco_key: cfg.disco_pub,
                hostinfo: cfg.hostinfo,
                kind: MapKind::LongPoll { omit_peers: false },
                endpoints: &[],
            };
            let jl = match req.write_json(&mut w.json[..]) {
                Ok(n) => n,
                Err(_) => return SessionEnd::RequestTooLarge,
            };
            if let Err(e) = wire.request(h2, &mut w.tx, STREAM_LONG_POLL, "/machine/map", cfg.host_header, &w.json[..jl]).await {
                return stage(e, Stage::Map);
            }
        }
        let now = wire.clock.now();
        if stats.first_map_applied {
            if now.saturating_sub(last_ping) >= PING_INTERVAL_MS {
                last_ping = now;
                h2.queue_ping(now.to_be_bytes());
                stats.pings_sent += 1;
            }
            if let Some(p) = endpoints.preferred_derp() {
                hostinfo.preferred_derp = u32::from(p);
            }
            if let Some(k) = endpoints.poll_endpoints(&mut ep_buf) {
                let k = k.min(MAX_ENDPOINTS);
                if k > 0 {
                    let w = bulk!();
                    let req = MapRequest { node_key: &node_pub, disco_key: cfg.disco_pub, hostinfo, kind: MapKind::EndpointUpdate, endpoints: &ep_buf[..k] };
                    let jl = match req.write_json(&mut w.json[..]) {
                        Ok(n) => n,
                        Err(_) => return SessionEnd::RequestTooLarge,
                    };
                    let hash = fnv1a32(&w.json[..jl]);
                    if ep_hash == Some(hash) {
                        stats.endpoint_updates_unchanged += 1;
                    } else {
                        if let Err(e) = wire.request(h2, &mut w.tx, next_update, "/machine/map", cfg.host_header, &w.json[..jl]).await {
                            return stage(e, Stage::Map);
                        }
                        next_update += 2;
                        ep_hash = Some(hash);
                        stats.endpoint_updates += 1;
                    }
                }
            }
        }
        if h2.pending_output() > 0 {
            let w = bulk!();
            if let Err(e) = wire.flush(h2, &mut w.tx).await {
                return stage(e, Stage::Map);
            }
        }

        // ---- wait for input ----
        if *pos == *len {
            // Nothing in progress (the first map applied, no half record, between map messages): give the buffers back while waiting for the server,
            // which is where a quiet membership spends nearly all its time.
            if stats.first_map_applied
                && mstream.framer.at_boundary()
                && let Some(x) = g.as_ref()
                && x.reader.buffered() == 0
            {
                g = None;
            }
            let (st, wait) = if stats.first_map_applied {
                (Stage::Map, TICK_MS)
            } else {
                let left = phase_deadline.saturating_sub(now);
                if left == 0 {
                    return if registered && !register_end || !early_done {
                        SessionEnd::Io { stage: if early_done { Stage::Register } else { Stage::Early }, fail: IoFail::Timeout }
                    } else {
                        SessionEnd::Map(MapEnd::Deadline)
                    };
                }
                (
                    if !early_done {
                        Stage::Early
                    } else if !map_sent {
                        Stage::Register
                    } else {
                        Stage::Map
                    },
                    left.min(TICK_MS as Millis) as u32,
                )
            };
            match read_some(wire.io, wire.clock, &mut rx[..], wait).await {
                Ok(k) => {
                    (*pos, *len) = (0, k);
                    stats.bytes_in += k as u64;
                    last_rx = wire.clock.now();
                }
                Err(IoFail::Timeout) => {
                    let silent = wire.clock.now().saturating_sub(last_rx);
                    if silent >= t.idle_ms as Millis {
                        return SessionEnd::Idle;
                    }
                    // the stall bound of the lease: a server that went quiet in the middle of a record or message
                    if g.is_some() && stats.first_map_applied && silent >= t.lease_stall_ms as Millis {
                        return SessionEnd::LeaseStall;
                    }
                    continue;
                }
                Err(fail) => return SessionEnd::Io { stage: st, fail },
            }
        }

        // ---- decrypt one record, process its plaintext ----
        let Bulk { reader, tx, json, projector } = bulk!();
        let (used, feed) = reader.feed(&mut wire.noise, &rx[*pos..*len]);
        *pos += used;
        let plain: &[u8] = match feed {
            Feed::NeedMore => continue,
            Feed::Error(e) => return SessionEnd::Record(e),
            Feed::Record(p) => p,
        };
        let mut rest: &[u8] = plain;
        if !early_done {
            match early.push(&mut json[..EARLY_BYTES], rest) {
                Err(e) => return SessionEnd::Early(e),
                Ok((k, EarlyStatus::NeedMore)) => {
                    rest = &rest[k..];
                    debug_assert!(rest.is_empty());
                    continue;
                }
                Ok((k, EarlyStatus::Present { challenge: c })) => {
                    rest = &rest[k..];
                    stats.challenge_seen = c.is_some();
                    challenge = c;
                    early_done = true;
                }
                Ok((k, EarlyStatus::Absent { replay })) => {
                    rest = &rest[k..];
                    early_done = true;
                    // The nine bytes belong to HTTP/2: feed them first.
                    let mut r = &replay[..];
                    loop {
                        let (n, ev) = h2.on_input(r);
                        r = &r[n..];
                        if let Some(end) = h2_event_outside_map(&ev, h2) {
                            return end;
                        }
                        if matches!(ev, Event::Idle) {
                            break;
                        }
                    }
                }
            }
        }
        // The map projector borrows the leased projector and the stats; the HTTP/2 events borrow `rest`.
        loop {
            let (n, ev) = h2.on_input(rest);
            rest = &rest[n..];
            match ev {
                Event::Idle => break,
                Event::Blocked => {
                    if let Err(e) = wire.flush(h2, tx).await {
                        return stage(e, Stage::Map);
                    }
                }
                Event::Data { stream, bytes } if stream == STREAM_REGISTER => {
                    if register_len + bytes.len() > json.len() {
                        register_overflow = true;
                    } else {
                        json[register_len..register_len + bytes.len()].copy_from_slice(bytes);
                        register_len += bytes.len();
                    }
                }
                Event::Headers { stream, status, .. } if stream == STREAM_REGISTER => register_status = status,
                Event::StreamEnd { stream } if stream == STREAM_REGISTER => register_end = true,
                Event::Data { stream, bytes } if stream == STREAM_LONG_POLL => {
                    let mut counting = Counting { inner: sink, stats, committed: false };
                    let mut b = bytes;
                    loop {
                        let (k, fe) = match mstream.framer.push(b) {
                            Ok(x) => x,
                            Err(tdongle_tailnet_control::map::MapError::BadLength(l)) => return SessionEnd::Map(MapEnd::BadLength(l)),
                        };
                        b = &b[k..];
                        match fe {
                            Some(FrameEvent::Start { .. }) => projector.reset(MapConfig::new(cfg.home_derp).with_flash_directory()),
                            Some(FrameEvent::Json(j)) => {
                                counting.stats.map_bytes += j.len() as u64;
                                if let Err(e) = projector.feed(j, &mut counting) {
                                    return SessionEnd::Map(MapEnd::Projector(e));
                                }
                            }
                            Some(FrameEvent::End) => {
                                if let Err(e) = projector.finish(&mut counting) {
                                    return SessionEnd::Map(MapEnd::Projector(e));
                                }
                                counting.stats.maps += 1;
                                mstream.mark_applied();
                                if counting.committed {
                                    counting.committed = false;
                                    if !counting.stats.first_map_applied {
                                        counting.stats.first_map_applied = true;
                                        last_ping = wire.clock.now();
                                        last_rx = last_ping;
                                        // from here on the writes are bounded by the lease's stall bound as well
                                        wire.io_ms = wire.io_ms.min(t.lease_stall_ms);
                                    }
                                }
                            }
                            None if k == 0 => break,
                            None => {}
                        }
                    }
                    let first = stats.first_map_applied;
                    if first {
                        guard.release(true).await;
                    }
                }
                Event::StreamEnd { stream } if stream == STREAM_LONG_POLL => {
                    return SessionEnd::Map(MapEnd::StreamEnded { clean: mstream.on_end() != StreamEnd::MidMessage });
                }
                Event::Ping { ack: true, .. } => stats.ping_acks += 1,
                other => {
                    if let Some(end) = h2_event_outside_map(&other, h2) {
                        return end;
                    }
                }
            }
        }
        // Keep the counters current for a caller that reads them while the session runs.
        stats.noise = *wire.noise.stats();
        stats.h2 = h2.counters;
        stats.bytes_out = *out_base + wire.bytes_out;
    }
}

fn stage(e: SessionEnd, s: Stage) -> SessionEnd {
    match e {
        SessionEnd::Io { fail, .. } => SessionEnd::Io { stage: s, fail },
        other => other,
    }
}

/// Events that end the session whatever the phase.
fn h2_event_outside_map(ev: &Event<'_>, h2: &H2Session) -> Option<SessionEnd> {
    match *ev {
        Event::Fatal(e) => Some(SessionEnd::H2(e)),
        Event::Closed => Some(SessionEnd::H2(h2::H2Error::FrameSize)),
        Event::GoAway { code, last_stream } => Some(SessionEnd::GoAway { code, debug: h2.close_info().debug.clone(), last_stream }),
        Event::Reset { stream, code } if stream == STREAM_REGISTER || stream == STREAM_LONG_POLL => Some(SessionEnd::Reset { stream, code }),
        _ => None,
    }
}
