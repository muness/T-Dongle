#![cfg(all(feature = "lease", feature = "p384"))]
//! The per-record lease from the shared pool: three TLS connections reading records into buffers of exactly the announced length, interleaved; memory
//! pressure turning into waiting (never a failed read); a server that stalls inside a record; and (ignored) the throughput / CPU comparison with the stock
//! connection.
use core::cell::RefCell;
use core::future::{Future, poll_fn};
use core::task::Poll;
use embassy_futures::block_on;
use embassy_futures::join::{join, join3};
use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tdongle_tailnet_admission::probe::{FixedProbe, HeapSnapshot};
use tdongle_tailnet_pool::{Mem, Pool};
use tdongle_tailnet_tls::lease::{LeasePool, LeasedTlsDerp, ReadError};
use tdongle_tailnet_tls::transport::{TlsParams, Upgrade, UpgradeParser, upgrade_request};
use tdongle_tailnet_tls::{DerpTransport, READ_RECORD_BYTES, TlsDerp, TrustAnchor, WRITE_RECORD_BYTES, parse_cert_name};
use tdongle_tailnet_types::test_util::TestRng;

const NOW: u64 = 1_791_244_800;
const H: &str = "derp1.test.example";

fn f(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}.der", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Non-blocking socket as an async `embedded-io` stream: `WouldBlock` yields to the executor (busy polling: fine for a test).
struct NbSock(TcpStream);
impl ErrorType for NbSock {
    type Error = ErrorKind;
}
impl Read for NbSock {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, ErrorKind> {
        poll_fn(|cx| match self.0.read(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(ErrorKind::Other)),
        })
        .await
    }
}
impl Write for NbSock {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, ErrorKind> {
        poll_fn(|cx| match self.0.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(ErrorKind::Other)),
        })
        .await
    }
    async fn flush(&mut self) -> Result<(), ErrorKind> {
        Ok(())
    }
}

fn after(d: Duration) -> impl Future<Output = ()> {
    let end = Instant::now() + d;
    poll_fn(move |cx| {
        if Instant::now() >= end {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);
impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// A heap with room for everything the tests ask: the floor is what the pool is tested against, so the probe reports the floor plus `room`.
fn heap(room: usize) -> FixedProbe {
    let free = tdongle_tailnet_admission::heap::ML_HB_FLOOR + room;
    FixedProbe(HeapSnapshot { free, largest: free, minimum: free })
}

#[derive(Clone, Copy)]
struct Spec {
    /// Records to send after the 101.
    records: usize,
    /// Plaintext bytes of each record.
    record: usize,
    /// Pause between records.
    gap: Duration,
    /// Wait this long after the 101 before the first record.
    delay: Duration,
    /// Send only this many bytes (header included) of the LAST record, then go quiet for 30 s.
    stall_in_last: Option<usize>,
}

fn serve(spec: Spec) -> u16 {
    let certs: Vec<CertificateDer<'static>> = ["leaf_ok", "ye2", "ye", "x2_cross", "derpkey"].iter().map(|n| CertificateDer::from(f(n))).collect();
    let provider = rustls::crypto::ring::default_provider();
    let signer = provider.key_provider.load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(f("key_leafk")))).unwrap();
    let ck = Arc::new(CertifiedKey { cert: certs, key: signer, ocsp: None });
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(ck))),
    );
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return };
        s.set_nodelay(true).ok();
        let mut c = rustls::ServerConnection::new(cfg).unwrap();
        {
            let mut tls = rustls::Stream::new(&mut c, &mut s);
            let mut req = [0u8; 512];
            let mut n = 0;
            loop {
                match tls.read(&mut req[n..]) {
                    Ok(0) | Err(_) => return,
                    Ok(k) => n += k,
                }
                if req[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n");
            let _ = tls.flush();
        }
        std::thread::sleep(spec.delay);
        let mut off = 0usize;
        for i in 0..spec.records {
            let data: Vec<u8> = (0..spec.record).map(|k| ((off + k) % 251) as u8).collect();
            off += spec.record;
            c.writer().write_all(&data).unwrap();
            if let Some(cut) = spec.stall_in_last.filter(|_| i + 1 == spec.records) {
                let mut v = Vec::new();
                c.write_tls(&mut v).unwrap();
                let _ = s.write_all(&v[..cut.min(v.len())]);
                std::thread::sleep(Duration::from_secs(30));
                return;
            }
            while c.wants_write() {
                if c.write_tls(&mut s).is_err() {
                    return;
                }
            }
            std::thread::sleep(spec.gap);
        }
        let mut sink = [0u8; 64];
        let _ = s.read(&mut sink); // keep the socket open until the client is done
    });
    port
}

fn test_anchor() -> (Vec<u8>, Vec<u8>) {
    fn tlv(b: &[u8]) -> (usize, usize) {
        let l = b[1] as usize;
        if l < 0x80 {
            (2, l)
        } else {
            let n = l & 0x7f;
            (2 + n, b[2..2 + n].iter().fold(0, |a, &x| a << 8 | x as usize))
        }
    }
    let d = f("x2");
    let (h, _) = tlv(&d);
    let cert = &d[h..];
    let (h, _) = tlv(cert);
    let mut c = &cert[h..];
    if c[0] == 0xa0 {
        let (h, l) = tlv(c);
        c = &c[h + l..];
    }
    let next = |c: &mut &[u8]| {
        let (h, l) = tlv(c);
        let t = c[..h + l].to_vec();
        *c = &c[h + l..];
        t
    };
    next(&mut c);
    next(&mut c);
    next(&mut c);
    next(&mut c);
    (next(&mut c), next(&mut c))
}

fn nb_connect(port: u16) -> NbSock {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_nonblocking(true).unwrap();
    s.set_nodelay(true).ok();
    NbSock(s)
}

/// The counters, the pool and the heap one test runs against.
struct Env {
    stats: LeasePool,
    pool: Pool,
    probe: FixedProbe,
}

impl Env {
    fn new(cap: usize) -> Env {
        Env { stats: LeasePool::new(), pool: Pool::new(cap), probe: heap(1 << 20) }
    }
    fn mem(&self) -> Mem<'_> {
        Mem { pool: &self.pool, heap: &self.probe }
    }
}

/// Run one leased client: handshake, upgrade, read `want` payload bytes (checking the pattern). `order` records which client read each record.
async fn leased_client(id: usize, port: u16, env: &Env, want: usize, stall: Duration, order: &RefCell<Vec<usize>>) -> Result<usize, ReadError> {
    let (s, k) = test_anchor();
    let anchors = [TrustAnchor { subject: &s, spki: &k }];
    let cert = parse_cert_name(Some(H), None);
    let params = TlsParams { hostname: H, cert: &cert, anchors: &anchors, now_unix: NOW };
    let mut wb = vec![0u8; WRITE_RECORD_BYTES];
    let mut rng = TestRng(0x1234 + id as u64);
    let mut c = LeasedTlsDerp::connect(nb_connect(port), &mut wb, &env.stats, env.mem(), &params, &mut rng).await.expect("leased handshake");
    let mut req = [0u8; 200];
    let n = upgrade_request(H, &mut req).unwrap();
    c.write_all(&req[..n]).await.unwrap();
    c.flush().await.unwrap();
    let mut p = UpgradeParser::new();
    let mut upgraded = false;
    let mut total = 0usize;
    // the carry buffer of the DERP layer is not needed here: the payload is checked in place
    while total < want {
        let mut got = 0;
        let r = c
            .read_with(
                || after(stall),
                |chunk| {
                    let mut chunk = chunk;
                    while !upgraded && !chunk.is_empty() {
                        let v = p.push(chunk[0]);
                        chunk = &chunk[1..];
                        assert_ne!(v, Upgrade::Refused);
                        upgraded = v == Upgrade::Done;
                    }
                    for (i, &b) in chunk.iter().enumerate().filter(|_| want <= 1 << 20) {
                        assert_eq!(b, ((total + got + i) % 251) as u8, "client {id}: payload corrupted at {}", total + got + i);
                    }
                    got += chunk.len();
                },
            )
            .await?;
        order.borrow_mut().push(id);
        let _ = r;
        total += got;
    }
    Ok(total)
}

#[test]
fn three_connections_read_records_into_exact_size_leases_and_hand_every_byte_back() {
    let spec = Spec { records: 12, record: 16384, gap: Duration::from_millis(3), delay: Duration::from_millis(0), stall_in_last: None };
    let ports = [serve(spec), serve(spec), serve(spec)];
    let env = Env::new(1 << 20);
    let order = RefCell::new(Vec::new());
    let want = 12 * 16384;
    let t = Instant::now();
    let (a, b, c) = block_on(join3(
        leased_client(0, ports[0], &env, want, Duration::from_secs(5), &order),
        leased_client(1, ports[1], &env, want, Duration::from_secs(5), &order),
        leased_client(2, ports[2], &env, want, Duration::from_secs(5), &order),
    ));
    assert_eq!((a.unwrap(), b.unwrap(), c.unwrap()), (want, want, want));
    assert_eq!(env.stats.timeouts(), 0);
    // handshakes lease per record too: 3 connections x (ServerHello + 4 flight records) + 3 x 12 payload records at least
    assert!(env.stats.leases() >= 3 * 12 + 3 * 3, "leases {}", env.stats.leases());
    // every lease was given back: nothing is held between records, and nothing leaks
    assert_eq!((env.stats.holders(), env.pool.in_use()), (0, 0));
    // never more than one record per connection at a time: 3 x 16,640 at the very most
    assert!(env.pool.stats().high_water as usize <= 3 * READ_RECORD_BYTES, "high water {}", env.pool.stats().high_water);
    // records of different connections really interleaved
    let order = order.borrow();
    let switches = order.windows(2).filter(|w| w[0] != w[1]).count();
    assert!(switches >= 12, "only {switches} switches in {order:?}");
    println!(
        "3 connections, {} KB each in {:?}: leases {}, record order switches {switches}, pool high water {} B",
        want / 1024,
        t.elapsed(),
        env.stats.leases(),
        env.pool.stats().high_water
    );
}

#[test]
fn a_lease_is_as_long_as_the_record_not_as_long_as_the_biggest_record() {
    // a Go derper writes through a 2 KiB bufio: records of about 2 KB. The old shared buffer was 16,640 B whatever the records were.
    let spec = Spec { records: 40, record: 1500, gap: Duration::from_millis(0), delay: Duration::from_millis(0), stall_in_last: None };
    let ports = [serve(spec), serve(spec)];
    let env = Env::new(1 << 20);
    let order = RefCell::new(Vec::new());
    let want = 40 * 1500;
    let (a, b) = block_on(join(
        leased_client(0, ports[0], &env, want, Duration::from_secs(5), &order),
        leased_client(1, ports[1], &env, want, Duration::from_secs(5), &order),
    ));
    assert_eq!((a.unwrap(), b.unwrap()), (want, want));
    // the handshake's Certificate flight (about 4.5 KB per record) is the biggest lease; data records are 1,500 + 22 B each
    let hw = env.pool.stats().high_water as usize;
    assert!(hw < 2 * 6_000, "high water {hw} B: the leases are not sized by the records");
    assert_eq!(env.pool.in_use(), 0);
}

#[test]
fn memory_pressure_is_backpressure_not_a_failed_read() {
    // The pool holds one maximal record. A stalls inside one (holding it), B and C start talking meanwhile: they must wait for memory (not fail, not drop
    // bytes) and read everything once A's stall timeout gives the bytes back.
    let a_spec = Spec { records: 2, record: 16384, gap: Duration::from_millis(1), delay: Duration::from_millis(0), stall_in_last: Some(3000) };
    let bc = Spec { records: 6, record: 16384, gap: Duration::from_millis(2), delay: Duration::from_millis(200), stall_in_last: None };
    let ports = [serve(a_spec), serve(bc), serve(bc)];
    let env = Env::new(READ_RECORD_BYTES);
    let order = RefCell::new(Vec::new());
    let want = 6 * 16384;
    let t = Instant::now();
    let stall = Duration::from_millis(700);
    let (a, b, c) = block_on(join3(
        leased_client(0, ports[0], &env, 2 * 16384, stall, &order),
        leased_client(1, ports[1], &env, want, Duration::from_secs(10), &order),
        leased_client(2, ports[2], &env, want, Duration::from_secs(10), &order),
    ));
    assert!(matches!(a, Err(ReadError::LeaseTimeout)), "{a:?}");
    assert_eq!((b.unwrap(), c.unwrap()), (want, want), "every byte arrived intact");
    assert!(t.elapsed() >= stall, "B and C had to wait for A's bytes to come back: {:?}", t.elapsed());
    let st = env.pool.stats();
    assert!(st.high_water as usize <= READ_RECORD_BYTES, "the cap held: {}", st.high_water);
    assert!(st.waits >= 2 && st.denied_cap > 0, "the pool must have said no and made B and C wait: {st:?}");
    assert_eq!((env.stats.holders(), env.pool.in_use()), (0, 0));
}

#[test]
fn a_stall_inside_a_record_times_out_gives_its_bytes_back_and_blocks_nobody() {
    // Connection A sends 3,000 bytes of a 16 KB record and goes quiet; B starts talking while A holds its record buffer.
    let a_spec = Spec { records: 2, record: 16384, gap: Duration::from_millis(1), delay: Duration::from_millis(0), stall_in_last: Some(3000) };
    let b_spec = Spec { records: 6, record: 16384, gap: Duration::from_millis(5), delay: Duration::from_millis(150), stall_in_last: None };
    let (pa, pb) = (serve(a_spec), serve(b_spec));
    let env = Env::new(1 << 20);
    let order = RefCell::new(Vec::new());
    let t = Instant::now();
    let stall = Duration::from_millis(600);
    let (a, (b, b_done)) = block_on(join(leased_client(0, pa, &env, 2 * 16384, stall, &order), async {
        let r = leased_client(1, pb, &env, 6 * 16384, Duration::from_secs(5), &order).await;
        (r, t.elapsed())
    }));
    assert!(matches!(a, Err(ReadError::LeaseTimeout)), "{a:?}");
    assert_eq!(b.unwrap(), 6 * 16384, "the other connection finishes");
    assert_eq!(env.stats.timeouts(), 1);
    // B no longer waits for A (the old shared buffer made it wait for A's timeout): it was done well before A gave up
    assert!(b_done < stall, "B finished at {b_done:?}, A's stall bound is {stall:?}");
    // and A's record buffer went back when it timed out
    assert_eq!((env.stats.holders(), env.pool.in_use()), (0, 0));
    println!("stall test: A timed out, B done at {b_done:?}, total {:?}", t.elapsed());
}

#[test]
fn a_record_longer_than_the_protocol_allows_is_refused_before_any_allocation() {
    // RFC 8446 5.2: ciphertext over 2^14 + 256 is a record_overflow. A server announcing 64 KB must not make the gateway ask the heap for 64 KB.
    use std::io::Write as _;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut sink = [0u8; 2048];
        let _ = std::io::Read::read(&mut s, &mut sink);
        // a ServerHello-shaped record header announcing 65,000 bytes
        let _ = s.write_all(&[0x16, 0x03, 0x03, 0xFD, 0xE8]);
        std::thread::sleep(Duration::from_millis(300));
    });
    let env = Env::new(1 << 20);
    let (s, k) = test_anchor();
    let anchors = [TrustAnchor { subject: &s, spki: &k }];
    let cert = parse_cert_name(Some(H), None);
    let params = TlsParams { hostname: H, cert: &cert, anchors: &anchors, now_unix: NOW };
    let mut wb = vec![0u8; WRITE_RECORD_BYTES];
    let mut rng = TestRng(9);
    let r = block_on(LeasedTlsDerp::connect(nb_connect(port), &mut wb, &env.stats, env.mem(), &params, &mut rng));
    assert!(r.is_err());
    assert_eq!(env.pool.stats().takes, [0, 0, 0], "nothing was allocated for an impossible record");
    h.join().unwrap();
}

async fn stock_client(id: usize, port: u16, want: usize) -> usize {
    let (s, k) = test_anchor();
    let anchors = [TrustAnchor { subject: &s, spki: &k }];
    let cert = parse_cert_name(Some(H), None);
    let params = TlsParams { hostname: H, cert: &cert, anchors: &anchors, now_unix: NOW };
    let (mut rb, mut wb) = (vec![0u8; READ_RECORD_BYTES], vec![0u8; WRITE_RECORD_BYTES]);
    let mut rng = TestRng(0x1234 + id as u64);
    let mut c = TlsDerp::connect(nb_connect(port), &mut rb, &mut wb, &params, &mut rng).await.expect("stock handshake");
    let mut req = [0u8; 200];
    let n = upgrade_request(H, &mut req).unwrap();
    c.write_all(&req[..n]).await.unwrap();
    c.flush().await.unwrap();
    let mut p = UpgradeParser::new();
    let mut b = [0u8; 1];
    loop {
        c.read(&mut b).await.unwrap();
        if p.push(b[0]) == Upgrade::Done {
            break;
        }
    }
    let mut total = 0;
    let mut buf = [0u8; 4096];
    while total < want {
        total += c.read(&mut buf).await.unwrap();
    }
    total
}

/// `cargo test -p tdongle-tailnet-tls --features lease --test lease -- --ignored --nocapture`
#[test]
#[ignore = "benchmark"]
fn throughput_and_cpu_stock_vs_lease() {
    let records = 400; // 6.5 MB per connection
    let want = records * 16384;
    let spec = Spec { records, record: 16384, gap: Duration::from_millis(0), delay: Duration::from_millis(0), stall_in_last: None };
    for conns in [1usize, 3] {
        // stock
        let ports: Vec<u16> = (0..conns).map(|_| serve(spec)).collect();
        let t = Instant::now();
        match conns {
            1 => {
                block_on(stock_client(0, ports[0], want));
            }
            _ => {
                block_on(join3(stock_client(0, ports[0], want), stock_client(1, ports[1], want), stock_client(2, ports[2], want)));
            }
        }
        let dt = t.elapsed();
        println!(
            "stock  x{conns}: {:.1} MB/s total ({:?} wall, single busy-polling thread so wall = CPU; {} B pinned read buffers)",
            (conns * want) as f64 / 1e6 / dt.as_secs_f64(),
            dt,
            conns * READ_RECORD_BYTES
        );
        // leased
        let ports: Vec<u16> = (0..conns).map(|_| serve(spec)).collect();
        let env = Env::new(1 << 20);
        let order = RefCell::new(Vec::new());
        let t = Instant::now();
        let s = Duration::from_secs(10);
        match conns {
            1 => {
                block_on(leased_client(0, ports[0], &env, want, s, &order)).unwrap();
            }
            _ => {
                let (a, b, c) = block_on(join3(
                    leased_client(0, ports[0], &env, want, s, &order),
                    leased_client(1, ports[1], &env, want, s, &order),
                    leased_client(2, ports[2], &env, want, s, &order),
                ));
                assert!(a.is_ok() && b.is_ok() && c.is_ok());
            }
        }
        let dt = t.elapsed();
        println!(
            "leased x{conns}: {:.1} MB/s total ({:?} wall; no pinned read buffers, pool high water {} B)",
            (conns * want) as f64 / 1e6 / dt.as_secs_f64(),
            dt,
            env.pool.stats().high_water
        );
    }
}

/// Needs the network: three leased connections to a real DERP server through the shared pool, each upgrades and reads the ServerKey frame.
#[test]
#[ignore = "needs network access to derp1.tailscale.com"]
fn live_derp_three_leased_connections() {
    use std::net::ToSocketAddrs;
    let host = "derp1.tailscale.com";
    let addr = (host, 443).to_socket_addrs().unwrap().find(|a| a.is_ipv4()).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let env = Env::new(1 << 20);
    let one = |id: u64| {
        let env = &env;
        async move {
            let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
            s.set_nonblocking(true).unwrap();
            let cert = parse_cert_name(Some(host), None);
            let params = TlsParams { hostname: host, cert: &cert, anchors: tdongle_tailnet_tls::DEFAULT_ANCHORS, now_unix: now };
            let mut wb = vec![0u8; WRITE_RECORD_BYTES];
            let mut rng = TestRng(now + id);
            let mut c = LeasedTlsDerp::connect(NbSock(s), &mut wb, &env.stats, env.mem(), &params, &mut rng).await.expect("handshake");
            let mut req = [0u8; 200];
            let n = upgrade_request(host, &mut req).unwrap();
            c.write_all(&req[..n]).await.unwrap();
            c.flush().await.unwrap();
            let (mut p, mut done, mut payload) = (UpgradeParser::new(), false, Vec::new());
            while payload.len() < 5 + 40 {
                c.read_with(
                    || after(Duration::from_secs(5)),
                    |chunk| {
                        for &b in chunk {
                            if !done { done = p.push(b) == Upgrade::Done } else { payload.push(b) }
                        }
                    },
                )
                .await
                .unwrap();
            }
            assert_eq!(payload[0], 0x01, "frameServerKey");
            c.trusted_by()
        }
    };
    let (a, b, c) = block_on(join3(one(1), one(2), one(3)));
    println!("three leased connections to {host}: {a:?} {b:?} {c:?}; leases {}, high water {}", env.stats.leases(), env.pool.stats().high_water);
    assert_eq!(env.pool.in_use(), 0);
}

/// Cancelling a stalled body retains its lease; resuming uses the original deadline, then poisons the connection and refunds exactly once.
#[test]
fn cancelled_owned_body_retains_lease_and_original_timeout_then_poison_refunds() {
    use embassy_futures::select::{Either, select};
    let spec = Spec { records: 1, record: 16384, gap: Duration::ZERO, delay: Duration::from_millis(10), stall_in_last: Some(3000) };
    let env = Env::new(READ_RECORD_BYTES);
    let (s, k) = test_anchor();
    let anchors = [TrustAnchor { subject: &s, spki: &k }];
    let cert = parse_cert_name(Some(H), None);
    let params = TlsParams { hostname: H, cert: &cert, anchors: &anchors, now_unix: NOW };
    let mut wb = vec![0u8; WRITE_RECORD_BYTES];
    let mut rng = TestRng(1234);
    block_on(async {
        let mut c = LeasedTlsDerp::connect(nb_connect(serve(spec)), &mut wb, &env.stats, env.mem(), &params, &mut rng).await.unwrap();
        let mut req = [0u8; 200];
        let n = upgrade_request(H, &mut req).unwrap();
        c.write_all(&req[..n]).await.unwrap();
        c.flush().await.unwrap();
        let mut p = UpgradeParser::new();
        let mut upgraded = false;
        while !upgraded {
            c.read_with(
                || after(Duration::from_secs(2)),
                |bytes| {
                    for &b in bytes {
                        upgraded |= p.push(b) == Upgrade::Done;
                    }
                },
            )
            .await
            .unwrap();
        }
        let mut deadline = None;
        let resumed_timer = |deadline: &mut Option<Instant>| {
            let end = *deadline.get_or_insert_with(|| Instant::now() + Duration::from_millis(150));
            after(end.saturating_duration_since(Instant::now()))
        };
        match select(c.read_owned(|| resumed_timer(&mut deadline)), after(Duration::from_millis(50))).await {
            Either::Second(()) => {}
            Either::First(_) => panic!("body must be stalled"),
        }
        assert_eq!(env.stats.holders(), 1, "cancelled future retains the original record");
        assert!(env.pool.in_use() > 16_000);
        let leases = env.stats.leases();
        let start = Instant::now();
        assert!(matches!(c.read_owned(|| resumed_timer(&mut deadline)).await, Err(ReadError::LeaseTimeout)));
        assert!(start.elapsed() < Duration::from_millis(140), "original timeout was retained");
        assert_eq!((env.pool.in_use(), env.stats.holders()), (0, 0));
        assert_eq!(env.stats.leases(), leases);
        assert_eq!(env.stats.timeouts(), 1);
        assert!(matches!(c.read_owned(|| after(Duration::from_secs(1))).await, Err(ReadError::LeaseTimeout)));
        assert_eq!((env.pool.in_use(), env.stats.holders()), (0, 0));
        assert_eq!(env.stats.leases(), leases, "poisoned stream never reacquires a lease");
    });
}

#[test]
fn owned_record_body_cancel_resume_preserves_exact_plaintext_and_single_lease() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Gated {
        io: NbSock,
        budget: Arc<AtomicUsize>,
    }
    impl ErrorType for Gated {
        type Error = ErrorKind;
    }
    impl Read for Gated {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, ErrorKind> {
            let budget = self.budget.load(Ordering::Relaxed);
            if budget == 0 {
                return core::future::pending().await;
            }
            let limit = buf.len().min(budget);
            let n = self.io.read(&mut buf[..limit]).await?;
            if budget != usize::MAX {
                self.budget.fetch_sub(n, Ordering::Relaxed);
            }
            Ok(n)
        }
    }
    impl Write for Gated {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, ErrorKind> {
            self.io.write(buf).await
        }
        async fn flush(&mut self) -> Result<(), ErrorKind> {
            self.io.flush().await
        }
    }
    let spec = Spec { records: 2, record: 16384, gap: Duration::ZERO, delay: Duration::from_millis(10), stall_in_last: None };
    let env = Env::new(READ_RECORD_BYTES);
    let (s, k) = test_anchor();
    let anchors = [TrustAnchor { subject: &s, spki: &k }];
    let cert = parse_cert_name(Some(H), None);
    let params = TlsParams { hostname: H, cert: &cert, anchors: &anchors, now_unix: NOW };
    let mut wb = vec![0u8; WRITE_RECORD_BYTES];
    let mut rng = TestRng(5678);
    let budget = Arc::new(AtomicUsize::new(usize::MAX));
    block_on(async {
        let io = Gated { io: nb_connect(serve(spec)), budget: budget.clone() };
        let mut c = LeasedTlsDerp::connect(io, &mut wb, &env.stats, env.mem(), &params, &mut rng).await.unwrap();
        let mut req = [0u8; 200];
        let n = upgrade_request(H, &mut req).unwrap();
        c.write_all(&req[..n]).await.unwrap();
        c.flush().await.unwrap();
        let mut p = UpgradeParser::new();
        let mut upgraded = false;
        while !upgraded {
            c.read_with(
                || after(Duration::from_secs(2)),
                |bytes| {
                    for &b in bytes {
                        upgraded |= p.push(b) == Upgrade::Done;
                    }
                },
            )
            .await
            .unwrap();
        }
        budget.store(7, Ordering::Relaxed); // Complete 5-byte header and only two ciphertext bytes.
        {
            let mut read = core::pin::pin!(c.read_owned(|| core::future::pending::<()>()));
            poll_fn(|cx| {
                assert!(read.as_mut().poll(cx).is_pending());
                if budget.load(Ordering::Relaxed) == 0 {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        }
        assert_eq!(env.stats.holders(), 1);
        let leases = env.stats.leases();
        budget.store(usize::MAX, Ordering::Relaxed);
        let first = c.read_owned(|| after(Duration::from_secs(2))).await.unwrap();
        assert_eq!(first.len(), 16384);
        for (i, &b) in first.iter().enumerate() {
            assert_eq!(b, (i % 251) as u8);
        }
        assert_eq!(env.stats.leases(), leases, "resume keeps original lease");
        drop(first);
        assert_eq!((env.pool.in_use(), env.stats.holders()), (0, 0));
        let second = c.read_owned(|| after(Duration::from_secs(2))).await.unwrap();
        for (i, &b) in second.iter().enumerate() {
            assert_eq!(b, ((16384 + i) % 251) as u8);
        }
        drop(second);
        assert_eq!((env.pool.in_use(), env.stats.holders()), (0, 0));
    });
}
