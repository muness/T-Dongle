#![cfg(all(feature = "lease", feature = "p384"))]
//! The shared record-buffer lease: three TLS connections, one 16,640 B buffer behind an embassy-sync mutex, records interleaved; a server that
//! stalls inside a record; and (ignored) the throughput / CPU comparison with the stock connection.
use core::cell::RefCell;
use core::future::{Future, poll_fn};
use core::task::Poll;
use embassy_futures::block_on;
use embassy_futures::join::{join, join3};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
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

#[derive(Clone, Copy)]
struct Spec {
    /// 16,384 byte records to send after the 101.
    records: usize,
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
            let data: Vec<u8> = (0..16384).map(|k| ((off + k) % 251) as u8).collect();
            off += 16384;
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

/// Run one leased client: handshake, upgrade, read `want` payload bytes (checking the pattern). `order` records which client read each record.
async fn leased_client(
    id: usize,
    port: u16,
    pool: &LeasePool<NoopRawMutex>,
    want: usize,
    stall: Duration,
    order: &RefCell<Vec<usize>>,
) -> Result<usize, ReadError> {
    let (s, k) = test_anchor();
    let anchors = [TrustAnchor { subject: &s, spki: &k }];
    let cert = parse_cert_name(Some(H), None);
    let params = TlsParams { hostname: H, cert: &cert, anchors: &anchors, now_unix: NOW };
    let mut wb = vec![0u8; WRITE_RECORD_BYTES];
    let mut rng = TestRng(0x1234 + id as u64);
    let mut c = LeasedTlsDerp::connect(nb_connect(port), &mut wb, pool, &params, &mut rng).await.expect("leased handshake");
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
fn three_connections_share_one_lease() {
    let spec = Spec { records: 12, gap: Duration::from_millis(3), delay: Duration::from_millis(0), stall_in_last: None };
    let ports = [serve(spec), serve(spec), serve(spec)];
    let pool = LeasePool::<NoopRawMutex>::new();
    let order = RefCell::new(Vec::new());
    let want = 12 * 16384;
    let t = Instant::now();
    let (a, b, c) = block_on(join3(
        leased_client(0, ports[0], &pool, want, Duration::from_secs(5), &order),
        leased_client(1, ports[1], &pool, want, Duration::from_secs(5), &order),
        leased_client(2, ports[2], &pool, want, Duration::from_secs(5), &order),
    ));
    assert_eq!((a.unwrap(), b.unwrap(), c.unwrap()), (want, want, want));
    assert_eq!(pool.max_holders(), 1, "never two holders of the one buffer");
    assert_eq!(pool.timeouts(), 0);
    // handshakes lease per record too: 3 connections x (ServerHello + 4 flight records) + 3 x 12 payload records at least
    assert!(pool.leases() >= 3 * 12 + 3 * 3, "leases {}", pool.leases());
    // records of different connections really interleaved
    let order = order.borrow();
    let switches = order.windows(2).filter(|w| w[0] != w[1]).count();
    assert!(switches >= 12, "only {switches} switches in {order:?}");
    println!(
        "3 connections, {} KB each in {:?}: leases {}, record order switches {switches}, max holders {}",
        want / 1024,
        t.elapsed(),
        pool.leases(),
        pool.max_holders()
    );
}

#[test]
fn a_stall_inside_a_record_times_out_and_the_others_continue() {
    // Connection A sends 3,000 bytes of a 16 KB record and goes quiet; B starts talking while A holds the lease.
    let a_spec = Spec { records: 2, gap: Duration::from_millis(1), delay: Duration::from_millis(0), stall_in_last: Some(3000) };
    let b_spec = Spec { records: 6, gap: Duration::from_millis(5), delay: Duration::from_millis(150), stall_in_last: None };
    let (pa, pb) = (serve(a_spec), serve(b_spec));
    let pool = LeasePool::<NoopRawMutex>::new();
    let order = RefCell::new(Vec::new());
    let t = Instant::now();
    let stall = Duration::from_millis(600);
    let (a, b) = block_on(join(leased_client(0, pa, &pool, 2 * 16384, stall, &order), leased_client(1, pb, &pool, 6 * 16384, Duration::from_secs(5), &order)));
    assert!(matches!(a, Err(ReadError::LeaseTimeout)), "{a:?}");
    assert_eq!(b.unwrap(), 6 * 16384, "the other connection finishes");
    assert_eq!(pool.timeouts(), 1);
    assert_eq!(pool.max_holders(), 1);
    // B waited for A's timeout (it was ready at ~150 ms and A holds the lease for 600 ms): the head-of-line cost is bounded by the timeout
    assert!(t.elapsed() >= stall && t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    // After the timeout the lease is free again (a third connection can lease at once)
    let spec = Spec { records: 2, gap: Duration::from_millis(0), delay: Duration::from_millis(0), stall_in_last: None };
    let pc = serve(spec);
    let c = block_on(leased_client(2, pc, &pool, 2 * 16384, Duration::from_secs(5), &order));
    assert_eq!(c.unwrap(), 2 * 16384);
    println!("stall test: A timed out, B done, total {:?}, lease holders max {}", t.elapsed(), pool.max_holders());
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
    let spec = Spec { records, gap: Duration::from_millis(0), delay: Duration::from_millis(0), stall_in_last: None };
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
        let pool = LeasePool::<NoopRawMutex>::new();
        let order = RefCell::new(Vec::new());
        let t = Instant::now();
        let s = Duration::from_secs(10);
        match conns {
            1 => {
                block_on(leased_client(0, ports[0], &pool, want, s, &order)).unwrap();
            }
            _ => {
                let (a, b, c) = block_on(join3(
                    leased_client(0, ports[0], &pool, want, s, &order),
                    leased_client(1, ports[1], &pool, want, s, &order),
                    leased_client(2, ports[2], &pool, want, s, &order),
                ));
                assert!(a.is_ok() && b.is_ok() && c.is_ok());
            }
        }
        let dt = t.elapsed();
        println!(
            "leased x{conns}: {:.1} MB/s total ({:?} wall; {} B pinned read buffers, 1 shared {} B, max holders {})",
            (conns * want) as f64 / 1e6 / dt.as_secs_f64(),
            dt,
            0,
            READ_RECORD_BYTES,
            pool.max_holders()
        );
    }
}

/// Needs the network: three leased connections to a real DERP server through ONE shared lease, each upgrades and reads the ServerKey frame.
#[test]
#[ignore = "needs network access to derp1.tailscale.com"]
fn live_derp_three_leased_connections() {
    use std::net::ToSocketAddrs;
    let host = "derp1.tailscale.com";
    let addr = (host, 443).to_socket_addrs().unwrap().find(|a| a.is_ipv4()).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let pool = LeasePool::<NoopRawMutex>::new();
    let one = |id: u64| {
        let pool = &pool;
        async move {
            let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
            s.set_nonblocking(true).unwrap();
            let cert = parse_cert_name(Some(host), None);
            let params = TlsParams { hostname: host, cert: &cert, anchors: tdongle_tailnet_tls::DEFAULT_ANCHORS, now_unix: now };
            let mut wb = vec![0u8; WRITE_RECORD_BYTES];
            let mut rng = TestRng(now + id);
            let mut c = LeasedTlsDerp::connect(NbSock(s), &mut wb, pool, &params, &mut rng).await.expect("handshake");
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
    println!("three leased connections to {host}: {a:?} {b:?} {c:?}; leases {}, max holders {}", pool.leases(), pool.max_holders());
    assert_eq!(pool.max_holders(), 1);
}
