#![cfg(feature = "p384")]
//! End to end: the TLS client (embedded-tls + the DERP verifier) against a local rustls TLS 1.3 server that presents the fixture chains
//! and sends 16 KB records, over loopback TCP. Also the failure paths of the C's tests, but through a real handshake.
use embassy_futures::block_on;
use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use tdongle_tailnet_tls::transport::{ConnectError, TlsParams, Upgrade, UpgradeParser, upgrade_request};
use tdongle_tailnet_tls::{DEFAULT_ANCHORS, DerpCert, DerpTransport, READ_RECORD_BYTES, Reject, TlsDerp, TrustedBy, WRITE_RECORD_BYTES, parse_cert_name};
use tdongle_tailnet_types::test_util::TestRng;

const NOW: u64 = 1_791_244_800;
const H: &str = "derp1.test.example";

fn f(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}.der", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

struct Sock(TcpStream);
impl ErrorType for Sock {
    type Error = ErrorKind;
}
impl Read for Sock {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, ErrorKind> {
        self.0.read(buf).map_err(|_| ErrorKind::Other)
    }
}
impl Write for Sock {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, ErrorKind> {
        self.0.write(buf).map_err(|_| ErrorKind::Other)
    }
    async fn flush(&mut self) -> Result<(), ErrorKind> {
        self.0.flush().map_err(|_| ErrorKind::Other)
    }
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);
impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Serve one connection: TLS 1.3 handshake, read the GET, answer 101, then `body` bytes of DERP-ish payload. Returns the port.
fn serve(chain: &[&str], key: &str, body: usize) -> (u16, std::thread::JoinHandle<usize>) {
    let certs: Vec<CertificateDer<'static>> = chain.iter().map(|n| CertificateDer::from(f(n))).collect();
    let provider = rustls::crypto::ring::default_provider();
    let signer = provider.key_provider.load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(f(key)))).unwrap();
    let ck = Arc::new(CertifiedKey { cert: certs, key: signer, ocsp: None });
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(ck)));
    let cfg = Arc::new(cfg);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut c = rustls::ServerConnection::new(cfg).unwrap();
        let mut tls = rustls::Stream::new(&mut c, &mut s);
        // The client may abandon the handshake (that is the test): any error just ends the thread.
        let mut req = [0u8; 512];
        let mut n = 0;
        loop {
            match tls.read(&mut req[n..]) {
                Ok(0) | Err(_) => return 0,
                Ok(k) => n += k,
            }
            if req[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let _ = tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n");
        let data: Vec<u8> = (0..body).map(|i| (i % 251) as u8).collect();
        let _ = tls.write_all(&data); // rustls cuts this into 16,384 byte records
        let _ = tls.flush();
        // Whatever the client sends next (the write-buffer test) until it closes.
        let mut sink = [0u8; 1024];
        let mut extra = 0usize;
        while let Ok(k) = tls.read(&mut sink) {
            if k == 0 {
                break;
            }
            for (i, &b) in sink[..k].iter().enumerate() {
                assert_eq!(b, ((extra + i) % 7) as u8);
            }
            extra += k;
        }
        extra
    });
    (port, h)
}

struct Outcome {
    result: Result<(usize, TrustedBy, u8), ConnectError>,
}

fn connect_run(port: u16, host: &str, cert_name: Option<&str>, now: u64, read_len: usize) -> Outcome {
    connect_run_with(port, host, cert_name, now, read_len, WRITE_RECORD_BYTES, 0, 70_000)
}

#[allow(clippy::too_many_arguments)]
fn connect_run_with(port: u16, host: &str, cert_name: Option<&str>, now: u64, read_len: usize, write_len: usize, extra: usize, want: usize) -> Outcome {
    let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut rb = vec![0u8; read_len];
    let mut wb = vec![0u8; write_len];
    let cert = parse_cert_name(Some(host), cert_name);
    let mut rng = TestRng(0x1234_5678_9abc_def0);
    let params = TlsParams { hostname: host, cert: &cert, anchors: DEFAULT_ANCHORS, now_unix: now };
    // The test PKI's own anchor (the real ISRG X2 constants do not sign the fixtures).
    let x2 = f("x2");
    let (subject, spki) = anchor_fields(&x2);
    let anchors = [tdongle_tailnet_tls::TrustAnchor { subject: &subject, spki: &spki }];
    let params = TlsParams { anchors: &anchors, ..params };
    let r = block_on(async {
        let mut c = TlsDerp::connect(Sock(sock), &mut rb, &mut wb, &params, &mut rng).await?;
        let (trusted_by, v) = (c.trusted_by(), c.signature_verifies());
        let mut req = [0u8; 200];
        let n = upgrade_request(host, &mut req).unwrap();
        c.write_all(&req[..n]).await.map_err(ConnectError::Tls)?;
        c.flush().await.map_err(ConnectError::Tls)?;
        // Read the 101 one byte at a time, then the body.
        let mut p = UpgradeParser::new();
        let mut b = [0u8; 1];
        loop {
            if c.read(&mut b).await.map_err(ConnectError::Tls)? == 0 {
                panic!("closed in upgrade");
            }
            match p.push(b[0]) {
                Upgrade::Pending => {}
                Upgrade::Done => break,
                Upgrade::Refused => panic!("refused"),
            }
        }
        let mut total = 0usize;
        let mut buf = [0u8; 1500];
        loop {
            match c.read(&mut buf).await {
                Ok(0) => break,
                Ok(k) => {
                    for (i, &x) in buf[..k].iter().enumerate() {
                        assert_eq!(x, ((total + i) % 251) as u8, "payload corrupted at {}", total + i);
                    }
                    total += k;
                }
                Err(e) => return Err(ConnectError::Tls(e)),
            }
            if total >= want {
                break;
            }
        }
        let data: Vec<u8> = (0..extra).map(|i| (i % 7) as u8).collect();
        c.write_all(&data).await.map_err(ConnectError::Tls)?;
        c.flush().await.map_err(ConnectError::Tls)?;
        Ok((total, trusted_by, v))
    });
    Outcome { result: r }
}

fn anchor_fields(d: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn tlv(b: &[u8]) -> (usize, usize) {
        let l = b[1] as usize;
        if l < 0x80 {
            (2, l)
        } else {
            let n = l & 0x7f;
            (2 + n, b[2..2 + n].iter().fold(0, |a, &x| a << 8 | x as usize))
        }
    }
    let (h, _) = tlv(d);
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

const CHAIN: [&str; 5] = ["leaf_ok", "ye2", "ye", "x2_cross", "derpkey"];

#[test]
fn full_session_with_16k_records() {
    let (port, h) = serve(&CHAIN, "key_leafk", 70_000);
    let o = connect_run(port, H, None, NOW, READ_RECORD_BYTES);
    let (total, how, verifies) = o.result.expect("handshake and 70 KB of payload");
    assert!(total >= 70_000);
    assert_eq!(how, TrustedBy::PresentedAnchor { anchor: 0 });
    assert_eq!(verifies, 3);
    let _ = h.join();
}

#[test]
fn record_buffer_must_hold_the_servers_record() {
    // 4 KiB holds the handshake (the Certificate message is ~3.5 KB here) but not a 16 KB record: a counted, clean failure.
    let (port, h) = serve(&CHAIN, "key_leafk", 70_000);
    let o = connect_run(port, H, None, NOW, 4096);
    assert!(matches!(o.result, Err(ConnectError::Tls(_))), "{:?}", o.result);
    let _ = h.join();
}

#[test]
fn refusals_through_a_real_handshake() {
    type Case<'a> = (&'a [&'a str], &'a str, Option<&'a str>, u64, Reject);
    let cases: &[Case<'_>] = &[
        (&["leaf_rogue", "rogue_ye2", "rogue_ye"], H, None, NOW, Reject::NotTrusted),
        (&["leaf_ok", "ye2", "ye", "x2_cross"], "derp2.test.example", None, NOW, Reject::NameMismatch),
        (&["leaf_expired", "ye2", "ye", "x2_cross"], H, None, NOW, Reject::Expired),
        (&["leaf_future", "ye2", "ye", "x2_cross"], H, None, NOW, Reject::NotYetValid),
        (&["leaf_cn_only", "ye2", "ye", "x2_cross"], H, None, NOW, Reject::NameMismatch),
        (&["leaf_fake", "fake_ye2", "fake_ye", "fake_x2"], H, None, NOW, Reject::NotTrusted),
        (&["leaf_ok", "ye2", "ye", "x2_cross"], H, Some("sha256-raw:00"), NOW, Reject::InvalidCertName),
        (&["leaf_ok", "ye2", "ye", "x2_cross"], H, None, 1_000, Reject::ClockNotSet),
    ];
    for (chain, host, cn, now, want) in cases {
        let (port, h) = serve(chain, "key_leafk", 10);
        let o = connect_run(port, host, *cn, *now, READ_RECORD_BYTES);
        match o.result {
            Err(ConnectError::Untrusted(r)) => assert_eq!(r, *want, "{chain:?}"),
            Err(ConnectError::ClockNotSet) => assert_eq!(*want, Reject::ClockNotSet),
            Err(ConnectError::InvalidCertName) => assert_eq!(*want, Reject::InvalidCertName),
            other => panic!("{chain:?}: {other:?}"),
        }
        let _ = h.join();
    }
}

#[test]
fn certificate_verify_must_match_the_leaf_key() {
    // The chain is valid but the server signs CertificateVerify with another key.
    let (port, h) = serve(&CHAIN, "key_pin", 10);
    let o = connect_run(port, H, None, NOW, READ_RECORD_BYTES);
    assert!(matches!(o.result, Err(ConnectError::Untrusted(Reject::BadHandshakeSignature))), "{:?}", o.result);
    let _ = h.join();
}

#[test]
fn pinned_self_signed_server() {
    use sha2::{Digest, Sha256};
    let pin: String = Sha256::digest(f("pin")).iter().map(|b| format!("{b:02x}")).collect();
    let pin = format!("sha256-raw:{pin}");
    let (port, h) = serve(&["pin", "derpkey"], "key_pin", 70_000);
    let o = connect_run(port, "pin.example", Some(&pin), NOW, READ_RECORD_BYTES);
    let (total, how, verifies) = o.result.expect("pinned session");
    assert!(total >= 70_000 && how == TrustedBy::Pin && verifies == 0);
    let _ = h.join();
    // Another self-signed certificate with the same name is refused.
    let (port, h) = serve(&["pin_other"], "key_pin2", 10);
    let o = connect_run(port, "pin.example", Some(&pin), NOW, READ_RECORD_BYTES);
    assert!(matches!(o.result, Err(ConnectError::Untrusted(Reject::PinMismatch))), "{:?}", o.result);
    let _ = h.join();
    let _ = DerpCert::Hostname;
}

#[test]
fn upgrade_request_and_response() {
    let mut out = [0u8; 200];
    let n = upgrade_request("derp1.tailscale.com", &mut out).unwrap();
    assert_eq!(&out[..n], b"GET /derp HTTP/1.1\r\nHost: derp1.tailscale.com\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n");
    assert!(upgrade_request("a b", &mut out).is_none() && upgrade_request("h\r\nX: y", &mut out).is_none() && upgrade_request("", &mut out).is_none());
    assert!(upgrade_request("derp1.tailscale.com", &mut out[..40]).is_none());
    let feed = |s: &[u8]| {
        let mut p = UpgradeParser::new();
        s.iter().map(|&b| p.push(b)).last().unwrap()
    };
    assert_eq!(feed(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\n\r\n"), Upgrade::Done);
    assert_eq!(feed(b"HTTP/1.0 101 x\r\n\r\n"), Upgrade::Done);
    assert_eq!(feed(b"HTTP/1.1 200 OK\r\nX: 101\r\n\r\n"), Upgrade::Refused, "101 elsewhere in the headers is not the status");
    assert_eq!(feed(b"HTTP/1.1 101"), Upgrade::Pending);
    assert_eq!(feed(&[b'x'; 600]), Upgrade::Refused, "header larger than HTTP_MAX");
}

#[test]
fn client_hello_offers_the_signature_algorithms_a_go_derper_needs() {
    // Go's TLS server refuses a client whose signature_algorithms lacks one the chain it would send is signed with: DERP's chain has the RSA-SHA256
    // cross-certificate (0x0401), an Ed25519 meta certificate (0x0807) and ECDSA-SHA384 certificates (0x0503). Measured against derp1.tailscale.com.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut b = [0u8; 1024];
        let n = s.read(&mut b).unwrap();
        b[..n].to_vec()
    });
    let o = connect_run(port, H, None, NOW, READ_RECORD_BYTES);
    assert!(o.result.is_err());
    let hello = h.join().unwrap();
    // extension signature_algorithms: 00 0d, len, list len, entries
    let i = hello.windows(2).position(|w| w == [0x00, 0x0d]).expect("signature_algorithms extension");
    let list_len = u16::from_be_bytes([hello[i + 4], hello[i + 5]]) as usize;
    let list: Vec<u16> = hello[i + 6..i + 6 + list_len].chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    for want in [0x0403u16, 0x0503, 0x0807, 0x0401] {
        assert!(list.contains(&want), "{want:#06x} missing from {list:04x?}");
    }
    // One cipher suite (TLS_AES_128_GCM_SHA256) and one group (secp256r1): nothing else is implemented.
    assert!(hello.windows(4).any(|w| w == [0x00, 0x02, 0x13, 0x01]));
}

#[test]
fn a_small_write_buffer_is_enough_and_large_writes_are_split() {
    // The handshake encodes only the ClientHello (about 190 B) through the write buffer; app data is cut into records that fit it.
    for wlen in [512usize, 1024, 4096] {
        let (port, h) = serve(&CHAIN, "key_leafk", 100);
        let o = connect_run_with(port, H, None, NOW, READ_RECORD_BYTES, wlen, 20_000, 100);
        assert!(o.result.is_ok(), "write buffer {wlen}: {:?}", o.result);
        assert_eq!(h.join().unwrap(), 20_000, "write buffer {wlen}");
    }
}

/// Needs the network: a normal TLS handshake with a real DERP server, the `GET /derp` upgrade, the 101 and the first DERP frame (ServerKey), then the
/// connection is abandoned. `cargo test -p tdongle-tailnet-tls --test handshake -- --ignored`.
#[test]
#[ignore = "needs network access to derp1.tailscale.com"]
fn live_derp_server() {
    use std::net::ToSocketAddrs;
    let host = "derp1.tailscale.com";
    let addr = (host, 443).to_socket_addrs().unwrap().find(|a| a.is_ipv4()).unwrap();
    let sock = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    let mut rb = vec![0u8; READ_RECORD_BYTES];
    let mut wb = vec![0u8; WRITE_RECORD_BYTES];
    let cert = parse_cert_name(Some(host), None);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let params = TlsParams { hostname: host, cert: &cert, anchors: DEFAULT_ANCHORS, now_unix: now };
    let mut rng = TestRng(now);
    block_on(async {
        let mut c = TlsDerp::connect(Sock(sock), &mut rb, &mut wb, &params, &mut rng).await.expect("handshake with the real DERP server");
        let mut req = [0u8; 200];
        let n = upgrade_request(host, &mut req).unwrap();
        c.write_all(&req[..n]).await.unwrap();
        c.flush().await.unwrap();
        let mut p = UpgradeParser::new();
        let mut b = [0u8; 1];
        loop {
            assert_eq!(c.read(&mut b).await.unwrap(), 1);
            match p.push(b[0]) {
                Upgrade::Pending => {}
                Upgrade::Done => break,
                Upgrade::Refused => panic!("upgrade refused"),
            }
        }
        // DERP frame: type (1) + length (4, big endian); frameServerKey = 0x01, payload = 8 byte magic "DERP\xf0\x9f\x94\x91" + 32 byte key.
        let mut hdr = [0u8; 5];
        let mut got = 0;
        while got < 5 {
            got += c.read(&mut hdr[got..]).await.unwrap();
        }
        assert_eq!(hdr[0], 0x01, "frameServerKey");
        assert_eq!(u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]), 40);
    });
}
