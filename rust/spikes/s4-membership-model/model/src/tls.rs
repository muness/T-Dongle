//! (b) DERP over TLS 1.3 with embedded-tls (client-only, no_std), the rustpki `CertVerifier` pinned to ONE trust anchor
//! (the shape of ADR 0021's trust-anchor match), and a REPLAYED server transcript so no network is needed.
//!
//! The transcript is recorded on the host (host/src/main.rs `gen`) from a real rustls TLS 1.3 server with the same deterministic
//! client RNG seed, so the client's ClientHello is byte-identical and every server message (incl. the ECDSA signatures) verifies.
use crate::fixtures;
use crate::meter::Meter;
use alloc::boxed::Box;
use alloc::vec;
use embedded_io_async::{ErrorType, Read, Write};
use embedded_tls::pki::CertVerifier;
use embedded_tls::{Aes128GcmSha256, Certificate, CryptoProvider, TlsClock, TlsConfig, TlsConnection, TlsContext, TlsError, TlsVerifier};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;

pub const SEED_TLS: u64 = 0xC3;
pub const SERVER_NAME: &str = "derp.model.test";
/// 2026-10-06T00:00:00Z
pub const NOW_UNIX: u64 = 1_791_244_800;
pub const CERT_SIZE: usize = 2048;
/// mbedTLS asymmetric content length in the C build: IN 16384, OUT 4096 (sdkconfig:1757-1759). embedded-tls needs the record
/// buffer to hold a whole encrypted record: 16384 + overhead.
pub const READ_REC: usize = 16384 + 256;
pub const WRITE_REC: usize = 4096;

pub struct FixedClock;
impl TlsClock for FixedClock {
    fn now() -> Option<u64> {
        Some(NOW_UNIX)
    }
}

pub struct Provider<'a> {
    rng: ChaCha8Rng,
    verifier: CertVerifier<'a, Aes128GcmSha256, FixedClock, CERT_SIZE>,
}
impl<'a> Provider<'a> {
    pub fn new(ca_der: &'a [u8]) -> Self {
        Provider { rng: ChaCha8Rng::seed_from_u64(SEED_TLS), verifier: CertVerifier::new(Certificate::X509(ca_der)) }
    }
}
impl CryptoProvider for Provider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = p256_sig::Sig;
    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }
    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }
}
/// `CryptoProvider::Signature` must be nameable even though client auth is unused.
pub mod p256_sig {
    pub struct Sig;
    impl AsRef<[u8]> for Sig {
        fn as_ref(&self) -> &[u8] {
            &[]
        }
    }
}

/// An in-memory transport: serves the recorded server bytes, swallows client bytes and checks they equal the recorded client bytes.
pub struct Replay {
    server: &'static [u8],
    rpos: usize,
    part1: usize,
    client_hs: usize,
    client_expect: &'static [u8],
    wpos: usize,
    pub client_bytes_match: bool,
    pub underflow: bool,
}
impl Replay {
    pub fn new() -> Self {
        let s = fixtures::TLS_SPLIT;
        let part1 = u32::from_le_bytes(s[0..4].try_into().unwrap()) as usize;
        let client_hs = u32::from_le_bytes(s[4..8].try_into().unwrap()) as usize;
        Replay { server: fixtures::TLS_SERVER_BYTES, rpos: 0, part1, client_hs, client_expect: fixtures::TLS_CLIENT_BYTES, wpos: 0, client_bytes_match: true, underflow: false }
    }
}
impl ErrorType for Replay {
    type Error = embedded_io_async::ErrorKind;
}
impl Read for Replay {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // Bytes after the first flight exist only once the client has written its Finished (as on a real socket).
        let limit = if self.wpos >= self.client_hs { self.server.len() } else { self.part1 };
        if self.rpos >= limit {
            self.underflow = true;
            return Err(embedded_io_async::ErrorKind::TimedOut);
        }
        let n = buf.len().min(limit - self.rpos);
        buf[..n].copy_from_slice(&self.server[self.rpos..self.rpos + n]);
        self.rpos += n;
        Ok(n)
    }
}
impl Write for Replay {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let end = (self.wpos + buf.len()).min(self.client_expect.len());
        if self.wpos < end && self.client_expect[self.wpos..end] != buf[..end - self.wpos] {
            self.client_bytes_match = false;
        }
        self.wpos += buf.len();
        Ok(buf.len())
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub type Conn = TlsConnection<'static, Replay, Aes128GcmSha256>;

pub struct Derp {
    pub conn: Conn,
    pub config: &'static TlsConfig<'static>,
    pub ok: bool,
    pub handshake_ok: bool,
}

/// Run the whole DERP TLS bring-up for one membership. `read_rec`/`write_rec`: record buffer sizes (16,640 / 4,096 by default).
pub async fn setup(m: &impl Meter, read_rec: usize, write_rec: usize) -> Derp {
    let mut ok = true;
    m.begin("tls.alloc_record_buffers");
    let rb: &'static mut [u8] = Box::leak(vec![0u8; read_rec].into_boxed_slice());
    let wb: &'static mut [u8] = Box::leak(vec![0u8; write_rec].into_boxed_slice());
    let config: &'static TlsConfig<'static> = Box::leak(Box::new(TlsConfig::new().with_server_name(SERVER_NAME)));
    m.end();

    m.begin("tls.handshake+verify(TLS1.3,P-256 key share,chain->pinned P-384 anchor)");
    let mut conn: Conn = TlsConnection::new(Replay::new(), rb, wb);
    let r = conn.open(TlsContext::new(config, Provider::new(fixtures::CA_DER))).await;
    m.end();
    let handshake_ok = r.is_ok();
    ok &= handshake_ok;
    if let Err(e) = r {
        m.size(tls_err(&e), 0);
    }

    Derp { conn, config, ok, handshake_ok }
}

fn tls_err(e: &TlsError) -> &'static str {
    match e {
        TlsError::InvalidCertificate => "TLS ERROR: InvalidCertificate",
        TlsError::InvalidSignature => "TLS ERROR: InvalidSignature",
        TlsError::InsufficientSpace => "TLS ERROR: InsufficientSpace",
        TlsError::Io(_) => "TLS ERROR: Io (replay underflow?)",
        TlsError::DecodeError => "TLS ERROR: DecodeError",
        TlsError::InvalidHandshake => "TLS ERROR: InvalidHandshake",
        TlsError::InvalidRecord => "TLS ERROR: InvalidRecord",
        _ => "TLS ERROR: other",
    }
}

/// After the handshake: send a 100 B DERP client frame, receive a 1,200 B record then a 16,000 B record (one maximal TLS record).
pub async fn app_data(m: &impl Meter, d: &mut Derp) -> bool {
    if !d.handshake_ok {
        return false;
    }
    let mut ok = true;
    m.begin("tls.app_write_100B");
    ok &= d.conn.write(&[0x44u8; 100]).await.is_ok();
    ok &= d.conn.flush().await.is_ok();
    m.end();
    m.begin("tls.app_read_1200B_then_16000B_record");
    let mut buf = [0u8; 1024];
    let mut total = 0usize;
    while total < 17200 {
        match d.conn.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    ok &= total == 17200;
    m.end();
    d.ok &= ok;
    ok
}

pub fn print_sizes(m: &impl Meter) {
    m.size("sizeof(TlsConnection<Replay,Aes128GcmSha256>)", core::mem::size_of::<Conn>());
    m.size("sizeof(CertVerifier<..,CERT_SIZE=2048>)", core::mem::size_of::<CertVerifier<'static, Aes128GcmSha256, FixedClock, CERT_SIZE>>());
    m.size("sizeof(TlsConfig)", core::mem::size_of::<TlsConfig<'static>>());
    m.size("sizeof(tls::Replay)", core::mem::size_of::<Replay>());
}
