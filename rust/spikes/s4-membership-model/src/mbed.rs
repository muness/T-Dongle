//! mbedtls-rs experiment: a REAL mbedTLS handshake on target between a client and a server session in the same executor over
//! in-memory pipes (no network). Allocations and poll-stack are attributed to the client and the server separately (mem::Tagged),
//! so the client's numbers are its own. mbedtls-rs-sys config here: SSL_IN_CONTENT_LEN 16384, SSL_OUT_CONTENT_LEN 4096 (the
//! C build's sdkconfig:1758-1759), hardware accel hooks for esp32s3, TLS 1.2 + 1.3. Certificate dates are NOT checked (no wall clock).
use crate::mem::{self, T_MBED_CLIENT, T_MBED_SERVER};
use core::convert::Infallible;
use core::ffi::CStr;
use embassy_futures::join::join;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::pipe::Pipe;
use mbedtls_rs::io::{ErrorType, Read, Write};
use mbedtls_rs::{Certificate, ClientSessionConfig, Credentials, PrivateKey, ServerSessionConfig, Session, SessionConfig, Tls, X509};
use rand_core10::{TryCryptoRng, TryRng};
use s4_model::meter::Meter;
use static_cell::StaticCell;

const CA: &[u8] = include_bytes!("../fixtures/ca.der");
const CHAIN_PEM: &[u8] = include_bytes!("../fixtures/chain.pem"); // NUL-terminated by host gen
const KEY: &[u8] = include_bytes!("../fixtures/leaf_key.der");

struct DetRng(rand_chacha::ChaCha8Rng);
impl TryRng for DetRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        use rand_core::RngCore;
        Ok(self.0.next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        use rand_core::RngCore;
        Ok(self.0.next_u64())
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        use rand_core::RngCore;
        self.0.fill_bytes(dest);
        Ok(())
    }
}
impl TryCryptoRng for DetRng {}

type P = Pipe<CriticalSectionRawMutex, 6144>;
struct End {
    rx: &'static P,
    tx: &'static P,
}
impl ErrorType for End {
    type Error = Infallible;
}
impl Read for End {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Infallible> {
        Ok(self.rx.read(buf).await)
    }
}
impl Write for End {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Infallible> {
        Ok(self.tx.write(buf).await)
    }
    async fn flush(&mut self) -> Result<(), Infallible> {
        Ok(())
    }
}

pub async fn run(m: &impl Meter) {
    use rand_core::SeedableRng;
    static RNG: StaticCell<DetRng> = StaticCell::new();
    static C2S: P = Pipe::new();
    static S2C: P = Pipe::new();

    m.begin("mbedtls.Tls::new");
    let rng = RNG.init(DetRng(rand_chacha::ChaCha8Rng::seed_from_u64(0x4d42)));
    let tls = Tls::new(rng).unwrap();
    m.end();

    m.begin("mbedtls.create client+server sessions");
    let mut client = mem::with_tag(T_MBED_CLIENT, || {
        let cfg = SessionConfig::Client(ClientSessionConfig { ca_chain: Some(Certificate::new_no_copy(CA).unwrap()), server_name: Some(c"derp.model.test"), ..ClientSessionConfig::new() });
        Session::new(tls.reference(), End { rx: &S2C, tx: &C2S }, &cfg).unwrap()
    });
    let mut server = mem::with_tag(T_MBED_SERVER, || {
        let chain = CStr::from_bytes_with_nul(CHAIN_PEM).unwrap();
        let cfg = SessionConfig::Server(ServerSessionConfig::new(Credentials { certificate: Certificate::new(X509::PEM(chain)).unwrap(), private_key: PrivateKey::new(X509::DER(KEY), None).unwrap() }));
        Session::new(tls.reference(), End { rx: &C2S, tx: &S2C }, &cfg).unwrap()
    });
    m.end();
    m.size("mbedtls sizeof(Session<End>)", core::mem::size_of_val(&client));
    esp_println::println!("S4 MBED after create: client heap_now={} server heap_now={}", mem::tag_cur(T_MBED_CLIENT), mem::tag_cur(T_MBED_SERVER));

    m.begin("mbedtls.handshake(client+server resident; see S4 TAG mbedtls-client/server for the split)");
    let (rc, rs) = join(mem::tagged(T_MBED_CLIENT, client.connect()), mem::tagged(T_MBED_SERVER, server.connect())).await;
    m.end();
    esp_println::println!("S4 MBED handshake client={:?} server={:?} version={:?}", rc.is_ok(), rs.is_ok(), client.tls_version().is_some());
    esp_println::println!("S4 MBED after handshake: client heap_now={} heap_peak={} | server heap_now={} heap_peak={}", mem::tag_cur(T_MBED_CLIENT), mem::tag_peak(T_MBED_CLIENT), mem::tag_cur(T_MBED_SERVER), mem::tag_peak(T_MBED_SERVER));

    m.begin("mbedtls.app data: server writes 16000 B, client reads");
    let payload = [0x43u8; 4000];
    let mut got = 0usize;
    let w = async {
        for _ in 0..4 {
            let _ = server.write(&payload).await;
        }
        let _ = server.flush().await;
    };
    let r = async {
        let mut b = [0u8; 1024];
        while got < 16000 {
            match client.read(&mut b).await {
                Ok(n) if n > 0 => got += n,
                _ => break,
            }
        }
    };
    join(mem::tagged(T_MBED_SERVER, w), mem::tagged(T_MBED_CLIENT, r)).await;
    m.end();
    esp_println::println!("S4 MBED app data got={} client heap_now={} heap_peak={}", got, mem::tag_cur(T_MBED_CLIENT), mem::tag_peak(T_MBED_CLIENT));
    mem::report_tags();

    m.begin("mbedtls.close+drop server (client stays)");
    let _ = server.close().await;
    drop(server);
    m.end();
    esp_println::println!("S4 MBED client steady (session open, idle): heap_now={}", mem::tag_cur(T_MBED_CLIENT));
    m.begin("mbedtls.drop client session + Tls");
    mem::with_tag(T_MBED_CLIENT, || drop(client));
    drop(tls);
    m.end();
}
