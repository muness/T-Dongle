use embedded_io_async::{ErrorType, Read, Write};
use embedded_tls::{Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use s4_model::{coord, tls};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

pub fn run() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../s4-membership-model/fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    gen_noise(&dir);
    gen_tls(&dir);
    println!("fixtures written to {}", dir.display());
}

fn gen_noise(dir: &std::path::Path) {
    let k = coord::keys();
    let mut ini = coord::initiator(&k);
    let mut rsp = coord::responder(&k);
    let mut m1 = [0u8; 128];
    let n1 = ini.write_message(&[], &mut m1).unwrap();
    let mut tmp = [0u8; 8];
    rsp.read_message(&m1[..n1], &mut tmp).unwrap();
    let mut m2 = [0u8; 128];
    let n2 = rsp.write_message(&[], &mut m2).unwrap();
    assert_eq!(n1, 96);
    std::fs::write(dir.join("noise_reply.bin"), &m2[..n2]).unwrap();
    let mut st = rsp.into_transport_mode().unwrap();
    // 1,024 B of synthetic MapResponse-shaped JSON
    let mut json = String::from("{\"Peers\":[");
    let mut i = 0;
    while json.len() < 1000 {
        json.push_str(&format!("{{\"Key\":\"nodekey:{:064x}\",\"Online\":true,\"Name\":\"p{}.tailnet.ts.net\"}},", i, i));
        i += 1;
    }
    let mut bytes = json.into_bytes();
    while bytes.len() < 1023 {
        bytes.push(b' ');
    }
    bytes.truncate(1023);
    bytes.push(b']');
    assert_eq!(bytes.len(), 1024);
    let mut rec = vec![0u8; 1100];
    let n = st.write_message(&bytes, &mut rec).unwrap();
    std::fs::write(dir.join("noise_record.bin"), &rec[..n]).unwrap();
    println!("noise: initiation {n1} B, reply {n2} B, record {n} B");
}

fn gen_certs(dir: &std::path::Path) -> (Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
    let nb = rcgen::date_time_ymd(2026, 1, 1);
    let na = rcgen::date_time_ymd(2036, 1, 1);
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let mut ca_p = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_p.distinguished_name.push(rcgen::DnType::CommonName, "S4 Model Root X2-like");
    ca_p.not_before = nb;
    ca_p.not_after = na;
    let ca_cert = ca_p.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::new(ca_p, ca_key);

    let im_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let mut im_p = CertificateParams::new(Vec::<String>::new()).unwrap();
    im_p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    im_p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    im_p.distinguished_name.push(rcgen::DnType::CommonName, "S4 Model Intermediate E5-like");
    im_p.not_before = nb;
    im_p.not_after = na;
    let im_cert = im_p.signed_by(&im_key, &ca_issuer).unwrap();
    let im_issuer = Issuer::new(im_p, im_key);

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_p = CertificateParams::new(vec![tls::SERVER_NAME.to_string()]).unwrap();
    leaf_p.distinguished_name.push(rcgen::DnType::CommonName, tls::SERVER_NAME);
    leaf_p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_p.not_before = nb;
    leaf_p.not_after = na;
    let leaf_cert = leaf_p.signed_by(&leaf_key, &im_issuer).unwrap();
    // mbedtls-rs fixtures: server chain as NUL-terminated PEM (leaf then intermediate) and the leaf key as PKCS#8 DER.
    let mut pem = format!("{}{}", leaf_cert.pem(), im_cert.pem()).into_bytes();
    pem.push(0);
    std::fs::write(dir.join("chain.pem"), pem).unwrap();
    std::fs::write(dir.join("leaf_key.der"), leaf_key.serialize_der()).unwrap();
    println!("certs: root {} B, intermediate {} B, leaf {} B", ca_cert.der().len(), im_cert.der().len(), leaf_cert.der().len());
    (ca_cert.der().to_vec(), vec![leaf_cert.der().to_vec(), im_cert.der().to_vec()], leaf_key.serialize_der())
}

/// std TcpStream as an embedded-io-async transport that records both directions.
struct Rec {
    s: TcpStream,
    server_in: Arc<Mutex<Vec<u8>>>,
    client_out: Arc<Mutex<Vec<u8>>>,
}
impl ErrorType for Rec {
    type Error = embedded_io_async::ErrorKind;
}
impl Read for Rec {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = self.s.read(buf).map_err(|_| embedded_io_async::ErrorKind::Other)?;
        self.server_in.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
}
impl Write for Rec {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let n = self.s.write(buf).map_err(|_| embedded_io_async::ErrorKind::Other)?;
        self.client_out.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.s.flush().map_err(|_| embedded_io_async::ErrorKind::Other)
    }
}

fn gen_tls(dir: &std::path::Path) {
    let (ca, chain, leaf_pkcs8) = gen_certs(dir);
    std::fs::write(dir.join("ca.der"), &ca).unwrap();

    let certs: Vec<CertificateDer<'static>> = chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_pkcs8));
    let mut cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]).with_no_client_auth().with_single_cert(certs, key).unwrap();
    cfg.send_tls13_tickets = 0;
    let cfg = Arc::new(cfg);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let th = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_nodelay(true).unwrap();
        let mut c = rustls::ServerConnection::new(cfg).unwrap();
        while c.is_handshaking() {
            c.complete_io(&mut s).unwrap();
        }
        c.writer().write_all(&[0x42u8; 1200]).unwrap();
        c.complete_io(&mut s).unwrap();
        c.writer().write_all(&[0x43u8; 16000]).unwrap();
        while c.wants_write() {
            c.write_tls(&mut s).unwrap();
        }
        // read the client's 100 B application frame
        let mut got = 0;
        while got < 100 {
            c.complete_io(&mut s).unwrap();
            let mut b = [0u8; 256];
            if let Ok(n) = c.reader().read(&mut b) {
                got += n;
            }
        }
    });

    let server_in = Arc::new(Mutex::new(Vec::new()));
    let client_out = Arc::new(Mutex::new(Vec::new()));
    let s = TcpStream::connect(addr).unwrap();
    let rec = Rec { s, server_in: server_in.clone(), client_out: client_out.clone() };
    let mut rb = vec![0u8; tls::READ_REC];
    let mut wb = vec![0u8; tls::WRITE_REC];
    let config = TlsConfig::new().with_server_name(tls::SERVER_NAME);
    let mut conn: TlsConnection<'_, Rec, Aes128GcmSha256> = TlsConnection::new(rec, &mut rb, &mut wb);
    let r = embassy_futures::block_on(conn.open(TlsContext::new(&config, tls::Provider::new(&ca))));
    r.expect("TLS handshake (host, real rustls server) failed");
    let part1 = server_in.lock().unwrap().len();
    let client_hs = client_out.lock().unwrap().len();
    embassy_futures::block_on(async {
        conn.write(&[0x44u8; 100]).await.unwrap();
        conn.flush().await.unwrap();
        let mut buf = [0u8; 1024];
        let mut total = 0;
        while total < 17200 {
            let n = conn.read(&mut buf).await.unwrap();
            assert!(n > 0);
            total += n;
        }
    });
    th.join().unwrap();
    let sv = server_in.lock().unwrap().clone();
    let cl = client_out.lock().unwrap().clone();
    std::fs::write(dir.join("tls_server.bin"), &sv).unwrap();
    std::fs::write(dir.join("tls_client.bin"), &cl).unwrap();
    let mut split = Vec::new();
    split.extend_from_slice(&(part1 as u32).to_le_bytes());
    split.extend_from_slice(&(client_hs as u32).to_le_bytes());
    std::fs::write(dir.join("tls_split.bin"), split).unwrap();
    println!("tls: server->client {} B (first flight {} B), client->server {} B (handshake {} B)", sv.len(), part1, cl.len(), client_hs);
}
