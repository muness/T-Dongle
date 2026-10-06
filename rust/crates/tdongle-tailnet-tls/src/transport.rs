//! [`DerpTransport`]: the byte stream under the DERP link, and its TLS implementation.

use crate::cert_name::DerpCert;
use crate::etls::{Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext, TlsError};
use crate::tls::{DerpProvider, DerpVerifier};
use crate::verify::{Reject, TrustAnchor, TrustedBy, clock_valid};
use core::cell::Cell;
use embedded_io_async::{Read, Write};
use tdongle_tailnet_types::Entropy;

/// The read record buffer a TLS connection pins for its whole life: one maximal TLS 1.3 record (16,384 plaintext + 256). The server picks the
/// record size (Go's `crypto/tls` ignores `max_fragment_length`), so a smaller buffer fails with `InsufficientSpace` on a large record. The C's
/// mbedTLS pins 1,336 B live because ESP-IDF's dynamic buffer sizes each record from its header and frees it after use.
pub const READ_RECORD_BYTES: usize = 16_384 + 256;
/// The write buffer: holds one record being encrypted (128 B of overhead + payload); larger writes are split into several records. 2,048 holds a
/// whole DERP packet (at most about 1,500 B plus its 5 B frame header) in one record; the C's `MBEDTLS_SSL_OUT_CONTENT_LEN` is 4,096. 512 works
/// too (tested), at one extra record per 384 B written.
pub const WRITE_RECORD_BYTES: usize = 2_048;

/// An ordered, reliable, encrypted byte stream to one DERP server. `read` returning 0 means the peer closed.
#[allow(async_fn_in_trait)]
pub trait DerpTransport {
    /// Transport error.
    type Error: core::fmt::Debug;
    /// Read at least one byte unless the stream ended (then 0).
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
    /// Write all of `buf` (it may stay buffered until [`flush`](DerpTransport::flush)).
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
    /// Push buffered bytes to the socket.
    async fn flush(&mut self) -> Result<(), Self::Error>;
}

/// Why [`TlsDerp::connect`] failed.
#[derive(Clone, Copy, Debug)]
pub enum ConnectError {
    /// The wall clock is not set: not attempted (the C's `tls_deferred`).
    ClockNotSet,
    /// CertName unusable: never connect.
    InvalidCertName,
    /// The server was refused by the trust policy (see [`Reject`]).
    Untrusted(Reject),
    /// The handshake failed for another reason (I/O, protocol, record too large for the buffer).
    Tls(TlsError),
}

/// A TLS 1.3 connection to a DERP server over any `embedded-io-async` socket.
pub struct TlsDerp<'a, IO: Read + Write> {
    conn: TlsConnection<'a, IO, Aes128GcmSha256>,
    trusted_by: TrustedBy,
    signature_verifies: u8,
}

impl<IO: Read + Write> core::fmt::Debug for TlsDerp<'_, IO> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsDerp").field("trusted_by", &self.trusted_by).finish_non_exhaustive()
    }
}

/// What a connection needs besides the socket and buffers.
#[derive(Clone, Copy, Debug)]
pub struct TlsParams<'a> {
    /// The node's `HostName`: the SNI, and the name the certificate must carry unless CertName says otherwise.
    pub hostname: &'a str,
    /// CertName semantics.
    pub cert: &'a DerpCert,
    /// Trust anchors (default [`crate::DEFAULT_ANCHORS`]).
    pub anchors: &'a [TrustAnchor<'a>],
    /// Unix time now (certificates are judged against it; must be set).
    pub now_unix: u64,
}

impl<'a, IO: Read + Write> TlsDerp<'a, IO> {
    /// Run the TLS handshake. `read_buf` should be [`READ_RECORD_BYTES`] and `write_buf` [`WRITE_RECORD_BYTES`]; both stay borrowed for the
    /// connection's life. On error the socket is dropped (a failed `embedded-tls` connection must be recreated).
    pub async fn connect(
        io: IO,
        read_buf: &'a mut [u8],
        write_buf: &'a mut [u8],
        params: &TlsParams<'_>,
        entropy: &mut dyn Entropy,
    ) -> Result<Self, ConnectError> {
        if !clock_valid(params.now_unix) {
            return Err(ConnectError::ClockNotSet);
        }
        if matches!(params.cert, DerpCert::Invalid) {
            return Err(ConnectError::InvalidCertName);
        }
        let why = Cell::new(None);
        // RSA schemes are offered although never used (this crate verifies only ECDSA): Go's crypto/tls server checks the signature algorithms of
        // every certificate in the chain it is about to send against the client's list, and DERP's chain carries the RSA-SHA256 cross-certificate of
        // ISRG Root X2 (signed by X1). Without rsa_pkcs1_sha256 in the ClientHello derp1.tailscale.com answers handshake_failure (measured).
        let config = TlsConfig::new().enable_rsa_signatures().with_server_name(params.hostname);
        let verifier = DerpVerifier::new(params.anchors, params.now_unix, params.cert, &why);
        let mut provider = DerpProvider::new(entropy, verifier);
        let mut conn = TlsConnection::new(io, read_buf, write_buf);
        match conn.open(TlsContext::new(&config, &mut provider)).await {
            Ok(()) => {
                let acc = provider.verifier().accepted().ok_or(ConnectError::Untrusted(Reject::NotTrusted))?;
                Ok(Self { trusted_by: acc.trusted_by, signature_verifies: acc.signature_verifies, conn })
            }
            Err(e) => Err(match why.get() {
                Some(r) => ConnectError::Untrusted(r),
                None => ConnectError::Tls(e),
            }),
        }
    }

    /// How the server's chain was trusted.
    pub fn trusted_by(&self) -> TrustedBy {
        self.trusted_by
    }

    /// Signature verifications the chain check did (CPU accounting; the CertificateVerify one is extra).
    pub fn signature_verifies(&self) -> u8 {
        self.signature_verifies
    }
}

impl<IO: Read + Write> DerpTransport for TlsDerp<'_, IO> {
    type Error = TlsError;
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        match self.conn.read(buf).await {
            Err(TlsError::ConnectionClosed) => Ok(0),
            other => other,
        }
    }
    async fn write_all(&mut self, mut buf: &[u8]) -> Result<(), TlsError> {
        while !buf.is_empty() {
            let n = self.conn.write(buf).await?;
            buf = &buf[n..];
        }
        Ok(())
    }
    async fn flush(&mut self) -> Result<(), TlsError> {
        self.conn.flush().await
    }
}

/// Longest upgrade response header the link reads before giving up (the C's `ML_DERP_HTTP_MAX`).
pub const HTTP_MAX: usize = 512;

/// Write the `GET /derp` upgrade request. `None` when `out` is too small or `host` has characters that do not belong in a header.
pub fn upgrade_request(host: &str, out: &mut [u8]) -> Option<usize> {
    if host.is_empty() || !host.bytes().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    let parts: [&[u8]; 3] = [b"GET /derp HTTP/1.1\r\nHost: ", host.as_bytes(), b"\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n"];
    let mut n = 0;
    for p in parts {
        out.get_mut(n..n + p.len())?.copy_from_slice(p);
        n += p.len();
    }
    Some(n)
}

/// Verdict of the upgrade response parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upgrade {
    /// Need more bytes.
    Pending,
    /// `HTTP/1.x 101` and the blank line: the DERP stream starts with the next byte.
    Done,
    /// Not a 101, or the header exceeded [`HTTP_MAX`].
    Refused,
}

/// Feeds the upgrade response one byte at a time (so nothing of the DERP stream behind it is consumed), as the C does.
#[derive(Clone, Debug)]
pub struct UpgradeParser {
    line: [u8; 12],
    seen: usize,
    tail: [u8; 4],
}

impl Default for UpgradeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl UpgradeParser {
    /// Fresh parser.
    pub const fn new() -> Self {
        Self { line: [0; 12], seen: 0, tail: [0; 4] }
    }
    /// Feed one byte.
    pub fn push(&mut self, b: u8) -> Upgrade {
        if self.seen < self.line.len() {
            self.line[self.seen] = b;
        }
        self.seen += 1;
        self.tail = [self.tail[1], self.tail[2], self.tail[3], b];
        if self.seen >= 4 && &self.tail == b"\r\n\r\n" {
            // "HTTP/1.x 101": the status code, not any "101" somewhere in the headers.
            let ok = self.seen >= 12 && &self.line[..7] == b"HTTP/1." && self.line[8] == b' ' && &self.line[9..12] == b"101";
            return if ok { Upgrade::Done } else { Upgrade::Refused };
        }
        if self.seen >= HTTP_MAX { Upgrade::Refused } else { Upgrade::Pending }
    }
}

/// Size of a [`TlsDerp`] over a zero-sized socket, for the memory table.
pub(crate) type _Sized = TlsDerp<'static, crate::tls::NullIo>;
