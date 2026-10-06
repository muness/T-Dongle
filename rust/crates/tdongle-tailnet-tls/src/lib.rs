//! TLS 1.3 client for the tailnet gateway's DERP connection (`derp*.tailscale.com:443`, then `GET /derp` with `Upgrade: DERP`).
//!
//! The stack is `embedded-tls` 0.19 (client only, TLS 1.3, `TLS_AES_128_GCM_SHA256`, P-256 key share, no allocation) driven through
//! `embedded-io-async`, with the DERP trust policy of the C (`ml_derp_cert.c`, `ml_derp_tls.c`, ADR 0021) as a custom verifier:
//!
//! * [`cert_name`]: `DERPNode.CertName` (hostname / other name / `sha256-raw:` pin / invalid).
//! * [`verify`]: the chain policy (SPKI-pinned anchors, dates, SAN-only names, ECDSA P-256/P-384 and RSA 2048..4096 signatures), sans-IO.
//! * [`tls`]: the verifier and crypto provider that plug the policy into `embedded-tls`.
//! * [`transport`]: the [`DerpTransport`] trait, its TLS implementation [`TlsDerp`] and the `/derp` upgrade request and response parser.
//!
//! Two facts measured against the live DERP map (88 hosts) shape the code:
//!
//! 1. `embedded-tls` offers only TLS 1.3 cipher suites. The Go `derper` (x/crypto autocert) then serves its **RSA** chain
//!    (`leaf RSA-2048 <- YR1 <- Root YR RSA-4096 <- ISRG Root X1`) and signs CertificateVerify with RSA-PSS, whereas the C (mbedTLS, TLS 1.2
//!    ECDHE-ECDSA suites) gets the ECDSA chain. Both verify here; RSA public operations are done by a small Montgomery routine on the stack.
//! 2. The ClientHello must list `rsa_pkcs1_sha256` although it is never used: the derper checks the signature algorithms of every certificate in
//!    the chain it would send (the ECDSA chain's ISRG Root X2 cross-certificate is RSA-signed) against the client's list, and refuses with
//!    `handshake_failure` otherwise.
//!
//! Memory (see [`STATE_BYTES`]): the connection pins one read record buffer ([`READ_RECORD_BYTES`], 16,640) and one write buffer
//! ([`WRITE_RECORD_BYTES`]) for its whole life; the handshake allocates nothing. No `alloc` anywhere. Cargo feature `p384` (default) adds P-384 and
//! SHA-384/512 (about 190 KB of xtensa flash) for the ECDSA chain.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod cert_name;
mod der;
mod rsa;
pub mod tls;
pub mod transport;
pub mod verify;

pub use cert_name::{DerpCert, parse_cert_name};
pub use transport::{DerpTransport, READ_RECORD_BYTES, TlsDerp, WRITE_RECORD_BYTES};
pub use verify::{
    Accepted, DEFAULT_ANCHORS, FAST_ANCHORS, ISRG_ROOT_X1, ISRG_ROOT_X2, ISRG_ROOT_YE, ISRG_ROOT_YR, Reject, TrustAnchor, TrustedBy, VerifyConfig, verify_chain,
};

/// `size_of` of the state a live DERP connection owns besides its two record buffers (host build; the xtensa figure is in the ADR).
pub const STATE_BYTES: usize = core::mem::size_of::<transport::TlsDerp<'static, tls::NullIo>>();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_sizes_for_the_adr() {
        // Host (64-bit) numbers; the xtensa figures are in the ADR (TlsDerp 1,280 B, DerpVerifier 760 B, Accepted 544 B, connect() future 2,840 B).
        std::println!(
            "STATE_BYTES(TlsDerp)={} DerpVerifier={} Accepted={} READ_RECORD_BYTES={} WRITE_RECORD_BYTES={}",
            STATE_BYTES,
            core::mem::size_of::<tls::DerpVerifier<'static>>(),
            core::mem::size_of::<Accepted>(),
            READ_RECORD_BYTES,
            WRITE_RECORD_BYTES
        );
        const { assert!(STATE_BYTES > 0 && STATE_BYTES < 4096) };
    }
}
