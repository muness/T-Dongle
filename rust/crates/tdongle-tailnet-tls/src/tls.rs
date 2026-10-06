//! The `embedded-tls` plug-ins: the DERP trust policy as a [`TlsVerifier`](embedded_tls::TlsVerifier) and an entropy adapter.

use crate::cert_name::DerpCert;
use crate::der::KeyKind;
use crate::rsa::{self, Hash as RsaHash, PublicKey};
use crate::verify::{Accepted, MAX_CHAIN, Reject, TrustAnchor, VerifyConfig, verify_chain};
use core::cell::Cell;
use embedded_io_async::{ErrorType, Read, Write};
use embedded_tls::{Aes128GcmSha256, CertificateEntryRef, CertificateRef, CertificateVerifyRef, CryptoProvider, SignatureScheme, TlsError, TlsVerifier};
use p256::ecdsa::signature::Verifier;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use tdongle_tailnet_types::{Entropy, FixedStr};

/// Adapts the firmware's [`Entropy`] to the `rand_core` 0.6 traits `embedded-tls` wants.
pub struct EntropyRng<'a>(pub &'a mut dyn Entropy);

impl core::fmt::Debug for EntropyRng<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EntropyRng")
    }
}

impl RngCore for EntropyRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill(dest);
        Ok(())
    }
}
impl CryptoRng for EntropyRng<'_> {}

/// The certificate verifier of one handshake: the DERP trust policy of [`verify_chain`] plus the CertificateVerify signature check.
///
/// `embedded-tls` calls `verify_certificate` with the server's chain and, later, `verify_signature` with CertificateVerify. If the host name was
/// never set (no SNI configured) both fail closed.
pub struct DerpVerifier<'a> {
    anchors: &'a [TrustAnchor<'a>],
    now_unix: u64,
    cert: &'a DerpCert,
    host: FixedStr<64>,
    host_set: bool,
    accepted: Option<Accepted>,
    transcript: Option<Sha256>,
    why: &'a Cell<Option<Reject>>,
}

impl core::fmt::Debug for DerpVerifier<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerpVerifier").field("now_unix", &self.now_unix).field("accepted", &self.accepted).finish_non_exhaustive()
    }
}

impl<'a> DerpVerifier<'a> {
    /// `why` receives the reason when the handshake is refused (`embedded-tls` only reports `InvalidCertificate`).
    pub fn new(anchors: &'a [TrustAnchor<'a>], now_unix: u64, cert: &'a DerpCert, why: &'a Cell<Option<Reject>>) -> Self {
        Self { anchors, now_unix, cert, host: FixedStr::new(), host_set: false, accepted: None, transcript: None, why }
    }

    /// What the chain check concluded, once `verify_certificate` has passed.
    pub fn accepted(&self) -> Option<&Accepted> {
        self.accepted.as_ref()
    }

    fn refuse(&self, r: Reject, e: TlsError) -> TlsError {
        self.why.set(Some(r));
        e
    }
}

impl TlsVerifier<Aes128GcmSha256> for DerpVerifier<'_> {
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), TlsError> {
        if hostname.len() > 63 {
            return Err(self.refuse(Reject::NoServerName, TlsError::InsufficientSpace));
        }
        self.host.set(hostname);
        self.host_set = true;
        Ok(())
    }

    fn verify_certificate(&mut self, transcript: &Sha256, cert: CertificateRef<'_>) -> Result<(), TlsError> {
        if !self.host_set {
            return Err(self.refuse(Reject::NoServerName, TlsError::InvalidCertificate));
        }
        let mut entries: [&[u8]; MAX_CHAIN] = [&[]; MAX_CHAIN];
        let mut n = 0;
        for e in &cert.entries {
            match e {
                CertificateEntryRef::X509(der) if n < MAX_CHAIN => {
                    entries[n] = der;
                    n += 1;
                }
                _ => return Err(self.refuse(Reject::Malformed, TlsError::InvalidCertificate)),
            }
        }
        let cfg = VerifyConfig { anchors: self.anchors, now_unix: self.now_unix, cert: self.cert, hostname: self.host.as_str() };
        match verify_chain(&cfg, &entries[..n]) {
            Ok(a) => {
                self.accepted = Some(a);
                self.transcript = Some(transcript.clone());
                Ok(())
            }
            Err(r) => Err(self.refuse(r, TlsError::InvalidCertificate)),
        }
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef<'_>) -> Result<(), TlsError> {
        let (Some(acc), Some(hash)) = (self.accepted.as_ref(), self.transcript.take()) else {
            return Err(self.refuse(Reject::BadHandshakeSignature, TlsError::InvalidSignature));
        };
        // RFC 8446 4.4.3: 64 x 0x20, the context string, 0x00, the transcript hash.
        let mut msg = [0x20u8; 64 + 34 + 32];
        msg[64..98].copy_from_slice(b"TLS 1.3, server CertificateVerify\0");
        msg[98..].copy_from_slice(&hash.finalize());
        let key = acc.leaf_key.point();
        let ok = match (verify.signature_scheme, acc.leaf_key.kind) {
            (SignatureScheme::EcdsaSecp256r1Sha256, KeyKind::EcP256) => p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                .ok()
                .zip(p256::ecdsa::Signature::from_der(verify.signature).ok())
                .is_some_and(|(k, s)| k.verify(&msg, &s).is_ok()),
            #[cfg(feature = "p384")]
            (SignatureScheme::EcdsaSecp384r1Sha384, KeyKind::EcP384) => p384::ecdsa::VerifyingKey::from_sec1_bytes(key)
                .ok()
                .zip(p384::ecdsa::Signature::from_der(verify.signature).ok())
                .is_some_and(|(k, s)| k.verify(&msg, &s).is_ok()),
            // TLS 1.3 has no PKCS#1 v1.5 for CertificateVerify: RSA leaves sign with RSA-PSS and a matching MGF1 hash.
            (SignatureScheme::RsaPssRsaeSha256, KeyKind::Rsa) => rsa_pss(key, RsaHash::Sha256, &msg, verify.signature),
            #[cfg(feature = "p384")]
            (SignatureScheme::RsaPssRsaeSha384, KeyKind::Rsa) => rsa_pss(key, RsaHash::Sha384, &msg, verify.signature),
            #[cfg(feature = "p384")]
            (SignatureScheme::RsaPssRsaeSha512, KeyKind::Rsa) => rsa_pss(key, RsaHash::Sha512, &msg, verify.signature),
            _ => return Err(self.refuse(Reject::BadHandshakeSignature, TlsError::InvalidSignatureScheme)),
        };
        if ok { Ok(()) } else { Err(self.refuse(Reject::BadHandshakeSignature, TlsError::InvalidSignature)) }
    }
}

fn rsa_pss(key: &[u8], h: RsaHash, msg: &[u8], sig: &[u8]) -> bool {
    PublicKey::parse(key).is_some_and(|pk| rsa::verify_pss(&pk, h, msg, sig))
}

/// `CryptoProvider::Signature` must be nameable even though client authentication is never used.
#[derive(Debug)]
pub struct NoSignature;
impl AsRef<[u8]> for NoSignature {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

/// The crypto provider of one DERP handshake: our entropy and our verifier. Client certificates are not supported.
#[derive(Debug)]
pub struct DerpProvider<'a> {
    rng: EntropyRng<'a>,
    verifier: DerpVerifier<'a>,
}

impl<'a> DerpProvider<'a> {
    /// Build from entropy and a verifier.
    pub fn new(entropy: &'a mut dyn Entropy, verifier: DerpVerifier<'a>) -> Self {
        Self { rng: EntropyRng(entropy), verifier }
    }
    /// The verifier (after the handshake: how trust was established).
    pub fn verifier(&self) -> &DerpVerifier<'a> {
        &self.verifier
    }
}

impl CryptoProvider for DerpProvider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = NoSignature;

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
        Ok(&mut self.verifier)
    }
}

/// A transport that does nothing; only used to compute [`crate::STATE_BYTES`].
#[derive(Debug)]
pub struct NullIo;
impl ErrorType for NullIo {
    type Error = core::convert::Infallible;
}
impl Read for NullIo {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(0)
    }
}
impl Write for NullIo {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(buf.len())
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
