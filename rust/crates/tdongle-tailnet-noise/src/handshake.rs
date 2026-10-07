//! The initiator (client) half of the handshake: `-> e, es, s, ss` then `<- e, ee, se`.

use crate::session::{Role, Session};
use crate::symmetric::Symmetric;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_types::{Entropy, Key32};

/// Length of the initiation message including its 5-byte header.
pub const INITIATION_LEN: usize = 101;
/// Length of the response message including its 3-byte header.
pub const RESPONSE_LEN: usize = 51;

pub(crate) const MSG_INITIATION: u8 = 1;
pub(crate) const MSG_RESPONSE: u8 = 2;
pub(crate) const MSG_ERROR: u8 = 3;
pub(crate) const INIT_PAYLOAD: usize = 96;
pub(crate) const RESP_PAYLOAD: usize = 48;

/// Why a handshake message was refused. Every variant is a distinct, countable outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// Fewer bytes than the message needs.
    Truncated,
    /// The slice or the header's length field is not the fixed length of this message.
    BadLength,
    /// A message type that is not the expected one.
    UnexpectedType(u8),
    /// The peer sent a type 3 error message (unauthenticated; read its body with the length from [`ResponseHeader`]).
    PeerRefused,
    /// A Diffie-Hellman result was the all-zero point (a small-order public key).
    LowOrderPoint,
    /// An AEAD tag did not verify.
    AuthFailed,
}

/// What the first three bytes of a server reply announce, for a reader that has not buffered the whole message yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseHeader {
    /// The 48-byte handshake response follows.
    Response,
    /// An unauthenticated error message of this many bytes follows (public hint only; the handshake failed).
    Error {
        /// Body length.
        len: u16,
    },
}

impl ResponseHeader {
    /// Classify a reply header. Anything but a well-formed response or error is refused.
    pub fn parse(hdr: &[u8; 3]) -> Result<ResponseHeader, HandshakeError> {
        let len = u16::from_be_bytes([hdr[1], hdr[2]]);
        match hdr[0] {
            MSG_RESPONSE if usize::from(len) == RESP_PAYLOAD => Ok(ResponseHeader::Response),
            MSG_RESPONSE => Err(HandshakeError::BadLength),
            MSG_ERROR => Ok(ResponseHeader::Error { len }),
            t => Err(HandshakeError::UnexpectedType(t)),
        }
    }
}

/// The initiator between sending msg1 and receiving msg2. Single use: [`Initiator::finish`] consumes it.
#[derive(Debug)]
pub struct Initiator {
    sym: Symmetric,
    machine: Key32,
    ephemeral: Key32,
    control: Key32,
    version: u16,
}

impl core::fmt::Debug for Symmetric {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Symmetric(..)")
    }
}

impl Initiator {
    /// Start a handshake: draws the ephemeral key from `rng` and returns the state plus the 101-byte initiation message to send.
    pub fn new(machine_priv: &Key32, control_pub: &Key32, version: u16, rng: &mut dyn Entropy) -> Result<(Initiator, [u8; INITIATION_LEN]), HandshakeError> {
        Self::with_ephemeral(machine_priv, control_pub, version, x25519::generate(rng))
    }

    /// As [`Initiator::new`] with a caller-chosen ephemeral private key (known-answer and differential tests only; never reuse one on a real connection).
    pub fn with_ephemeral(
        machine_priv: &Key32,
        control_pub: &Key32,
        version: u16,
        ephemeral: Key32,
    ) -> Result<(Initiator, [u8; INITIATION_LEN]), HandshakeError> {
        Self::build(machine_priv, &x25519::public(machine_priv), control_pub, version, ephemeral)
    }

    /// As [`Initiator::new`] when the caller already holds the machine public key (the C keeps it next to the private key): saves one
    /// scalar multiplication, about a sixth of the handshake's CPU. The caller guarantees `machine_pub` belongs to `machine_priv`; a wrong one
    /// produces a message the server refuses.
    pub fn new_with_public(
        machine_priv: &Key32,
        machine_pub: &Key32,
        control_pub: &Key32,
        version: u16,
        rng: &mut dyn Entropy,
    ) -> Result<(Initiator, [u8; INITIATION_LEN]), HandshakeError> {
        Self::build(machine_priv, machine_pub, control_pub, version, x25519::generate(rng))
    }

    fn build(
        machine_priv: &Key32,
        machine_pub: &Key32,
        control_pub: &Key32,
        version: u16,
        ephemeral: Key32,
    ) -> Result<(Initiator, [u8; INITIATION_LEN]), HandshakeError> {
        let mut sym = Symmetric::new(version, control_pub);
        let mut msg = [0u8; INITIATION_LEN];
        msg[..2].copy_from_slice(&version.to_be_bytes());
        msg[2] = MSG_INITIATION;
        msg[3..5].copy_from_slice(&(INIT_PAYLOAD as u16).to_be_bytes());
        let body = &mut msg[5..];
        // e
        let e_pub = x25519::public(&ephemeral);
        body[..32].copy_from_slice(e_pub.as_bytes());
        sym.mix_hash(e_pub.as_bytes());
        // es, s
        let k = sym.mix_dh(&ephemeral, control_pub)?;
        body[32..64].copy_from_slice(machine_pub.as_bytes());
        sym.encrypt_and_hash(&k, &mut body[32..80], 32);
        // ss, empty payload
        let k = sym.mix_dh(machine_priv, control_pub)?;
        sym.encrypt_and_hash(&k, &mut body[80..96], 0);
        Ok((Initiator { sym, machine: machine_priv.clone(), ephemeral, control: control_pub.clone(), version }, msg))
    }

    /// Process the complete 51-byte response (header included) and return the transport session.
    pub fn finish(mut self, msg2: &[u8]) -> Result<Session, HandshakeError> {
        if msg2.len() < 3 {
            return Err(HandshakeError::Truncated);
        }
        match ResponseHeader::parse(&[msg2[0], msg2[1], msg2[2]])? {
            ResponseHeader::Error { .. } => return Err(HandshakeError::PeerRefused),
            ResponseHeader::Response => {}
        }
        if msg2.len() < RESPONSE_LEN {
            return Err(HandshakeError::Truncated);
        }
        if msg2.len() != RESPONSE_LEN {
            return Err(HandshakeError::BadLength);
        }
        let mut re = Key32::ZERO;
        re.0.copy_from_slice(&msg2[3..35]);
        self.sym.mix_hash(&msg2[3..35]);
        self.sym.mix_dh(&self.ephemeral, &re)?; // ee
        let k = self.sym.mix_dh(&self.machine, &re)?; // se
        self.sym.decrypt_and_hash(&k, &msg2[35..51], &mut [])?;
        let (k1, k2) = self.sym.split();
        Ok(Session::new(Role::Initiator, k1, k2, self.sym.h, self.version, self.control.clone()))
    }
}
