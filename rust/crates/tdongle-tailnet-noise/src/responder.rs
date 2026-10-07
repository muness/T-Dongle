//! The responder (server) half, for tests and the host interop server. The device never answers a handshake.

use crate::handshake::{HandshakeError, INIT_PAYLOAD, INITIATION_LEN, MSG_INITIATION, MSG_RESPONSE, RESP_PAYLOAD, RESPONSE_LEN};
use crate::session::{Role, Session};
use crate::symmetric::Symmetric;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_types::{Entropy, Key32};

/// A completed server-side handshake.
#[derive(Debug)]
pub struct Accepted {
    /// Transport session (the server sends with the second split key and receives with the first).
    pub session: Session,
    /// The 51-byte response to send to the client.
    pub response: [u8; RESPONSE_LEN],
    /// The client's authenticated machine public key.
    pub machine_pub: Key32,
    /// The protocol version the client announced (and mixed into the prologue).
    pub version: u16,
}

/// Process a 101-byte initiation message with the control server's private key; ephemeral from `rng`.
pub fn accept(control_priv: &Key32, msg1: &[u8], rng: &mut dyn Entropy) -> Result<Accepted, HandshakeError> {
    accept_with_ephemeral(control_priv, msg1, x25519::generate(rng))
}

/// As [`accept`] with a caller-chosen ephemeral private key (tests only).
pub fn accept_with_ephemeral(control_priv: &Key32, msg1: &[u8], ephemeral: Key32) -> Result<Accepted, HandshakeError> {
    if msg1.len() < INITIATION_LEN {
        return Err(HandshakeError::Truncated);
    }
    if msg1.len() != INITIATION_LEN || usize::from(u16::from_be_bytes([msg1[3], msg1[4]])) != INIT_PAYLOAD {
        return Err(HandshakeError::BadLength);
    }
    if msg1[2] != MSG_INITIATION {
        return Err(HandshakeError::UnexpectedType(msg1[2]));
    }
    let version = u16::from_be_bytes([msg1[0], msg1[1]]);
    let control_pub = x25519::public(control_priv);
    let mut sym = Symmetric::new(version, &control_pub);
    let body = &msg1[5..];
    let mut re = Key32::ZERO;
    re.0.copy_from_slice(&body[..32]);
    sym.mix_hash(&body[..32]);
    let k = sym.mix_dh(control_priv, &re)?; // es
    let mut machine_pub = Key32::ZERO;
    sym.decrypt_and_hash(&k, &body[32..80], &mut machine_pub.0)?;
    let k = sym.mix_dh(control_priv, &machine_pub)?; // ss
    sym.decrypt_and_hash(&k, &body[80..96], &mut [])?;

    let mut response = [0u8; RESPONSE_LEN];
    response[0] = MSG_RESPONSE;
    response[1..3].copy_from_slice(&(RESP_PAYLOAD as u16).to_be_bytes());
    let e_pub = x25519::public(&ephemeral);
    response[3..35].copy_from_slice(e_pub.as_bytes());
    sym.mix_hash(e_pub.as_bytes());
    sym.mix_dh(&ephemeral, &re)?; // ee
    let k = sym.mix_dh(&ephemeral, &machine_pub)?; // se
    sym.encrypt_and_hash(&k, &mut response[35..51], 0);
    let (k1, k2) = sym.split();
    let session = Session::new(Role::Responder, k1, k2, sym.h, version, machine_pub.clone());
    Ok(Accepted { session, response, machine_pub, version })
}

/// A type 3 error message (unauthenticated): `3 | len(2) | text`. Returns the bytes written to `out` (text cut to fit, at most 65535 bytes).
pub fn error_message(text: &[u8], out: &mut [u8]) -> usize {
    let n = text.len().min(out.len().saturating_sub(3)).min(usize::from(u16::MAX));
    if out.len() < 3 {
        return 0;
    }
    out[0] = crate::handshake::MSG_ERROR;
    out[1..3].copy_from_slice(&(n as u16).to_be_bytes());
    out[3..3 + n].copy_from_slice(&text[..n]);
    3 + n
}
