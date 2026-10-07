//! The plaintext inside a DISCO box, as `disco/disco.go` lays it out: `type (1) | version (1) | payload`.
//!
//! * **Ping** (`0x01`): `txid (12)`, then optionally the sender's node key (32), then zero padding (used to probe the path MTU). A key of 32 zero bytes
//!   is not a key: it is padding, as in Go (`AppendMarshal` omits a zero key, `parsePing` skips an all-zero one).
//! * **Pong** (`0x02`): `txid (12) | source ip (16, v4-mapped) | port (2)`: the address the ping was seen from.
//! * **CallMeMaybe** (`0x03`): `N x (ip (16) | port (2))`. Like Go, a payload that is empty, not a whole number of endpoints or of a non-zero version
//!   is accepted as "no endpoints" (`parseCallMeMaybe` returns an empty message, not an error).
//! * The relay types `0x04..=0x09` are recognised and reported as [`Message::Unsupported`]: this gateway does not do UDP relay.
//!
//! Parsing never allocates and never copies a payload: a CallMeMaybe is an iterator over the packet's own bytes. Encoding writes into the caller's buffer
//! and refuses (never truncates) when it does not fit.

use crate::addr::{EP_LEN, Ep};

/// `"TS" + U+1F4AC` in UTF-8: the first six bytes of every DISCO packet.
pub const MAGIC: [u8; 6] = [b'T', b'S', 0xf0, 0x9f, 0x92, 0xac];
/// Bytes of a transaction id.
pub const TXID_LEN: usize = 12;
/// Bytes of a NaCl box nonce.
pub const NONCE_LEN: usize = 24;
/// `type | version`.
pub const MSG_HEADER_LEN: usize = 2;
/// Bytes of a node key inside a ping.
pub const NODE_KEY_LEN: usize = 32;
/// Plaintext bytes of a pong without its 2-byte header.
pub const PONG_LEN: usize = TXID_LEN + EP_LEN;

/// Message type bytes.
pub mod ty {
    /// Ping.
    pub const PING: u8 = 0x01;
    /// Pong.
    pub const PONG: u8 = 0x02;
    /// CallMeMaybe.
    pub const CALL_ME_MAYBE: u8 = 0x03;
    /// First relay type (BindUDPRelayEndpoint).
    pub const RELAY_FIRST: u8 = 0x04;
    /// Last relay type (AllocateUDPRelayEndpointResponse).
    pub const RELAY_LAST: u8 = 0x09;
}

/// Why a plaintext did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Shorter than its type needs (Go `errShort`).
    Short,
    /// A type byte this crate and Go both do not know.
    UnknownType(u8),
}

/// Why a message did not encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The caller's buffer is too small; nothing was written past what fits.
    BufferTooSmall,
}

/// A ping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping<'a> {
    /// Random per-ping transaction id.
    pub txid: [u8; TXID_LEN],
    /// The sender's WireGuard node key (alleged: combine with the netmap before trusting it). `None` for old clients and for an all-zero key.
    pub node_key: Option<&'a [u8; NODE_KEY_LEN]>,
    /// Zero bytes after the message.
    pub padding: usize,
}

/// A pong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    /// The ping's transaction id.
    pub txid: [u8; TXID_LEN],
    /// The ping's source address as the pong's sender saw it (the DERP magic address for a ping that came over DERP).
    pub src: Ep,
}

/// The endpoint list of a CallMeMaybe, read straight from the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoints<'a> {
    raw: &'a [u8],
}

impl<'a> Endpoints<'a> {
    /// No endpoints.
    pub const EMPTY: Endpoints<'static> = Endpoints { raw: &[] };
    /// Number of endpoints.
    pub fn len(&self) -> usize {
        self.raw.len() / EP_LEN
    }
    /// True when there are none.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
    /// The endpoints in order.
    pub fn iter(&self) -> impl Iterator<Item = Ep> + 'a {
        self.raw.as_chunks::<EP_LEN>().0.iter().filter_map(|c| Ep::from_wire(c))
    }
}

/// A parsed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    /// Ping.
    Ping(Ping<'a>),
    /// Pong.
    Pong(Pong),
    /// CallMeMaybe; `lax` is true when the payload was ignored for being malformed (the endpoint list is then empty).
    CallMeMaybe {
        /// The endpoints.
        endpoints: Endpoints<'a>,
        /// The payload was rejected under Go's lax rules.
        lax: bool,
    },
    /// A UDP-relay message type (`0x04..=0x09`) that this gateway does not implement.
    Unsupported(u8),
}

/// Parse the decrypted bytes of a box.
pub fn parse(p: &[u8]) -> Result<Message<'_>, ParseError> {
    if p.len() < MSG_HEADER_LEN {
        return Err(ParseError::Short);
    }
    let (t, ver, body) = (p[0], p[1], &p[MSG_HEADER_LEN..]);
    match t {
        ty::PING => {
            if body.len() < TXID_LEN {
                return Err(ParseError::Short);
            }
            let mut txid = [0u8; TXID_LEN];
            txid.copy_from_slice(&body[..TXID_LEN]);
            let rest = &body[TXID_LEN..];
            let mut padding = rest.len();
            let mut node_key = None;
            // "Deliberately lax on longer-than-expected messages": a non-zero 32-byte key is the key, anything else is padding.
            if rest.len() >= NODE_KEY_LEN {
                let k: &[u8; NODE_KEY_LEN] = rest[..NODE_KEY_LEN].try_into().map_err(|_| ParseError::Short)?;
                if k.iter().any(|&b| b != 0) {
                    node_key = Some(k);
                    padding -= NODE_KEY_LEN;
                }
            }
            Ok(Message::Ping(Ping { txid, node_key, padding }))
        }
        ty::PONG => {
            if body.len() < PONG_LEN {
                return Err(ParseError::Short);
            }
            let mut txid = [0u8; TXID_LEN];
            txid.copy_from_slice(&body[..TXID_LEN]);
            let src = Ep::from_wire(&body[TXID_LEN..]).ok_or(ParseError::Short)?;
            Ok(Message::Pong(Pong { txid, src }))
        }
        ty::CALL_ME_MAYBE => {
            if body.len() % EP_LEN != 0 || ver != 0 || body.is_empty() {
                // Go returns an empty CallMeMaybe, not an error, for the empty payload too; only the non-empty rejects are "lax".
                return Ok(Message::CallMeMaybe { endpoints: Endpoints::EMPTY, lax: !body.is_empty() });
            }
            Ok(Message::CallMeMaybe { endpoints: Endpoints { raw: body }, lax: false })
        }
        ty::RELAY_FIRST..=ty::RELAY_LAST => Ok(Message::Unsupported(t)),
        _ => Err(ParseError::UnknownType(t)),
    }
}

/// Plaintext length of a ping.
pub fn ping_len(p: &Ping<'_>) -> usize {
    MSG_HEADER_LEN + TXID_LEN + if key_present(p.node_key) { NODE_KEY_LEN } else { 0 } + p.padding
}

fn key_present(k: Option<&[u8; NODE_KEY_LEN]>) -> bool {
    k.is_some_and(|k| k.iter().any(|&b| b != 0))
}

/// Encode a ping into `out`; returns the length. A zero node key is omitted, as in Go.
pub fn encode_ping(out: &mut [u8], p: &Ping<'_>) -> Result<usize, EncodeError> {
    let n = ping_len(p);
    let out = out.get_mut(..n).ok_or(EncodeError::BufferTooSmall)?;
    out[0] = ty::PING;
    out[1] = 0;
    out[2..2 + TXID_LEN].copy_from_slice(&p.txid);
    let mut at = 2 + TXID_LEN;
    if let Some(k) = p.node_key.filter(|k| k.iter().any(|&b| b != 0)) {
        out[at..at + NODE_KEY_LEN].copy_from_slice(k);
        at += NODE_KEY_LEN;
    }
    out[at..].fill(0);
    Ok(n)
}

/// Encode a pong; returns the length (32).
pub fn encode_pong(out: &mut [u8], p: &Pong) -> Result<usize, EncodeError> {
    let n = MSG_HEADER_LEN + PONG_LEN;
    let out = out.get_mut(..n).ok_or(EncodeError::BufferTooSmall)?;
    out[0] = ty::PONG;
    out[1] = 0;
    out[2..2 + TXID_LEN].copy_from_slice(&p.txid);
    p.src.write_wire(&mut out[2 + TXID_LEN..]);
    Ok(n)
}

/// Encode a CallMeMaybe with `eps`; returns the length.
pub fn encode_call_me_maybe(out: &mut [u8], eps: &[Ep]) -> Result<usize, EncodeError> {
    let n = MSG_HEADER_LEN + EP_LEN * eps.len();
    let out = out.get_mut(..n).ok_or(EncodeError::BufferTooSmall)?;
    out[0] = ty::CALL_ME_MAYBE;
    out[1] = 0;
    for (i, e) in eps.iter().enumerate() {
        e.write_wire(&mut out[MSG_HEADER_LEN + i * EP_LEN..]);
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    fn unhex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|h| u8::from_str_radix(h, 16).unwrap()).collect()
    }

    const TX: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[1] = 1;
        k[2] = 2;
        k[30] = 30;
        k[31] = 31;
        k
    }

    /// The vectors of Go's `disco_test.go` `TestMarshalAndParse` (ping, ping_with_nodekey_src, ping_with_padding, ...).
    #[test]
    fn go_vectors_encode_and_parse() {
        let nk = key();
        let cases: [(&str, Ping<'_>, &str); 4] = [
            ("ping", Ping { txid: TX, node_key: None, padding: 0 }, "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c"),
            (
                "ping_with_nodekey_src",
                Ping { txid: TX, node_key: Some(&nk), padding: 0 },
                "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f",
            ),
            ("ping_with_padding", Ping { txid: TX, node_key: None, padding: 3 }, "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00"),
            (
                "ping_with_padding_and_nodekey_src",
                Ping { txid: TX, node_key: Some(&nk), padding: 3 },
                "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 00 00",
            ),
        ];
        for (name, p, want) in cases {
            let want = unhex(want);
            let mut buf = [0xeeu8; 128];
            let n = encode_ping(&mut buf, &p).unwrap();
            assert_eq!(&buf[..n], &want[..], "{name}");
            assert_eq!(ping_len(&p), n);
            assert_eq!(parse(&want), Ok(Message::Ping(p)), "{name}");
        }
    }

    #[test]
    fn go_vectors_pong() {
        let v4 = unhex("02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00 00 00 00 00 00 00 00 ff ff 02 03 04 05 04 d2");
        let p = Pong { txid: TX, src: Ep::v4([2, 3, 4, 5], 1234) };
        let mut buf = [0u8; 64];
        let n = encode_pong(&mut buf, &p).unwrap();
        assert_eq!(&buf[..n], &v4[..]);
        assert_eq!(parse(&v4), Ok(Message::Pong(p)));
        // pongv6: fed0::12 port 6666
        let v6 = unhex("02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c fe d0 00 00 00 00 00 00 00 00 00 00 00 00 00 12 1a 0a");
        let src = Ep::v6([0xfe, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12], 6666);
        let p = Pong { txid: TX, src };
        let n = encode_pong(&mut buf, &p).unwrap();
        assert_eq!(&buf[..n], &v6[..]);
        assert_eq!(parse(&v6), Ok(Message::Pong(p)));
    }

    #[test]
    fn go_vectors_call_me_maybe() {
        let mut buf = [0u8; 128];
        let n = encode_call_me_maybe(&mut buf, &[]).unwrap();
        assert_eq!(&buf[..n], &unhex("03 00")[..]);
        assert_eq!(parse(&buf[..n]), Ok(Message::CallMeMaybe { endpoints: Endpoints::EMPTY, lax: false }));
        let eps = [Ep::v4([1, 2, 3, 4], 567), Ep::v6([0x20, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x34, 0x56], 789)];
        let want = unhex("03 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 02 37 20 01 00 00 00 00 00 00 00 00 00 00 00 00 34 56 03 15");
        let n = encode_call_me_maybe(&mut buf, &eps).unwrap();
        assert_eq!(&buf[..n], &want[..]);
        match parse(&want).unwrap() {
            Message::CallMeMaybe { endpoints, lax } => {
                assert!(!lax);
                assert_eq!(endpoints.len(), 2);
                assert!(endpoints.iter().eq(eps.iter().copied()));
            }
            m => panic!("{m:?}"),
        }
    }

    #[test]
    fn call_me_maybe_lax_rules() {
        // not a multiple of 18, a non-zero version: accepted as empty, flagged lax (Go: empty message, no error)
        let mut p = unhex("03 00");
        p.extend_from_slice(&[0u8; 17]);
        assert_eq!(parse(&p), Ok(Message::CallMeMaybe { endpoints: Endpoints::EMPTY, lax: true }));
        let mut p = unhex("03 01");
        p.extend_from_slice(&[0u8; 18]);
        assert_eq!(parse(&p), Ok(Message::CallMeMaybe { endpoints: Endpoints::EMPTY, lax: true }));
    }

    #[test]
    fn relay_types_are_unsupported_not_unknown() {
        for t in 4u8..=9 {
            assert_eq!(parse(&[t, 0, 1, 2, 3]), Ok(Message::Unsupported(t)));
        }
        assert_eq!(parse(&[0x0a, 0]), Err(ParseError::UnknownType(0x0a)));
        assert_eq!(parse(&[0x00, 0]), Err(ParseError::UnknownType(0)));
        assert_eq!(parse(&[0x01]), Err(ParseError::Short));
        assert_eq!(parse(&[]), Err(ParseError::Short));
    }

    #[test]
    fn short_and_lax_ping_and_pong() {
        assert_eq!(parse(&[1, 0, 1, 2, 3]), Err(ParseError::Short));
        assert_eq!(parse(&[2, 0, 0, 0]), Err(ParseError::Short));
        // a ping with a zero "key" is padding (Go: all-zero trailing bytes are padding, not a NodeKey)
        let mut p = unhex("01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c");
        p.extend_from_slice(&[0u8; 40]);
        assert_eq!(parse(&p), Ok(Message::Ping(Ping { txid: TX, node_key: None, padding: 40 })));
        // trailing bytes after a pong are ignored ("always ignore bytes at the end")
        let mut pong = unhex("02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00 00 00 00 00 00 00 00 ff ff 02 03 04 05 04 d2");
        pong.extend_from_slice(&[9, 9, 9]);
        assert!(matches!(parse(&pong), Ok(Message::Pong(_))));
    }

    #[test]
    fn encoders_refuse_small_buffers() {
        let p = Ping { txid: TX, node_key: None, padding: 10 };
        let mut b = [0u8; 40];
        assert_eq!(encode_ping(&mut b[..23], &p), Err(EncodeError::BufferTooSmall));
        assert_eq!(encode_pong(&mut b[..31], &Pong { txid: TX, src: Ep::NONE }), Err(EncodeError::BufferTooSmall));
        assert_eq!(encode_call_me_maybe(&mut b[..19], &[Ep::NONE]), Err(EncodeError::BufferTooSmall));
        assert_eq!(encode_ping(&mut b[..24], &p), Ok(24));
    }
}
