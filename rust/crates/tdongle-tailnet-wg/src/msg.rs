//! Wire formats (whitepaper section 5.4): the four message types, their exact sizes, and parsing that never panics.
//!
//! Every message starts with a type byte and three zero bytes. Integers are little endian. Parsing validates only what the framing fixes (type, reserved
//! bytes, exact length per type; at least a header plus tag for transport); nothing here touches a key.

use crate::consts::PADDING_MULTIPLE;

/// Message type bytes.
pub const TYPE_INITIATION: u8 = 1;
/// Message type bytes.
pub const TYPE_RESPONSE: u8 = 2;
/// Message type bytes.
pub const TYPE_COOKIE_REPLY: u8 = 3;
/// Message type bytes.
pub const TYPE_TRANSPORT: u8 = 4;

/// Handshake initiation size.
pub const INITIATION_LEN: usize = 148;
/// Handshake response size.
pub const RESPONSE_LEN: usize = 92;
/// Cookie reply size.
pub const COOKIE_REPLY_LEN: usize = 64;
/// Transport header (type, receiver, counter).
pub const TRANSPORT_HEADER_LEN: usize = 16;
/// Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// The smallest transport message: a keepalive (header and tag, no payload).
pub const KEEPALIVE_LEN: usize = TRANSPORT_HEADER_LEN + TAG_LEN;
/// TAI64N timestamp.
pub const TIMESTAMP_LEN: usize = 12;
/// A MAC (mac1, mac2, cookie).
pub const MAC_LEN: usize = 16;

/// Why a datagram is not a WireGuard message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than four bytes.
    Short,
    /// Type byte not 1..=4.
    BadType,
    /// The three reserved bytes are not zero.
    BadReserved,
    /// Wrong length for the type.
    BadLength,
}

/// A message kind, from [`classify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    /// 148 bytes.
    Initiation,
    /// 92 bytes.
    Response,
    /// 64 bytes.
    CookieReply,
    /// At least 32 bytes.
    Transport,
}

/// The type of a datagram, checking its framing and length (the C `wireguard_get_message_type`).
pub fn classify(pkt: &[u8]) -> Result<MsgType, ParseError> {
    if pkt.len() < 4 {
        return Err(ParseError::Short);
    }
    if pkt[1] != 0 || pkt[2] != 0 || pkt[3] != 0 {
        return Err(ParseError::BadReserved);
    }
    let (t, ok) = match pkt[0] {
        TYPE_INITIATION => (MsgType::Initiation, pkt.len() == INITIATION_LEN),
        TYPE_RESPONSE => (MsgType::Response, pkt.len() == RESPONSE_LEN),
        TYPE_COOKIE_REPLY => (MsgType::CookieReply, pkt.len() == COOKIE_REPLY_LEN),
        TYPE_TRANSPORT => (MsgType::Transport, pkt.len() >= KEEPALIVE_LEN),
        _ => return Err(ParseError::BadType),
    };
    if ok { Ok(t) } else { Err(ParseError::BadLength) }
}

fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut o = [0u8; N];
    o.copy_from_slice(&b[..N]);
    o
}

/// Message 1 (initiator to responder).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Initiation {
    /// The initiator's receiver index.
    pub sender: u32,
    /// Unencrypted ephemeral public key.
    pub ephemeral: [u8; 32],
    /// Encrypted static public key, with tag.
    pub enc_static: [u8; 48],
    /// Encrypted TAI64N timestamp, with tag.
    pub enc_timestamp: [u8; 28],
    /// MAC over everything before it.
    pub mac1: [u8; MAC_LEN],
    /// Cookie MAC (zero without a cookie).
    pub mac2: [u8; MAC_LEN],
}

impl Initiation {
    /// Bytes covered by mac1.
    pub const MAC1_COVERS: usize = INITIATION_LEN - 2 * MAC_LEN;
    /// Bytes covered by mac2.
    pub const MAC2_COVERS: usize = INITIATION_LEN - MAC_LEN;

    /// Parse an exactly-148-byte message of type 1.
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        if classify(p)? != MsgType::Initiation {
            return Err(ParseError::BadType);
        }
        Ok(Self {
            sender: u32le(&p[4..]),
            ephemeral: arr(&p[8..]),
            enc_static: arr(&p[40..]),
            enc_timestamp: arr(&p[88..]),
            mac1: arr(&p[116..]),
            mac2: arr(&p[132..]),
        })
    }

    /// The wire form.
    pub fn encode(&self) -> [u8; INITIATION_LEN] {
        let mut o = [0u8; INITIATION_LEN];
        o[0] = TYPE_INITIATION;
        o[4..8].copy_from_slice(&self.sender.to_le_bytes());
        o[8..40].copy_from_slice(&self.ephemeral);
        o[40..88].copy_from_slice(&self.enc_static);
        o[88..116].copy_from_slice(&self.enc_timestamp);
        o[116..132].copy_from_slice(&self.mac1);
        o[132..148].copy_from_slice(&self.mac2);
        o
    }
}

/// Message 2 (responder to initiator).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The responder's receiver index.
    pub sender: u32,
    /// The initiator's index, echoed.
    pub receiver: u32,
    /// Unencrypted ephemeral public key.
    pub ephemeral: [u8; 32],
    /// AEAD of the empty string: just the tag.
    pub enc_empty: [u8; 16],
    /// MAC over everything before it.
    pub mac1: [u8; MAC_LEN],
    /// Cookie MAC (zero without a cookie).
    pub mac2: [u8; MAC_LEN],
}

impl Response {
    /// Bytes covered by mac1.
    pub const MAC1_COVERS: usize = RESPONSE_LEN - 2 * MAC_LEN;
    /// Bytes covered by mac2.
    pub const MAC2_COVERS: usize = RESPONSE_LEN - MAC_LEN;

    /// Parse an exactly-92-byte message of type 2.
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        if classify(p)? != MsgType::Response {
            return Err(ParseError::BadType);
        }
        Ok(Self {
            sender: u32le(&p[4..]),
            receiver: u32le(&p[8..]),
            ephemeral: arr(&p[12..]),
            enc_empty: arr(&p[44..]),
            mac1: arr(&p[60..]),
            mac2: arr(&p[76..]),
        })
    }

    /// The wire form.
    pub fn encode(&self) -> [u8; RESPONSE_LEN] {
        let mut o = [0u8; RESPONSE_LEN];
        o[0] = TYPE_RESPONSE;
        o[4..8].copy_from_slice(&self.sender.to_le_bytes());
        o[8..12].copy_from_slice(&self.receiver.to_le_bytes());
        o[12..44].copy_from_slice(&self.ephemeral);
        o[44..60].copy_from_slice(&self.enc_empty);
        o[60..76].copy_from_slice(&self.mac1);
        o[76..92].copy_from_slice(&self.mac2);
        o
    }
}

/// Message 3 (cookie reply).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CookieReply {
    /// The index of the message being answered (its `sender`).
    pub receiver: u32,
    /// XChaCha20 nonce.
    pub nonce: [u8; 24],
    /// Encrypted cookie, with tag.
    pub enc_cookie: [u8; 32],
}

impl CookieReply {
    /// Parse an exactly-64-byte message of type 3.
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        if classify(p)? != MsgType::CookieReply {
            return Err(ParseError::BadType);
        }
        Ok(Self { receiver: u32le(&p[4..]), nonce: arr(&p[8..]), enc_cookie: arr(&p[32..]) })
    }

    /// The wire form.
    pub fn encode(&self) -> [u8; COOKIE_REPLY_LEN] {
        let mut o = [0u8; COOKIE_REPLY_LEN];
        o[0] = TYPE_COOKIE_REPLY;
        o[4..8].copy_from_slice(&self.receiver.to_le_bytes());
        o[8..32].copy_from_slice(&self.nonce);
        o[32..64].copy_from_slice(&self.enc_cookie);
        o
    }
}

/// The 16-byte transport header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportHeader {
    /// The recipient's receiver index.
    pub receiver: u32,
    /// The message counter (the AEAD nonce).
    pub counter: u64,
}

impl TransportHeader {
    /// Parse the header of a datagram of at least [`KEEPALIVE_LEN`] bytes.
    pub fn parse(p: &[u8]) -> Result<Self, ParseError> {
        if classify(p)? != MsgType::Transport {
            return Err(ParseError::BadType);
        }
        Ok(Self { receiver: u32le(&p[4..]), counter: u64::from_le_bytes(arr(&p[8..])) })
    }

    /// Write the header into the first 16 bytes of `out` (which must be at least that long).
    pub fn write(&self, out: &mut [u8]) {
        out[0] = TYPE_TRANSPORT;
        out[1] = 0;
        out[2] = 0;
        out[3] = 0;
        out[4..8].copy_from_slice(&self.receiver.to_le_bytes());
        out[8..16].copy_from_slice(&self.counter.to_le_bytes());
    }
}

/// `n` rounded up to the next multiple of 16 (the C `WIREGUARDIF_DATA_PAD`; zero stays zero, so a keepalive is not padded).
pub const fn padded_len(n: usize) -> usize {
    (n + PADDING_MULTIPLE - 1) & !(PADDING_MULTIPLE - 1)
}

/// The datagram length for a payload of `n` bytes: header, padded payload, tag (the C `WIREGUARDIF_DATA_ALLOC`).
pub const fn transport_len(n: usize) -> usize {
    TRANSPORT_HEADER_LEN + padded_len(n) + TAG_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn sizes_are_the_wire_sizes() {
        assert_eq!((INITIATION_LEN, RESPONSE_LEN, COOKIE_REPLY_LEN, KEEPALIVE_LEN), (148, 92, 64, 32));
        assert_eq!(4 + 4 + 32 + 48 + 28 + 16 + 16, INITIATION_LEN);
        assert_eq!(4 + 4 + 4 + 32 + 16 + 16 + 16, RESPONSE_LEN);
        assert_eq!(4 + 4 + 24 + 32, COOKIE_REPLY_LEN);
    }

    #[test]
    fn padding_rule() {
        assert_eq!(padded_len(0), 0);
        for n in 1..=16 {
            assert_eq!(padded_len(n), 16);
        }
        assert_eq!(padded_len(17), 32);
        assert_eq!(padded_len(1400), 1408);
        assert_eq!(transport_len(0), KEEPALIVE_LEN);
        assert_eq!(transport_len(1400), 16 + 1408 + 16);
        for n in 0..300 {
            assert!(padded_len(n) >= n && padded_len(n).is_multiple_of(16) && padded_len(n) - n < 16);
        }
    }

    #[test]
    fn classify_framing() {
        let mut m = [0u8; INITIATION_LEN];
        m[0] = 1;
        assert_eq!(classify(&m), Ok(MsgType::Initiation));
        assert_eq!(classify(&m[..147]), Err(ParseError::BadLength));
        m[2] = 1;
        assert_eq!(classify(&m), Err(ParseError::BadReserved));
        assert_eq!(classify(&[1, 0, 0]), Err(ParseError::Short));
        assert_eq!(classify(&[9, 0, 0, 0]), Err(ParseError::BadType));
        assert_eq!(classify(&[0, 0, 0, 0]), Err(ParseError::BadType));
        let mut t = [0u8; 40];
        t[0] = 4;
        assert_eq!(classify(&t), Ok(MsgType::Transport));
        assert_eq!(classify(&t[..31]), Err(ParseError::BadLength));
        assert_eq!(classify(&t[..32]), Ok(MsgType::Transport));
    }

    proptest! {
        #[test]
        fn initiation_roundtrip(sender in any::<u32>(), e in proptest::array::uniform32(any::<u8>()), s in proptest::collection::vec(any::<u8>(), 48),
                                t in proptest::collection::vec(any::<u8>(), 28), m1 in proptest::array::uniform16(any::<u8>()), m2 in proptest::array::uniform16(any::<u8>())) {
            let msg = Initiation { sender, ephemeral: e, enc_static: arr(&s), enc_timestamp: arr(&t), mac1: m1, mac2: m2 };
            prop_assert_eq!(Initiation::parse(&msg.encode()), Ok(msg));
        }

        #[test]
        fn response_and_cookie_roundtrip(a in any::<u32>(), b in any::<u32>(), e in proptest::array::uniform32(any::<u8>()), x in proptest::array::uniform16(any::<u8>()),
                                         n in proptest::collection::vec(any::<u8>(), 24), c in proptest::collection::vec(any::<u8>(), 32)) {
            let r = Response { sender: a, receiver: b, ephemeral: e, enc_empty: x, mac1: x, mac2: x };
            prop_assert_eq!(Response::parse(&r.encode()), Ok(r));
            let ck = CookieReply { receiver: a, nonce: arr(&n), enc_cookie: arr(&c) };
            prop_assert_eq!(CookieReply::parse(&ck.encode()), Ok(ck));
        }

        #[test]
        fn transport_header_roundtrip(r in any::<u32>(), c in any::<u64>()) {
            let h = TransportHeader { receiver: r, counter: c };
            let mut buf = [0u8; 40];
            h.write(&mut buf);
            prop_assert_eq!(TransportHeader::parse(&buf), Ok(h));
        }

        /// No input panics, and a classification always agrees with the typed parsers.
        #[test]
        fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..200)) {
            match classify(&data) {
                Ok(MsgType::Initiation) => prop_assert!(Initiation::parse(&data).is_ok()),
                Ok(MsgType::Response) => prop_assert!(Response::parse(&data).is_ok()),
                Ok(MsgType::CookieReply) => prop_assert!(CookieReply::parse(&data).is_ok()),
                Ok(MsgType::Transport) => prop_assert!(TransportHeader::parse(&data).is_ok()),
                Err(_) => {
                    prop_assert!(Initiation::parse(&data).is_err() && Response::parse(&data).is_err());
                    prop_assert!(CookieReply::parse(&data).is_err() && TransportHeader::parse(&data).is_err());
                }
            }
        }
    }
}
