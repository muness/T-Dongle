//! The DISCO envelope: `magic (6) | sender disco public key (32) | nonce (24) | NaCl box (16-byte tag, then ciphertext)`.
//!
//! Everything works in place on the caller's packet buffer. Sealing writes the plaintext at its final offset, seals it where it lies and fills in the
//! header; opening verifies the tag and decrypts where the box lies and returns a slice of the same buffer. The box is `crypto_box` (X25519, HSalsa20,
//! XSalsa20-Poly1305) from `tdongle_tailnet_crypto::nacl`; the per-peer *shared* key (`beforenm`) is computed once per peer key and cached by the caller.
//!
//! Receive is one function, [`process`], and every way it can end is an [`RxOutcome`] that [`RxCounters`] counts: nothing falls through.

use crate::msg::{self, EncodeError, MAGIC, Message, NONCE_LEN, ParseError, Ping, Pong};
use tdongle_tailnet_crypto::nacl;
use tdongle_tailnet_types::{Counter, Entropy, Key32};

/// Bytes before the box: magic, sender key, nonce.
pub const HEADER_LEN: usize = 6 + 32 + NONCE_LEN;
/// Bytes of the box's authentication tag.
pub const TAG_LEN: usize = nacl::TAG_LEN;
/// Bytes a sealed packet adds to its plaintext.
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;
/// Largest DISCO packet accepted (one Ethernet MTU of UDP payload; a ping padded for MTU probing is the largest real message).
pub const MAX_PACKET: usize = 1500;

/// Go's `LooksLikeDiscoWrapper`: long enough for a header and starts with the magic.
pub fn looks_like_disco(p: &[u8]) -> bool {
    p.len() >= HEADER_LEN && p[..6] == MAGIC
}

/// The sender's disco public key of a DISCO-looking packet (Go's `Source`).
pub fn source(p: &[u8]) -> Option<&[u8; 32]> {
    if !looks_like_disco(p) {
        return None;
    }
    p[6..38].try_into().ok()
}

/// A random nonce.
pub fn fresh_nonce(rng: &mut dyn Entropy) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rng.fill(&mut n);
    n
}

/// Seal a message built by `encode` (which is given `out[OVERHEAD..]` and returns the plaintext length) into `out`; returns the packet length.
pub fn seal_with(
    out: &mut [u8],
    my_pub: &Key32,
    shared: &Key32,
    nonce: &[u8; NONCE_LEN],
    encode: impl FnOnce(&mut [u8]) -> Result<usize, EncodeError>,
) -> Result<usize, EncodeError> {
    if out.len() < OVERHEAD {
        return Err(EncodeError::BufferTooSmall);
    }
    let plain = encode(&mut out[OVERHEAD..])?;
    let total = OVERHEAD + plain;
    out[..6].copy_from_slice(&MAGIC);
    out[6..38].copy_from_slice(my_pub.as_bytes());
    out[38..HEADER_LEN].copy_from_slice(nonce);
    // The plaintext sits at 78.., the tag goes into 62..78 in front of it (NaCl layout), so the box is `out[62..total]`.
    nacl::secretbox_seal(shared, nonce, &mut out[HEADER_LEN..total]).map_err(|_| EncodeError::BufferTooSmall)?;
    Ok(total)
}

/// Seal a ping.
pub fn seal_ping(out: &mut [u8], my_pub: &Key32, shared: &Key32, nonce: &[u8; NONCE_LEN], p: &Ping<'_>) -> Result<usize, EncodeError> {
    seal_with(out, my_pub, shared, nonce, |b| msg::encode_ping(b, p))
}

/// Seal a pong.
pub fn seal_pong(out: &mut [u8], my_pub: &Key32, shared: &Key32, nonce: &[u8; NONCE_LEN], p: &Pong) -> Result<usize, EncodeError> {
    seal_with(out, my_pub, shared, nonce, |b| msg::encode_pong(b, p))
}

/// Seal a CallMeMaybe.
pub fn seal_call_me_maybe(out: &mut [u8], my_pub: &Key32, shared: &Key32, nonce: &[u8; NONCE_LEN], eps: &[crate::Ep]) -> Result<usize, EncodeError> {
    seal_with(out, my_pub, shared, nonce, |b| msg::encode_call_me_maybe(b, eps))
}

/// A DISCO packet that parses as an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The claimed sender disco public key (a claim until the box opens with it).
    pub sender: [u8; 32],
    /// The box nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Bytes of box (tag included) after the header.
    pub box_len: usize,
}

/// Parse the envelope header without touching the box.
pub fn parse_header(p: &[u8]) -> Result<Header, RxOutcome> {
    if p.len() > MAX_PACKET {
        return Err(RxOutcome::TooLong);
    }
    if !looks_like_disco(p) {
        return Err(RxOutcome::NotDisco);
    }
    let box_len = p.len() - HEADER_LEN;
    if box_len < TAG_LEN {
        return Err(RxOutcome::NoBox);
    }
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&p[6..38]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&p[38..HEADER_LEN]);
    Ok(Header { sender, nonce, box_len })
}

/// Open the box of a packet in place; on success the plaintext is `pkt[OVERHEAD..]`.
pub fn open_in_place<'a>(pkt: &'a mut [u8], nonce: &[u8; NONCE_LEN], shared: &Key32) -> Result<&'a [u8], nacl::OpenError> {
    if pkt.len() < OVERHEAD {
        return Err(nacl::OpenError);
    }
    nacl::secretbox_open(shared, nonce, &mut pkt[HEADER_LEN..])?;
    Ok(&pkt[OVERHEAD..])
}

/// Opaque id of a peer slot, chosen by the caller.
pub type PeerId = u8;

/// How the receive pipeline finds the key for a sender. The three steps keep the C's order (ADR 0012/0013, `directory_disco_admit`): a sender that is
/// not resident must prove it holds its private key (the box opens) *before* it is given a slot.
pub trait PeerResolver {
    /// The resident peer holding this disco key, and the shared key for it.
    fn resident(&mut self, sender: &[u8; 32]) -> Option<(PeerId, Key32)>;
    /// A peer that is in the directory but not resident. The implementation spends its admission budget here ([`crate::policy::TrialGate`]) and returns
    /// an opaque candidate token and the shared key, or `None` when the key is unknown or the budget is spent.
    fn candidate(&mut self, sender: &[u8; 32]) -> Option<(u32, Key32)>;
    /// The candidate's box opened: make it resident. `None` when there is no slot for it.
    fn activate(&mut self, candidate: u32) -> Option<PeerId>;
}

/// A DISCO packet that opened and parsed.
#[derive(Debug, PartialEq, Eq)]
pub struct Received<'a> {
    /// The sender.
    pub peer: PeerId,
    /// The sender was not resident and was activated by this packet.
    pub activated: bool,
    /// The message.
    pub message: Message<'a>,
}

impl Received<'_> {
    /// The outcome to count for this packet.
    pub fn outcome(&self) -> RxOutcome {
        match self.message {
            Message::Ping(_) => RxOutcome::Ping,
            Message::Pong(_) => RxOutcome::Pong,
            Message::CallMeMaybe { lax: false, .. } => RxOutcome::CallMeMaybe,
            Message::CallMeMaybe { lax: true, .. } => RxOutcome::CallMeMaybeLax,
            Message::Unsupported(_) => RxOutcome::Unsupported,
        }
    }
}

/// Everything that can happen to a received DISCO-port datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RxOutcome {
    /// Accepted: ping.
    Ping,
    /// Accepted: pong.
    Pong,
    /// Accepted: call-me-maybe.
    CallMeMaybe,
    /// Accepted but the call-me-maybe payload was malformed and ignored (as Go does).
    CallMeMaybeLax,
    /// Accepted: a UDP-relay message this gateway ignores.
    Unsupported,
    /// Dropped: no DISCO magic or shorter than a header.
    NotDisco,
    /// Dropped: longer than [`MAX_PACKET`].
    TooLong,
    /// Dropped: no room for a box tag after the header.
    NoBox,
    /// Dropped: the sender key belongs to no peer (a stranger or a rotation the netmap has not delivered).
    UnknownSender,
    /// Dropped: the sender is a peer but its shared key could not be derived.
    NoSharedKey,
    /// Dropped: the box of a resident peer did not open (stale key material: tamper, wrong key, truncation).
    OpenFailed,
    /// Dropped: the box of a non-resident directory peer did not open: a forged claim; it bought nothing.
    CandidateFailed,
    /// Dropped: the box opened but the peer table had no slot.
    NoSlot,
    /// Dropped: the plaintext is shorter than its message type needs.
    Short,
    /// Dropped: an unknown message type.
    UnknownType,
}

impl RxOutcome {
    /// Number of outcomes.
    pub const COUNT: usize = 15;
    /// Stable name for status output.
    pub const fn name(self) -> &'static str {
        match self {
            RxOutcome::Ping => "ping",
            RxOutcome::Pong => "pong",
            RxOutcome::CallMeMaybe => "call_me_maybe",
            RxOutcome::CallMeMaybeLax => "call_me_maybe_lax",
            RxOutcome::Unsupported => "unsupported",
            RxOutcome::NotDisco => "not_disco",
            RxOutcome::TooLong => "too_long",
            RxOutcome::NoBox => "no_box",
            RxOutcome::UnknownSender => "unknown_sender",
            RxOutcome::NoSharedKey => "no_shared_key",
            RxOutcome::OpenFailed => "open_failed",
            RxOutcome::CandidateFailed => "candidate_failed",
            RxOutcome::NoSlot => "no_slot",
            RxOutcome::Short => "short",
            RxOutcome::UnknownType => "unknown_type",
        }
    }
    /// All outcomes in discriminant order.
    pub const ALL: [RxOutcome; RxOutcome::COUNT] = [
        RxOutcome::Ping,
        RxOutcome::Pong,
        RxOutcome::CallMeMaybe,
        RxOutcome::CallMeMaybeLax,
        RxOutcome::Unsupported,
        RxOutcome::NotDisco,
        RxOutcome::TooLong,
        RxOutcome::NoBox,
        RxOutcome::UnknownSender,
        RxOutcome::NoSharedKey,
        RxOutcome::OpenFailed,
        RxOutcome::CandidateFailed,
        RxOutcome::NoSlot,
        RxOutcome::Short,
        RxOutcome::UnknownType,
    ];
    /// True for the outcomes in which a message was delivered.
    pub const fn accepted(self) -> bool {
        matches!(self, RxOutcome::Ping | RxOutcome::Pong | RxOutcome::CallMeMaybe | RxOutcome::CallMeMaybeLax | RxOutcome::Unsupported)
    }
}

impl From<ParseError> for RxOutcome {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::Short => RxOutcome::Short,
            ParseError::UnknownType(_) => RxOutcome::UnknownType,
        }
    }
}

/// One counter per [`RxOutcome`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxCounters([Counter; RxOutcome::COUNT]);

impl Default for RxCounters {
    fn default() -> Self {
        Self::new()
    }
}

impl RxCounters {
    /// All zero.
    pub const fn new() -> Self {
        RxCounters([Counter(0); RxOutcome::COUNT])
    }
    /// Count one outcome.
    pub fn record(&mut self, o: RxOutcome) {
        self.0[o as usize].bump();
    }
    /// Count the outcome of a [`process`] call.
    pub fn record_result(&mut self, r: &Result<Received<'_>, RxOutcome>) {
        match r {
            Ok(rx) => self.record(rx.outcome()),
            Err(o) => self.record(*o),
        }
    }
    /// The count of one outcome.
    pub fn get(&self, o: RxOutcome) -> u32 {
        self.0[o as usize].get()
    }
    /// Sum of all outcomes: every datagram given to [`process`] is exactly one.
    pub fn total(&self) -> u64 {
        self.0.iter().map(|c| u64::from(c.get())).sum()
    }
}

/// Receive one datagram that arrived on the DISCO socket or over DERP: header checks, sender lookup, box open, parse. In place; the returned message
/// borrows the packet. The caller counts the result with [`RxCounters::record_result`].
pub fn process<'a, R: PeerResolver + ?Sized>(pkt: &'a mut [u8], resolver: &mut R) -> Result<Received<'a>, RxOutcome> {
    let h = parse_header(pkt)?;
    let (peer, activated) = if let Some((id, shared)) = resolver.resident(&h.sender) {
        open_in_place(pkt, &h.nonce, &shared).map_err(|_| RxOutcome::OpenFailed)?;
        (id, false)
    } else {
        let (token, shared) = resolver.candidate(&h.sender).ok_or(RxOutcome::UnknownSender)?;
        open_in_place(pkt, &h.nonce, &shared).map_err(|_| RxOutcome::CandidateFailed)?;
        (resolver.activate(token).ok_or(RxOutcome::NoSlot)?, true)
    };
    let message = msg::parse(&pkt[OVERHEAD..]).map_err(RxOutcome::from)?;
    Ok(Received { peer, activated, message })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ep;
    use tdongle_tailnet_crypto::x25519;

    fn kp(seed: u8) -> (Key32, Key32) {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = seed.wrapping_mul(17).wrapping_add(i as u8 * 3 + 1);
        }
        let sec = Key32(s);
        let public = x25519::public(&sec);
        (sec, public)
    }

    struct One {
        id: PeerId,
        key: Key32,
        shared: Key32,
        cand: Option<Key32>,
        slots: bool,
    }
    impl PeerResolver for One {
        fn resident(&mut self, s: &[u8; 32]) -> Option<(PeerId, Key32)> {
            (s == self.key.as_bytes() && self.cand.is_none()).then(|| (self.id, self.shared.clone()))
        }
        fn candidate(&mut self, s: &[u8; 32]) -> Option<(u32, Key32)> {
            (s == self.key.as_bytes()).then(|| (7, self.shared.clone()))
        }
        fn activate(&mut self, c: u32) -> Option<PeerId> {
            assert_eq!(c, 7);
            self.slots.then_some(self.id)
        }
    }

    fn world() -> (Key32, Key32, Key32, Key32, Key32) {
        let (a_sec, a_pub) = kp(1);
        let (b_sec, b_pub) = kp(2);
        let shared = nacl::precompute(&a_sec, &b_pub).unwrap();
        (a_sec, a_pub, b_sec, b_pub, shared)
    }

    #[test]
    fn seal_open_round_trip_all_messages() {
        let (_a_sec, a_pub, b_sec, _b_pub, shared_a) = world();
        let shared_b = nacl::precompute(&b_sec, &a_pub).unwrap();
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
        let mut r = One { id: 3, key: a_pub.clone(), shared: shared_b, cand: None, slots: true };
        let nonce = [7u8; 24];
        let nk = [9u8; 32];
        let mut buf = [0u8; 256];

        let n = seal_ping(&mut buf, &a_pub, &shared_a, &nonce, &Ping { txid: [4; 12], node_key: Some(&nk), padding: 5 }).unwrap();
        assert_eq!(n, OVERHEAD + 2 + 12 + 32 + 5);
        let rx = process(&mut buf[..n], &mut r).unwrap();
        assert_eq!(rx.peer, 3);
        assert!(!rx.activated);
        assert_eq!(rx.message, Message::Ping(Ping { txid: [4; 12], node_key: Some(&nk), padding: 5 }));

        let n = seal_pong(&mut buf, &a_pub, &shared_a, &nonce, &Pong { txid: [5; 12], src: Ep::v4([1, 2, 3, 4], 99) }).unwrap();
        assert_eq!(n, OVERHEAD + 32);
        assert_eq!(process(&mut buf[..n], &mut r).unwrap().message, Message::Pong(Pong { txid: [5; 12], src: Ep::v4([1, 2, 3, 4], 99) }));

        let eps = [Ep::v4([10, 0, 0, 1], 41641), Ep::v4([8, 8, 8, 8], 1)];
        let n = seal_call_me_maybe(&mut buf, &a_pub, &shared_a, &nonce, &eps).unwrap();
        match process(&mut buf[..n], &mut r).unwrap().message {
            Message::CallMeMaybe { endpoints, lax } => {
                assert!(!lax);
                assert!(endpoints.iter().eq(eps.iter().copied()));
            }
            m => panic!("{m:?}"),
        }
    }

    #[test]
    fn every_failure_is_one_outcome() {
        let (_a_sec, a_pub, b_sec, _b_pub, shared_a) = world();
        let shared_b = nacl::precompute(&b_sec, &a_pub).unwrap();
        let mk = || One { id: 1, key: a_pub.clone(), shared: shared_b.clone(), cand: None, slots: true };
        let nonce = [1u8; 24];
        let mut good = [0u8; 200];
        let n = seal_pong(&mut good, &a_pub, &shared_a, &nonce, &Pong { txid: [1; 12], src: Ep::NONE }).unwrap();
        let good = &good[..n];
        let mut c = RxCounters::new();
        let mut calls = 0u64;
        let mut run = |p: &[u8], r: &mut One, c: &mut RxCounters| {
            calls += 1;
            let mut b = [0u8; 1600];
            b[..p.len()].copy_from_slice(p);
            let res = process(&mut b[..p.len()], r);
            c.record_result(&res);
            res.map(|rx| rx.outcome())
        };
        let mut r = mk();
        assert_eq!(run(good, &mut r, &mut c), Ok(RxOutcome::Pong));
        // tamper: every byte of the box and the nonce
        for i in 38..n {
            let mut bad = good.to_vec();
            bad[i] ^= 0x40;
            assert_eq!(run(&bad, &mut r, &mut c), Err(RxOutcome::OpenFailed), "byte {i}");
        }
        // wrong sender key in the header: unknown sender
        let mut bad = good.to_vec();
        bad[10] ^= 1;
        assert_eq!(run(&bad, &mut r, &mut c), Err(RxOutcome::UnknownSender));
        // truncated
        assert_eq!(run(&good[..n - 1], &mut r, &mut c), Err(RxOutcome::OpenFailed));
        assert_eq!(run(&good[..HEADER_LEN + 15], &mut r, &mut c), Err(RxOutcome::NoBox));
        assert_eq!(run(&good[..HEADER_LEN - 1], &mut r, &mut c), Err(RxOutcome::NotDisco));
        assert_eq!(run(&[], &mut r, &mut c), Err(RxOutcome::NotDisco));
        // magic
        let mut bad = good.to_vec();
        bad[0] = b'X';
        assert_eq!(run(&bad, &mut r, &mut c), Err(RxOutcome::NotDisco));
        // oversize
        let big = [0u8; MAX_PACKET + 1];
        assert_eq!(run(&big, &mut r, &mut c), Err(RxOutcome::TooLong));
        // a valid box around a short or unknown plaintext
        let mut buf = [0u8; 200];
        let n2 = seal_with(&mut buf, &a_pub, &shared_a, &nonce, |b| {
            b[0] = 0x01;
            Ok(1)
        })
        .unwrap();
        assert_eq!(run(&buf[..n2], &mut r, &mut c), Err(RxOutcome::Short));
        let n2 = seal_with(&mut buf, &a_pub, &shared_a, &nonce, |b| {
            b[..2].copy_from_slice(&[0x7f, 0]);
            Ok(2)
        })
        .unwrap();
        assert_eq!(run(&buf[..n2], &mut r, &mut c), Err(RxOutcome::UnknownType));
        let n2 = seal_with(&mut buf, &a_pub, &shared_a, &nonce, |b| {
            b[..2].copy_from_slice(&[0x05, 0]);
            Ok(2)
        })
        .unwrap();
        assert_eq!(run(&buf[..n2], &mut r, &mut c), Ok(RxOutcome::Unsupported));
        // every datagram counted exactly once
        assert_eq!(c.total(), calls);
    }

    #[test]
    fn candidate_flow() {
        let (_a_sec, a_pub, b_sec, _b_pub, shared_a) = world();
        let shared_b = nacl::precompute(&b_sec, &a_pub).unwrap();
        let nonce = [1u8; 24];
        let mut buf = [0u8; 200];
        let n = seal_pong(&mut buf, &a_pub, &shared_a, &nonce, &Pong { txid: [1; 12], src: Ep::NONE }).unwrap();
        // a non-resident directory peer whose box opens is activated
        let mut r = One { id: 5, key: a_pub.clone(), shared: shared_b.clone(), cand: Some(shared_b.clone()), slots: true };
        let rx = process(&mut buf[..n], &mut r).unwrap();
        assert!(rx.activated && rx.peer == 5);
        // no slot
        let mut buf2 = [0u8; 200];
        seal_pong(&mut buf2, &a_pub, &shared_a, &nonce, &Pong { txid: [1; 12], src: Ep::NONE }).unwrap();
        let mut r = One { id: 5, key: a_pub.clone(), shared: shared_b.clone(), cand: Some(shared_b.clone()), slots: false };
        assert_eq!(process(&mut buf2[..n], &mut r), Err(RxOutcome::NoSlot));
        // a forged claim: right key in the header, box made by someone else
        let (e_sec, _) = kp(9);
        let forged_shared = nacl::precompute(&e_sec, &a_pub).unwrap();
        let mut buf3 = [0u8; 200];
        let n3 = seal_pong(&mut buf3, &a_pub, &forged_shared, &nonce, &Pong { txid: [1; 12], src: Ep::NONE }).unwrap();
        let mut r = One { id: 5, key: a_pub.clone(), shared: shared_b.clone(), cand: Some(shared_b), slots: true };
        assert_eq!(process(&mut buf3[..n3], &mut r), Err(RxOutcome::CandidateFailed));
    }

    #[test]
    fn source_and_looks_like() {
        let (_s, a_pub, ..) = world();
        let mut b = [0u8; 100];
        b[..6].copy_from_slice(&MAGIC);
        b[6..38].copy_from_slice(a_pub.as_bytes());
        assert!(looks_like_disco(&b[..62]) && !looks_like_disco(&b[..61]));
        assert_eq!(source(&b[..62]), Some(a_pub.as_bytes()));
        assert_eq!(source(&b[..10]), None);
    }
}
