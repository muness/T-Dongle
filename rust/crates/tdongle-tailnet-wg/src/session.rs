//! A transport session (one WireGuard "keypair"): both keys, the send counter, the replay window and the timestamps, and the two halves of the packet path
//! as separate steps so the runtime can run the expensive one without any shared lock (ADR 0013's `begin / compute / commit`):
//!
//! ```text
//! send:     Session::tx_reserve(now)          [under the lock, a few instructions: picks the counter, copies the key]
//!           TxTicket::seal(buf, plain_len)    [NO lock: pad, header, ChaCha20-Poly1305 in place; touches nothing shared]
//! receive:  Session::rx_peek(counter, now)    [under the lock: expiry and replay pre-check, copies the key]
//!           RxTicket::open(packet)            [NO lock: authenticate and decrypt in place]
//!           Session::rx_commit(counter)       [under the lock: record the counter in the replay window (only after authentication)]
//! ```
//!
//! A ticket owns a copy of the key (zeroized on drop), so a session that is rolled, destroyed or wiped while a packet is in flight cannot change what that packet
//! is sealed or opened with.

use crate::consts::*;
use crate::error::{Dropped, SealError, TxError};
use crate::msg::{KEEPALIVE_LEN, TAG_LEN, TRANSPORT_HEADER_LEN, TransportHeader, padded_len};
use crate::replay::{ReplayVerdict, ReplayWindow};
use tdongle_tailnet_crypto::aead::{AuthError, open_detached, seal_detached};
use tdongle_tailnet_crypto::blake::kdf2;
use tdongle_tailnet_types::Millis;
use zeroize::Zeroize;

/// One session's keys and counters.
#[derive(Clone)]
pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    replay: ReplayWindow,
    local_index: u32,
    remote_index: u32,
    created: Millis,
    initiator: bool,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("local_index", &self.local_index)
            .field("remote_index", &self.remote_index)
            .field("initiator", &self.initiator)
            .field("created", &self.created)
            .field("send_counter", &self.send_counter)
            .finish_non_exhaustive()
    }
}

impl core::ops::Drop for Session {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

/// A reserved send counter and a copy of the key: everything needed to seal one datagram.
pub struct TxTicket {
    key: [u8; 32],
    counter: u64,
    remote_index: u32,
    /// The session wants replacing: it carried `REKEY_AFTER_MESSAGES` or (as initiator) is older than `REKEY_AFTER_TIME`.
    pub rekey_due: bool,
}

impl core::fmt::Debug for TxTicket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxTicket").field("counter", &self.counter).field("remote_index", &self.remote_index).finish_non_exhaustive()
    }
}

impl core::ops::Drop for TxTicket {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl TxTicket {
    /// The counter reserved (the nonce of this datagram).
    pub fn counter(&self) -> u64 {
        self.counter
    }
    /// The receiver index this datagram is addressed to.
    pub fn remote_index(&self) -> u32 {
        self.remote_index
    }

    /// Build the datagram in place. `buf` is `[16 B header space][plaintext of plain_len bytes][room for padding and the 16 B tag]`; the plaintext must already
    /// be at `buf[16..16 + plain_len]`. The padding (zeros to a multiple of 16), header and tag are written here. Returns the datagram length
    /// ([`transport_len`](crate::msg::transport_len)). Needs no lock and reads nothing but `self` and `buf`; a keepalive is `plain_len == 0` (32 bytes).
    pub fn seal(&self, buf: &mut [u8], plain_len: usize) -> Result<usize, SealError> {
        let padded = padded_len(plain_len);
        let total = TRANSPORT_HEADER_LEN + padded + TAG_LEN;
        if buf.len() < total {
            return Err(SealError::BufferTooSmall);
        }
        TransportHeader { receiver: self.remote_index, counter: self.counter }.write(buf);
        let body = &mut buf[TRANSPORT_HEADER_LEN..total];
        let (data, tag) = body.split_at_mut(padded);
        data[plain_len..].fill(0);
        let t = seal_detached(&self.key, self.counter, &[], data);
        tag.copy_from_slice(&t);
        Ok(total)
    }
}

/// What the compute step of the receive path needs: the key and the nonce.
pub struct RxTicket {
    key: [u8; 32],
    counter: u64,
    local_index: u32,
}

impl core::fmt::Debug for RxTicket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxTicket").field("counter", &self.counter).field("local_index", &self.local_index).finish_non_exhaustive()
    }
}

impl core::ops::Drop for RxTicket {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl RxTicket {
    /// The counter from the header.
    pub fn counter(&self) -> u64 {
        self.counter
    }
    /// The receiver index (ours) the datagram was addressed to; commit finds the session again by it.
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// Authenticate and decrypt `packet` (the whole datagram, at least 32 bytes) in place; the plaintext, padding included, is then at
    /// `packet[16..16 + n]` and `n` is returned (0 for a keepalive). On failure the bytes are unspecified: drop the datagram. Needs no lock.
    pub fn open(&self, packet: &mut [u8]) -> Result<usize, AuthError> {
        if packet.len() < KEEPALIVE_LEN {
            return Err(AuthError);
        }
        let body = &mut packet[TRANSPORT_HEADER_LEN..];
        let n = body.len() - TAG_LEN;
        let (data, tag) = body.split_at_mut(n);
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(tag);
        open_detached(&self.key, self.counter, &[], data, &t)?;
        Ok(n)
    }
}

impl Session {
    /// `size_of::<Session>()`.
    pub const BYTES: usize = core::mem::size_of::<Session>();

    /// Derive a session from the final chaining key (whitepaper 5.4.5: `(Tsend_i, Trecv_i) = Kdf2(C, empty)`, swapped for the responder).
    pub fn from_chaining_key(ck: &[u8; 32], initiator: bool, local_index: u32, remote_index: u32, now: Millis) -> Session {
        let (t1, t2) = kdf2(ck, &[]);
        let (send_key, recv_key) = if initiator { (t1, t2) } else { (t2, t1) };
        Session { send_key, recv_key, send_counter: 0, replay: ReplayWindow::new(), local_index, remote_index, created: now, initiator }
    }

    /// A session from explicit keys (tests and cross-implementation vectors).
    pub fn from_keys(send_key: [u8; 32], recv_key: [u8; 32], initiator: bool, local_index: u32, remote_index: u32, now: Millis) -> Session {
        Session { send_key, recv_key, send_counter: 0, replay: ReplayWindow::new(), local_index, remote_index, created: now, initiator }
    }

    /// Our receiver index for this session.
    pub fn local_index(&self) -> u32 {
        self.local_index
    }
    /// The peer's receiver index.
    pub fn remote_index(&self) -> u32 {
        self.remote_index
    }
    /// Did we send the initiation?
    pub fn is_initiator(&self) -> bool {
        self.initiator
    }
    /// When the session was derived.
    pub fn created(&self) -> Millis {
        self.created
    }
    /// The next send counter (also: how many counters were reserved).
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }
    /// The replay window.
    pub fn replay(&self) -> &ReplayWindow {
        &self.replay
    }
    /// Age at `now` (saturating).
    pub fn age(&self, now: Millis) -> Millis {
        now.saturating_sub(self.created)
    }
    /// `REJECT_AFTER_TIME` old or older: neither sends nor receives.
    pub fn is_expired(&self, now: Millis) -> bool {
        self.age(now) >= REJECT_AFTER_TIME
    }

    /// Reserve the next counter and copy the key. Refuses an expired or exhausted session. The counter is consumed even if the datagram is later dropped
    /// (gaps are legal in WireGuard; a counter is never used twice).
    pub fn tx_reserve(&mut self, now: Millis) -> Result<TxTicket, TxError> {
        if self.is_expired(now) {
            return Err(TxError::Expired);
        }
        if self.send_counter >= REJECT_AFTER_MESSAGES {
            return Err(TxError::Exhausted);
        }
        let counter = self.send_counter;
        self.send_counter += 1;
        let rekey_due = counter >= REKEY_AFTER_MESSAGES || (self.initiator && self.age(now) >= REKEY_AFTER_TIME);
        Ok(TxTicket { key: self.send_key, counter, remote_index: self.remote_index, rekey_due })
    }

    /// The cheap pre-check of the receive path: the session must not be expired and the counter must be fresh in the window (nothing is recorded).
    pub fn rx_peek(&self, counter: u64, now: Millis) -> Result<RxTicket, Dropped> {
        if self.is_expired(now) {
            return Err(Dropped::SessionExpired);
        }
        match self.replay.peek(counter) {
            ReplayVerdict::Ok => Ok(RxTicket { key: self.recv_key, counter, local_index: self.local_index }),
            ReplayVerdict::Duplicate => Err(Dropped::ReplayDuplicate),
            ReplayVerdict::TooOld => Err(Dropped::ReplayTooOld),
            ReplayVerdict::Limit => Err(Dropped::ReplayLimit),
        }
    }

    /// Record an authenticated counter. A concurrent datagram with the same counter may have been committed since [`rx_peek`](Self::rx_peek): that one is
    /// then the duplicate.
    pub fn rx_commit(&mut self, counter: u64) -> Result<(), Dropped> {
        match self.replay.check(counter) {
            ReplayVerdict::Ok => Ok(()),
            ReplayVerdict::Duplicate => Err(Dropped::ReplayDuplicate),
            ReplayVerdict::TooOld => Err(Dropped::ReplayTooOld),
            ReplayVerdict::Limit => Err(Dropped::ReplayLimit),
        }
    }

    /// Test hook / diagnostics: set the send counter (e.g. to approach the limits).
    pub fn set_send_counter(&mut self, c: u64) {
        self.send_counter = c;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::transport_len;

    fn pair() -> (Session, Session) {
        let ck = [5u8; 32];
        (Session::from_chaining_key(&ck, true, 1, 2, 0), Session::from_chaining_key(&ck, false, 2, 1, 0))
    }

    #[test]
    fn seal_open_every_length() {
        let (mut a, mut b) = pair();
        for n in 0..200usize {
            let mut buf = [0xEEu8; 300];
            for (i, x) in buf[16..16 + n].iter_mut().enumerate() {
                *x = i as u8;
            }
            let t = a.tx_reserve(1).unwrap();
            let len = t.seal(&mut buf, n).unwrap();
            assert_eq!(len, transport_len(n));
            let h = TransportHeader::parse(&buf[..len]).unwrap();
            assert_eq!(h, TransportHeader { receiver: 2, counter: n as u64 });
            let rt = b.rx_peek(h.counter, 1).unwrap();
            let m = rt.open(&mut buf[..len]).unwrap();
            assert_eq!(m, padded_len(n));
            assert!(buf[16..16 + n].iter().enumerate().all(|(i, &x)| x == i as u8));
            assert!(buf[16 + n..16 + m].iter().all(|&x| x == 0), "padding is zero");
            b.rx_commit(h.counter).unwrap();
            assert_eq!(b.rx_commit(h.counter), Err(Dropped::ReplayDuplicate));
        }
    }

    #[test]
    fn seal_refuses_small_buffers_and_open_tamper() {
        let (mut a, b) = pair();
        let t = a.tx_reserve(0).unwrap();
        assert_eq!(t.seal(&mut [0u8; 47], 1), Err(SealError::BufferTooSmall));
        assert_eq!(t.seal(&mut [0u8; 48], 1), Ok(48));
        let mut buf = [0u8; 64];
        let t = a.tx_reserve(0).unwrap();
        let len = t.seal(&mut buf, 20).unwrap();
        for i in (0..len).filter(|i| !(4..8).contains(i)) {
            // (bytes 4..8, the receiver index, are not authenticated by the tag: they select the session, nothing more)
            let mut bad = buf;
            bad[i] ^= 0x40;
            let r = TransportHeader::parse(&bad[..len]);
            // flipping a header byte changes the counter (nonce) or index; either way the tag must fail
            if let Ok(h) = r
                && let Ok(rt) = b.rx_peek(h.counter, 0)
            {
                assert!(rt.open(&mut bad[..len]).is_err(), "byte {i}");
            }
        }
        assert!(b.rx_peek(1, 0).unwrap().open(&mut buf[..31]).is_err());
    }

    #[test]
    fn counters_never_repeat_and_limits_hold() {
        let (mut a, _) = pair();
        let c: u64 = (0..5).map(|_| a.tx_reserve(0).unwrap().counter()).fold(0, |p, c| {
            assert!(c >= p);
            c
        });
        assert_eq!(c, 4);
        a.set_send_counter(REJECT_AFTER_MESSAGES - 1);
        assert!(a.tx_reserve(0).is_ok());
        assert_eq!(a.tx_reserve(0).unwrap_err(), TxError::Exhausted);
        let (mut a, _) = pair();
        assert_eq!(a.tx_reserve(REJECT_AFTER_TIME).unwrap_err(), TxError::Expired);
        assert!(a.tx_reserve(REJECT_AFTER_TIME - 1).is_ok());
    }

    #[test]
    fn rekey_due_rules() {
        let (mut a, mut b) = pair();
        assert!(!a.tx_reserve(REKEY_AFTER_TIME - 1).unwrap().rekey_due);
        assert!(a.tx_reserve(REKEY_AFTER_TIME).unwrap().rekey_due, "initiator rekeys by age");
        assert!(!b.tx_reserve(REKEY_AFTER_TIME).unwrap().rekey_due, "responder does not");
        b.set_send_counter(REKEY_AFTER_MESSAGES);
        assert!(b.tx_reserve(0).unwrap().rekey_due, "either rekeys by message count");
    }

    #[test]
    fn rx_peek_rules() {
        let (a, mut b) = pair();
        assert_eq!(a.rx_peek(0, REJECT_AFTER_TIME).unwrap_err(), Dropped::SessionExpired);
        assert_eq!(b.rx_peek(REJECT_AFTER_MESSAGES, 0).unwrap_err(), Dropped::ReplayLimit);
        b.rx_commit(1000).unwrap();
        assert_eq!(b.rx_peek(1000, 0).unwrap_err(), Dropped::ReplayDuplicate);
        assert_eq!(b.rx_peek(1000 - 481, 0).unwrap_err(), Dropped::ReplayTooOld);
        assert!(b.rx_peek(1000 - 480, 0).is_ok());
    }

    #[test]
    fn ticket_survives_session_destruction() {
        let (mut a, b) = pair();
        let t = a.tx_reserve(0).unwrap();
        let mut buf = [0u8; 64];
        let len = t.seal(&mut buf, 8).unwrap();
        let rt = b.rx_peek(t.counter(), 0).unwrap();
        drop(b);
        drop(a);
        assert_eq!(rt.open(&mut buf[..len]), Ok(16));
    }
}
