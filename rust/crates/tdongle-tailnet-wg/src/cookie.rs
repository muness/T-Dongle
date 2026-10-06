//! mac1, mac2 and cookie replies (whitepaper 5.4.4, 5.3 and 5.4.7).
//!
//! * **mac1** proves the sender knows our public key. Every handshake message carries one; a message without a valid mac1 is dropped before any X25519.
//! * **mac2** proves the sender recently received a cookie *from us* at its address. Required only when we are "under load" (the caller decides; the C's
//!   `wireguard_is_under_load`, wireguard-go's `UnderLoadAfterTime`). Without a valid mac2 under load, a valid-mac1 message is answered with a
//!   [`CookieReply`](crate::msg::CookieReply) instead of being processed. The cookie is `MAC(secret, source address and port)`; the secret rotates every
//!   two minutes.

use crate::consts::COOKIE_LIFETIME;
use crate::error::Dropped;
use crate::ident::Identity;
use crate::msg::{COOKIE_REPLY_LEN, CookieReply, INITIATION_LEN, MAC_LEN, MsgType, RESPONSE_LEN, classify};
use subtle::ConstantTimeEq;
use tdongle_tailnet_crypto::aead::{xopen_detached, xseal_detached};
use tdongle_tailnet_crypto::blake::mac128;
use tdongle_tailnet_types::{Entropy, Millis};
use zeroize::Zeroize;

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Fill in mac1 (and mac2) of an outgoing handshake message, which is the whole 148 or 92 byte message with its two MAC fields (the last 32 bytes) free.
/// `mac1_key` is the recipient's [`label_key`](crate::ident::label_key); `cookie` is the latest cookie the recipient gave us, if still valid.
pub fn add_macs(msg: &mut [u8], mac1_key: &[u8; 32], cookie: Option<&[u8; 16]>) {
    let n = msg.len();
    debug_assert!(n == INITIATION_LEN || n == RESPONSE_LEN);
    if n < 2 * MAC_LEN {
        return;
    }
    let mac1 = mac128(mac1_key, &[&msg[..n - 2 * MAC_LEN]]);
    msg[n - 2 * MAC_LEN..n - MAC_LEN].copy_from_slice(&mac1);
    let mac2 = match cookie {
        Some(c) => mac128(c, &[&msg[..n - MAC_LEN]]),
        None => [0; MAC_LEN],
    };
    msg[n - MAC_LEN..].copy_from_slice(&mac2);
}

/// Verify the mac1 of a received handshake message with our own mac1 key.
pub fn check_mac1(msg: &[u8], mac1_key: &[u8; 32]) -> bool {
    let n = msg.len();
    if n < 2 * MAC_LEN {
        return false;
    }
    let want = mac128(mac1_key, &[&msg[..n - 2 * MAC_LEN]]);
    ct_eq(&want, &msg[n - 2 * MAC_LEN..n - MAC_LEN])
}

/// The responder's cookie secret and the checks and replies built on it. One per membership (device), not per peer.
pub struct CookieChecker {
    secret: [u8; 32],
    set_at: Option<Millis>,
}

impl core::fmt::Debug for CookieChecker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CookieChecker").field("set_at", &self.set_at).finish_non_exhaustive()
    }
}

impl core::ops::Drop for CookieChecker {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Default for CookieChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieChecker {
    /// No secret yet (the first reply creates one).
    pub const fn new() -> Self {
        Self { secret: [0; 32], set_at: None }
    }

    fn fresh(&self, now: Millis) -> bool {
        self.set_at.is_some_and(|t| now.saturating_sub(t) <= COOKIE_LIFETIME)
    }

    fn cookie_for(&self, src: &[u8]) -> [u8; 16] {
        mac128(&self.secret, &[src])
    }

    /// Does `msg`'s mac2 verify against the cookie for `src` (the sender's address and port as the runtime encodes them)? False if the secret expired.
    pub fn check_mac2(&self, msg: &[u8], src: &[u8], now: Millis) -> bool {
        let n = msg.len();
        if n < 2 * MAC_LEN || !self.fresh(now) {
            return false;
        }
        let cookie = self.cookie_for(src);
        let want = mac128(&cookie, &[&msg[..n - MAC_LEN]]);
        ct_eq(&want, &msg[n - MAC_LEN..])
    }

    /// Build the cookie reply to a message whose mac1 verified. `sender` is that message's `sender` field.
    pub fn create_reply(&mut self, id: &Identity, msg: &[u8], sender: u32, src: &[u8], now: Millis, rng: &mut dyn Entropy) -> [u8; COOKIE_REPLY_LEN] {
        if !self.fresh(now) {
            rng.fill(&mut self.secret);
            self.set_at = Some(now);
        }
        let mut nonce = [0u8; 24];
        rng.fill(&mut nonce);
        let mut enc = [0u8; 32];
        enc[..16].copy_from_slice(&self.cookie_for(src));
        let n = msg.len();
        let aad: &[u8] = if n >= 2 * MAC_LEN { &msg[n - 2 * MAC_LEN..n - MAC_LEN] } else { &[] };
        let (body, tag) = enc.split_at_mut(16);
        tag.copy_from_slice(&xseal_detached(id.cookie_key(), &nonce, aad, body));
        CookieReply { receiver: sender, nonce, enc_cookie: enc }.encode()
    }
}

/// What to do with a received initiation or response after the MAC checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Valid: process it.
    Pass,
    /// mac1 valid but under load without a valid mac2: send this cookie reply to the source, do not process.
    CookieReply([u8; COOKIE_REPLY_LEN]),
    /// Drop it.
    Drop(Dropped),
}

/// The MAC gate in front of every handshake message (both kinds): framing, mac1 under our key, and under load also mac2 (answering with a cookie reply
/// when it is missing or stale). `src` is the datagram's source address and port encoding; `under_load` is the runtime's decision.
pub fn screen(id: &Identity, checker: &mut CookieChecker, msg: &[u8], src: &[u8], under_load: bool, now: Millis, rng: &mut dyn Entropy) -> Screen {
    match classify(msg) {
        Ok(MsgType::Initiation | MsgType::Response) => {}
        Ok(_) => return Screen::Drop(Dropped::ParseType),
        Err(e) => return Screen::Drop(e.into()),
    }
    if !check_mac1(msg, id.mac1_key()) {
        return Screen::Drop(Dropped::BadMac1);
    }
    if !under_load || checker.check_mac2(msg, src, now) {
        return Screen::Pass;
    }
    let sender = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
    Screen::CookieReply(checker.create_reply(id, msg, sender, src, now, rng))
}

/// Open a cookie reply with the replying peer's cookie key and the mac1 of the message it answers.
pub fn open_cookie_reply(peer_cookie_key: &[u8; 32], last_mac1: &[u8; 16], reply: &CookieReply) -> Option<[u8; 16]> {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&reply.enc_cookie[..16]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&reply.enc_cookie[16..]);
    xopen_detached(peer_cookie_key, &reply.nonce, last_mac1, &mut buf, &tag).ok()?;
    Some(buf)
}
