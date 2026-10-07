//! The hot half of a peer: handshake state, the three session slots, timers and counters. Everything a resident peer needs and nothing a configured-but-idle
//! peer should cost; a pool of these is shared by all memberships ([`PeerHot::BYTES`]). The cold half (public key, preshared key) is
//! [`PeerCold`], passed in by reference to every call that needs it.
//!
//! Sans-IO: time is a [`Millis`] argument, entropy `&mut dyn Entropy`, wall-clock a [`WallClock`], receiver indices an [`IndexAllocator`]. Methods return
//! datagrams as arrays or [`Actions`] the runtime performs; nothing here sends or sleeps.
//!
//! # Session lifecycle (whitepaper 6.1, wireguard-go `BeginSymmetricSession`)
//!
//! * the initiator derives its session on a valid response and uses it at once (`current`); the previous `current` becomes `previous` (or `next` does, if one
//!   was waiting);
//! * the responder derives its session when it sends the response, but it sits in `next` and **cannot send** until the first authenticated transport message
//!   arrives on it (key confirmation); that datagram promotes `next` to `current` and `current` to `previous`;
//! * every session dies at `REJECT_AFTER_TIME` or `REJECT_AFTER_MESSAGES`; all key material of a peer is wiped `3 * REJECT_AFTER_TIME` after the last session
//!   was derived.
//!
//! # Timers (wireguard-go `timers.go`, as deadlines)
//!
//! [`PeerHot::poll`] is level triggered: it returns what is due and keeps returning it until the runtime does it (calling `create_initiation`,
//! [`tx_prepare`](PeerHot::tx_prepare) with [`TxKind::Keepalive`]). [`PeerHot::next_wake`] says when to poll next.

use crate::consts::*;
use crate::cookie::{add_macs, open_cookie_reply};
use crate::error::{Dropped, InitError, TxError};
use crate::ident::{Identity, PeerCold, WallClock, tai_succ, tai64n};
use crate::index::IndexAllocator;
use crate::msg::{CookieReply, INITIATION_LEN, Initiation, KEEPALIVE_LEN, RESPONSE_LEN, Response, TAG_LEN, TransportHeader};
use crate::session::{RxTicket, Session, TxTicket};
use tdongle_tailnet_crypto::aead::{open_detached, seal_detached};
use tdongle_tailnet_crypto::blake::{hash2, kdf1, kdf2, kdf3};
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_types::{Entropy, Key32, Millis};
use zeroize::Zeroize;

/// An optional timestamp in 8 bytes (`u64::MAX` is "not set").
#[derive(Clone, Copy, PartialEq, Eq)]
struct At(u64);

impl core::fmt::Debug for At {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.get() {
            Some(t) => write!(f, "{t}"),
            None => f.write_str("-"),
        }
    }
}

impl At {
    const NONE: At = At(u64::MAX);
    fn get(self) -> Option<Millis> {
        if self.0 == u64::MAX { None } else { Some(self.0) }
    }
    fn set(&mut self, t: Millis) {
        self.0 = t.min(u64::MAX - 1);
    }
    fn clear(&mut self) {
        self.0 = u64::MAX;
    }
    fn is_set(self) -> bool {
        self.0 != u64::MAX
    }
    fn due(self, now: Millis) -> bool {
        self.0 != u64::MAX && self.0 <= now
    }
}

/// Handshake progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HsState {
    /// Nothing in flight.
    Idle,
    /// We sent an initiation and wait for the response.
    InitiationSent,
    /// We consumed an initiation and have not answered yet.
    InitiationConsumed,
}

struct Handshake {
    state: HsState,
    local_index: u32,
    remote_index: u32,
    eph_priv: [u8; 32],
    remote_eph: [u8; 32],
    hash: [u8; 32],
    ck: [u8; 32],
}

impl Handshake {
    const fn idle() -> Self {
        Handshake { state: HsState::Idle, local_index: 0, remote_index: 0, eph_priv: [0; 32], remote_eph: [0; 32], hash: [0; 32], ck: [0; 32] }
    }
    fn wipe(&mut self) {
        self.eph_priv.zeroize();
        self.remote_eph.zeroize();
        self.hash.zeroize();
        self.ck.zeroize();
        self.local_index = 0;
        self.remote_index = 0;
        self.state = HsState::Idle;
    }
}

impl core::ops::Drop for Handshake {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// What [`PeerHot::poll`] found due. Combine with `|`, test with [`contains`](Actions::contains).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Actions(u8);

impl Actions {
    /// Nothing is due.
    pub const NONE: Actions = Actions(0);
    /// Send a keepalive: [`PeerHot::tx_prepare`] with [`TxKind::Keepalive`], seal with `plain_len == 0`.
    pub const SEND_KEEPALIVE: Actions = Actions(1);
    /// Send an initiation: [`PeerHot::create_initiation`].
    pub const SEND_INITIATION: Actions = Actions(2);
    /// The handshake series ran for `REKEY_ATTEMPT_TIME` without an answer and was abandoned: drop the packets queued for this peer.
    pub const HANDSHAKE_GAVE_UP: Actions = Actions(4);
    /// A session (or all key material) expired and was wiped; the peer may now be idle ([`PeerHot::is_idle`]).
    pub const KEYS_EXPIRED: Actions = Actions(8);
    /// Is every bit of `o` set?
    pub fn contains(self, o: Actions) -> bool {
        self.0 & o.0 == o.0
    }
    /// Nothing due?
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for Actions {
    type Output = Actions;
    fn bitor(self, o: Actions) -> Actions {
        Actions(self.0 | o.0)
    }
}
impl core::ops::BitOrAssign for Actions {
    fn bitor_assign(&mut self, o: Actions) {
        self.0 |= o.0;
    }
}
impl core::fmt::Debug for Actions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for (a, n) in [
            (Self::SEND_KEEPALIVE, "SEND_KEEPALIVE"),
            (Self::SEND_INITIATION, "SEND_INITIATION"),
            (Self::HANDSHAKE_GAVE_UP, "HANDSHAKE_GAVE_UP"),
            (Self::KEYS_EXPIRED, "KEYS_EXPIRED"),
        ] {
            if self.contains(a) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(n)?;
                first = false;
            }
        }
        if first { f.write_str("NONE") } else { Ok(()) }
    }
}

/// What a transmitted datagram is, for the timers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxKind {
    /// Carries a payload.
    Data,
    /// Empty (32 bytes).
    Keepalive,
}

/// The result of a datagram that authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxOutcome {
    /// Decrypted length, padding included, at `packet[16..16 + plain_len]`. Zero for a keepalive.
    pub plain_len: usize,
    /// It was a keepalive (nothing to deliver).
    pub keepalive: bool,
    /// It was the first datagram on a responder's session: the session is now `current`; send what was queued for this peer.
    pub confirmed: bool,
}

/// The first half of an initiation, which needs only our identity: the peer's static key, decrypted. The runtime looks the peer up with
/// [`peer_public`](Self::peer_public) (acquiring a hot slot if the peer is not resident) and passes this to [`PeerHot::consume_initiation`].
pub struct InitiationStage1 {
    hash: [u8; 32],
    ck: [u8; 32],
    remote_eph: [u8; 32],
    sender: u32,
    peer_public: Key32,
    enc_timestamp: [u8; 28],
}

impl core::fmt::Debug for InitiationStage1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InitiationStage1(sender={}, peer={:?})", self.sender, self.peer_public.short())
    }
}

impl core::ops::Drop for InitiationStage1 {
    fn drop(&mut self) {
        self.hash.zeroize();
        self.ck.zeroize();
    }
}

impl InitiationStage1 {
    /// The initiator's static public key.
    pub fn peer_public(&self) -> &Key32 {
        &self.peer_public
    }
    /// The initiator's receiver index.
    pub fn sender(&self) -> u32 {
        self.sender
    }
}

impl Identity {
    /// Step one of consuming an initiation (the caller has run [`screen`](crate::cookie::screen)): one X25519 with our static key, then decrypt the sender's
    /// static public key. Touches no peer state.
    pub fn consume_initiation_stage1(&self, msg: &Initiation) -> Result<InitiationStage1, Dropped> {
        let mut hash = hash2(&INITIAL_HASH, &self.public().0);
        let mut ck = kdf1(&INITIAL_CHAIN_KEY, &msg.ephemeral);
        hash = hash2(&hash, &msg.ephemeral);
        let ss = self.dh(&Key32(msg.ephemeral)).ok_or(Dropped::DhZero)?;
        let (ck2, mut key) = kdf2(&ck, &ss.0);
        ck = ck2;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&msg.enc_static[..32]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&msg.enc_static[32..]);
        let r = open_detached(&key, 0, &hash, &mut pk, &tag);
        key.zeroize();
        if r.is_err() {
            return Err(Dropped::HsAuthStatic);
        }
        hash = hash2(&hash, &msg.enc_static);
        Ok(InitiationStage1 { hash, ck, remote_eph: msg.ephemeral, sender: msg.sender, peer_public: Key32(pk), enc_timestamp: msg.enc_timestamp })
    }
}

/// An initiation whose cryptography (two X25519, about 40 ms on the S3) runs outside any lock: [`PeerHot::initiation_begin`] copies what the crypto reads,
/// [`compute`](Self::compute) does it on the job's own storage, [`PeerHot::initiation_commit`] installs the handshake state if the peer is still as it was.
pub struct InitiationJob {
    id_public: [u8; 32],
    peer_public: [u8; 32],
    static_dh: [u8; 32],
    mac1_key: [u8; 32],
    cookie: Option<[u8; 16]>,
    eph_priv: [u8; 32],
    timestamp: [u8; 12],
    index: u32,
    jitter: u16,
    generation: u16,
    ok: bool,
    ck: [u8; 32],
    hash: [u8; 32],
    msg: [u8; INITIATION_LEN],
}

impl core::fmt::Debug for InitiationJob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "InitiationJob(index={}, ok={})", self.index, self.ok)
    }
}

impl core::ops::Drop for InitiationJob {
    fn drop(&mut self) {
        self.static_dh.zeroize();
        self.eph_priv.zeroize();
        self.ck.zeroize();
        self.hash.zeroize();
    }
}

impl InitiationJob {
    /// The receiver index this initiation carries.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Do the cryptography. Reads and writes only `self`; needs no lock. Check the result with [`ok`](Self::ok) (false only for a small-order peer key).
    pub fn compute(&mut self) {
        let eph = Key32(self.eph_priv);
        let e_pub = x25519::public(&eph);
        let mut ck = kdf1(&INITIAL_CHAIN_KEY, &e_pub.0);
        let mut hash = hash2(&INITIAL_HASH, &self.peer_public);
        hash = hash2(&hash, &e_pub.0);
        let Some(ss) = x25519::shared(&eph, &Key32(self.peer_public)) else {
            self.ok = false;
            return;
        };
        let (ck2, mut key) = kdf2(&ck, &ss.0);
        ck = ck2;
        let mut enc_static = [0u8; 48];
        enc_static[..32].copy_from_slice(&self.id_public);
        let t = seal_detached(&key, 0, &hash, &mut enc_static[..32]);
        enc_static[32..].copy_from_slice(&t);
        hash = hash2(&hash, &enc_static);
        let (ck3, key2) = kdf2(&ck, &self.static_dh);
        ck = ck3;
        key.zeroize();
        key = key2;
        let mut enc_ts = [0u8; 28];
        enc_ts[..12].copy_from_slice(&self.timestamp);
        let t = seal_detached(&key, 0, &hash, &mut enc_ts[..12]);
        enc_ts[12..].copy_from_slice(&t);
        hash = hash2(&hash, &enc_ts);
        key.zeroize();
        let mut msg = Initiation { sender: self.index, ephemeral: e_pub.0, enc_static, enc_timestamp: enc_ts, mac1: [0; 16], mac2: [0; 16] }.encode();
        add_macs(&mut msg, &self.mac1_key, self.cookie.as_ref());
        self.msg = msg;
        self.ck = ck;
        self.hash = hash;
        self.static_dh.zeroize();
        self.ok = true;
    }

    /// Did [`compute`](Self::compute) succeed?
    pub fn ok(&self) -> bool {
        self.ok
    }
}

/// The hot state of one peer. See the module documentation.
pub struct PeerHot {
    hs: Handshake,
    hs_generation: u16,
    cur: Option<Session>,
    prev: Option<Session>,
    next: Option<Session>,
    greatest_ts: [u8; 12],
    last_ts_sent: [u8; 12],
    cookie: [u8; 16],
    last_mac1: [u8; 16],
    last_mac1_valid: bool,
    cookie_at: At,
    last_initiation_rx: At,
    last_initiation_tx: At,
    retransmit_at: At,
    keepalive_at: At,
    new_handshake_at: At,
    zero_keys_at: At,
    persistent_at: At,
    attempt_started: At,
    last_rx: At,
    last_tx: At,
    last_handshake: At,
    persistent_interval_s: u16,
    jitter: u16,
    attempts: u8,
    want_handshake: bool,
    need_another_keepalive: bool,
}

impl core::fmt::Debug for PeerHot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerHot")
            .field("hs", &self.hs.state)
            .field("cur", &self.cur.as_ref().map(|s| s.local_index()))
            .field("prev", &self.prev.as_ref().map(|s| s.local_index()))
            .field("next", &self.next.as_ref().map(|s| s.local_index()))
            .field("attempts", &self.attempts)
            .field("want_handshake", &self.want_handshake)
            .finish_non_exhaustive()
    }
}

impl Default for PeerHot {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerHot {
    /// `size_of::<PeerHot>()` on this target: the cost of one pool slot's protocol state (the C's `struct wireguard_peer` was 904 B with allowed IPs).
    pub const BYTES: usize = core::mem::size_of::<PeerHot>();

    /// A fresh slot: no handshake, no sessions, no timers.
    pub const fn new() -> PeerHot {
        PeerHot {
            hs: Handshake::idle(),
            hs_generation: 0,
            cur: None,
            prev: None,
            next: None,
            greatest_ts: [0; 12],
            last_ts_sent: [0; 12],
            cookie: [0; 16],
            last_mac1: [0; 16],
            last_mac1_valid: false,
            cookie_at: At::NONE,
            last_initiation_rx: At::NONE,
            last_initiation_tx: At::NONE,
            retransmit_at: At::NONE,
            keepalive_at: At::NONE,
            new_handshake_at: At::NONE,
            zero_keys_at: At::NONE,
            persistent_at: At::NONE,
            attempt_started: At::NONE,
            last_rx: At::NONE,
            last_tx: At::NONE,
            last_handshake: At::NONE,
            persistent_interval_s: 0,
            jitter: 0,
            attempts: 0,
            want_handshake: false,
            need_another_keepalive: false,
        }
    }

    /// Return the slot to its initial state, wiping every key (a slot going back to the pool). Also forgets the greatest timestamp: save it first with
    /// [`greatest_timestamp`](Self::greatest_timestamp) if the peer stays configured.
    pub fn reset(&mut self) {
        *self = PeerHot::new();
    }

    // ---- state queries -------------------------------------------------------------------------------------------------------------------------

    /// No handshake, no session: the slot may be reclaimed without losing anything but timers.
    pub fn is_idle(&self) -> bool {
        self.hs.state == HsState::Idle
            && self.cur.is_none()
            && self.prev.is_none()
            && self.next.is_none()
            && !self.want_handshake
            && !self.retransmit_at.is_set()
    }
    /// Is there a session we can send on?
    pub fn has_session(&self) -> bool {
        self.cur.is_some()
    }
    /// Handshake progress.
    pub fn handshake_state(&self) -> HsState {
        self.hs.state
    }
    /// Initiations sent in the current series.
    pub fn handshake_attempts(&self) -> u8 {
        self.attempts
    }
    /// The current session, if any (read only: for status output).
    pub fn current(&self) -> Option<&Session> {
        self.cur.as_ref()
    }
    /// The previous session.
    pub fn previous(&self) -> Option<&Session> {
        self.prev.as_ref()
    }
    /// The unconfirmed responder session.
    pub fn next(&self) -> Option<&Session> {
        self.next.as_ref()
    }
    /// When we last received any authenticated message from the peer.
    pub fn last_rx(&self) -> Option<Millis> {
        self.last_rx.get()
    }
    /// When we last sent one.
    pub fn last_tx(&self) -> Option<Millis> {
        self.last_tx.get()
    }
    /// When a handshake last completed (response consumed, or first transport on a responder session).
    pub fn last_handshake(&self) -> Option<Millis> {
        self.last_handshake.get()
    }
    /// Does a handshake series want an initiation (set by [`request_handshake`](Self::request_handshake) and the rekey rules)?
    pub fn wants_handshake(&self) -> bool {
        self.want_handshake
    }
    /// Call `f` with every receiver index this slot holds (sessions and the handshake): the pool's uniqueness check.
    pub fn for_each_index(&self, mut f: impl FnMut(u32)) {
        for s in [&self.cur, &self.prev, &self.next].into_iter().flatten() {
            f(s.local_index());
        }
        if self.hs.state != HsState::Idle {
            f(self.hs.local_index);
        }
    }
    /// Does this slot hold `index`?
    pub fn uses_index(&self, index: u32) -> bool {
        let mut hit = false;
        self.for_each_index(|i| hit |= i == index);
        hit
    }
    /// The session with receiver index `index`, if the slot has one.
    pub fn session_by_index(&self, index: u32) -> Option<&Session> {
        [&self.cur, &self.prev, &self.next].into_iter().flatten().find(|s| s.local_index() == index)
    }

    /// Test hook: set the send counter of the current session (to approach `REKEY_AFTER_MESSAGES` / `REJECT_AFTER_MESSAGES` without sending 2^60 packets).
    #[doc(hidden)]
    pub fn test_set_send_counter(&mut self, c: u64) {
        if let Some(s) = self.cur.as_mut() {
            s.set_send_counter(c);
        }
    }

    /// The greatest initiation timestamp (TAI64N) accepted from this peer: the responder's replay protection. A pool that evicts a slot should keep this
    /// 12-byte value with the peer's cold record and restore it with [`set_greatest_timestamp`](Self::set_greatest_timestamp) when the peer is next made
    /// resident; otherwise a replayed old initiation is accepted again once (it can only create an unusable `next` session and cost two X25519).
    pub fn greatest_timestamp(&self) -> [u8; 12] {
        self.greatest_ts
    }

    /// Restore the value saved from [`greatest_timestamp`](Self::greatest_timestamp).
    pub fn set_greatest_timestamp(&mut self, ts: [u8; 12]) {
        self.greatest_ts = ts;
    }

    /// Set the persistent keepalive interval in seconds (0 disables): a keepalive after that long without sending or receiving anything authenticated.
    pub fn set_persistent_keepalive(&mut self, secs: u16, now: Millis) {
        self.persistent_interval_s = secs;
        if secs == 0 {
            self.persistent_at.clear();
        } else {
            self.persistent_at.set(now + secs as u64 * 1000);
        }
    }

    /// Outgoing traffic found no session: arm a handshake (rate limited by `REKEY_TIMEOUT` and the series bookkeeping, so calling this per packet is fine).
    pub fn request_handshake(&mut self, _now: Millis) {
        if !self.retransmit_at.is_set() {
            self.want_handshake = true;
        }
    }

    /// Like [`request_handshake`](Self::request_handshake) but also lifts the `REKEY_TIMEOUT` spacing (a new endpoint was learned; the C's "clear
    /// `last_initiation_tx`"). Never lifts it for a series that is already retransmitting.
    pub fn request_handshake_now(&mut self, now: Millis) {
        if !self.retransmit_at.is_set() {
            self.last_initiation_tx.clear();
        }
        self.request_handshake(now);
    }

    // ---- timer bookkeeping ---------------------------------------------------------------------------------------------------------------------

    fn arm_persistent(&mut self, now: Millis) {
        if self.persistent_interval_s > 0 {
            self.persistent_at.set(now + self.persistent_interval_s as u64 * 1000);
        }
    }
    fn authenticated_tx(&mut self, now: Millis) {
        self.last_tx.set(now);
        self.keepalive_at.clear();
        self.need_another_keepalive = false;
        self.arm_persistent(now);
    }
    fn authenticated_rx(&mut self, now: Millis) {
        self.last_rx.set(now);
        self.new_handshake_at.clear();
        self.arm_persistent(now);
    }
    fn data_sent(&mut self, now: Millis) {
        if !self.new_handshake_at.is_set() {
            self.new_handshake_at.set(now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + self.jitter as u64);
        }
    }
    fn data_received(&mut self, now: Millis) {
        if !self.keepalive_at.is_set() {
            self.keepalive_at.set(now + KEEPALIVE_TIMEOUT);
        } else {
            self.need_another_keepalive = true;
        }
    }
    fn handshake_complete(&mut self, now: Millis) {
        self.retransmit_at.clear();
        self.attempt_started.clear();
        self.attempts = 0;
        self.want_handshake = false;
        self.last_handshake.set(now);
    }
    fn session_derived(&mut self, now: Millis) {
        self.zero_keys_at.set(now + ZERO_KEY_MATERIAL_AFTER);
    }
    fn initiation_gate_open(&self, now: Millis) -> bool {
        self.last_initiation_tx.get().is_none_or(|t| now.saturating_sub(t) >= REKEY_TIMEOUT)
    }
    fn bump_generation(&mut self) {
        self.hs_generation = self.hs_generation.wrapping_add(1);
    }

    fn wipe_secrets(&mut self) {
        self.hs.wipe();
        self.cur = None;
        self.prev = None;
        self.next = None;
        self.retransmit_at.clear();
        self.keepalive_at.clear();
        self.new_handshake_at.clear();
        self.zero_keys_at.clear();
        self.attempt_started.clear();
        self.need_another_keepalive = false;
        self.want_handshake = false;
        self.last_mac1_valid = false;
        self.bump_generation();
    }

    // ---- timers --------------------------------------------------------------------------------------------------------------------------------

    /// Run the timers at `now`: expire sessions, wipe stale key material, abandon a handshake series that ran its time, and report what the runtime must do.
    /// Level triggered: unless the runtime acts, the same actions are reported again.
    pub fn poll(&mut self, now: Millis) -> Actions {
        let mut a = Actions::NONE;
        for slot in [&mut self.cur, &mut self.prev, &mut self.next] {
            if slot.as_ref().is_some_and(|s| s.is_expired(now) || s.send_counter() >= REJECT_AFTER_MESSAGES) {
                *slot = None;
                a |= Actions::KEYS_EXPIRED;
            }
        }
        if self.zero_keys_at.due(now) {
            self.wipe_secrets();
            a |= Actions::KEYS_EXPIRED;
        }
        let mut want_init = self.want_handshake;
        if self.retransmit_at.due(now) {
            let over = self.attempt_started.get().is_some_and(|t| now.saturating_sub(t) >= REKEY_ATTEMPT_TIME) || self.attempts >= MAX_HANDSHAKE_ATTEMPTS;
            if over {
                self.retransmit_at.clear();
                self.attempt_started.clear();
                self.want_handshake = false;
                self.keepalive_at.clear();
                want_init = false;
                if self.hs.state == HsState::InitiationSent {
                    self.hs.wipe();
                    self.bump_generation();
                }
                if !self.zero_keys_at.is_set() {
                    self.zero_keys_at.set(now + ZERO_KEY_MATERIAL_AFTER);
                }
                a |= Actions::HANDSHAKE_GAVE_UP;
            } else {
                want_init = true;
            }
        }
        if self.new_handshake_at.due(now) {
            self.new_handshake_at.clear();
            self.want_handshake = true;
            want_init = true;
        }
        if self.keepalive_at.due(now) || self.persistent_at.due(now) {
            if self.cur.is_some() {
                a |= Actions::SEND_KEEPALIVE;
            } else if self.next.is_none() {
                self.keepalive_at.clear();
                if self.persistent_at.due(now) {
                    self.want_handshake = true;
                    want_init = true;
                }
            }
        }
        if (want_init || self.want_handshake) && self.initiation_gate_open(now) {
            a |= Actions::SEND_INITIATION;
        }
        a
    }

    /// The earliest time at which [`poll`](Self::poll) may report something new (`None`: nothing is scheduled). `now` is the current time; a result at or
    /// before it means "poll now".
    pub fn next_wake(&self, now: Millis) -> Option<Millis> {
        let mut w: Option<Millis> = None;
        let mut min = |t: Millis| w = Some(w.map_or(t, |c| c.min(t)));
        for t in [self.retransmit_at, self.keepalive_at, self.new_handshake_at, self.zero_keys_at, self.persistent_at] {
            if let Some(t) = t.get() {
                min(t);
            }
        }
        for s in [&self.cur, &self.prev, &self.next].into_iter().flatten() {
            min(s.created().saturating_add(REJECT_AFTER_TIME));
        }
        if self.want_handshake {
            min(self.last_initiation_tx.get().map_or(now, |t| t + REKEY_TIMEOUT));
        }
        w
    }

    // ---- sending -------------------------------------------------------------------------------------------------------------------------------

    /// Prepare one datagram: pick the current session, reserve a counter and copy the key into the ticket (a few instructions; seal the datagram with
    /// [`TxTicket::seal`] without any lock). `NoSession` also arms a handshake; an expired or exhausted session is wiped (and arms one too). A ticket
    /// that reports `rekey_due`, a responder session near its end, count towards `want_handshake`. Timers treat a reserved counter as sent.
    pub fn tx_prepare(&mut self, now: Millis, kind: TxKind) -> Result<TxTicket, TxError> {
        let Some(s) = self.cur.as_mut() else {
            self.request_handshake(now);
            return Err(TxError::NoSession);
        };
        let ticket = match s.tx_reserve(now) {
            Ok(t) => t,
            Err(e) => {
                self.cur = None;
                self.request_handshake(now);
                return Err(e);
            }
        };
        let responder_old = !s.is_initiator() && s.age(now) >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT;
        if ticket.rekey_due || responder_old {
            self.request_handshake(now);
        }
        let again = self.need_another_keepalive && kind == TxKind::Keepalive;
        self.authenticated_tx(now);
        if again {
            self.keepalive_at.set(now + KEEPALIVE_TIMEOUT);
        }
        if kind == TxKind::Data {
            self.data_sent(now);
        }
        Ok(ticket)
    }

    // ---- receiving transport -------------------------------------------------------------------------------------------------------------------

    /// First step of receiving a transport datagram: find the session by receiver index (current, previous or next), check expiry and the replay window
    /// (nothing is recorded), and copy the key. Cheap; the runtime then runs [`RxTicket::open`] without a lock and calls [`rx_commit`](Self::rx_commit).
    pub fn rx_begin(&self, receiver: u32, counter: u64, now: Millis) -> Result<RxTicket, Dropped> {
        let s = self.session_by_index(receiver).ok_or(Dropped::NoSession)?;
        s.rx_peek(counter, now)
    }

    /// Last step: the datagram authenticated to `plain_len` bytes. Record the counter (the session is found again by index: it may have rolled meanwhile),
    /// refresh the timers, promote a responder's `next` session on its first datagram. A second datagram with the same counter that was begun in parallel is
    /// the one refused here as a duplicate.
    pub fn rx_commit(&mut self, t: &RxTicket, plain_len: usize, now: Millis) -> Result<RxOutcome, Dropped> {
        let idx = t.local_index();
        let in_next = if self.cur.as_ref().is_some_and(|s| s.local_index() == idx) {
            self.cur.as_mut().map(|s| s.rx_commit(t.counter())).transpose()?;
            false
        } else if self.prev.as_ref().is_some_and(|s| s.local_index() == idx) {
            self.prev.as_mut().map(|s| s.rx_commit(t.counter())).transpose()?;
            false
        } else if self.next.as_ref().is_some_and(|s| s.local_index() == idx) {
            self.next.as_mut().map(|s| s.rx_commit(t.counter())).transpose()?;
            true
        } else {
            return Err(Dropped::NoSession);
        };
        self.authenticated_rx(now);
        let mut confirmed = false;
        if in_next {
            // key confirmation: the first authenticated message on the responder's session promotes it.
            self.prev = self.cur.take();
            self.cur = self.next.take();
            self.handshake_complete(now);
            confirmed = true;
        }
        if self.cur.as_ref().is_some_and(|c| c.is_initiator() && c.age(now) >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT) {
            self.request_handshake(now);
        }
        let keepalive = plain_len == 0;
        if !keepalive {
            self.data_received(now);
        }
        Ok(RxOutcome { plain_len, keepalive, confirmed })
    }

    /// The whole receive path in one call, for callers that hold the slot throughout: parse, begin, decrypt in place, commit. `packet` is the datagram.
    pub fn decrypt(&mut self, packet: &mut [u8], now: Millis) -> Result<RxOutcome, Dropped> {
        let h = TransportHeader::parse(packet).map_err(Dropped::from)?;
        let ticket = self.rx_begin(h.receiver, h.counter, now)?;
        let n = ticket.open(packet).map_err(|_| Dropped::AuthFail)?;
        self.rx_commit(&ticket, n, now)
    }

    /// The whole send path in one call: `buf` is `[16 B][plaintext of plain_len][room]`; returns the datagram length.
    pub fn encrypt(&mut self, buf: &mut [u8], plain_len: usize, now: Millis) -> Result<usize, TxError> {
        let kind = if plain_len == 0 { TxKind::Keepalive } else { TxKind::Data };
        let t = self.tx_prepare(now, kind)?;
        t.seal(buf, plain_len).map_err(|_| TxError::BufferTooSmall)
    }

    // ---- handshake: initiator ------------------------------------------------------------------------------------------------------------------

    /// First of the three steps of an initiation (`begin`, [`InitiationJob::compute`], [`initiation_commit`](Self::initiation_commit)): checks the
    /// `REKEY_TIMEOUT` spacing, draws the ephemeral key, the receiver index and the timestamp, and copies what the crypto reads.
    pub fn initiation_begin(
        &mut self,
        id: &Identity,
        cold: &PeerCold,
        now: Millis,
        wall: WallClock,
        rng: &mut dyn Entropy,
        idx: &mut dyn IndexAllocator,
    ) -> Result<InitiationJob, InitError> {
        if !self.initiation_gate_open(now) {
            return Err(InitError::TooSoon);
        }
        let index = idx.allocate().ok_or(InitError::NoIndex)?;
        let mut ts = tai64n(wall);
        if ts <= self.last_ts_sent {
            ts = tai_succ(&self.last_ts_sent);
        }
        self.last_ts_sent = ts;
        let eph = x25519::generate(rng);
        let mut j = [0u8; 2];
        rng.fill(&mut j);
        let jitter = (u16::from_le_bytes(j) as u64 % REKEY_TIMEOUT_JITTER_MAX) as u16;
        let cookie = if self.cookie_at.get().is_some_and(|t| now.saturating_sub(t) <= COOKIE_LIFETIME) { Some(self.cookie) } else { None };
        Ok(InitiationJob {
            id_public: id.public().0,
            peer_public: cold.public().0,
            static_dh: cold.static_dh().0,
            mac1_key: cold.mac1_key(),
            cookie,
            eph_priv: eph.0,
            timestamp: ts,
            index,
            jitter,
            generation: self.hs_generation,
            ok: false,
            ck: [0; 32],
            hash: [0; 32],
            msg: [0; INITIATION_LEN],
        })
    }

    /// Last step: if the slot's handshake state is unchanged since `begin` (nothing else started or consumed a handshake meanwhile), install the computed
    /// state and return the datagram. Otherwise `BadState` (the index is released). Starts the retransmit timer.
    pub fn initiation_commit(&mut self, job: InitiationJob, now: Millis, idx: &mut dyn IndexAllocator) -> Result<[u8; INITIATION_LEN], InitError> {
        if !job.ok {
            idx.release(job.index);
            return Err(InitError::DhZero);
        }
        if job.generation != self.hs_generation {
            idx.release(job.index);
            return Err(InitError::BadState);
        }
        self.hs.wipe();
        self.hs.state = HsState::InitiationSent;
        self.hs.local_index = job.index;
        self.hs.eph_priv = job.eph_priv;
        self.hs.ck = job.ck;
        self.hs.hash = job.hash;
        self.bump_generation();
        self.last_mac1.copy_from_slice(&job.msg[INITIATION_LEN - 32..INITIATION_LEN - 16]);
        self.last_mac1_valid = true;
        self.want_handshake = false;
        self.last_initiation_tx.set(now);
        if self.retransmit_at.is_set() {
            self.attempts = self.attempts.saturating_add(1);
        } else {
            self.attempts = 1;
            self.attempt_started.set(now);
        }
        self.jitter = job.jitter;
        self.retransmit_at.set(now + REKEY_TIMEOUT + job.jitter as u64);
        self.authenticated_tx(now);
        Ok(job.msg)
    }

    /// `begin`, `compute` and `commit` in a row, for callers that hold the slot throughout.
    pub fn create_initiation(
        &mut self,
        id: &Identity,
        cold: &PeerCold,
        now: Millis,
        wall: WallClock,
        rng: &mut dyn Entropy,
        idx: &mut dyn IndexAllocator,
    ) -> Result<[u8; INITIATION_LEN], InitError> {
        let mut job = self.initiation_begin(id, cold, now, wall, rng, idx)?;
        job.compute();
        self.initiation_commit(job, now, idx)
    }

    /// Consume the peer's response to our initiation (after [`screen`](crate::cookie::screen)): verify it, derive the session (the initiator may send on it
    /// at once) and queue the confirming keepalive ([`Actions::SEND_KEEPALIVE`] on the next poll). Returns the new session's local index. On any failure the
    /// slot is unchanged.
    pub fn consume_response(&mut self, id: &Identity, cold: &PeerCold, msg: &Response, now: Millis) -> Result<u32, Dropped> {
        if self.hs.state != HsState::InitiationSent || msg.receiver != self.hs.local_index {
            return Err(Dropped::HsNoHandshake);
        }
        let eph = Key32(self.hs.eph_priv);
        let mut hash = hash2(&self.hs.hash, &msg.ephemeral);
        let mut ck = kdf1(&self.hs.ck, &msg.ephemeral);
        let their_e = Key32(msg.ephemeral);
        let ss = x25519::shared(&eph, &their_e).ok_or(Dropped::DhZero)?;
        ck = kdf1(&ck, &ss.0);
        let ss = id.dh(&their_e).ok_or(Dropped::DhZero)?;
        ck = kdf1(&ck, &ss.0);
        let (ck3, mut tau, mut key) = kdf3(&ck, &cold.psk().0);
        ck = ck3;
        hash = hash2(&hash, &tau);
        tau.zeroize();
        let mut empty = [0u8; 0];
        let r = open_detached(&key, 0, &hash, &mut empty, &msg.enc_empty);
        key.zeroize();
        if r.is_err() {
            ck.zeroize();
            return Err(Dropped::HsAuthResponse);
        }
        let local = self.hs.local_index;
        let session = Session::from_chaining_key(&ck, true, local, msg.sender, now);
        ck.zeroize();
        self.hs.wipe();
        self.bump_generation();
        self.last_mac1_valid = false;
        // whitepaper 6.1 / BeginSymmetricSession, initiator branch
        let old_next = self.next.take();
        self.prev = if old_next.is_some() { old_next } else { self.cur.take() };
        self.cur = Some(session);
        self.session_derived(now);
        self.authenticated_rx(now);
        self.handshake_complete(now);
        self.keepalive_at.set(now);
        Ok(local)
    }

    /// Consume a cookie reply: if it answers our last initiation's mac1 and decrypts, store the cookie (used for mac2 of the next 120 s of handshake messages).
    pub fn consume_cookie_reply(&mut self, cold: &PeerCold, reply: &CookieReply, now: Millis) -> Result<(), Dropped> {
        if !self.last_mac1_valid || self.hs.state != HsState::InitiationSent || reply.receiver != self.hs.local_index {
            return Err(Dropped::CookieUnexpected);
        }
        let c = open_cookie_reply(&cold.cookie_key(), &self.last_mac1, reply).ok_or(Dropped::CookieAuth)?;
        self.cookie = c;
        self.cookie_at.set(now);
        self.last_mac1_valid = false;
        Ok(())
    }

    // ---- handshake: responder ------------------------------------------------------------------------------------------------------------------

    /// Step two of consuming an initiation, on the slot of the peer `stage1` named (`cold.public() == stage1.peer_public()`): decrypt and check the
    /// timestamp (strictly newer than any seen from this peer: replay protection), refuse floods, and keep the handshake state for
    /// [`create_response`](Self::create_response). A consumed initiation supersedes an initiation we have outstanding (both sides started at once).
    pub fn consume_initiation(&mut self, st: &InitiationStage1, cold: &PeerCold, now: Millis) -> Result<(), Dropped> {
        if *cold.public() != st.peer_public {
            return Err(Dropped::HsUnknownPeer);
        }
        let (mut ck, mut key) = kdf2(&st.ck, &cold.static_dh().0);
        let mut ts = [0u8; 12];
        ts.copy_from_slice(&st.enc_timestamp[..12]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&st.enc_timestamp[12..]);
        let r = open_detached(&key, 0, &st.hash, &mut ts, &tag);
        key.zeroize();
        if r.is_err() {
            ck.zeroize();
            return Err(Dropped::HsAuthTimestamp);
        }
        let hash = hash2(&st.hash, &st.enc_timestamp);
        if ts <= self.greatest_ts {
            ck.zeroize();
            return Err(Dropped::HsTimestampReplay);
        }
        if self.last_initiation_rx.get().is_some_and(|t| now.saturating_sub(t) <= MIN_INITIATION_INTERVAL) {
            ck.zeroize();
            return Err(Dropped::HsFlood);
        }
        self.greatest_ts = ts;
        self.last_initiation_rx.set(now);
        self.hs.wipe();
        self.hs.state = HsState::InitiationConsumed;
        self.hs.remote_index = st.sender;
        self.hs.remote_eph = st.remote_eph;
        self.hs.hash = hash;
        self.hs.ck = ck;
        ck.zeroize();
        self.bump_generation();
        self.last_mac1_valid = false;
        self.authenticated_rx(now);
        Ok(())
    }

    /// Answer the initiation consumed by [`consume_initiation`](Self::consume_initiation): derive the responder session into `next` (it cannot send until
    /// the peer's first datagram confirms it) and return the response.
    pub fn create_response(
        &mut self,
        id: &Identity,
        cold: &PeerCold,
        now: Millis,
        rng: &mut dyn Entropy,
        idx: &mut dyn IndexAllocator,
    ) -> Result<[u8; RESPONSE_LEN], InitError> {
        if self.hs.state != HsState::InitiationConsumed {
            return Err(InitError::BadState);
        }
        let _ = id;
        let index = idx.allocate().ok_or(InitError::NoIndex)?;
        let eph = x25519::generate(rng);
        let e_pub = x25519::public(&eph);
        let mut hash = hash2(&self.hs.hash, &e_pub.0);
        let mut ck = kdf1(&self.hs.ck, &e_pub.0);
        let dh = match (x25519::shared(&eph, &Key32(self.hs.remote_eph)), x25519::shared(&eph, cold.public())) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                idx.release(index);
                return Err(InitError::DhZero);
            }
        };
        ck = kdf1(&ck, &dh.0.0);
        ck = kdf1(&ck, &dh.1.0);
        let (ck3, mut tau, mut key) = kdf3(&ck, &cold.psk().0);
        ck = ck3;
        hash = hash2(&hash, &tau);
        tau.zeroize();
        let mut empty = [0u8; 0];
        let tag = seal_detached(&key, 0, &hash, &mut empty);
        key.zeroize();
        let remote_index = self.hs.remote_index;
        let mut msg = Response { sender: index, receiver: remote_index, ephemeral: e_pub.0, enc_empty: tag, mac1: [0; 16], mac2: [0; 16] }.encode();
        let cookie = if self.cookie_at.get().is_some_and(|t| now.saturating_sub(t) <= COOKIE_LIFETIME) { Some(self.cookie) } else { None };
        add_macs(&mut msg, &cold.mac1_key(), cookie.as_ref());
        let session = Session::from_chaining_key(&ck, false, index, remote_index, now);
        ck.zeroize();
        self.hs.wipe();
        self.bump_generation();
        // BeginSymmetricSession, responder branch
        self.next = Some(session);
        self.prev = None;
        self.session_derived(now);
        self.authenticated_tx(now);
        Ok(msg)
    }
}

// Keep the constant documented as used.
const _: usize = KEEPALIVE_LEN;
