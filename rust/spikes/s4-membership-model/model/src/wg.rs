//! (c) WireGuard peer state + the Noise_IKpsk2 handshake and transport, over chacha20poly1305 / blake2 / hmac / x25519-dalek.
//! Field layout mirrors wireguard_lwip/src/wireguard.h (struct wireguard_keypair / _handshake / _peer / _device).
use crate::meter::Meter;
use alloc::boxed::Box;
use alloc::vec::Vec;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAX_PEERS: usize = 8; // CONFIG_ML_MAX_PEERS=8 (build-release/sdkconfig:2072)
pub const REPLAY_RING_BITS: usize = 512; // wireguard_replay.h:25
pub const REPLAY_BLOCKS: usize = REPLAY_RING_BITS / 32;

type HmacB = Hmac<Blake2s256>;
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

fn hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacB as HmacKeyInit>::new_from_slice(key).unwrap();
    m.update(data);
    m.finalize().into_bytes().into()
}
fn kdf2(ck: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t0 = hmac(ck, input);
    let mut b = [0u8; 33];
    b[0] = 1;
    let t1 = hmac(&t0, &b[..1]);
    let mut c = [0u8; 33];
    c[..32].copy_from_slice(&t1);
    c[32] = 2;
    let t2 = hmac(&t0, &c);
    (t1, t2)
}
fn kdf1(ck: &[u8; 32], input: &[u8]) -> [u8; 32] {
    kdf2(ck, input).0
}
fn aead_seal(key: &[u8; 32], counter: u64, aad: &[u8], pt: &[u8], out: &mut [u8]) {
    let c = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    out[..pt.len()].copy_from_slice(pt);
    let tag = c.encrypt_inout_detached(Nonce::from_slice(&nonce), aad, (&mut out[..pt.len()]).into()).unwrap();
    out[pt.len()..pt.len() + 16].copy_from_slice(&tag);
}
fn aead_open(key: &[u8; 32], counter: u64, aad: &[u8], ct: &mut [u8]) -> bool {
    let c = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    let n = ct.len() - 16;
    let (body, tag) = ct.split_at_mut(n);
    let tag: [u8; 16] = (&*tag).try_into().unwrap();
    c.decrypt_inout_detached(Nonce::from_slice(&nonce), aad, body.into(), (&tag).into()).is_ok()
}
fn dh(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*sk).diffie_hellman(&PublicKey::from(*pk)).to_bytes()
}
fn pubkey(sk: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*sk)).to_bytes()
}

#[derive(Clone, Copy)]
pub struct Replay {
    pub counter: u64,
    pub ring: [u32; REPLAY_BLOCKS],
}
impl Replay {
    pub const fn new() -> Self {
        Replay { counter: 0, ring: [0; REPLAY_BLOCKS] }
    }
    /// Accept `their` once (sliding window, same rule as wireguard_replay.h).
    pub fn check(&mut self, their: u64) -> bool {
        const WINDOW: u64 = (REPLAY_RING_BITS - 32) as u64;
        let block = their >> 5;
        if their > self.counter {
            let cur = self.counter >> 5;
            let adv = (block - cur).min(REPLAY_BLOCKS as u64);
            for i in 1..=adv {
                self.ring[((cur + i) as usize) & (REPLAY_BLOCKS - 1)] = 0;
            }
            self.counter = their;
        } else if their + WINDOW < self.counter {
            return false;
        }
        let idx = (block as usize) & (REPLAY_BLOCKS - 1);
        let bit = 1u32 << (their & 31);
        if self.ring[idx] & bit != 0 {
            return false;
        }
        self.ring[idx] |= bit;
        true
    }
}

#[derive(Clone, Copy)]
pub struct Keypair {
    pub valid: bool,
    pub initiator: bool,
    pub keypair_millis: u32,
    pub sending_key: [u8; 32],
    pub sending_valid: bool,
    pub sending_counter: u64,
    pub receiving_key: [u8; 32],
    pub receiving_valid: bool,
    pub last_tx: u32,
    pub last_rx: u32,
    pub replay: Replay,
    pub local_index: u32,
    pub remote_index: u32,
}
impl Keypair {
    pub const fn empty() -> Self {
        Keypair {
            valid: false,
            initiator: false,
            keypair_millis: 0,
            sending_key: [0; 32],
            sending_valid: false,
            sending_counter: 0,
            receiving_key: [0; 32],
            receiving_valid: false,
            last_tx: 0,
            last_rx: 0,
            replay: Replay::new(),
            local_index: 0,
            remote_index: 0,
        }
    }
}
#[derive(Clone, Copy)]
pub struct Handshake {
    pub valid: bool,
    pub initiator: bool,
    pub local_index: u32,
    pub remote_index: u32,
    pub ephemeral_private: [u8; 32],
    pub remote_ephemeral: [u8; 32],
    pub hash: [u8; 32],
    pub chaining_key: [u8; 32],
}
#[derive(Clone, Copy)]
pub struct AllowedIp {
    pub valid: bool,
    pub ip: [u8; 16],
    pub mask: [u8; 16],
}
#[derive(Clone, Copy)]
pub struct Peer {
    pub valid: bool,
    pub active: bool,
    pub connect_ip: [u8; 17], // lwIP ip_addr_t on a dual-stack build is 20 B; 17 here (v6 + tag) rounds the same in repr(Rust)
    pub connect_port: u16,
    pub ip: [u8; 17],
    pub port: u16,
    pub keepalive_interval: u16,
    pub allowed: [AllowedIp; 2],
    pub public_key: [u8; 32],
    pub preshared_key: [u8; 32],
    pub public_key_dh: [u8; 32],
    pub curr: Keypair,
    pub prev: Keypair,
    pub next: Keypair,
    pub greatest_timestamp: [u8; 12],
    pub handshake: Handshake,
    pub cookie_millis: u32,
    pub cookie: [u8; 16],
    pub handshake_mac1_valid: bool,
    pub handshake_mac1: [u8; 16],
    pub label_cookie_key: [u8; 32],
    pub label_mac1_key: [u8; 32],
    pub last_initiation_rx: u32,
    pub last_initiation_tx: u32,
    pub last_tx: u32,
    pub last_rx: u32,
    pub send_handshake: bool,
    pub handshake_attempts: u8,
}
impl Peer {
    pub fn new(pk: [u8; 32], my_sk: &[u8; 32]) -> Self {
        let e = AllowedIp { valid: false, ip: [0; 16], mask: [0; 16] };
        Peer {
            valid: true,
            active: true,
            connect_ip: [0; 17],
            connect_port: 41641,
            ip: [0; 17],
            port: 0,
            keepalive_interval: 25,
            allowed: [e; 2],
            public_key: pk,
            preshared_key: [0; 32],
            public_key_dh: dh(my_sk, &pk),
            curr: Keypair::empty(),
            prev: Keypair::empty(),
            next: Keypair::empty(),
            greatest_timestamp: [0; 12],
            handshake: Handshake { valid: false, initiator: false, local_index: 0, remote_index: 0, ephemeral_private: [0; 32], remote_ephemeral: [0; 32], hash: [0; 32], chaining_key: [0; 32] },
            cookie_millis: 0,
            cookie: [0; 16],
            handshake_mac1_valid: false,
            handshake_mac1: [0; 16],
            label_cookie_key: [0; 32],
            label_mac1_key: [0; 32],
            last_initiation_rx: 0,
            last_initiation_tx: 0,
            last_tx: 0,
            last_rx: 0,
            send_handshake: false,
            handshake_attempts: 0,
        }
    }
}

/// The device: keys + a table of peer slots. `Box<Peer>` slots are allocated on demand (as the C pool does, wireguard_pool.c).
pub struct Device {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub cookie_secret: [u8; 32],
    pub cookie_secret_millis: u32,
    pub label_cookie_key: [u8; 32],
    pub label_mac1_key: [u8; 32],
    pub peers: [Option<Box<Peer>>; MAX_PEERS],
    pub next_hs_peer: u8,
}
impl Device {
    pub fn new(sk: [u8; 32]) -> Self {
        Device {
            private_key: sk,
            public_key: pubkey(&sk),
            cookie_secret: [0; 32],
            cookie_secret_millis: 0,
            label_cookie_key: [0; 32],
            label_mac1_key: [0; 32],
            peers: [const { None }; MAX_PEERS],
            next_hs_peer: 0,
        }
    }
    pub fn add_peer(&mut self, pk: [u8; 32]) -> usize {
        let i = self.peers.iter().position(|p| p.is_none()).unwrap();
        self.peers[i] = Some(Box::new(Peer::new(pk, &self.private_key)));
        i
    }
}

/// Initiation: returns (message, chaining key, hash, ephemeral secret) for the initiator. Message layout as WireGuard (148 B).
pub struct Init {
    pub msg: [u8; 148],
    pub ck: [u8; 32],
    pub h: [u8; 32],
    pub e_priv: [u8; 32],
}
pub fn initiate(my_sk: &[u8; 32], their_pk: &[u8; 32], e_priv: [u8; 32], index: u32) -> Init {
    let my_pk = pubkey(my_sk);
    let e_pub = pubkey(&e_priv);
    let ck0 = {
        let mut h = Blake2s256::new();
        h.update(CONSTRUCTION);
        h.finalize().into()
    };
    let mut h = hash2(&ck0, IDENTIFIER);
    h = hash2(&h, their_pk);
    let mut ck = kdf1(&ck0, &e_pub);
    h = hash2(&h, &e_pub);
    let (c, k) = kdf2(&ck, &dh(&e_priv, their_pk));
    ck = c;
    let mut enc_s = [0u8; 48];
    aead_seal(&k, 0, &h, &my_pk, &mut enc_s);
    h = hash2(&h, &enc_s);
    let (c, k) = kdf2(&ck, &dh(my_sk, their_pk));
    ck = c;
    let mut enc_t = [0u8; 28];
    aead_seal(&k, 0, &h, &[0x40, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], &mut enc_t);
    h = hash2(&h, &enc_t);
    let mut msg = [0u8; 148];
    msg[0] = 1;
    msg[4..8].copy_from_slice(&index.to_le_bytes());
    msg[8..40].copy_from_slice(&e_pub);
    msg[40..88].copy_from_slice(&enc_s);
    msg[88..116].copy_from_slice(&enc_t);
    Init { msg, ck, h, e_priv }
}

/// Responder side (the synthetic remote peer): consume an initiation, produce a response, derive the transport keys.
pub struct Resp {
    pub msg: [u8; 92],
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub ok: bool,
}
pub fn respond(my_sk: &[u8; 32], init_msg: &[u8; 148], e_priv: [u8; 32], index: u32) -> Resp {
    let my_pk = pubkey(my_sk);
    let ck0: [u8; 32] = {
        let mut h = Blake2s256::new();
        h.update(CONSTRUCTION);
        h.finalize().into()
    };
    let mut h = hash2(&ck0, IDENTIFIER);
    h = hash2(&h, &my_pk);
    let e_i: [u8; 32] = init_msg[8..40].try_into().unwrap();
    let mut ck = kdf1(&ck0, &e_i);
    h = hash2(&h, &e_i);
    let (c, k) = kdf2(&ck, &dh(my_sk, &e_i));
    ck = c;
    let mut s = [0u8; 48];
    s.copy_from_slice(&init_msg[40..88]);
    let ok1 = aead_open(&k, 0, &h, &mut s);
    h = hash2(&h, &init_msg[40..88]);
    let s_i: [u8; 32] = s[..32].try_into().unwrap();
    let (c, k) = kdf2(&ck, &dh(my_sk, &s_i));
    ck = c;
    let mut t = [0u8; 28];
    t.copy_from_slice(&init_msg[88..116]);
    let ok2 = aead_open(&k, 0, &h, &mut t);
    h = hash2(&h, &init_msg[88..116]);
    // response
    let e_pub = pubkey(&e_priv);
    ck = kdf1(&ck, &e_pub);
    h = hash2(&h, &e_pub);
    ck = kdf1(&ck, &dh(&e_priv, &e_i));
    ck = kdf1(&ck, &dh(&e_priv, &s_i));
    let (c, tau, k) = {
        let t0 = hmac(&ck, &[0u8; 32]); // psk = 0
        let t1 = hmac(&t0, &[1]);
        let mut b = [0u8; 33];
        b[..32].copy_from_slice(&t1);
        b[32] = 2;
        let t2 = hmac(&t0, &b);
        let mut b3 = [0u8; 33];
        b3[..32].copy_from_slice(&t2);
        b3[32] = 3;
        let t3 = hmac(&t0, &b3);
        (t1, t2, t3)
    };
    ck = c;
    h = hash2(&h, &tau);
    let mut enc_n = [0u8; 16];
    aead_seal(&k, 0, &h, &[], &mut enc_n);
    let mut msg = [0u8; 92];
    msg[0] = 2;
    msg[4..8].copy_from_slice(&index.to_le_bytes());
    msg[12..44].copy_from_slice(&e_pub);
    msg[44..60].copy_from_slice(&enc_n);
    let (recv, send) = kdf2(&ck, &[]);
    Resp { msg, send_key: send, recv_key: recv, ok: ok1 && ok2 }
}

/// Initiator consumes the response (ee, se, psk, empty AEAD) and derives its transport keys; returns (sending, receiving).
pub fn consume_response(init: &Init, my_sk: &[u8; 32], resp: &[u8; 92]) -> Option<([u8; 32], [u8; 32])> {
    let e_r: [u8; 32] = resp[12..44].try_into().unwrap();
    let mut ck = kdf1(&init.ck, &e_r);
    let mut h = hash2(&init.h, &e_r);
    ck = kdf1(&ck, &dh(&init.e_priv, &e_r));
    ck = kdf1(&ck, &dh(my_sk, &e_r));
    let t0 = hmac(&ck, &[0u8; 32]);
    let t1 = hmac(&t0, &[1]);
    let mut b = [0u8; 33];
    b[..32].copy_from_slice(&t1);
    b[32] = 2;
    let t2 = hmac(&t0, &b);
    let mut b3 = [0u8; 33];
    b3[..32].copy_from_slice(&t2);
    b3[32] = 3;
    let t3 = hmac(&t0, &b3);
    ck = t1;
    h = hash2(&h, &t2);
    let mut n = [0u8; 16];
    n.copy_from_slice(&resp[44..60]);
    if !aead_open(&t3, 0, &h, &mut n) {
        return None;
    }
    let (send, recv) = kdf2(&ck, &[]);
    Some((send, recv))
}

/// Seal a transport packet: counter + ChaCha20-Poly1305 over `len` bytes (in place, tag appended).
pub fn seal(kp: &mut Keypair, buf: &mut [u8], len: usize) -> usize {
    let c = kp.sending_counter;
    kp.sending_counter += 1;
    let key = kp.sending_key;
    let (body, rest) = buf.split_at_mut(len);
    let cc = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&c.to_le_bytes());
    let tag = cc.encrypt_inout_detached(Nonce::from_slice(&nonce), &[], body.into()).unwrap();
    rest[..16].copy_from_slice(&tag);
    len + 16
}
pub fn open(kp: &mut Keypair, buf: &mut [u8], len: usize, counter: u64) -> bool {
    if !kp.replay.check(counter) {
        return false;
    }
    let key = kp.receiving_key;
    aead_open(&key, counter, &[], &mut buf[..len])
}

pub struct Wg {
    pub dev: Device,
}

/// Bring the WireGuard side up: device + `resident` peers, run one full handshake for peer 0 and move packets.
pub fn setup(m: &impl Meter, resident: usize) -> (Wg, bool) {
    let my_sk = [0x33u8; 32];
    let mut ok = true;
    m.begin("wg.device");
    let mut dev = Device::new(my_sk);
    m.end();

    let remote_sk = [0x44u8; 32];
    let remote_pk = pubkey(&remote_sk);

    m.begin("wg.peers_resident");
    for i in 0..resident {
        let mut pk = remote_pk;
        pk[0] ^= i as u8;
        dev.add_peer(pk);
    }
    m.end();

    // Initiator side measured; the "remote" side (respond) runs outside the measured window.
    m.begin("wg.handshake_initiate");
    let init = initiate(&my_sk, &remote_pk, [0x55u8; 32], 7);
    m.end();
    let resp = respond(&remote_sk, &init.msg, [0x66u8; 32], 9);
    ok &= resp.ok;
    m.begin("wg.handshake_consume_response");
    let keys = consume_response(&init, &my_sk, &resp.msg);
    m.end();
    ok &= keys.is_some();
    let (send, recv) = keys.unwrap_or(([0; 32], [0; 32]));
    ok &= send == resp.recv_key && recv == resp.send_key;
    if let Some(p) = dev.peers[0].as_mut() {
        p.curr.valid = true;
        p.curr.sending_key = send;
        p.curr.sending_valid = true;
        p.curr.receiving_key = recv;
        p.curr.receiving_valid = true;
    }

    m.begin("wg.transport_1400B_seal_open");
    let mut buf = [0u8; 1500];
    for (i, b) in buf.iter_mut().enumerate().take(1400) {
        *b = i as u8;
    }
    if let Some(p) = dev.peers[0].as_mut() {
        let n = seal(&mut p.curr, &mut buf, 1400);
        // loopback open with the SAME direction key: swap so the model exercises decrypt + replay window
        p.curr.receiving_key = p.curr.sending_key;
        ok &= open(&mut p.curr, &mut buf, n, 0);
        ok &= !open(&mut p.curr, &mut buf, n, 0); // replay rejected
    }
    m.end();
    (Wg { dev }, ok)
}

pub fn exercise(w: &mut Wg) -> bool {
    let mut buf = [0u8; 256];
    if let Some(p) = w.dev.peers[0].as_mut() {
        let n = seal(&mut p.curr, &mut buf, 100);
        p.curr.receiving_key = p.curr.sending_key;
        let c = p.curr.sending_counter - 1;
        return open(&mut p.curr, &mut buf, n, c);
    }
    false
}

pub fn print_sizes(m: &impl Meter) {
    m.size("sizeof(wg::Peer)      [C wireguard_peer slot: 904 B ADR0013, 1,096 B ml_admission.h:104]", core::mem::size_of::<Peer>());
    m.size("sizeof(wg::Keypair)", core::mem::size_of::<Keypair>());
    m.size("sizeof(wg::Handshake)", core::mem::size_of::<Handshake>());
    m.size("sizeof(wg::Device)    [C device with 8 inline slots 7,952 B; 228 B + pool ADR0013]", core::mem::size_of::<Device>());
}

#[allow(dead_code)]
fn _unused(_: Vec<u8>) {}
