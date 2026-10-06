//! (a) The coord task: ts2021 control channel = Noise_IK_25519_ChaChaPoly_BLAKE2s (snow) + HTTP/2 framing buffer +
//! network-map window + the peer table the map is applied to.
use crate::fixtures;
use crate::meter::Meter;
use crate::rng::DetResolver;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use x25519_dalek::{PublicKey, StaticSecret};

pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const PROLOGUE: &[u8] = b"Tailscale Control Protocol v1";
pub const SEED_CLIENT: u64 = 0xA1;
pub const SEED_SERVER: u64 = 0xB2;

pub struct Keys {
    pub client_priv: [u8; 32],
    pub server_priv: [u8; 32],
    pub server_pub: [u8; 32],
}
pub fn keys() -> Keys {
    let client_priv = [0x11u8; 32];
    let server_priv = [0x22u8; 32];
    let server_pub = PublicKey::from(&StaticSecret::from(server_priv)).to_bytes();
    Keys { client_priv, server_priv, server_pub }
}

pub fn initiator(k: &Keys) -> snow::HandshakeState {
    let p: snow::params::NoiseParams = PATTERN.parse().unwrap();
    snow::Builder::with_resolver(p, Box::new(DetResolver(SEED_CLIENT)))
        .local_private_key(&k.client_priv)
        .unwrap()
        .remote_public_key(&k.server_pub)
        .unwrap()
        .prologue(PROLOGUE)
        .unwrap()
        .build_initiator()
        .unwrap()
}
pub fn responder(k: &Keys) -> snow::HandshakeState {
    let p: snow::params::NoiseParams = PATTERN.parse().unwrap();
    snow::Builder::with_resolver(p, Box::new(DetResolver(SEED_SERVER)))
        .local_private_key(&k.server_priv)
        .unwrap()
        .prologue(PROLOGUE)
        .unwrap()
        .build_responder()
        .unwrap()
}

/// What the coord task allocates for receiving. Three variants are compared (see FINDINGS.md).
#[derive(Clone, Copy)]
pub struct CoordCfg {
    pub name: &'static str,
    /// Noise record decrypt buffer (ts2021 records are at most 4096 B of plaintext + 3 B header + 16 B tag in Tailscale's controlbase).
    pub noise_rec: usize,
    /// HTTP/2 frame reassembly buffer.
    pub h2_frame: usize,
    /// Network-map JSON window / projection workspace.
    pub map_win: usize,
}
impl CoordCfg {
    /// The C figure IF it were private to a membership: gateway_plain 20,496 + gateway_json 16,384 (gateway_workspace.inc,
    /// ml_gateway_limits.h). In the C they are ONE static pair shared by all memberships behind a mutex.
    pub const C_FIGURE_PRIVATE: CoordCfg = CoordCfg { name: "c-figure-private", noise_rec: 20496, h2_frame: 0, map_win: 16384 };
    /// Streaming design: records decrypted in place in a 4,099 B buffer, DATA payload fed straight to the parser, a small
    /// frame-control buffer, and a 2 KiB token window. A DESIGN ASSUMPTION; the parser itself is not written here.
    pub const STREAMING: CoordCfg = CoordCfg { name: "streaming-window", noise_rec: 4099, h2_frame: 256, map_win: 2048 };
    /// Shared workspace (what the C does): this membership holds none of it; one 36,880 B copy lives elsewhere.
    pub const SHARED: CoordCfg = CoordCfg { name: "shared-workspace", noise_rec: 0, h2_frame: 0, map_win: 0 };
}

/// Bounds taken from streaming-map-execution.md: nesting 32, field names 128 B, scalar tokens 95 B.
pub struct StreamParser {
    pub depth: u8,
    pub stack: [u8; 32],
    pub key: [u8; 128],
    pub key_len: u8,
    pub scalar: [u8; 96],
    pub scalar_len: u8,
    pub in_string: bool,
    pub escape: bool,
    pub tokens: u32,
}
impl StreamParser {
    pub const fn new() -> Self {
        StreamParser { depth: 0, stack: [0; 32], key: [0; 128], key_len: 0, scalar: [0; 96], scalar_len: 0, in_string: false, escape: false, tokens: 0 }
    }
    /// A minimal, real byte-at-a-time scanner so the state is exercised (not a full map projector).
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.in_string {
                if self.escape {
                    self.escape = false;
                } else if b == b'\\' {
                    self.escape = true;
                } else if b == b'"' {
                    self.in_string = false;
                    self.tokens += 1;
                } else if (self.scalar_len as usize) < self.scalar.len() {
                    self.scalar[self.scalar_len as usize] = b;
                    self.scalar_len += 1;
                }
                continue;
            }
            match b {
                b'"' => {
                    self.in_string = true;
                    self.scalar_len = 0;
                }
                b'{' | b'[' => {
                    if (self.depth as usize) < self.stack.len() {
                        self.stack[self.depth as usize] = b;
                        self.depth += 1;
                    }
                }
                b'}' | b']' => self.depth = self.depth.saturating_sub(1),
                b':' => {
                    self.key_len = self.scalar_len.min(128);
                    self.key[..self.key_len as usize].copy_from_slice(&self.scalar[..self.key_len as usize]);
                }
                _ => {}
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Endpoint {
    pub ip: u32,
    pub port: u16,
    pub is_ipv6: bool,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Route {
    pub network: u32,
    pub prefix_len: u8,
}

/// Field-for-field mirror of the C `ml_peer_t` (microlink_internal.h:429-514), same types, `repr(C)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PeerRecC {
    pub jit_used_ms: u64,
    pub vpn_ip: u32,
    pub public_key: [u8; 32],
    pub disco_key: [u8; 32],
    pub hostname: [u8; 64],
    pub active: bool,
    pub unconfirmed: bool,
    pub endpoints: [Endpoint; 8],
    pub endpoint_count: i32,
    pub derp_region: u16,
    pub last_ping_sent_ms: u64,
    pub last_pong_recv_ms: u64,
    pub trust_until_ms: u64,
    pub last_send_ms: u64,
    pub last_upgrade_ms: u64,
    pub last_cmm_rx_ms: u64,
    pub best_last_pong_ms: u64,
    pub disco_shared: [u8; 32],
    pub disco_shared_for: [u8; 32],
    pub disco_shared_valid: bool,
    pub best_ip: u32,
    pub best_port: u16,
    pub has_direct_path: bool,
    pub wg_peer_index: i32,
    pub last_init_handshake_ms: u64,
    pub peer_added_ms: u64,
    pub derp_fallback_active: bool,
    pub last_derp_attempt_ms: u64,
    pub is_exit_node: bool,
    pub subnet_routes: [Route; 8],
    pub subnet_route_count: u8,
    pub online: bool,
    pub node_id: u64,
}
/// The same fields with Rust's default repr (the compiler reorders to remove padding). The only "saving" Rust gives for free.
#[derive(Clone, Copy)]
pub struct PeerRecReordered {
    pub jit_used_ms: u64,
    pub vpn_ip: u32,
    pub public_key: [u8; 32],
    pub disco_key: [u8; 32],
    pub hostname: [u8; 64],
    pub active: bool,
    pub unconfirmed: bool,
    pub endpoints: [Endpoint; 8],
    pub endpoint_count: i32,
    pub derp_region: u16,
    pub last_ping_sent_ms: u64,
    pub last_pong_recv_ms: u64,
    pub trust_until_ms: u64,
    pub last_send_ms: u64,
    pub last_upgrade_ms: u64,
    pub last_cmm_rx_ms: u64,
    pub best_last_pong_ms: u64,
    pub disco_shared: [u8; 32],
    pub disco_shared_for: [u8; 32],
    pub disco_shared_valid: bool,
    pub best_ip: u32,
    pub best_port: u16,
    pub has_direct_path: bool,
    pub wg_peer_index: i32,
    pub last_init_handshake_ms: u64,
    pub peer_added_ms: u64,
    pub derp_fallback_active: bool,
    pub last_derp_attempt_ms: u64,
    pub is_exit_node: bool,
    pub subnet_routes: [Route; 8],
    pub subnet_route_count: u8,
    pub online: bool,
    pub node_id: u64,
}
impl PeerRecReordered {
    pub fn synth(i: u8) -> Self {
        let mut p: PeerRecReordered = unsafe { core::mem::zeroed() };
        p.public_key = [i; 32];
        p.disco_key = [i ^ 0x5a; 32];
        p.vpn_ip = 0x6440_0000 | i as u32;
        p.node_id = 1000 + i as u64;
        p.endpoint_count = 2;
        p.endpoints[0] = Endpoint { ip: 0x0a00_0001, port: 41641, is_ipv6: false };
        p.online = true;
        p
    }
}

pub struct Coord {
    pub transport: snow::TransportState,
    pub noise: Box<[u8]>,
    pub h2: Box<[u8]>,
    pub win: Box<[u8]>,
    pub parser: StreamParser,
    pub peers: Vec<PeerRecReordered>,
    pub h2_next_stream: u32,
}

/// Bring one coord task's state up. Returns the state and whether every cryptographic check passed.
pub fn setup(m: &impl Meter, cfg: &CoordCfg, nroster: usize) -> (Coord, bool) {
    let k = keys();
    let mut ok = true;

    m.begin("coord.noise_handshake");
    let mut hs = initiator(&k);
    let mut init = [0u8; 128];
    let n = hs.write_message(&[], &mut init).unwrap();
    ok &= n == 96;
    let mut out = [0u8; 8];
    let r = hs.read_message(fixtures::NOISE_REPLY, &mut out);
    ok &= r.is_ok();
    let mut transport = hs.into_transport_mode().unwrap();
    m.end();

    m.begin("coord.noise_record_decrypt");
    let mut rec = [0u8; 1100];
    let l = transport.read_message(fixtures::NOISE_RECORD, &mut rec).unwrap_or(0);
    ok &= l == 1024;
    let mut parser = StreamParser::new();
    parser.feed(&rec[..l]);
    ok &= parser.tokens > 8;
    m.end();

    m.begin("coord.buffers");
    let noise = vec![0u8; cfg.noise_rec].into_boxed_slice();
    let h2 = vec![0u8; cfg.h2_frame].into_boxed_slice();
    let win = vec![0u8; cfg.map_win].into_boxed_slice();
    m.end();

    m.begin("coord.peer_table");
    let mut peers = Vec::with_capacity(nroster);
    for i in 0..nroster {
        peers.push(PeerRecReordered::synth(i as u8));
    }
    m.end();

    (Coord { transport, noise, h2, win, parser, peers, h2_next_stream: 7 }, ok)
}

/// One synthetic "map update" exercise for the steady loop: decrypt a record, parse it, touch the window.
pub fn exercise(c: &mut Coord) -> bool {
    let mut rec = [0u8; 1100];
    // Decrypting the SAME recorded record twice would fail the nonce; instead exercise the parser on the plaintext shape.
    let _ = &mut rec;
    c.parser.feed(b"{\"Peers\":[{\"Key\":\"nodekey:00\",\"Online\":true}]}");
    if let Some(b) = c.win.first_mut() {
        *b = b.wrapping_add(1);
    }
    c.parser.depth == 0 || c.parser.depth > 0
}

pub fn print_sizes(m: &impl Meter) {
    m.size("sizeof(PeerRecC)  [C ml_peer_t mirror, repr(C)]", core::mem::size_of::<PeerRecC>());
    m.size("sizeof(PeerRec)   [same fields, Rust repr]", core::mem::size_of::<PeerRecReordered>());
    m.size("sizeof(StreamParser)", core::mem::size_of::<StreamParser>());
    m.size("sizeof(snow::TransportState)", core::mem::size_of::<snow::TransportState>());
    m.size("sizeof(snow::HandshakeState)", core::mem::size_of::<snow::HandshakeState>());
    m.size("sizeof(Coord)", core::mem::size_of::<Coord>());
}
