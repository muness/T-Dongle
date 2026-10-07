//! (d) DISCO and STUN tasks: smoltcp UDP sockets (the socket layer embassy-net wraps), the RX queues, the probe table and
//! the per-peer DISCO shared secret. NaCl box (XSalsa20-Poly1305) is stood in for by XChaCha20-Poly1305: same 32 B key, same
//! 24 B nonce, same 16 B tag, so state and buffer sizes are identical; CPU cost differs and is not modelled.
use crate::meter::Meter;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use smoltcp::socket::{tcp, udp};

pub const MTU_SLOT: usize = 1536; // "1.5 KB" slots (ML_MAX_PACKET_SIZE 1500 + header, rounded)
pub const DISCO_Q: usize = 8; // ML_DISCO_RX_QUEUE_DEPTH (microlink_internal.h:145)
pub const STUN_Q: usize = 4; // ML_STUN_RX_QUEUE_DEPTH (microlink_internal.h:157)

#[derive(Clone, Copy)]
pub struct Probe {
    pub txid: [u8; 12],
    pub dest_ip: u32,
    pub dest_port: u16,
    pub sent_ms: u64,
    pub peer_index: i32,
    pub active: bool,
}

/// How a bounded RX queue holds its datagrams.
pub enum Queue {
    /// Inline slots: DEPTH x 1,536 B reserved for the life of the membership (the simple embassy `Channel<_, Packet, N>` shape).
    Inline { slots: Box<[[u8; MTU_SLOT]]>, lens: Vec<u16>, head: usize, count: usize },
    /// Pointer slots, payload heap-allocated on arrival and freed on pop (what the C does, bounded in bytes elsewhere).
    Pointer { slots: Vec<Option<Box<[u8]>>>, head: usize, count: usize },
}
impl Queue {
    pub fn inline(depth: usize) -> Self {
        Queue::Inline { slots: vec![[0u8; MTU_SLOT]; depth].into_boxed_slice(), lens: vec![0; depth], head: 0, count: 0 }
    }
    pub fn pointer(depth: usize) -> Self {
        let mut v = Vec::with_capacity(depth);
        v.resize_with(depth, || None);
        Queue::Pointer { slots: v, head: 0, count: 0 }
    }
    pub fn push(&mut self, data: &[u8]) -> bool {
        match self {
            Queue::Inline { slots, lens, head, count } => {
                if *count == slots.len() {
                    return false;
                }
                let i = (*head + *count) % slots.len();
                slots[i][..data.len()].copy_from_slice(data);
                lens[i] = data.len() as u16;
                *count += 1;
                true
            }
            Queue::Pointer { slots, head, count } => {
                if *count == slots.len() {
                    return false;
                }
                let i = (*head + *count) % slots.len();
                slots[i] = Some(data.to_vec().into_boxed_slice());
                *count += 1;
                true
            }
        }
    }
    pub fn pop(&mut self) -> Option<usize> {
        match self {
            Queue::Inline { slots, lens, head, count } => {
                if *count == 0 {
                    return None;
                }
                let l = lens[*head] as usize;
                *head = (*head + 1) % slots.len();
                *count -= 1;
                Some(l)
            }
            Queue::Pointer { slots, head, count } => {
                if *count == 0 {
                    return None;
                }
                let l = slots[*head].take().map(|b| b.len()).unwrap_or(0);
                *head = (*head + 1) % slots.len();
                *count -= 1;
                Some(l)
            }
        }
    }
}

pub struct UdpSock {
    pub s: udp::Socket<'static>,
}
pub fn udp_socket(rx_pkts: usize, rx_bytes: usize, tx_pkts: usize, tx_bytes: usize) -> udp::Socket<'static> {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; rx_pkts], vec![0u8; rx_bytes]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; tx_pkts], vec![0u8; tx_bytes]);
    udp::Socket::new(rx, tx)
}
pub fn tcp_socket(rx: usize, tx: usize) -> tcp::Socket<'static> {
    tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; rx]), tcp::SocketBuffer::new(vec![0u8; tx]))
}

pub struct Disco {
    /// DISCO UDP socket (v4), the two STUN sockets (v4, v6), as in the C (three UDP sockets per membership).
    pub disco_sock: udp::Socket<'static>,
    pub stun4: udp::Socket<'static>,
    pub stun6: udp::Socket<'static>,
    /// control (coord) and DERP TCP sockets; rx = CONFIG_LWIP_TCP_WND_DEFAULT 8,640 (sdkconfig:1641) so the window matches the C.
    pub coord_tcp: tcp::Socket<'static>,
    pub derp_tcp: tcp::Socket<'static>,
    pub disco_q: Queue,
    pub stun_q: Queue,
    pub probes: [Probe; 32],
    pub shared: [[u8; 32]; 8],
    pub key: Key,
}

/// Socket buffer sizes (smoltcp sockets own fixed buffers; lwIP allocates pbufs on demand up to the window).
#[derive(Clone, Copy)]
pub struct NetCfg {
    pub coord_rx: usize,
    pub coord_tx: usize,
    pub derp_rx: usize,
    pub derp_tx: usize,
    /// DISCO UDP socket: datagram slots (1,536 B each) in the rx / tx buffers.
    pub disco_rx_pkts: usize,
    pub disco_tx_pkts: usize,
}
impl NetCfg {
    /// Windows equal to the C's CONFIG_LWIP_TCP_WND_DEFAULT 8,640 (sdkconfig:1641) on receive; tx 2,048 control / 4,096 DERP.
    pub const C_WINDOW: NetCfg = NetCfg { coord_rx: 8640, coord_tx: 2048, derp_rx: 8640, derp_tx: 4096, disco_rx_pkts: 4, disco_tx_pkts: 2 };
    /// Minimum-viable sensitivity point (NOT a throughput-validated size): 2 MSS rx / 1 MSS tx control, 3 MSS / 2 MSS DERP (MSS 1,440), DISCO 2 rx / 1 tx datagram slots.
    pub const SMALL: NetCfg = NetCfg { coord_rx: 2880, coord_tx: 1440, derp_rx: 4320, derp_tx: 2880, disco_rx_pkts: 2, disco_tx_pkts: 1 };
}

/// `inline_queues` = reserve DEPTH x 1,536 B per queue; false = pointer slots.
pub fn setup(m: &impl Meter, inline_queues: bool, peers: usize, tcp: &NetCfg) -> (Disco, bool) {
    let mut ok = true;
    m.begin("net.sockets(3 udp + 2 tcp, smoltcp)");
    let disco_sock = udp_socket(tcp.disco_rx_pkts, tcp.disco_rx_pkts * MTU_SLOT, tcp.disco_tx_pkts, tcp.disco_tx_pkts * MTU_SLOT);
    let stun4 = udp_socket(2, 2 * 576, 1, 128);
    let stun6 = udp_socket(2, 2 * 576, 1, 128);
    let coord_tcp = tcp_socket(tcp.coord_rx, tcp.coord_tx);
    let derp_tcp = tcp_socket(tcp.derp_rx, tcp.derp_tx);
    m.end();

    m.begin(if inline_queues { "disco.queues(inline 8+4 x 1536)" } else { "disco.queues(pointer 8+4)" });
    let (disco_q, stun_q) = if inline_queues { (Queue::inline(DISCO_Q), Queue::inline(STUN_Q)) } else { (Queue::pointer(DISCO_Q), Queue::pointer(STUN_Q)) };
    m.end();

    m.begin("disco.state(probes32+shared8)");
    let probes = [Probe { txid: [0; 12], dest_ip: 0, dest_port: 0, sent_ms: 0, peer_index: -1, active: false }; 32];
    let mut shared = [[0u8; 32]; 8];
    for i in 0..peers.min(8) {
        shared[i] = [i as u8 ^ 0xA5; 32];
    }
    m.end();

    let mut d = Disco { disco_sock, stun4, stun6, coord_tcp, derp_tcp, disco_q, stun_q, probes, shared, key: *Key::from_slice(&[7u8; 32]) };

    m.begin("disco.exercise(3 queued pkts + seal/open)");
    let pkt = [0xD5u8; 1200];
    ok &= d.disco_q.push(&pkt) && d.disco_q.push(&pkt) && d.disco_q.push(&pkt);
    ok &= d.disco_q.pop() == Some(1200);
    ok &= d.disco_q.pop() == Some(1200);
    ok &= d.disco_q.pop() == Some(1200);
    let c = XChaCha20Poly1305::new(&d.key);
    let nonce = XNonce::from_slice(&[9u8; 24]);
    let mut buf = [1u8; 100 + 16];
    let tag = c.encrypt_inout_detached(nonce, &[], (&mut buf[..100]).into()).unwrap();
    ok &= c.decrypt_inout_detached(nonce, &[], (&mut buf[..100]).into(), &tag).is_ok();
    m.end();
    (d, ok)
}

pub fn exercise(d: &mut Disco) -> bool {
    let pkt = [0xD5u8; 200];
    let a = d.stun_q.push(&pkt);
    let b = d.stun_q.pop() == Some(200);
    a && b
}

pub fn print_sizes(m: &impl Meter) {
    m.size("sizeof(udp::Socket)", core::mem::size_of::<udp::Socket<'static>>());
    m.size("sizeof(tcp::Socket)", core::mem::size_of::<tcp::Socket<'static>>());
    m.size("sizeof(Probe) x32", core::mem::size_of::<Probe>() * 32);
    m.size("sizeof(Disco)", core::mem::size_of::<Disco>());
}
