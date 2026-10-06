//! Host adapters for the control driver: tokio TCP, a wall clock, OS entropy, a recording map sink, and a wrapper for the Go interop server in
//! `rust/tools/tailnet-interop`.

use embedded_io_adapters::tokio_1::FromTokio;
use std::io::Read as _;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tdongle_tailnet_ctl::{Clock, Connect};
use tdongle_tailnet_map::types::{DerpMap, PeerAction, SelfNode};
use tdongle_tailnet_map::{MapEvent, MapSink, SinkError};
use tdongle_tailnet_types::{Entropy, Key32, Millis};
use tokio::net::TcpStream;

pub mod server;

/// Opens plain TCP connections to one address.
#[derive(Clone, Debug)]
pub struct TokioConnect {
    /// `host:port`.
    pub addr: String,
    /// Connections opened so far.
    pub opened: Arc<Mutex<u32>>,
}

impl TokioConnect {
    /// For `addr`.
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into(), opened: Arc::new(Mutex::new(0)) }
    }
}

impl Connect for TokioConnect {
    type Stream = FromTokio<TcpStream>;
    async fn connect(&mut self) -> Result<Self::Stream, ()> {
        let s = TcpStream::connect(&self.addr).await.map_err(|_| ())?;
        s.set_nodelay(true).ok();
        *self.opened.lock().unwrap() += 1;
        Ok(FromTokio::new(s))
    }
}

/// Monotonic clock plus tokio timeouts.
#[derive(Debug)]
pub struct TokioClock {
    start: Instant,
}

impl Default for TokioClock {
    fn default() -> Self {
        Self { start: Instant::now() }
    }
}

impl Clock for TokioClock {
    fn now(&self) -> Millis {
        self.start.elapsed().as_millis() as Millis
    }
    async fn timeout<F: std::future::Future>(&mut self, ms: u32, fut: F) -> Option<F::Output> {
        tokio::time::timeout(std::time::Duration::from_millis(ms as u64), fut).await.ok()
    }
}

/// Entropy from `/dev/urandom`.
#[derive(Debug, Default)]
pub struct OsRng;

impl Entropy for OsRng {
    fn fill(&mut self, buf: &mut [u8]) {
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(buf)).expect("/dev/urandom");
    }
}

/// A fresh random key (private).
pub fn random_key() -> Key32 {
    let mut k = [0u8; 32];
    OsRng.fill(&mut k);
    Key32(k)
}

/// What the recording sink saw.
#[derive(Clone, Debug, Default)]
pub struct Recorded {
    /// The last self node.
    pub self_node: Option<SelfNode>,
    /// The last DERP map.
    pub derp: Option<DerpMap>,
    /// `(action, group as u8, node key, vpn ip)` of every peer event, in order.
    pub peers: Vec<(PeerAction, u8, Key32, u32)>,
    /// Commits seen, and for each the section sizes `[Peers, Removed, Patch, Changed]`.
    pub commits: Vec<[u32; 4]>,
    /// Keepalive maps.
    pub keepalives: u32,
    /// Aborted maps.
    pub aborts: u32,
    /// Domain.
    pub domain: Option<String>,
}

/// A map sink that records what it is given; clones share state.
#[derive(Clone, Debug, Default)]
pub struct RecordingSink(pub Arc<Mutex<Recorded>>);

impl MapSink for RecordingSink {
    fn event(&mut self, event: MapEvent<'_>) -> Result<(), SinkError> {
        let mut r = self.0.lock().unwrap();
        match event {
            MapEvent::Peer(p) => r.peers.push((p.action, p.group as u8, p.node_key.clone(), p.vpn_ip)),
            MapEvent::SelfNode(n) => r.self_node = Some(n.clone()),
            MapEvent::Derp(d) => r.derp = Some(d.clone()),
            MapEvent::Domain(d) => r.domain = Some(d.to_string()),
            MapEvent::KeepAlive => r.keepalives += 1,
            MapEvent::Commit(s) => {
                let e = s.section_entries;
                r.commits.push([e[2], e[3], e[4], e[6]]);
            }
            MapEvent::Abort(_) => r.aborts += 1,
            _ => {}
        }
        Ok(())
    }
}
