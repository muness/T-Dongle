//! The end-to-end harness: the real runtime on tokio sockets, an in-memory platform and storage, a model heap, and a fake USB host (smoltcp), against the
//! real Go control server, DERP server and tsnet peers of `rust/tools/tailnet-interop`.
//!
//! Threads: the **runtime thread** runs `tdongle_tailnet_runtime::run` on a current-thread tokio runtime (everything it owns is single-threaded, as on the
//! device); the **host thread** runs the smoltcp host; the **test thread** drives both through blocking calls and calls `TailnetApi` from its own thread,
//! as the firmware's HTTP task does.

use crate::fakewifi::FakeWifi;
use crate::mem::{MemPlatform, MemStorage, ModelHeap};
use crate::server::{GoServer, locate};
use crate::tokio_net::{NetControl, TokioNet};
use crate::usbhost::{HostHandle, spawn_host};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tdongle_tailnet_engine::{RamDirectory, TxFate};
use tdongle_tailnet_fw::{MemberAction, Reply, TailnetApi};
use tdongle_tailnet_runtime::shared::{Config, Shared};
use tdongle_tailnet_runtime::wifi::WifiRaw;

/// The directory of the harness's engines.
pub type Dir = RamDirectory<3, 16, 32>;
/// The shared state of the harness's runtime.
pub type Sh = Shared<CriticalSectionRawMutex, MemPlatform, MemStorage, Dir>;

/// Locate (or build) the Go server binary, or say why not (the tests then skip with that message).
pub fn go_binary() -> Result<std::path::PathBuf, String> {
    locate()
}

/// Spawn a Go server (control + DERP) with a fresh tailnet.
pub fn spawn_go() -> Result<GoServer, String> {
    GoServer::spawn(&go_binary()?)
}

/// Poll `f` every 50 ms until it is true or `secs` pass; panics with `what` on timeout.
pub fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out ({secs}s) waiting for {what}");
}

/// Like [`wait_until`] but returns whether it succeeded.
pub fn try_wait(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// What to build a gateway with.
#[derive(Clone, Debug)]
pub struct GatewayOpts {
    /// `host:port` of the control server the memberships talk to.
    pub control: String,
    /// The model heap's free bytes at boot.
    pub heap_free: usize,
    /// The model heap's largest free block at boot.
    pub heap_largest: usize,
    /// Share this storage (a "reboot" test passes the old one).
    pub storage: Option<MemStorage>,
    /// The station address.
    pub local_ip: [u8; 4],
    /// The resolver the lease advertises (and where the DNS forwarder's datagrams go: `dns_redirect`).
    pub dns: Option<[u8; 4]>,
    /// Control server address per membership slot (slot 0 first), when memberships talk to different servers.
    pub control_routes: Vec<String>,
}

impl GatewayOpts {
    /// Defaults: a 106 KB heap like the board's after boot, 24,576 B largest block, loopback.
    pub fn new(control: &str) -> Self {
        GatewayOpts {
            control: control.to_string(),
            heap_free: 106_000,
            heap_largest: 24_576,
            storage: None,
            local_ip: [127, 0, 0, 1],
            dns: None,
            control_routes: Vec::new(),
        }
    }
}

/// A running gateway.
pub struct Gateway {
    /// The runtime's shared state.
    pub sh: &'static Sh,
    /// Network switches.
    pub net: Arc<NetControl>,
    /// The fake USB host.
    pub host: HostHandle,
    /// NVS.
    pub storage: MemStorage,
    /// The model heap.
    pub heap: Arc<ModelHeap>,
    /// The fake Wi-Fi data path (NAT + a reflecting "Internet").
    pub wifi: Arc<FakeWifi>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gateway")
    }
}

impl Gateway {
    /// Build and start a gateway.
    pub fn start(opts: GatewayOpts) -> Gateway {
        let heap = Arc::new(ModelHeap::new(opts.heap_free, opts.heap_largest));
        let platform = MemPlatform::new(heap.clone());
        let storage = opts.storage.clone().unwrap_or_default();
        let (host_ip, port) = opts.control.rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap())).unwrap();
        let cfg = Config {
            control_host: Box::leak(host_ip.into_boxed_str()),
            control_port: port,
            control_pub: None,
            udp_port_base: 0,
            usb_mac: None,
            firmware: "host-harness",
            timeouts: tdongle_tailnet_ctl::Timeouts { io_ms: 5_000, first_map_ms: 20_000, idle_ms: 20_000, lease_stall_ms: 5_000 },
            charge_static_bytes: false,
        };
        let sh: &'static Sh = Box::leak(Box::new(Shared::new(cfg, platform, storage.clone(), Dir::new())));
        // the heap the runtime draws from: everything it holds is in the pool now (socket windows, TLS records, the control workspace of a negotiation), so the
        // model heap is the pool's `in_use`; the elastic floor must still hold at the minimum
        heap.set_model(move || sh.pool.in_use());
        // the largest free block shrinks by the control workspace of a negotiation in flight (the one big block the model has), not by the pool's many small ones
        heap.set_block_model(move || sh.stats.neg_now.load(Ordering::SeqCst) as usize * core::mem::size_of::<tdongle_tailnet_ctl::Bulk>());
        let ctl = Arc::new(NetControl::default());
        for (slot, a) in opts.control_routes.iter().enumerate() {
            ctl.route_control(slot, a.parse().expect("control route"));
        }
        let mut net = TokioNet::new(ctl.clone(), opts.local_ip);
        net.dns = opts.dns;
        let wifi = Arc::new(FakeWifi::new(u32::from_be_bytes(opts.local_ip)));
        let wifi_run = wifi.clone();
        let (usb, host) = spawn_host();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let join = std::thread::Builder::new()
            .name("tailnet-runtime".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                rt.block_on(async move {
                    tokio::select! {
                        _ = tdongle_tailnet_runtime::run(sh, net, usb, ArcWifi(wifi_run)) => {}
                        _ = stop_rx => {}
                    }
                });
            })
            .unwrap();
        Gateway { sh, net: ctl, host, storage, heap, wifi, stop: Some(stop_tx), join: Some(join) }
    }

    /// `TailnetApi::member_action`, from the calling thread.
    pub fn action(&self, a: MemberAction) -> Reply {
        TailnetApi::member_action(self.sh, &a)
    }

    /// Add a membership; returns its id (the registry's newest, enabled).
    pub fn add(&self, label: &str, key: &str) -> u32 {
        let r = self.action(MemberAction::add(label.as_bytes(), key.as_bytes()));
        assert_eq!(r.error, None, "add {label}");
        self.sh.registry.lock(|c| c.borrow().reg.iter().find(|m| m.label() == label.as_bytes()).map(|m| m.id).expect("added"))
    }

    /// Engine counters for a membership.
    pub fn member_status(&self, id: u32) -> Option<tdongle_tailnet_engine::MemberStatus> {
        let snap = self.sh.snapshot();
        snap.members.iter().flatten().find(|m| m.id == id).copied()
    }

    /// Packets sent through DERP / directly, all memberships.
    pub fn sent(&self) -> (u32, u32) {
        self.sh.with_engine(|e, _| (e.stats().tx_count(TxFate::SentDerp), e.stats().tx_count(TxFate::SentDirect)))
    }

    /// The membership is routing: the engine published it as ready and a netmap has been applied.
    pub fn is_ready(&self, id: u32) -> bool {
        self.member_status(id).is_some_and(|m| m.ready && m.derp_ready)
    }

    /// The identities check of the engine (every packet ended in exactly one counted outcome).
    pub fn check_engine(&self) {
        self.sh.with_engine(|e, _| e.check_identities().expect("engine identities"));
    }

    /// Everything the runtime holds for memberships is back to what it was before the first one started: no slot in use, the engine empty, the token free,
    /// the ledger at zero with no underflow, the queues empty, nothing but the settings namespace in storage. Returns what is not, one per line.
    pub fn leaks(&self) -> Vec<String> {
        use tdongle_tailnet_admission::ledger::Owner;
        let sh = self.sh;
        let mut v = Vec::new();
        for (i, s) in sh.slots.iter().enumerate() {
            let st = s.status();
            if st.state != tdongle_tailnet_runtime::shared::SlotState::Free || st.id != 0 {
                v.push(format!("slot {i} not free: {:?} id {}", st.state, st.id));
            }
            if s.alive.load(Ordering::SeqCst) != 0 {
                v.push(format!("slot {i} tasks still alive: {:#b}", s.alive.load(Ordering::SeqCst)));
            }
            if s.udp_q.len_bytes() != 0 || s.derp_q.len_bytes() != 0 {
                v.push(format!("slot {i} queues not empty"));
            }
        }
        sh.with_engine(|e, _| {
            if e.member_count() != 0 {
                v.push(format!("engine still has {} memberships", e.member_count()));
            }
            if e.pool().used() != 0 {
                v.push(format!("WireGuard pool still has {} slots", e.pool().used()));
            }
            if e.jit_store().used_blocks() != 0 {
                v.push("parked-packet arena not empty".into());
            }
        });
        let neg = sh.token.status(sh.now());
        if neg.holder != 0 || neg.waiting != 0 {
            v.push(format!("negotiation token held by {} with {} waiting", neg.holder, neg.waiting));
        }
        for o in Owner::ALL {
            let st = sh.ledger.owner(o);
            if st.live != 0 {
                v.push(format!("ledger owner {} still holds {} bytes", o.name(), st.live));
            }
        }
        if sh.ledger.underflows() != 0 {
            v.push(format!("ledger underflows {}", sh.ledger.underflows()));
        }
        if sh.ready_count.load(Ordering::SeqCst) != 0 {
            v.push("ready_count not zero".into());
        }
        let extra: Vec<String> = self.storage.namespaces().into_iter().filter(|n| n != "tn_settings").collect();
        if !extra.is_empty() {
            v.push(format!("identity namespaces left in storage: {extra:?}"));
        }
        v
    }

    /// A multi-line description of the queues, the engine's counters and the relay links, for failure messages.
    pub fn dump(&self) -> String {
        use tdongle_tailnet_engine::{HostFate, RxFate};
        let mut o = String::new();
        let sh = self.sh;
        o += &format!("host_q {:?}\n", sh.host_q.stats());
        for (i, s) in sh.slots.iter().enumerate() {
            let st = s.status();
            if st.state == tdongle_tailnet_runtime::shared::SlotState::Free {
                continue;
            }
            o += &format!(
                "slot {i} id {} state {:?} udp_q {:?} derp_q {:?}\n  derp {:?} frames_rx {} frames_tx {} tx_drop(not_ready {} no_space {} over_budget {}) udp tx {} rx {} err {}\n",
                st.id,
                st.state,
                s.udp_q.stats(),
                s.derp_q.stats(),
                st.derp_state,
                st.derp.frames_rx.get(),
                st.derp.frames_tx.get(),
                st.derp.tx_drop_not_ready.get(),
                st.derp.tx_drop_no_space.get(),
                st.derp.tx_drop_over_budget.get(),
                st.udp_tx,
                st.udp_rx,
                st.udp_tx_err
            );
        }
        sh.with_engine(|e, _| {
            let st = e.stats();
            o += "engine tx:";
            for f in TxFate::ALL {
                if st.tx_count(f) != 0 {
                    o += &format!(" {}={}", f.name(), st.tx_count(f));
                }
            }
            o += "\nengine rx:";
            for f in RxFate::ALL {
                if st.rx_count(f) != 0 {
                    o += &format!(" {}={}", f.name(), st.rx_count(f));
                }
            }
            o += "\nengine host:";
            for f in HostFate::ALL {
                if st.host_count(f) != 0 {
                    o += &format!(" {}={}", f.name(), st.host_count(f));
                }
            }
            o += "\n";
        });
        let mut route = String::new();
        let _ = tdongle_tailnet_fw::TailnetApi::serial_command(sh, "route", &mut route);
        // only the non-zero counters
        o += "router:";
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(route.trim())
            && let Some(m) = v.as_object()
        {
            for (k, v) in m {
                if let Some(n) = v.as_u64().filter(|n| *n != 0 && k != "schema") {
                    o += &format!(" {k}={n}");
                }
            }
        }
        o += "\n";
        o
    }

    /// Stop the runtime and wait for its thread.
    pub fn stop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `FakeWifi` shared between the runtime (which owns its `WifiRaw`) and the test (which reads its counters).
struct ArcWifi(Arc<FakeWifi>);

impl WifiRaw for ArcWifi {
    fn nat_outbound(&self, now: u64, p: &mut [u8]) -> tdongle_tailnet_usbnet::napt::Verdict {
        self.0.nat_outbound(now, p)
    }
    fn try_send(&self, l3: &[u8]) -> bool {
        self.0.try_send(l3)
    }
    async fn next_to_host(&self, buf: &mut [u8]) -> usize {
        self.0.next_to_host(buf).await
    }
    fn try_next_to_host(&self, buf: &mut [u8]) -> Option<usize> {
        self.0.try_next_to_host(buf)
    }
    fn nat_tick(&self, now: u64) -> usize {
        self.0.nat_tick(now)
    }
    fn stack_config_changed(&self) {
        self.0.stack_config_changed()
    }
    fn new_association(&self) {
        self.0.new_association()
    }
}
