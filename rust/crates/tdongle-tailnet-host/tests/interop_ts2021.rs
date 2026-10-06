//! The control client against a REAL Tailscale control server (`tailscale.com/tstest/integration/testcontrol`, in `rust/tools/tailnet-interop`): the
//! ts2021 upgrade, Noise IK, HTTP/2, register, and the streaming map long poll, over plain HTTP as the device does.
//!
//! Skips (printing why) when the Go server binary is unavailable: set `TAILNET_INTEROP_SERVER`, or have `go` installed so it is built into
//! `~/.cache/tdongle-tailnet-interop-server`. Everything runs in one test function because the Go server is shared state (and takes a second to start).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tdongle_tailnet_control::requests::{ENDPOINT_LOCAL, Endpoint, EndpointAddr, Hostinfo};
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_ctl::{EndpointSource, NoGate, SessionConfig, SessionEnd, SessionStats, Stage, Workspace, fetch_control_key, run_session};
use tdongle_tailnet_host::server::{GoServer, locate};
use tdongle_tailnet_host::{OsRng, RecordingSink, TokioClock, TokioConnect, random_key};
use tdongle_tailnet_map::types::PeerAction;
use tdongle_tailnet_types::Key32;

fn wait_until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

struct SharedEndpoints(Arc<Mutex<Option<Vec<Endpoint>>>>);
impl EndpointSource for SharedEndpoints {
    fn poll_endpoints(&mut self, out: &mut [Endpoint]) -> Option<usize> {
        let v = self.0.lock().unwrap().take()?;
        out[..v.len()].copy_from_slice(&v);
        Some(v.len())
    }
}

/// A control client running on its own thread (its own current-thread tokio runtime).
struct Client {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<JoinHandle<(Option<SessionEnd>, SessionStats)>>,
    sink: RecordingSink,
    node_key: String,
    endpoints: Arc<Mutex<Option<Vec<Endpoint>>>>,
    done: Arc<AtomicBool>,
}

struct Opts {
    connect: String,
    host_header: String,
    auth_key: &'static str,
    pin: Option<Key32>,
    name: &'static str,
}

impl Client {
    fn start(o: Opts) -> Client {
        let (machine, node, disco) = (random_key(), random_key(), random_key());
        let node_key = format!("nodekey:{}", hex(x25519::public(&node).as_bytes()));
        let sink = RecordingSink::default();
        let endpoints = Arc::new(Mutex::new(None));
        let done = Arc::new(AtomicBool::new(false));
        let (stop, stop_rx) = tokio::sync::oneshot::channel();
        let (s2, e2, d2) = (sink.clone(), endpoints.clone(), done.clone());
        let join = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let disco_pub = x25519::public(&disco);
                let cfg = SessionConfig {
                    host_header: &o.host_header,
                    machine_priv: &machine,
                    node_priv: &node,
                    disco_pub: &disco_pub,
                    hostinfo: Hostinfo::new(o.name, 900),
                    auth_key: o.auth_key,
                    followup: "",
                    control_pub: o.pin.as_ref(),
                    home_derp: 900,
                    timeouts: Default::default(),
                };
                let mut ws = Box::new(Workspace::new());
                let (mut connect, mut clock, mut gate, mut eps, mut rng) =
                    (TokioConnect::new(o.connect), TokioClock::default(), NoGate, SharedEndpoints(e2), OsRng);
                let mut sink = s2;
                let end = tokio::select! {
                    e = run_session(&mut connect, &mut clock, &cfg, &mut ws, &mut sink, &mut gate, &mut eps, &mut rng) => Some(e),
                    _ = stop_rx => None,
                };
                d2.store(true, Ordering::SeqCst);
                (end, ws.stats)
            })
        });
        Client { stop: Some(stop), join: Some(join), sink, node_key, endpoints, done }
    }

    fn first_map(&self) -> bool {
        !self.sink.0.lock().unwrap().commits.is_empty()
    }

    /// Stop it (if still running) and return how it ended (`None` = stopped by us) and its counters.
    fn finish(mut self) -> (Option<SessionEnd>, SessionStats) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        self.join.take().unwrap().join().unwrap()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A TCP forwarder that can be cut.
struct Proxy {
    addr: String,
    cut: Arc<AtomicBool>,
}

impl Proxy {
    fn start(upstream: String) -> Proxy {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let cut = Arc::new(AtomicBool::new(false));
        let c2 = cut.clone();
        thread::spawn(move || {
            for client in l.incoming().flatten() {
                let Ok(server) = TcpStream::connect(&upstream) else { continue };
                let (c, s) = (client.try_clone().unwrap(), server.try_clone().unwrap());
                let (cut_a, cut_b) = (c2.clone(), c2.clone());
                for (mut from, mut to, cut) in [(client, server, cut_a), (s, c, cut_b)] {
                    thread::spawn(move || {
                        from.set_read_timeout(Some(Duration::from_millis(100))).ok();
                        let mut buf = [0u8; 4096];
                        loop {
                            if cut.load(Ordering::SeqCst) {
                                let _ = from.shutdown(Shutdown::Both);
                                let _ = to.shutdown(Shutdown::Both);
                                return;
                            }
                            match from.read(&mut buf) {
                                Ok(0) => {
                                    let _ = to.shutdown(Shutdown::Write);
                                    return;
                                }
                                Ok(n) => {
                                    if to.write_all(&buf[..n]).is_err() {
                                        return;
                                    }
                                }
                                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                                Err(_) => return,
                            }
                        }
                    });
                }
            }
        });
        Proxy { addr, cut }
    }
}

fn fetch_key(addr: &str) -> Key32 {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (mut c, mut k, mut buf) = (TokioConnect::new(addr), TokioClock::default(), vec![0u8; 2048]);
        fetch_control_key(&mut c, &mut k, addr, &mut buf, 5000).await.expect("GET /key")
    })
}

fn derp_port_of(rec: &tdongle_tailnet_host::Recorded) -> Option<u16> {
    let d = rec.derp.as_ref()?;
    let r = d.regions[..d.count as usize].iter().find(|r| r.region_id == 900)?;
    Some(r.nodes[0].derp_port)
}

#[test]
fn ts2021_against_the_real_control_server() {
    let bin = match locate() {
        Ok(b) => b,
        Err(why) => {
            println!("SKIPPED interop_ts2021: {why}");
            return;
        }
    };
    let mut srv = GoServer::spawn(&bin).expect("start the Go interop server");
    let addr = srv.control_addr.clone();
    println!("interop server: control http://{addr}, DERP port {}", srv.derp_port);

    // ---- control key: GET /key (the KeyCache path), then pinned -----------------------------------------------------------------------------
    let key = fetch_key(&addr);
    assert!(!key.is_zero());
    println!("GET /key?v=131 -> publicKey mkey:{}", &hex(key.as_bytes())[..16]);
    let mut cache = tdongle_tailnet_control::http::KeyCache::new();
    assert_eq!(cache.plan(false, false, false), tdongle_tailnet_control::http::KeyPlan::FetchPlain);
    cache.store_fetched(key.clone(), false);
    assert_eq!(cache.plan(false, false, false), tdongle_tailnet_control::http::KeyPlan::Cached);

    // ---- node A: key fetched by the driver, no auth key --------------------------------------------------------------------------------------
    let a = Client::start(Opts { connect: addr.clone(), host_header: addr.clone(), auth_key: "", pin: None, name: "rust-a" });
    wait_until("node A's first map", 20, || a.first_map());
    assert_eq!(srv.cmd(&format!("await {}", a.node_key)), "AWAITED", "the control server shows A's streaming map request open");
    assert!(srv.nodes().contains(&a.node_key), "node A registered");
    assert_eq!(srv.cmd("inmap"), "INMAP 1");
    {
        let r = a.sink.0.lock().unwrap();
        let me = r.self_node.as_ref().expect("SelfNode");
        let ip = me.vpn_ip.expect("a 100.x address");
        assert_eq!(ip >> 24, 100, "Tailscale CGNAT address, got {ip:#x}");
        assert_eq!(derp_port_of(&r), Some(srv.derp_port), "DERP region 900 points at the local DERP server");
        let d = r.derp.as_ref().unwrap();
        assert_eq!(d.regions[0].nodes[0].ipv4, Some([127, 0, 0, 1]));
        assert_eq!(me.cap, 131);
        println!(
            "SelfNode {:?} ip {}.{}.{}.{} DERP 900 -> 127.0.0.1:{}",
            me.name.as_ref().map(|n| n.as_str()),
            ip >> 24,
            ip >> 16 & 255,
            ip >> 8 & 255,
            ip & 255,
            srv.derp_port
        );
    }

    // ---- `fake` adds a node that appears in full maps (testcontrol does not push it to running streams) ---------------------------------------
    assert_eq!(srv.cmd("fake"), "OK");

    // ---- a lite endpoint update on a new stream, accepted by the server -------------------------------------------------------------------------
    *a.endpoints.lock().unwrap() = Some(vec![Endpoint { addr: EndpointAddr::V4 { ip: [192, 168, 7, 7], port: 41641 }, kind: ENDPOINT_LOCAL }]);
    wait_until("the endpoint update to be sent", 5, || a.endpoints.lock().unwrap().is_none());
    thread::sleep(Duration::from_millis(1500));
    assert_eq!(srv.cmd("inmap"), "INMAP 1", "the long poll survives the update");

    // ---- node B: a second node, with an auth key, pinned control key ---------------------------------------------------------------------------
    let b = Client::start(Opts {
        connect: addr.clone(),
        host_header: addr.clone(),
        auth_key: "tskey-auth-kTESTtest-0123456789",
        pin: Some(key.clone()),
        name: "rust-b",
    });
    wait_until("node B's first map", 20, || b.first_map());
    assert_eq!(srv.cmd(&format!("await {}", b.node_key)), "AWAITED");
    let nodes = srv.nodes();
    assert!(nodes.contains(&a.node_key) && nodes.contains(&b.node_key), "two nodes registered: {nodes:?}");
    let (ip_a, ip_b) =
        (a.sink.0.lock().unwrap().self_node.as_ref().unwrap().vpn_ip.unwrap(), b.sink.0.lock().unwrap().self_node.as_ref().unwrap().vpn_ip.unwrap());
    assert_ne!(ip_a, ip_b, "distinct tailnet addresses");
    // testcontrol adds a node to the others' maps when it sends its lite (non-streaming) update, as a real client does with its endpoints.
    *b.endpoints.lock().unwrap() = Some(vec![Endpoint { addr: EndpointAddr::V4 { ip: [10, 9, 8, 7], port: 4242 }, kind: ENDPOINT_LOCAL }]);
    wait_until("A to learn about B", 15, || a.sink.0.lock().unwrap().peers.iter().any(|p| p.3 == ip_b));
    {
        // testcontrol always answers with the full list: A's later maps carry authoritative `Peers` (section 2), never a PeersChanged delta.
        let r = a.sink.0.lock().unwrap();
        let (action, group, _, _) = r.peers.iter().find(|p| p.3 == ip_b).unwrap().clone();
        println!("A: B arrived as action {action:?} in section {group} (2 = full Peers list), commit {} of A's stream", r.commits.len());
        assert_eq!((action, group), (PeerAction::Add, 2));
        assert!(r.commits.len() >= 2);
    }
    // B's first map is the full list: A and the fake node, authoritative (section 2).
    wait_until("B to learn about A", 5, || b.sink.0.lock().unwrap().peers.iter().any(|p| p.3 == ip_a));
    {
        let r = b.sink.0.lock().unwrap();
        assert!(
            r.peers.iter().filter(|p| p.1 == 2).count() >= 2,
            "B's full list holds A and the fake node: {:?}",
            r.peers.iter().map(|p| (p.1, p.3)).collect::<Vec<_>>()
        );
    }
    println!("second node registered with an auth key; both see each other");

    // ---- keepalive / ping traffic on an established stream ---------------------------------------------------------------------------------------
    thread::sleep(Duration::from_secs(6));

    // ---- server drops the connection mid-map ------------------------------------------------------------------------------------------------
    let proxy = Proxy::start(addr.clone());
    let c = Client::start(Opts { connect: proxy.addr.clone(), host_header: addr.clone(), auth_key: "", pin: Some(key.clone()), name: "rust-c" });
    wait_until("node C's first map through the proxy", 20, || c.first_map());
    proxy.cut.store(true, Ordering::SeqCst);
    wait_until("node C to notice", 10, || c.done.load(Ordering::SeqCst));
    let (end_c, stats_c) = c.finish();
    let end_c = end_c.expect("session ended by itself");
    println!("connection cut mid-map -> {end_c:?} (noise_error {}, map_error {})", end_c.noise_error(), end_c.map_error());
    assert!(matches!(end_c, SessionEnd::Io { stage: Stage::Map, .. }), "{end_c:?}");
    assert_eq!(end_c.noise_error(), 5);
    assert!(stats_c.first_map_applied && stats_c.maps >= 1);

    // ---- wrong control key fails cleanly at the Noise stage -------------------------------------------------------------------------------------
    let wrong = x25519::public(&random_key());
    let w = Client::start(Opts { connect: addr.clone(), host_header: addr.clone(), auth_key: "", pin: Some(wrong), name: "rust-w" });
    wait_until("the wrong-key session to end", 15, || w.done.load(Ordering::SeqCst));
    let (end_w, stats_w) = w.finish();
    let end_w = end_w.expect("ended by itself");
    println!("wrong control key -> {end_w:?} (noise_error {})", end_w.noise_error());
    assert!(
        matches!(end_w, SessionEnd::Upgrade(_) | SessionEnd::Handshake(_) | SessionEnd::Io { stage: Stage::Upgrade | Stage::Handshake, .. }),
        "must fail before any register: {end_w:?}"
    );
    assert_eq!(stats_w.maps, 0);
    assert!(!srv.nodes().iter().any(|n| n.is_empty()));

    // ---- summary ------------------------------------------------------------------------------------------------------------------------------
    let (end_a, stats_a) = a.finish();
    assert!(end_a.is_none(), "node A was still healthy when stopped: {end_a:?}");
    let (end_b, stats_b) = b.finish();
    assert!(end_b.is_none(), "node B was still healthy when stopped: {end_b:?}");
    assert!(stats_a.endpoint_updates == 1 && stats_a.pings_sent >= 1 && stats_a.ping_acks >= 1, "{stats_a:?}");
    assert_eq!(stats_a.h2.fatal.get(), 0);
    assert_eq!(stats_a.noise.auth_failures.get(), 0);
    for (n, s) in [("A", &stats_a), ("B", &stats_b)] {
        println!(
            "node {n}: maps {} (keepalives {}, peer events {}), map bytes {}, register response {} B (MachineAuthorized {}), wire in/out {}/{} B, noise records sealed/opened {}/{}, h2 frames {} data {} B, pings {}/{}, endpoint updates {}",
            s.maps,
            s.keepalives,
            s.peer_events,
            s.map_bytes,
            s.register_bytes,
            s.machine_authorized,
            s.bytes_in,
            s.bytes_out,
            s.noise.sealed.get(),
            s.noise.opened.get(),
            s.h2.frames_in.get(),
            s.h2.data_bytes_in.get(),
            s.ping_acks,
            s.pings_sent,
            s.endpoint_updates
        );
    }
    println!(
        "workspace {} B, noise session {} B, h2 session {} B, projector {} B",
        tdongle_tailnet_ctl::sizes::WORKSPACE,
        tdongle_tailnet_ctl::sizes::NOISE_SESSION,
        tdongle_tailnet_ctl::sizes::H2_SESSION,
        tdongle_tailnet_ctl::sizes::PROJECTOR
    );
}
