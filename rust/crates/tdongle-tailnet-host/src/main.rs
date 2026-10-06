//! `ts2021-interop <control-host:port> [--auth-key K] [--pin HEX]`: runs the control driver against a server for 10 seconds and prints what happened.

use tdongle_tailnet_control::requests::Hostinfo;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_ctl::{NoEndpoints, NoGate, SessionConfig, Workspace, run_session};
use tdongle_tailnet_host::{OsRng, RecordingSink, TokioClock, TokioConnect, random_key};
use tdongle_tailnet_types::Key32;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(addr) = args.get(1) else {
        eprintln!("usage: ts2021-interop <host:port> [--auth-key K] [--pin HEX]");
        std::process::exit(2);
    };
    let auth_key = args.iter().position(|a| a == "--auth-key").and_then(|i| args.get(i + 1)).cloned().unwrap_or_default();
    let pin = args.iter().position(|a| a == "--pin").and_then(|i| args.get(i + 1)).and_then(|h| Key32::from_hex(h.as_bytes()));
    let (machine, node, disco) = (random_key(), random_key(), random_key());
    let disco_pub = x25519::public(&disco);
    let cfg = SessionConfig {
        host_header: addr,
        machine_priv: &machine,
        node_priv: &node,
        disco_pub: &disco_pub,
        hostinfo: Hostinfo::new("rust-ts2021", 900),
        auth_key: &auth_key,
        followup: "",
        control_pub: pin.as_ref(),
        home_derp: 900,
        timeouts: Default::default(),
    };
    let mut ws = Box::new(Workspace::new());
    let sink = RecordingSink::default();
    let mut s = sink.clone();
    let mut connect = TokioConnect::new(addr.clone());
    let mut clock = TokioClock::default();
    let (mut gate, mut eps, mut rng) = (NoGate, NoEndpoints, OsRng);
    let run = run_session(&mut connect, &mut clock, &cfg, &mut ws, &mut s, &mut gate, &mut eps, &mut rng);
    let end = tokio::time::timeout(std::time::Duration::from_secs(10), run).await;
    println!("end: {end:?}");
    println!("stats: {:?}", ws.stats);
    println!("recorded: {:?}", sink.0.lock().unwrap().self_node);
}
