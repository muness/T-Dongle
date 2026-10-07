//! A handle on the Go interop server (`rust/tools/tailnet-interop`): a real Tailscale `testcontrol` server and DERP server.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// Where the binary is looked for: `TAILNET_INTEROP_SERVER`, else `~/.cache/tdongle-tailnet-interop-server`; if absent and `go` exists it is built there from
/// `rust/tools/tailnet-interop`. `Err` carries the reason it is not available.
pub fn locate() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("TAILNET_INTEROP_SERVER") {
        let p = PathBuf::from(p);
        return if p.is_file() { Ok(p) } else { Err(format!("TAILNET_INTEROP_SERVER={} is not a file", p.display())) };
    }
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let p = PathBuf::from(home).join(".cache/tdongle-tailnet-interop-server");
    if p.is_file() {
        return Ok(p);
    }
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/tailnet-interop");
    if !src.join("main.go").is_file() {
        return Err(format!("no interop server binary at {} and no source at {}", p.display(), src.display()));
    }
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&p)
        .arg(".")
        .current_dir(&src)
        .status()
        .map_err(|e| format!("`go` is not available to build the server: {e}"))?;
    if status.success() && p.is_file() { Ok(p) } else { Err("`go build` of the interop server failed".into()) }
}

/// The running server.
#[derive(Debug)]
pub struct GoServer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// `host:port` of the control server.
    pub control_addr: String,
    /// DERP TLS port.
    pub derp_port: u16,
    /// The STUN responder's UDP port (the DERP node advertises it).
    pub stun_port: u16,
}

impl GoServer {
    /// Spawn the binary and read its hello line.
    pub fn spawn(bin: &std::path::Path) -> Result<Self, String> {
        Self::spawn_with(bin, &[])
    }

    /// Spawn with extra environment (`INTEROP_CONTROL_PORT`, `INTEROP_DERP_PORT`: fixed ports, so a restarted server is found at the same address).
    pub fn spawn_with(bin: &std::path::Path, env: &[(&str, String)]) -> Result<Self, String> {
        let mut cmd = Command::new(bin);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|e| format!("spawn {}: {e}", bin.display()))?;
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut hello = String::new();
        stdout.read_line(&mut hello).map_err(|e| e.to_string())?;
        let v: serde_json::Value = serde_json::from_str(hello.trim()).map_err(|e| format!("hello {hello:?}: {e}"))?;
        let control = v["control"].as_str().ok_or("no control url")?;
        let control_addr = control.trim_start_matches("http://").trim_end_matches('/').to_string();
        let derp_port = v["derp_port"].as_u64().ok_or("no derp_port")? as u16;
        let stun_port = v["stun_port"].as_u64().unwrap_or(0) as u16;
        Ok(Self { child, stdin, stdout, control_addr, derp_port, stun_port })
    }

    /// Send one command line and return the reply line.
    pub fn cmd(&mut self, line: &str) -> String {
        writeln!(self.stdin, "{line}").and_then(|_| self.stdin.flush()).expect("server stdin");
        let mut out = String::new();
        self.stdout.read_line(&mut out).expect("server stdout");
        out.trim().to_string()
    }

    /// Start a tsnet peer named `name`; returns its tailnet IPv4 and node key (`nodekey:...`).
    pub fn peer(&mut self, name: &str) -> Result<([u8; 4], String), String> {
        let r = self.cmd(&format!("peer {name}"));
        let mut it = r.split_whitespace();
        if it.next() != Some("PEER") {
            return Err(r);
        }
        let ip: std::net::Ipv4Addr = it.next().ok_or("no ip")?.parse().map_err(|e| format!("{e}"))?;
        Ok((ip.octets(), it.next().ok_or("no key")?.to_string()))
    }

    /// Close a peer (the control server then tells the others).
    pub fn peer_close(&mut self, name: &str) -> bool {
        self.cmd(&format!("peerclose {name}")) == "OK"
    }

    /// Queue a raw `tailcfg.MapResponse` (JSON) on a node's streaming map.
    pub fn rawmap(&mut self, nodekey: &str, json: &str) -> bool {
        self.cmd(&format!("rawmap {nodekey} {json}")) == "OK"
    }

    /// `(name, node id, node key)` of every node the control server knows.
    pub fn ids(&mut self) -> Vec<(String, u64, String)> {
        self.cmd("ids")
            .split_whitespace()
            .skip(1)
            .filter_map(|t| {
                let (name, rest) = t.split_once('=')?;
                let (id, key) = rest.split_once(':')?;
                Some((name.to_string(), id.parse().ok()?, key.to_string()))
            })
            .collect()
    }

    /// The home DERP region the control server has for a node (what it tells the node's peers).
    pub fn home_derp(&mut self, nodekey: &str) -> Option<u32> {
        self.cmd(&format!("homederp {nodekey}")).strip_prefix("HOME ")?.parse().ok()
    }

    /// The endpoints the control server has for a node.
    pub fn endpoints(&mut self, nodekey: &str) -> Vec<String> {
        let r = self.cmd(&format!("eps {nodekey}"));
        r.strip_prefix("EPS ").map(|e| e.split(',').filter(|x| !x.is_empty()).map(String::from).collect()).unwrap_or_default()
    }

    /// Node public keys the control server knows (`nodekey:...`).
    pub fn nodes(&mut self) -> Vec<String> {
        self.cmd("nodes").split_whitespace().skip(2).map(String::from).collect()
    }
}

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
