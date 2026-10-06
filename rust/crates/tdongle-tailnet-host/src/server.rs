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
}

impl GoServer {
    /// Spawn the binary and read its hello line.
    pub fn spawn(bin: &std::path::Path) -> Result<Self, String> {
        let mut child = Command::new(bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", bin.display()))?;
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut hello = String::new();
        stdout.read_line(&mut hello).map_err(|e| e.to_string())?;
        let v: serde_json::Value = serde_json::from_str(hello.trim()).map_err(|e| format!("hello {hello:?}: {e}"))?;
        let control = v["control"].as_str().ok_or("no control url")?;
        let control_addr = control.trim_start_matches("http://").trim_end_matches('/').to_string();
        let derp_port = v["derp_port"].as_u64().ok_or("no derp_port")? as u16;
        Ok(Self { child, stdin, stdout, control_addr, derp_port })
    }

    /// Send one command line and return the reply line.
    pub fn cmd(&mut self, line: &str) -> String {
        writeln!(self.stdin, "{line}").and_then(|_| self.stdin.flush()).expect("server stdin");
        let mut out = String::new();
        self.stdout.read_line(&mut out).expect("server stdout");
        out.trim().to_string()
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
