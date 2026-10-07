//! Interoperability with a real wireguard-go `device` (the reference implementation, golang.zx2c4.com/wireguard).
//!
//! Every scenario is a conversation between this crate and a Go device with one peer (this crate), driven over a line protocol (`> command` to Go,
//! `< reply` from Go). The conversation is **recorded** in `tests/fixtures/wireguard_go_<scenario>.txt` and **replayed** in a plain `cargo test`: this crate's
//! side is fully deterministic (seeded entropy, fixed clock and indices), so the replay asserts that every datagram this crate emits is byte-identical to the
//! one that wireguard-go accepted when the fixture was recorded, and feeds the recorded wireguard-go datagrams (initiations, responses, transport, cookie
//! replies) to this crate. Set `WG_GO_ORACLE=<path to the oracle test binary>` to talk to a live wireguard-go instead (and `WG_GO_RECORD=1` to rewrite the
//! fixtures); the helper's source is not part of the repository (it is a few hundred lines of Go in `device/oracle_test.go` of a wireguard-go checkout:
//! `CreateMessageInitiation`, `ConsumeMessageInitiation`, `CreateMessageResponse`, `ConsumeMessageResponse`, `BeginSymmetricSession`, the keypairs' AEADs and
//! the cookie checker/generator).

mod common;
use common::*;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_wg::cookie::{Screen, screen};
use tdongle_tailnet_wg::msg::{CookieReply, Initiation, transport_len};
use tdongle_tailnet_wg::*;

const GO_PRIV: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = 0x40 + i as u8;
        i += 1;
    }
    k
};
const RUST_PRIV: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = 0xa0 ^ (i as u8 * 3);
        i += 1;
    }
    k
};
const PSK: [u8; 32] = [0x77; 32];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

struct Live {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

struct Oracle {
    name: String,
    live: Option<Live>,
    replay: Vec<(String, String)>,
    pos: usize,
    record: Vec<(String, String)>,
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(format!("wireguard_go_{name}.txt"))
}

impl Oracle {
    fn open(name: &str, psk: bool) -> Oracle {
        let rust_pub = Identity::new(&Key32(RUST_PRIV)).unwrap().public().clone();
        if let Ok(bin) = std::env::var("WG_GO_ORACLE") {
            let mut cmd = Command::new(bin);
            cmd.args(["-test.run", "TestOracleServer"]).env("WG_ORACLE", "1").env("WG_PRIV", hex(&GO_PRIV)).env("WG_PEER_PUB", hex(&rust_pub.0));
            if psk {
                cmd.env("WG_PSK", hex(&PSK));
            }
            let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("spawn the wireguard-go oracle");
            let stdin = child.stdin.take().unwrap();
            let stdout = BufReader::new(child.stdout.take().unwrap());
            Oracle { name: name.into(), live: Some(Live { child, stdin, stdout }), replay: vec![], pos: 0, record: vec![] }
        } else {
            let text = std::fs::read_to_string(fixture_path(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}; record it with WG_GO_ORACLE"));
            let mut replay = vec![];
            let mut lines = text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty());
            while let Some(c) = lines.next() {
                let r = lines.next().expect("odd fixture");
                replay.push((c.strip_prefix("> ").expect("> line").to_string(), r.strip_prefix("< ").expect("< line").to_string()));
            }
            Oracle { name: name.into(), live: None, replay, pos: 0, record: vec![] }
        }
    }

    /// Ask wireguard-go; `Ok(payload)` for `ok ...`, `Err(text)` for `err ...`.
    fn call(&mut self, cmd: String) -> Result<String, String> {
        let reply = if let Some(l) = &mut self.live {
            writeln!(l.stdin, "{cmd}").unwrap();
            l.stdin.flush().unwrap();
            let mut line = String::new();
            l.stdout.read_line(&mut line).unwrap();
            let line = line.trim_end().to_string();
            self.record.push((cmd, line.clone()));
            line
        } else {
            let (c, r) = self.replay.get(self.pos).unwrap_or_else(|| panic!("{}: transcript ended at step {}", self.name, self.pos)).clone();
            assert_eq!(
                c, cmd,
                "{}: step {}: this crate emitted something different from what wireguard-go accepted when the fixture was recorded",
                self.name, self.pos
            );
            self.pos += 1;
            r
        };
        match reply.strip_prefix("ok") {
            Some(rest) => Ok(rest.trim().to_string()),
            None => Err(reply),
        }
    }

    fn finish(mut self) {
        if let Some(mut l) = self.live.take() {
            drop(l.stdin);
            let _ = l.child.wait();
            if std::env::var("WG_GO_RECORD").is_ok() {
                let mut s = format!(
                    "# transcript with wireguard-go (golang.zx2c4.com/wireguard device package); scenario {}\n# lines alternate: '> command to the Go device' / '< its reply'\n",
                    self.name
                );
                for (c, r) in &self.record {
                    s.push_str(&format!("> {c}\n< {r}\n"));
                }
                std::fs::write(fixture_path(&self.name), s).unwrap();
            }
        } else {
            assert_eq!(self.pos, self.replay.len(), "{}: the test did not consume the whole transcript", self.name);
        }
    }
}

fn pad(p: &[u8]) -> Vec<u8> {
    let mut v = p.to_vec();
    v.resize((p.len() + 15) & !15, 0);
    v
}

fn rust_side(psk: bool) -> Side {
    let go_pub = Identity::new(&Key32(GO_PRIV)).unwrap().public().clone();
    Side::with_keys(&Key32(RUST_PRIV), &go_pub, psk.then(|| Key32(PSK)), 0x7000, 0xfeed_0000_0000_0001)
}

fn go_pub_check(o: &mut Oracle, s: &Side) {
    // the key derivation (clamping, X25519 base point) agrees with wireguard-go's
    let reply = o.call("pub".into()).unwrap();
    assert_eq!(reply, hex(&s.cold.public().0));
}

fn rust_to_go(o: &mut Oracle, rust: &mut Side, mut now: u64) {
    // every padding remainder, a keepalive, a replay and a tampered datagram
    for n in [0usize, 1, 15, 16, 17, 100, 1399, 1400] {
        now += 10;
        let payload: Vec<u8> = (0..n).map(|i| (i * 13 + n) as u8).collect();
        let d = rust.send(&payload, now).unwrap();
        assert_eq!(d.len(), transport_len(n));
        let pt = o.call(format!("open {}", hex(&d))).unwrap_or_else(|e| panic!("wireguard-go refused our datagram (len {n}): {e}"));
        assert_eq!(unhex(&pt), pad(&payload), "wireguard-go decrypted something else (len {n})");
        assert!(o.call(format!("open {}", hex(&d))).is_err(), "wireguard-go refuses the replay");
    }
    now += 10;
    let d = rust.send(b"tamper me", now).unwrap();
    let mut bad = d.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(o.call(format!("open {}", hex(&bad))).is_err());
    assert!(o.call(format!("open {}", hex(&d))).is_ok());
}

/// Go seals, we open; returns whether one of them confirmed our (responder) session.
fn go_to_rust(o: &mut Oracle, rust: &mut Side, mut now: u64) -> bool {
    let mut confirmed = false;
    for (ctr, n) in [0usize, 1, 15, 16, 17, 100, 1400].into_iter().enumerate() {
        now += 10;
        let payload: Vec<u8> = (0..n).map(|i| (i * 7 + 3 * n) as u8).collect();
        let dg = unhex(&o.call(format!("seal {ctr} {}", hex(&pad(&payload)))).unwrap());
        assert_eq!(dg.len(), transport_len(n));
        match rust.rx(&dg, now) {
            Event::Keepalive => assert_eq!(n, 0),
            Event::Confirmed(p) => {
                assert!(!confirmed, "confirmed twice");
                confirmed = true;
                assert_eq!(p, pad(&payload));
            }
            Event::Payload(p) => assert_eq!(p, pad(&payload), "len {n}"),
            e => panic!("len {n}: {e:?}"),
        }
        assert!(matches!(rust.rx(&dg, now), Event::Dropped(Dropped::ReplayDuplicate)));
    }
    confirmed
}

fn rust_initiates(name: &str, psk: bool) {
    let mut o = Oracle::open(name, psk);
    let mut r = rust_side(psk);
    go_pub_check(&mut o, &r);
    let init = r.initiate(1_000_000).unwrap();
    let resp = unhex(&o.call(format!("consume_init {}", hex(&init))).expect("wireguard-go accepted our initiation"));
    assert_eq!(resp.len(), 92);
    assert_eq!(r.rx(&resp, 1_000_100), Event::Established, "we accepted wireguard-go's response");
    rust_to_go(&mut o, &mut r, 1_000_200);
    assert!(!go_to_rust(&mut o, &mut r, 1_000_400), "the initiator's session was never unconfirmed");
    o.finish();
}

fn go_initiates(name: &str, psk: bool) {
    let mut o = Oracle::open(name, psk);
    let mut r = rust_side(psk);
    go_pub_check(&mut o, &r);
    let init = unhex(&o.call("init".into()).unwrap());
    assert_eq!(init.len(), 148);
    let Event::Reply(resp) = r.rx(&init, 2_000_000) else { panic!("we refused wireguard-go's initiation") };
    o.call(format!("consume_response {}", hex(&resp))).expect("wireguard-go accepted our response");
    // the responder (us) cannot send before the first datagram from Go
    assert_eq!(r.send(b"x", 2_000_001), Err(TxError::NoSession));
    // Go sends its confirming keepalive first
    assert!(go_to_rust(&mut o, &mut r, 2_000_100), "the first datagram from Go confirms our responder session");
    rust_to_go(&mut o, &mut r, 2_000_400);
    o.finish();
}

#[test]
fn rust_initiates_without_psk() {
    rust_initiates("rust_initiates", false);
}
#[test]
fn rust_initiates_with_psk() {
    rust_initiates("rust_initiates_psk", true);
}
#[test]
fn go_initiates_without_psk() {
    go_initiates("go_initiates", false);
}
#[test]
fn go_initiates_with_psk() {
    go_initiates("go_initiates_psk", true);
}

#[test]
fn psk_mismatch_is_refused_by_both() {
    // wireguard-go has no psk, we have one: it must not complete, either way round
    let mut o = Oracle::open("psk_mismatch", false);
    let mut r = rust_side(true);
    let init = r.initiate(5_000_000).unwrap();
    // go answers (the initiation does not depend on the psk)...
    let resp = unhex(&o.call(format!("consume_init {}", hex(&init))).unwrap());
    // ... but its response cannot authenticate under our psk
    assert_eq!(r.rx(&resp, 5_000_100), Event::Dropped(Dropped::HsAuthResponse));
    // and the other way: go initiates, we (with psk) respond, go cannot open our response
    let init = unhex(&o.call("init".into()).unwrap());
    let Event::Reply(resp) = r.rx(&init, 5_000_200) else { panic!() };
    assert!(o.call(format!("consume_response {}", hex(&resp))).is_err());
    o.finish();
}

#[test]
fn cookies_interoperate() {
    let mut o = Oracle::open("cookies", false);
    let mut r = rust_side(false);
    let src = r.src.clone();

    // 1. we initiate; wireguard-go is "under load" and answers with a cookie reply (its CookieChecker.CreateReply); we store it
    let init1 = r.initiate(10_000_000).unwrap();
    assert_eq!(o.call(format!("check_mac2 {} {}", hex(&init1), hex(&src))).unwrap(), "false");
    let cr = unhex(&o.call(format!("cookie_reply {} {}", hex(&init1), hex(&src))).unwrap());
    assert_eq!(cr.len(), 64);
    assert_eq!(r.rx(&cr, 10_000_100), Event::CookieStored, "we decrypted wireguard-go's cookie reply");
    // 2. our next initiation carries a mac2 that wireguard-go's CheckMAC2 accepts for our source address, and rejects for another
    let init2 = r.initiate(10_006_000).unwrap();
    assert_eq!(o.call(format!("check_mac2 {} {}", hex(&init2), hex(&src))).unwrap(), "true", "our mac2 verifies under wireguard-go's cookie");
    assert_eq!(o.call(format!("check_mac2 {} {}", hex(&init2), hex(&[1, 2, 3, 4, 0, 80]))).unwrap(), "false");
    o.call(format!("consume_init {}", hex(&init2))).expect("and the initiation is accepted");

    // 3. the other way: wireguard-go initiates, we are under load and answer with a cookie reply; it consumes it and its next initiation passes our mac2 check
    let g1 = unhex(&o.call("init".into()).unwrap());
    let mut p = g1.clone();
    let go_src = vec![198, 51, 100, 9, 0x1f, 0x90];
    let Event::Reply(our_cr) = r.on_packet(&mut p, 10_007_000, true, &go_src) else { panic!("expected a cookie reply") };
    assert_eq!(o.call(format!("consume_cookie {}", hex(&our_cr))).unwrap(), "true", "wireguard-go decrypted our cookie reply");
    let g2 = unhex(&o.call("init".into()).unwrap());
    assert_ne!(&g2[132..], &[0u8; 16], "wireguard-go now sends mac2");
    // the screen under load passes it (mac1 and mac2 both verify)
    let s = screen(&r.id, &mut r.checker, &g2, &go_src, true, 10_007_500, &mut r.rng);
    assert_eq!(s, Screen::Pass);
    // from another address it does not
    assert!(matches!(screen(&r.id, &mut r.checker, &g2, &[9, 9, 9, 9, 0, 1], true, 10_007_600, &mut r.rng), Screen::CookieReply(_)));
    let m = Initiation::parse(&g2).unwrap();
    assert!(r.id.consume_initiation_stage1(&m).is_ok());
    let _ = CookieReply::parse(&our_cr).unwrap();
    o.finish();
}
