//! Golden traces from the real C: each `tests/golden/*.scn` scenario is replayed against the Rust UI and the output must be byte-identical to the
//! `*.trace` that `tools/gen_golden.sh` produced by running the real `menu.c`, `led.c`, `core.c`, `traffic.c`, `ui_settings.c`, `setup_boot.c` and the
//! verbatim `device_ui.inc` poll (`tools/ui_trace.c`). Regenerate with `tools/gen_golden.sh`; the C commit is in `tests/golden/C_REF`.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;
use tdongle_traffic::Reading;
use tdongle_ui::health;
use tdongle_ui::led::{self, LedInputs, LedMode};
use tdongle_ui::settings::Settings;
use tdongle_ui::setup_boot::{Session, SetupRequest};
use tdongle_ui::ui::{Content, Inputs, Snapshot, Ui};

#[derive(Default)]
struct World {
    setup_active: bool,
    wifi_ready: bool,
    state_ok: bool,
    lock_busy: bool,
    session: Session,
    ap_name: String,
    display: Settings,
    saved: u8,
    names: [String; 8],
    // fw
    bridge: bool,
    wifi: bool,
    recovery: bool,
    saved_wifi: bool,
    installing: bool,
    usb: bool,
    usb_configured: bool,
    usb_suspended: bool,
    active_slot: u32,
    tn_saved: u32,
    enabled: u32,
    ready: u32,
    login: u32,
    failed: u32,
    usb_resets: u32,
    heap_free: u32,
    heap_min: u32,
    heap_largest: u32,
    reset_reason: u32,
    active_name: String,
    ssid: String,
    link_connected: bool,
    link_rssi_valid: bool,
    link_rssi: i32,
    connects: u32,
    last_connect_ms: u32,
    last_reason: u32,
    counters: (u32, u32, u32, u32), // down_bytes, up_bytes, down_frames, up_frames
    tally: health::Counters,
}

struct Rng(u32);
impl Rng {
    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

struct Run {
    w: World,
    ui: Option<Ui>,
    now: u64,
    presses: Vec<(u64, u64)>,
    down_override: Option<bool>,
    last_status: String,
    out: String,
}

impl Run {
    fn set(&mut self, k: &str, v: &str) {
        let n: u64 = v.trim().parse().unwrap_or(0);
        let w = &mut self.w;
        match k {
            "saved" => w.saved = n as u8,
            "setup" => w.setup_active = n != 0,
            "wifi_ready" => w.wifi_ready = n != 0,
            "online" => {}
            "state_ok" => w.state_ok = n != 0,
            "bridge" => w.bridge = n != 0,
            "wifi" => w.wifi = n != 0,
            "recovery" => w.recovery = n != 0,
            "saved_wifi" => w.saved_wifi = n != 0,
            "installing" => w.installing = n != 0,
            "usb" => w.usb = n != 0,
            "usb_configured" => w.usb_configured = n != 0,
            "usb_suspended" => w.usb_suspended = n != 0,
            "active_slot" => w.active_slot = n as u32,
            "tn_saved" => w.tn_saved = n as u32,
            "enabled" => w.enabled = n as u32,
            "ready" => w.ready = n as u32,
            "login" => w.login = n as u32,
            "failed" => w.failed = n as u32,
            "usb_resets" => w.usb_resets = n as u32,
            "heap_free" => w.heap_free = n as u32,
            "heap_min" => w.heap_min = n as u32,
            "heap_largest" => w.heap_largest = n as u32,
            "reset_reason" => w.reset_reason = n as u32,
            "link_connected" => w.link_connected = n != 0,
            "link_rssi_valid" => w.link_rssi_valid = n != 0,
            "link_rssi" => w.link_rssi = v.trim().parse().unwrap(),
            "connects" => w.connects = n as u32,
            "last_connect_ms" => w.last_connect_ms = n as u32,
            "last_reason" => w.last_reason = n as u32,
            "brightness" => w.display.brightness = n as u8,
            "rotation" => w.display.rotation = n as u8,
            "dim_seconds" => w.display.dim_seconds = n as u16,
            "lock_busy" => w.lock_busy = n != 0,
            "active_name" => w.active_name = v.to_string(),
            "ssid" => w.ssid = v.to_string(),
            "ap_name" => w.ap_name = v.to_string(),
            "boots" => w.tally.boots = n as u32,
            "watchdogs" => w.tally.watchdogs = n as u32,
            "panics" => w.tally.panics = n as u32,
            k if k.len() == 5 && k.starts_with("name") => w.names[(k.as_bytes()[4] - b'1') as usize] = v.to_string(),
            _ => panic!("unknown key {k}"),
        }
    }

    fn poll(&mut self) {
        let now = self.now;
        let down = self.down_override.unwrap_or_else(|| self.presses.iter().any(|&(a, b)| now >= a && now < b));
        let w = &self.w;
        let names = w.names.clone();
        let (saved, busy) = (w.saved as u32, w.lock_busy);
        let lookup = move |slot: u32| -> Option<&'static str> {
            let _ = (&names, saved, busy, slot);
            None
        };
        let _ = lookup;
        let name_fn = |slot: u32| -> Option<&str> {
            if busy || !(1..=8).contains(&slot) {
                return None;
            }
            Some(if slot <= saved { w.names[(slot - 1) as usize].as_str() } else { "" })
        };
        let snapshot = Snapshot {
            bridge: w.bridge,
            wifi: w.wifi,
            recovery: w.recovery,
            saved_wifi: w.saved_wifi,
            active_slot: w.active_slot,
            active_name: &w.active_name,
            ssid: &w.ssid,
            saved: w.tn_saved,
            enabled: w.enabled,
            ready: w.ready,
            login: w.login,
            failed: w.failed,
            installing: w.installing,
            usb: w.usb,
            usb_configured: w.usb_configured,
            usb_suspended: w.usb_suspended,
            link_connected: w.link_connected,
            link_rssi_valid: w.link_rssi_valid,
            link_rssi: w.link_rssi,
            setup_ap_name: &w.ap_name,
            uptime_s: (now / 1000) as u32,
            connects: w.connects,
            last_connect_ms: w.last_connect_ms,
            last_reason: w.last_reason,
            usb_resets: w.usb_resets,
            heap_free: w.heap_free,
            heap_min: w.heap_min,
            heap_largest: w.heap_largest,
            reset_reason: w.reset_reason,
            boots: w.tally.boots,
            watchdogs: w.tally.watchdogs,
            panics: w.tally.panics,
        };
        let input = Inputs {
            button_down: down,
            setup_active: w.setup_active,
            setup_session: w.session,
            wifi_ready: w.wifi_ready,
            saved_count: w.saved,
            display: w.display,
            snapshot: if w.state_ok { Some(snapshot) } else { None },
            traffic: Reading { down_bytes: w.counters.0, up_bytes: w.counters.1, down_frames: w.counters.2, up_frames: w.counters.3 },
            network_name: &name_fn,
        };
        let ui = self.ui.as_mut().unwrap();
        let a = ui.tick(now, &input);
        let out = &mut self.out;
        if a.restart == Some(SetupRequest::Leave) {
            writeln!(out, "t={now} restart leave").unwrap();
        }
        if let Some(d) = a.draw {
            writeln!(out, "t={now} apply backlight={} rotation={}", d.backlight_percent, d.rotation).unwrap();
            match d.content {
                Content::Menu { rows, attention } => {
                    write!(out, "t={now} show rows attention={}", attention as u8).unwrap();
                    for r in rows {
                        write!(out, " |{}", r.as_str()).unwrap();
                    }
                    writeln!(out).unwrap();
                }
                Content::Status(s) => {
                    let mut l = String::new();
                    let b = |x: bool| x as u8;
                    write!(
                        l,
                        "bridge={} wifi={} saved_wifi={} recovery={} starting={} installing={} usb={} usb_configured={} usb_suspended={} saved={} enabled={} ready={} login={} failed={} \
                         page={} rssi_valid={} rssi={} ssid=[{}] setup={} ap_ssid=[{}] setup_seconds_left={} down_kbps={} up_kbps={} down_bytes={} up_bytes={} down_frames={} up_frames={} bars=",
                        b(s.bridge), b(s.wifi), b(s.saved_wifi), b(s.recovery), b(s.starting), b(s.installing), b(s.usb), b(s.usb_configured), b(s.usb_suspended), s.saved,
                        s.enabled, s.ready, s.login, s.failed, s.page, b(s.rssi_valid), s.rssi, s.ssid, b(s.setup), s.ap_ssid, s.setup_seconds_left, s.down_kbps, s.up_kbps,
                        s.down_bytes, s.up_bytes, s.down_frames, s.up_frames
                    )
                    .unwrap();
                    for x in s.bars {
                        write!(l, "{x:02x}").unwrap();
                    }
                    write!(
                        l,
                        " uptime_s={} wifi_up_s={} connects={} last_reason={} usb_resets={} heap_free={} heap_min={} heap_largest={} reset_reason={} boots={} watchdogs={} panics={} \
                         health_view={} active_slot={} active_name=[{}]",
                        s.uptime_s, s.wifi_up_s, s.connects, s.last_reason, s.usb_resets, s.heap_free, s.heap_min, s.heap_largest, s.reset_reason, s.boots, s.watchdogs,
                        s.panics, s.health_view, s.active_slot, s.active_name
                    )
                    .unwrap();
                    if l == self.last_status {
                        writeln!(out, "t={now} show status same").unwrap();
                    } else {
                        writeln!(out, "t={now} show status {l}").unwrap();
                    }
                    self.last_status = l;
                }
            }
        }
        if let Some(l) = a.led {
            let hex: String = l.frame.iter().map(|b| format!("{b:02x}")).collect();
            writeln!(out, "t={now} led {hex}").unwrap();
        }
        if let Some(c) = ui.take_command() {
            writeln!(out, "t={now} cmd {c}").unwrap();
        }
    }

    fn fuzz(&mut self, seed: u32, n: u32) {
        let mut rng = Rng(if seed == 0 { 1 } else { seed });
        let mut next_toggle = self.now;
        let mut down = false;
        for _ in 0..n {
            self.now += 10 + (rng.next() % 30) as u64;
            if self.now >= next_toggle {
                down = !down;
                let a = rng.next();
                let b = rng.next();
                let dur = if down {
                    if a % 4 == 0 { 1600 + b % 900 } else { 20 + b % 80 }
                } else if a % 8 == 0 {
                    12000
                } else {
                    40 + b % 800
                };
                next_toggle = self.now + dur as u64;
            }
            let r = rng.next();
            if r % 48 == 0 {
                let k = rng.next() % 12;
                let v = rng.next();
                self.mutate(k, v);
            }
            let a = rng.next();
            let b = rng.next();
            let c = rng.next();
            if c % 4 == 0 {
                self.w.counters.0 = self.w.counters.0.wrapping_add(a % 3000);
                self.w.counters.2 += 1;
                self.w.counters.1 = self.w.counters.1.wrapping_add(b % 800);
                self.w.counters.3 += 1;
            }
            self.down_override = Some(down);
            self.poll();
        }
        self.down_override = None;
    }

    fn mutate(&mut self, k: u32, v: u32) {
        const REASONS: [u32; 5] = [0, 8, 15, 201, 202];
        const DIMS: [u16; 3] = [10, 20, 60];
        let now = self.now as u32;
        let w = &mut self.w;
        match k {
            0 => w.saved = (v % 9) as u8,
            1 => {
                if w.setup_active {
                    w.setup_active = false;
                    w.session = Session::inactive();
                } else {
                    w.setup_active = true;
                    w.session = Session::start(now);
                }
            }
            2 => w.state_ok = v % 8 != 0,
            3 => w.wifi = v & 1 != 0,
            4 => w.usb = v & 1 != 0,
            5 => w.recovery = v % 8 == 0,
            6 => w.bridge = v & 1 != 0,
            7 => {
                w.ready = v % 3;
                w.failed = (v >> 4) % 2;
                w.login = (v >> 8) % 2;
            }
            8 => w.last_reason = REASONS[(v % 5) as usize],
            9 => w.display.dim_seconds = DIMS[(v % 3) as usize],
            10 => w.saved_wifi = v % 8 != 0,
            _ => w.wifi_ready = v % 4 != 0,
        }
    }
}

fn run_scenario(text: &str) -> String {
    let mut r = Run {
        w: World { state_ok: true, bridge: true, ap_name: "TDongle-AB0CF9".into(), display: Settings::default(), ..World::default() },
        ui: None,
        now: 0,
        presses: vec![],
        down_override: None,
        last_status: String::new(),
        out: String::new(),
    };
    for (i, n) in r.w.names.iter_mut().enumerate() {
        *n = format!("Net{}", i + 1);
    }
    for line in text.lines() {
        let line = line.trim_end();
        let mut it = line.split_whitespace();
        let Some(cmd) = it.next() else { continue };
        if cmd.starts_with('#') {
            continue;
        }
        let num = |s: Option<&str>| s.unwrap().parse::<u64>().unwrap();
        match cmd {
            "start" => {
                r.now = num(it.next());
                r.ui = Some(Ui::new(r.now));
            }
            "press" => {
                let (a, b) = (num(it.next()), num(it.next()));
                r.presses.push((a, b));
            }
            "set" => {
                let k = it.next().unwrap();
                let rest = line.splitn(3, char::is_whitespace).nth(2).unwrap_or("");
                // the C reads the value to the end of the line after one separator
                let v = line.trim_start().strip_prefix("set").unwrap().trim_start().strip_prefix(k).unwrap().trim_start();
                let _ = rest;
                r.set(k, v);
            }
            "traffic" => {
                let (db, ub, df, uf) = (num(it.next()) as u32, num(it.next()) as u32, num(it.next()) as u32, num(it.next()) as u32);
                if df > 0 {
                    r.w.counters.0 = r.w.counters.0.wrapping_add(db);
                    r.w.counters.2 = r.w.counters.2.wrapping_add(df);
                }
                if uf > 0 {
                    r.w.counters.1 = r.w.counters.1.wrapping_add(ub);
                    r.w.counters.3 = r.w.counters.3.wrapping_add(uf);
                }
            }
            "setup_start" => {
                r.w.setup_active = true;
                r.w.session = Session::start(r.now as u32);
            }
            "setup_stop" => {
                r.w.setup_active = false;
                r.w.session = Session::inactive();
            }
            "tick" => {
                let (from, to, step) = (num(it.next()), num(it.next()), num(it.next()));
                let mut t = from;
                while t <= to {
                    r.now = t;
                    r.poll();
                    t += step;
                }
            }
            "fuzz" => {
                let (seed, n) = (num(it.next()) as u32, num(it.next()) as u32);
                r.fuzz(seed, n);
            }
            _ => panic!("unknown command {cmd}"),
        }
    }
    r.out
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

#[test]
fn scenarios_match_the_c_traces() {
    let mut names: Vec<_> = fs::read_dir(dir()).unwrap().filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "scn")).collect();
    names.sort();
    assert!(names.len() >= 12, "scenarios missing: {names:?}");
    for scn in names {
        let want = fs::read_to_string(scn.with_extension("trace")).unwrap();
        let got = run_scenario(&fs::read_to_string(&scn).unwrap());
        if got != want {
            let (g, w): (Vec<_>, Vec<_>) = (got.lines().collect(), want.lines().collect());
            let i = g.iter().zip(&w).position(|(a, b)| a != b).unwrap_or(g.len().min(w.len()));
            panic!(
                "{}: first difference at trace line {} (rust {} lines, C {} lines)\n  C   : {}\n  rust: {}",
                scn.display(),
                i + 1,
                g.len(),
                w.len(),
                w.get(i).unwrap_or(&"<end>"),
                g.get(i).unwrap_or(&"<end>")
            );
        }
    }
}

#[test]
fn led_sweep_matches_the_c_trace() {
    let want = fs::read_to_string(dir().join("led_sweep.trace")).unwrap();
    let names = ["JOIN", "SETUP", "UP", "FAIL", "ATTENTION", "LOGIN"];
    let modes = [LedMode::Join, LedMode::Setup, LedMode::Up, LedMode::Fail, LedMode::Attention, LedMode::Login];
    let mut out = String::new();
    for (m, mode) in modes.iter().enumerate() {
        for since in 0..3 {
            let s0: u32 = [500, 0xffff_ff00, 123_456_789][since];
            let mut d = 0u32;
            while d < 6000 {
                let now = s0.wrapping_add(d);
                let c = led::color(*mode, now, s0);
                let f = led::apa102_frame(c);
                let hex: String = f.iter().map(|b| format!("{b:02x}")).collect();
                writeln!(out, "{} since={} now={} rgb={},{},{} frame={}", names[m], s0, now, c.r, c.g, c.b, hex).unwrap();
                d += 37;
            }
        }
    }
    for bits in 0..1u32 << 10 {
        let b = |i: u32| (bits >> i) & 1 != 0;
        let i = LedInputs {
            setup: b(0),
            no_network: b(1),
            associated: b(2),
            usb_ready: b(3),
            recovery: b(4),
            tailnet: b(5),
            tailnet_ready: b(6) as u32,
            tailnet_failed: b(7) as u32,
            tailnet_login: b(8) as u32,
            last_reason: if b(9) { 201 } else { 8 },
        };
        let idx = modes.iter().position(|m| *m == led::select(&i)).unwrap();
        writeln!(out, "select {bits} -> {}", names[idx]).unwrap();
    }
    assert!(out == want, "led sweep differs from the C trace");
}
