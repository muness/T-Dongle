#![allow(dead_code)]
use tdongle_setup::boot::SetupBoot;
use tdongle_setup::host::SetupHost;
use tdongle_setup::http::{Reader, Step};
use tdongle_setup::response::Response;
use tdongle_setup::router::{BodyIn, Conn, Portal};
use tdongle_setup::scan::ScanList;

pub fn unhex(s: &str) -> Vec<u8> {
    if s == "-" || s == "~" {
        return Vec::new();
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

pub fn hex(b: &[u8]) -> String {
    if b.is_empty() { "-".into() } else { b.iter().map(|x| format!("{x:02x}")).collect() }
}

pub fn golden(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

pub const AP_PEER: u32 = 0xc0a8_0402; // 192.168.4.2
pub const AP_LOCAL: u32 = 0xc0a8_0401;
pub const USB_PEER: u32 = 0xc0a8_4d02;
pub const USB_LOCAL: u32 = 0xc0a8_4d01;

pub fn ap_conn() -> Conn {
    Conn { peer: Some(AP_PEER), local: Some(AP_LOCAL) }
}

type SavedCall = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, i32, i32);

#[derive(Default, Debug)]
pub struct FakeHost {
    pub ready: bool,
    pub recovery: bool,
    pub lock_ok: bool,
    pub saved: Vec<(Vec<u8>, Vec<u8>, u8)>,
    pub preferred: Option<usize>,
    pub scan: Option<ScanList>,
    pub busy: bool,
    pub kicks: Vec<bool>,
    pub saves: Vec<SavedCall>,
    pub removes: Vec<Vec<u8>>,
    pub leave_requests: u32,
    pub leave_ok: bool,
    pub save_ok: bool,
    pub locked: bool,
}

impl FakeHost {
    pub fn new() -> Self {
        Self { ready: true, lock_ok: true, leave_ok: true, save_ok: true, ..Self::default() }
    }
}

impl SetupHost for FakeHost {
    fn wifi_ready(&self) -> bool {
        self.ready
    }
    fn recovery(&self) -> bool {
        self.recovery
    }
    fn lock_settings(&mut self, _w: u32) -> bool {
        self.locked = self.lock_ok;
        self.lock_ok
    }
    fn unlock_settings(&mut self) {
        self.locked = false;
    }
    fn scan_kick(&mut self, again: bool) {
        self.kicks.push(again);
    }
    fn scan_result(&mut self, out: &mut ScanList) -> bool {
        if let Some(s) = &self.scan {
            *out = *s;
        }
        self.busy
    }
    fn saved_count(&self) -> usize {
        self.saved.len()
    }
    fn saved_ssid(&self, i: usize) -> &[u8] {
        &self.saved[i].0
    }
    fn saved_name(&self, i: usize) -> &[u8] {
        &self.saved[i].1
    }
    fn saved_priority(&self, i: usize) -> u8 {
        self.saved[i].2
    }
    fn saved_preferred(&self) -> Option<usize> {
        self.preferred
    }
    fn save_wifi(&mut self, ssid: &[u8], password: &[u8], name: Option<&[u8]>, priority: i32, slot: i32) -> bool {
        self.saves.push((ssid.to_vec(), password.to_vec(), name.map(<[u8]>::to_vec), priority, slot));
        if self.save_ok {
            self.saved.push((ssid.to_vec(), ssid.to_vec(), 50));
        }
        self.save_ok
    }
    fn remove_wifi(&mut self, ssid: &[u8]) -> bool {
        self.removes.push(ssid.to_vec());
        let before = self.saved.len();
        self.saved.retain(|s| s.0 != ssid);
        self.saved.len() != before
    }
    fn request_leave(&mut self) -> bool {
        self.leave_requests += 1;
        self.leave_ok
    }
}

pub fn portal() -> Portal {
    let boot = SetupBoot::decide(false, 0, 0, 0, false, true).unwrap();
    Portal::new(&boot, &[0x11; 16], &[0x34, 0x85, 0x18, 0xab, 0x0c, 0xf9], 1000)
}

pub fn token(p: &Portal) -> String {
    String::from_utf8(p.token().to_vec()).unwrap()
}

/// Feed `raw` to a reader, serve it, and return the full response bytes (plus whether the connection closes).
pub fn exchange(p: &Portal, conn: &Conn, host: &mut FakeHost, raw: &[u8]) -> (Vec<u8>, bool) {
    let mut reader = Reader::new(0);
    let (used, step) = reader.push(raw, 0);
    let mut out = vec![0u8; 4096];
    match step {
        Step::Reject(e) => {
            let r = Response::error(e.into(), None, true);
            let mut buf = vec![0u8; 4096];
            let n = r.write_into(&mut buf).unwrap();
            buf.truncate(n);
            return (buf, true);
        }
        Step::More => panic!("incomplete request in test: {used} of {}", raw.len()),
        Step::Ready => {}
    }
    let req = reader.request().unwrap();
    let body = BodyIn { bytes: reader.body(), incomplete: reader.body_incomplete() };
    let resp = p.serve(conn, &req, body, host, &mut out);
    let mut buf = vec![0u8; 60000];
    let n = resp.write_into(&mut buf).unwrap();
    buf.truncate(n);
    (buf, resp.close || reader.must_close())
}

pub fn get(path: &str, host_header: &str, extra: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\n{extra}\r\n").into_bytes()
}

pub fn post(path: &str, host_header: &str, extra: &str, body: &str) -> Vec<u8> {
    format!("POST {path} HTTP/1.1\r\nHost: {host_header}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
}

pub fn status_line(resp: &[u8]) -> String {
    String::from_utf8_lossy(resp.split(|&b| b == b'\r').next().unwrap()).into_owned()
}

pub fn body_of(resp: &[u8]) -> Vec<u8> {
    let at = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    resp[at + 4..].to_vec()
}
