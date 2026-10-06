//! A whole request through the reader and the router, from a client of the setup network (with and without the right token): the router
//! must never panic and must never act without the token.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_setup::boot::SetupBoot;
use tdongle_setup::host::SetupHost;
use tdongle_setup::http::{Reader, Step};
use tdongle_setup::router::{BodyIn, Conn, Portal};
use tdongle_setup::scan::ScanList;

#[derive(Default)]
struct Host {
    acted: bool,
}

impl SetupHost for Host {
    fn wifi_ready(&self) -> bool { true }
    fn recovery(&self) -> bool { false }
    fn lock_settings(&mut self, _: u32) -> bool { true }
    fn unlock_settings(&mut self) {}
    fn scan_kick(&mut self, _: bool) { self.acted = true; }
    fn scan_result(&mut self, _: &mut ScanList) -> bool { false }
    fn saved_count(&self) -> usize { 0 }
    fn saved_ssid(&self, _: usize) -> &[u8] { b"" }
    fn saved_name(&self, _: usize) -> &[u8] { b"" }
    fn saved_priority(&self, _: usize) -> u8 { 0 }
    fn saved_preferred(&self) -> Option<usize> { None }
    fn save_wifi(&mut self, _: &[u8], _: &[u8], _: Option<&[u8]>, _: i32, _: i32) -> bool { self.acted = true; true }
    fn remove_wifi(&mut self, _: &[u8]) -> bool { self.acted = true; true }
    fn request_leave(&mut self) -> bool { self.acted = true; true }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let boot = SetupBoot::decide(false, 0, 0, 0, false, true).unwrap();
    let portal = Portal::new(&boot, &[7; 16], &[0; 6], 0);
    let conn = Conn { peer: Some(0xc0a8_0402), local: Some(0xc0a8_0401) };
    // mode bit 0: put the real token in front of the fuzzed bytes as a header; otherwise the request has none.
    let mut raw = Vec::new();
    if mode & 1 == 1 {
        raw.extend_from_slice(b"POST /command HTTP/1.1\r\nHost: 192.168.4.1\r\nContent-Type: application/json\r\nX-Setup-Token: ");
        raw.extend_from_slice(portal.token());
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(rest);
    let mut reader = Reader::new(0);
    let (_, step) = reader.push(&raw, 0);
    if step != Step::Ready {
        return;
    }
    let mut host = Host::default();
    let mut out = [0u8; 4096];
    let req = reader.request().unwrap();
    let has_token = req.header("X-Setup-Token", 40).ok().is_some_and(|t| t == portal.token());
    let resp = portal.serve(&conn, &req, BodyIn { bytes: reader.body(), incomplete: reader.body_incomplete() }, &mut host, &mut out);
    let mut sink = vec![0u8; 70000];
    let _ = resp.write_into(&mut sink);
    if !has_token {
        assert!(!host.acted, "acted without the token");
    }
});
