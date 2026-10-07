//! The request router: every endpoint the setup page (and, in the C, the USB page) uses, with the C's handlers' decisions and texts.
//!
//! One server, registered like `start_http`: `GET /`, `/status`, `/diagnostics`, `/wifi-scan`, `/wifi-saved`, `/boot-status` and
//! `POST /command`, exact path match, nothing else. Every other path from a client of the setup network is a captive-portal probe
//! (Android `/generate_204`, iOS `/hotspot-detect.html`, Windows `/connecttest.txt`, ...) and gets `302 Location: http://192.168.4.1/`.
//! Method mismatch on a known path is `405` with the connection closed. No CORS header is ever sent and `OPTIONS` is `405`, so a
//! cross-origin page cannot read or preflight anything; a request with a foreign `Origin` or `Host` is refused before the token is looked at.

use crate::access::{self, Action, Endpoint, Facts, Origin, TOKEN_LENGTH};
use crate::boot::{Session, SetupBoot};
use crate::host::SetupHost;
use crate::http::{HeaderValue, Method, Request};
use crate::json::{self, Fields, Json, Val};
use crate::page;
use crate::response::{ErrCode, Response};
use crate::scan::ScanList;
use crate::tailnet::{Adapter, Reply};
use tdongle_nvs_format::wifi_meta::{MetaSlot, PRIORITY_MAX};
use tdongle_nvs_format::wifi_profiles::LIMIT as PROFILE_LIMIT;

/// The canonical address everything redirects to.
pub const LOCATION: &str = "http://192.168.4.1/";

/// The socket facts of one connection.
#[derive(Clone, Copy, Debug)]
pub struct Conn {
    /// `getpeername` as IPv4 (host order), `None` when it could not be read or is not IPv4.
    pub peer: Option<u32>,
    /// `getsockname` as IPv4 (host order).
    pub local: Option<u32>,
}

/// The request body as read.
#[derive(Clone, Copy, Debug)]
pub struct BodyIn<'a> {
    /// The bytes received.
    pub bytes: &'a [u8],
    /// Fewer than `Content-Length` bytes arrived.
    pub incomplete: bool,
}

impl BodyIn<'_> {
    /// No body.
    pub const NONE: BodyIn<'static> = BodyIn { bytes: &[], incomplete: false };
}

/// What the periodic check decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick {
    /// Keep serving.
    Continue,
    /// Restart into normal mode now (`setup_restart(SETUP_REQUEST_LEAVE, 0)`).
    Leave,
}

/// One setup boot's portal state: the per-boot token, the session clock, the preselected slot.
#[derive(Debug)]
pub struct Portal {
    token: [u8; TOKEN_LENGTH],
    preselect: core::sync::atomic::AtomicU8,
    session: Session,
    ap_name: [u8; crate::boot::SSID_LEN],
}

const NOT_USB: &str = "USB access required";

fn failure<'a>(out: &'a mut [u8], message: &str) -> Response<'a> {
    let mut j = Json::new(out);
    j.raw(b"{\"ok\":false,\"error\":").string(message.as_bytes()).raw(b"}");
    let len = j.bytes().len();
    if j.overflowed() {
        return Response::error(ErrCode::Internal, Some("Out of memory"), false);
    }
    Response::ok(&out[..len]).status("400 Bad Request").content_type("application/json").header("Cache-Control", "no-store")
}

fn json_ok<'a>(out: &'a mut [u8], oom: &'static str, build: impl FnOnce(&mut Json<'_>)) -> Response<'a> {
    let mut j = Json::new(out);
    build(&mut j);
    let len = j.bytes().len();
    if j.overflowed() {
        return Response::error(ErrCode::Internal, Some(oom), false);
    }
    Response::ok(&out[..len]).content_type("application/json").header("Cache-Control", "no-store")
}

impl Portal {
    /// Start the portal for this setup boot: `token` is 16 hardware-random bytes formatted by [`access::token_format`], `now_ms` the
    /// boot time the ten minute clock starts from, `mac` the station MAC (the access point is `TDongle-XXXXXX`).
    #[must_use]
    pub fn new(boot: &SetupBoot, random: &[u8; 16], mac: &[u8; 6], now_ms: u32) -> Self {
        Self { token: access::token_format(random), preselect: core::sync::atomic::AtomicU8::new(boot.preselect()), session: boot.session(now_ms), ap_name: crate::boot::ap_ssid(mac) }
    }

    /// The per-boot token the page carries.
    #[must_use]
    pub const fn token(&self) -> &[u8; TOKEN_LENGTH] {
        &self.token
    }

    /// The access point name.
    #[must_use]
    pub const fn ap_name(&self) -> &[u8; crate::boot::SSID_LEN] {
        &self.ap_name
    }

    /// The session (for `status` `setup ... seconds_left=` and the LCD countdown).
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// `setup N` over serial while setup is open: offer saved network `n` (0: none).
    pub fn set_preselect(&self, n: u8) {
        self.preselect.store(n, core::sync::atomic::Ordering::Relaxed);
    }

    /// The control task's check and the failsafe timer: end setup when the session is over or the access point never came up.
    #[must_use]
    pub fn tick(&self, now_ms: u32, access_point_up: bool) -> Tick {
        if self.session.should_end(now_ms, access_point_up) { Tick::Leave } else { Tick::Continue }
    }

    fn facts<'r>(req: &Request<'r>, conn: &Conn, setup_active: bool) -> Option<Facts<'r>> {
        let host = req.header("Host", 64).ok();
        let origin = if req.header_len("Origin") != 0 {
            match req.header("Origin", 96) {
                HeaderValue::Value(v) => Some(v),
                _ => return None, // too long: refused outright
            }
        } else {
            None
        };
        Some(Facts { peer: conn.peer, local: conn.local, setup_active, host, origin })
    }

    /// `request_origin`.
    fn origin(&self, req: &Request<'_>, conn: &Conn) -> Origin {
        Self::facts(req, conn, true).map_or(Origin::Denied, |f| access::classify(&f))
    }

    /// `setup_redirect`: any other name or path asked of the setup network goes to the one canonical address.
    fn redirect(conn: &Conn, error: ErrCode) -> Response<'static> {
        match conn.peer {
            Some(p) if access::in_setup_subnet(p) => {
                Response::ok(b"").status("302 Found").header("Location", LOCATION).header("Cache-Control", "no-store")
            }
            _ => Response::error(error, Some(if error == ErrCode::NotFound { "Not found" } else { "Not available" }), false),
        }
    }

    /// `endpoint_allowed`: the refusal, or the origin.
    fn gate(&self, req: &Request<'_>, conn: &Conn, endpoint: Endpoint) -> Result<Origin, Response<'static>> {
        let origin = self.origin(req, conn);
        if !access::endpoint_allowed(origin, endpoint) {
            return Err(Response::error(ErrCode::Forbidden, Some(NOT_USB), false));
        }
        if origin == Origin::SetupAp && endpoint != Endpoint::Home {
            // `char supplied[ACCESS_TOKEN_LENGTH + 8]`
            let supplied = req.header("X-Setup-Token", TOKEN_LENGTH + 8).ok();
            if !access::token_equal(supplied, &self.token) {
                return Err(Response::error(ErrCode::Forbidden, Some("Invalid setup token"), false));
            }
        }
        Ok(origin)
    }

    /// Answer one request. `out` is scratch for JSON bodies (4 KiB is enough for sixteen escaped SSIDs).
    pub fn serve<'a, H: SetupHost>(&'a self, conn: &Conn, req: &Request<'_>, body: BodyIn<'_>, host: &mut H, out: &'a mut [u8]) -> Response<'a> {
        let Some(path) = req.path else { return Response::silent_close() };
        let known: Option<(Method, Endpoint)> = match path {
            b"/" => Some((Method::Get, Endpoint::Home)),
            b"/status" => Some((Method::Get, Endpoint::Status)),
            b"/diagnostics" => Some((Method::Get, Endpoint::Diagnostics)),
            b"/wifi-scan" => Some((Method::Get, Endpoint::WifiScan)),
            b"/command" => Some((Method::Post, Endpoint::Command)),
            b"/boot-status" => Some((Method::Get, Endpoint::BootStatus)),
            b"/wifi-saved" => Some((Method::Get, Endpoint::WifiSaved)),
            _ => None,
        };
        let Some((method, endpoint)) = known else { return Self::redirect(conn, ErrCode::NotFound) };
        if req.method != method {
            return Response::error(ErrCode::MethodNotAllowed, None, true);
        }
        match endpoint {
            Endpoint::Home => self.home(req, conn),
            Endpoint::Status | Endpoint::Diagnostics | Endpoint::BootStatus => match self.gate(req, conn, endpoint) {
                Err(r) => r,
                Ok(_) => match Adapter.report() {
                    Reply::Done => json_ok(out, "Out of memory", |j| {
                        j.raw(b"{\"ok\":true}");
                    }),
                    Reply::Failure(m) => failure(out, m),
                },
            },
            Endpoint::WifiScan => self.wifi_scan(req, conn, host, out),
            Endpoint::WifiSaved => self.wifi_saved(req, conn, host, out),
            Endpoint::Command => self.command(req, conn, body, host, out),
        }
    }

    fn home(&self, req: &Request<'_>, conn: &Conn) -> Response<'_> {
        match self.origin(req, conn) {
            Origin::SetupAp => {
                let Some((before, after)) = page::split_at_token() else {
                    return Response::error(ErrCode::Internal, Some("Setup page unavailable"), false);
                };
                Response::chunked([before, &self.token, after])
                    .header("Cache-Control", "no-store")
                    .header("X-Content-Type-Options", "nosniff")
                    .header("X-Frame-Options", "DENY")
                    .header("Content-Security-Policy", page::AP_CSP)
            }
            Origin::Usb => Response::ok2(page::SETUP_HTML, page::SETUP_HTML_WIRE_NUL).header("Content-Security-Policy", page::USB_CSP),
            Origin::Denied => match conn.peer {
                Some(p) if access::in_setup_subnet(p) => Self::redirect(conn, ErrCode::NotFound),
                _ => Response::error(ErrCode::Forbidden, Some("Open this page through USB Ethernet at 192.168.77.1"), false),
            },
        }
    }

    fn wifi_scan<'a, H: SetupHost>(&self, req: &Request<'_>, conn: &Conn, host: &mut H, out: &'a mut [u8]) -> Response<'a> {
        if let Err(r) = self.gate(req, conn, Endpoint::WifiScan) {
            return r;
        }
        if !host.wifi_ready() {
            return failure(out, "Wi-Fi startup failed; saved diagnostics contain the reason");
        }
        // `char query[32]`: a longer query is not read at all.
        let again = req.query.is_some_and(|q| q.len() < 32 && q.windows(5).any(|w| w == b"again"));
        host.scan_kick(again);
        let mut list = ScanList::new();
        let busy = host.scan_result(&mut list);
        json_ok(out, "Out of memory returning Wi-Fi scan", |j| {
            j.raw(b"{\"ok\":true,\"busy\":").boolean(busy).raw(b",\"networks\":[");
            for (i, e) in list.entries().iter().enumerate() {
                if i > 0 {
                    j.raw(b",");
                }
                j.raw(b"{\"ssid\":").string(e.ssid()).raw(b",\"rssi\":").int(i64::from(e.rssi)).raw(b",\"secure\":").boolean(e.secure).raw(b"}");
            }
            j.raw(b"]}");
        })
    }

    fn wifi_saved<'a, H: SetupHost>(&self, req: &Request<'_>, conn: &Conn, host: &mut H, out: &'a mut [u8]) -> Response<'a> {
        let origin = match self.gate(req, conn, Endpoint::WifiSaved) {
            Ok(o) => o,
            Err(r) => return r,
        };
        if !host.lock_settings(100) {
            return failure(out, "Settings are busy; retry shortly");
        }
        let count = host.saved_count();
        let full = origin == Origin::Usb;
        let mut free = if count < PROFILE_LIMIT { count + 1 } else { 0 };
        let pre = usize::from(self.preselect.load(core::sync::atomic::Ordering::Relaxed));
        if pre != 0 && pre <= count + 1 && pre <= PROFILE_LIMIT {
            free = pre;
        }
        let response = json_ok(out, "Out of memory listing Wi-Fi networks", |j| {
            j.raw(b"{\"ok\":true,\"networks\":[");
            for i in 0..count {
                if i > 0 {
                    j.raw(b",");
                }
                let ssid = cstr(host.saved_ssid(i));
                // The open setup network gets slot and SSID (the name shown is the SSID) and no more: no priority, no preference, no name.
                j.raw(b"{\"slot\":").int(i as i64 + 1).raw(b",\"name\":").string(if full { cstr(host.saved_name(i)) } else { ssid });
                j.raw(b",\"ssid\":").string(ssid);
                if full {
                    j.raw(b",\"priority\":").int(i64::from(host.saved_priority(i))).raw(b",\"preferred\":").boolean(host.saved_preferred() == Some(i));
                }
                j.raw(b"}");
            }
            j.raw(b"],\"free\":").int(free as i64).raw(b",\"max\":").int(PROFILE_LIMIT as i64).raw(b"}");
        });
        host.unlock_settings();
        response
    }

    fn command<'a, H: SetupHost>(&self, req: &Request<'_>, conn: &Conn, body: BodyIn<'_>, host: &mut H, out: &'a mut [u8]) -> Response<'a> {
        let origin = match self.gate(req, conn, Endpoint::Command) {
            Ok(o) => o,
            Err(r) => return r,
        };
        if req.header("Content-Type", 64).ok() != Some(b"application/json") {
            return failure(out, "JSON required");
        }
        if req.content_len == 0 || req.content_len > crate::http::MAX_BODY as u64 {
            return failure(out, "Request is too large");
        }
        if body.incomplete || (body.bytes.len() as u64) < req.content_len {
            return failure(out, "Incomplete request");
        }
        let Some(fields) = json::parse(body.bytes) else { return failure(out, "Invalid JSON") };
        let action = access::parse_action(fields.string(fields.action));
        if !access::action_allowed(origin, action) {
            // From the open setup network only the Wi-Fi actions exist: no tailnet memberships (their sign-in keys), no routing mode.
            return failure(out, if origin == Origin::SetupAp { "That is not available from the setup network" } else { "Unknown action" });
        }
        if !host.lock_settings(1000) {
            return failure(out, "Memberships are busy; retry shortly");
        }
        let result = if host.recovery() {
            Err("Recovery mode: settings are preserved. Use Restart services in the app after saving diagnostics.")
        } else {
            match action {
                Action::Wifi => wifi_action(origin, &fields, host),
                Action::SetupDone => {
                    if host.request_leave() {
                        Ok(())
                    } else {
                        Err("Setup is not running")
                    }
                }
                Action::WifiRemove => match fields.string(fields.ssid) {
                    Some(ssid) if host.remove_wifi(ssid) => Ok(()),
                    _ => Err("Could not remove that saved network"),
                },
                Action::Mode | Action::Add | Action::Remove | Action::Enable => match Adapter.action(action, &fields) {
                    Reply::Done => Ok(()),
                    Reply::Failure(m) => Err(m),
                },
                Action::Unknown => Err("Unknown action"),
            }
        };
        host.unlock_settings();
        match result {
            Err(m) => failure(out, m),
            Ok(()) => json_ok(out, "Out of memory", |j| {
                j.raw(b"{\"ok\":true}");
            }),
        }
    }
}

/// A C string held in a fixed buffer: up to the first NUL.
fn cstr(b: &[u8]) -> &[u8] {
    b.split(|&c| c == 0).next().unwrap_or(&[])
}

/// `cJSON_IsNumber` + `valuedouble == (int)valuedouble` + range, as the handler's `extras_ok` computes it.
fn int_in(v: Val, min: i32, max: i32) -> Option<i32> {
    let Val::Num(d) = v else { return None };
    // cJSON's valueint saturates; the comparison is against the truncating cast.
    let int = if d >= f64::from(i32::MAX) { i32::MAX } else if d <= f64::from(i32::MIN) { i32::MIN } else { d as i32 };
    (d == f64::from(int) && (min..=max).contains(&int)).then_some(int)
}

fn wifi_action<H: SetupHost>(origin: Origin, f: &Fields, host: &mut H) -> Result<(), &'static str> {
    if !host.wifi_ready() {
        return Err("Wi-Fi did not start; restart services after saving diagnostics");
    }
    let (ssid, password) = (f.string(f.ssid), f.string(f.password));
    let name = if access::may_set_metadata(origin) { f.string(f.name) } else { None };
    let priority_item = if access::may_set_metadata(origin) { f.priority } else { Val::Absent };
    let mut slot = -1;
    let mut priority = -1;
    let mut extras_ok = true;
    if f.slot != Val::Absent {
        match int_in(f.slot, 1, PROFILE_LIMIT as i32) {
            Some(n) => slot = n - 1,
            None => extras_ok = false,
        }
    }
    if extras_ok && priority_item != Val::Absent {
        match int_in(priority_item, 0, i32::from(PRIORITY_MAX)) {
            Some(n) => priority = n,
            None => extras_ok = false,
        }
    }
    if extras_ok && name.is_some_and(|n| !n.is_empty() && !MetaSlot::name_valid(n)) {
        extras_ok = false;
    }
    let (Some(ssid), Some(password)) = (ssid, password) else { return Err("Enter a valid Wi-Fi name and password") };
    if ssid.is_empty() || ssid.len() > 32 || password.len() > 63 {
        return Err("Enter a valid Wi-Fi name and password");
    }
    if origin == Origin::SetupAp && !password.is_empty() && password.len() < 8 {
        return Err("Passwords need at least 8 characters. Leave it empty only for an open network.");
    }
    if !access::may_replace(origin) {
        let count = host.saved_count();
        let saved = (0..count).any(|i| cstr(host.saved_ssid(i)) == ssid);
        if saved || (slot >= 0 && (slot as usize) < count) {
            return Err("That network is already saved. Delete it first to change it: replacing a saved network is not available on the setup network.");
        }
    }
    if !extras_ok {
        return Err("Use a name of up to 24 plain characters, a slot from 1 to 8 and a priority from 0 to 100");
    }
    let name = name.filter(|n| !n.is_empty());
    if host.save_wifi(ssid, password, name, priority, slot) {
        Ok(())
    } else {
        Err("Could not save Wi-Fi; at most eight networks can be saved, and a network can only be in one slot")
    }
}
