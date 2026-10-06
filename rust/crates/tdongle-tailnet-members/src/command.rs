//! The setup page's member API: `POST /command` with `{"action":"add"|"enable"|"remove",...}`, and exactly what the C handler answers.
//!
//! The firmware does the I/O (reading the request, the `members_lock`, NVS, stopping a membership's client); this module decides. The order of the
//! checks and the texts are those of `command()` in `alternative/tailnet/main/gateway_main.c`:
//!
//! 1. [`parse_request`]: Content-Type, body size, JSON, the action name and whether the origin may use it (before the lock);
//! 2. the firmware takes `members_lock` (1 s) and answers [`Reply::busy`] if it cannot;
//! 3. [`apply`]: recovery mode, then the action on the [`Registry`], persisting through [`MemberIo`];
//! 4. [`Reply`]: HTTP 200 `{"ok":true}` or HTTP 400 `{"ok":false,"error":"..."}`, `application/json`, `Cache-Control: no-store`.

use crate::json_in::{Reader, Val};
use crate::registry::{AddError, KEY_MAX, LABEL_MAX, Registry};
use crate::text::CText;
use core::fmt;
use zeroize::Zeroize;

/// The largest request body (`content_len > 1024` is refused).
pub const MAX_BODY: usize = 1024;

/// The exact error texts of the C handler (the setup page shows them).
pub mod text {
    /// `Content-Type` is not exactly `application/json`.
    pub const JSON_REQUIRED: &str = "JSON required";
    /// The body is empty or over 1024 bytes.
    pub const TOO_LARGE: &str = "Request is too large";
    /// The body could not be read completely.
    pub const INCOMPLETE: &str = "Incomplete request";
    /// `cJSON_Parse` refused the body.
    pub const INVALID_JSON: &str = "Invalid JSON";
    /// The action is not one the origin may use (from the open setup network).
    pub const NOT_FROM_SETUP: &str = "That is not available from the setup network";
    /// No such action.
    pub const UNKNOWN_ACTION: &str = "Unknown action";
    /// `members_lock` was not available within a second.
    pub const BUSY: &str = "Memberships are busy; retry shortly";
    /// Recovery mode or unusable settings.
    pub const RECOVERY: &str = "Recovery mode: settings are preserved. Use Restart services in the app after saving diagnostics.";
    /// `add`: label missing, empty, over 20 bytes, or key of 160 bytes or more.
    pub const ADD_INPUT: &str = "Use a short label and valid auth key";
    /// `add`: a character that is not a letter, digit or hyphen.
    pub const LABEL_CHARS: &str = "Labels use letters, numbers and hyphens";
    /// `add`: label already saved (ignoring case).
    pub const LABEL_TAKEN: &str = "That label is already saved";
    /// `add`: no memory/id for another membership.
    pub const NO_ROOM: &str = "Cannot allocate another membership";
    /// `add`: persisting failed.
    pub const ADD_NOT_SAVED: &str = "Membership could not be saved";
    /// `enable`/`remove`: no such id.
    pub const NOT_FOUND: &str = "Membership not found";
    /// `enable`: persisting failed.
    pub const CHANGE_NOT_SAVED: &str = "Change could not be saved";
    /// `enable` (disconnect): the client has not finished stopping.
    pub const DISCONNECT_PENDING: &str = "Disconnect is still finishing; retry shortly";
    /// `remove`: the client has not finished stopping.
    pub const REMOVAL_PENDING: &str = "Removal is waiting for shutdown; retry shortly";
    /// `remove`: persisting failed.
    pub const REMOVAL_NOT_SAVED: &str = "Removal could not be saved";
    /// `remove`: removed, but the identity namespace could not be erased.
    pub const IDENTITY_CLEANUP: &str = "Membership removed, but stored identity cleanup failed";
    /// `Membership.error` after a stop that did not complete.
    pub const SHUTDOWN_RUNNING: &str = "Shutdown is still running; retry after it finishes";
    /// `Membership.error` while another membership negotiates.
    pub const WAITING_FOR_JOIN: &str = "Waiting for another membership to finish joining";
    /// `Membership.error` when admission refuses.
    pub const NOT_ENOUGH_MEMORY: &str = "Not enough free memory to activate this membership";
    /// `Membership.error`: sockets reserved.
    pub const SOCKETS_RESERVED: &str = "Socket capacity reserved for USB setup and DNS";
    /// `Membership.error`: identity could not be allocated or saved.
    pub const IDENTITY_FAILED: &str = "Could not allocate or save this identity";
    /// `Membership.error`: the route table is damaged.
    pub const ROUTING_DAMAGED: &str = "Routing storage is damaged; tailnet access is disabled";
    /// `Membership.error`: the provisioning key could not be erased from storage.
    pub const KEY_CLEANUP: &str = "Connected; provisioning-key cleanup could not be saved";
}

/// The HTTP status of a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// 200 OK.
    Ok,
    /// 400 Bad Request (`httpd_resp_set_status(req, "400 Bad Request")`).
    BadRequest,
}

impl Status {
    /// The numeric code.
    pub fn code(self) -> u16 {
        match self {
            Status::Ok => 200,
            Status::BadRequest => 400,
        }
    }
    /// The status line text passed to `httpd_resp_set_status`.
    pub fn line(self) -> &'static str {
        match self {
            Status::Ok => "200 OK",
            Status::BadRequest => "400 Bad Request",
        }
    }
}

/// An HTTP reply: [`Reply::OK`] or an error with its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    /// `None` for success.
    pub error: Option<&'static str>,
}

impl Reply {
    /// `{"ok":true}` with 200.
    pub const OK: Reply = Reply { error: None };
    /// A 400 with this text.
    pub const fn failure(message: &'static str) -> Reply {
        Reply { error: Some(message) }
    }
    /// The `members_lock` timeout answer.
    pub const fn busy() -> Reply {
        Reply::failure(text::BUSY)
    }
    /// The status.
    pub fn status(&self) -> Status {
        if self.error.is_some() { Status::BadRequest } else { Status::Ok }
    }
    /// The `Content-Type` of the body.
    pub const CONTENT_TYPE: &'static str = "application/json";
    /// The `Cache-Control` header value.
    pub const CACHE_CONTROL: &'static str = "no-store";
    /// Write the body (`cJSON_PrintUnformatted` of `{"ok":..}` / `{"ok":false,"error":..}`). The texts hold nothing JSON escapes.
    pub fn write_body(&self, out: &mut dyn fmt::Write) -> fmt::Result {
        match self.error {
            None => out.write_str("{\"ok\":true}"),
            Some(e) => {
                out.write_str("{\"ok\":false,\"error\":\"")?;
                out.write_str(e)?;
                out.write_str("\"}")
            }
        }
    }
}

/// Who is asking (`access_origin`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The host on the USB link: every action.
    Usb,
    /// A phone on the open setup access point: Wi-Fi actions only.
    SetupAp,
}

/// The actions of `/command` (`access_action`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    /// `mode`
    Mode,
    /// `wifi`
    Wifi,
    /// `wifi_remove`
    WifiRemove,
    /// `add`
    Add,
    /// `remove`
    Remove,
    /// `enable`
    Enable,
    /// `setup_done`
    SetupDone,
}

impl ActionKind {
    /// `access_action_parse`.
    pub fn parse(name: &[u8]) -> Option<ActionKind> {
        Some(match name {
            b"mode" => ActionKind::Mode,
            b"wifi" => ActionKind::Wifi,
            b"wifi_remove" => ActionKind::WifiRemove,
            b"add" => ActionKind::Add,
            b"remove" => ActionKind::Remove,
            b"enable" => ActionKind::Enable,
            b"setup_done" => ActionKind::SetupDone,
            _ => return None,
        })
    }
    /// `access_action_allowed` for a known action.
    pub fn allowed(self, origin: Origin) -> bool {
        match origin {
            Origin::Usb => true,
            Origin::SetupAp => matches!(self, ActionKind::Wifi | ActionKind::WifiRemove | ActionKind::SetupDone),
        }
    }
}

/// A member action, typed. `Enable`/`Disable` are the one `enable` action with `enabled` true / not true (anything but the literal `true` disconnects).
/// An `id` that is not a number naming a possible id (non-numeric, fractional, negative, 0, above `u32::MAX`) is carried as id 0, which no membership has.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // transient on the handler's stack; boxing would need an allocator
pub enum MemberAction {
    /// `add` with its label (None when absent or not a string) and key (empty when absent or not a string).
    Add {
        /// The label as decoded (C-string semantics).
        label: Option<CText<LABEL_MAX>>,
        /// The auth key.
        key: CText<KEY_MAX>,
    },
    /// `enable` with `enabled: true`.
    Enable(u32),
    /// `enable` with `enabled` anything else.
    Disable(u32),
    /// `remove`.
    Remove(u32),
}

impl MemberAction {
    /// An `add` from plain bytes.
    pub fn add(label: &[u8], key: &[u8]) -> MemberAction {
        MemberAction::Add { label: Some(CText::from_bytes(label)), key: CText::from_bytes(key) }
    }
}

impl Drop for MemberAction {
    fn drop(&mut self) {
        if let MemberAction::Add { key, .. } = self {
            key.zeroize();
        }
    }
}

/// A request that passed the checks before the lock.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // see MemberAction
pub enum Parsed {
    /// A member action: take the lock, then [`apply`].
    Member(MemberAction),
    /// An action of another module (`mode`, `wifi`, `wifi_remove`, `setup_done`); the firmware parses its fields from the same body.
    Other(ActionKind),
}

fn id_of(r: &Reader<'_>, root: usize) -> u32 {
    match r.get(root, "id") {
        Ok(Some(Val::Number(v))) => crate::json_in::as_u32(v).unwrap_or(0),
        _ => 0,
    }
}

/// The checks `command()` makes before it takes the lock: `content_type` is the header value if present and shorter than 64 bytes (`None` otherwise),
/// `content_len` the declared length, `body` what was received.
pub fn parse_request(origin: Origin, content_type: Option<&[u8]>, content_len: usize, body: &[u8]) -> Result<Parsed, Reply> {
    if content_type != Some(b"application/json") {
        return Err(Reply::failure(text::JSON_REQUIRED));
    }
    if content_len == 0 || content_len > MAX_BODY {
        return Err(Reply::failure(text::TOO_LARGE));
    }
    if body.len() < content_len {
        return Err(Reply::failure(text::INCOMPLETE));
    }
    let r = Reader::new(&body[..content_len]);
    let (root, rp) = r.root().map_err(|_| Reply::failure(text::INVALID_JSON))?;
    let name = match root {
        Val::Object(_) => match r.get(rp, "action") {
            Ok(Some(Val::Str(s, e))) => Some(r.text::<16>(s, e)),
            _ => None,
        },
        _ => None,
    };
    let kind = name.as_ref().filter(|n| !n.overflowed()).and_then(|n| ActionKind::parse(n.as_bytes()));
    let Some(kind) = kind.filter(|k| k.allowed(origin)) else {
        return Err(Reply::failure(if origin == Origin::SetupAp { text::NOT_FROM_SETUP } else { text::UNKNOWN_ACTION }));
    };
    Ok(match kind {
        ActionKind::Add => {
            let label = match r.get(rp, "label") {
                Ok(Some(Val::Str(s, e))) => Some(r.text::<LABEL_MAX>(s, e)),
                _ => None,
            };
            let key = match r.get(rp, "key") {
                Ok(Some(Val::Str(s, e))) => r.text::<KEY_MAX>(s, e),
                _ => CText::new(),
            };
            Parsed::Member(MemberAction::Add { label, key })
        }
        ActionKind::Remove => Parsed::Member(MemberAction::Remove(id_of(&r, rp))),
        ActionKind::Enable => {
            let id = id_of(&r, rp);
            if matches!(r.get(rp, "enabled"), Ok(Some(Val::True))) {
                Parsed::Member(MemberAction::Enable(id))
            } else {
                Parsed::Member(MemberAction::Disable(id))
            }
        }
        other => Parsed::Other(other),
    })
}

/// What the firmware does for the registry. Every method is the C call named beside it.
pub trait MemberIo {
    /// `!settings_ok || gateway_boot_recovery()`.
    fn recovery(&self) -> bool;
    /// `nvs_set_str(store, "members", json)` and `nvs_commit`; false if either failed (or settings are not usable).
    fn persist(&mut self, json: &[u8]) -> bool;
    /// `m->client != NULL`: a client exists for this membership.
    fn has_client(&self, id: u32) -> bool;
    /// `stop_member`: `gateway_suspend(id)`, then stop and destroy the client. False if the stop did not finish (`stop_incomplete`).
    fn stop(&mut self, id: u32) -> bool;
    /// `gateway_forget(id)`.
    fn forget(&mut self, id: u32);
    /// Open `namespace`, `nvs_erase_all`, commit, close. False if any step failed.
    fn erase_identity(&mut self, namespace: &[u8]) -> bool;
    /// `gateway_dns_domains_refresh()`; the handler calls it on every path that reaches the action.
    fn refresh_dns(&mut self);
}

fn save<const N: usize>(reg: &Registry<N>, io: &mut dyn MemberIo, scratch: &mut [u8]) -> bool {
    let ok = match reg.encode(scratch) {
        Ok(n) => io.persist(&scratch[..n]),
        Err(_) => false,
    };
    scratch.zeroize();
    ok
}

/// Run a member action under the lock. `scratch` holds the JSON being saved (use [`crate::ENCODE_BUFFER`] bytes; it is zeroed after every save).
pub fn apply<const N: usize>(reg: &mut Registry<N>, action: &MemberAction, io: &mut dyn MemberIo, scratch: &mut [u8]) -> Reply {
    if io.recovery() {
        return Reply::failure(text::RECOVERY);
    }
    let error = match action {
        MemberAction::Add { label, key } => add(reg, label.as_ref(), key, io, scratch),
        MemberAction::Enable(id) => enable(reg, *id, true, io, scratch),
        MemberAction::Disable(id) => enable(reg, *id, false, io, scratch),
        MemberAction::Remove(id) => remove(reg, *id, io, scratch),
    };
    io.refresh_dns();
    match error {
        Some(e) => Reply::failure(e),
        None => Reply::OK,
    }
}

fn add<const N: usize>(
    reg: &mut Registry<N>,
    label: Option<&CText<LABEL_MAX>>,
    key: &CText<KEY_MAX>,
    io: &mut dyn MemberIo,
    scratch: &mut [u8],
) -> Option<&'static str> {
    match reg.add(label, key) {
        Err(AddError::BadInput) => Some(text::ADD_INPUT),
        Err(AddError::LabelChars) => Some(text::LABEL_CHARS),
        Err(AddError::LabelTaken) => Some(text::LABEL_TAKEN),
        Err(AddError::NoRoom) => Some(text::NO_ROOM),
        Ok(id) => {
            if save(reg, io, scratch) {
                None
            } else {
                reg.undo_add(id);
                Some(text::ADD_NOT_SAVED)
            }
        }
    }
}

fn enable<const N: usize>(reg: &mut Registry<N>, id: u32, enabled: bool, io: &mut dyn MemberIo, scratch: &mut [u8]) -> Option<&'static str> {
    let Some(old) = reg.get(id).map(|m| m.enabled) else { return Some(text::NOT_FOUND) };
    if let Some(m) = reg.get_mut(id) {
        m.enabled = enabled;
    }
    if !save(reg, io, scratch) {
        if let Some(m) = reg.get_mut(id) {
            m.enabled = old;
        }
        return Some(text::CHANGE_NOT_SAVED);
    }
    if !enabled && io.has_client(id) {
        if !io.stop(id) {
            if let Some(m) = reg.get_mut(id) {
                m.set_error(text::SHUTDOWN_RUNNING);
            }
            return Some(text::DISCONNECT_PENDING);
        }
        if let Some(m) = reg.get_mut(id) {
            m.error.clear();
        }
    }
    None
}

fn remove<const N: usize>(reg: &mut Registry<N>, id: u32, io: &mut dyn MemberIo, scratch: &mut [u8]) -> Option<&'static str> {
    if reg.get(id).is_none() {
        return Some(text::NOT_FOUND);
    }
    if let Some(m) = reg.get_mut(id) {
        m.enabled = false;
    }
    if !io.stop(id) {
        if let Some(m) = reg.get_mut(id) {
            m.set_error(text::SHUTDOWN_RUNNING);
        }
        save(reg, io, scratch); // the C ignores the result: it only wants the disabled state kept
        return Some(text::REMOVAL_PENDING);
    }
    let Some((at, member)) = reg.take(id) else { return Some(text::NOT_FOUND) };
    if !save(reg, io, scratch) {
        reg.reinsert(at, member);
        return Some(text::REMOVAL_NOT_SAVED);
    }
    io.forget(id);
    let ns = member.namespace();
    if io.erase_identity(ns.as_bytes()) { None } else { Some(text::IDENTITY_CLEANUP) }
}
