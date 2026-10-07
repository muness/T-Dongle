//! The membership registry: the saved tailnets (`membership_t` minus the live client), their persisted JSON and the rules both the settings loader and
//! the `add` handler enforce.

use crate::json_in::{Reader, SyntaxError, Val, as_u32};
use crate::json_out::Sink;
use crate::text::CText;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Most memberships the registry holds. The C has no constant (the heap decides, ADR 0013: a gateway runs a handful); eight keeps the stored JSON at about
/// 2 KB of the 16 KB the settings string may use and matches the eight-peers-per-member sizing of the router tests.
pub const MAX_MEMBERS: usize = 8;
/// Longest label (`strlen(label) <= 20`).
pub const LABEL_MAX: usize = 20;
/// Longest auth key (`strlen(key) < 160`).
pub const KEY_MAX: usize = 159;
/// Longest runtime error text (`char error[64]`).
pub const ERROR_MAX: usize = 63;
/// The stored `members` string must be shorter than this (`strlen(json) < 16384`); a string of `MAX_JSON_BYTES` or more is refused on save, and on load
/// anything that is not shorter than this (the NVS size includes the NUL: `n > 16384`) is refused.
pub const MAX_JSON_BYTES: usize = 16384;
/// Smallest scratch buffer [`Registry::encode`] always fits in.
pub const ENCODE_BUFFER: usize = MAX_JSON_BYTES;

/// One saved membership.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Member {
    /// The id (>= 1), also the identity namespace's suffix.
    pub id: u32,
    label: CText<LABEL_MAX>,
    key: CText<KEY_MAX>,
    /// Whether the membership should be running.
    pub enabled: bool,
    /// The last runtime error shown on the setup page (not persisted).
    pub error: CText<ERROR_MAX>,
}

impl core::fmt::Debug for Member {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Member").field("id", &self.id).field("label", &self.label).field("key", &"<redacted>").field("enabled", &self.enabled).finish()
    }
}

impl Member {
    const EMPTY: Member = Member { id: 0, label: CText::new(), key: CText::new(), enabled: false, error: CText::new() };
    /// A membership from stored parts, unvalidated (the settings loader, tests and tools; the `add` handler goes through [`Registry::add`]).
    pub fn restored(id: u32, label: &[u8], key: &[u8], enabled: bool) -> Member {
        Member { id, label: CText::from_bytes(label), key: CText::from_bytes(key), enabled, error: CText::new() }
    }
    /// The label bytes.
    pub fn label(&self) -> &[u8] {
        self.label.as_bytes()
    }
    /// The provisioning auth key bytes (empty after the first successful join).
    pub fn key(&self) -> &[u8] {
        self.key.as_bytes()
    }
    /// The identity NVS namespace, `tn_%08lx`.
    pub fn namespace(&self) -> CText<11> {
        let mut t = CText::new();
        for &b in b"tn_" {
            t.push(b);
        }
        for shift in (0..8).rev() {
            t.push(b"0123456789abcdef"[((self.id >> (shift * 4)) & 15) as usize]);
        }
        t
    }
    /// The tailnet hostname, `tdongle-<label>-<id in lower-case hex, no padding>` (at most 37 bytes; the C holds 47).
    pub fn hostname(&self) -> CText<47> {
        let mut t = CText::new();
        for &b in b"tdongle-" {
            t.push(b);
        }
        for &b in self.label.as_bytes() {
            t.push(b);
        }
        t.push(b'-');
        let mut started = false;
        for shift in (0..8).rev() {
            let d = ((self.id >> (shift * 4)) & 15) as u8;
            if d != 0 || started || shift == 0 {
                started = true;
                t.push(b"0123456789abcdef"[d as usize]);
            }
        }
        t
    }
    /// Set the runtime error text (truncated to 63 bytes like `strlcpy`).
    pub fn set_error(&mut self, text: &str) {
        self.error.clear();
        for &b in text.as_bytes() {
            if self.error.len() == ERROR_MAX {
                break;
            }
            self.error.push(b);
        }
    }
}

/// Why an `add` was refused (the C's `error` strings, in the C's precedence).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddError {
    /// Missing, empty or over-long label, or an over-long key: "Use a short label and valid auth key".
    BadInput,
    /// A character other than a letter, digit or hyphen: "Labels use letters, numbers and hyphens".
    LabelChars,
    /// A label equal ignoring case to a saved one: "That label is already saved".
    LabelTaken,
    /// No room (the registry is full, or the id counter is exhausted): "Cannot allocate another membership".
    NoRoom,
}

/// Why a stored `members` string was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// Not shorter than 16,384 bytes with its NUL, or shorter than 2 bytes with it (empty).
    Size,
    /// cJSON would not parse it.
    Syntax,
    /// Not an object with a valid `next_id` and a `members` array.
    Header,
    /// A member entry failed its validation (shape, label, key, enabled, id range).
    Entry,
    /// Two entries share an id or a label (ignoring case).
    Duplicate,
    /// More entries than the registry holds (the C is bounded by memory only).
    Capacity,
}

/// Why the registry could not be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The JSON would not be shorter than 16,384 bytes (the C refuses to write it).
    TooLarge,
    /// The caller's buffer is smaller than the JSON.
    Buffer,
}

impl From<SyntaxError> for LoadError {
    fn from(_: SyntaxError) -> Self {
        LoadError::Syntax
    }
}

/// The saved memberships, newest first (the C pushes at the head of a linked list), with the id counter.
#[derive(Debug)]
pub struct Registry<const N: usize = MAX_MEMBERS> {
    items: [Member; N],
    len: usize,
    next_id: u32,
}

/// The registry the firmware uses.
pub type MemberRegistry = Registry<MAX_MEMBERS>;

impl<const N: usize> Default for Registry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Registry<N> {
    /// Bytes of one registry (host measurement helper for the memory ADR).
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// An empty registry (`next_id = 1`).
    pub const fn new() -> Self {
        Registry { items: [Member::EMPTY; N], len: 0, next_id: 1 }
    }
    /// Number of memberships.
    pub fn len(&self) -> usize {
        self.len
    }
    /// True when there are none.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// The next id an `add` will use.
    pub fn next_id(&self) -> u32 {
        self.next_id
    }
    /// The memberships, newest first (the order the C walks and saves them in).
    pub fn iter(&self) -> core::slice::Iter<'_, Member> {
        self.items[..self.len].iter()
    }
    /// The membership with this id.
    pub fn get(&self, id: u32) -> Option<&Member> {
        self.iter().find(|m| m.id == id)
    }
    /// The membership with this id, mutably (the manager task sets `error` and clears the key through this).
    pub fn get_mut(&mut self, id: u32) -> Option<&mut Member> {
        self.items[..self.len].iter_mut().find(|m| m.id == id)
    }
    fn position(&self, id: u32) -> Option<usize> {
        self.iter().position(|m| m.id == id)
    }
    fn label_taken(&self, label: &[u8]) -> bool {
        self.iter().any(|m| m.label.eq_ignore_case(label))
    }
    fn push_front(&mut self, m: Member) {
        let mut i = self.len;
        while i > 0 {
            self.items.swap(i, i - 1);
            i -= 1;
        }
        self.items[0] = m;
        self.len += 1;
    }
    fn remove_at(&mut self, i: usize) {
        self.items[i].zeroize();
        for j in i..self.len - 1 {
            self.items.swap(j, j + 1);
        }
        self.len -= 1;
    }

    /// The `add` handler's validation and insertion. On success the new membership (enabled, id = the old `next_id`) is at the head and `next_id` is
    /// incremented; returns its id. Nothing is persisted here: if saving fails call [`Registry::undo_add`].
    pub fn add(&mut self, label: Option<&CText<LABEL_MAX>>, key: &CText<KEY_MAX>) -> Result<u32, AddError> {
        let label = match label {
            Some(l) if !l.is_empty() && !l.overflowed() && !key.overflowed() => l,
            _ => return Err(AddError::BadInput),
        };
        // The C records the LAST of its two checks that fails: a duplicate beats a bad character.
        let mut error = None;
        if label.as_bytes().iter().any(|&c| !c.is_ascii_alphanumeric() && c != b'-') {
            error = Some(AddError::LabelChars);
        }
        if self.label_taken(label.as_bytes()) {
            error = Some(AddError::LabelTaken);
        }
        if let Some(e) = error {
            return Err(e);
        }
        if self.len == N || self.next_id == 0 || self.next_id == u32::MAX {
            return Err(AddError::NoRoom);
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut m = Member::EMPTY;
        m.id = id;
        m.label = *label;
        m.key = *key;
        m.enabled = true;
        self.push_front(m);
        Ok(id)
    }

    /// Append a membership at the tail (restoring a saved list in its saved order) and set the id counter; false when full.
    pub fn append(&mut self, m: Member) -> bool {
        if self.len == N {
            return false;
        }
        self.items[self.len] = m;
        self.len += 1;
        true
    }

    /// Set the id counter (restoring a saved list).
    pub fn set_next_id(&mut self, next_id: u32) {
        self.next_id = next_id;
    }

    /// Roll back the `add` that returned `id` (the save failed): drop it and give the id back.
    pub fn undo_add(&mut self, id: u32) {
        if let Some(i) = self.position(id) {
            self.remove_at(i);
            self.next_id -= 1;
        }
    }

    /// Remove a membership, returning it (its key is zeroed when the returned value drops) and its position, for [`Registry::reinsert`].
    pub fn take(&mut self, id: u32) -> Option<(usize, Member)> {
        let i = self.position(id)?;
        let m = self.items[i].clone();
        self.remove_at(i);
        Some((i, m))
    }

    /// Put a membership back where [`Registry::take`] found it.
    pub fn reinsert(&mut self, at: usize, m: Member) {
        if self.len == N {
            return;
        }
        let at = at.min(self.len);
        self.push_front(m);
        for i in 0..at {
            self.items.swap(i, i + 1);
        }
    }

    /// Erase the provisioning key of a membership (after it connected).
    pub fn clear_key(&mut self, id: u32) {
        if let Some(m) = self.get_mut(id) {
            m.key.clear();
        }
    }

    /// `save_members`' string: `{"members":[{"id":..,"label":"..","key":"..","enabled":..},..],"next_id":..}` in registry order, exactly as
    /// `cJSON_PrintUnformatted` prints it. Returns its length. A string of 16,384 bytes or more is [`EncodeError::TooLarge`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Sink::new(out);
        w.raw(b"{\"members\":[");
        for (i, m) in self.iter().enumerate() {
            if i > 0 {
                w.raw(b",");
            }
            w.raw(b"{\"id\":");
            w.number(u64::from(m.id));
            w.raw(b",\"label\":");
            w.string(m.label.as_bytes());
            w.raw(b",\"key\":");
            w.string(m.key.as_bytes());
            w.raw(if m.enabled { b",\"enabled\":true}" } else { b",\"enabled\":false}" });
        }
        w.raw(b"],\"next_id\":");
        w.number(u64::from(self.next_id));
        w.raw(b"}");
        if w.total() >= MAX_JSON_BYTES {
            return Err(EncodeError::TooLarge);
        }
        if w.overflow > 0 {
            return Err(EncodeError::Buffer);
        }
        Ok(w.len())
    }

    /// `load_members` with the NVS lookup folded in: `None` is `ESP_ERR_NVS_NOT_FOUND` (a fresh install: success, registry untouched).
    pub fn load_stored(&mut self, stored: Option<&[u8]>) -> Result<(), LoadError> {
        match stored {
            None => Ok(()),
            Some(s) => self.load(s),
        }
    }

    /// `load_members`: replace the registry by the stored string, or leave it untouched and say why. `stored` is the NVS string without its terminator.
    /// The accepted language is cJSON's (see [`crate::json_in`]); the semantic rules are the C's: `next_id` an integer in `[1, 2^32 - 1)`; `members` an
    /// array of objects each with a non-empty label of at most 20 bytes, a string key shorter than 160, a boolean `enabled` and an integer `id` in
    /// `[1, next_id)`; ids and labels (ignoring case) unique. The entries load in reverse order, as the C's head-insertion does.
    pub fn load(&mut self, stored: &[u8]) -> Result<(), LoadError> {
        let n = stored.iter().position(|&b| b == 0).unwrap_or(stored.len()) + 1;
        if !(2..=MAX_JSON_BYTES).contains(&n) {
            return Err(LoadError::Size);
        }
        let r = Reader::new(stored);
        let (root, rp) = r.root()?;
        if !matches!(root, Val::Object(_)) {
            return Err(LoadError::Header);
        }
        let (mut id_item, mut list_item) = (None, None);
        for m in r.members(rp) {
            let m = m?;
            if id_item.is_none() && r.key_is(&m, "next_id") {
                id_item = Some(m.val);
            }
            if list_item.is_none() && r.key_is(&m, "members") {
                list_item = Some(m.val);
            }
        }
        let next_id = match id_item {
            Some(Val::Number(v)) if v >= 1.0 && v < f64::from(u32::MAX) && as_u32(v).is_some() => v,
            _ => return Err(LoadError::Header),
        };
        let Some(Val::Array(ap)) = list_item else { return Err(LoadError::Header) };
        let mut loaded = Registry::<N>::new();
        for el in r.elements(ap) {
            let Val::Object(op) = el? else { return Err(LoadError::Entry) };
            let (mut label, mut key, mut id, mut enabled) = (None, None, None, None);
            for m in r.members(op) {
                let m = m?;
                if label.is_none() && r.key_is(&m, "label") {
                    label = Some(m.val);
                }
                if key.is_none() && r.key_is(&m, "key") {
                    key = Some(m.val);
                }
                if id.is_none() && r.key_is(&m, "id") {
                    id = Some(m.val);
                }
                if enabled.is_none() && r.key_is(&m, "enabled") {
                    enabled = Some(m.val);
                }
            }
            let (Some(Val::Str(ls, le)), Some(Val::Str(ks, ke)), Some(Val::Number(mid)), Some(en)) = (label, key, id, enabled) else {
                return Err(LoadError::Entry);
            };
            let label = r.text::<LABEL_MAX>(ls, le);
            let key = r.text::<KEY_MAX>(ks, ke);
            if label.is_empty() || label.overflowed() || key.overflowed() || !en.is_bool() {
                return Err(LoadError::Entry);
            }
            if !(mid >= 1.0 && mid < next_id && as_u32(mid).is_some()) {
                return Err(LoadError::Entry);
            }
            let mid = mid as u32;
            if loaded.iter().any(|m| m.id == mid) || loaded.label_taken(label.as_bytes()) {
                return Err(LoadError::Duplicate);
            }
            if loaded.len == N {
                return Err(LoadError::Capacity);
            }
            let mut m = Member::EMPTY;
            m.id = mid;
            m.label = label;
            m.key = key;
            m.enabled = en.is_true();
            loaded.push_front(m);
        }
        loaded.next_id = next_id as u32;
        *self = loaded;
        Ok(())
    }
}
