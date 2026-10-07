//! `metadata JSON`: the companion firmware's compare-and-set edit of a saved network's name, priority and preference.
//!
//! Port of `metadata_parse_json` and `metadata_apply` (`main/profile_json.c`, `main/core.c` of the companion C firmware, branch
//! `codex/test-firmware`; contract in `docs/companion-contract.md`). The JSON language is the one of [`crate::profile_json`] (cJSON 1.7.19
//! plus the same pre-checks: C string, at most 500 bytes, no `\u` escape, nothing after the object), with these keys, each exactly once:
//!
//! | key | type | rule |
//! |---|---|---|
//! | `slot` | number | integer 1 to 8 |
//! | `expectedName` | string | shorter than 25 bytes, then printable ASCII 1 to 24 |
//! | `expectedSsid` | string | shorter than 33 bytes, then printable ASCII 1 to 32 |
//! | `expectedPriority` | number | integer 0 to 100 |
//! | `name` | string | shorter than 25 bytes, then printable ASCII 1 to 24, and no ` ssid=` in it |
//! | `priority` | number | integer 0 to 100 |
//! | `preferred` | `true` / `false` | |
//!
//! [`MetadataEdit::apply`] then checks the identity (`expectedName`, `expectedSsid`, `expectedPriority` must be what the slot holds now)
//! and changes only the name and the priority, plus the preferred network when `preferred` is true. SSID and password are never touched,
//! and nothing reassociates (C: "association unchanged").

use crate::cstr::{c_str, is_printable};
use crate::profile_json::{Cursor, MAX_LEN, integer};
use crate::wifi_meta::{MetaSet, NAME_MAX, PRIORITY_MAX, SSID_MAX};
use crate::wifi_profiles::SavedNetworks;

const K_SLOT: u8 = 1;
const K_EXPECTED_NAME: u8 = 2;
const K_EXPECTED_SSID: u8 = 4;
const K_EXPECTED_PRIORITY: u8 = 8;
const K_NAME: u8 = 16;
const K_PRIORITY: u8 = 32;
const K_PREFERRED: u8 = 64;
const ALL: u8 = 127;

/// Why a `metadata` command is refused (C `metadata_parse_json` returning false). The firmware answers every one of them with the same text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataJsonError {
    /// More than [`MAX_LEN`] bytes.
    TooLong,
    /// A backslash followed by `u` or by the end of the text.
    EscapeNotAllowed,
    /// Not a JSON object of the accepted shape (syntax, a value of a type no key takes, text after the object).
    Malformed,
    /// An unknown key, or one given twice.
    BadKey,
    /// One of the seven keys is missing.
    MissingKey,
    /// A number out of range or not an integer, a string too long for its field, or `preferred` not a boolean.
    BadValue,
    /// A name or SSID that is not printable ASCII of the right length, or a name containing ` ssid=`.
    InvalidText,
}

/// A parsed `metadata` command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataEdit {
    /// Saved network index, 0 to 7 (the text says 1 to 8).
    pub slot: usize,
    expected_name: [u8; NAME_MAX + 1],
    expected_ssid: [u8; SSID_MAX + 1],
    /// The priority the slot must have now.
    pub expected_priority: u8,
    name: [u8; NAME_MAX + 1],
    /// The new priority.
    pub priority: u8,
    /// Make this slot the preferred network (false leaves the preference as it is).
    pub preferred: bool,
}

impl MetadataEdit {
    /// The name the slot must have now.
    #[must_use]
    pub fn expected_name(&self) -> &[u8] {
        c_str(&self.expected_name)
    }
    /// The SSID the slot must have now.
    #[must_use]
    pub fn expected_ssid(&self) -> &[u8] {
        c_str(&self.expected_ssid)
    }
    /// The new name.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        c_str(&self.name)
    }

    /// C `metadata_apply` on the live settings: `None` when the slot no longer holds exactly the expected name, SSID and priority (or does
    /// not exist), otherwise the new metadata (the list itself is unchanged).
    #[must_use]
    pub fn apply(&self, list: &SavedNetworks, meta: &MetaSet) -> Option<MetaSet> {
        if self.slot >= list.count {
            return None;
        }
        let current = &meta.slot[self.slot];
        if current.name_bytes() != self.expected_name() || list.profiles[self.slot].ssid_bytes() != self.expected_ssid() || current.priority != self.expected_priority {
            return None;
        }
        let mut m = *meta;
        m.slot[self.slot].name = self.name;
        m.slot[self.slot].priority = self.priority;
        if self.preferred {
            m.preferred = Some(self.slot);
        }
        Some(m)
    }
}

/// C `printable(s, max, min)`.
fn printable(s: &[u8], max: usize, min: usize) -> bool {
    let s = c_str(s);
    (min..=max).contains(&s.len()) && s.iter().all(|&b| is_printable(b))
}

fn key_bit(key: &[u8]) -> Option<u8> {
    Some(match key {
        b"slot" => K_SLOT,
        b"expectedName" => K_EXPECTED_NAME,
        b"expectedSsid" => K_EXPECTED_SSID,
        b"expectedPriority" => K_EXPECTED_PRIORITY,
        b"name" => K_NAME,
        b"priority" => K_PRIORITY,
        b"preferred" => K_PREFERRED,
        _ => return None,
    })
}

/// C `metadata_parse_json` (which ends with `metadata_apply` on a copy holding the expected values: the text checks of the apply step).
///
/// # Errors
/// A [`MetadataJsonError`].
pub fn metadata_parse_json(json: &[u8]) -> Result<MetadataEdit, MetadataJsonError> {
    use MetadataJsonError as E;
    let text = c_str(json);
    if text.len() > MAX_LEN {
        return Err(E::TooLong);
    }
    let mut i = 0;
    while i < text.len() {
        if text[i] == b'\\' {
            if text.get(i + 1).is_none_or(|&n| n == b'u') {
                return Err(E::EscapeNotAllowed);
            }
            i += 1;
        }
        i += 1;
    }
    let body = if text.len() >= 4 && text.starts_with(&[0xEF, 0xBB, 0xBF]) { &text[3..] } else { text };
    let mut cur = Cursor { text: body, at: 0 };
    let mut edit = MetadataEdit {
        slot: 0,
        expected_name: [0; NAME_MAX + 1],
        expected_ssid: [0; SSID_MAX + 1],
        expected_priority: 0,
        name: [0; NAME_MAX + 1],
        priority: 0,
        preferred: false,
    };
    let malformed = |_| E::Malformed;
    cur.skip_ws();
    if !cur.eat(b'{') {
        return Err(E::Malformed);
    }
    cur.skip_ws();
    let mut seen = 0u8;
    if cur.peek() != Some(b'}') {
        loop {
            cur.skip_ws();
            let mut key = [0u8; 17];
            let key_len = cur.string(&mut key).map_err(malformed)?;
            let bit = key.get(..key_len).and_then(key_bit).ok_or(E::BadKey)?;
            if seen & bit != 0 {
                return Err(E::BadKey);
            }
            seen |= bit;
            cur.skip_ws();
            if !cur.eat(b':') {
                return Err(E::Malformed);
            }
            cur.skip_ws();
            match bit {
                K_SLOT | K_EXPECTED_PRIORITY | K_PRIORITY => {
                    if !matches!(cur.peek(), Some(b'-' | b'0'..=b'9')) {
                        return Err(E::Malformed);
                    }
                    let value = cur.number().map_err(malformed)?;
                    match bit {
                        K_SLOT => edit.slot = integer(value, 1, 8).ok_or(E::BadValue)? as usize - 1,
                        K_EXPECTED_PRIORITY => edit.expected_priority = integer(value, 0, i32::from(PRIORITY_MAX)).ok_or(E::BadValue)? as u8,
                        _ => edit.priority = integer(value, 0, i32::from(PRIORITY_MAX)).ok_or(E::BadValue)? as u8,
                    }
                }
                K_PREFERRED => {
                    let rest = &cur.text[cur.at..];
                    if rest.starts_with(b"true") {
                        edit.preferred = true;
                        cur.at += 4;
                    } else if rest.starts_with(b"false") {
                        cur.at += 5;
                    } else {
                        return Err(E::Malformed);
                    }
                }
                _ => {
                    let field: &mut [u8] = match bit {
                        K_EXPECTED_NAME => &mut edit.expected_name,
                        K_EXPECTED_SSID => &mut edit.expected_ssid,
                        _ => &mut edit.name,
                    };
                    let len = cur.string(field).map_err(malformed)?;
                    if len >= field.len() {
                        return Err(E::BadValue);
                    }
                }
            }
            cur.skip_ws();
            if !cur.eat(b',') {
                break;
            }
        }
    }
    if !cur.eat(b'}') {
        return Err(E::Malformed);
    }
    cur.skip_ws();
    if cur.peek().is_some() {
        return Err(E::Malformed);
    }
    if seen != ALL {
        return Err(E::MissingKey);
    }
    let name = edit.name();
    if !printable(name, NAME_MAX, 1)
        || name.windows(6).any(|w| w == b" ssid=")
        || !printable(edit.expected_name(), NAME_MAX, 1)
        || !printable(edit.expected_ssid(), SSID_MAX, 1)
    {
        return Err(E::InvalidText);
    }
    Ok(edit)
}
