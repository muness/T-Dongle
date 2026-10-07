//! Per-network metadata of the saved Wi-Fi list: display name, priority and the preferred network.
//!
//! Port of `main/wifi_meta.{h,c}` (tested by `tests/test_wifi_meta.c`). The metadata lives in its own NVS blob
//! (`tn_settings/wifi_meta`, [`MetaBlob`], 516 bytes) keyed by SSID rather than by slot, so reordering or deleting networks, or an
//! older build editing `wifi_profiles`, can never attach a priority to the wrong network.

use crate::cstr::{c_str, copy_str, is_printable, is_terminated, read_u32};

/// Number of saved-network slots (C `WIFI_META_SLOTS`).
pub const SLOTS: usize = 8;
/// Longest display name (C `WIFI_META_NAME_MAX`).
pub const NAME_MAX: usize = 24;
/// Priority of a network that has none (C `WIFI_META_PRIORITY_DEFAULT`).
pub const PRIORITY_DEFAULT: u8 = 50;
/// Highest priority (C `WIFI_META_PRIORITY_MAX`).
pub const PRIORITY_MAX: u8 = 100;
/// Longest SSID (C `WIFI_META_SSID_MAX`).
pub const SSID_MAX: usize = 32;
/// Schema of the persisted blob (C `WIFI_META_SCHEMA`).
pub const SCHEMA: u32 = 1;
/// Size of the persisted blob: `sizeof(wifi_meta_blob)` on xtensa and on a 64-bit host.
pub const BLOB_LEN: usize = 516;

const ENTRY_LEN: usize = (SSID_MAX + 1) + (NAME_MAX + 1) + 1;
const PREFERRED_AT: usize = 8;
const ENTRIES_AT: usize = PREFERRED_AT + SSID_MAX + 1;
/// The struct has byte alignment inside and 4-byte alignment overall (`uint32_t`), so its size is the end of the last entry rounded up to 4.
const _: () = assert!((ENTRIES_AT + SLOTS * ENTRY_LEN).next_multiple_of(4) == BLOB_LEN);

/// Name and priority of one saved network (C `wifi_meta_slot`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetaSlot {
    /// NUL-terminated display name in a 25-byte array (C `char name[25]`).
    pub name: [u8; NAME_MAX + 1],
    /// Priority, 0 to [`PRIORITY_MAX`].
    pub priority: u8,
}

impl MetaSlot {
    /// An empty slot: no name, priority 0 (what C leaves in the slots beyond the saved count).
    pub const EMPTY: Self = Self { name: [0; NAME_MAX + 1], priority: 0 };

    /// The name without its terminator.
    #[must_use]
    pub fn name_bytes(&self) -> &[u8] {
        c_str(&self.name)
    }

    /// C `wifi_meta_name_valid`: 1 to 24 printable ASCII characters. Unlike an SSID a name is shown on the screen and serial console.
    #[must_use]
    pub fn name_valid(name: &[u8]) -> bool {
        let n = c_str(name);
        (1..=NAME_MAX).contains(&n.len()) && n.iter().all(|&b| is_printable(b))
    }

    /// C `wifi_meta_slot_default`: the name is the SSID cut to 24 characters with every non-printable byte shown as `?`, priority 50.
    #[must_use]
    pub fn default_for(ssid: &[u8]) -> Self {
        let mut slot = Self::EMPTY;
        for (dst, &b) in slot.name[..NAME_MAX].iter_mut().zip(c_str(ssid)) {
            *dst = if is_printable(b) { b } else { b'?' };
        }
        slot.priority = PRIORITY_DEFAULT;
        slot
    }
}

/// The metadata of the whole saved list, parallel to it and in the same order (C `wifi_meta_set`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetaSet {
    /// One entry per saved slot; slots beyond the saved count are [`MetaSlot::EMPTY`].
    pub slot: [MetaSlot; SLOTS],
    /// Slot index of the preferred network (C: `int preferred`, -1 for none).
    pub preferred: Option<usize>,
}

/// Why a stored [`MetaBlob`] was refused (C `blob_valid` returning false).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaBlobError {
    /// The blob is not exactly [`BLOB_LEN`] bytes, or the saved list has more than [`SLOTS`] networks.
    WrongSize,
    /// Schema other than [`SCHEMA`].
    BadSchema,
    /// `count` above [`SLOTS`].
    BadCount,
    /// A string the blob relies on has no terminator (the preferred SSID, or an SSID or name of one of the first `count` entries).
    Unterminated,
    /// A priority above [`PRIORITY_MAX`] in one of the first `count` entries.
    BadPriority,
}

impl MetaSet {
    /// C `wifi_meta_defaults`: every listed network gets its default name and priority, nothing preferred. At most [`SLOTS`] SSIDs count.
    #[must_use]
    pub fn defaults(ssids: &[&[u8]]) -> Self {
        let mut set = Self { slot: [MetaSlot::EMPTY; SLOTS], preferred: None };
        for (slot, ssid) in set.slot.iter_mut().zip(ssids) {
            *slot = MetaSlot::default_for(ssid);
        }
        set
    }

    /// C `wifi_meta_remove`: drop the entry of saved slot `slot` of `count`; later entries move up, a removed preferred network is
    /// forgotten and a preferred one that moves keeps pointing at its network. Out of range (`slot >= count` or `count > 8`): nothing.
    pub fn remove(&mut self, count: usize, slot: usize) {
        if slot >= count || count > SLOTS {
            return;
        }
        self.slot.copy_within(slot + 1..count, slot);
        self.slot[count - 1] = MetaSlot::EMPTY;
        self.preferred = match self.preferred {
            Some(p) if p == slot => None,
            Some(p) if p > slot => Some(p - 1),
            other => other,
        };
    }

    /// C `wifi_meta_overlay`: lay the stored blob over what `self` already holds. Only networks the blob has an entry for take its
    /// priority (and its name, when the stored name is valid); the others keep what `self` had. The blob's preferred network, present
    /// or "none", is authoritative. `ssids` is the saved list in order. On error `self` is untouched.
    ///
    /// # Errors
    /// Any [`MetaBlobError`]; `ssids` longer than [`SLOTS`] is [`MetaBlobError::WrongSize`] (C: `count > WIFI_META_SLOTS`).
    pub fn overlay(&mut self, data: &[u8], ssids: &[&[u8]]) -> Result<(), MetaBlobError> {
        if ssids.len() > SLOTS {
            return Err(MetaBlobError::WrongSize);
        }
        let blob = MetaBlob::from_bytes(data)?;
        for (slot, ssid) in self.slot.iter_mut().zip(ssids) {
            let ssid = c_str(ssid);
            let Some(entry) = blob.entries().iter().find(|e| c_str(&e.ssid) == ssid) else {
                continue;
            };
            if MetaSlot::name_valid(&entry.name) {
                slot.name = [0; NAME_MAX + 1];
                copy_str(&mut slot.name[..NAME_MAX], &entry.name);
            }
            slot.priority = entry.priority;
        }
        let wanted = c_str(&blob.preferred_ssid);
        self.preferred = None;
        if !wanted.is_empty() {
            for (i, ssid) in ssids.iter().enumerate() {
                if c_str(ssid) == wanted {
                    self.preferred = Some(i);
                }
            }
        }
        Ok(())
    }
}

/// One persisted entry (the anonymous `entry[]` struct of C `wifi_meta_blob`): 59 bytes, byte alignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetaEntry {
    /// SSID the entry belongs to (`char ssid[33]`).
    pub ssid: [u8; SSID_MAX + 1],
    /// Display name (`char name[25]`).
    pub name: [u8; NAME_MAX + 1],
    /// Priority.
    pub priority: u8,
}

impl MetaEntry {
    const ZERO: Self = Self { ssid: [0; SSID_MAX + 1], name: [0; NAME_MAX + 1], priority: 0 };
}

/// The persisted form, NVS `tn_settings/wifi_meta` (C `wifi_meta_blob`, 516 bytes).
///
/// Layout (offsets): `schema` u32 at 0, `count` u32 at 4, `preferred_ssid[33]` at 8, eight 59-byte entries from 41
/// (`ssid[33]` +0, `name[25]` +33, `priority` +58), 3 bytes of tail padding that are always written as zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetaBlob {
    /// Always [`SCHEMA`] for a blob that [`MetaBlob::from_bytes`] accepts.
    pub schema: u32,
    /// Number of entries in use, at most [`SLOTS`].
    pub count: u32,
    /// SSID of the preferred network, empty for none.
    pub preferred_ssid: [u8; SSID_MAX + 1],
    /// All eight entries as stored; only the first `count` are meaningful.
    pub entry: [MetaEntry; SLOTS],
}

impl MetaBlob {
    /// The entries in use.
    #[must_use]
    pub fn entries(&self) -> &[MetaEntry] {
        &self.entry[..self.count as usize]
    }

    /// C `wifi_meta_encode`: the blob for the list `ssids` (at most 8 are stored) with metadata `set`. Padding and unused entries are zero.
    #[must_use]
    pub fn encode(ssids: &[&[u8]], set: &MetaSet) -> Self {
        let count = ssids.len().min(SLOTS);
        let mut blob = Self { schema: SCHEMA, count: count as u32, preferred_ssid: [0; SSID_MAX + 1], entry: [MetaEntry::ZERO; SLOTS] };
        for ((entry, ssid), slot) in blob.entry.iter_mut().zip(ssids).zip(&set.slot) {
            copy_str(&mut entry.ssid[..SSID_MAX], ssid);
            copy_str(&mut entry.name[..NAME_MAX], &slot.name);
            entry.priority = slot.priority;
        }
        if let Some(p) = set.preferred.filter(|&p| p < count) {
            copy_str(&mut blob.preferred_ssid[..SSID_MAX], ssids[p]);
        }
        blob
    }

    /// Parse and validate a stored blob exactly as C `blob_valid`: length 516, schema 1, `count <= 8`, a terminated preferred SSID, and
    /// for each of the first `count` entries a terminated SSID and name and a priority of at most 100. Entries at or beyond `count`
    /// and bytes after a terminator are not looked at, but they are kept so that [`MetaBlob::to_bytes`] returns the input.
    ///
    /// # Errors
    /// The first failed rule as a [`MetaBlobError`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, MetaBlobError> {
        if data.len() != BLOB_LEN {
            return Err(MetaBlobError::WrongSize);
        }
        let mut blob = Self { schema: read_u32(data, 0), count: read_u32(data, 4), preferred_ssid: [0; SSID_MAX + 1], entry: [MetaEntry::ZERO; SLOTS] };
        blob.preferred_ssid.copy_from_slice(&data[PREFERRED_AT..PREFERRED_AT + SSID_MAX + 1]);
        for (i, e) in blob.entry.iter_mut().enumerate() {
            let at = ENTRIES_AT + i * ENTRY_LEN;
            e.ssid.copy_from_slice(&data[at..at + SSID_MAX + 1]);
            e.name.copy_from_slice(&data[at + SSID_MAX + 1..at + SSID_MAX + 1 + NAME_MAX + 1]);
            e.priority = data[at + ENTRY_LEN - 1];
        }
        if blob.schema != SCHEMA {
            return Err(MetaBlobError::BadSchema);
        }
        if blob.count as usize > SLOTS {
            return Err(MetaBlobError::BadCount);
        }
        if !is_terminated(&blob.preferred_ssid) {
            return Err(MetaBlobError::Unterminated);
        }
        for e in blob.entries() {
            if !is_terminated(&e.ssid) || !is_terminated(&e.name) {
                return Err(MetaBlobError::Unterminated);
            }
            if e.priority > PRIORITY_MAX {
                return Err(MetaBlobError::BadPriority);
            }
        }
        Ok(blob)
    }

    /// The 516 bytes C stores for this blob (little endian, tail padding zero).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BLOB_LEN] {
        let mut out = [0u8; BLOB_LEN];
        out[0..4].copy_from_slice(&self.schema.to_le_bytes());
        out[4..8].copy_from_slice(&self.count.to_le_bytes());
        out[PREFERRED_AT..PREFERRED_AT + SSID_MAX + 1].copy_from_slice(&self.preferred_ssid);
        for (i, e) in self.entry.iter().enumerate() {
            let at = ENTRIES_AT + i * ENTRY_LEN;
            out[at..at + SSID_MAX + 1].copy_from_slice(&e.ssid);
            out[at + SSID_MAX + 1..at + SSID_MAX + 1 + NAME_MAX + 1].copy_from_slice(&e.name);
            out[at + ENTRY_LEN - 1] = e.priority;
        }
        out
    }
}
