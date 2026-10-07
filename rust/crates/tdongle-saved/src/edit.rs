//! Editing the saved list: the pure half of the C `wifi_save_with`, `wifi_set_preferred` and the in-memory part of `wifi_factory_reset`
//! (`alternative/tailnet/main/wifi_profiles.inc`). The caller persists the result (`tdongle_nvs_write::Store::save_profiles`: metadata first, then the list) and
//! only then replaces its copy, so a failed write changes nothing, as in C.

use tdongle_nvs_format::wifi_meta::{MetaSet, MetaSlot, PRIORITY_MAX, SLOTS};
use tdongle_nvs_format::wifi_profiles::{LIMIT, SavedNetworks, SavedProfile};

fn c_str(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

fn copy_trunc(dst: &mut [u8], src: &[u8]) {
    // strlcpy: at most len - 1 bytes, always terminated, the rest zero (the C struct is memset or fully overwritten by the caller's copy)
    dst.fill(0);
    let n = c_str(src).len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
}

/// C `wifi_save_with`. `name` empty or `None` and `priority < 0` keep what the slot has (or the defaults for a new or replaced network); `slot >= 0` targets that
/// slot (one past the end appends), `-1` finds the network by SSID. Returns the new list and metadata, or `None` where the C returns false.
#[must_use]
pub fn save_with(list: &SavedNetworks, meta: &MetaSet, ssid: &[u8], password: &[u8], name: Option<&[u8]>, priority: i32, remove: bool, slot: i32) -> Option<(SavedNetworks, MetaSet)> {
    let ssid = c_str(ssid);
    let name = name.map(c_str).filter(|n| !n.is_empty());
    let mut i = list.list().iter().position(|p| p.ssid_bytes() == ssid).unwrap_or(list.count);
    if slot >= 0 {
        let slot = slot as usize;
        if slot > list.count || (i < list.count && i != slot) {
            return None;
        }
        i = slot;
    }
    if remove && i == list.count {
        return None;
    }
    if !remove && i == LIMIT {
        return None;
    }
    if !remove && name.is_some_and(|n| !MetaSlot::name_valid(n)) {
        return None;
    }
    if !remove && priority > i32::from(PRIORITY_MAX) {
        return None;
    }
    let mut l = *list;
    let mut m = *meta;
    if remove {
        let count = l.count;
        l.profiles.copy_within(i + 1..count, i);
        l.profiles[count - 1] = SavedProfile::EMPTY;
        m.remove(count, i);
        l.count -= 1;
    } else {
        let same = i < l.count && l.profiles[i].ssid_bytes() == ssid;
        copy_trunc(&mut l.profiles[i].ssid, ssid);
        copy_trunc(&mut l.profiles[i].password, password);
        if i == l.count {
            l.count += 1;
        }
        if !same {
            m.slot[i] = MetaSlot::default_for(ssid);
        }
        if let Some(n) = name {
            m.slot[i].name = [0; tdongle_nvs_format::wifi_meta::NAME_MAX + 1];
            copy_trunc(&mut m.slot[i].name, n);
        }
        if priority >= 0 {
            m.slot[i].priority = priority as u8;
        }
    }
    debug_assert!(l.count <= SLOTS);
    Some((l, m))
}

/// C `wifi_set_preferred`: `slot` 0-based, -1 clears. `None` where the C returns false (out of range); `Some(same meta)` when nothing changes.
#[must_use]
pub fn set_preferred(list: &SavedNetworks, meta: &MetaSet, slot: i32) -> Option<MetaSet> {
    if slot < -1 || slot >= list.count as i32 {
        return None;
    }
    let mut m = *meta;
    m.preferred = usize::try_from(slot).ok();
    Some(m)
}

/// The in-memory result of `wifi_factory_reset`: no networks, default metadata.
#[must_use]
pub fn factory_reset() -> (SavedNetworks, MetaSet) {
    (SavedNetworks::default(), MetaSet::defaults(&[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> (SavedNetworks, MetaSet) {
        let l = SavedNetworks::default();
        let m = MetaSet::defaults(&[]);
        save_with(&l, &m, b"home", b"pw1", None, -1, false, -1).unwrap()
    }

    #[test]
    fn append_replace_remove() {
        let (l, m) = base();
        assert_eq!(l.count, 1);
        assert_eq!(m.slot[0].name_bytes(), b"home");
        assert_eq!(m.slot[0].priority, 50);
        let (l, m) = save_with(&l, &m, b"work", b"pw2", Some(b"Office"), 70, false, -1).unwrap();
        assert_eq!(l.count, 2);
        assert_eq!((m.slot[1].name_bytes(), m.slot[1].priority), (&b"Office"[..], 70));
        // replace slot 0 with another network: its own default name and priority
        let (l2, m2) = save_with(&l, &m, b"cafe", b"x", None, -1, false, 0).unwrap();
        assert_eq!(l2.list()[0].ssid_bytes(), b"cafe");
        assert_eq!(m2.slot[0].name_bytes(), b"cafe");
        // same SSID in another slot is refused
        assert!(save_with(&l, &m, b"work", b"x", None, -1, false, 0).is_none());
        // remove the first: the second moves up, metadata with it
        let (l3, m3) = save_with(&l, &m, b"home", b"", None, -1, true, -1).unwrap();
        assert_eq!(l3.count, 1);
        assert_eq!(l3.list()[0].ssid_bytes(), b"work");
        assert_eq!(m3.slot[0].name_bytes(), b"Office");
        assert_eq!(m3.slot[1], MetaSlot::EMPTY);
        assert!(save_with(&l3, &m3, b"nope", b"", None, -1, true, -1).is_none());
    }

    #[test]
    fn limits_and_validation() {
        let (mut l, mut m) = base();
        for i in 1..8u8 {
            let ssid = [b'n', b'0' + i];
            (l, m) = save_with(&l, &m, &ssid, b"p", None, -1, false, -1).unwrap();
        }
        assert_eq!(l.count, 8);
        assert!(save_with(&l, &m, b"ninth", b"p", None, -1, false, -1).is_none());
        assert!(save_with(&l, &m, b"home", b"p", None, 101, false, -1).is_none());
        assert!(save_with(&l, &m, b"home", b"p", Some(b"bad\x01name"), -1, false, -1).is_none());
        assert!(save_with(&l, &m, b"home", b"p", None, -1, false, 9).is_none());
    }

    #[test]
    fn preferred_follows_removal_and_replace_keeps_it() {
        let (l, m) = base();
        let (l, m) = save_with(&l, &m, b"b", b"p", None, -1, false, -1).unwrap();
        let m = set_preferred(&l, &m, 1).unwrap();
        let (l2, m2) = save_with(&l, &m, b"c", b"p", None, -1, false, 1).unwrap(); // replace the preferred slot
        assert_eq!(m2.preferred, Some(1));
        let (_, m3) = save_with(&l2, &m2, b"home", b"", None, -1, true, -1).unwrap(); // remove slot 0: preferred moves up
        assert_eq!(m3.preferred, Some(0));
        assert!(set_preferred(&l, &m, 2).is_none());
        assert_eq!(set_preferred(&l, &m, -1).unwrap().preferred, None);
    }

    #[test]
    fn long_values_are_cut_like_strlcpy() {
        let l = SavedNetworks::default();
        let m = MetaSet::defaults(&[]);
        let ssid = [b'a'; 40];
        let pw = [b'p'; 80];
        let (l, _) = save_with(&l, &m, &ssid, &pw, None, -1, false, -1).unwrap();
        assert_eq!(l.list()[0].ssid_bytes().len(), 32);
        assert_eq!(l.list()[0].password_bytes().len(), 63);
    }
}
