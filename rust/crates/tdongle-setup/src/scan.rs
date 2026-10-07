//! The "nearby networks" list of the setup page (`main/scan_list.c`).
//!
//! One entry per network, strongest first, at most [`MAX`]; hidden and duplicate entries are dropped and an SSID that is not strict UTF-8
//! or contains a control character is left out (the user can still type it).

/// `SCAN_LIST_MAX`.
pub const MAX: usize = 16;
/// `SCAN_SSID_MAX`.
pub const SSID_MAX: usize = 32;

/// One network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    ssid: [u8; SSID_MAX],
    len: u8,
    /// Signal strength, dBm.
    pub rssi: i8,
    /// Not an open network.
    pub secure: bool,
}

impl Entry {
    const EMPTY: Self = Self { ssid: [0; SSID_MAX], len: 0, rssi: 0, secure: false };
    /// The SSID bytes.
    #[must_use]
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..usize::from(self.len)]
    }
}

/// `scan_list`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanList {
    count: usize,
    entry: [Entry; MAX],
}

impl Default for ScanList {
    fn default() -> Self {
        Self::new()
    }
}

/// `scan_ssid_text_safe`: strict UTF-8 (no overlong forms, no surrogates, nothing above U+10FFFF) and no control characters.
#[must_use]
pub fn ssid_text_safe(s: &[u8]) -> bool {
    let n = s.len();
    let mut i = 0;
    while i < n {
        let c = s[i];
        if c < 0x20 || c == 0x7f {
            return false;
        }
        if c < 0x80 {
            i += 1;
            continue;
        }
        let (extra, mut cp) = match c {
            0xc2..=0xdf => (1, u32::from(c & 0x1f)),
            0xe0..=0xef => (2, u32::from(c & 0x0f)),
            0xf0..=0xf4 => (3, u32::from(c & 0x07)),
            _ => return false,
        };
        if i + extra >= n {
            return false;
        }
        for k in 1..=extra {
            if s[i + k] & 0xc0 != 0x80 {
                return false;
            }
            cp = cp << 6 | u32::from(s[i + k] & 0x3f);
        }
        if (extra == 2 && cp < 0x800) || (extra == 3 && !(0x10000..=0x10ffff).contains(&cp)) || (0xd800..=0xdfff).contains(&cp) {
            return false;
        }
        i += extra + 1;
    }
    true
}

impl ScanList {
    /// `scan_list_init`.
    #[must_use]
    pub const fn new() -> Self {
        Self { count: 0, entry: [Entry::EMPTY; MAX] }
    }
    /// The entries, strongest first.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entry[..self.count]
    }

    fn bubble(&mut self, mut j: usize) {
        while j > 0 && self.entry[j].rssi > self.entry[j - 1].rssi {
            self.entry.swap(j, j - 1);
            j -= 1;
        }
    }

    /// `scan_list_offer`: `ssid` is the driver's 32 byte field (NUL terminated only when shorter).
    pub fn offer(&mut self, ssid: &[u8; 32], rssi: i32, secure: bool) {
        let length = ssid.iter().position(|&b| b == 0).unwrap_or(SSID_MAX);
        if length == 0 || !ssid_text_safe(&ssid[..length]) {
            return;
        }
        let rssi = rssi.clamp(-128, 127) as i8;
        for i in 0..self.count {
            if self.entry[i].ssid() == &ssid[..length] {
                self.entry[i].secure |= secure;
                if rssi > self.entry[i].rssi {
                    self.entry[i].rssi = rssi;
                } else {
                    return;
                }
                self.bubble(i);
                return;
            }
        }
        let at = if self.count == MAX {
            if rssi <= self.entry[MAX - 1].rssi {
                return;
            }
            MAX - 1
        } else {
            self.count += 1;
            self.count - 1
        };
        let mut e = Entry { ssid: [0; SSID_MAX], len: length as u8, rssi, secure };
        e.ssid[..length].copy_from_slice(&ssid[..length]);
        self.entry[at] = e;
        self.bubble(at);
    }
}
