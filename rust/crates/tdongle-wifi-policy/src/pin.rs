//! A network the user chose with `use N` is pinned: `wifi_pin`, `wifi_pin_set`, `wifi_pin_clear`, `wifi_pin_pick_ranked`, `wifi_pin_pick`.

use crate::rank::{PROFILE_LIMIT, Rank, pick_ranked};

/// Worker passes the join may fail in a row before the pin is given up (C `WIFI_PIN_MAX_ATTEMPTS`).
pub const PIN_MAX_ATTEMPTS: u32 = 3;

/// The pinned network (C `wifi_pin`).
///
/// Automatic roaming and strongest-signal selection leave a pinned network alone until the user changes it, the saved networks are edited,
/// or the join fails [`PIN_MAX_ATTEMPTS`] worker passes in a row; then the pin is dropped, [`Pin::failed_slot`] says which network, and
/// normal selection resumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pin {
    /// Pinned slot, 0-based (C: `int slot`, -1 for none).
    pub slot: Option<usize>,
    /// Failed passes since the pin was set or last connected.
    pub attempts: u32,
    /// The slot, 0-based, whose pin was given up. C keeps it 1-based with 0 for none (`failed_slot`); add 1 to print what C printed.
    pub failed_slot: Option<usize>,
}

impl Default for Pin {
    /// C `WIFI_PIN_INIT`: nothing pinned.
    fn default() -> Self {
        Self::NONE
    }
}

impl Pin {
    /// C `WIFI_PIN_INIT`.
    pub const NONE: Self = Self {
        slot: None,
        attempts: 0,
        failed_slot: None,
    };

    /// C `wifi_pin_set`: pin `slot` (0-based) and forget any earlier failure.
    pub fn set(&mut self, slot: usize) {
        *self = Self {
            slot: Some(slot),
            attempts: 0,
            failed_slot: None,
        };
    }

    /// C `wifi_pin_clear`: nothing pinned, no failure remembered.
    pub fn clear(&mut self) {
        *self = Self::NONE;
    }

    /// C `wifi_pin_pick_ranked`: the worker's choice, the slot to connect to or `None` to stay.
    ///
    /// Unpinned: [`pick_ranked`]. Pinned: stay while connected to the pinned network; otherwise retry it regardless of signal (it may be
    /// hidden or briefly unseen) until [`PIN_MAX_ATTEMPTS`] passes have been used, then give the pin up, record [`Pin::failed_slot`] and
    /// fall back to the ranked choice. A pin beyond the saved list (`slot >= count`) is dropped first.
    pub fn pick_ranked(
        &mut self,
        signal: &[i16; PROFILE_LIMIT],
        count: usize,
        current: Option<usize>,
        connected: bool,
        rank: &Rank,
    ) -> Option<usize> {
        if self.slot.is_some_and(|s| s >= count) {
            self.clear();
        }
        let Some(slot) = self.slot else {
            return pick_ranked(signal, count, current, connected, rank);
        };
        if connected && current == Some(slot) {
            self.attempts = 0;
            return None;
        }
        self.attempts += 1;
        if self.attempts > PIN_MAX_ATTEMPTS {
            self.failed_slot = Some(slot);
            self.slot = None;
            self.attempts = 0;
            return pick_ranked(signal, count, current, connected, rank);
        }
        Some(slot)
    }

    /// C `wifi_pin_pick`: [`Pin::pick_ranked`] with no priorities and nothing preferred.
    pub fn pick(
        &mut self,
        signal: &[i16; PROFILE_LIMIT],
        count: usize,
        current: Option<usize>,
        connected: bool,
    ) -> Option<usize> {
        self.pick_ranked(signal, count, current, connected, &Rank::NONE)
    }
}
