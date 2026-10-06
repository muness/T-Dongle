//! Ranking of saved networks: `wifi_rank`, `wifi_rank_better`, `wifi_pick_ranked`, `wifi_pick`, `wifi_rank_order`.

/// Most saved networks (C `WIFI_PROFILE_LIMIT`).
pub const PROFILE_LIMIT: usize = 8;
/// Priority of a network that has none (C `WIFI_PRIORITY_DEFAULT`).
pub const PRIORITY_DEFAULT: u8 = 50;
/// Highest priority (C `WIFI_PRIORITY_MAX`).
pub const PRIORITY_MAX: u8 = 100;
/// A network at this signal (dBm) or stronger can carry traffic (C `WIFI_USABLE_DBM`).
pub const USABLE_DBM: i16 = -85;
/// A connected network stronger than this (dBm) is never left (C `WIFI_HEALTHY_DBM`).
pub const HEALTHY_DBM: i16 = -75;
/// A weak connected network is left only for a candidate at least this many dB stronger (C `WIFI_HYSTERESIS_DB`).
pub const HYSTERESIS_DB: i16 = 12;
/// The signal value meaning "not seen in this scan" (C: `signal[i] > -127` is "seen").
pub const NOT_SEEN_DBM: i16 = -127;

/// The preferred network and per-slot priorities that order the saved networks (C `wifi_rank`).
///
/// C passes a nullable pointer, and `WIFI_RANK_NONE` is `{NULL, -1}`; [`Rank::NONE`] is that value, and "no rank" is the same as it: every
/// priority at the default and nothing preferred, which reduces the choice to the strongest signal with ties to the lower slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rank {
    /// Priority of each saved slot (C: `const uint8_t *priority`, one entry per slot, or NULL for all-default).
    pub priority: Option<[u8; PROFILE_LIMIT]>,
    /// Preferred slot, 0-based (C: `int preferred`, -1 for none).
    pub preferred: Option<usize>,
}

impl Rank {
    /// C `WIFI_RANK_NONE`.
    pub const NONE: Self = Self {
        priority: None,
        preferred: None,
    };

    /// C `wifi_rank_priority`: the priority of `slot` (the default when there are no priorities or the slot is out of range).
    #[must_use]
    pub fn priority_of(&self, slot: usize) -> u8 {
        self.priority
            .and_then(|p| p.get(slot).copied())
            .unwrap_or(PRIORITY_DEFAULT)
    }

    fn is_preferred(&self, slot: usize) -> bool {
        self.preferred == Some(slot)
    }
}

impl Default for Rank {
    fn default() -> Self {
        Self::NONE
    }
}

/// C `wifi_rank_better`: is slot `a` a strictly better choice than slot `b`? Both must have been seen. Order of keys: usable beats
/// unusable, then preferred, then higher priority, then stronger signal.
#[must_use]
pub fn rank_better(rank: &Rank, signal: &[i16; PROFILE_LIMIT], a: usize, b: usize) -> bool {
    let (a_usable, b_usable) = (signal[a] >= USABLE_DBM, signal[b] >= USABLE_DBM);
    if a_usable != b_usable {
        return a_usable;
    }
    let (a_pref, b_pref) = (rank.is_preferred(a), rank.is_preferred(b));
    if a_pref != b_pref {
        return a_pref;
    }
    let (pa, pb) = (rank.priority_of(a), rank.priority_of(b));
    if pa != pb {
        return pa > pb;
    }
    signal[a] > signal[b]
}

/// C `wifi_pick_ranked`: the slot to switch to, or `None` to stay.
///
/// `signal[i]` is the strongest RSSI seen for saved slot `i` in the last scan, [`NOT_SEEN_DBM`] when not seen; `count` is the number of
/// saved networks (values above 8 are clamped); `current` is the slot of the connected network, if it is a saved one. When offline
/// (`connected` false) the best network is returned. When connected, the link is kept if it is healthy (stronger than [`HEALTHY_DBM`]), or if
/// the best candidate is not at least [`HYSTERESIS_DB`] stronger than the current signal. A `current` outside the signal array is treated
/// as no current network.
#[must_use]
pub fn pick_ranked(
    signal: &[i16; PROFILE_LIMIT],
    count: usize,
    current: Option<usize>,
    connected: bool,
    rank: &Rank,
) -> Option<usize> {
    let mut best: Option<usize> = None;
    for i in 0..count.min(PROFILE_LIMIT) {
        if signal[i] > NOT_SEEN_DBM && best.is_none_or(|b| rank_better(rank, signal, i, b)) {
            best = Some(i);
        }
    }
    if !connected {
        return best;
    }
    let best = best?;
    if Some(best) == current {
        return None;
    }
    if let Some(cur) = current.filter(|&c| c < PROFILE_LIMIT)
        && (signal[cur] > HEALTHY_DBM || signal[best] < signal[cur] + HYSTERESIS_DB)
    {
        return None;
    }
    Some(best)
}

/// C `wifi_pick`: [`pick_ranked`] with no priorities and nothing preferred. Stable ties, 12 dB hysteresis and the weak-current threshold
/// prevent churn.
#[must_use]
pub fn pick(
    signal: &[i16; PROFILE_LIMIT],
    count: usize,
    current: Option<usize>,
    connected: bool,
) -> Option<usize> {
    pick_ranked(signal, count, current, connected, &Rank::NONE)
}

/// C `wifi_rank_order`: the order in which networks that were not seen (hidden SSIDs, or out of range right now) are tried while offline:
/// the preferred slot, then by priority (higher first), then by slot. Returns the slot numbers in order; entries from `count` on are 0.
/// `count` above 8 is clamped.
#[must_use]
pub fn rank_order(rank: &Rank, count: usize) -> [u8; PROFILE_LIMIT] {
    let count = count.min(PROFILE_LIMIT);
    let mut order = [0u8; PROFILE_LIMIT];
    for (i, slot) in order.iter_mut().enumerate().take(count) {
        *slot = i as u8;
    }
    for i in 1..count {
        // Insertion sort: at most eight entries, stable.
        let slot = order[i];
        let mut j = i;
        while j > 0 {
            let prev = order[j - 1];
            let (slot_pref, prev_pref) = (
                rank.is_preferred(usize::from(slot)),
                rank.is_preferred(usize::from(prev)),
            );
            let before = if slot_pref == prev_pref {
                rank.priority_of(usize::from(slot)) > rank.priority_of(usize::from(prev))
            } else {
                slot_pref
            };
            if !before {
                break;
            }
            order[j] = prev;
            j -= 1;
        }
        order[j] = slot;
    }
    order
}
