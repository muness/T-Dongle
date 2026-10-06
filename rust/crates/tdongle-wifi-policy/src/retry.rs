//! The Wi-Fi retry and trial rules of `main/core.c`: `policy_next`, `retry_delay_ms`, `trial_decision`.

use tdongle_nvs_format::legacy::{LegacySettings, PROFILE_MAX};

/// Longest wait between join attempts, ms (the cap of C `retry_delay_ms`).
pub const RETRY_DELAY_MAX_MS: u32 = 30_000;
/// Failures after which the delay stops growing (C: `failures >= 5`).
pub const RETRY_BACKOFF_STEPS: u32 = 5;
/// A candidate network must stay associated this long to be committed, ms.
pub const TRIAL_STABLE_MS: u64 = 10_000;
/// The candidate must have associated within this long of the trial start, ms.
pub const TRIAL_ASSOCIATE_WITHIN_MS: u64 = 35_000;
/// A trial that has not committed after this long is abandoned, ms.
pub const TRIAL_TIMEOUT_MS: u64 = 45_000;

/// C `policy_next`: the next v0.1.x profile slot to try, given the `tried` bitmask (bit `i` set once slot `i` was tried).
///
/// The preferred slot goes first when it holds a network and has not been tried; then the untried network with the highest priority, the
/// lowest slot winning ties. `None` when every network was tried (C: -1). The settings must satisfy [`LegacySettings::valid`]; a
/// `preferred` beyond the eight slots is treated as "no preferred" instead of reading out of bounds.
#[must_use]
pub fn policy_next(settings: &LegacySettings, tried: u8) -> Option<usize> {
    let usable = |i: usize| settings.p[i].ssid[0] != 0 && tried & (1 << i) == 0;
    let preferred = usize::from(settings.preferred);
    if preferred < PROFILE_MAX && usable(preferred) {
        return Some(preferred);
    }
    let mut best: Option<usize> = None;
    for i in (0..PROFILE_MAX).filter(|&i| usable(i)) {
        if best.is_none_or(|b| settings.p[i].priority > settings.p[b].priority) {
            best = Some(i);
        }
    }
    best
}

/// C `retry_delay_ms`: 1 s doubling with each failure (1, 2, 4, 8, 16 s), then [`RETRY_DELAY_MAX_MS`] from the fifth failure on.
#[must_use]
pub const fn retry_delay_ms(failures: u32) -> u32 {
    if failures >= RETRY_BACKOFF_STEPS {
        RETRY_DELAY_MAX_MS
    } else {
        1000 << failures
    }
}

/// Outcome of a candidate-network trial (C `trial_decision`: 0, 1, -1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrialDecision {
    /// 0: keep waiting.
    Waiting,
    /// 1: the candidate held a link long enough; commit to it.
    Commit,
    /// -1: give up on the candidate.
    TimedOut,
}

/// C `trial_decision`, all times in ms: `now`, when the trial `started`, and since when the station has been continuously `associated`
/// (`associated_since`, meaningful only when `associated`).
///
/// A clock that went backwards (`now < started`) abandons the trial. The candidate is committed once it associated no later than
/// [`TRIAL_ASSOCIATE_WITHIN_MS`] after the start (and not before it: an association epoch older than the trial is another connection) and
/// has stayed [`TRIAL_STABLE_MS`]; otherwise the trial times out [`TRIAL_TIMEOUT_MS`] after it began.
#[must_use]
pub const fn trial_decision(
    now: u64,
    started: u64,
    associated_since: u64,
    associated: bool,
) -> TrialDecision {
    if now < started {
        return TrialDecision::TimedOut;
    }
    if associated
        && associated_since >= started
        && associated_since <= now
        && now - associated_since >= TRIAL_STABLE_MS
        && associated_since - started <= TRIAL_ASSOCIATE_WITHIN_MS
    {
        return TrialDecision::Commit;
    }
    if now - started >= TRIAL_TIMEOUT_MS {
        TrialDecision::TimedOut
    } else {
        TrialDecision::Waiting
    }
}
