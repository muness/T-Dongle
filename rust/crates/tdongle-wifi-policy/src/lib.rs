//! Saved-network selection and Wi-Fi retry policy, as pure functions.
//!
//! Ports of `alternative/tailnet/main/wifi_policy.h` ([`rank`], [`pin`]) and of the Wi-Fi parts of `main/core.c` ([`retry`]:
//! `policy_next`, `retry_delay_ms`, `trial_decision`). Nothing here touches the radio, NVS or a clock: callers pass in what they scanned
//! and what time it is.
//!
//! Three things decide which saved network is joined, strongest first:
//! 1. the preferred slot, if it is usable;
//! 2. the network's priority (0 to 100, default 50);
//! 3. signal strength, with ties to the lower slot.
//!
//! "Usable" is [`USABLE_DBM`] or stronger. Leaving a working link is deliberately hard: a connected network stronger than
//! [`HEALTHY_DBM`] is kept whatever else is in range, and a weaker one is left only for a candidate at least [`HYSTERESIS_DB`] stronger.
//!
//! `profile_parse_json` is not here: it produces the v0.1.x `profile_t` and lives in
//! [`tdongle_nvs_format::profile_json`].

#![no_std]
#![forbid(unsafe_code)]

pub mod pin;
pub mod rank;
pub mod retry;

pub use pin::{PIN_MAX_ATTEMPTS, Pin};
pub use rank::{
    HEALTHY_DBM, HYSTERESIS_DB, NOT_SEEN_DBM, PRIORITY_DEFAULT, PRIORITY_MAX, PROFILE_LIMIT, Rank,
    USABLE_DBM, pick, pick_ranked, rank_better, rank_order,
};
