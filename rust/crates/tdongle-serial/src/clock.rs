//! Supervision of the SNTP wall clock: the port of `main/clock_sync.h` (`gw_clock_*`; tests: `tests/test_clock_sync.c`).
//!
//! TLS certificate validity cannot be judged before the clock is set, so the DERP relay waits for it. A clock that never arrives must be
//! a visible fault, not a silent one: while the clock is wrong and the uplink is up, [`Clock::poll`] asks, on a doubling schedule, for
//! the SNTP client to be restarted against the next server of [`SERVER_NAMES`]. It never blocks and never gates anything itself.

use core::fmt;

/// `GW_CLOCK_SERVERS`.
pub const SERVERS: usize = 3;
/// Delay after the uplink comes up before the first restart (`GW_CLOCK_FIRST_RETRY_MS`).
pub const FIRST_RETRY_MS: u32 = 30_000;
/// Backoff ceiling (`GW_CLOCK_MAX_RETRY_MS`).
pub const MAX_RETRY_MS: u32 = 600_000;
/// `gw_clock_server_name`.
pub const SERVER_NAMES: [&str; SERVERS] = ["pool.ntp.org", "time.cloudflare.com", "time.google.com"];

/// What the manager task must do after a poll (`gw_clock_action`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Nothing.
    Nothing,
    /// Restart SNTP with [`Clock::server_name`].
    Restart,
}

/// The one word `status` and `/status` print for the clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The wall clock is set.
    Synced,
    /// No uplink: nothing can be asked of a server yet.
    WaitingForNetwork,
    /// Uplink up, no restart needed so far.
    Syncing,
    /// At least one restart was needed.
    Failing,
}

impl State {
    /// The text: `synced`, `waiting_for_network`, `syncing` or `failing`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::WaitingForNetwork => "waiting_for_network",
            Self::Syncing => "syncing",
            Self::Failing => "failing",
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The supervisor state (`gw_clock_t`). All-zero is the initial state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Clock {
    /// The wall clock has been plausible at least once.
    pub synced: bool,
    /// Index into [`SERVER_NAMES`] currently in use.
    pub server: u8,
    /// SNTP restarts requested because no time arrived.
    pub restarts: u32,
    /// Delay before the next restart.
    pub backoff_ms: u32,
    /// 0 = not armed (uplink down, or clock set); manager task only.
    pub next_retry_ms: u64,
    /// `next_retry_ms - now` as of the last poll: readable from any task (a 64 bit value is not read atomically on this CPU).
    pub retry_in_ms: u32,
}

impl Clock {
    /// `gw_clock_step`: the state machine alone.
    pub fn step(&mut self, now_ms: u64, clock_valid: bool, uplink_up: bool) -> Action {
        if clock_valid {
            self.synced = true;
            self.backoff_ms = 0;
            self.next_retry_ms = 0;
            return Action::Nothing;
        }
        if !uplink_up {
            // Nothing can be asked of a server yet.
            self.next_retry_ms = 0;
            return Action::Nothing;
        }
        if self.next_retry_ms == 0 {
            // The uplink just came up: give the first request time.
            self.backoff_ms = FIRST_RETRY_MS;
            self.next_retry_ms = now_ms.wrapping_add(u64::from(self.backoff_ms));
            return Action::Nothing;
        }
        if now_ms < self.next_retry_ms {
            return Action::Nothing;
        }
        self.restarts = self.restarts.wrapping_add(1);
        self.server = ((u32::from(self.server) + 1) % SERVERS as u32) as u8;
        self.backoff_ms = if self.backoff_ms >= MAX_RETRY_MS / 2 { MAX_RETRY_MS } else { self.backoff_ms.wrapping_mul(2) };
        self.next_retry_ms = now_ms.wrapping_add(u64::from(self.backoff_ms));
        Action::Restart
    }

    /// `gw_clock_poll`: [`step`](Self::step), then publish `retry_in_ms`.
    pub fn poll(&mut self, now_ms: u64, clock_valid: bool, uplink_up: bool) -> Action {
        let action = self.step(now_ms, clock_valid, uplink_up);
        self.retry_in_ms = if self.next_retry_ms > now_ms { (self.next_retry_ms - now_ms) as u32 } else { 0 };
        action
    }

    /// `gw_clock_state`: one word for `/status` and the serial console.
    #[must_use]
    pub const fn state(&self, clock_valid: bool, uplink_up: bool) -> State {
        if clock_valid {
            State::Synced
        } else if !uplink_up {
            State::WaitingForNetwork
        } else if self.restarts != 0 {
            State::Failing
        } else {
            State::Syncing
        }
    }

    /// The server in use: `gw_clock_server_name[server % GW_CLOCK_SERVERS]` (the modulo is what the status line applies).
    #[must_use]
    pub const fn server_name(&self) -> &'static str {
        SERVER_NAMES[self.server as usize % SERVERS]
    }
}
