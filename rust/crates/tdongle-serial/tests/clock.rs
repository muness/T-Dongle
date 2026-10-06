//! Port of `tests/test_clock_sync.c` (the `gw_clock_*` half; the DERP pacing half belongs to another crate).

use tdongle_serial::clock::{Action, Clock, FIRST_RETRY_MS, MAX_RETRY_MS, SERVERS, State};

#[test]
fn a_missing_wall_clock_is_retried_with_backoff_and_rotating_servers() {
    let mut c = Clock::default();
    let mut t: u64 = 5000;

    // Uplink down: nothing is asked of a server, nothing is armed.
    assert_eq!(c.poll(t, false, false), Action::Nothing);
    assert!(c.next_retry_ms == 0 && c.state(false, false).name() == "waiting_for_network");

    // Uplink up: the first request gets time, then restarts back off and rotate servers.
    assert_eq!(c.poll(t, false, true), Action::Nothing);
    assert_eq!(c.state(false, true), State::Syncing);
    assert_eq!(c.retry_in_ms, FIRST_RETRY_MS);
    assert_eq!(c.poll(t + u64::from(FIRST_RETRY_MS) - 1, false, true), Action::Nothing);
    t += u64::from(FIRST_RETRY_MS);
    assert_eq!(c.poll(t, false, true), Action::Restart);
    assert_eq!((c.restarts, c.server, c.backoff_ms), (1, 1, 2 * FIRST_RETRY_MS));
    assert_eq!(c.state(false, true).name(), "failing");
    let mut previous = c.backoff_ms;
    for _ in 0..30 {
        // a clock that never comes: bounded, never silent
        t += u64::from(c.backoff_ms);
        assert_eq!(c.poll(t - 1, false, true), Action::Nothing);
        assert_eq!(c.poll(t, false, true), Action::Restart);
        assert!(c.backoff_ms >= previous && c.backoff_ms <= MAX_RETRY_MS);
        assert!(usize::from(c.server) < SERVERS);
        previous = c.backoff_ms;
    }
    assert_eq!((c.backoff_ms, c.restarts), (MAX_RETRY_MS, 31));

    // Losing the uplink disarms the schedule; the backoff restarts from the first step.
    assert_eq!(c.poll(t + 1, false, false), Action::Nothing);
    assert_eq!(c.next_retry_ms, 0);
    assert_eq!(c.poll(t + 2, false, true), Action::Nothing);
    assert_eq!(c.backoff_ms, FIRST_RETRY_MS);

    // Once the clock is set the supervision stops and says so.
    assert_eq!(c.poll(t + 3, true, true), Action::Nothing);
    assert!(c.synced && c.next_retry_ms == 0 && c.retry_in_ms == 0);
    assert_eq!(c.state(true, true).name(), "synced");
}

#[test]
fn the_server_in_use_is_named_with_the_status_line_modulo() {
    let mut c = Clock::default();
    assert_eq!(c.server_name(), "pool.ntp.org");
    c.server = 1;
    assert_eq!(c.server_name(), "time.cloudflare.com");
    c.server = 2;
    assert_eq!(c.server_name(), "time.google.com");
    c.server = 3;
    assert_eq!(c.server_name(), "pool.ntp.org", "an out-of-range index wraps like `% GW_CLOCK_SERVERS`");
    c.server = 255;
    assert_eq!(c.server_name(), "pool.ntp.org");
}

#[test]
fn step_does_not_publish_retry_in_ms_but_poll_does() {
    let mut c = Clock::default();
    c.step(100, false, true);
    assert_eq!(c.retry_in_ms, 0);
    c.poll(101, false, true);
    assert_eq!(c.retry_in_ms, FIRST_RETRY_MS - 1);
}

#[test]
fn the_state_words_follow_the_c_precedence() {
    let failing = Clock { restarts: 2, ..Clock::default() };
    assert_eq!(failing.state(true, false), State::Synced, "a valid clock wins over everything");
    assert_eq!(failing.state(false, false), State::WaitingForNetwork);
    assert_eq!(failing.state(false, true), State::Failing);
    assert_eq!(Clock::default().state(false, true), State::Syncing);
}
