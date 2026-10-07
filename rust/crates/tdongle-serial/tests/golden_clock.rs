//! `clock` against the real `clock_sync.h` (golden/clock.golden).

mod common;

use common::*;
use tdongle_serial::clock::{self, Action, Clock};

fn describe(step: usize, action: Action, c: &Clock, valid: bool, up: bool) -> String {
    format!(
        "step={step} action={} synced={} server={} restarts={} backoff_ms={} next_retry_ms={} retry_in_ms={} state={}\n",
        u8::from(action == Action::Restart),
        u8::from(c.synced),
        c.server,
        c.restarts,
        c.backoff_ms,
        c.next_retry_ms,
        c.retry_in_ms,
        c.state(valid, up)
    )
}

#[test]
fn step_and_poll_traces_match_the_c_header() {
    let all = scenarios();
    let golden = golden("clock.golden");
    for sc in all["clock"].as_array().expect("clock") {
        let name = sc["name"].as_str().expect("name");
        let mut c = clock(&sc["initial"]);
        let mut got = String::new();
        for (i, step) in sc["steps"].as_array().expect("steps").iter().enumerate() {
            let kind = step[0].as_str().expect("kind");
            let now = step[1].as_u64().expect("now");
            let (valid, up) = (step[2].as_i64() != Some(0), step[3].as_i64() != Some(0));
            let action = if kind == "poll" { c.poll(now, valid, up) } else { c.step(now, valid, up) };
            got += &describe(i, action, &c, valid, up);
        }
        assert_eq!(got.as_bytes(), entry(&golden, name), "clock scenario {name}");
    }
}

#[test]
fn state_words_and_constants_match_the_c_header() {
    let all = scenarios();
    let golden = golden("clock.golden");
    let mut got = String::new();
    for st in all["clock_states"].as_array().expect("states") {
        let c = Clock { restarts: u32_of(st, "restarts"), ..Clock::default() };
        let (valid, up) = (u32_of(st, "valid") != 0, u32_of(st, "up") != 0);
        got += &format!("restarts={} valid={} up={} state={}\n", c.restarts, u8::from(valid), u8::from(up), c.state(valid, up));
    }
    assert_eq!(got.as_bytes(), entry(&golden, "states"));
    let constants = format!(
        "servers={} first_retry_ms={} max_retry_ms={} names={}\n",
        clock::SERVERS,
        clock::FIRST_RETRY_MS,
        clock::MAX_RETRY_MS,
        clock::SERVER_NAMES.join(",")
    );
    assert_eq!(constants.as_bytes(), entry(&golden, "constants"));
}
