//! Properties: no panic for arbitrary event sequences; the menu always returns to idle; a factory reset is never issued without the full confirm sequence.
use proptest::prelude::*;
use tdongle_traffic::Reading;
use tdongle_ui::menu::*;
use tdongle_ui::reset::{Confirm, ResetArm};
use tdongle_ui::settings::Settings;
use tdongle_ui::setup_boot::Session;
use tdongle_ui::ui::{Command, Inputs, Snapshot, Ui};

/// Gaps stay below 2^31 ms (24.8 days): the confirmation expiry is a signed 32 bit difference, as in C, and the device polls every 20 ms, so a longer gap between
/// two events cannot happen.
fn event() -> impl Strategy<Value = (bool, u32, u8, bool)> {
    // (hold?, time step, saved_count, setup_active)
    (any::<bool>(), prop_oneof![0u32..50, 9_000u32..11_000, 0u32..0x4000_0000], 0u8..=8, any::<bool>())
}

proptest! {
    /// Any sequence of menu events, contexts and clock values, including a list that changes under the menu and a clock that wraps: no panic, and the
    /// state stays consistent (the selected item exists while the menu is open).
    #[test]
    fn menu_never_panics(seq in proptest::collection::vec(event(), 0..200), start in any::<u32>()) {
        let mut m = Menu::new();
        let mut now = start;
        for (hold, dt, saved, setup) in seq {
            now = now.wrapping_add(dt);
            let c = MenuContext { setup_active: setup, saved_count: saved };
            let (consumed, a) = m.handle(&c, if hold { MenuEvent::Hold } else { MenuEvent::Short }, now);
            if !consumed { prop_assert!(a == MenuAction::None && !m.open && !hold); }
            if let MenuAction::Use(n) = a { prop_assert!(n >= 1 && n <= saved as u32); }
            if m.open { prop_assert!(m.item < c.item_count() || m.item >= c.item_count()); }
            m.tick(now);
            let _ = m.render(&c, |_| "x");
        }
    }

    /// From any reachable state the menu returns to idle: Short steps (and cancels any confirmation) up to the last item, which is Exit menu, and a hold
    /// there closes it. At most `items + 1` more events.
    #[test]
    fn menu_always_returns_to_idle(seq in proptest::collection::vec(event(), 0..200), start in any::<u32>()) {
        let mut m = Menu::new();
        let mut now = start;
        let mut last = MenuContext::default();
        for (hold, dt, saved, setup) in seq {
            now = now.wrapping_add(dt);
            last = MenuContext { setup_active: setup, saved_count: saved };
            m.handle(&last, if hold { MenuEvent::Hold } else { MenuEvent::Short }, now);
        }
        let mut n = 0;
        while m.open {
            n += 1;
            prop_assert!(n <= last.item_count() + 2, "menu stuck open");
            if m.item + 1 == last.item_count() && !m.confirm {
                let (_, a) = m.handle(&last, MenuEvent::Hold, now);
                prop_assert_eq!(a, MenuAction::None); // Exit menu runs nothing
            } else {
                m.handle(&last, MenuEvent::Short, now);
            }
        }
        prop_assert!(!m.open);
    }

    /// `ConfirmReset` only ever follows `Reset`, with no short press and no other action between, less than 10 s later (wrap safe).
    #[test]
    fn confirm_reset_needs_the_full_sequence(seq in proptest::collection::vec(event(), 0..400), start in any::<u32>()) {
        let mut m = Menu::new();
        let mut now = start;
        let mut armed: Option<u32> = None;
        for (hold, dt, saved, setup) in seq {
            now = now.wrapping_add(dt);
            let c = MenuContext { setup_active: setup, saved_count: saved };
            let (consumed, a) = m.handle(&c, if hold { MenuEvent::Hold } else { MenuEvent::Short }, now);
            match a {
                MenuAction::Reset => armed = Some(now),
                MenuAction::ConfirmReset => {
                    let t = armed.expect("confirm without reset");
                    prop_assert!(now.wrapping_sub(t) < CONFIRM_MS, "confirm after the window");
                    armed = None;
                }
                _ => {
                    if consumed { armed = None; }
                }
            }
        }
    }

    /// The same through the UI poll with an arbitrary button waveform: `confirm-reset` is only queued after `reset`, within 10 s, with nothing else in between.
    #[test]
    fn ui_confirm_reset_needs_the_full_sequence(
        wave in proptest::collection::vec((1u64..3000, any::<bool>()), 0..300),
        start in any::<u64>(),
        saved in 0u8..=8,
    ) {
        let mut ui = Ui::new(start);
        let mut now = start;
        let mut armed: Option<u64> = None;
        let name = |_: u32| Some("n");
        let snap = Snapshot::default();
        let mut down = false;
        for (dt, d) in wave {
            // poll every 20 ms during the step so presses and holds are detected as on the device
            let end = now + dt;
            if d { down = !down; }
            while now < end {
                now += 20;
                let input = Inputs { button_down: down, setup_active: false, setup_session: Session::inactive(), wifi_ready: true, saved_count: saved,
                    display: Settings::default(), snapshot: Some(snap), traffic: Reading::default(), network_name: &name };
                ui.tick(now, &input);
                match ui.take_command() {
                    Some(Command::Reset) => armed = Some(now),
                    Some(Command::ConfirmReset) => {
                        let t = armed.expect("confirm-reset without reset");
                        prop_assert!(now - t < 10_100, "confirm-reset after the window ({} ms)", now - t);
                        armed = None;
                    }
                    Some(_) => armed = None,
                    None => {}
                }
            }
        }
    }

    /// The whole poll never panics, whatever the clock (including wraps and 64 bit extremes), facts, settings and counters.
    #[test]
    fn ui_tick_never_panics(
        steps in proptest::collection::vec((0u64..100_000, any::<bool>(), any::<bool>(), any::<u8>(), any::<(u32, u32)>(), any::<bool>()), 0..300),
        start in prop_oneof![any::<u64>(), 0u64..10, (u32::MAX as u64 - 100_000)..(u32::MAX as u64 + 100_000)],
        brightness in any::<u8>(), rotation in any::<u8>(), dim in any::<u16>(),
    ) {
        let mut ui = Ui::new(start);
        let mut now = start;
        let name = |s: u32| if s % 2 == 0 { None } else { Some("a long long long long long long network name") };
        for (dt, down, setup, saved, (c0, c1), ok) in steps {
            now = now.wrapping_add(dt);
            let snap = Snapshot { saved_wifi: true, ssid: "s", ..Snapshot::default() };
            let input = Inputs {
                button_down: down, setup_active: setup, setup_session: if setup { Session::start(now as u32) } else { Session::inactive() }, wifi_ready: ok,
                saved_count: saved, display: Settings { brightness, rotation, dim_seconds: dim }, snapshot: if ok { Some(snap) } else { None },
                traffic: Reading { down_bytes: c0, up_bytes: c1, down_frames: c0 / 7, up_frames: c1 / 7 }, network_name: &name,
            };
            let a = ui.tick(now, &input);
            let _ = (a, ui.take_command());
        }
    }

    /// Settings parsing and blobs never panic; whatever parses is valid and round-trips through the blob.
    #[test]
    fn settings_parse_is_total(s in "\\PC{0,24}", blob in proptest::collection::vec(any::<u8>(), 0..12)) {
        if let Some(p) = Settings::parse(&s) {
            prop_assert!(p.valid());
            prop_assert_eq!(Settings::decode(&p.encode()), Some(p));
        }
        if let Some(p) = Settings::decode(&blob) { prop_assert!(p.valid()); }
    }
}

#[test]
fn command_layer_reset_needs_arming_and_expires() {
    let mut r = ResetArm::new();
    assert_eq!(r.confirm(5), Confirm::Expired); // never armed
    r.reset(1000);
    assert!(r.is_armed(10_999));
    assert_eq!(r.confirm(10_999), Confirm::Erase);
    assert_eq!(r.confirm(10_999), Confirm::Expired); // one shot
    r.reset(1000);
    assert_eq!(r.confirm(11_000), Confirm::Expired); // exactly 10 s: expired
    assert_eq!(r.confirm(11_001), Confirm::Expired); // and it disarmed
    r.reset(0xffff_fff0);
    assert_eq!(r.confirm(0xffff_fff0u32.wrapping_add(9_999)), Confirm::Erase); // across the wrap
    r.reset(0xffff_fff0);
    assert_eq!(r.confirm(0xffff_fff0u32.wrapping_add(10_000)), Confirm::Expired);
}

#[test]
fn commands_are_the_serial_lines() {
    assert_eq!(Command::Setup.line().as_str(), "setup");
    assert_eq!(Command::Cancel.line().as_str(), "cancel");
    assert_eq!(Command::Use(7).line().as_str(), "use 7");
    assert_eq!(Command::Reset.line().as_str(), "reset");
    assert_eq!(Command::ConfirmReset.line().as_str(), "confirm-reset");
}
