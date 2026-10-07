//! The app/bootloader protocol end to end, on the host: an app model that arms, may become healthy, and may fail, against the bootloader's decision.

use tdongle_rescue::*;

/// What the app does in one boot.
#[derive(Clone, Copy)]
enum App {
    /// Never arms (the C firmware): the word is left alone.
    Silent,
    /// Arms and then fails (any reset that keeps the RTC domain).
    Fails,
    /// Arms, becomes healthy, and is then reset (a deliberate or late failure).
    HealthyThenReset,
}

fn boot(store0: &mut u32, app: App, power_on: bool) -> BootDecision {
    let d = bootloader_decision(*store0, power_on);
    if let BootDecision::App(w) = d {
        *store0 = w;
        match app {
            App::Silent => {}
            App::Fails => *store0 = armed_word(*store0),
            App::HealthyThenReset => {
                *store0 = armed_word(*store0);
                let (_, count) = decode(*store0).unwrap();
                assert!(count < LIMIT);
                *store0 = word(HEALTHY, 0); // mark_healthy
            }
        }
    } else {
        *store0 = 0;
    }
    d
}

#[test]
fn two_unhealthy_boots_in_a_row_end_in_rom_download_mode() {
    let mut w = 0u32;
    assert!(matches!(boot(&mut w, App::Fails, true), BootDecision::App(_))); // power-on: boot A
    assert_eq!(decode(w), Some((ARMED, 0)));
    assert!(matches!(boot(&mut w, App::Fails, false), BootDecision::App(_))); // reset: boot B, count 1
    assert_eq!(decode(w), Some((ARMED, 1)));
    assert_eq!(boot(&mut w, App::Fails, false), BootDecision::DownloadMode, "the second failed boot in a row");
    assert_eq!(w, 0, "and the word is cleared so a flashed image runs normally");
    assert!(matches!(boot(&mut w, App::Fails, false), BootDecision::App(_)), "ROM download mode is left by a flash; the next app boot starts again");
}

#[test]
fn a_healthy_boot_resets_the_count() {
    let mut w = 0u32;
    let _ = boot(&mut w, App::Fails, true);
    let _ = boot(&mut w, App::Fails, false); // count 1
    assert!(matches!(boot(&mut w, App::HealthyThenReset, false), BootDecision::App(_)) || w == 0);
}

#[test]
fn healthy_then_reset_is_never_counted_against_the_app() {
    let mut w = word(HEALTHY, 0);
    for _ in 0..10 {
        assert!(matches!(boot(&mut w, App::HealthyThenReset, false), BootDecision::App(_)));
        assert_eq!(decode(w), Some((HEALTHY, 0)));
    }
}

#[test]
fn power_on_clears_and_silent_apps_are_unaffected() {
    let mut w = word(ARMED, 1);
    assert_eq!(bootloader_decision(w, true), BootDecision::App(0));
    w = 0x1234_5678; // not ours
    assert_eq!(bootloader_decision(w, false), BootDecision::App(w));
    let mut silent = 0u32;
    for _ in 0..5 {
        assert!(matches!(boot(&mut silent, App::Silent, false), BootDecision::App(_)));
        assert_eq!(silent, 0);
    }
}

#[test]
fn an_app_that_hangs_before_it_arms_still_counts() {
    // the bootloader hands state 0 with the count; an app that never gets as far as `arm` leaves it, and the next boot counts it
    let mut w = 0u32;
    let _ = boot(&mut w, App::Fails, true);
    let d1 = bootloader_decision(w, false);
    let BootDecision::App(handed) = d1 else { panic!() };
    assert_eq!(decode(handed), Some((HANDED, 1)));
    assert_eq!(bootloader_decision(handed, false), BootDecision::DownloadMode, "state 0 is not HEALTHY");
}

#[test]
fn arm_keeps_the_handed_count_and_ignores_foreign_words() {
    assert_eq!(armed_word(word(HANDED, 1)), word(ARMED, 1));
    assert_eq!(armed_word(0), word(ARMED, 0));
    assert_eq!(armed_word(0xDEAD_BEEF), word(ARMED, 0));
    assert_eq!(state_name(ARMED), "armed");
    assert_eq!(state_name(HEALTHY), "healthy");
}

#[test]
fn healthy_needs_thirty_continuous_seconds_and_one_bad_check_restarts_the_clock() {
    let mut t = HealthyTimer::new();
    for s in 0..30 {
        assert!(!t.observe(s * 1000, true), "{s}");
    }
    assert!(t.observe(30_000, true));
    let mut t = HealthyTimer::new();
    assert!(!t.observe(0, true));
    assert!(!t.observe(20_000, true));
    assert!(!t.observe(21_000, false), "a stalled heartbeat or an unconfigured USB");
    assert!(!t.observe(40_000, true), "the clock restarted at 40 s");
    assert!(!t.observe(69_000, true));
    assert!(t.observe(70_000, true));
    assert!(t.observe(71_000, false), "once healthy, stays reported healthy for the boot");
}

#[test]
fn every_reset_path_the_image_can_take_keeps_the_rtc_domain() {
    for path in IMAGE_RESET_PATHS {
        assert_eq!(path.scope(), ResetScope::DigitalOnly, "{path:?} would wipe STORE0 and the bootloader would see no magic");
    }
    // and the ones that do wipe it are exactly the ones the image must not use
    assert_eq!(ResetPath::RtcWatchdogResetsRtc.scope(), ResetScope::IncludingRtc, "the first release used this action: irqoff ended with count 0");
    assert_eq!(ResetPath::PowerOn.scope(), ResetScope::IncludingRtc);
    assert_eq!(RWDT_RESET, ResetScope::DigitalOnly);
}

#[test]
fn a_watchdog_reset_that_keeps_the_rtc_domain_is_counted_and_one_that_wipes_it_is_not() {
    // irqoff round 1 with a digital-only reset: the word survives and the bootloader counts it
    let armed_after_demote = demoted_word(0);
    assert_eq!(bootloader_decision(armed_after_demote, false), BootDecision::App(word(HANDED, 1)));
    // with the RTC wiped (the bug) the word is gone: the bootloader sees nothing and the count restarts
    assert_eq!(bootloader_decision(0, false), BootDecision::App(0));
}

#[test]
fn selftest_commands_parse() {
    assert_eq!(Selftest::parse("spin"), Some(Selftest::Spin));
    assert_eq!(Selftest::parse(" irqoff "), Some(Selftest::IrqOff));
    assert_eq!(Selftest::parse("panic"), Some(Selftest::Panic));
    assert_eq!(Selftest::parse("console"), Some(Selftest::Console));
    assert_eq!(Selftest::parse("usb"), Some(Selftest::Usb));
    assert_eq!(Selftest::parse("nope"), None);
}

#[test]
fn two_selftests_end_in_rom_mode_even_when_the_image_was_healthy() {
    // a healthy image (HEALTHY, count 0) runs the first selftest: it demotes with the handed count (0), then breaks
    let BootDecision::App(handed) = bootloader_decision(demoted_word(0), false) else { panic!("the first selftest must reboot into the app") };
    assert_eq!(decode(handed), Some((HANDED, 1)), "count 1 after the first selftest");
    // the app arms (keeping count 1), may even become healthy; the second selftest demotes with the handed count (1) and breaks
    assert_eq!(decode(armed_word(handed)), Some((ARMED, 1)));
    assert_eq!(bootloader_decision(demoted_word(1), false), BootDecision::DownloadMode, "the second selftest lands in ROM download mode");
}

#[test]
fn the_test_plan_of_the_board_in_the_model() {
    // `selftest spin` -> reset with count 1 -> `selftest spin` again -> ROM mode, no human involved
    let mut w = 0u32;
    let _ = boot(&mut w, App::Fails, true); // power-on, app armed
    let BootDecision::App(h) = bootloader_decision(w, false) else { panic!() };
    assert_eq!(decode(h).unwrap().1, 1, "the app sees count 1 after the first selftest");
    w = armed_word(h);
    assert_eq!(bootloader_decision(w, false), BootDecision::DownloadMode, "the second selftest in a row lands in ROM mode");
}

mod rwdt_registers {
    use tdongle_rescue::rwdt::*;

    #[test]
    fn the_value_written_to_wdtconfig0_is_exactly_this() {
        // EN | STG0=3 | CPU_RESET_LENGTH=7 | SYS_RESET_LENGTH=7 | PROCPU_RESET_EN | APPCPU_RESET_EN | PAUSE_IN_SLP, everything else 0
        assert_eq!(config0(Action::ResetDigital), 0xB007_EE00);
    }

    #[test]
    fn stage_actions_and_their_scope() {
        assert_eq!(config0(Action::ResetIncludingRtc), 0x8000_0000 | (4 << 28) | 0x0007_EE00);
        assert_eq!(config0(Action::ResetIncludingRtc), 0xC007_EE00);
        assert!(Action::ResetDigital.keeps_rtc() && !Action::ResetIncludingRtc.keeps_rtc());
        assert_eq!(Action::ResetDigital.reset_reason(), Some(9), "RTCWDT_SYS_RESET");
        assert_eq!(Action::ResetIncludingRtc.reset_reason(), Some(16), "RTCWDT_RTC_RESET: what the first two releases produced (SysRtcWdt)");
        assert_eq!(Action::from_config0(0xB007_EE00), Some(Action::ResetDigital));
    }

    #[test]
    fn what_boot_status_will_show_for_each_armed_state() {
        let good = Snapshot { config: [config0(Action::ResetDigital), 1_000_000, 0, 0, 0] };
        assert!(good.enabled() && good.safe_for_rescue() && !good.flashboot());
        // the esp-hal `enable()` clobber: it rewrites WDTCONFIG0 with stage 0 = 4 whatever was set before
        let clobbered = Snapshot { config: [config0(Action::ResetIncludingRtc), 1_000_000, 0, 0, 0] };
        assert!(clobbered.enabled() && !clobbered.safe_for_rescue());
        // disabled (what `esp_hal::init` did) and flash-boot protection still on (before the bootloader clears it)
        assert!(!Snapshot { config: [0, 0, 0, 0, 0] }.safe_for_rescue());
        assert!(Snapshot { config: [config0(Action::ResetDigital) | (1 << 12), 0, 0, 0, 0] }.flashboot());
        // an action that does not reset is not a rescue
        assert!(!Snapshot { config: [config0(Action::Interrupt), 0, 0, 0, 0] }.safe_for_rescue());
        assert_eq!(RTC_CNTL_BASE + WDTCONFIG0, 0x6000_8098);
        assert_eq!(RTC_CNTL_BASE + WDTWPROTECT, 0x6000_80B0);
        assert_eq!(RTC_CNTL_BASE + STORE0, 0x6000_8050);
    }

    #[test]
    fn the_only_selftest_visible_difference_between_the_two_actions_is_the_scope() {
        for a in [Action::ResetDigital, Action::ResetIncludingRtc] {
            assert!(a.reset_reason().is_some());
        }
        assert_eq!(config0(Action::ResetDigital) ^ config0(Action::ResetIncludingRtc), (3 ^ 4) << 28);
    }
}
