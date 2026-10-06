use super::*;
use crate::report::{BootStatus, write_boot_status};
use proptest::prelude::*;

fn text<F: FnOnce(&mut std::string::String)>(f: F) -> std::string::String {
    let mut s = std::string::String::new();
    f(&mut s);
    s
}

#[test]
fn first_boot_is_normal() {
    let mut rec = Record::EMPTY;
    let boot = rec.begin_boot();
    assert!(!boot.safe_mode);
    assert_eq!(boot.previous.unstable_boots, 0);
    assert_eq!(boot.previous.panic_text(), "");
}

#[test]
fn power_on_garbage_is_an_empty_record() {
    for fill in [0u32, 0xffff_ffff, 0xdead_beef, 0x7d6c_b007] {
        let words = [fill; WORDS];
        let mut rec = Record::from_words(&words);
        assert!(!rec.begin_boot().safe_mode, "{fill:#x}");
    }
}

#[test]
fn two_unstable_boots_then_safe_mode_which_is_sticky() {
    let mut rec = Record::EMPTY;
    assert!(!rec.begin_boot().safe_mode); // boot 1, resets before stable
    assert!(!rec.begin_boot().safe_mode); // boot 2
    let third = rec.begin_boot();
    assert!(third.safe_mode);
    assert_eq!(third.previous.unstable_boots, 2);
    rec.mark_stable(third.safe_mode); // safe mode stays up: no change
    assert!(rec.begin_boot().safe_mode);
    rec.leave_safe_mode(); // console `normal`
    assert!(!rec.begin_boot().safe_mode);
}

#[test]
fn a_stable_boot_forgets_history() {
    let mut rec = Record::EMPTY;
    let _ = rec.begin_boot();
    let _ = rec.begin_boot();
    rec.note_panic(format_args!("boom"));
    let boot = rec.begin_boot();
    assert!(boot.safe_mode);
    let mut rec = Record::EMPTY;
    let _ = rec.begin_boot();
    rec.mark_stable(false);
    let boot = rec.begin_boot();
    assert!(!boot.safe_mode);
    assert_eq!(boot.previous.unstable_boots, 0);
    assert_eq!(boot.previous.panic_text(), "");
}

#[test]
fn stage_and_panic_reach_the_next_boot_through_rtc_words() {
    let mut rec = Record::EMPTY;
    let _ = rec.begin_boot();
    rec.note_stage(Stage::RadioInit);
    rec.note_panic(format_args!("src/main.rs:{} {}", 412, "called `Result::unwrap()` on an `Err` value"));
    let words = rec.to_words(); // the reset
    let mut rec = Record::from_words(&words);
    let boot = rec.begin_boot();
    assert_eq!(boot.previous.stage, Some(Stage::RadioInit));
    assert_eq!(boot.previous.panics, 1);
    assert_eq!(boot.previous.panic_text(), "src/main.rs:412 called `Result::unwrap()` on an `Err` value");
    assert_eq!(rec.stage(), Some(Stage::Boot));
}

#[test]
fn long_panic_text_is_cut_on_a_character_boundary() {
    let mut rec = Record::EMPTY;
    let long: std::string::String = "ä".repeat(200);
    rec.note_panic(format_args!("{long}"));
    let boot = Record::from_words(&rec.to_words()).begin_boot();
    let t = boot.previous.panic_text();
    assert!(t.len() <= MSG_MAX && !t.is_empty());
    assert!(t.chars().all(|c| c == 'ä'));
}

#[test]
fn a_corrupt_length_or_text_is_dropped_not_trusted() {
    let mut rec = Record::EMPTY;
    rec.note_panic(format_args!("x"));
    let mut words = rec.to_words();
    words[1] = (words[1] & 0x00ff_ffff) | (250u32 << 24); // msg_len = 250 > MSG_MAX
    assert_eq!(Record::from_words(&words), Record::EMPTY);
    let mut words = rec.to_words();
    words[2] = 0xffff_ffff; // invalid UTF-8 in the text (length 1 covers byte 8 only)
    assert_eq!(Record::from_words(&words), Record::EMPTY);
}

#[test]
fn boot_status_is_one_valid_json_line_with_escaped_text() {
    let elf = [0xabu8; 32];
    let s = BootStatus {
        firmware: "0.3.0-rust",
        elf: &elf,
        reset_reason: "CoreMwdt0",
        stage: "usb",
        previous_stage: "radio_init",
        previous_panic: "src/a.rs:1 \"quote\" back\\slash \u{1} tab\t newline\n ünïcode",
        safe_mode: true,
        unstable_boots: 2,
        uptime_ms: 1234,
        free_heap: Some(99_000),
    };
    let line = text(|o| write_boot_status(o, &s).unwrap());
    assert!(!line.contains('\n') && !line.contains('\r'));
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["elf"], "ab".repeat(32));
    assert_eq!(v["previous_panic"], s.previous_panic);
    assert_eq!(v["safe_mode"], true);
    assert_eq!(v["recovery"], true);
    assert_eq!(v["previous_stage"], "radio_init");
    assert_eq!(v["free_memory"], 99_000);
}

proptest! {
    #[test]
    fn any_words_decode_and_begin_boot_without_panicking(words in proptest::collection::vec(any::<u32>(), WORDS)) {
        let words: [u32; WORDS] = words.try_into().unwrap();
        let mut rec = Record::from_words(&words);
        let boot = rec.begin_boot();
        let _ = boot.previous.panic_text();
        prop_assert_eq!(Record::from_words(&rec.to_words()), rec);
    }

    #[test]
    fn panic_text_always_fits_and_round_trips(s in ".{0,300}") {
        let mut rec = Record::EMPTY;
        rec.note_panic(format_args!("{s}"));
        let back = Record::from_words(&rec.to_words());
        let boot = { let mut b = back; b.begin_boot() };
        prop_assert!(boot.previous.panic_text().len() <= MSG_MAX);
        prop_assert!(s.starts_with(boot.previous.panic_text()));
    }
}

#[test]
fn stage_bytes_round_trip() {
    for s in Stage::ALL {
        assert_eq!(Stage::from_byte(s as u8), Some(s));
    }
    assert_eq!(Stage::from_byte(7), None);
}
