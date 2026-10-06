//! The serial path end to end, in the pure parts: bytes in, `LineReader`, `Command::parse`, reply texts out. The firmware only adds queues,
//! storage and restarts around this (`tests/test_serial_commands.c` exercises those with mocks; the cases that are pure are here).

use tdongle_serial::command::{Command, DisplayArgs, SetupArg, SlotArg};
use tdongle_serial::console::{Event, LineReader};
use tdongle_serial::reply;

/// What a minimal firmware would send for the pure commands: the console replies, the reply of `help`/`capabilities`/unknown, and `done>`.
fn session(input: &[u8], tailnet: bool) -> String {
    let mut reader = LineReader::new();
    let mut out = String::new();
    for &b in input {
        let command_line = match reader.feed(b) {
            None => continue,
            Some(Event::Line(line)) => line.to_string(),
            Some(event) => {
                out += event.reply().expect("console reply");
                continue;
            }
        };
        match Command::parse(&command_line) {
            Command::Help => reply::write_help(&mut out, tailnet, "").expect("write"),
            Command::Capabilities => reply::write_capabilities(&mut out, tailnet, "").expect("write"),
            Command::Display(DisplayArgs::Invalid) => out += reply::DISPLAY_USAGE,
            Command::Setup(SetupArg::Invalid) => out += reply::SETUP_USAGE,
            Command::Use(SlotArg::TrailingGarbage) => out += reply::USE_INVALID,
            Command::Cancel => out += reply::CANCEL_NOOP,
            Command::Reset => out += reply::RESET_ARMED,
            Command::Unknown => reply::write_unknown(&mut out, tailnet).expect("write"),
            other => panic!("not a pure command: {other:?}"),
        }
        out += reply::DONE;
    }
    out
}

#[test]
fn help_over_a_terminal_that_sends_lf() {
    assert_eq!(session(b"help\n", false), format!("{}done>\r\n", reply::HELP_BRIDGE));
    assert_eq!(session(b"help\n", true), format!("{}done>\r\n", reply::HELP_TAILNET));
}

#[test]
fn crlf_terminals_see_a_prompt_after_every_command() {
    assert_eq!(session(b"cancel\r\n", false), "OK setup saved\r\ndone>\r\ntdongle>\r\n");
}

#[test]
fn a_bad_byte_is_reported_once_and_the_next_command_works() {
    assert_eq!(session(b"he\x00lp\rreset\r", false), "ERR line too long/invalid; discarded\r\nConfirm within 10 seconds: confirm-reset\r\ndone>\r\n");
}

#[test]
fn unknown_commands_name_the_mode_specific_hint() {
    assert_eq!(session(b"nonsense\r", false), "ERR Unknown command; type help\r\ndone>\r\n");
    assert_eq!(session(b"nonsense\r", true), "ERR Unknown command; type help. USB setup: http://192.168.77.1/\r\ndone>\r\n");
}

#[test]
fn the_error_replies_of_the_front_panel_commands() {
    assert_eq!(session(b"display 4 0 60\r", false), "ERR display: brightness 5..100 rotation 0|1 dim 10..3600 seconds\r\ndone>\r\n");
    assert_eq!(session(b"setup 9\r", false), "ERR setup: optionally a saved network number 1 to 8\r\ndone>\r\n");
    assert_eq!(session(b"use 1x\r", false), "ERR Invalid saved network\r\ndone>\r\n");
}

#[test]
fn backspace_edits_before_dispatch() {
    assert_eq!(session(b"helx\x7fp\r", false), format!("{}done>\r\n", reply::HELP_BRIDGE));
}
