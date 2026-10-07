//! The line discipline of `console.c` `rx()`.

mod common;

use common::render;
use tdongle_serial::console::{self, Event, LINE_CHARS_MAX, LineReader, MGMT_CHUNK_MAX, OVERFLOW_REPLY, PROMPT, mgmt_chunks};

/// What the console produced for a byte stream, as owned values: `Some(line)` for a submitted line, a marker for the replies.
#[derive(Debug, PartialEq, Eq)]
enum Out {
    Line(String),
    Prompt,
    Overflow,
}

fn feed_all(reader: &mut LineReader, bytes: &[u8]) -> Vec<Out> {
    let mut out = Vec::new();
    for &b in bytes {
        match reader.feed(b) {
            Some(Event::Line(l)) => out.push(Out::Line(l.to_string())),
            Some(Event::Prompt) => out.push(Out::Prompt),
            Some(Event::Overflow) => out.push(Out::Overflow),
            None => {}
        }
    }
    out
}

fn run(bytes: &[u8]) -> Vec<Out> {
    feed_all(&mut LineReader::new(), bytes)
}

#[test]
fn a_line_ends_at_cr_or_lf() {
    assert_eq!(run(b"help\r"), [Out::Line("help".into())]);
    assert_eq!(run(b"help\n"), [Out::Line("help".into())]);
    assert_eq!(run(b"status\rlist\n"), [Out::Line("status".into()), Out::Line("list".into())]);
    assert_eq!(run(b"help"), []);
}

#[test]
fn an_empty_line_is_a_prompt_and_a_crlf_pair_is_a_line_then_a_prompt() {
    assert_eq!(run(b"\r"), [Out::Prompt]);
    assert_eq!(run(b"\n"), [Out::Prompt]);
    assert_eq!(run(b"\r\n\r\n"), [Out::Prompt, Out::Prompt, Out::Prompt, Out::Prompt]);
    // The documented consequence: CRLF after a command gives the line and then a prompt.
    assert_eq!(run(b"help\r\n"), [Out::Line("help".into()), Out::Prompt]);
    assert_eq!(PROMPT, "tdongle>\r\n");
}

#[test]
fn backspace_and_delete_erase_the_last_character() {
    assert_eq!(run(b"helx\x08p\r"), [Out::Line("help".into())]);
    assert_eq!(run(b"helx\x7fp\r"), [Out::Line("help".into())]);
    assert_eq!(run(b"ab\x08\x08\x08\x08c\r"), [Out::Line("c".into())], "erasing an empty line does nothing");
    assert_eq!(run(b"a\x08\r"), [Out::Prompt], "a line erased to nothing is an empty line");
}

#[test]
fn a_line_of_511_characters_is_accepted_and_512_is_discarded() {
    let ok = "a".repeat(LINE_CHARS_MAX);
    let mut input = ok.clone().into_bytes();
    input.push(b'\r');
    assert_eq!(run(&input), [Out::Line(ok)]);

    let mut input = "a".repeat(LINE_CHARS_MAX + 1).into_bytes();
    input.push(b'\r');
    assert_eq!(run(&input), [Out::Overflow]);
    assert_eq!(OVERFLOW_REPLY, "ERR line too long/invalid; discarded\r\n");
}

#[test]
fn a_non_printable_byte_discards_the_line_at_its_terminator() {
    for bad in [0u8, 1, 9, 27, 31, 128, 200, 255] {
        assert_eq!(run(&[b'a', bad, b'b', b'\r']), [Out::Overflow], "byte {bad}");
    }
    for ok in [32u8, 126] {
        assert_eq!(run(&[b'a', ok, b'\r']), [Out::Line(format!("a{}", char::from(ok)))]);
    }
    // Nothing is said until the terminator, and the next line is clean.
    let mut r = LineReader::new();
    assert_eq!(feed_all(&mut r, b"ab\x01cd"), []);
    assert!(r.overflowed());
    assert_eq!(feed_all(&mut r, b"\rhelp\r"), [Out::Overflow, Out::Line("help".into())]);
    assert!(!r.overflowed());
}

#[test]
fn a_doomed_line_stays_doomed_even_when_edited() {
    // C: BS/DEL still shorten `used` while `overflow` is set, but never clear it.
    assert_eq!(run(b"a\x01\x08\x08b\r"), [Out::Overflow]);
    assert_eq!(run(&[b"x".repeat(600), b"\x08".repeat(600), b"\r".to_vec()].concat()), [Out::Overflow]);
}

#[test]
fn an_overlong_line_followed_by_an_empty_one_prompts_after_the_error() {
    let mut input = "z".repeat(700).into_bytes();
    input.extend_from_slice(b"\r\n");
    assert_eq!(run(&input), [Out::Overflow, Out::Prompt]);
}

#[test]
fn event_replies_are_the_console_texts() {
    assert_eq!(Event::Prompt.reply(), Some(PROMPT));
    assert_eq!(Event::Overflow.reply(), Some(OVERFLOW_REPLY));
    assert_eq!(Event::Line("x").reply(), None);
}

#[test]
fn feeding_is_state_free_between_lines() {
    let mut r = LineReader::new();
    assert!(r.is_empty());
    feed_all(&mut r, b"abc");
    assert_eq!(r.len(), 3);
    feed_all(&mut r, b"\r");
    assert!(r.is_empty() && !r.overflowed());
}

#[test]
fn mgmt_write_chunks_cover_the_reply_in_pieces_of_127_bytes() {
    assert_eq!(MGMT_CHUNK_MAX, 127);
    assert_eq!(mgmt_chunks(b"").count(), 0);
    assert_eq!(mgmt_chunks(b"abc").collect::<Vec<_>>(), [b"abc".as_slice()]);
    let reply = vec![b'x'; 127 * 2 + 5];
    let sizes: Vec<usize> = mgmt_chunks(&reply).map(<[u8]>::len).collect();
    assert_eq!(sizes, [127, 127, 5]);
    assert_eq!(mgmt_chunks(&reply).flatten().copied().collect::<Vec<u8>>(), reply);
    assert_eq!(mgmt_chunks(&reply[..127]).count(), 1);
    assert_eq!(mgmt_chunks(&reply[..128]).count(), 2);
    // The longest report (the `help` text) goes out in several pieces whose concatenation is the text.
    let help = tdongle_serial::reply::HELP_BRIDGE;
    assert!(mgmt_chunks(help.as_bytes()).count() > 1);
    assert_eq!(mgmt_chunks(help.as_bytes()).flatten().copied().collect::<Vec<u8>>(), help.as_bytes());
}

#[test]
fn the_greeting_names_the_mode_and_the_version() {
    assert_eq!(render(|w| console::write_greeting(w, false, "0.3.0")), "T-Dongle-S3 adapter 0.3.0. Type help. Input is not echoed.\r\n");
    assert_eq!(render(|w| console::write_greeting(w, true, "0.3.0")), "T-Dongle-S3 tailnet 0.3.0. Type help. Input is not echoed.\r\n");
}
