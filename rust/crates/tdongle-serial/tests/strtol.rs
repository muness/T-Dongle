//! `strtol` / `strtoul` against the C library on ~1500 inputs (golden/strtol.golden).
//!
//! The golden was produced on a 64 bit `long`; the dongle's is 32 bits. The two agree except where a value leaves the 32 bit range, where
//! the 32 bit library saturates (`LONG_MAX`, `LONG_MIN`, `ULONG_MAX`): the expectation below applies that to the 64 bit result.

mod common;

use common::{golden, hex, scenarios};
use tdongle_serial::command::{strtol, strtoul};

#[test]
fn number_parsing_agrees_with_the_c_library() {
    let all = scenarios();
    let inputs = all["strtol"].as_array().expect("inputs");
    let golden = golden("strtol.golden");
    assert_eq!(inputs.len(), golden.len());
    assert!(inputs.len() > 1500);
    for (hex_text, (name, body)) in inputs.iter().zip(&golden) {
        let input = String::from_utf8(hex(hex_text.as_str().expect("hex"))).expect("ascii input");
        let text = String::from_utf8(body.clone()).expect("utf8");
        let f: Vec<&str> = text.split_whitespace().collect();
        let (c_long, c_rest, c_ulong, c_rest2): (i64, usize, u64, usize) =
            (f[0].parse().expect("long"), f[1].parse().expect("rest"), f[2].parse().expect("ulong"), f[3].parse().expect("rest"));

        let (value, rest) = strtol(&input);
        let want = i32::try_from(c_long.clamp(i64::from(i32::MIN), i64::from(i32::MAX))).expect("clamped");
        assert_eq!((value, rest.len()), (want, c_rest), "strtol({input:?}) [{name}]");

        let (uvalue, urest) = strtoul(&input);
        let negative = input.trim_start_matches([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']).starts_with('-');
        let want = if negative && c_ulong != 0 && ((c_ulong >> 32) != 0xFFFF_FFFF || c_ulong & 0xFFFF_FFFF == 0) {
            u32::MAX // out of range for a 32 bit long: ULONG_MAX whatever the sign
        } else if negative {
            (c_ulong & 0xFFFF_FFFF) as u32
        } else {
            u32::try_from(c_ulong.min(u64::from(u32::MAX))).expect("clamped")
        };
        assert_eq!((uvalue, urest.len()), (want, c_rest2), "strtoul({input:?}) [{name}]");
    }
}
