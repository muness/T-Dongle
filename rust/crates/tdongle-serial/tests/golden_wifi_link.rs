//! `wifi_link` against the real `wifi_link.h` (golden/wifi_link.golden).

mod common;

use common::*;
use tdongle_serial::wifi_link::{self, Info, JoinState};

#[test]
fn line_and_json_match_the_c_header_at_every_capacity() {
    let all = scenarios();
    let golden = golden("wifi_link.golden");
    let mut cases = 0;
    let mut refused = 0;
    for sc in all["wifi_link"].as_array().expect("scenarios") {
        let name = sc["name"].as_str().expect("name");
        let (l, e) = (link(&sc["link"]), events(&sc["events"]));
        for (entry_name, body) in golden.iter().filter(|(n, _)| n.starts_with(&format!("{name}/"))) {
            let (what, cap) =
                entry_name[name.len() + 1..].split_once('@').map_or((&entry_name[name.len() + 1..], 0), |(w, c)| (w, c.parse::<usize>().expect("cap")));
            let mut buf = vec![b'x'; cap + 8];
            let got = match what {
                "line" => wifi_link::line(&mut buf[..cap], &l, &e),
                "json" => wifi_link::json(&mut buf[..cap], &l, &e),
                "rssi_text" => {
                    assert_eq!(l.rssi_text().to_string().as_bytes(), &body[..], "{entry_name}");
                    continue;
                }
                other => panic!("{other}"),
            };
            cases += 1;
            match got {
                Some(n) => {
                    assert_eq!(&buf[..n], &body[..], "{entry_name}");
                    assert_eq!(buf[n], 0, "{entry_name}: C stores the terminator");
                    assert!(n < cap, "{entry_name}");
                }
                None => {
                    refused += 1;
                    assert!(body.is_empty(), "{entry_name}: Rust refused, C produced {:?}", String::from_utf8_lossy(body));
                    assert_eq!(buf[0], 0, "{entry_name}: a refusal leaves the empty string, like C");
                }
            }
            // The unbounded sinks give the same text as a big enough buffer.
            if !body.is_empty() {
                let text = if what == "line" { render(|w| wifi_link::write_line(w, &l, &e)) } else { render(|w| wifi_link::write_json(w, &l, &e)) };
                assert_eq!(text.as_bytes(), &body[..], "{entry_name}");
            }
        }
    }
    assert!(cases > 600 && refused > 50, "{cases} cases, {refused} refusals");
}

#[test]
fn names_modes_and_rssi_tokens_match_the_c_header_for_every_raw_value() {
    let golden = golden("wifi_link.golden");
    for v in 0u32..300 {
        let want = String::from_utf8(entry(&golden, &format!("names/{v}")).to_vec()).expect("utf8");
        let got = format!(
            "phy={} secondary={} ps={} join={} modes={}",
            wifi_link::phy_name(v),
            wifi_link::secondary_name(v),
            wifi_link::ps_name(v),
            wifi_link::join_name(v),
            wifi_link::modes_text((v & 255) as u8)
        );
        assert_eq!(got, want, "value {v}");
    }
    for r in -128i32..=127 {
        let info = Info { connected: true, rssi_valid: true, rssi: i8::try_from(r).expect("i8"), ..Info::default() };
        assert_eq!(info.rssi_text().to_string().as_bytes(), entry(&golden, &format!("rssi/{r}")), "rssi {r}");
    }
}

#[test]
fn join_state_follows_the_c_precedence() {
    for bits in 0..8u8 {
        let info = Info { connected: bits & 1 != 0, pinned: bits & 2 != 0, pin_failed_slot: bits >> 2, ..Info::default() };
        let want = if info.connected {
            JoinState::Connected
        } else if info.pinned {
            JoinState::Joining
        } else if info.pin_failed_slot != 0 {
            JoinState::Failed
        } else {
            JoinState::Disconnected
        };
        assert_eq!(info.join_state(), want);
    }
}
