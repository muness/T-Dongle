//! The Rust writer's key sequence over a fully populated `Status` equals the one tools/key_order.py extracts from the C source
//! (and tests/golden/key_order.txt, which is that script's checked-in output).

use tdongle_tailnet_status::*;

/// The keys of a JSON text in document order: every string that is followed by `:`.
pub fn keys(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let start = i + 1;
            i += 1;
            while b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            if b.get(i + 1) == Some(&b':') {
                out.push(text[start..i].to_string());
            }
        }
        i += 1;
    }
    out
}

pub fn full_status() -> Vec<u8> {
    let peers = [Peer { name: b"server.ts.net", address: 0x6402_0304 }];
    let client =
        Client { vpn_ip: 0x6401_0203, dns: b"dongle.ts.net", stack_free: [1, 2, u32::MAX, 4, 5], derp_state: b"ready", peers: &peers, ..Client::default() };
    let members = [Member { id: 1, label: b"work", enabled: true, client: Some(client), ..Member::default() }];
    let locks = [PmLock { name: b"<lock>", ..PmLock::default() }];
    let ssids: [&[u8]; 1] = [b"home"];
    let st = Status {
        firmware: b"0.3.0",
        mode: b"tailnet_gateway",
        chip_temperature: Temperature { samples: 1, ..Temperature::default() },
        power: Power { locks: &locks, ..Power::default() },
        wifi_link: Some(b"{}"),
        saved_wifi: &ssids,
        members: &members,
        ..Status::default()
    };
    let mut out = vec![];
    assert!(write_status(
        &mut |c: &[u8]| {
            out.extend_from_slice(c);
            true
        },
        &st
    ));
    out
}

#[test]
fn key_sequence_equals_the_c_source() {
    let json = String::from_utf8(full_status()).unwrap();
    serde_json::from_str::<serde_json::Value>(&json).unwrap();
    let rust = keys(&json);
    let golden: Vec<String> =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/key_order.txt")).unwrap().lines().map(String::from).collect();
    assert_eq!(rust, golden, "differs from the checked-in extraction");
    // Re-extract from the C source when python3 and the C tree are there: the checked-in file must not be stale.
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/key_order.py");
    if let Ok(o) =
        std::process::Command::new("python3").arg(script).output().and_then(|o| if o.status.success() { Ok(o) } else { Err(std::io::ErrorKind::Other.into()) })
    {
        let live: Vec<String> = String::from_utf8(o.stdout).unwrap().lines().map(String::from).collect();
        assert_eq!(rust, live, "differs from the keys the C source writes today");
    }
}

#[test]
fn no_key_is_repeated_inside_one_object() {
    // The Android app and setup.html index objects by key; the C never repeats one. serde would hide a repeat, so scan the text.
    let text = String::from_utf8(full_status()).unwrap();
    let b = text.as_bytes();
    let mut stack: Vec<Option<std::collections::HashSet<String>>> = vec![];
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'{' => stack.push(Some(Default::default())),
            b'[' => stack.push(None),
            b'}' | b']' => {
                stack.pop();
            }
            b'"' => {
                let start = i + 1;
                i += 1;
                while b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                if b.get(i + 1) == Some(&b':') {
                    let set = stack.last_mut().unwrap().as_mut().expect("a key outside an object");
                    assert!(set.insert(text[start..i].to_string()), "repeated key {}", &text[start..i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
}
