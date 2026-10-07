//! Ports of `tests/test_ui_settings.c`, plus a randomized comparison of the parser against a naive reference.
use tdongle_nvs_format::ui_settings::{BLOB_LEN, UiSettings, UiSettingsError};

fn ui(brightness: u8, rotation: u8, dim_seconds: u16) -> UiSettings {
    UiSettings { brightness, rotation, dim_seconds }
}

#[test]
fn defaults_and_ranges() {
    let s = UiSettings::default();
    assert_eq!(s, ui(60, 0, 60)); // v0.1.1 defaults
    assert!(s.valid());
    let t = |b, r, d| ui(b, r, d).valid();
    assert!(!t(4, 0, 60) && t(5, 0, 60) && t(100, 0, 60) && !t(101, 0, 60));
    assert!(t(60, 1, 60) && !t(60, 2, 60));
    assert!(!t(60, 0, 9) && t(60, 0, 10) && t(60, 0, 3600) && !t(60, 0, 3601));
}

#[test]
fn parse_accepts() {
    assert_eq!(UiSettings::parse(b"60 0 60"), Ok(ui(60, 0, 60)));
    assert_eq!(UiSettings::parse(b"100 1 3600"), Ok(ui(100, 1, 3600)));
    assert_eq!(UiSettings::parse(b"  5   0   10  "), Ok(ui(5, 0, 10)));
    assert_eq!(UiSettings::parse(b"075 1 0100"), Ok(ui(75, 1, 100)));
    assert_eq!(UiSettings::parse(b"00005 00000 00010"), Ok(ui(5, 0, 10)));
    assert_eq!(UiSettings::parse(b"60 0 60\0 trailing after NUL"), Ok(ui(60, 0, 60)));
}

#[test]
fn parse_refuses() {
    let bad: [&[u8]; 24] = [
        b"",
        b"60",
        b"60 0",
        b"60 0 60 1",
        b"60 0 60 x",
        b"4 0 60",
        b"101 0 60",
        b"60 2 60",
        b"60 0 9",
        b"60 0 3601",
        b"-5 0 60",
        b"+5 0 60",
        b"60,0,60",
        b"60 0 60abc",
        b"x 0 60",
        b"60 0 99999999",
        b"999999 0 60",
        b"6O 0 60",
        b"60\t0 60",
        b"60 0 60\n",
        b"60 0 600000",
        b"   ",
        b"60  0",
        b"256 0 60",
    ];
    for text in bad {
        assert!(UiSettings::parse(text).is_err(), "{:?}", String::from_utf8_lossy(text));
    }
    assert_eq!(UiSettings::parse(b"60 0 x"), Err(UiSettingsError::Malformed));
    assert_eq!(UiSettings::parse(b"4 0 60"), Err(UiSettingsError::OutOfRange));
}

/// A naive reference for the grammar: split on spaces, three tokens of 1 to 5 ASCII digits, range check.
fn reference(text: &[u8]) -> Option<UiSettings> {
    let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
    let text = &text[..end];
    let tokens: Vec<&[u8]> = text.split(|&b| b == b' ').filter(|t| !t.is_empty()).collect();
    if tokens.len() != 3 {
        return None;
    }
    let mut v = [0u64; 3];
    for (i, t) in tokens.iter().enumerate() {
        if t.len() > 5 || !t.iter().all(u8::is_ascii_digit) {
            return None;
        }
        v[i] = std::str::from_utf8(t).ok()?.parse().ok()?;
    }
    let s = ui(v[0].min(255) as u8, v[1].min(255) as u8, v[2].min(65535) as u16);
    s.valid().then_some(s)
}

#[test]
fn parse_matches_reference_on_random_text() {
    let mut state = 0x1234_5678_9abc_def1u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let alphabet = b"0123456789  -+x\t\n";
    let (mut accepted, mut total) = (0, 0);
    for round in 0..200_000 {
        let text: Vec<u8> = if round % 2 == 0 {
            let len = (next() % 20) as usize;
            (0..len).map(|_| alphabet[(next() % alphabet.len() as u64) as usize]).collect()
        } else {
            // Near-valid text: three numbers (often in range) with random spacing, then up to two random edits.
            let mut t = Vec::new();
            for n in [next() % 120, next() % 3, next() % 3700] {
                t.extend(std::iter::repeat_n(b' ', (next() % 3) as usize));
                t.extend(format!("{n:0width$}", width = (next() % 3) as usize + 1).bytes());
            }
            t.extend(std::iter::repeat_n(b' ', (next() % 3) as usize));
            for _ in 0..next() % 3 {
                let at = (next() % (t.len() as u64 + 1)) as usize;
                let c = alphabet[(next() % alphabet.len() as u64) as usize];
                match next() % 3 {
                    0 if at < t.len() => t[at] = c,
                    1 => t.insert(at, c),
                    _ if at < t.len() => {
                        t.remove(at);
                    }
                    _ => {}
                }
            }
            t
        };
        total += 1;
        let got = UiSettings::parse(&text).ok();
        assert_eq!(got, reference(&text), "{:?}", String::from_utf8_lossy(&text));
        accepted += usize::from(got.is_some());
    }
    assert!(accepted > 100, "the generator should hit valid input sometimes ({accepted} of {total})");
}

#[test]
fn backlight() {
    let mut s = ui(60, 0, 60);
    assert_eq!(s.backlight_percent(false), 60);
    assert_eq!(s.backlight_percent(true), 5);
    s.brightness = 5;
    assert_eq!(s.backlight_percent(true), 5); // dimming never brightens
    assert_eq!(UiSettings::backlight_duty(100), 0);
    assert_eq!(UiSettings::backlight_duty(0), 255); // active low: full brightness is duty 0
    assert_eq!(UiSettings::backlight_duty(60), 255 - 153);
    assert_eq!(UiSettings::backlight_duty(200), 0);
    let mut previous = 256;
    for p in 0..=100 {
        let d = UiSettings::backlight_duty(p);
        assert!(d <= previous && d <= 255);
        previous = d;
    }
}

#[test]
fn blob() {
    let s = ui(33, 1, 900);
    let b = s.to_bytes();
    assert_eq!(b.len(), BLOB_LEN);
    assert_eq!(b, [1, 0, 0, 0, 33, 1, 0x84, 0x03]); // schema@0, brightness@4, rotation@5, dim_seconds@6 little endian
    assert_eq!(UiSettings::from_bytes(&b), Ok(s));
    let with = |i: usize, v: u8| {
        let mut x = b;
        x[i] = v;
        UiSettings::from_bytes(&x)
    };
    assert_eq!(with(0, 2), Err(UiSettingsError::BadSchema));
    assert_eq!(with(1, 1), Err(UiSettingsError::BadSchema));
    assert_eq!(with(4, 1), Err(UiSettingsError::OutOfRange));
    assert_eq!(with(5, 2), Err(UiSettingsError::OutOfRange));
    assert_eq!(with(7, 0xff), Err(UiSettingsError::OutOfRange));
    assert_eq!(UiSettings::from_bytes(&b[..7]), Err(UiSettingsError::WrongSize));
    assert_eq!(UiSettings::from_bytes(&[&b[..], &[0]].concat()), Err(UiSettingsError::WrongSize));
    assert_eq!(UiSettings::from_bytes(&[]), Err(UiSettingsError::WrongSize));
}
