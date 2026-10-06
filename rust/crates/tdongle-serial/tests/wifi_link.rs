//! Port of `tests/test_wifi_link.c` (the wifi_link.h part): names, rssi tokens, join states, event counters, roams, exact text, bounds.

use tdongle_serial::wifi_link::{self as wl, Events, Info, JSON_MAX, JoinState, LINE_MAX};

fn json_text(l: &Info, e: &Events) -> String {
    let mut s = String::new();
    wl::write_json(&mut s, l, e).expect("write");
    s
}

fn line_text(l: &Info, e: &Events) -> String {
    let mut s = String::new();
    wl::write_line(&mut s, l, e).expect("write");
    s
}

fn link_full() -> Info {
    Info {
        connected: true,
        rssi_valid: true,
        rssi: -61,
        channel: 6,
        secondary: 1,
        phy: wl::PHY_HT40,
        bw_cfg_mhz: 40,
        ap_bw_mhz: 40,
        ap_modes: wl::AP_B | wl::AP_G | wl::AP_N,
        ps: 0,
        tx_power_valid: true,
        tx_power_qdbm: 78,
        selected_slot: 2,
        pinned: true,
        pin_failed_slot: 0,
    }
}

fn link_widest() -> Info {
    Info {
        connected: true,
        rssi_valid: true,
        rssi: -128,
        channel: 255,
        secondary: 2,
        phy: wl::PHY_VHT20,
        bw_cfg_mhz: 255,
        ap_bw_mhz: 255,
        ap_modes: 255,
        ps: 2,
        tx_power_valid: true,
        tx_power_qdbm: -128,
        selected_slot: 255,
        pinned: true,
        pin_failed_slot: 255,
    }
}

fn widest_events() -> Events {
    Events {
        connects: u32::MAX,
        disconnects: u32::MAX,
        beacon_timeouts: u32::MAX,
        last_disconnect_ms: u32::MAX,
        last_reason: u16::MAX,
        last_disconnect_rssi: -128,
        ..Events::default()
    }
}

#[test]
fn names() {
    assert_eq!(wl::phy_name(wl::PHY_11B.into()), "11b");
    assert_eq!(wl::phy_name(wl::PHY_11G.into()), "11g");
    assert_eq!(wl::phy_name(wl::PHY_HT20.into()), "HT20");
    assert_eq!(wl::phy_name(wl::PHY_HT40.into()), "HT40");
    assert_eq!(wl::phy_name(wl::PHY_UNKNOWN.into()), "unknown");
    assert_eq!(wl::phy_name(8), "unknown");
    assert_eq!(wl::phy_name(wl::PHY_COUNT), "unknown");
    assert_eq!(wl::secondary_name(0), "none");
    assert_eq!(wl::secondary_name(1), "above");
    assert_eq!(wl::secondary_name(2), "below");
    assert_eq!(wl::secondary_name(3), "unknown");
    assert_eq!(wl::ps_name(0), "none");
    assert_eq!(wl::ps_name(1), "min_modem");
    assert_eq!(wl::ps_name(2), "max_modem");
    assert_eq!(wl::ps_name(wl::PS_UNKNOWN.into()), "unknown");
    assert_eq!(wl::modes_text(0).as_str(), "-");
    assert_eq!(wl::modes_text(wl::AP_B | wl::AP_G | wl::AP_N).as_str(), "bgn");
    assert_eq!(wl::modes_text(wl::AP_G | wl::AP_N | wl::AP_AX).as_str(), "gnax");
    assert_eq!(wl::modes_text(15).as_str(), "bgnax");
    assert_eq!(wl::modes_text(15).as_str().len(), 5);
}

#[test]
fn rssi_text() {
    let mut l = link_full();
    assert_eq!(l.rssi_text().to_string(), "-61");
    l.rssi = -128;
    assert_eq!(l.rssi_text().to_string(), "-128");
    l.rssi = 127;
    assert_eq!(l.rssi_text().to_string(), "127", "very strong signals can read positive");
    l.rssi = 0;
    assert_eq!(l.rssi_text().to_string(), "0");
    l.rssi_valid = false;
    assert_eq!(l.rssi_text().to_string(), "unknown");
    let mut l = link_full();
    l.connected = false;
    assert_eq!(l.rssi_text().to_string(), "unknown");
    // The token keeps matching Android's rssi=(?:unknown|-?\d+) for every value.
    for r in -128i16..=127 {
        let mut l = link_full();
        l.rssi = i8::try_from(r).expect("i8");
        assert_eq!(l.rssi_text().to_string().parse::<i16>(), Ok(r));
    }
}

#[test]
fn join_states() {
    let mut l = Info::default();
    assert_eq!(l.join_state(), JoinState::Disconnected);
    assert_eq!(l.join_state().name(), "disconnected");
    l.pinned = true;
    assert_eq!(l.join_state().name(), "joining");
    l.connected = true;
    assert_eq!(l.join_state().name(), "connected");
    let l = Info { pin_failed_slot: 3, ..Info::default() };
    assert_eq!(l.join_state().name(), "failed");
    let mut out = [0u8; JSON_MAX];
    let n = wl::json(&mut out, &l, &Events::default()).expect("fits");
    let text = core::str::from_utf8(&out[..n]).expect("ascii");
    assert!(text.contains("\"join\":\"failed\"") && text.contains("\"pin_failed_slot\":3"));
    assert_eq!(wl::join_name(99), "disconnected");
    assert_eq!(JoinState::from_u32(1), JoinState::Joining);
}

#[test]
fn events() {
    let mut e = Events::default();
    e.note_connect();
    e.note_disconnect(8, -70, 1000);
    assert_eq!((e.connects, e.disconnects, e.beacon_timeouts, e.last_reason, e.last_disconnect_rssi, e.last_disconnect_ms), (1, 1, 0, 8, -70, 1000));
    e.note_disconnect(wl::REASON_BEACON_TIMEOUT, -300, 2000); // clamped, never wrapped
    assert_eq!((e.disconnects, e.beacon_timeouts, e.last_reason, e.last_disconnect_rssi), (2, 1, 200, -128));
    e.note_disconnect(1, 500, 3000);
    assert_eq!((e.last_disconnect_rssi, e.beacon_timeouts), (127, 1));
    e.note_disconnect(0x1_0008, 0, 4000); // the C cast to uint16_t
    assert_eq!(e.last_reason, 8);
}

#[test]
fn roams() {
    let mut e = Events::default();
    let (a, b) = ([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]);
    e.note_association(Some(&a), 1000);
    assert_eq!((e.connects, e.roams, e.last_connect_ms, e.have_bssid), (1, 0, 1000, true), "the first association is not a roam");
    e.note_association(Some(&a), 2000);
    assert_eq!((e.connects, e.roams, e.last_connect_ms), (2, 0, 2000), "the same access point again: a reconnect");
    e.note_association(Some(&b), 3000);
    assert_eq!((e.connects, e.roams, e.last_bssid), (3, 1, b), "another one: a roam");
    e.note_association(Some(&a), 4000);
    assert_eq!((e.roams, e.last_connect_ms), (2, 4000));
    e.note_association(None, 5000); // no address in the event: counted, never a roam
    assert_eq!((e.connects, e.roams, e.last_bssid), (5, 2, a));
    e.note_disconnect(8, -70, 6000);
    assert_eq!((e.roams, e.have_bssid), (2, true), "losing the link is not a roam by itself");
    // The access point address stays out of every report.
    let l = link_full();
    let json = json_text(&l, &e);
    let line = line_text(&l, &e);
    assert!(!json.contains("bssid") && !json.contains("roams") && !line.contains("bssid") && !line.contains("roams"));
}

#[test]
fn json_exact() {
    let e =
        Events { connects: 3, disconnects: 2, beacon_timeouts: 1, last_disconnect_ms: 9000, last_reason: 200, last_disconnect_rssi: -85, ..Events::default() };
    assert_eq!(
        json_text(&link_full(), &e),
        "{\"connected\":true,\"join\":\"connected\",\"selected_slot\":2,\"pinned\":true,\"pin_failed_slot\":0,\"rssi_dbm\":-61,\"channel\":6,\"secondary\":\"above\",\"phy\":\"HT40\",\"bandwidth_cfg_mhz\":40,\
         \"ap_bandwidth_mhz\":40,\"ap_modes\":\"bgn\",\"power_save\":\"none\",\"tx_power_qdbm\":78,\"connects\":3,\"disconnects\":2,\
         \"beacon_timeouts\":1,\"last_disconnect_reason\":200,\"last_disconnect_rssi_dbm\":-85,\"last_disconnect_uptime_ms\":9000}"
    );
    let down = Info { phy: wl::PHY_UNKNOWN, ps: wl::PS_UNKNOWN, secondary: wl::SECOND_UNKNOWN, ..Info::default() };
    assert_eq!(
        json_text(&down, &e),
        "{\"connected\":false,\"join\":\"disconnected\",\"selected_slot\":0,\"pinned\":false,\"pin_failed_slot\":0,\"connects\":3,\"disconnects\":2,\"beacon_timeouts\":1,\"last_disconnect_reason\":200,\
         \"last_disconnect_rssi_dbm\":-85,\"last_disconnect_uptime_ms\":9000}"
    );
    let l = Info { rssi_valid: false, tx_power_valid: false, phy: wl::PHY_UNKNOWN, ps: wl::PS_UNKNOWN, ..link_full() };
    let text = json_text(&l, &e);
    for part in ["\"rssi_dbm\":null,", "\"phy\":\"unknown\"", "\"tx_power_qdbm\":null,", "\"power_save\":\"unknown\""] {
        assert!(text.contains(part), "{part} in {text}");
    }
    assert!(!text.contains("ssid") && !text.contains("bssid"));
}

#[test]
fn json_bounds() {
    // Widest possible values fit JSON_MAX with room to spare, and every shorter buffer refuses.
    let (l, e) = (link_widest(), widest_events());
    let mut big = [0u8; 1024];
    let n = wl::json(&mut big, &l, &e).expect("fits");
    assert!(n > 0 && n < JSON_MAX);
    let mut tight = [0u8; JSON_MAX];
    assert_eq!(wl::json(&mut tight, &l, &e), Some(n));
    for cap in 1..=n {
        let mut small = vec![b'x'; 1024];
        assert_eq!(wl::json(&mut small[..cap], &l, &e), None, "cap {cap}");
        assert!(small[..cap].contains(&0), "always terminated inside the capacity");
    }
    assert_eq!(wl::json(&mut [], &l, &e), None);
    let mut exactly = vec![0u8; n + 1];
    assert_eq!(wl::json(&mut exactly, &l, &e), Some(n), "the terminator needs one byte");
    let down = Info::default();
    assert!(wl::json(&mut big, &down, &e).expect("fits") < n);
}

#[test]
fn line_exact() {
    let e = Events { connects: 1, ..Events::default() };
    assert_eq!(
        line_text(&link_full(), &e),
        "wifi_link connected=1 join=connected selected=2 pinned=1 pin_failed=0 rssi_dbm=-61 channel=6 secondary=above phy=HT40 bandwidth_cfg_mhz=40 ap_bandwidth_mhz=40 ap_modes=bgn \
         power_save=none tx_power_qdbm=78 connects=1 disconnects=0 beacon_timeouts=0 last_disconnect_reason=0\r\n"
    );
    assert!(!line_text(&link_full(), &e).starts_with("mode="), "must not look like the Android status line");
    assert_eq!(
        line_text(&Info::default(), &e),
        "wifi_link connected=0 join=disconnected selected=0 pinned=0 pin_failed=0 connects=1 disconnects=0 beacon_timeouts=0 last_disconnect_reason=0\r\n"
    );
    let (l, e) = (link_widest(), widest_events());
    let mut big = [0u8; 1024];
    let n = wl::line(&mut big, &l, &e).expect("fits");
    assert!(n > 0 && n < LINE_MAX);
    let mut tight = [0u8; LINE_MAX];
    assert_eq!(wl::line(&mut tight, &l, &e), Some(n));
    for cap in 1..=n {
        let mut small = vec![b'x'; 1024];
        assert_eq!(wl::line(&mut small[..cap], &l, &e), None, "cap {cap}");
        assert!(small[..cap].contains(&0));
    }
    // An unknown transmit power reads `unknown`, a known one is a signed integer.
    let l = Info { tx_power_valid: false, ..link_full() };
    assert!(line_text(&l, &Events::default()).contains(" tx_power_qdbm=unknown connects="));
}
