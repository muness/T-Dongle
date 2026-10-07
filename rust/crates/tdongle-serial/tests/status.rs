//! Hand-checked `status` text for a typical device (the shape every client parses), independent of the golden files.

use tdongle_serial::clock::Clock;
use tdongle_serial::memory_log::{MemoryLog, Record};
use tdongle_serial::status::{DisplayState, Mode, Prefs, Snapshot, Temperature, Traffic, write_status};
use tdongle_serial::wifi_link::{Events, Info};
use tdongle_traffic::Reading;

fn typical<'a>(memory: &'a MemoryLog, priorities: &'a [u8]) -> Snapshot<'a> {
    Snapshot {
        mode: Mode::Adapter,
        wifi_current: 1,
        online: true,
        firmware: "9.9.9-test",
        usb_mounted: true,
        usb_ready: true,
        uptime_ms: 4_294_967_296 + 17,
        free_heap: 100_000,
        temperature: Temperature {
            valid: true,
            current_tenths: 553,
            peak_tenths: 600,
            sampled_at_ms: 1200,
            errors: 0,
            samples: 7,
            changed_at_ms: 900,
            age_ms: 40,
        },
        clock: Clock { restarts: 0, ..Clock::default() },
        clock_valid: false,
        link: Info { connected: true, rssi_valid: true, rssi: -61, channel: 6, selected_slot: 2, ..Info::default() },
        events: Events { roams: 2, connects: 1, ..Events::default() },
        prefs: Prefs { saved: 2, preferred: Some(1), priorities, roaming_assist: true },
        display: DisplayState { brightness: 60, rotation: 0, dim_seconds: 60, page: 2 },
        setup_ap_name: "TDongle-AB0CF9",
        setup_seconds_left: 0,
        traffic: Traffic {
            counters: Reading { down_bytes: 1000, up_bytes: 2000, down_frames: 3, up_frames: 4 },
            down_kbps: 1234,
            up_kbps: 56,
            usb_resets: 3,
            control_stack_free_bytes: 1234,
        },
        memory,
    }
}

fn text(s: &Snapshot<'_>) -> String {
    let mut out = String::new();
    write_status(&mut out, s).expect("write");
    out
}

#[test]
fn a_typical_adapter_status() {
    let mut log = MemoryLog::new();
    log.note(Record { uptime_ms: 5000, operation: 4, requested: 512, free_bytes: 90_000, minimum_bytes: 80_000, largest_bytes: 60_000, failed: 0 }, false);
    let s = typical(&log, &[80, 30]);
    assert_eq!(
        text(&s),
        "mode=adapter trial=0 active=2 wifi=up rssi=-61 usb_enumerated=1 usb_transport_ready=1 host_interface_ready=unknown internet=not_checked\r\n\
         firmware=9.9.9-test\r\n\
         uptime_ms=4294967313 free_heap=100000\r\n\
         chip_temperature valid=1 current_tenths=553 peak_tenths=600 sampled_uptime_ms=1200 errors=0\r\n\
         chip_temperature_detail age_ms=40 samples=7 changed_uptime_ms=900 step_tenths=10\r\n\
         clock=syncing valid=0 sntp_restarts=0 server=pool.ntp.org retry_in_ms=0\r\n\
         wifi_link connected=1 join=connected selected=2 pinned=0 pin_failed=0 rssi_dbm=-61 channel=6 secondary=none phy=lr bandwidth_cfg_mhz=0 ap_bandwidth_mhz=0 ap_modes=- power_save=none \
         tx_power_qdbm=unknown connects=1 disconnects=0 beacon_timeouts=0 last_disconnect_reason=0\r\n\
         wifi_prefs saved=2 preferred=2 priorities=80,30 roaming_assist=1 roams=2\r\n\
         display brightness=60 rotation=0 dim_seconds=60 page=2\r\n\
         setup active=0 ap=- seconds_left=0\r\n\
         traffic down_bytes=1000 up_bytes=2000 down_frames=3 up_frames=4 down_kbps=1234 up_kbps=56 usb_resets=3 control_stack_free_bytes=1234\r\n\
         memory_pressure uptime_ms=5000 operation=4 requested=512 free=90000 minimum=80000 largest=60000 failed=0\r\n"
    );
}

#[test]
fn setup_mode_shows_the_access_point_and_no_networks_show_a_dash() {
    let log = MemoryLog::new();
    let mut s = typical(&log, &[]);
    s.mode = Mode::Setup;
    s.setup_seconds_left = 287;
    s.prefs = Prefs { saved: 0, preferred: None, priorities: &[], roaming_assist: true };
    s.online = false;
    s.wifi_current = -1;
    s.link = Info::default();
    let out = text(&s);
    assert!(out.starts_with("mode=setup trial=0 active=0 wifi=joining rssi=unknown "));
    assert!(out.contains("\r\nsetup active=1 ap=TDongle-AB0CF9 seconds_left=287\r\n"));
    assert!(out.contains("\r\nwifi_prefs saved=0 preferred=0 priorities=- roaming_assist=1 roams=2\r\n"));
    assert!(out.contains("\r\nclock=waiting_for_network valid=0 "));
    assert!(out.contains("\r\nwifi_link connected=0 join=disconnected "));
    assert!(!out.contains("memory_pressure"));
}

#[test]
fn temperature_before_the_first_sample_reports_the_max_age() {
    let log = MemoryLog::new();
    let mut s = typical(&log, &[]);
    s.temperature = Temperature { age_ms: u32::MAX, ..Temperature::default() };
    let out = text(&s);
    assert!(out.contains("\r\nchip_temperature valid=0 current_tenths=0 peak_tenths=0 sampled_uptime_ms=0 errors=0\r\n"));
    assert!(out.contains("\r\nchip_temperature_detail age_ms=4294967295 samples=0 changed_uptime_ms=0 step_tenths=10\r\n"));
}

#[test]
fn priorities_stop_where_the_c_loop_stops() {
    let log = MemoryLog::new();
    // Eight priorities of three digits: 3 + 7 * 4 = 31 characters, the longest the 33 byte buffer holds.
    let mut s = typical(&log, &[100; 8]);
    s.prefs.saved = 8;
    assert!(text(&s).contains("priorities=100,100,100,100,100,100,100,100 "));
    // More saved networks than the array has slots never reads past it (C has 8 slots).
    let mut s = typical(&log, &[1, 2, 3]);
    s.prefs.saved = 5;
    assert!(text(&s).contains("priorities=1,2,3,0,0 "));
}
