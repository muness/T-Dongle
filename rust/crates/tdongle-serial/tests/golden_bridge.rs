//! `bridge_report` against the real `bridge_status.inc`: the visitor's order and mapping, the line rule, and the identities.

mod common;

use common::*;
use serde_json::Value;
use tdongle_bridge::Stats;
use tdongle_serial::bridge_report::{self, LINE_MAX, LineWriter, Report, RingReport, RxClassReport, WifiTxReport};

fn u(v: &Value, key: &str) -> u32 {
    u32_of(v, key)
}

macro_rules! set_u32 {
    ($target:ident, $name:expr, $value:expr; $($field:ident),* $(,)?) => {
        match $name {
            $( stringify!($field) => $target.$field = u32::try_from($value).expect("u32"), )*
            other => panic!("unexpected field {other}"),
        }
    };
}

fn l2(v: &Value) -> Stats {
    let mut s = Stats::default();
    for (name, value) in v.as_object().expect("l2 object") {
        let value = value.as_i64().expect("number");
        match name.as_str() {
            "linked" => s.linked = value != 0,
            "h2w_last_tx_error" => s.h2w_last_tx_error = i32::try_from(value).expect("i32"),
            other => set_u32!(s, other, value;
                link_changes, worker_stack_free,
                w2h_frames, w2h_forwarded, w2h_invalid, w2h_own_mac, w2h_link_down, w2h_usb_not_ready, w2h_ring_full, w2h_raced,
                h2w_frames, h2w_queued, h2w_invalid, h2w_foreign_mac, h2w_link_down, h2w_held, h2w_resumes, h2w_sent, h2w_stale,
                h2w_sojourn_drop, h2w_link_down_queued, h2w_tx_failed, h2w_tx_retries, h2w_queue_depth, h2w_queue_high_water,
                h2w_codel_signals, h2w_ce_marked, h2w_codel_drop, h2w_codel_count,
                h2w_ecn_not_ect, h2w_ecn_capable, h2w_ecn_ce, h2w_ecn_exempt, h2w_ecn_not_ip, h2w_syn_ecn_setup, w2h_synack_ecn,
                pm_notes, pm_note_us_sum, pm_note_us_max, h2w_wait_us_sum, h2w_wait_us_max, h2w_tx_us_sum, h2w_tx_us_max,
                h2w_signal_us_sum, h2w_signal_us_max, h2w_room_waits, h2w_room_wait_us_sum, h2w_room_wait_us_max),
        }
    }
    s
}

fn ring(v: &Value) -> RingReport {
    RingReport {
        ring_bytes: u(v, "ring_bytes"),
        high_water_slabs: u(v, "high_water_slabs"),
        enqueued_frames: u(v, "enqueued_frames"),
        sent_frames: u(v, "sent_frames"),
        dropped_full: u(v, "dropped_full"),
        dropped_link_down: u(v, "dropped_link_down"),
        flushed_link_down: u(v, "flushed_link_down"),
        grow_events: u(v, "grow_events"),
        shrink_events: u(v, "shrink_events"),
        grow_denied_heap: u(v, "grow_denied_heap"),
        grow_denied_largest: u(v, "grow_denied_largest"),
        max_bytes: u(v, "max_bytes"),
        cold_starts: u(v, "cold_starts"),
        cold_us_sum: u(v, "cold_us_sum"),
        cold_us_max: u(v, "cold_us_max"),
    }
}

fn rx(v: &Value) -> RxClassReport {
    RxClassReport {
        ntbs: u(v, "ntbs"),
        ntb_bytes: u(v, "ntb_bytes"),
        ntb_max_bytes: u(v, "ntb_max_bytes"),
        datagrams: u(v, "datagrams"),
        dwell_us_sum: u(v, "dwell_us_sum"),
        dwell_us_max: u(v, "dwell_us_max"),
        holds: u(v, "holds"),
        hold_us_sum: u(v, "hold_us_sum"),
        hold_us_max: u(v, "hold_us_max"),
    }
}

fn wifi_tx(v: &Value) -> WifiTxReport {
    WifiTxReport {
        installed: flag(v, "installed"),
        tx_done_cb: flag(v, "tx_done_cb"),
        charged: u(v, "charged"),
        done: u(v, "done"),
        aborted: u(v, "aborted"),
        flushed: u(v, "flushed"),
        stale: u(v, "stale"),
        unmatched: u(v, "unmatched"),
        inflight: u(v, "inflight"),
        high_water: u(v, "high_water"),
        refused_pool: u(v, "refused_pool"),
        refused_heap: u(v, "refused_heap"),
    }
}

fn with_report<R>(sc: &Value, f: impl FnOnce(&Report<'_>) -> R) -> R {
    let (l2, ring, rx, wifi_tx) = (l2(&sc["l2"]), ring(&sc["ring"]), rx(&sc["rx"]), wifi_tx(&sc["wifi_tx"]));
    f(&Report { l2: &l2, ring: &ring, rx: &rx, wifi_tx: &wifi_tx })
}

#[test]
fn the_visit_order_is_the_order_of_the_e_lines_of_the_c_file() {
    let schema = String::from_utf8(std::fs::read(golden_dir().join("bridge_schema.golden")).expect("schema")).expect("utf8");
    let expected: Vec<(&str, &str)> = schema.lines().map(|l| l.split_once(' ').expect("pair")).collect();
    assert!(expected.len() > 70, "{}", expected.len());
    let zero = Report { l2: &Stats::default(), ring: &RingReport::default(), rx: &RxClassReport::default(), wifi_tx: &WifiTxReport::default() };
    let mut seen = Vec::new();
    bridge_report::visit(&zero, &mut |s, n, _| seen.push((s.to_string(), n.to_string())));
    let seen: Vec<(&str, &str)> = seen.iter().map(|(s, n)| (s.as_str(), n.as_str())).collect();
    assert_eq!(seen, expected);
    // Sections: contiguous, in the documented order, never revisited.
    let mut sections: Vec<&str> = Vec::new();
    for (s, _) in &seen {
        if sections.last() != Some(s) {
            sections.push(s);
        }
    }
    assert_eq!(sections, bridge_report::SECTIONS);
}

#[test]
fn the_json_field_lists_of_the_scenarios_are_the_fields_the_visitor_reads() {
    // Every field the C visitor reads has a value in the scenarios (and no other), so the mapping is exercised end to end.
    let all = scenarios();
    let fields = &all["bridge_fields"];
    let sc = &all["bridge"][0];
    for group in ["l2", "ring", "rx", "wifi_tx"] {
        let mut want: Vec<&str> = fields[group].as_array().expect("fields").iter().map(|f| f.as_str().expect("name")).collect();
        let mut have: Vec<&str> = sc[group].as_object().expect("group").keys().map(String::as_str).collect();
        want.sort_unstable();
        have.sort_unstable();
        assert_eq!(have, want, "{group}");
    }
}

#[test]
fn status_lines_match_the_real_c_visitor_and_renderer() {
    let all = scenarios();
    let golden = golden("bridge_status.golden");
    assert_eq!(all["bridge"].as_array().expect("bridge").len(), golden.len());
    for sc in all["bridge"].as_array().expect("bridge") {
        let name = sc["name"].as_str().expect("name");
        let got = with_report(sc, |r| render(|w| bridge_report::write_status_lines(w, r)));
        assert_eq!(got.as_bytes(), entry(&golden, name), "bridge scenario {name}");
    }
}

#[test]
fn every_line_stays_below_the_448_byte_buffer_with_the_worst_case_values() {
    let all = scenarios();
    for sc in all["bridge"].as_array().expect("bridge") {
        let name = sc["name"].as_str().expect("name");
        let text = with_report(sc, |r| render(|w| bridge_report::write_status_lines(w, r)));
        let lines: Vec<&str> = text.split_inclusive("\r\n").collect();
        assert_eq!(lines.len(), 8, "{name}: one line per section");
        for line in lines {
            assert!(line.ends_with("\r\n") && line.len() < LINE_MAX, "{name}: {} bytes", line.len());
        }
    }
    // The widest case is the one the C test pins: all counters at u32::MAX, the error at i32::MIN.
    let widest = all["bridge"].as_array().expect("bridge").iter().find(|s| s["name"] == "max_u32_with_error_min").expect("scenario");
    let text = with_report(widest, |r| render(|w| bridge_report::write_status_lines(w, r)));
    assert_eq!(text.lines().map(str::len).max(), Some(444));
}

#[test]
fn counter_identities_hold_on_the_sample_numbers() {
    let all = scenarios();
    let sc = all["bridge"].as_array().expect("bridge").iter().find(|s| s["name"] == "identities").expect("scenario");
    let stats = l2(&sc["l2"]);
    assert_eq!(stats.check_identities(), Ok(()));
    let w = wifi_tx(&sc["wifi_tx"]);
    assert_eq!(w.charged, w.done + w.aborted + w.flushed + w.stale + w.inflight);
    // The same identities, read back out of the rendered text (what a client sees).
    let text = with_report(sc, |r| render(|out| bridge_report::write_status_lines(out, r)));
    let value = |section: &str, name: &str| -> i64 {
        let line = text.lines().find(|l| l.starts_with(&format!("bridge_{section} "))).expect("section");
        line.split(' ').find_map(|f| f.strip_prefix(&format!("{name}="))).expect("field").parse().expect("number")
    };
    assert_eq!(
        value("to_host", "frames"),
        ["forwarded", "invalid", "own_mac", "link_down", "usb_not_ready", "ring_full"].iter().map(|n| value("to_host", n)).sum::<i64>()
    );
    assert_eq!(value("to_wifi", "frames"), ["queued", "invalid", "foreign_mac", "link_down"].iter().map(|n| value("to_wifi", n)).sum::<i64>());
    assert_eq!(
        value("to_wifi", "queued"),
        ["sent", "stale", "sojourn_drop", "link_down_queued", "tx_failed", "codel_drop", "queue_depth"].iter().map(|n| value("to_wifi", n)).sum::<i64>()
    );
    assert_eq!(value("wifi_tx", "charged"), ["done", "aborted", "flushed", "stale", "inflight"].iter().map(|n| value("wifi_tx", n)).sum::<i64>());
}

#[test]
fn known_sample_numbers_render_to_a_hand_checked_text() {
    let l2 = Stats {
        linked: true,
        link_changes: 2,
        worker_stack_free: 1500,
        w2h_frames: 10,
        w2h_forwarded: 9,
        w2h_own_mac: 1,
        h2w_frames: 5,
        h2w_queued: 5,
        h2w_sent: 5,
        h2w_last_tx_error: -3,
        h2w_ecn_capable: 4,
        pm_notes: 7,
        ..Stats::default()
    };
    let ring = RingReport {
        ring_bytes: 16384,
        max_bytes: 40960,
        enqueued_frames: 9,
        sent_frames: 9,
        cold_starts: 3,
        cold_us_sum: 450,
        cold_us_max: 200,
        ..RingReport::default()
    };
    let rx = RxClassReport { ntbs: 2, ntb_bytes: 3000, ntb_max_bytes: 1600, datagrams: 5, ..RxClassReport::default() };
    let wifi = WifiTxReport { installed: true, tx_done_cb: true, charged: 5, done: 5, ..WifiTxReport::default() };
    let text = render(|w| bridge_report::write_status_lines(w, &Report { l2: &l2, ring: &ring, rx: &rx, wifi_tx: &wifi }));
    let expected = "\
bridge_link linked=1 changes=2 worker_stack_free=1500\r\n\
bridge_to_host frames=10 forwarded=9 invalid=0 own_mac=1 link_down=0 usb_not_ready=0 ring_full=0 raced=0\r\n\
bridge_to_wifi frames=5 queued=5 invalid=0 foreign_mac=0 link_down=0 held=0 resumes=0 sent=5 stale=0 sojourn_drop=0 link_down_queued=0 tx_failed=0 tx_retries=0 last_tx_error=-3 queue_depth=0 queue_high_water=0 codel_signals=0 ce_marked=0 codel_drop=0 codel_count=0\r\n\
bridge_ecn not_ect=0 capable=4 ce=0 exempt=0 not_ip=0 syn_setup=0 synack_accept=0\r\n\
bridge_rx_class ntbs=2 ntb_bytes=3000 ntb_max_bytes=1600 datagrams=5 dwell_us_sum=0 dwell_us_max=0 holds=0 hold_us_sum=0 hold_us_max=0\r\n\
bridge_usb_ring ring_bytes=16384 high_water_slabs=0 enqueued=9 sent=9 dropped_full=0 dropped_link_down=0 flushed_link_down=0 grow_events=0 shrink_events=0 grow_denied_heap=0 grow_denied_largest=0 ring_max_bytes=40960\r\n\
bridge_timing cold_starts=3 cold_us_sum=450 cold_us_max=200 pm_notes=7 pm_note_us_sum=0 pm_note_us_max=0 wait_us_sum=0 wait_us_max=0 tx_us_sum=0 tx_us_max=0 signal_us_sum=0 signal_us_max=0 room_waits=0 room_wait_us_sum=0 room_wait_us_max=0\r\n\
bridge_wifi_tx installed=1 tx_done_cb=1 charged=5 done=5 aborted=0 flushed=0 stale=0 unmatched=0 inflight=0 high_water=0 refused_pool=0 refused_heap=0\r\n";
    assert_eq!(text, expected);
}

#[test]
fn the_line_renderer_matches_the_c_emitter_on_synthetic_sequences() {
    let all = scenarios();
    let golden = golden("bridge_emit.golden");
    assert_eq!(all["bridge_emit"].as_array().expect("emit").len(), golden.len());
    for sc in all["bridge_emit"].as_array().expect("emit") {
        let name = sc["name"].as_str().expect("name");
        let mut out = String::new();
        let mut lines = LineWriter::new(&mut out);
        for item in sc["seq"].as_array().expect("seq") {
            lines.emit(item[0].as_str().expect("section"), item[1].as_str().expect("name"), item[2].as_i64().expect("i64")).expect("emit");
        }
        lines.flush().expect("flush");
        assert_eq!(out.as_bytes(), entry(&golden, name), "sequence {name}");
    }
}

#[test]
fn a_field_that_does_not_fit_is_left_out_whole_and_a_shorter_one_still_fits() {
    let mut out = String::new();
    let mut lines = LineWriter::new(&mut out);
    for i in 0..18 {
        lines.emit("t", &format!("f{i:02}"), i64::MIN).expect("emit");
    }
    lines.emit("t", "this_name_is_long_enough_to_not_fit_x", i64::MIN).expect("emit");
    lines.emit("t", "s", 1).expect("emit");
    lines.flush().expect("flush");
    assert!(out.ends_with(" s=1\r\n"), "{out}");
    assert!(!out.contains("this_name"));
    assert!(out.len() < LINE_MAX, "{}", out.len());
    // i64 extremes print as %lld does.
    let mut out = String::new();
    let mut lines = LineWriter::new(&mut out);
    lines.emit("s", "max", i64::MAX).expect("emit");
    lines.emit("s", "min", i64::MIN).expect("emit");
    lines.flush().expect("flush");
    assert_eq!(out, "bridge_s max=9223372036854775807 min=-9223372036854775808\r\n");
}

#[test]
fn flushing_with_nothing_pending_writes_nothing() {
    let mut out = String::new();
    let mut lines = LineWriter::new(&mut out);
    lines.flush().expect("flush");
    lines.emit("a", "x", 1).expect("emit");
    lines.flush().expect("flush");
    lines.flush().expect("flush");
    assert_eq!(out, "bridge_a x=1\r\n");
}
