//! The record ring of `tdongle_runtime/memory.c`: which notes are kept, and which record is evicted.

mod common;

use common::{golden, record, scenarios};
use tdongle_serial::memory_log::{CAPACITY, MemoryLog, Record, RecordSource};

fn rec(uptime_ms: u32, minimum_bytes: u32) -> Record {
    Record { uptime_ms, operation: 1, requested: 10, free_bytes: minimum_bytes + 100, minimum_bytes, largest_bytes: 50, failed: 0 }
}

#[test]
fn the_first_note_is_always_kept() {
    let mut log = MemoryLog::new();
    assert_eq!(log.count(), 0);
    assert_eq!(log.get(0), None);
    assert!(log.note(rec(1, 5000), false));
    assert_eq!(log.count(), 1);
    assert_eq!(log.get(0).map(|r| r.uptime_ms), Some(1));
}

#[test]
fn ordinary_notes_at_an_unchanged_or_higher_minimum_are_dropped() {
    let mut log = MemoryLog::new();
    assert!(log.note(rec(1, 5000), false));
    assert!(!log.note(rec(2, 5000), false), "same minimum");
    assert!(!log.note(rec(3, 6000), false), "higher minimum");
    assert_eq!(log.count(), 1);
}

#[test]
fn a_lower_minimum_is_a_low_water_transition_and_is_kept() {
    let mut log = MemoryLog::new();
    assert!(log.note(rec(1, 5000), false));
    assert!(log.note(rec(2, 4999), false));
    assert!(!log.note(rec(3, 4999), false), "compared with the newest kept record");
    assert!(log.note(rec(4, 4000), false));
    let kept: Vec<u32> = log.iter().map(|r| r.uptime_ms).collect();
    assert_eq!(kept, [1, 2, 4]);
}

#[test]
fn a_failure_is_always_kept_and_marked() {
    let mut log = MemoryLog::new();
    log.note(rec(1, 5000), false);
    assert!(log.note(rec(2, 9000), true));
    let r = log.get(1).expect("kept");
    assert_eq!(r.failed, 1);
    assert_eq!(log.get(0).expect("kept").failed, 0);
    // `failed` is what the caller says, not what the record carried in.
    let mut dirty = rec(3, 1);
    dirty.failed = 77;
    log.note(dirty, false);
    assert_eq!(log.get(2).expect("kept").failed, 0);
}

#[test]
fn the_ring_holds_sixteen_and_evicts_the_oldest() {
    let mut log = MemoryLog::new();
    for i in 0..20u32 {
        assert!(log.note(rec(i, 10_000 - i), false), "each step is lower than the last");
    }
    assert_eq!(log.count(), CAPACITY);
    let kept: Vec<u32> = log.iter().map(|r| r.uptime_ms).collect();
    assert_eq!(kept, (4..20).collect::<Vec<u32>>(), "0..4 were evicted, oldest first");
    assert_eq!(log.get(0).map(|r| r.uptime_ms), Some(4));
    assert_eq!(log.get(15).map(|r| r.uptime_ms), Some(19));
    assert_eq!(log.get(16), None);
}

#[test]
fn failures_survive_ordinary_traffic_but_not_sixteen_more_notes() {
    let mut log = MemoryLog::new();
    log.note(rec(0, 5000), true);
    for i in 1..100 {
        log.note(rec(i, 5000), false);
    }
    assert_eq!(log.count(), 1, "ordinary traffic evicts nothing: it is not stored");
    assert_eq!(log.get(0).map(|r| (r.uptime_ms, r.failed)), Some((0, 1)));
    // The quirk of the C code: further transitions or failures do push the old failure out.
    for i in 1..=16 {
        log.note(rec(1000 + i, 5000), true);
    }
    assert!(log.iter().all(|r| r.uptime_ms >= 1000), "the original failure was evicted");
}

#[test]
fn the_comparison_is_with_the_newest_kept_record_across_the_wrap() {
    let mut log = MemoryLog::new();
    for i in 0..CAPACITY as u32 {
        log.note(rec(i, 1000 - i), false);
    }
    // The next slot to write is index 0 again; the newest record is at index 15, minimum 985.
    assert!(!log.note(rec(100, 985), false));
    assert!(log.note(rec(101, 984), false));
    assert_eq!(log.get(CAPACITY - 1).map(|r| r.uptime_ms), Some(101));
}

#[test]
fn a_slice_and_an_array_are_record_sources_too() {
    let records = [rec(1, 3), rec(2, 2)];
    assert_eq!(RecordSource::count(&records), 2);
    assert_eq!(RecordSource::get(&records, 1).map(|r| r.uptime_ms), Some(2));
    let slice: &[Record] = &records;
    assert_eq!(RecordSource::count(&slice), 2);
    assert_eq!(RecordSource::get(&slice, 2), None);
}

#[test]
fn the_ring_behaves_like_the_real_memory_c_on_every_scenario() {
    let all = scenarios();
    let golden = golden("memory_log.golden");
    assert_eq!(all["memory_log"].as_array().expect("scenarios").len(), golden.len());
    for sc in all["memory_log"].as_array().expect("scenarios") {
        let name = sc["name"].as_str().expect("name");
        let mut log = MemoryLog::new();
        let mut text = String::new();
        for step in sc["steps"].as_array().expect("steps") {
            let r = record(step);
            // C: `failed` is `int`, stored as `!!failed`.
            let kept = log.note(r, r.failed != 0);
            text += &format!("kept={}\n", u8::from(kept));
        }
        text += &format!("count={}\n", log.count());
        for r in log.iter() {
            text += &format!("{} {} {} {} {} {} {}\n", r.uptime_ms, r.operation, r.requested, r.free_bytes, r.minimum_bytes, r.largest_bytes, r.failed);
        }
        // C returns a zero record beyond the end.
        text += "beyond 0 0\n";
        assert!(log.get(log.count()).is_none());
        let want = &golden.iter().find(|(n, _)| n == name).expect("entry").1;
        assert_eq!(text.as_bytes(), &want[..], "memory log scenario {name}");
    }
}
