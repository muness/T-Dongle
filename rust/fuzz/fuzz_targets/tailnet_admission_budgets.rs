//! The inbound budgets (WireGuard receive bytes, USB receive slots) and the run planner under arbitrary schedules: counters never wrap.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_admission::usb_rx::{Admit, Budget as UsbBudget, GATEWAY_USB_RX_INFLIGHT_MAX};
use tdongle_tailnet_admission::wg_rx::{plan_runs, Budget as WgBudget, RunStats, ML_WG_RX_QUEUE_BYTES};

fuzz_target!(|data: &[u8]| {
    let wg = WgBudget::new();
    let usb = UsbBudget::new();
    let mut held: Vec<usize> = Vec::new();
    let mut usb_held = 0u32;
    for c in data.chunks(3) {
        let len = usize::from(*c.first().unwrap_or(&0)) * 6;
        let heap = usize::from(*c.get(1).unwrap_or(&0)) * 400;
        match c.get(2).copied().unwrap_or(0) % 4 {
            0 => {
                if wg.admit(len, heap) == tdongle_tailnet_admission::wg_rx::Verdict::Ok {
                    held.push(len);
                }
            }
            1 => {
                if let Some(l) = held.pop() {
                    wg.release(l);
                }
            }
            2 => {
                if usb.admit(len as u32, heap) == Admit::Admitted {
                    usb_held += 1;
                }
            }
            _ => {
                if usb_held > 0 {
                    usb.release();
                    usb_held -= 1;
                }
            }
        }
        assert!(wg.queued() <= ML_WG_RX_QUEUE_BYTES);
        assert!(usb.inflight() <= GATEWAY_USB_RX_INFLIGHT_MAX);
    }
    let is_data: Vec<bool> = data.iter().map(|b| b & 1 == 0).collect();
    let mut st = RunStats::default();
    let mut covered = 0;
    plan_runs(&is_data, &mut st, |r| {
        covered += match r {
            tdongle_tailnet_admission::wg_rx::Run::Data { start, end } => end - start,
            tdongle_tailnet_admission::wg_rx::Run::Single { .. } => 1,
        }
    });
    assert_eq!(covered, is_data.len());
});
