//! Any Ethernet frame the USB host sends the runtime's USB side (ARP, DHCP, ICMP to the dongle, DNS, alias traffic, everything the NAT would take): no
//! panic, every frame ends as exactly one `UsbAction`, and what the runtime builds for the host is a well-formed frame.
//!
//! Needs in `rust/fuzz/Cargo.toml`: `tdongle-tailnet-runtime = { path = "../crates/tdongle-tailnet-runtime", features = ["size-probe"] }` (the feature brings the
//! stub platform and storage), plus `embassy-time = { version = "0.5", features = ["std", "generic-queue-64"] }` and
//! `critical-section = { version = "1.2", features = ["std"] }` (the runtime links a time driver and a critical-section implementation).
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use tdongle_tailnet_runtime::probe::{ProbeShared, shared};
use tdongle_tailnet_runtime::usb::{FRAME_MAX, UsbAction, UsbSide, derive_usb_mac, host_frame};
use tdongle_tailnet_runtime::wifi::NoWifi;
use tdongle_tailnet_types::Entropy;

struct Zero;
impl Entropy for Zero {
    fn fill(&mut self, b: &mut [u8]) {
        b.fill(7);
    }
}

thread_local! {
    static SH: RefCell<Option<(ProbeShared, UsbSide)>> = const { RefCell::new(None) };
}

fuzz_target!(|data: &[u8]| {
    SH.with(|c| {
        let mut c = c.borrow_mut();
        let (sh, un) = c.get_or_insert_with(|| (shared(), UsbSide::new(derive_usb_mac([2, 0, 0, 0, 0, 1]), &mut Zero)));
        let mut reply = [0u8; FRAME_MAX];
        let mut now = 0u64;
        // frames separated by a 2-byte big-endian length
        let mut rest = data;
        while rest.len() >= 2 {
            let n = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
            let (frame, after) = rest[2..].split_at(n);
            let mut f = frame.to_vec();
            match host_frame(sh, un, &NoWifi, now, &mut f, &mut reply) {
                UsbAction::Reply(len) | UsbAction::Echo(len) | UsbAction::Icmp(len) => {
                    assert!((14..=FRAME_MAX).contains(&len));
                }
                UsbAction::ToEngine | UsbAction::Dns | UsbAction::Napt | UsbAction::Dropped => {}
            }
            now += 1000;
            rest = after;
        }
    });
});
