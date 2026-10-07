//! The memory table: RAM per membership to the byte, measured on the host (M-host), with the device figures to read next to it
//! (`rust/crates/tdongle-tailnet-runtime/size-table.sh` prints M-elf for every slot count; the numbers below are labelled by where they come from).
//!
//! `cargo test -p tdongle-tailnet-host --test memory -- --nocapture`

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use std::time::Duration;
use tdongle_tailnet_engine::GatewayEngine;
use tdongle_tailnet_host::harness::*;
use tdongle_tailnet_runtime::shared::{DERP_Q, DNS_Q, HOST_Q, MAX_RUN, SCRATCH, Slot, UDP_Q};
use tdongle_tailnet_runtime::sizes::*;

#[test]
fn ram_per_membership_to_the_byte() {
    let gw = Gateway::start(GatewayOpts::new("127.0.0.1:1"));
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while FUT_RUN_BYTES(&gw) == 0 && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    let sh = gw.sh;
    let f = |i| future_bytes(sh, i);
    let slot = core::mem::size_of::<Slot<CriticalSectionRawMutex>>();
    let sess = core::mem::size_of::<tdongle_tailnet_ctl::SessionBuf>();
    let bulk = core::mem::size_of::<tdongle_tailnet_ctl::Bulk>();
    let eng = GatewayEngine::<Dir>::per_member_bytes();
    let st = static_sizes::<Dir>();
    let shared = core::mem::size_of::<Sh>();
    let dir = core::mem::size_of::<Dir>();

    let futures_per_member = f(FUT_CONTROL) + f(FUT_DERP) + f(FUT_UDP);
    let statics_per_member = slot;
    let engine_per_member = eng.in_engine;
    let net_per_member = tdongle_tailnet_runtime::net_embassy::GatewayBuffers::PER_MEMBER;
    let total = futures_per_member + statics_per_member + engine_per_member + net_per_member;
    let gateway_shared = f(FUT_USB)
        + f(FUT_SUPERVISOR)
        + f(FUT_TIMER)
        + f(FUT_LINK)
        + f(FUT_DNS)
        + HOST_Q
        + DNS_Q
        + st.lease
        + bulk
        + SCRATCH
        + st.token
        + st.registry
        + st.usb_side;

    println!("MEMORY TABLE, host 64-bit (M-host); sizes of types are exact, this host's pointer width inflates the futures against the device (M-elf)");
    println!("  per membership slot (x{MAX_RUN} in this configuration):");
    println!("    control future            {:>8}   (the run_session state machine: Noise, HTTP/2, counters; its big buffers are leased)", f(FUT_CONTROL));
    println!("    derp future               {:>8}   (the Link, TLS connection and handshake, staging buffers)", f(FUT_DERP));
    println!("    udp future                {:>8}   (no datagram buffer of its own: the shared scratch)", f(FUT_UDP));
    println!(
        "    Slot static               {:>8}   = control session state {sess} + UDP queue {UDP_Q} + DERP queue {DERP_Q} + status/identity/signals {}",
        slot,
        slot.saturating_sub(sess + UDP_Q + DERP_Q)
    );
    println!(
        "    engine, Member<8> record  {:>8}   (+ resident WireGuard slots {} from the shared pool of 12, DISCO {}, router share {})",
        eng.in_engine, eng.wg_slots_resident, eng.disco, eng.router_share
    );
    println!("    socket buffers (embassy)  {:>8}   GatewayBuffers::PER_MEMBER (const, same on the device)", net_per_member);
    println!("    ------------------------------------");
    println!("    RAM per membership        {:>8}   (M-host futures + exact statics; device: see size-table.sh)", total);
    println!("  once for the gateway:");
    println!(
        "    usb {} + supervisor {} + timer {} + link {} + dns {} futures; host queue {HOST_Q}; dns queue {DNS_Q}; TLS lease {}; control Bulk {bulk}; scratch {SCRATCH}; token {}; registry {}; usb side {}",
        f(FUT_USB),
        f(FUT_SUPERVISOR),
        f(FUT_TIMER),
        f(FUT_LINK),
        f(FUT_DNS),
        st.lease,
        st.token,
        st.registry,
        st.usb_side
    );
    println!(
        "    = {gateway_shared}   (+ engine shared part {} = engine {} - {MAX_RUN} x Member)",
        st.engine.saturating_sub(MAX_RUN * eng.in_engine),
        st.engine
    );
    println!("  Shared in all (host): {shared} B, of which the test directory {dir}; the joined run future: {} B", FUT_RUN_BYTES(&gw));
    println!("  the control workspace is one gateway-wide set (Bulk {bulk} B), leased per record / message; each membership keeps {sess} B of session state");
    assert!(f(FUT_CONTROL) > 0 && f(FUT_DERP) > f(FUT_UDP) && f(FUT_RUN) > f(FUT_DERP) * MAX_RUN);
    assert!(total > 30_000 && total < 250_000, "{total}");
    assert_eq!(st.lease, 16_640);
    // the point of the lease: a membership's slot no longer holds the workspace
    assert!(slot < bulk / 2 && slot >= UDP_Q + DERP_Q + sess, "slot {slot}, bulk {bulk}");
    assert!(sess < 2_000, "{sess}");
}

#[allow(non_snake_case)]
fn FUT_RUN_BYTES(gw: &Gateway) -> usize {
    future_bytes(gw.sh, FUT_RUN)
}
