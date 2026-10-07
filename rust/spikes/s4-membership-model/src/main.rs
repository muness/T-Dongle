//! S4: memory model of tailnet memberships on no_std (esp-hal + esp-rtos/embassy). See FINDINGS.md.
//! Prints `S4 ...` lines over esp-println (USB-Serial-JTAG/UART auto). No network. Nothing is flashed by this spike's tooling.
#![no_std]
#![no_main]
extern crate alloc;

mod libc_stubs;
mod mbed;
mod mem;

use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::timer::timg::TimerGroup;
use mem::METER;
use s4_model::scenario::Cfg;
use s4_model::{coord, disco, tls, wg};
use tinyrlibc as _;

esp_bootloader_esp_idf::esp_app_desc!();

/// The C's negotiation token (ml_negotiation.c): one setup at a time, so each phase's heap peak is its own and
/// the join peak is single-flight whatever N is.
static TOKEN: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());
static DONE: Channel<CriticalSectionRawMutex, (usize, &'static str, bool), 16> = Channel::new();

const CFG: Cfg = Cfg::DEFAULT;
const MEMBERSHIPS: usize = 3;

#[embassy_executor::task(pool_size = 3)]
async fn coord_task(id: usize) {
    mem::tagged(mem::T_COORD, coord_task_body(id)).await
}

async fn coord_task_body(id: usize) {
    let mut c = {
        let _g = TOKEN.lock().await;
        let (c, ok) = coord::setup(&METER, &CFG.coord, 8);
        DONE.send((id, "coord", ok)).await;
        c
    };
    loop {
        Timer::after(Duration::from_millis(2000)).await;
        let _g = TOKEN.lock().await;
        coord::exercise(&mut c);
    }
}

/// The C serialises every join behind one negotiation token, so a single task performs the DERP TLS handshakes and its
/// future (the handshake state) exists once, not once per membership. It hands the established connection to the
/// membership's own derp task.
static HS_REQ: Channel<CriticalSectionRawMutex, usize, 4> = Channel::new();
static DERP_OUT: Channel<CriticalSectionRawMutex, SendDerp, 1> = Channel::new();
struct SendDerp(tls::Derp);
// SAFETY: single-core executor; the connection is only ever touched by one task at a time.
unsafe impl Send for SendDerp {}

#[embassy_executor::task]
async fn negotiator_task() {
    mem::tagged(mem::T_DERP, negotiator_body()).await
}

async fn negotiator_body() {
    loop {
        let id = HS_REQ.receive().await;
        let _g = TOKEN.lock().await;
        let mut d = tls::setup(&METER, CFG.tls_read, CFG.tls_write).await;
        let ok = tls::app_data(&METER, &mut d).await;
        DONE.send((id, "derp-tls", ok && d.ok)).await;
        DERP_OUT.send(SendDerp(d)).await;
    }
}

#[embassy_executor::task(pool_size = 3)]
async fn derp_task(id: usize) {
    mem::tagged(mem::T_DERP, derp_task_body(id)).await
}

async fn derp_task_body(id: usize) {
    let _ = id;
    let conn = DERP_OUT.receive().await; // the established connection (+ a pointer to its 16,640 B record buffer) lives here
    loop {
        core::hint::black_box(&conn);
        Timer::after(Duration::from_millis(5000)).await;
    }
}

#[embassy_executor::task(pool_size = 3)]
async fn wg_task(id: usize) {
    mem::tagged(mem::T_WG, wg_task_body(id)).await
}

async fn wg_task_body(id: usize) {
    let mut w = {
        let _g = TOKEN.lock().await;
        let (w, ok) = wg::setup(&METER, CFG.resident_peers);
        DONE.send((id, "wireguard", ok)).await;
        w
    };
    loop {
        Timer::after(Duration::from_millis(1000)).await;
        let _g = TOKEN.lock().await;
        wg::exercise(&mut w);
    }
}

#[embassy_executor::task(pool_size = 3)]
async fn disco_task(id: usize) {
    mem::tagged(mem::T_DISCO, disco_task_body(id)).await
}

async fn disco_task_body(id: usize) {
    let mut d = {
        let _g = TOKEN.lock().await;
        let (d, ok) = disco::setup(&METER, CFG.inline_queues, CFG.resident_peers, &CFG.tcp);
        DONE.send((id, "disco+stun", ok)).await;
        d
    };
    loop {
        Timer::after(Duration::from_millis(1500)).await;
        let _g = TOKEN.lock().await;
        disco::exercise(&mut d);
    }
}

fn report_static() {
    let (data_s, data_e, bss_s, bss_e) = unsafe { (&raw const mem::_data_start as usize, &raw const mem::_data_end as usize, &raw const mem::_bss_start as usize, &raw const mem::_bss_end as usize) };
    let (se, ss) = mem::stack_bounds();
    esp_println::println!(
        "S4 STATIC data={} bss={} stack_total={} heap_total={} heap_used={} heap_free={}",
        data_e - data_s,
        bss_e - bss_s,
        ss - se,
        esp_alloc::HEAP.free() + esp_alloc::HEAP.used(),
        mem::used(),
        mem::free()
    );
}

// rescue: exempt (USB-Serial-JTAG only: this image never starts the OTG device, so esptool can always reset it into the ROM loader without BOOT)
#[esp_rtos::main]
async fn main(spawner: Spawner) {
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    // Same split as esp-radio's documented setup (esp-radio src/lib.rs:40-41): reclaimed bootloader RAM + a DRAM region.
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 72 * 1024);
    esp_alloc::heap_allocator!(size: 160 * 1024);
    let t = TimerGroup::new(p.TIMG0);
    esp_rtos::start(t.timer0, p.FROM_CPU_INTR0);

    Timer::after(Duration::from_millis(3000)).await; // let a serial monitor attach
    esp_println::println!("S4 BEGIN s4-membership-model {} memberships={}", env!("CARGO_PKG_VERSION"), MEMBERSHIPS);
    report_static();
    {
        use s4_model::meter::Meter;
        coord::print_sizes(&METER);
        wg::print_sizes(&METER);
        disco::print_sizes(&METER);
        tls::print_sizes(&METER);
        METER.size("CFG tls_read_record_buffer", CFG.tls_read);
        METER.size("CFG tls_write_record_buffer", CFG.tls_write);
        let f = tls::setup(&METER, 0, 0);
        METER.size("future size_of_val(tls::setup)", core::mem::size_of_val(&f));
        drop(f);
    }
    // Empty probe: how much stack an idle window "uses" (interrupt frames etc). Subtract from the phase numbers.
    {
        use s4_model::meter::Meter;
        METER.begin("stack.empty_probe_10ms");
        Timer::after(Duration::from_millis(10)).await;
        METER.end();
    }

    // Real mbedTLS (mbedtls-rs) handshake on target, client and server in this executor over pipes. Runs first, on an empty heap
    // (the session is dropped afterwards), so its numbers are not mixed with the memberships'.
    {
        let _g = TOKEN.lock().await;
        esp_println::println!("S4 MBED begin heap_used={} heap_free={}", mem::used(), mem::free());
        mbed::run(&METER).await;
    }
    spawner.spawn(negotiator_task().unwrap());
    let base0 = mem::used();
    for id in 0..MEMBERSHIPS {
        let before = mem::used();
        mem::reset_peak();
        esp_println::println!("S4 MEMBERSHIP {} begin heap_used={} heap_free={}", id + 1, before, mem::free());
        spawner.spawn(coord_task(id).unwrap());
        spawner.spawn(derp_task(id).unwrap());
        HS_REQ.send(id).await;
        spawner.spawn(wg_task(id).unwrap());
        spawner.spawn(disco_task(id).unwrap());
        let mut all_ok = true;
        for _ in 0..4 {
            let (i, what, ok) = DONE.receive().await;
            esp_println::println!("S4 DONE membership={} task={} ok={}", i + 1, what, ok);
            all_ok &= ok;
        }
        let after = mem::used();
        esp_println::println!(
            "S4 MEMBERSHIP {} retained={} peak_above_start={} cumulative={} heap_free={} alloc_fails={} ok={}",
            id + 1,
            after as isize - before as isize,
            mem::peak() as isize - before as isize,
            after as isize - base0 as isize,
            mem::free(),
            mem::fails(),
            all_ok
        );
        report_static();
    }

    esp_println::println!("S4 TAGS after the {} memberships (mbedtls-* rows are from the earlier mbedtls run):", MEMBERSHIPS);
    mem::report_tags();

    // Steady state: all tasks looping and allocating transiently, 20 s window.
    mem::reset_peak();
    let steady0 = mem::used();
    let mut round = 0u32;
    loop {
        Timer::after(Duration::from_millis(5000)).await;
        round += 1;
        esp_println::println!(
            "S4 STEADY round={} used={} (+{} over end-of-setup) peak_since_setup={} free={} alloc_fails={}",
            round,
            mem::used(),
            mem::used() as isize - steady0 as isize,
            mem::peak() as isize - steady0 as isize,
            mem::free(),
            mem::fails()
        );
        mem::report_tags();
        if round % 6 == 0 {
            esp_println::println!("S4 NOTE: reset the board to capture the full S4 PHASE table from boot");
        }
    }
}
