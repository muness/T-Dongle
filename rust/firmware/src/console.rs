//! The serial console: CDC bytes in, one command at a time, replies out. Port of `console.c` (line discipline, output queue and writer) and
//! `control.c` (the command task and its dispatch). The line discipline, the command grammar and every reply text are `tdongle-serial`
//! (golden-tested against the C); this file is the queues, the tasks and the wiring to the rest of the firmware.

use core::fmt::{self, Write};
use std::cell::Cell;
use std::sync::OnceLock;

use esp_idf_svc::hal::cpu::Core;
use esp_idf_svc::hal::task::queue::Queue;
use esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration;
use tdongle_serial::command::{Command, DisplayArgs, SlotArg};
use tdongle_serial::console::{Event, LineReader, MGMT_CHUNK_MAX, OVERFLOW_REPLY, PROMPT, QUEUE_FULL_REPLY};
use tdongle_serial::reply;

use crate::sys::single::SingleContext;
use crate::sys::task::ms_to_ticks;
use crate::usb;

const COMMAND_QUEUE: usize = 2;
const OUTPUT_QUEUE: usize = 8;
/// The control task polls its queue this often; it also samples the traffic rates once a window.
const POLL_MS: u32 = 100;
/// The control task's stack. The C task has 4,096 B with a 1 KB margin rule; Rust's formatting machinery is bigger, so this is a measured number:
/// `control_stack_free_bytes` in the `traffic` status line reports the high-water mark (rule 11 of ADR 0001: keep at least 1 KB free).
const CONTROL_STACK: usize = 6144;

type Line = [u8; tdongle_serial::console::LINE_MAX];
type Chunk = [u8; MGMT_CHUNK_MAX + 1];

struct Queues {
    commands: Queue<Line>,
    output: Queue<Chunk>,
}

static QUEUES: OnceLock<Queues> = OnceLock::new();
/// The line reader belongs to the TinyUSB task (the CDC receive callback).
static READER: SingleContext<LineReader> = SingleContext::new();

thread_local! {
    /// The control task waits (up to 300 ms) for room in the output queue, so boot reports do not silently lose chunks; every other task queues
    /// with a zero wait, as `mgmt_write` does, because the TinyUSB task must never block.
    static MAY_WAIT: Cell<bool> = const { Cell::new(false) };
}

/// `mgmt_write`: queue `text` for the host (see [`mgmt_write_bytes`]).
pub fn mgmt_write(text: &str) {
    mgmt_write_bytes(text.as_bytes());
}

/// `mgmt_write` on raw bytes (an SSID is not necessarily UTF-8): queue them in 127 byte chunks (NUL padded, as the C queue items are). Bytes are
/// never reordered; a full queue drops the chunk (and, for every task but the control task, does not wait).
pub fn mgmt_write_bytes(text: &[u8]) {
    let Some(queues) = QUEUES.get() else { return };
    let wait = if MAY_WAIT.with(Cell::get) { ms_to_ticks(300) } else { 0 };
    for piece in tdongle_serial::console::mgmt_chunks(text) {
        let mut chunk = [0u8; MGMT_CHUNK_MAX + 1];
        chunk[..piece.len()].copy_from_slice(piece);
        if queues.output.send_back(chunk, wait).is_err() {
            return; // the queue's own error: nothing to do but drop (counted nowhere in C either)
        }
    }
}

/// A `fmt::Write` that feeds [`mgmt_write`] in pieces, so a report never needs a buffer of its own size.
struct Out;

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        mgmt_write(s);
        Ok(())
    }
}

/// The sinks here never fail (a full queue drops, like C), so a formatting result carries no information.
fn infallible(result: fmt::Result) {
    debug_assert!(result.is_ok());
}

/// The TinyUSB task: bytes from the CDC port.
pub fn feed(bytes: &[u8]) {
    // SAFETY: only the TinyUSB task calls this (`usb::cdc::tud_cdc_rx_cb`).
    let Some(reader) = (unsafe { READER.get_mut() }) else { return };
    let Some(queues) = QUEUES.get() else { return };
    for &byte in bytes {
        match reader.feed(byte) {
            Some(Event::Line(line)) => {
                let mut item = [0u8; tdongle_serial::console::LINE_MAX];
                item[..line.len()].copy_from_slice(line.as_bytes());
                if queues.commands.send_back(item, 0).is_err() {
                    mgmt_write(QUEUE_FULL_REPLY);
                }
            }
            Some(Event::Prompt) => mgmt_write(PROMPT),
            Some(Event::Overflow) => mgmt_write(OVERFLOW_REPLY),
            None => {}
        }
    }
}

/// The host opened or closed the port: greet on DTR.
pub fn on_line_state(dtr: bool) {
    if dtr {
        let mut out = Out;
        infallible(tdongle_serial::console::write_greeting(&mut out, false, crate::VERSION));
    }
}

/// Create the queues and start the writer and the control task.
///
/// # Errors
/// A queue or a task could not be created.
pub fn start() -> Result<(), &'static str> {
    let queues = Queues { commands: Queue::new(COMMAND_QUEUE), output: Queue::new(OUTPUT_QUEUE) };
    QUEUES.set(queues).map_err(|_| "the console was started twice")?;
    // SAFETY: boot, before the TinyUSB task can call `feed`.
    unsafe { READER.install(LineReader::new()) };
    spawn(c"console_tx", 3072, 2, writer)?;
    spawn(c"gateway_control", CONTROL_STACK, 3, control)
}

fn spawn(name: &'static core::ffi::CStr, stack: usize, priority: u8, body: fn()) -> Result<(), &'static str> {
    let c_name = name;
    ThreadSpawnConfiguration { name: Some(c_name), stack_size: stack, priority, pin_to_core: Some(Core::Core0), ..Default::default() }
        .set()
        .map_err(|_| "could not configure a console task")?;
    let spawned = std::thread::Builder::new().name(name.to_string_lossy().into_owned()).stack_size(stack).spawn(body);
    crate::sys::reset_thread_spawn_defaults();
    spawned.map(|_| ()).map_err(|_| "could not start a console task")
}

/// `writer`: the console_tx task pushes queued chunks to the CDC port, retrying a bounded number of times.
fn writer() {
    let Some(queues) = QUEUES.get() else { return };
    loop {
        let Some((chunk, _)) = queues.output.recv_front(u32::MAX) else { continue };
        let length = chunk.iter().position(|&b| b == 0).unwrap_or(chunk.len());
        let (mut offset, mut retries) = (0, 0);
        while offset < length && retries < 10 {
            retries += 1;
            offset += usb::cdc::write_queue(&chunk[offset..length]);
            usb::cdc::write_flush(20);
            if offset < length {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// `command_task`.
fn control() {
    MAY_WAIT.with(|w| w.set(true));
    let Some(queues) = QUEUES.get() else { return };
    let mut sampler = tdongle_traffic::Sampler::new();
    let mut last_sample = 0u32;
    loop {
        let now = crate::sys::now_ms();
        if now.wrapping_sub(last_sample) >= 250 || last_sample == 0 {
            sampler.sample(&usb::net::TRAFFIC.read(), now);
            crate::report::set_rates(sampler.down_kbps, sampler.up_kbps);
            last_sample = now;
        }
        let Some((line, _)) = queues.commands.recv_front(ms_to_ticks(POLL_MS).max(1)) else { continue };
        let length = line.iter().position(|&b| b == 0).unwrap_or(line.len());
        let text = core::str::from_utf8(&line[..length]).unwrap_or("");
        dispatch(text);
        mgmt_write(reply::DONE);
    }
}

/// The reply of a command that exists in the C firmware but not yet in this phase of the port (settings writes, the setup access point, the
/// panel). Honest and byte-stable so a client can tell.
const NOT_YET: &str = "ERR Not available in the Rust port yet (phase 2: setup, display and saved-network editing)\r\n";

fn dispatch(line: &str) {
    let mut out = Out;
    match Command::parse(line) {
        Command::Help => infallible(reply::write_help_implemented(&mut out, "T-Dongle Wi-Fi bridge", reply::PHASE1_FIRMWARE_COMMANDS)),
        Command::Capabilities => infallible(reply::write_capabilities_implemented(&mut out, &["boot_diagnostics", "power_report"])),
        Command::Pm => crate::report::pm(&mut out),
        Command::BootStatus => crate::report::boot_status(&mut out),
        Command::Status => crate::report::status(&mut out),
        Command::List => crate::report::list(&mut out),
        Command::Mode(mode) => crate::report::mode(mode),
        Command::Use(SlotArg::Number(slot)) => crate::report::use_network(i64::from(slot)),
        Command::Use(SlotArg::TrailingGarbage) => mgmt_write(reply::USE_INVALID),
        Command::Display(DisplayArgs::Show) => crate::report::display(&mut out),
        Command::Reboot => {
            crate::guard::leave_safe_mode();
            mgmt_write(reply::REBOOT_OK);
            std::thread::sleep(std::time::Duration::from_millis(200));
            crate::sys::restart();
        }
        Command::Bootloader => {
            crate::guard::leave_safe_mode(); // a deliberate reset is not a failed boot
            mgmt_write(reply::BOOTLOADER_OK);
            std::thread::sleep(std::time::Duration::from_millis(200));
            crate::sys::reboot_to_rom_download();
        }
        Command::Unknown => infallible(reply::write_unknown(&mut out, false)),
        Command::Display(_)
        | Command::Setup(_)
        | Command::Cancel
        | Command::Reset
        | Command::ConfirmReset
        | Command::Profile(_)
        | Command::Del(_)
        | Command::Scan
        | Command::RetryStartup
        | Command::CryptoBench
        | Command::Diagnostic(_) => mgmt_write(NOT_YET),
    }
}
