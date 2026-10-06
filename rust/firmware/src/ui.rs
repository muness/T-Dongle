//! The device UI: the ST7735 panel, the backlight, the BOOT button and the APA102 status light, driven by the pure state machines of `tdongle-ui` and rendered by `tdongle-lcd`.
//!
//! Boot order (the screen must show within about a second of every boot): the task starts the panel (reset, init sequence, the STARTING screen) with the backlight off,
//! waits up to 700 ms for the stored display settings (the init task reads them), then switches the backlight on at the stored brightness, as the C does. From then on
//! it polls every `POLL_MS` like `gateway_display_tick`. Every hardware call here is bounded; a panel that does not answer cannot stop the console (own task, thread executor).
#![allow(clippy::too_many_arguments)]

use core::sync::atomic::Ordering;

use embassy_time::{Duration, Instant, Timer};
use esp_hal::gpio::{DriveMode, Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::ledc::channel::{self, ChannelIFace};
use esp_hal::ledc::timer::{self, TimerIFace};
use esp_hal::ledc::{Ledc, LowSpeed};
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::time::Rate;
use tdongle_lcd::{LCD_BARS, LcdState, View, compose, compose_rows, panel};
use tdongle_ui::menu::ROWS;
use tdongle_ui::settings::Settings;
use tdongle_ui::setup_boot::Session;
use tdongle_ui::text::Text;
use tdongle_ui::ui::{Command, Content, Inputs, Snapshot, Ui, POLL_MS};

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8};

use crate::{FIRMWARE, SAVED, STORED};

/// Self-verification counters for the `ui` status line (so the UI can be checked over serial, with nobody looking at the dongle).
pub static PANEL_STATE: AtomicU8 = AtomicU8::new(0); // 0 not started, 1 ok, 2 spi init failed, 3 backlight failed (panel ok), 4 draw failed
pub static SPI_ERRORS: AtomicU32 = AtomicU32::new(0);
pub static FRAMES_DRAWN: AtomicU32 = AtomicU32::new(0);
pub static LAST_VIEW_CRC: AtomicU32 = AtomicU32::new(0);
pub static LAST_PAGE: AtomicU32 = AtomicU32::new(0);
pub static BACKLIGHT_PCT: AtomicU32 = AtomicU32::new(0);
pub static ROTATION: AtomicU8 = AtomicU8::new(0);
pub static BUTTON_PRESSES: AtomicU32 = AtomicU32::new(0);
pub static BUTTON_HOLDS: AtomicU32 = AtomicU32::new(0);
pub static MENU_OPEN: AtomicBool = AtomicBool::new(false);
pub static LED_RGB: AtomicU32 = AtomicU32::new(0);
pub static LED_WRITES: AtomicU32 = AtomicU32::new(0);
/// Milliseconds from reset to the first frame with the backlight on (0 = not yet).
pub static BOOT_SCREEN_MS: AtomicU32 = AtomicU32::new(0);
/// `ui press short|long`: milliseconds of injected button-down still to deliver (0 = none), set by the console.
pub static INJECT_MS: AtomicU32 = AtomicU32::new(0);

fn crc32(view: &View) -> u32 {
    let mut crc = !0u32;
    let mut feed = |b: u8| {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (!(crc & 1)).wrapping_add(1));
        }
    };
    view.text.iter().for_each(|&b| feed(b));
    view.bars.iter().for_each(|&b| feed(b));
    feed(u8::from(view.attention));
    feed(view.layout);
    feed(view.bar_count);
    !crc
}

/// The `ui` line of `status`.
pub fn write_status_line(out: &mut alloc::string::String) {
    use core::fmt::Write;
    let state = match PANEL_STATE.load(Ordering::Relaxed) {
        0 => "not_started",
        1 => "ok",
        2 => "spi_init_failed",
        3 => "backlight_failed",
        _ => "draw_failed",
    };
    let rgb = LED_RGB.load(Ordering::Relaxed);
    let _ = write!(
        out,
        "ui panel_init={} spi_errors={} frames_drawn={} last_view_crc={:08x} last_page={} backlight_pct={} rotation={} button_presses={} button_holds={} menu_open={} led_rgb={:06x} led_writes={} boot_screen_ms={}\r\n",
        state,
        SPI_ERRORS.load(Ordering::Relaxed),
        FRAMES_DRAWN.load(Ordering::Relaxed),
        LAST_VIEW_CRC.load(Ordering::Relaxed),
        LAST_PAGE.load(Ordering::Relaxed),
        BACKLIGHT_PCT.load(Ordering::Relaxed),
        ROTATION.load(Ordering::Relaxed),
        BUTTON_PRESSES.load(Ordering::Relaxed),
        BUTTON_HOLDS.load(Ordering::Relaxed),
        u8::from(MENU_OPEN.load(Ordering::Relaxed)),
        rgb,
        LED_WRITES.load(Ordering::Relaxed),
        BOOT_SCREEN_MS.load(Ordering::Relaxed)
    );
}

/// The panel on SPI2 (mode 0, 20 MHz, CS/DC/RST on plain GPIOs).
struct Panel {
    spi: Spi<'static, esp_hal::Blocking>,
    cs: Output<'static>,
    dc: Output<'static>,
    previous: View,
    rotation: u8,
    percent: u32,
}

impl Panel {
    fn command(&mut self, cmd: u8, data: &[u8]) -> bool {
        self.cs.set_low();
        self.dc.set_low();
        let mut ok = self.spi.write(&[cmd]).is_ok();
        if !data.is_empty() {
            self.dc.set_high();
            ok &= self.spi.write(data).is_ok();
        }
        self.cs.set_high();
        if !ok {
            SPI_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    async fn send(&mut self, c: panel::Cmd) {
        // The C sends the table's data bytes with the command; `Cmd::data()` carries them (some commands carry one 0x00).
        let _ = self.command(c.cmd, c.data());
        Timer::after_millis(u64::from(c.delay_ms)).await;
    }

    /// Paint `view` unless it is what is on the glass (`draw`). One scanline per transfer, yielding between lines.
    async fn draw(&mut self, view: &View) {
        if self.previous == *view {
            return;
        }
        let mut row = [0u16; 160];
        for y in 0..tdongle_lcd::HEIGHT {
            tdongle_lcd::render_row(view, y, &mut row);
            let (cas, ras) = panel::row_window(y as u16);
            let wire = panel::to_wire(&row);
            let ok = self.command(panel::cmd::CASET, &cas) && self.command(panel::cmd::RASET, &ras) && self.command(panel::cmd::RAMWR, &wire);
            if !ok {
                PANEL_STATE.store(4, Ordering::Relaxed);
                return; // the panel does not answer: keep `previous`, try again next poll
            }
            if y % 8 == 7 {
                embassy_futures::yield_now().await;
            }
        }
        self.previous = *view;
        FRAMES_DRAWN.fetch_add(1, Ordering::Relaxed);
        LAST_VIEW_CRC.store(crc32(view), Ordering::Relaxed);
        if PANEL_STATE.load(Ordering::Relaxed) == 4 {
            PANEL_STATE.store(1, Ordering::Relaxed);
        }
    }
}

/// Backlight: LEDC PWM, 1 kHz, 8 bit, on the active-low pin (`backlight_init`).
struct Backlight {
    channel: channel::Channel<'static, LowSpeed>,
}

impl Backlight {
    fn apply(&self, percent: u32) {
        let duty = tdongle_lcd::backlight_duty(percent);
        let _ = self.channel.set_duty(((duty * 100 + 127) / 255) as u8);
    }
}

/// APA102 on two plain GPIOs (clocked MSB first; the part is not timing critical).
struct Led {
    data: Output<'static>,
    clock: Output<'static>,
}

impl Led {
    fn write(&mut self, frame: &[u8; 12]) {
        for &byte in frame {
            for bit in (0..8).rev() {
                self.data.set_level(Level::from(byte >> bit & 1 != 0));
                self.clock.set_high();
                self.clock.set_low();
            }
        }
    }
}

fn settings() -> (Option<Settings>, bool) {
    match critical_section::with(|cs| STORED.borrow(cs).get()) {
        Some(s) => (Some(Settings { brightness: s.display.brightness, rotation: s.display.rotation, dim_seconds: s.display.dim_seconds }), true),
        None => (None, false),
    }
}

/// The pins and peripherals of the front panel.
pub struct Hardware {
    pub spi: esp_hal::peripherals::SPI2<'static>,
    pub mosi: esp_hal::peripherals::GPIO3<'static>,
    pub clk: esp_hal::peripherals::GPIO5<'static>,
    pub cs: esp_hal::peripherals::GPIO4<'static>,
    pub dc: esp_hal::peripherals::GPIO2<'static>,
    pub rst: esp_hal::peripherals::GPIO1<'static>,
    pub bl: esp_hal::peripherals::GPIO38<'static>,
    pub button: esp_hal::peripherals::GPIO0<'static>,
    pub led_data: esp_hal::peripherals::GPIO40<'static>,
    pub led_clk: esp_hal::peripherals::GPIO39<'static>,
    pub ledc: esp_hal::peripherals::LEDC<'static>,
}

/// Why the panel did not start (kept for the `init` command).
fn note(text: &str) {
    crate::init_note(text);
}

#[embassy_executor::task]
pub async fn ui_task(hw: Hardware) -> ! {
    let hw = hw;
    // Backlight pin first: off (high) until the first frame is on the glass.
    let mut ledc = Ledc::new(hw.ledc);
    ledc.set_global_slow_clock(esp_hal::ledc::LSGlobalClkSource::APBClk);
    let timer: &'static mut esp_hal::ledc::timer::Timer<'static, LowSpeed> = alloc::boxed::Box::leak(alloc::boxed::Box::new(ledc.timer::<LowSpeed>(timer::Number::Timer0)));
    let timer_ok = timer
        .configure(timer::config::Config { duty: timer::config::Duty::Duty8Bit, clock_source: timer::LSClockSource::APBClk, frequency: Rate::from_khz(1) })
        .is_ok();
    let timer: &'static esp_hal::ledc::timer::Timer<'static, LowSpeed> = timer;
    let mut channel = ledc.channel::<LowSpeed>(channel::Number::Channel0, hw.bl);
    let backlight = if timer_ok && channel.configure(channel::config::Config { timer, duty_pct: 100, drive_mode: DriveMode::PushPull }).is_ok() {
        Some(Backlight { channel })
    } else {
        note("backlight PWM failed");
        PANEL_STATE.store(3, Ordering::Relaxed);
        None
    };

    let mut led = Led { data: Output::new(hw.led_data, Level::Low, OutputConfig::default()), clock: Output::new(hw.led_clk, Level::Low, OutputConfig::default()) };
    let button = Input::new(hw.button, InputConfig::default().with_pull(Pull::Up));
    let mut rst = Output::new(hw.rst, Level::High, OutputConfig::default());
    let spi = Spi::new(hw.spi, SpiConfig::default().with_frequency(Rate::from_hz(panel::SPI_HZ)).with_mode(esp_hal::spi::Mode::_0))
        .map(|s| s.with_sck(hw.clk).with_mosi(hw.mosi));
    let Ok(spi) = spi else {
        note("panel SPI failed");
        PANEL_STATE.store(2, Ordering::Relaxed);
        loop {
            Timer::after_secs(3600).await;
        }
    };
    let mut p = Panel {
        spi,
        cs: Output::new(hw.cs, Level::High, OutputConfig::default()),
        dc: Output::new(hw.dc, Level::High, OutputConfig::default()),
        previous: View::POISONED,
        rotation: 0,
        percent: 101,
    };
    // Hardware reset, then the C's bring-up sequence.
    rst.set_low();
    Timer::after_millis(u64::from(panel::RESET_LOW_MS)).await;
    rst.set_high();
    Timer::after_millis(u64::from(panel::RESET_HIGH_MS)).await;
    for c in panel::Bringup::new() {
        p.send(c).await;
    }

    // The STARTING screen, on the glass before the light comes on.
    let mut boot = LcdState::ZERO;
    boot.starting = true;
    boot.usb = crate::ALT.load(Ordering::Relaxed) != 0;
    boot.usb_configured = crate::CONFIGURED.load(Ordering::Relaxed);
    let view = compose(&boot, FIRMWARE);
    p.draw(&view).await;
    if PANEL_STATE.load(Ordering::Relaxed) == 0 {
        PANEL_STATE.store(1, Ordering::Relaxed);
    }

    // The stored brightness and rotation, as soon as the init task has read them (at most 700 ms: then the defaults).
    let waited = Instant::now();
    let display = loop {
        if let (Some(s), true) = settings() {
            break s;
        }
        if waited.elapsed() > Duration::from_millis(700) {
            break Settings::default();
        }
        Timer::after_millis(20).await;
    };
    apply(&mut p, backlight.as_ref(), display.backlight_percent(false), display.rotation).await;
    BOOT_SCREEN_MS.store(Instant::now().as_millis() as u32, Ordering::Relaxed);

    let mut ui = Ui::new(Instant::now().as_millis());
    let mut names: [Text<24>; 8] = [Text::new(); 8];
    let mut inject_until: u64 = 0;
    let mut was_down = false;
    let mut down_since: u64 = 0;
    loop {
        Timer::after_millis(u64::from(POLL_MS)).await;
        let now = Instant::now().as_millis();
        let req = INJECT_MS.swap(0, Ordering::Relaxed);
        if req != 0 {
            inject_until = now + u64::from(req);
        }
        let down = button.is_low() || now < inject_until;
        if down && !was_down {
            down_since = now;
            BUTTON_PRESSES.fetch_add(1, Ordering::Relaxed);
        } else if !down && was_down && now - down_since >= tdongle_ui::button::HOLD_MS {
            BUTTON_HOLDS.fetch_add(1, Ordering::Relaxed);
        }
        was_down = down;
        let (stored, _) = settings();
        let display = stored.unwrap_or(display);
        // Snapshot and names are copied out of the shared state before anything is formatted or sent.
        let mut ssid = [0u8; 33];
        let mut ssid_len = 0;
        let (saved_count, active_slot) = SAVED.lock(|c| match c.borrow().as_ref() {
            Some(l) => {
                for (i, slot) in l.meta.slot.iter().enumerate().take(l.saved.list().len().min(8)) {
                    names[i] = Text::from_str_truncated(core::str::from_utf8(slot.name_bytes()).unwrap_or(""));
                }
                let sel = crate::SELECTED.load(Ordering::Relaxed);
                if crate::CONNECTED_NOW.load(Ordering::Relaxed) && sel >= 0 {
                    if let Some(p) = l.saved.list().get(sel as usize) {
                        let b = p.ssid_bytes();
                        ssid_len = b.len().min(32);
                        ssid[..ssid_len].copy_from_slice(&b[..ssid_len]);
                    }
                    (l.saved.list().len() as u8, sel as u32 + 1)
                } else {
                    (l.saved.list().len() as u8, 0)
                }
            }
            None => (0, 0),
        });
        let ssid_text = core::str::from_utf8(&ssid[..ssid_len]).unwrap_or("");
        let active_name = if active_slot >= 1 { names[(active_slot - 1) as usize] } else { Text::new() };
        let connected = crate::CONNECTED_NOW.load(Ordering::Relaxed);
        let heap = esp_alloc::HEAP.free() as u32;
        let snapshot = Snapshot {
            bridge: true,
            wifi: connected,
            recovery: false,
            saved_wifi: saved_count > 0,
            active_slot,
            active_name: active_name.as_str(),
            ssid: ssid_text,
            usb: crate::ALT.load(Ordering::Relaxed) != 0,
            usb_configured: crate::CONFIGURED.load(Ordering::Relaxed),
            usb_suspended: false,
            link_connected: connected,
            link_rssi_valid: crate::RSSI_VALID.load(Ordering::Relaxed),
            link_rssi: crate::RSSI.load(Ordering::Relaxed),
            uptime_s: (now / 1000) as u32,
            connects: crate::CONNECTS.load(Ordering::Relaxed),
            last_connect_ms: crate::LAST_CONNECT_MS.load(Ordering::Relaxed),
            last_reason: crate::LAST_REASON.load(Ordering::Relaxed),
            usb_resets: crate::RESETS.load(Ordering::Relaxed),
            heap_free: heap,
            heap_min: crate::l2::HEAP_MIN.load(Ordering::Relaxed).min(heap),
            heap_largest: heap,
            reset_reason: 0,
            ..Snapshot::default()
        };
        let lookup = |slot: u32| -> Option<&str> { names.get((slot as usize).wrapping_sub(1)).map(Text::as_str) };
        let inputs = Inputs {
            button_down: down,
            setup_active: false,
            setup_session: Session::inactive(),
            wifi_ready: connected,
            saved_count,
            display,
            snapshot: Some(snapshot),
            traffic: tdongle_traffic::Reading {
                down_bytes: crate::DOWN_BYTES.load(Ordering::Relaxed),
                up_bytes: crate::UP_BYTES.load(Ordering::Relaxed),
                down_frames: crate::DOWN_FRAMES.load(Ordering::Relaxed),
                up_frames: crate::UP_FRAMES.load(Ordering::Relaxed),
            },
            network_name: &lookup,
        };
        let actions = ui.tick(now, &inputs);
        LAST_PAGE.store(ui.page, Ordering::Relaxed);
        MENU_OPEN.store(ui.menu.open, Ordering::Relaxed);
        if let Some(d) = actions.draw {
            apply(&mut p, backlight.as_ref(), d.backlight_percent, d.rotation).await;
            let view = match &d.content {
                Content::Status(f) => compose(f, FIRMWARE),
                Content::Menu { rows, attention } => {
                    let mut text = [[0u8; tdongle_lcd::ROW_BYTES]; ROWS];
                    for (dst, src) in text.iter_mut().zip(rows.iter()) {
                        let b = src.as_bytes();
                        let n = b.len().min(tdongle_lcd::ROW_BYTES - 1);
                        dst[..n].copy_from_slice(&b[..n]);
                    }
                    compose_rows(&text, *attention)
                }
            };
            p.draw(&view).await;
        }
        if let Some(w) = actions.led {
            led.write(&w.frame);
            LED_RGB.store(u32::from(w.color.r) << 16 | u32::from(w.color.g) << 8 | u32::from(w.color.b), Ordering::Relaxed);
            LED_WRITES.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(cmd) = ui.take_command() {
            dispatch(cmd);
        }
    }
}

/// Backlight percentage and rotation, sent to the hardware only when they change (`apply_locked`).
async fn apply(p: &mut Panel, backlight: Option<&Backlight>, percent: u32, rotation: u8) {
    if let Some(b) = backlight {
        if percent != p.percent {
            b.apply(percent);
            p.percent = percent;
            BACKLIGHT_PCT.store(percent, Ordering::Relaxed);
        }
    }
    if rotation != p.rotation {
        if let Some(c) = panel::rotation_cmd(rotation) {
            p.send(c).await;
            p.rotation = rotation;
            ROTATION.store(rotation, Ordering::Relaxed);
            p.previous = View::POISONED; // repaint
        }
    }
}

/// A command a button gesture chose (`gateway_ui_take_command`): the same lines the serial console takes.
fn dispatch(cmd: Command) {
    match cmd {
        Command::Use(n) => {
            let count = SAVED.lock(|c| c.borrow().as_ref().map_or(0, |l| l.saved.list().len())) as u32;
            if (1..=count).contains(&n) {
                crate::PINNED.store(n as i32 - 1, Ordering::Relaxed);
                crate::USE_REQ.signal(());
            }
        }
        other => crate::ui_command(other),
    }
}
