//! The UI poll: port of `alternative/tailnet/main/device_ui.inc` (`gateway_display_tick`, `ui_compose`, `ui_run`, `gateway_ui_take_command`).
//!
//! The firmware calls [`Ui::tick`] every [`POLL_MS`] (the control task does it between commands), with the current time, the raw button level and the
//! facts the poll reads, and performs the returned [`Actions`]. [`Ui::take_command`] hands out the command a gesture chose (the control task takes it
//! right after each tick). Nothing here touches hardware, allocates or locks.

use crate::button::{Button, ButtonEvent};
use crate::led::{self, LedInputs, LedMode, Rgb};
use crate::menu::{Menu, MenuAction, MenuContext, MenuEvent, ROWS, Row};
use crate::settings::Settings;
use crate::setup_boot::{Session, SetupRequest};
use crate::text::Text;
use core::fmt::{self, Write};
use tdongle_traffic::{HISTORY, Reading, Sampler};

/// The poll period the control task uses between commands (`UI_POLL_MS`).
pub const POLL_MS: u32 = 20;
/// The screen is redrawn on a gesture or at least this often (`UI_DRAW_MS`).
pub const DRAW_MS: u32 = 250;
/// The status light is recomputed this often (`UI_LED_MS`).
pub const LED_MS: u32 = led::LED_MS;
/// The status light is rewritten at least this often (`UI_LED_REFRESH_MS`).
pub const LED_REFRESH_MS: u32 = led::REFRESH_MS;
/// The Health page rotates through its three views this often (`UI_HEALTH_ROTATE_MS`).
pub const HEALTH_ROTATE_MS: u32 = 4000;
/// Screen pages (`LCD_PAGES`): 0 Connection, 1 Traffic, 2 Health, 3 Setup.
pub const PAGES: u32 = 4;
/// Health views.
pub const HEALTH_VIEWS: u32 = 3;
/// Longest command a gesture queues (the C slot is 20 bytes with the NUL).
pub const COMMAND_MAX: usize = 19;

/// A command a button gesture chose: the same lines the serial console takes, so the two cannot disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// `setup`
    Setup,
    /// `cancel`
    Cancel,
    /// `use N`
    Use(u32),
    /// `reset`
    Reset,
    /// `confirm-reset`
    ConfirmReset,
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Setup => f.write_str("setup"),
            Command::Cancel => f.write_str("cancel"),
            Command::Use(n) => write!(f, "use {n}"),
            Command::Reset => f.write_str("reset"),
            Command::ConfirmReset => f.write_str("confirm-reset"),
        }
    }
}

impl Command {
    /// The command line.
    pub fn line(&self) -> Text<COMMAND_MAX> {
        let mut t = Text::new();
        let _ = write!(t, "{self}");
        t
    }
}

/// Everything `gateway_display_state` and `ui_compose` read from the rest of the firmware. Strings are the firmware's current values.
#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot<'a> {
    // gateway_display_state (under members_lock)
    /// `!gateway_tailnet_mode()`.
    pub bridge: bool,
    /// Wi-Fi joined (`online`).
    pub wifi: bool,
    /// `gateway_boot_needs_attention()`.
    pub recovery: bool,
    /// At least one Wi-Fi network saved.
    pub saved_wifi: bool,
    /// The saved network in use, 1-based, 0 none.
    pub active_slot: u32,
    /// Display name of the active saved network.
    pub active_name: &'a str,
    /// The joined network's SSID (empty unless joined).
    pub ssid: &'a str,
    /// Tailnet memberships.
    pub saved: u32,
    /// Enabled memberships.
    pub enabled: u32,
    /// Memberships connected and ready.
    pub ready: u32,
    /// Memberships waiting for a sign-in.
    pub login: u32,
    /// Memberships in error.
    pub failed: u32,
    // ui_compose
    /// `gateway_display_is_installing()`.
    pub installing: bool,
    /// `tud_ready()`.
    pub usb: bool,
    /// `tud_mounted()`.
    pub usb_configured: bool,
    /// `tud_suspended()`.
    pub usb_suspended: bool,
    /// `wifi_link_read().connected`.
    pub link_connected: bool,
    /// `wifi_link_read().rssi_valid`.
    pub link_rssi_valid: bool,
    /// `wifi_link_read().rssi` (dBm).
    pub link_rssi: i32,
    /// Setup access point name (`TDongle-XXXXXX`).
    pub setup_ap_name: &'a str,
    /// Seconds since boot from the 64 bit clock (`now` wraps after 49.7 days).
    pub uptime_s: u32,
    /// `wifi_link_stats.connects`.
    pub connects: u32,
    /// `wifi_link_stats.last_connect_ms` (32 bit ms clock).
    pub last_connect_ms: u32,
    /// `wifi_link_stats.last_reason`.
    pub last_reason: u32,
    /// `gateway_usb_health(8)`.
    pub usb_resets: u32,
    /// `esp_get_free_heap_size()`.
    pub heap_free: u32,
    /// Minimum free internal heap since boot.
    pub heap_min: u32,
    /// Largest free internal block; only read when [`Ui::wants_heap_largest`] (the query walks the heap with the allocator locked).
    pub heap_largest: u32,
    /// Reset reason at boot.
    pub reset_reason: u32,
    /// Health tallies from RTC.
    pub boots: u32,
    /// Watchdog resets.
    pub watchdogs: u32,
    /// Panics.
    pub panics: u32,
}

/// What one poll reads.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    /// The raw button level: true while pressed (GPIO0 low).
    pub button_down: bool,
    /// A setup boot (`setup_active`).
    pub setup_active: bool,
    /// The setup session clock.
    pub setup_session: Session,
    /// The setup access point is up (`wifi_ready`).
    pub wifi_ready: bool,
    /// Saved Wi-Fi networks, 0 to 8.
    pub saved_count: u8,
    /// The display settings in force.
    pub display: Settings,
    /// `None` when the state lock is busy (`gateway_display_state` failed): the draw is skipped and tried again next poll.
    pub snapshot: Option<Snapshot<'a>>,
    /// `traffic_read()`.
    pub traffic: Reading,
    /// Display name of saved network `slot` (1-based) for the menu; `None` when the lock is busy (the previous name stays).
    pub network_name: &'a dyn Fn(u32) -> Option<&'a str>,
}

impl fmt::Debug for Inputs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inputs").field("button_down", &self.button_down).field("setup_active", &self.setup_active).field("snapshot", &self.snapshot).finish_non_exhaustive()
    }
}

/// The LCD state of `ui_compose` (the `lcd_state` fields), filled from the sources the C fills them from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LcdFields {
    /// Bridge mode (not tailnet).
    pub bridge: bool,
    /// Wi-Fi joined.
    pub wifi: bool,
    /// Wi-Fi network saved.
    pub saved_wifi: bool,
    /// Recovery screen.
    pub recovery: bool,
    /// Starting overlay (never set by the poll).
    pub starting: bool,
    /// Installing overlay.
    pub installing: bool,
    /// USB ready.
    pub usb: bool,
    /// USB configured.
    pub usb_configured: bool,
    /// USB suspended.
    pub usb_suspended: bool,
    /// Tailnet memberships.
    pub saved: u32,
    /// Enabled.
    pub enabled: u32,
    /// Ready.
    pub ready: u32,
    /// Login pending.
    pub login: u32,
    /// Failed.
    pub failed: u32,
    /// Screen page 0..=3.
    pub page: u32,
    /// RSSI is valid.
    pub rssi_valid: bool,
    /// dBm.
    pub rssi: i32,
    /// Joined SSID (32 bytes).
    pub ssid: Text<32>,
    /// A setup boot.
    pub setup: bool,
    /// Setup access point name (15 bytes).
    pub ap_ssid: Text<15>,
    /// Setup seconds left.
    pub setup_seconds_left: u32,
    /// Down kbit/s.
    pub down_kbps: u32,
    /// Up kbit/s.
    pub up_kbps: u32,
    /// Bytes to the host.
    pub down_bytes: u64,
    /// Bytes from the host.
    pub up_bytes: u64,
    /// Frames to the host.
    pub down_frames: u64,
    /// Frames from the host.
    pub up_frames: u64,
    /// Traffic bars, oldest first, 0..=20.
    pub bars: [u8; HISTORY],
    /// Uptime seconds.
    pub uptime_s: u32,
    /// Seconds since the Wi-Fi join.
    pub wifi_up_s: u32,
    /// Wi-Fi connects.
    pub connects: u32,
    /// Last disconnect reason.
    pub last_reason: u32,
    /// USB resets.
    pub usb_resets: u32,
    /// Free heap.
    pub heap_free: u32,
    /// Minimum free heap.
    pub heap_min: u32,
    /// Largest block (0 unless the Health view that shows it is on the glass).
    pub heap_largest: u32,
    /// Reset reason.
    pub reset_reason: u32,
    /// Boots.
    pub boots: u32,
    /// Watchdog resets.
    pub watchdogs: u32,
    /// Panics.
    pub panics: u32,
    /// Health view 0..=2.
    pub health_view: u32,
    /// Active saved network, 1-based.
    pub active_slot: u32,
    /// Its name (24 bytes).
    pub active_name: Text<24>,
}

/// What goes on the glass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content {
    /// The open menu: rows as [`Menu::render`] produced them; `attention` while a factory reset awaits confirmation.
    Menu {
        /// Menu text.
        rows: [Row; ROWS],
        /// Attention colours.
        attention: bool,
    },
    /// The status screens: compose with the LCD crate (`lcd_compose`).
    Status(LcdFields),
}

/// One redraw: backlight and rotation (the panel layer sends them to the hardware only when they change), then the view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Draw {
    /// Backlight percent (dimmed or configured).
    pub backlight_percent: u32,
    /// 0 or 1 (180 degrees).
    pub rotation: u8,
    /// The view.
    pub content: Content,
}

/// A status-light write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedWrite {
    /// The colour.
    pub color: Rgb,
    /// The 12 byte APA102 frame to clock out MSB first (data on [`led::DATA_PIN`], clock on [`led::CLK_PIN`]).
    pub frame: [u8; 12],
}

/// What the firmware must do after a poll.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Actions {
    /// Restart now: the setup session ended or its access point never came up (`setup_restart(SETUP_REQUEST_LEAVE, 0)`).
    pub restart: Option<SetupRequest>,
    /// Redraw the screen (backlight, rotation, view).
    pub draw: Option<Draw>,
    /// Write the status light.
    pub led: Option<LedWrite>,
}

/// The UI poll state (`ui`). All of it belongs to one caller.
#[derive(Clone, Debug)]
pub struct Ui {
    button: Button,
    /// The button menu.
    pub menu: Menu,
    /// The screen page, 0..=3.
    pub page: u32,
    last_touch_ms: u32,
    last_draw_ms: u32,
    last_led_ms: u32,
    led_sent_ms: u32,
    led_since_ms: u32,
    redraw: bool,
    led: LedMode,
    led_sent: Rgb,
    led_sent_valid: bool,
    led_in: LedInputs,
    traffic: Sampler,
    menu_name: Text<24>,
    pending: Option<Command>,
}

impl Ui {
    /// `ui_start`: at `now_ms`, the light is JOIN, a redraw is due.
    pub fn new(now_ms: u64) -> Self {
        let now = now_ms as u32;
        Ui {
            button: Button::new(),
            menu: Menu::new(),
            page: 0,
            last_touch_ms: now,
            last_draw_ms: 0,
            last_led_ms: 0,
            led_sent_ms: 0,
            led_since_ms: now,
            redraw: true,
            led: LedMode::Join,
            led_sent: Rgb::default(),
            led_sent_valid: false,
            led_in: LedInputs::default(),
            traffic: Sampler::new(),
            menu_name: Text::new(),
            pending: None,
        }
    }

    /// The current Health view (the three views rotate every [`HEALTH_ROTATE_MS`] from the 32 bit clock).
    pub fn health_view(now_ms: u32) -> u32 {
        (now_ms / HEALTH_ROTATE_MS) % HEALTH_VIEWS
    }

    /// The Health view that shows the largest free block is on the glass, so [`Snapshot::heap_largest`] must be read for this poll.
    pub fn wants_heap_largest(&self, now_ms: u64) -> bool {
        self.page == 2 && Self::health_view(now_ms as u32) == 1
    }

    /// The traffic sampler (rates for the serial `status` report).
    pub fn traffic(&self) -> &Sampler {
        &self.traffic
    }

    /// `gateway_ui_take_command`: the command a gesture chose, once. The firmware's control task takes it right after each tick.
    pub fn take_command(&mut self) -> Option<Command> {
        self.pending.take()
    }

    /// `ui_submit`: a command is queued only if the slot is empty.
    fn submit(&mut self, c: Command) {
        if self.pending.is_none() {
            self.pending = Some(c);
        }
    }

    fn run(&mut self, a: MenuAction) {
        match a {
            MenuAction::Setup => self.submit(Command::Setup),
            MenuAction::CancelSetup => self.submit(Command::Cancel),
            MenuAction::Use(n) => self.submit(Command::Use(n)),
            MenuAction::Reset => self.submit(Command::Reset),
            MenuAction::ConfirmReset => self.submit(Command::ConfirmReset),
            MenuAction::None => {}
        }
    }

    /// One poll at `now_ms` (a 64 bit millisecond clock; the 32 bit truncation is taken inside where the C uses it).
    pub fn tick(&mut self, now_ms: u64, input: &Inputs<'_>) -> Actions {
        let now = now_ms as u32;
        let mut out = Actions::default();
        // Before anything that can be unavailable (the panel, the lock): a setup boot always ends, whatever failed to start.
        if input.setup_active && input.setup_session.should_end(now, input.wifi_ready) {
            out.restart = Some(SetupRequest::Leave);
        }
        // A press while the backlight is dimmed only wakes it (the whole gesture is swallowed), as in v0.1.1.
        let mut dim = !input.setup_active && now.wrapping_sub(self.last_touch_ms) > (input.display.dim_seconds as u32) * 1000;
        let event = self.button.update(input.button_down, dim, now_ms);
        if event != ButtonEvent::None {
            self.last_touch_ms = now;
            dim = false;
            self.redraw = true;
            // no network switching during setup (see `use`)
            let ctx = MenuContext { setup_active: input.setup_active, saved_count: if input.setup_active { 0 } else { input.saved_count } };
            match event {
                ButtonEvent::Short => {
                    if !self.menu.handle(&ctx, MenuEvent::Short, now).0 {
                        self.page = (self.page + 1) % PAGES;
                    }
                }
                ButtonEvent::Hold => {
                    let (consumed, action) = self.menu.handle(&ctx, MenuEvent::Hold, now);
                    if consumed {
                        self.run(action);
                    }
                }
                _ => {}
            }
        }
        self.menu.tick(now);
        // Screen: redraw on a gesture or every DRAW_MS.
        if self.redraw || now.wrapping_sub(self.last_draw_ms) >= DRAW_MS {
            if let Some(content) = self.compose(now, now_ms, input) {
                self.last_draw_ms = now;
                self.redraw = false;
                out.draw = Some(Draw { backlight_percent: input.display.backlight_percent(dim), rotation: input.display.rotation, content });
                let mode = led::select(&self.led_in);
                if mode != self.led {
                    self.led = mode;
                    self.led_since_ms = now;
                }
            }
        }
        // Status light: animated every LED_MS, written only when the colour changed (and once a second regardless).
        if now.wrapping_sub(self.last_led_ms) >= LED_MS {
            self.last_led_ms = now;
            let color = led::color(self.led, now, self.led_since_ms);
            if !self.led_sent_valid || color != self.led_sent || now.wrapping_sub(self.led_sent_ms) >= LED_REFRESH_MS {
                out.led = Some(LedWrite { color, frame: led::apa102_frame(color) });
                self.led_sent = color;
                self.led_sent_valid = true;
                self.led_sent_ms = now;
            }
        }
        out
    }

    /// `ui_compose`: the state the screen and the light are drawn from. `None` when the state lock was busy.
    fn compose(&mut self, now: u32, now_ms: u64, input: &Inputs<'_>) -> Option<Content> {
        let s = input.snapshot.as_ref()?;
        let mut st = LcdFields {
            bridge: s.bridge,
            wifi: s.wifi,
            saved_wifi: s.saved_wifi,
            recovery: s.recovery,
            starting: false,
            installing: s.installing,
            usb: s.usb,
            usb_configured: s.usb_configured,
            usb_suspended: s.usb_suspended,
            saved: s.saved,
            enabled: s.enabled,
            ready: s.ready,
            login: s.login,
            failed: s.failed,
            page: self.page,
            health_view: Self::health_view(now),
            rssi_valid: s.link_connected && s.link_rssi_valid,
            rssi: s.link_rssi,
            setup: input.setup_active,
            active_slot: s.active_slot,
            active_name: Text::from_str_truncated(s.active_name),
            ssid: Text::from_str_truncated(s.ssid),
            ..LcdFields::default()
        };
        if input.setup_active {
            st.ap_ssid = Text::from_str_truncated(s.setup_ap_name);
            st.setup_seconds_left = input.setup_session.seconds_left(now);
        }
        self.traffic.sample(&input.traffic, now);
        st.down_kbps = self.traffic.down_kbps;
        st.up_kbps = self.traffic.up_kbps;
        st.down_bytes = self.traffic.down_total;
        st.up_bytes = self.traffic.up_total;
        st.down_frames = self.traffic.down_frames_total;
        st.up_frames = self.traffic.up_frames_total;
        st.bars = self.traffic.bars();
        st.uptime_s = s.uptime_s;
        st.wifi_up_s = if s.wifi && s.connects != 0 { now.wrapping_sub(s.last_connect_ms) / 1000 } else { 0 };
        st.connects = s.connects;
        st.last_reason = s.last_reason;
        st.usb_resets = s.usb_resets;
        st.heap_free = s.heap_free;
        st.heap_min = s.heap_min;
        st.heap_largest = if self.wants_heap_largest(now_ms) { s.heap_largest } else { 0 };
        st.reset_reason = s.reset_reason;
        st.boots = s.boots;
        st.watchdogs = s.watchdogs;
        st.panics = s.panics;
        self.led_in = LedInputs {
            setup: input.setup_active,
            no_network: !s.saved_wifi,
            associated: s.wifi,
            usb_ready: s.usb,
            recovery: s.recovery,
            tailnet: !s.bridge,
            tailnet_ready: s.ready,
            tailnet_failed: s.failed,
            tailnet_login: s.login,
            last_reason: s.last_reason as u16,
        };
        if self.menu.open {
            let ctx = MenuContext { setup_active: input.setup_active, saved_count: if input.setup_active { 0 } else { input.saved_count } };
            // ui_name_of: only the shown item's name is fetched; the previous name stays when the lock is busy.
            let item = if self.menu.item < ctx.item_count() { self.menu.item } else { 0 };
            if item >= 1 && item <= ctx.saved_count as u32 {
                if let Some(n) = (input.network_name)(item) {
                    self.menu_name = Text::from_str_truncated(n);
                }
            }
            let name = self.menu_name;
            let rows = self.menu.render(&ctx, |_| name.as_str());
            return Some(Content::Menu { rows, attention: self.menu.confirm });
        }
        Some(Content::Status(st))
    }
}
