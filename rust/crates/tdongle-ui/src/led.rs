//! The APA102 status light: one pixel, GPIO39 clock / GPIO40 data (original T-Dongle-S3). Port of `main/led.{h,c}` (test: `tests/test_led.c`).
//!
//! States: SETUP breathing blue; JOIN breathing amber; UP one bright arrival glow then steady green; FAIL two red blinks; ATTENTION slow red breathing
//! (recovery mode); LOGIN breathing cyan (tailnet mode, waiting for the sign-in). The bit-banging is the firmware's; this crate yields the frame bytes.

/// APA102 clock pin.
pub const CLK_PIN: u8 = 39;
/// APA102 data pin.
pub const DATA_PIN: u8 = 40;
/// Animation step: the colour is recomputed this often.
pub const LED_MS: u32 = 50;
/// The pixel is rewritten at least this often even when unchanged (so a glitch on the two wires cannot persist).
pub const REFRESH_MS: u32 = 1000;
/// Brightness header byte of the single pixel (`0xE0 | 2`).
pub const BRIGHTNESS_HEADER: u8 = 0xe2;

/// Which pattern to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedMode {
    /// Joining Wi-Fi, waiting for USB, or waiting for the tailnet.
    Join,
    /// Setup access point, or no Wi-Fi network saved.
    Setup,
    /// Up.
    Up,
    /// Join failure.
    Fail,
    /// Recovery mode.
    Attention,
    /// Waiting for a tailnet sign-in approval.
    Login,
}

/// A colour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rgb {
    /// Red.
    pub r: u8,
    /// Green.
    pub g: u8,
    /// Blue.
    pub b: u8,
}

/// What the mode is chosen from (`led_inputs`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LedInputs {
    /// Setup access point running.
    pub setup: bool,
    /// No Wi-Fi network saved.
    pub no_network: bool,
    /// Joined Wi-Fi.
    pub associated: bool,
    /// USB link ready.
    pub usb_ready: bool,
    /// Recovery mode.
    pub recovery: bool,
    /// Tailnet gateway mode.
    pub tailnet: bool,
    /// Tailnets ready.
    pub tailnet_ready: u32,
    /// Tailnets failed.
    pub tailnet_failed: u32,
    /// Tailnets waiting for a sign-in.
    pub tailnet_login: u32,
    /// `wifi_err_reason_t` of the last disconnect.
    pub last_reason: u16,
}

/// Disconnect reasons that mean "wrong network or password" (`NO_AP_FOUND` 201, `AUTH_FAIL` 202, `4WAY_HANDSHAKE_TIMEOUT` 15).
pub fn reason_is_join_failure(reason: u16) -> bool {
    reason == 201 || reason == 202 || reason == 15
}

/// The mode for the current inputs (`led_select`).
pub fn select(i: &LedInputs) -> LedMode {
    if i.recovery {
        return LedMode::Attention;
    }
    if i.setup || i.no_network {
        return LedMode::Setup;
    }
    if i.tailnet {
        if i.associated && i.tailnet_login != 0 {
            return LedMode::Login;
        }
        if i.associated && i.tailnet_ready != 0 && i.usb_ready {
            return LedMode::Up;
        }
        if i.associated && i.tailnet_failed != 0 {
            return LedMode::Fail;
        }
    } else if i.associated && i.usb_ready {
        return LedMode::Up;
    }
    if !i.associated && reason_is_join_failure(i.last_reason) {
        return LedMode::Fail;
    }
    LedMode::Join
}

/// A slow triangle wave, 40..=255, so the status reads as "alive" rather than "blinking".
fn breathe(now: u32, period_ms: u32) -> u32 {
    let t = now % period_ms;
    let half = period_ms / 2;
    let up = if t < half { t } else { period_ms - t };
    40 + up * 215 / half
}

/// The colour to show at `now_ms`; `since_ms` is when the current mode began (for the arrival glow and the blink phase).
pub fn color(mode: LedMode, now_ms: u32, since_ms: u32) -> Rgb {
    let since = now_ms.wrapping_sub(since_ms);
    match mode {
        LedMode::Setup => Rgb { r: 0, g: 0, b: (breathe(now_ms, 3000) * 180 / 255) as u8 },
        LedMode::Up => {
            if since < 1200 {
                let w = 120 - since * 120 / 1200;
                Rgb { r: w as u8, g: 180, b: w as u8 }
            } else {
                Rgb { r: 0, g: 180, b: 0 }
            }
        }
        LedMode::Fail => {
            let t = since % 2000;
            Rgb { r: if t < 150 || (300..450).contains(&t) { 180 } else { 0 }, g: 0, b: 0 }
        }
        LedMode::Attention => Rgb { r: (breathe(now_ms, 4000) * 180 / 255) as u8, g: 0, b: 0 },
        LedMode::Login => {
            let k = breathe(now_ms, 2400);
            Rgb { r: 0, g: (k * 150 / 255) as u8, b: (k * 180 / 255) as u8 }
        }
        LedMode::Join => {
            let k = breathe(now_ms, 1600);
            Rgb { r: (k * 120 / 255) as u8, g: (k * 60 / 255) as u8, b: 0 }
        }
    }
}

/// The 12 byte APA102 frame for one pixel: 4 byte start frame (zeros), the LED frame (brightness header `0xE2`, blue, green, red), 4 byte end frame (`0xFF`).
pub fn apa102_frame(c: Rgb) -> [u8; 12] {
    [0, 0, 0, 0, BRIGHTNESS_HEADER, c.b, c.g, c.r, 0xff, 0xff, 0xff, 0xff]
}
