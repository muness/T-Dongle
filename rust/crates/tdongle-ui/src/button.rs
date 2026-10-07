//! The one button: 30 ms debounce, a hold fires once after 1500 ms, a press while the backlight is dimmed only wakes it
//! (the whole gesture is swallowed). Port of `button_update` in `main/core.c` (test: `tests/test_core.c`, `buttons`).

/// Debounce time.
pub const DEBOUNCE_MS: u64 = 30;
/// Hold time that fires [`ButtonEvent::Hold`].
pub const HOLD_MS: u64 = 1500;

/// What a poll saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonEvent {
    /// Nothing.
    None,
    /// Released after a short press.
    Short,
    /// Held for [`HOLD_MS`] (fires once, while still down).
    Hold,
    /// Pressed while dimmed: only wakes the display; the rest of the gesture is ignored.
    Wake,
}

/// Debouncer state (`button_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Button {
    raw: bool,
    stable: bool,
    fired: bool,
    suppress: bool,
    edge: u64,
    pressed: u64,
}

impl Button {
    /// Released, idle.
    pub const fn new() -> Self {
        Button { raw: false, stable: false, fired: false, suppress: false, edge: 0, pressed: 0 }
    }
    /// One poll. `down` is the raw level (pressed = true), `dimmed` whether the backlight is dimmed, `ms` a 64 bit millisecond clock
    /// (the firmware uses the 64 bit clock: debounce and hold are differences, which a 32 bit count would break at 49.7 days).
    pub fn update(&mut self, down: bool, dimmed: bool, ms: u64) -> ButtonEvent {
        if down != self.raw {
            self.raw = down;
            self.edge = ms;
        }
        if ms.wrapping_sub(self.edge) >= DEBOUNCE_MS && self.stable != down {
            self.stable = down;
            if down {
                self.pressed = ms;
                self.fired = false;
                self.suppress = dimmed;
                if dimmed {
                    return ButtonEvent::Wake;
                }
            } else if !self.fired && !self.suppress {
                return ButtonEvent::Short;
            }
        }
        if self.stable && !self.fired && !self.suppress && ms.wrapping_sub(self.pressed) >= HOLD_MS {
            self.fired = true;
            return ButtonEvent::Hold;
        }
        ButtonEvent::None
    }
}
