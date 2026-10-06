//! The device UI as pure state machines (the port of the C front panel): the button, the menu, the status light, the display settings, the setup boot,
//! the health tallies and the UI poll that ties them together. No hardware, no allocation, no unsafe code: the firmware supplies the time, the button level
//! and the facts, and performs the [`ui::Actions`] it gets back. The C sources are the specification (see `tests/golden`).

#![no_std]
#![forbid(unsafe_code)]

pub mod access;
pub mod button;
pub mod health;
pub mod led;
pub mod menu;
pub mod reset;
pub mod settings;
pub mod setup_boot;
pub mod text;
pub mod ui;

/// Board pins used by the UI (`main/board.h`).
pub mod board {
    /// BOOT button, active low, internal pull-up.
    pub const BUTTON: u8 = 0;
    /// APA102 data.
    pub const LED_DATA: u8 = crate::led::DATA_PIN;
    /// APA102 clock.
    pub const LED_CLK: u8 = crate::led::CLK_PIN;
}
