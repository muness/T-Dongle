//! The status screen of the T-Dongle-S3, as pure `no_std` logic.
//!
//! Port of `alternative/tailnet/main/lcd_view.{c,h}` (plus `traffic_format_mbps` / `traffic_format_megabytes` of `main/traffic.c`, the
//! `ui_settings_backlight_duty` mapping and the ST7735 panel configuration of `main/board.h`, `lcd.c` and
//! `components/st7735/esp_lcd_st7735.c`). Everything is checked pixel for pixel and byte for byte against the REAL C compiled by
//! `tools/gen_golden.py` (see its header; CI regenerates and diffs).
//!
//! # Design (no_alloc)
//!
//! * [`LcdState`] is the snapshot the control task builds (same fields as C `lcd_state`; text fields are NUL-terminated byte arrays).
//! * [`compose`] turns it into a [`View`]: 170 bytes, no heap, no framebuffer. `View: PartialEq` is `memcmp` of the C struct: the
//!   struct has no padding, [`compose`] zeroes it first, and the status and rows layouts share one 135 byte text area exactly like the C
//!   union, so "unchanged, skip the redraw" is `view == previous`.
//! * [`render_row`] renders one of the 80 scanlines into a caller's `[u16; 160]` (RGB565, host byte order). The firmware swaps bytes
//!   per pixel before the SPI transfer ([`panel::to_wire`]) and pushes it with the window of [`panel::row_window`].
//! * [`panel`] holds the ST7735 pins, the init command sequence, MADCTL and the CASET/RASET windows as data.

#![no_std]
#![forbid(unsafe_code)]

pub mod fmt;
pub mod font;
pub mod panel;
pub mod render;
pub mod state;
pub mod view;

pub use render::render_row;
pub use state::LcdState;
pub use view::{LAYOUT_ROWS, LAYOUT_STATUS, View, compose, compose_rows, format_count, format_duration, format_mbps, format_megabytes};

/// C `LCD_PAGES`: Connection, Traffic, Health, Setup.
pub const LCD_PAGES: u32 = 4;
/// C `LCD_BARS`: bars of the traffic graph.
pub const LCD_BARS: usize = 32;
/// C `LCD_ROWS`: text rows of the rows layout (row 0 is the heading).
pub const LCD_ROWS: usize = 5;
/// Bytes of one text row including the NUL (`char row[LCD_ROWS][27]`): at most 26 characters.
pub const ROW_BYTES: usize = 27;
/// Panel width in pixels (C `BOARD_WIDTH`).
pub const WIDTH: usize = 160;
/// Panel height in pixels (C `BOARD_HEIGHT`).
pub const HEIGHT: usize = 80;
/// Backlight duty (8 bit, active low) for a brightness percent (C `ui_settings_backlight_duty`), reusing the NVS crate's function.
#[must_use]
pub fn backlight_duty(percent: u32) -> u32 {
    tdongle_nvs_format::ui_settings::UiSettings::backlight_duty(percent)
}
