//! The ST7735 panel of the T-Dongle-S3 as data: pins (`main/board.h`), SPI setup and bring-up (`lcd.c` `gateway_display_start`),
//! the init command table and every register write of `components/st7735/esp_lcd_st7735.c`, so the firmware only pushes bytes.
//!
//! The order the C performs (and [`Bringup`] reproduces):
//! 1. backlight pin as output, level 1 (off: active low); SPI bus 2, MOSI/CLK only, 20 MHz, mode 0, 8 bit command and parameter;
//! 2. hardware reset: RST low [`RESET_LOW_MS`], high [`RESET_HIGH_MS`];
//! 3. [`Bringup`]: SLPOUT + 100 ms, MADCTL (BGR only), COLMOD 0x55, the [`INIT_SEQUENCE`] table (whose first entry is a SWRESET: the C
//!    sends it, so do we), then `invert on`, `swap_xy`, `mirror`, `display on`;
//! 4. per scanline: CASET, RASET ([`row_window`]), RAMWR with 320 bytes of [`to_wire`] pixels;
//! 5. backlight: LEDC 1 kHz, 8 bit, duty from [`crate::backlight_duty`] (starts at duty 255 = off until the first frame is drawn).

/// SPI MOSI (C `BOARD_LCD_MOSI`).
pub const PIN_MOSI: u8 = 3;
/// SPI clock (C `BOARD_LCD_CLK`).
pub const PIN_CLK: u8 = 5;
/// Chip select (C `BOARD_LCD_CS`).
pub const PIN_CS: u8 = 4;
/// Data/command (C `BOARD_LCD_DC`).
pub const PIN_DC: u8 = 2;
/// Reset, active low (the C leaves `reset_active_high` false).
pub const PIN_RST: u8 = 1;
/// Backlight (C `BOARD_LCD_BL`), driven by LEDC.
pub const PIN_BL: u8 = 38;
/// `BOARD_LCD_BL_ACTIVE_LOW`: duty 255 is off, 0 is full.
pub const BL_ACTIVE_LOW: bool = true;
/// Backlight PWM frequency (LEDC, 8 bit resolution).
pub const BL_PWM_HZ: u32 = 1000;
/// SPI clock (`cfg.pclk_hz`).
pub const SPI_HZ: u32 = 20_000_000;
/// SPI mode.
pub const SPI_MODE: u8 = 0;
/// Visible size.
pub const WIDTH: u16 = 160;
/// Visible size.
pub const HEIGHT: u16 = 80;
/// `esp_lcd_panel_set_gap(panel, 1, 26)`.
pub const GAP_X: u16 = 1;
/// See [`GAP_X`].
pub const GAP_Y: u16 = 26;
/// Bytes per scanline on the wire (160 pixels of RGB565).
pub const ROW_WIRE_BYTES: usize = 320;
/// Hardware reset: RST held low (ms), then high (ms).
pub const RESET_LOW_MS: u32 = 10;
/// See [`RESET_LOW_MS`].
pub const RESET_HIGH_MS: u32 = 10;
/// Delay after the first SLPOUT of `panel_st7735_init`.
pub const SLPOUT_DELAY_MS: u32 = 100;

/// Command bytes (`ST7735_*` of esp_lcd_st7735.h and `LCD_CMD_*` of esp_lcd_panel_commands.h).
pub mod cmd {
    pub const SWRESET: u8 = 0x01;
    pub const SLPOUT: u8 = 0x11;
    pub const NORON: u8 = 0x13;
    pub const INVON: u8 = 0x21;
    pub const INVOFF: u8 = 0x20;
    pub const DISPOFF: u8 = 0x28;
    pub const DISPON: u8 = 0x29;
    pub const CASET: u8 = 0x2A;
    pub const RASET: u8 = 0x2B;
    pub const RAMWR: u8 = 0x2C;
    pub const MADCTL: u8 = 0x36;
    pub const COLMOD: u8 = 0x3A;
    pub const FRMCTR1: u8 = 0xB1;
    pub const FRMCTR2: u8 = 0xB2;
    pub const FRMCTR3: u8 = 0xB3;
    pub const INVCTR: u8 = 0xB4;
    pub const PWCTR1: u8 = 0xC0;
    pub const PWCTR2: u8 = 0xC1;
    pub const PWCTR3: u8 = 0xC2;
    pub const PWCTR4: u8 = 0xC3;
    pub const PWCTR5: u8 = 0xC4;
    pub const VMCTR1: u8 = 0xC5;
    pub const GMCTRP1: u8 = 0xE0;
    pub const GMCTRN1: u8 = 0xE1;
}

/// MADCTL bits (`LCD_CMD_*_BIT`).
pub const MADCTL_MY: u8 = 0x80;
/// See [`MADCTL_MY`].
pub const MADCTL_MX: u8 = 0x40;
/// See [`MADCTL_MY`].
pub const MADCTL_MV: u8 = 0x20;
/// BGR colour order (`LCD_CMD_BGR_BIT`), set because `rgb_ele_order = BGR`.
pub const MADCTL_BGR: u8 = 0x08;
/// COLMOD for 16 bit RGB565 as `esp_lcd_new_panel_st7735` sets it before the table (the table's own COLMOD, [`COLMOD_TABLE`], follows).
pub const COLMOD_RGB565: u8 = 0x55;
/// The COLMOD value in the init table.
pub const COLMOD_TABLE: u8 = 0x05;

/// One command with up to 16 parameter bytes and a delay after it (C `st7735_lcd_init_cmd_t`, with the data inline).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cmd {
    pub cmd: u8,
    data: [u8; 16],
    len: u8,
    /// Delay after the command (`vTaskDelay(pdMS_TO_TICKS(delay_ms))`; 0 still yields in the C).
    pub delay_ms: u16,
}

impl Cmd {
    /// A command with `data` (at most 16 bytes) and a delay.
    #[must_use]
    pub const fn new(cmd: u8, data: &[u8], delay_ms: u16) -> Self {
        let mut d = [0u8; 16];
        let mut i = 0;
        while i < data.len() {
            d[i] = data[i];
            i += 1;
        }
        Self { cmd, data: d, len: data.len() as u8, delay_ms }
    }
    /// The parameter bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }
}

/// C `vendor_specific_init_default` (all delays are 0 in the table), command by command, including the quirks: SWRESET, SLPOUT, INVON
/// and the others carry one `0x00` data byte (`data_bytes` is 1 in the C table).
pub const INIT_SEQUENCE: [Cmd; 18] = [
    Cmd::new(cmd::SWRESET, &[0x00], 0),
    Cmd::new(cmd::SLPOUT, &[0x00], 0),
    Cmd::new(cmd::FRMCTR1, &[0x05, 0x3A, 0x3A], 0),
    Cmd::new(cmd::FRMCTR2, &[0x05, 0x3A, 0x3A], 0),
    Cmd::new(cmd::FRMCTR3, &[0x05, 0x3A, 0x3A, 0x05, 0x3A, 0x3A], 0),
    Cmd::new(cmd::INVCTR, &[0x03], 0),
    Cmd::new(cmd::PWCTR1, &[0x62, 0x02, 0x04], 0),
    Cmd::new(cmd::PWCTR2, &[0xC0], 0),
    Cmd::new(cmd::PWCTR3, &[0x0D, 0x00], 0),
    Cmd::new(cmd::PWCTR4, &[0x8D, 0x6A], 0),
    Cmd::new(cmd::PWCTR5, &[0x8D, 0xEE], 0),
    Cmd::new(cmd::VMCTR1, &[0x0E], 0),
    Cmd::new(cmd::INVON, &[0x00], 0),
    Cmd::new(cmd::COLMOD, &[COLMOD_TABLE], 0),
    Cmd::new(cmd::GMCTRP1, &[0x10, 0x0E, 0x02, 0x03, 0x0E, 0x07, 0x02, 0x07, 0x0A, 0x12, 0x27, 0x37, 0x00, 0x0D, 0x0E, 0x10], 0),
    Cmd::new(cmd::GMCTRN1, &[0x10, 0x0E, 0x03, 0x03, 0x0F, 0x06, 0x02, 0x08, 0x0A, 0x13, 0x26, 0x36, 0x00, 0x0D, 0x0E, 0x10], 0),
    Cmd::new(cmd::NORON, &[0x00], 0),
    Cmd::new(cmd::DISPON, &[0x00], 0),
];

/// MADCTL for `rotation` after the C's `swap_xy(true)` and `mirror`: rotation 0 is `mirror(false, true)` (BGR | MV | MY = 0xA8),
/// rotation 1 (180 degrees) flips both mirror flags, `mirror(true, false)` (BGR | MV | MX = 0x68). The C applies only rotations 0 and 1
/// (`rotation <= UI_ROTATION_MAX`); any other value is treated as 0, as `gateway_display_start` does.
#[must_use]
pub const fn madctl(rotation: u8) -> u8 {
    let mirror = if rotation == 1 { MADCTL_MX } else { MADCTL_MY };
    MADCTL_BGR | MADCTL_MV | mirror
}

/// The MADCTL command for [`madctl`].
#[must_use]
pub const fn madctl_cmd(rotation: u8) -> Cmd {
    Cmd::new(cmd::MADCTL, &[madctl(rotation)], 0)
}

/// Column/row address window of `draw_bitmap(x_start, y_start, x_end, y_end)` with the gap added: returns the 4 parameter bytes of
/// CASET and of RASET (`start >> 8, start, (end - 1) >> 8, end - 1`). The C asserts `x_start < x_end` and `y_start < y_end`.
#[must_use]
pub const fn window(x_start: u16, y_start: u16, x_end: u16, y_end: u16) -> ([u8; 4], [u8; 4]) {
    let (xs, xe, ys, ye) = (x_start + GAP_X, x_end + GAP_X, y_start + GAP_Y, y_end + GAP_Y);
    ([(xs >> 8) as u8, xs as u8, ((xe - 1) >> 8) as u8, (xe - 1) as u8], [(ys >> 8) as u8, ys as u8, ((ye - 1) >> 8) as u8, (ye - 1) as u8])
}

/// The window of scanline `y` as `draw()` pushes it: `draw_bitmap(0, y, 160, y + 1)`.
#[must_use]
pub const fn row_window(y: u16) -> ([u8; 4], [u8; 4]) {
    window(0, y, WIDTH, y + 1)
}

/// `pixels[x] = (pixels[x] << 8) | (pixels[x] >> 8)`: the byte swap `draw()` applies in place before the transfer.
pub fn swap_row(row: &mut [u16; 160]) {
    for p in row.iter_mut() {
        *p = p.swap_bytes();
    }
}

/// The 320 bytes to clock out for a rendered row: each RGB565 pixel high byte first (what the C sends after [`swap_row`] on a little
/// endian CPU).
#[must_use]
pub fn to_wire(row: &[u16; 160]) -> [u8; ROW_WIRE_BYTES] {
    let mut out = [0u8; ROW_WIRE_BYTES];
    for (i, p) in row.iter().enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&p.to_be_bytes());
    }
    out
}

/// The MADCTL write of `apply_locked` for a rotation change: `Some` only for rotation 0 or 1 (`rotation <= UI_ROTATION_MAX`), and the
/// caller then repaints (C: `memset(&previous, 0xff, ...)`, i.e. `previous = View::POISONED`). 180 degrees flips both mirror flags; the
/// window is symmetric (gap 1,26 inside 132x162), so the gap does not change.
#[must_use]
pub const fn rotation_cmd(rotation: u8) -> Option<Cmd> {
    if rotation <= 1 { Some(madctl_cmd(rotation)) } else { None }
}

/// Every command of `esp_lcd_panel_init` plus the configuration calls of `gateway_display_start`, in order. The C always starts at
/// rotation 0 and applies the stored rotation afterwards with [`rotation_cmd`]. Hardware reset (RST pin, [`RESET_LOW_MS`] /
/// [`RESET_HIGH_MS`]) comes before the first item and is not a command.
///
/// Order: SLPOUT (+100 ms), MADCTL(BGR), COLMOD(0x55), the 18 table entries, INVON, MADCTL(BGR|MV), MADCTL(rotation 0), DISPON.
#[derive(Clone, Copy, Debug)]
pub struct Bringup {
    i: usize,
}

/// Number of commands [`Bringup`] yields.
pub const BRINGUP_LEN: usize = 3 + INIT_SEQUENCE.len() + 4;

impl Bringup {
    /// Start the sequence.
    #[must_use]
    pub const fn new() -> Self {
        Self { i: 0 }
    }
}

impl Default for Bringup {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for Bringup {
    type Item = Cmd;
    fn next(&mut self) -> Option<Cmd> {
        let i = self.i;
        let t = INIT_SEQUENCE.len();
        let c = match i {
            0 => Cmd::new(cmd::SLPOUT, &[], SLPOUT_DELAY_MS as u16),
            1 => Cmd::new(cmd::MADCTL, &[MADCTL_BGR], 0),
            2 => Cmd::new(cmd::COLMOD, &[COLMOD_RGB565], 0),
            n if n < 3 + t => INIT_SEQUENCE[n - 3],
            n if n == 3 + t => Cmd::new(cmd::INVON, &[], 0),
            n if n == 4 + t => Cmd::new(cmd::MADCTL, &[MADCTL_BGR | MADCTL_MV], 0),
            n if n == 5 + t => madctl_cmd(0),
            n if n == 6 + t => Cmd::new(cmd::DISPON, &[], 0),
            _ => return None,
        };
        self.i += 1;
        Some(c)
    }
}
