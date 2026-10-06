//! C `lcd_render_row`: one scanline, no framebuffer.

use crate::font::glyph;
use crate::view::{DETAIL, EXTRA, FOOTER, HINT, LAYOUT_ROWS, TEXT_BYTES, TITLE, View};
use crate::{LCD_BARS, LCD_ROWS, ROW_BYTES};

/// Colours (RGB565, host byte order), the C `enum {BACKGROUND, ...}`.
pub const BACKGROUND: u16 = 0x10a2;
/// See [`BACKGROUND`].
pub const ACCENT: u16 = 0x86b8;
/// See [`BACKGROUND`].
pub const ATTENTION: u16 = 0xff37;
/// See [`BACKGROUND`].
pub const TEXT: u16 = 0xdf3c;
/// See [`BACKGROUND`].
pub const RULE: u16 = 0x3a68;
/// See [`BACKGROUND`].
pub const FOOTER_COLOR: u16 = 0xb637;
/// See [`BACKGROUND`].
pub const MUTED: u16 = 0x9d75;

/// C `line()`: text at byte offset `off` of the text area, at most 26 characters, glyphs 5 px wide at 6 px pitch times `scale`,
/// clipped at x = 157. Reads stop at the first NUL or the end of the shared text area (never out of bounds).
fn line(out: &mut [u16; 160], y: usize, off: usize, top: usize, scale: usize, color: u16, text: &[u8; TEXT_BYTES]) {
    if y < top || y >= top + 7 * scale {
        return;
    }
    let row = (y - top) / scale;
    let mut i = 0;
    while i < 26 && off + i < TEXT_BYTES && text[off + i] != 0 {
        let g = glyph(text[off + i], row);
        for x in 0..5 * scale {
            let pixel = 3 + i * 6 * scale + x;
            if pixel >= 157 {
                break;
            }
            if g & (1 << (4 - x / scale)) != 0 {
                out[pixel] = color;
            }
        }
        i += 1;
    }
}

/// C `bars()`: `bar_count` bars of 4 px at a 5 px pitch, growing up from row 79, at most 20 px tall (0 is drawn as 1).
fn bars(out: &mut [u16; 160], y: usize, v: &View) {
    if y < 60 {
        return;
    }
    let height_from_bottom = 79 - y + 1;
    let mut i = 0;
    while i < usize::from(v.bar_count) && i < LCD_BARS {
        let mut h = usize::from(v.bars[i]).min(20);
        if h == 0 {
            h = 1;
        }
        if height_from_bottom <= h {
            for x in 0..4 {
                if i * 5 + x < 160 {
                    out[i * 5 + x] = ACCENT;
                }
            }
        }
        i += 1;
    }
}

/// C `lcd_render_row`: scanline `y` (0 to 79; larger values give a background line) as RGB565 in host byte order. Writes only `out`.
pub fn render_row(view: &View, y: usize, out: &mut [u16; 160]) {
    out.fill(BACKGROUND);
    if y >= 80 {
        return;
    }
    let t = &view.text;
    if view.layout == LAYOUT_ROWS {
        for i in 0..LCD_ROWS {
            let color = if i == 0 { if view.attention { ATTENTION } else { ACCENT } } else { TEXT };
            line(out, y, i * ROW_BYTES, 4 + 13 * i, 1, color, t);
        }
        bars(out, y, view);
        return;
    }
    line(out, y, TITLE, 8, 2, if view.attention { ATTENTION } else { ACCENT }, t);
    line(out, y, DETAIL, 28, 1, TEXT, t);
    line(out, y, HINT, 39, 1, TEXT, t);
    line(out, y, EXTRA, 50, 1, MUTED, t);
    if y == 63 {
        for p in out.iter_mut().take(157).skip(3) {
            *p = RULE;
        }
    }
    line(out, y, FOOTER, 69, 1, FOOTER_COLOR, t);
}
