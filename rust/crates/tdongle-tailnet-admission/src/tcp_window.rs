//! Build-time checks for the lwIP TCP window settings (`tcp_window_budget.h`, `tools/test-tcp-window.py`, ADR 0015 and 0022).
//!
//! The C includes the header in `gateway_main.c` so a firmware with inconsistent values does not compile, and a Python tool compiles it against
//! `sdkconfig.defaults` and against deliberately wrong values. Here [`Params::violations`] is the same set of assertions as a `const fn`, the
//! device's values are [`SDKCONFIG`], and a `const` assertion makes them a build error.

use crate::heap::ML_HB_PIN_BUFFERS;

/// One of the six assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Violation {
    /// `TCP_WND` over 64 KB needs window scaling, which this board cannot enable.
    WindowOver64k = 0,
    /// The receive mailbox is smaller than window/MSS + 2: lwIP would drop segments the window said it would accept.
    MailboxTooSmall,
    /// One stalled socket could pin more than half the dynamic Wi-Fi RX pool.
    PinsHalfTheRxPool,
    /// The window can pin more Wi-Fi RX buffers than the heap budget allows (ADR 0022).
    PinsMoreThanHeapBudget,
    /// The send buffer needs more segments than the default segment pool.
    SendBufferSegments,
    /// lwIP needs at least two segments of window and send buffer.
    BelowTwoSegments,
}

/// The lwIP and Wi-Fi settings the checks read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// `TCP_WND` (`CONFIG_LWIP_TCP_WND_DEFAULT`).
    pub tcp_wnd: u32,
    /// `TCP_SND_BUF` (`CONFIG_LWIP_TCP_SND_BUF_DEFAULT`).
    pub tcp_snd_buf: u32,
    /// `TCP_MSS`.
    pub tcp_mss: u32,
    /// `LWIP_WND_SCALE`.
    pub wnd_scale: bool,
    /// `DEFAULT_TCP_RECVMBOX_SIZE` (`CONFIG_LWIP_TCP_RECVMBOX_SIZE`).
    pub recvmbox: u32,
    /// `CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM`.
    pub wifi_dynamic_rx: u32,
    /// `MEMP_NUM_TCP_SEG` (lwIP's default segment pool, 16).
    pub memp_num_tcp_seg: u32,
}

/// `sdkconfig.defaults` of the C firmware, with the IDF v5.5.5 defaults for what it leaves alone (MSS 1440, `MEMP_NUM_TCP_SEG` 16).
pub const SDKCONFIG: Params =
    Params { tcp_wnd: 8640, tcp_snd_buf: 11_520, tcp_mss: 1440, wnd_scale: false, recvmbox: 8, wifi_dynamic_rx: 16, memp_num_tcp_seg: 16 };

impl Params {
    /// The violated assertions, as a bit set indexed by [`Violation`] (`1 << v as u8`). Empty means the settings are consistent.
    #[must_use]
    pub const fn violations(&self) -> u8 {
        let segs = self.tcp_wnd / self.tcp_mss;
        let mut v = 0u8;
        if !self.wnd_scale && self.tcp_wnd > 65_535 {
            v |= 1 << Violation::WindowOver64k as u8;
        }
        if self.recvmbox < segs + 2 {
            v |= 1 << Violation::MailboxTooSmall as u8;
        }
        if segs > self.wifi_dynamic_rx / 2 {
            v |= 1 << Violation::PinsHalfTheRxPool as u8;
        }
        if segs > ML_HB_PIN_BUFFERS {
            v |= 1 << Violation::PinsMoreThanHeapBudget as u8;
        }
        if self.tcp_snd_buf / self.tcp_mss > self.memp_num_tcp_seg {
            v |= 1 << Violation::SendBufferSegments as u8;
        }
        if self.tcp_snd_buf < 2 * self.tcp_mss || self.tcp_wnd < 2 * self.tcp_mss {
            v |= 1 << Violation::BelowTwoSegments as u8;
        }
        v
    }

    /// Whether `v` is among the violations.
    #[must_use]
    pub const fn violates(&self, v: Violation) -> bool {
        self.violations() & (1 << v as u8) != 0
    }

    /// Wi-Fi RX buffers one TCP window can pin, in segments.
    #[must_use]
    pub const fn window_segments(&self) -> u32 {
        self.tcp_wnd / self.tcp_mss
    }
}

const _: () = assert!(SDKCONFIG.violations() == 0, "sdkconfig.defaults violates the TCP window budget");
#[allow(clippy::manual_is_multiple_of)]
const _: () = assert!(SDKCONFIG.tcp_wnd % SDKCONFIG.tcp_mss == 0 && SDKCONFIG.tcp_wnd >= 5760, "a whole number of segments, at least the 5,760 B baseline");
