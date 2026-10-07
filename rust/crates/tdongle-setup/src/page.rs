//! The two embedded pages, byte for byte the C files (`tests/assets.rs` compares them with `alternative/tailnet/main`).
//!
//! The C embeds them with `EMBED_TXTFILES`: no compression or minification, and a NUL byte is appended to each. The setup access point's
//! page is searched with `strstr` (so the NUL ends it) and sent in three chunks around the token; the USB page is sent with
//! `setup_html_end - setup_html_start`, which **includes that NUL** (an ESP-IDF text embed is `file bytes + 0`): [`SETUP_HTML_WIRE`].

/// `alternative/tailnet/main/setup_ap.html`, with the token marker.
pub const SETUP_AP_HTML: &[u8] = include_bytes!("../assets/setup_ap.html");
/// `alternative/tailnet/main/setup.html` (the USB page; unreachable from a setup boot, which has no USB netif).
pub const SETUP_HTML: &[u8] = include_bytes!("../assets/setup.html");
/// What the C sends for the USB page: the file and the NUL of the text embed.
pub const SETUP_HTML_WIRE_NUL: &[u8] = b"\0";
/// The token placeholder `strstr` looks for.
pub const TOKEN_MARKER: &[u8] = b"@@TOKEN@@";
/// The Content-Security-Policy of the setup access point's page.
pub const AP_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'";
/// The Content-Security-Policy of the USB page.
pub const USB_CSP: &str = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'";

/// The page split around the token marker: `(before, after)`; `None` if the marker is missing (the C answers 500 "Setup page unavailable").
#[must_use]
pub fn split_at_token() -> Option<(&'static [u8], &'static [u8])> {
    let at = SETUP_AP_HTML.windows(TOKEN_MARKER.len()).position(|w| w == TOKEN_MARKER)?;
    Some((&SETUP_AP_HTML[..at], &SETUP_AP_HTML[at + TOKEN_MARKER.len()..]))
}
