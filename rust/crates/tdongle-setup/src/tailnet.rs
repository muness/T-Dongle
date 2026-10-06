//! The tailnet seam: one small private adapter, so the tailnet port can replace it with its own trait (`tdongle-tailnet-fw` on
//! `rust/tailnet`) without touching the router.
//!
//! In a setup boot nothing of the tailnet side runs (ADR 0024: `start_member` refuses, no manager, no directory), so every reply is the
//! C's "not available" text. The router calls these only for the **USB** origin: the setup network never reaches them (its action
//! allowlist stops at `wifi`, `wifi_remove`, `setup_done`).

use crate::access::Action;
use crate::json::Fields;

/// The reply a request gets when the tailnet side is not part of this boot (`failure(req, ...)` for the setup network).
pub const NOT_AVAILABLE: &str = "That is not available from the setup network";

/// The tailnet-side endpoints and actions. Private: the default is the setup-boot behaviour.
#[derive(Debug, Default)]
pub(crate) struct Adapter;

/// What a tailnet-side request produced.
pub(crate) enum Reply {
    /// Nothing to add to the standard `{"ok":true}`.
    #[allow(dead_code)]
    Done,
    /// `failure(req, message)`.
    Failure(&'static str),
}

impl Adapter {
    /// `mode`, `add`, `remove`, `enable`: the membership and routing-mode actions of `/command`.
    pub(crate) fn action(&mut self, _action: Action, _fields: &Fields) -> Reply {
        Reply::Failure(NOT_AVAILABLE)
    }

    /// `/status`, `/diagnostics` and `/boot-status` for the USB origin: the tailnet report.
    pub(crate) fn report(&mut self) -> Reply {
        Reply::Failure(NOT_AVAILABLE)
    }
}
