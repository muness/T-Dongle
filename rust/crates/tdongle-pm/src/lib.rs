//! CPU-frequency power management of the T-Dongle firmware, as a pure `no_std`, allocation-free, `unsafe`-free crate.
//!
//! Port of `components/tdongle_runtime/tdongle_pm_burst.c`, `include/tdongle_pm_burst.h`, `tdongle_pm.c` and `include/tdongle_pm.h`, which stay
//! the specification (design: `docs/adr/0016-dfs-power-management.md`). The hardware (`esp_pm_configure`, `esp_pm_lock_*`, `esp_timer`, the
//! clock) is the [`PmHardware`] trait; locks and timers behind a single burst are [`PmBackend`] and [`ArmTimer`].
//!
//! * [`burst`]: [`PmBurst`], the nesting counter around a lock: acquire on idle to busy, release on busy to idle, forced release, underflow and
//!   interrupt accounting.
//! * [`activity`]: the forwarding-activity hold ([`PmActivity`], [`ActivityState`]): one atomic load per packet while held, a lock acquire and a
//!   one-shot timer after a quiet spell, release [`ACTIVITY_HOLD_US`] (200 ms) after the last note.
//! * [`pm`]: [`Pm`], the registry of up to [`MAX_BURSTS`] bursts over a [`PmHardware`], and the [`PmStatus`] the serial `pm` command prints.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod activity;
pub mod burst;
pub mod pm;

#[cfg(test)]
#[macro_use]
extern crate std;
#[cfg(test)]
mod tests;

pub use activity::{ActivityState, ArmTimer, NoTimer, PmActivity};
pub use burst::{Burst, BurstName, BurstStats, NAME_MAX, NoBackend, PmBackend, PmBurst};
pub use pm::{ACTIVITY_BURST_NAME, ACTIVITY_HOLD_US, BurstId, LockCreate, MAX_BURSTS, MAX_MHZ, MIN_MHZ, Pm, PmHardware, PmStatus, RegisterError, SlotBurst};
