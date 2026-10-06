//! The `pm` command: the report lines of `control.c` `pm_report`, over plain input structs (the firmware maps `tdongle_pm_status_t` into them).
//!
//! The command prints the `power` line, one `pm_lock` line per registered burst lock, and then IDF's own lock table
//! (`esp_pm_dump_locks`) under [`crate::reply::PM_DUMP_HEADER`], cut into console sized lines by [`write_dump`].

use crate::reply::PM_DUMP_HEADER;
use crate::text::emit;
use core::fmt;

/// The scaling state (the head of `tdongle_pm_status_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Power {
    /// `esp_pm_configure` succeeded: the CPU moves between min and max (printed `%d`: 0 or 1).
    pub scaling: bool,
    /// `esp_err_t` of the last `tdongle_pm_start` (0 = `ESP_OK`).
    pub configure_error: i32,
    /// The clock right now, MHz.
    pub cpu_mhz: u32,
    /// Configured maximum, MHz; 0 when scaling is off.
    pub max_mhz: u32,
    /// Configured minimum, MHz; 0 when scaling is off.
    pub min_mhz: u32,
    /// Locks that could not be created.
    pub lock_create_failures: u32,
}

/// One CPU-frequency-max lock (`tdongle_pm_burst_stats_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lock<'a> {
    /// Lock name.
    pub name: &'a str,
    /// Nesting depth now.
    pub depth: u32,
    /// Idle to busy transitions.
    pub acquires: u32,
    /// Busy to idle transitions, including forced ones.
    pub releases: u32,
    /// Total time busy; wraps at 2^32 us.
    pub held_us: u32,
    /// Deepest nesting.
    pub max_depth: u32,
    /// `end()` without `begin()`.
    pub underflows: u32,
    /// `release_all()` found the section still open.
    pub forced_releases: u32,
    /// The backend refused an acquire.
    pub backend_failures: u32,
    /// Calls refused from an interrupt.
    pub isr_rejects: u32,
}

/// `power scaling=%d cpu_mhz=%lu max_mhz=%lu min_mhz=%lu configure_error=%d lock_create_failures=%lu`, in the 200 byte line buffer of C.
///
/// # Errors
/// Whatever the sink returns.
pub fn write_power<W: fmt::Write>(w: &mut W, p: &Power) -> fmt::Result {
    emit(
        w,
        &mut [0; 200],
        format_args!(
            "power scaling={} cpu_mhz={} max_mhz={} min_mhz={} configure_error={} lock_create_failures={}\r\n",
            u8::from(p.scaling),
            p.cpu_mhz,
            p.max_mhz,
            p.min_mhz,
            p.configure_error,
            p.lock_create_failures
        ),
    )
}

/// `pm_lock name=%s depth=%lu ...`, in the 200 byte line buffer of C (a very long name would cut the line, as it does there).
///
/// # Errors
/// Whatever the sink returns.
pub fn write_lock<W: fmt::Write>(w: &mut W, b: &Lock<'_>) -> fmt::Result {
    emit(
        w,
        &mut [0; 200],
        format_args!(
            "pm_lock name={} depth={} acquires={} releases={} held_us={} max_depth={} underflows={} forced_releases={} backend_failures={} \
             isr_rejects={}\r\n",
            b.name, b.depth, b.acquires, b.releases, b.held_us, b.max_depth, b.underflows, b.forced_releases, b.backend_failures, b.isr_rejects
        ),
    )
}

/// The `esp_pm_dump_locks` text as `pm_report` prints it, after the [`PM_DUMP_HEADER`] (which this writes first).
///
/// The C loop, kept exactly: split at `\n`, send each piece (at most 117 bytes) plus `\r\n`, an empty line included. A line longer than
/// 117 bytes is cut and then **the next byte is skipped as if it were the newline**; that byte is lost, and the rest of the line comes out
/// as a further piece. (The real table's lines are far shorter.) The text ends at its first NUL.
///
/// # Errors
/// Whatever the sink returns.
pub fn write_dump<W: fmt::Write>(w: &mut W, dump: &str) -> fmt::Result {
    const PART_MAX: usize = 120 - 3;
    w.write_str(PM_DUMP_HEADER)?;
    let mut rest = dump.split('\0').next().unwrap_or("").as_bytes();
    while !rest.is_empty() {
        let eol = rest.iter().position(|&b| b == b'\n');
        let mut n = eol.unwrap_or(rest.len());
        if n > PART_MAX {
            n = PART_MAX;
        }
        // ASCII in practice; a cut inside a multi-byte character drops the dangling bytes.
        let piece = &rest[..n];
        w.write_str(core::str::from_utf8(piece).unwrap_or_else(|e| core::str::from_utf8(&piece[..e.valid_up_to()]).unwrap_or("")))?;
        w.write_str("\r\n")?;
        rest = &rest[(n + usize::from(eol.is_some())).min(rest.len())..];
        if eol.is_none() {
            break;
        }
    }
    Ok(())
}

/// The whole `pm` reply: the power line, a line per lock, then (when the firmware could read it) the lock table.
///
/// # Errors
/// Whatever the sink returns.
pub fn write_report<W: fmt::Write>(w: &mut W, power: &Power, locks: &[Lock<'_>], dump: Option<&str>) -> fmt::Result {
    write_power(w, power)?;
    for lock in locks {
        write_lock(w, lock)?;
    }
    if let Some(dump) = dump { write_dump(w, dump) } else { Ok(()) }
}
