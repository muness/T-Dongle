//! The progress supervisor: a list of liveness counters, each bumped by a heartbeat task that runs in one executor, and a check, run from a task in a *different*,
//! higher-priority executor, that every counter has advanced within its deadline. The watchdog is fed only while all of them have; when one has not, the verdict names it,
//! so the reset reason is "task X stopped" and not just "the watchdog fired".
//!
//! Why not one independent feeding task (the first guard): a task that nothing else can starve proves only that its own executor is polled. The S3 board run showed the
//! gap: the console task, on the same executor as everything else, could stop being polled while the feeding task kept running (or, with a driver call that never returns inside
//! a critical section, nothing ran and only the hardware watchdog was left, naming nothing). Pure and tested: `no_std`, no unsafe code.

/// What a check found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// Every counter advanced in time: feed the watchdog.
    Healthy,
    /// This counter's task made no progress for longer than its deadline: record it, do not feed, reset.
    Stalled(&'static str),
}

/// `N` liveness counters with a deadline each.
#[derive(Clone, Copy, Debug)]
pub struct Watch<const N: usize> {
    names: [&'static str; N],
    deadline_ms: [u32; N],
    last: [u32; N],
    advanced_at: [u64; N],
}

impl<const N: usize> Watch<N> {
    /// Counters named `names`, each allowed `deadline_ms` without advancing, all considered fresh at `now_ms` (a start-up grace: nothing can be stalled before its deadline).
    #[must_use]
    pub const fn new(names: [&'static str; N], deadline_ms: [u32; N], now_ms: u64) -> Self {
        Self { names, deadline_ms, last: [0; N], advanced_at: [now_ms; N] }
    }

    /// Look at the counters at `now_ms`. A counter that differs from the last reading has advanced (wrapping is fine: only equality matters). The first stalled counter in
    /// declaration order is reported.
    pub fn check(&mut self, now_ms: u64, counters: [u32; N]) -> Verdict {
        let mut stalled = None;
        for (i, &counter) in counters.iter().enumerate() {
            if counter != self.last[i] {
                self.last[i] = counter;
                self.advanced_at[i] = now_ms;
            } else if now_ms.saturating_sub(self.advanced_at[i]) > u64::from(self.deadline_ms[i]) && stalled.is_none() {
                stalled = Some(self.names[i]);
            }
        }
        stalled.map_or(Verdict::Healthy, Verdict::Stalled)
    }
}
