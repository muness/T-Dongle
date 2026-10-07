//! Socket admission and accounting (`socket_budget.{h,c}`).
//!
//! 3 HTTP server internals + 2 HTTP clients + DNS listener/forwarder + SNTP are the recovery reserve ([`GATEWAY_SOCKET_RECOVERY`] = 8
//! descriptors); each membership reserves [`GATEWAY_SOCKETS_PER_MEMBER`] = 5 (DISCO, IPv6 STUN, control TCP, DERP TCP and one transient
//! key-fetch/netcheck socket). There is no product membership cap: the descriptor budget is the cap.
//!
//! The C wraps `lwip_socket`/`lwip_accept`/`lwip_close` with link-time wrappers. In Rust the firmware calls [`Accounting`] from its own socket
//! shims; the structure is the same, the lock is the caller's (a critical section), and no heap, I/O or journal write happens in it.

/// `GATEWAY_SOCKET_RECOVERY`.
pub const GATEWAY_SOCKET_RECOVERY: u32 = 8;
/// `GATEWAY_SOCKETS_PER_MEMBER`.
pub const GATEWAY_SOCKETS_PER_MEMBER: u32 = 5;
/// `CONFIG_LWIP_MAX_SOCKETS` (sdkconfig.defaults) of the device.
pub const CONFIG_LWIP_MAX_SOCKETS: u32 = 20;

/// `gateway_socket_admit`: may another membership start, given `total` descriptors, `active` memberships and `used` descriptors open now?
#[must_use]
pub const fn admit(total: u32, active: u32, used: u32) -> bool {
    total >= GATEWAY_SOCKET_RECOVERY
        && used <= total
        && total - used >= GATEWAY_SOCKETS_PER_MEMBER
        && active < (total - GATEWAY_SOCKET_RECOVERY) / GATEWAY_SOCKETS_PER_MEMBER
}

/// Which wrapper observed an allocation (`last_operation`: 1 socket, 2 accept).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Operation {
    /// `lwip_socket`.
    Socket = 1,
    /// `lwip_accept`.
    Accept = 2,
}

/// `gateway_socket_stats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Descriptors open now.
    pub open: u32,
    /// Highest number open (capped at the descriptor total).
    pub peak: u32,
    /// Allocation failures.
    pub failures: u32,
    /// `errno` of the last failure.
    pub last_errno: u32,
    /// [`Operation`] of the last failure (0 none).
    pub last_operation: u32,
    /// Time of the last failure, ms.
    pub last_at_ms: u32,
}

/// The accounting: observes every allocation and close.
#[derive(Debug, Clone, Copy)]
pub struct Accounting {
    max_sockets: u32,
    stats: Stats,
}

impl Accounting {
    /// For a descriptor total of `max_sockets` (`CONFIG_LWIP_MAX_SOCKETS`).
    #[must_use]
    pub const fn new(max_sockets: u32) -> Self {
        Self { max_sockets, stats: Stats { open: 0, peak: 0, failures: 0, last_errno: 0, last_operation: 0, last_at_ms: 0 } }
    }

    /// An allocation attempt finished: `Ok(())` for a descriptor, `Err(errno)` for a failure. A non-blocking `accept` that failed with
    /// EAGAIN/EWOULDBLOCK is readiness, not an allocation failure: use [`Accounting::accept_would_block`] and do not call this.
    pub fn allocated(&mut self, op: Operation, result: Result<(), u32>, now_ms: u32) {
        match result {
            Err(errno) => {
                self.stats.failures += 1;
                self.stats.last_errno = errno;
                self.stats.last_operation = op as u32;
                self.stats.last_at_ms = now_ms;
            }
            Ok(()) => {
                self.stats.open += 1;
                let observed = self.stats.open.min(self.max_sockets);
                if observed > self.stats.peak {
                    self.stats.peak = observed;
                }
            }
        }
    }

    /// A non-blocking `accept` found nothing: not counted.
    pub fn accept_would_block(&mut self) {}

    /// `lwip_close` succeeded.
    pub fn closed(&mut self) {
        if self.stats.open != 0 {
            self.stats.open -= 1;
        }
    }

    /// `gateway_sockets_snapshot`.
    #[must_use]
    pub const fn snapshot(&self) -> Stats {
        self.stats
    }
}
