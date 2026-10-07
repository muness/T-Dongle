//! TLS records read into **per-record leases from the shared [`tdongle_tailnet_pool::Pool`]** (feature `lease`, needs the vendored `embedded-tls`, see
//! `rust/vendor/embedded-tls/PATCH.md`).
//!
//! A [`LeasedTlsDerp`] pins **no** read buffer, and neither does the firmware: it used to share one static 16,640 byte record buffer between the
//! memberships, a lock held for a record's body. Now each record is read into a buffer of exactly the length its header announced (about 2 KB from a Go
//! derper, whose writes go through a 2 KiB bufio; 16,640 at most, RFC 8446 5.2), taken from the pool when the header has arrived and given back when the
//! plaintext has been handed on. Reading waits for no lock, so a stalled server no longer blocks the other memberships' relays; what a stalled record holds
//! is its own few KB, and the **stall timeout** (started when the buffer is taken, as before) still ends it: the read fails with
//! [`ReadError::LeaseTimeout`], the buffer goes back and the connection must be dropped (its reader is mid-record).
//!
//! Memory is admitted like every elastic consumer (ADR 0022): a handshake record is a [`Class::Negotiation`] allocation (the join's transient, which the
//! floor reserves), a data record a [`Class::Record`] one (leaves the elastic floor free). When the pool says no the read **waits** for memory
//! ([`tdongle_tailnet_pool::Pool::alloc_wait`]): the relay is backpressured, nothing is dropped or panics, and the wait is counted.

use crate::READ_RECORD_BYTES;
use crate::cert_name::DerpCert;
use crate::etls::{Aes128GcmSha256, RecordBufProvider, TlsConfig, TlsConnection, TlsContext, TlsError};
use crate::tls::{DerpProvider, DerpVerifier};
use crate::transport::{ConnectError, TlsParams};
use crate::verify::{Reject, TrustedBy, clock_valid};
use core::cell::Cell;
use core::future::Future;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use embassy_futures::select::{Either, select};
use embedded_io_async::{Read, Write};
use tdongle_tailnet_pool::{Class, Mem, PoolBuf};
use tdongle_tailnet_types::Entropy;

/// The counters of the record leases (the buffers themselves come from the pool). Put one in a `static`.
pub struct LeasePool {
    holders: AtomicU8,
    max_holders: AtomicU8,
    leases: AtomicU32,
    timeouts: AtomicU32,
}

impl core::fmt::Debug for LeasePool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LeasePool").field("max_holders", &self.max_holders()).field("leases", &self.leases()).field("timeouts", &self.timeouts()).finish()
    }
}

impl Default for LeasePool {
    fn default() -> Self {
        Self::new()
    }
}

impl LeasePool {
    /// No leases yet.
    pub const fn new() -> Self {
        Self { holders: AtomicU8::new(0), max_holders: AtomicU8::new(0), leases: AtomicU32::new(0), timeouts: AtomicU32::new(0) }
    }
    /// Record buffers held right now (across every connection).
    pub fn holders(&self) -> u8 {
        self.holders.load(Ordering::Relaxed)
    }
    /// Most record buffers ever held at once.
    pub fn max_holders(&self) -> u8 {
        self.max_holders.load(Ordering::Relaxed)
    }
    /// Leases taken.
    pub fn leases(&self) -> u32 {
        self.leases.load(Ordering::Relaxed)
    }
    /// Leases ended by the stall timeout.
    pub fn timeouts(&self) -> u32 {
        self.timeouts.load(Ordering::Relaxed)
    }
}

/// A held lease: one record's buffer; its bytes go back to the pool on drop.
pub struct Lease<'a> {
    buf: PoolBuf<'a>,
    stats: &'a LeasePool,
}

impl core::fmt::Debug for Lease<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Lease")
    }
}
impl Deref for Lease<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}
impl DerefMut for Lease<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.stats.holders.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The [`RecordBufProvider`] over the pool: every lease is a buffer of the announced record's length.
#[derive(Debug)]
pub struct PoolLease<'a> {
    /// The counters.
    pub stats: &'a LeasePool,
    /// Where the buffers come from.
    pub mem: Mem<'a>,
    /// The admission class of the buffers.
    pub class: Class,
}

impl<'a> RecordBufProvider for PoolLease<'a> {
    type Guard<'g>
        = Lease<'a>
    where
        Self: 'g;
    fn lease(&mut self, len: usize) -> impl Future<Output = Lease<'a>> {
        let (stats, mem, class) = (self.stats, self.mem, self.class);
        async move {
            let buf = mem.alloc_wait(class, len.min(READ_RECORD_BYTES)).await;
            let n = stats.holders.fetch_add(1, Ordering::Relaxed) + 1;
            stats.max_holders.fetch_max(n, Ordering::Relaxed);
            stats.leases.fetch_add(1, Ordering::Relaxed);
            Lease { buf, stats }
        }
    }
}

/// Why [`LeasedTlsDerp::read_with`] failed.
#[derive(Clone, Copy, Debug)]
pub enum ReadError {
    /// The record did not arrive in time once the lease was taken; the lease is released and the connection is unusable.
    LeaseTimeout,
    /// TLS or transport failure (including `ConnectionClosed`).
    Tls(TlsError),
}

impl ReadError {
    /// The peer closed the connection (a close_notify, or the TCP end): end of stream, not a failure.
    pub fn is_closed(&self) -> bool {
        matches!(self, ReadError::Tls(TlsError::ConnectionClosed))
    }
}

/// A TLS 1.3 connection to a DERP server that pins no read record buffer.
pub struct LeasedTlsDerp<'a, IO: Read + Write> {
    conn: TlsConnection<'a, IO, Aes128GcmSha256>,
    pool: &'a LeasePool,
    mem: Mem<'a>,
    trusted_by: TrustedBy,
    signature_verifies: u8,
}

impl<IO: Read + Write> core::fmt::Debug for LeasedTlsDerp<'_, IO> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LeasedTlsDerp").field("trusted_by", &self.trusted_by).finish_non_exhaustive()
    }
}

impl<'a, IO: Read + Write> LeasedTlsDerp<'a, IO> {
    /// Handshake. Only `write_buf` ([`crate::WRITE_RECORD_BYTES`]) is pinned; every server record is read into the pool's buffer.
    pub async fn connect(
        io: IO,
        write_buf: &'a mut [u8],
        pool: &'a LeasePool,
        mem: Mem<'a>,
        params: &TlsParams<'_>,
        entropy: &mut dyn Entropy,
    ) -> Result<Self, ConnectError> {
        if !clock_valid(params.now_unix) {
            return Err(ConnectError::ClockNotSet);
        }
        if matches!(params.cert, DerpCert::Invalid) {
            return Err(ConnectError::InvalidCertName);
        }
        let why = Cell::new(None);
        let config = TlsConfig::new().enable_rsa_signatures().with_server_name(params.hostname); // see TlsDerp::connect for why RSA is offered
        let verifier = DerpVerifier::new(params.anchors, params.now_unix, params.cert, &why);
        let mut provider = DerpProvider::new(entropy, verifier);
        let mut conn = TlsConnection::new_leased(io, write_buf);
        match conn.open_leased(TlsContext::new(&config, &mut provider), &mut PoolLease { stats: pool, mem, class: Class::Negotiation }).await {
            Ok(()) => {
                let acc = provider.verifier().accepted().ok_or(ConnectError::Untrusted(Reject::NotTrusted))?;
                Ok(Self { trusted_by: acc.trusted_by, signature_verifies: acc.signature_verifies, conn, pool, mem })
            }
            Err(e) => Err(match why.get() {
                Some(r) => ConnectError::Untrusted(r),
                None => ConnectError::Tls(e),
            }),
        }
    }

    /// How the server's chain was trusted.
    pub fn trusted_by(&self) -> TrustedBy {
        self.trusted_by
    }

    /// Signature verifications the chain check did.
    pub fn signature_verifies(&self) -> u8 {
        self.signature_verifies
    }

    /// Wait until the header of the next TLS record has arrived: no lease is taken and no buffer is touched, so this is the call a task makes while it
    /// waits for the server (and can `select` against other work: it is **cancel-safe**, the header is kept). Follow it with [`LeasedTlsDerp::read_with`],
    /// which then takes the lease at once. Errors as `read_with`'s `ReadError::Tls`.
    pub async fn wait_record(&mut self) -> Result<(), TlsError> {
        self.conn.wait_record().await.map(|_| ())
    }

    /// [`LeasedTlsDerp::wait_record`], returning the length of the record whose header has arrived (its plaintext is at most that many bytes): what a reader that must hold
    /// the record back until its consumer has room needs to know. Cancel-safe like `wait_record`.
    pub async fn wait_record_len(&mut self) -> Result<usize, TlsError> {
        self.conn.wait_record().await
    }

    /// Receive one TLS record's plaintext and pass it to `f` (in one or more slices, in order). Returns the plaintext length (0 for a
    /// post-handshake message such as a session ticket: call again). Cancel-safe only while waiting for the header.
    ///
    /// `stall_timeout` is called once, right after the lease is taken, and its future bounds how long the record body may take; if it completes first the
    /// read fails with [`ReadError::LeaseTimeout`] and the lease is released.
    /// `f` runs while the lease is held: copy what you need into your carry buffer (a partial DERP frame, about 2 KB) and return.
    pub async fn read_with<T: Future<Output = ()>>(&mut self, stall_timeout: impl FnOnce() -> T, mut f: impl FnMut(&[u8])) -> Result<usize, ReadError> {
        // 1. No lease while waiting for the server; the header says how long the record is.
        let len = self.conn.wait_record().await.map_err(ReadError::Tls)?;
        // 2. The lease, for this one record: exactly that many bytes.
        let mut provider = PoolLease { stats: self.pool, mem: self.mem, class: Class::Record };
        let mut lease = provider.lease(len).await;
        let timer = stall_timeout();
        let outcome = select(self.conn.read_record_leased(&mut lease), timer).await;
        match outcome {
            Either::First(Ok(mut rb)) => {
                let mut n = 0;
                while !rb.is_empty() {
                    let chunk = rb.pop(rb.len());
                    f(chunk);
                    n += chunk.len();
                }
                Ok(n)
            }
            Either::First(Err(e)) => Err(ReadError::Tls(e)),
            Either::Second(()) => {
                self.pool.timeouts.fetch_add(1, Ordering::Relaxed);
                Err(ReadError::LeaseTimeout)
            }
        }
    }

    /// Write everything (buffered until `flush`); the write buffer is pinned, not leased.
    pub async fn write_all(&mut self, mut buf: &[u8]) -> Result<(), TlsError> {
        while !buf.is_empty() {
            let n = self.conn.write(buf).await?;
            buf = &buf[n..];
        }
        Ok(())
    }

    /// Push buffered records to the socket.
    pub async fn flush(&mut self) -> Result<(), TlsError> {
        self.conn.flush().await
    }
}
