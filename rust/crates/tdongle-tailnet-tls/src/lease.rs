//! One 16,640 byte record buffer shared by every DERP connection (feature `lease`, needs the vendored `embedded-tls`, see `rust/vendor/embedded-tls/PATCH.md`).
//!
//! A [`LeasedTlsDerp`] pins **no** read buffer. To read, it first waits for the 5 byte header of the next TLS record (no buffer, no lock: this is
//! where a quiet connection spends its time), then takes the pool's lock, reads the record body into the shared buffer, decrypts it in place,
//! hands the plaintext to a callback and releases the lock. The lock is therefore held for one record's body, the decrypt and the callback, nothing else.
//!
//! **Head-of-line blocking (the weave doc's F2a).** A connection whose server stalls *inside* a record keeps the lock and delays every other
//! membership. The bound chosen here is a **stall timeout started when the lock is taken**: the caller passes a timer future factory, and if the
//! record is not complete in time the read fails with [`ReadError::LeaseTimeout`], the lock is released and the connection must be dropped
//! (its reader is mid-record). Gating on "the whole record is already in the socket" was rejected: the C's lwIP receive window is 5,760 B, smaller
//! than a 16 KB record, so such a gate would never open for the records the server may legally send. The cost of the timeout design is that one
//! stalled membership delays the others by at most the timeout, once, and loses its DERP connection. A record the server sends in one go (Go's
//! derper writes through a 2 KiB bufio, so records are about 2 KB) holds the lock for a few milliseconds.
//!
//! The handshake leases per record as well: the Certificate record (about 4.5 KB) is the largest, but each server flight record is a separate lease.

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
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::mutex::{Mutex, MutexGuard};
use embedded_io_async::{Read, Write};
use tdongle_tailnet_types::Entropy;

/// The shared buffer and its counters. Put one in a `static`.
pub struct LeasePool<M: RawMutex> {
    buf: Mutex<M, [u8; READ_RECORD_BYTES]>,
    holders: AtomicU8,
    max_holders: AtomicU8,
    leases: AtomicU32,
    timeouts: AtomicU32,
}

impl<M: RawMutex> core::fmt::Debug for LeasePool<M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LeasePool").field("max_holders", &self.max_holders()).field("leases", &self.leases()).field("timeouts", &self.timeouts()).finish()
    }
}

impl<M: RawMutex> Default for LeasePool<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: RawMutex> LeasePool<M> {
    /// An empty pool.
    pub const fn new() -> Self {
        Self {
            buf: Mutex::new([0; READ_RECORD_BYTES]),
            holders: AtomicU8::new(0),
            max_holders: AtomicU8::new(0),
            leases: AtomicU32::new(0),
            timeouts: AtomicU32::new(0),
        }
    }
    /// Most holders ever at once (the invariant is 1).
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

/// A held lease on the pool's buffer; released on drop.
pub struct Lease<'a, M: RawMutex> {
    guard: MutexGuard<'a, M, [u8; READ_RECORD_BYTES]>,
    pool: &'a LeasePool<M>,
}

impl<M: RawMutex> core::fmt::Debug for Lease<'_, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Lease")
    }
}
impl<M: RawMutex> Deref for Lease<'_, M> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.guard[..]
    }
}
impl<M: RawMutex> DerefMut for Lease<'_, M> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.guard[..]
    }
}
impl<M: RawMutex> Drop for Lease<'_, M> {
    fn drop(&mut self) {
        self.pool.holders.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The [`RecordBufProvider`] over a pool.
#[derive(Debug)]
pub struct PoolLease<'a, M: RawMutex>(pub &'a LeasePool<M>);

impl<'a, M: RawMutex> RecordBufProvider for PoolLease<'a, M> {
    type Guard<'g>
        = Lease<'g, M>
    where
        Self: 'g;
    fn lease(&mut self) -> impl Future<Output = Lease<'_, M>> {
        let pool: &'a LeasePool<M> = self.0;
        async move {
            let guard = pool.buf.lock().await;
            let n = pool.holders.fetch_add(1, Ordering::Relaxed) + 1;
            pool.max_holders.fetch_max(n, Ordering::Relaxed);
            pool.leases.fetch_add(1, Ordering::Relaxed);
            Lease { guard, pool }
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

/// A TLS 1.3 connection to a DERP server that pins no read record buffer.
pub struct LeasedTlsDerp<'a, IO: Read + Write, M: RawMutex> {
    conn: TlsConnection<'a, IO, Aes128GcmSha256>,
    pool: &'a LeasePool<M>,
    trusted_by: TrustedBy,
    signature_verifies: u8,
}

impl<IO: Read + Write, M: RawMutex> core::fmt::Debug for LeasedTlsDerp<'_, IO, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LeasedTlsDerp").field("trusted_by", &self.trusted_by).finish_non_exhaustive()
    }
}

impl<'a, IO: Read + Write, M: RawMutex> LeasedTlsDerp<'a, IO, M> {
    /// Handshake. Only `write_buf` ([`crate::WRITE_RECORD_BYTES`]) is pinned; every server record is read into the pool's buffer.
    pub async fn connect(
        io: IO,
        write_buf: &'a mut [u8],
        pool: &'a LeasePool<M>,
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
        match conn.open_leased(TlsContext::new(&config, &mut provider), &mut PoolLease(pool)).await {
            Ok(()) => {
                let acc = provider.verifier().accepted().ok_or(ConnectError::Untrusted(Reject::NotTrusted))?;
                Ok(Self { trusted_by: acc.trusted_by, signature_verifies: acc.signature_verifies, conn, pool })
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

    /// Receive one TLS record's plaintext and pass it to `f` (in one or more slices, in order). Returns the plaintext length (0 for a
    /// post-handshake message such as a session ticket: call again). Cancel-safe only while waiting for the header.
    ///
    /// `stall_timeout` is called once, right after the lease is taken, and its future bounds how long the record body may take; if it completes first the
    /// read fails with [`ReadError::LeaseTimeout`] and the lease is released.
    /// `f` runs while the lease is held: copy what you need into your carry buffer (a partial DERP frame, about 2 KB) and return.
    pub async fn read_with<T: Future<Output = ()>>(&mut self, stall_timeout: impl FnOnce() -> T, mut f: impl FnMut(&[u8])) -> Result<usize, ReadError> {
        // 1. No lease while waiting for the server.
        self.conn.wait_record().await.map_err(ReadError::Tls)?;
        // 2. The lease, for this one record.
        let mut provider = PoolLease(self.pool);
        let mut lease = provider.lease().await;
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
