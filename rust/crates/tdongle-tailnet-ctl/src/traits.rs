//! The platform hooks of the driver.

use core::future::Future;
use embedded_io_async::{Read, Write};
use tdongle_tailnet_control::requests::Endpoint;
use tdongle_tailnet_types::Millis;

/// Opens TCP connections to the control server (port 80 for the device, plain HTTP). Called once for the `/key` fetch (when the key is not pinned)
/// and once for the control connection; the first stream is dropped before the second is opened.
pub trait Connect {
    /// The byte stream.
    type Stream: Read + Write;
    /// Open a connection, or `Err(())` if it cannot be made.
    #[allow(async_fn_in_trait)]
    async fn connect(&mut self) -> Result<Self::Stream, ()>;
}

/// Time: a monotonic clock and a timeout combinator (the driver takes no executor dependency).
pub trait Clock {
    /// Monotonic milliseconds.
    fn now(&self) -> Millis;
    /// Run `fut`, dropping it and returning `None` if it has not finished after `ms` milliseconds.
    #[allow(async_fn_in_trait)]
    async fn timeout<F: Future>(&mut self, ms: u32, fut: F) -> Option<F::Output>;
}

/// The negotiation-token hooks (ADR 0013: phase A is held from before the TCP connect until the first map is applied or anything fails).
pub trait Gate {
    /// Before the connect and handshake; may wait.
    #[allow(async_fn_in_trait)]
    async fn begin_negotiation(&mut self);
    /// After the first map was applied (`ok`), or on a failure before that.
    #[allow(async_fn_in_trait)]
    async fn end_negotiation(&mut self, ok: bool);
}

/// A [`Gate`] that does nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoGate;

impl Gate for NoGate {
    async fn begin_negotiation(&mut self) {}
    async fn end_negotiation(&mut self, _ok: bool) {}
}

/// Where new local endpoints come from (the C's STUN results). Polled at least once a second while the map stream is open.
pub trait EndpointSource {
    /// If the endpoint set changed since the last call, write it to `out` and return its length; otherwise `None`. The driver sends a lite update
    /// (`Stream=false`, `OmitPeers=true`) only if the resulting request differs from the last one it sent.
    fn poll_endpoints(&mut self, out: &mut [Endpoint]) -> Option<usize>;
}

/// An [`EndpointSource`] with no endpoints.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoEndpoints;

impl EndpointSource for NoEndpoints {
    fn poll_endpoints(&mut self, _out: &mut [Endpoint]) -> Option<usize> {
        None
    }
}
