//! Draining one ready UDP socket (`ml_net_io_drain.h`, ADR 0019).
//!
//! The bug this replaces: net_io read ONE datagram from a ready socket per select pass, while lwIP's per-socket mailbox, when full, frees the
//! datagram without counting it anywhere (~7 % of a 3 Mbit/s stream was lost silently). A ready socket is now read until it is empty, capped
//! at [`ML_NET_IO_DRAIN_CAP`] per call so one busy socket cannot hold the shared net_io task for long; whatever is left stays in the mailbox
//! and `drain_capped` counts the times that happened. Datagrams of one socket reach the sink in the order `recv` returned them.

use crate::rx_stats::{RxStat, RxStats};

pub use crate::limits::{ML_NET_IO_DEEP, ML_NET_IO_DRAIN_CAP};

/// What one `recv` returned (`ML_DRAIN_EMPTY`, `ML_DRAIN_ERROR`, or a length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recv {
    /// A datagram of this length was written to the buffer (0 allowed: an empty UDP datagram).
    Datagram {
        /// Length in bytes.
        len: usize,
        /// Source IPv4 address.
        src_ip: u32,
        /// Source port.
        src_port: u16,
    },
    /// Nothing (more) to read (EAGAIN / EWOULDBLOCK).
    Empty,
    /// `recv` failed for another reason.
    Error,
}

/// The socket side of the drain.
pub trait Source {
    /// Read one datagram into `buf`.
    fn recv(&mut self, buf: &mut [u8]) -> Recv;
}

/// Where non-empty datagrams go.
pub trait Sink {
    /// One datagram, in arrival order.
    fn datagram(&mut self, data: &[u8], src_ip: u32, src_port: u16);
}

/// `ml_net_io_drain`: reads up to `max` datagrams, returns how many were read (empty ones included).
pub fn drain(src: &mut impl Source, sink: &mut impl Sink, stats: &RxStats, scratch: &mut [u8], max: u32) -> u32 {
    let mut got = 0;
    while got < max {
        match src.recv(scratch) {
            Recv::Empty => break,
            Recv::Error => {
                stats.add(RxStat::UdpRecvErr, 1);
                break;
            }
            Recv::Datagram { len, src_ip, src_port } => {
                got += 1;
                stats.add(RxStat::UdpRx, 1);
                if len == 0 {
                    stats.add(RxStat::UdpRxEmpty, 1);
                    continue;
                }
                let len = len.min(scratch.len());
                sink.datagram(&scratch[..len], src_ip, src_port);
            }
        }
    }
    stats.add(RxStat::DrainCalls, 1);
    if got == max {
        stats.add(RxStat::DrainCapped, 1);
    }
    if got >= ML_NET_IO_DEEP {
        stats.add(RxStat::DrainDeep, 1);
    }
    stats.burst(got);
    got
}
