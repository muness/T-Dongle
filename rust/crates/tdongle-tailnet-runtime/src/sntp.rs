//! The SNTP exchange of the wall clock (the C's `clock_sync`): one request, one answer, over an `embassy-net` UDP socket. The firmware's clock task (server rotation,
//! DNS, the hourly resync) calls it, and the host test runs it through the real stack and the Wi-Fi mux, so a regression of UDP receive on the station shows up
//! there and not first on a board that cannot join.

use core::sync::atomic::{AtomicU32, Ordering};
use embassy_net::udp::UdpSocket;
use embassy_net::Ipv4Address;
use embassy_time::{Duration, with_timeout};

/// Seconds between the NTP epoch (1900) and the Unix epoch.
pub const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
/// Length of the datagram the last answer carried (0: none yet) and the first two bytes of it, for the `tn_sntp` line.
pub static LAST_LEN: AtomicU32 = AtomicU32::new(0);
/// See [`LAST_LEN`].
pub static LAST_HEAD: AtomicU32 = AtomicU32::new(0);

/// Why an exchange failed: 2 the send failed, 3 no answer within `wait`, 4 not a server answer (or a kiss of death), 5 a time before the C's validity floor.
pub async fn exchange(sock: &mut UdpSocket<'_>, ip: Ipv4Address, wait: Duration) -> Result<u64, u32> {
    let mut req = [0u8; 48];
    req[0] = 0x23; // LI 0, version 4, mode 3 (client)
    sock.send_to(&req, (ip, 123)).await.map_err(|_| 2u32)?;
    let mut resp = [0u8; 64];
    let (n, _) = with_timeout(wait, sock.recv_from(&mut resp)).await.ok().and_then(Result::ok).ok_or(3u32)?;
    LAST_LEN.store(n as u32, Ordering::Relaxed);
    LAST_HEAD.store(u32::from(u16::from_be_bytes([resp[0], resp[1]])), Ordering::Relaxed);
    if n < 48 || resp[0] & 7 != 4 || resp[1] == 0 {
        return Err(4);
    }
    let secs = u64::from(u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]));
    let unix = secs.checked_sub(NTP_UNIX_OFFSET).ok_or(4u32)?;
    if unix > 1_700_000_000 { Ok(unix) } else { Err(5) } // the C's validity rule
}
