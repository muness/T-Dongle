//! The setup access point's DHCP server: `tdongle-dhcp` (the lwIP server's behaviour) over one embassy-net UDP socket on port 67.
//!
//! Every reply goes out as a broadcast to 255.255.255.255:68: a client that does not have its address yet cannot answer an ARP request for it, and DHCP clients accept a
//! broadcast reply whatever their BROADCAST flag says (lwIP unicasts through a temporary ARP entry; the on-air difference is only the destination MAC).

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, Ipv4Address, Stack};
use embassy_time::{Instant, Timer};

#[embassy_executor::task]
pub async fn task(stack: Stack<'static>) -> ! {
    let mut rx_meta = [PacketMetadata::EMPTY; 4];
    let mut tx_meta = [PacketMetadata::EMPTY; 4];
    let mut rx = [0u8; 4 * 600];
    let mut tx = [0u8; 2 * 600];
    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx, &mut tx_meta, &mut tx);
    let Ok(mut server) = tdongle_dhcp::Server::new(tdongle_dhcp::Config::setup_ap()) else {
        crate::init_note("setup: DHCP server config refused");
        loop {
            Timer::after_secs(3600).await;
        }
    };
    if socket.bind(67).is_err() {
        crate::init_note("setup: DHCP server could not bind port 67");
        loop {
            Timer::after_secs(3600).await;
        }
    }
    let mut request = [0u8; tdongle_dhcp::MAX_REQUEST];
    let mut reply = [0u8; tdongle_dhcp::MIN_REPLY + 64];
    let broadcast = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(255, 255, 255, 255)), 68);
    loop {
        let Ok((n, _from)) = socket.recv_from(&mut request).await else { continue };
        if let Some(r) = server.handle(&request[..n], Instant::now().as_millis() as u32, &mut reply) {
            let _ = socket.send_to(&reply[..r.len], broadcast).await;
        }
    }
}
