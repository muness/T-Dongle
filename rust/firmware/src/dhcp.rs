//! The setup access point's DHCP server: `tdongle-dhcp` (the lwIP server's behaviour) over one embassy-net UDP socket on port 67.
//!
//! Replies are sent the way lwIP sends them: a unicast reply is an Ethernet frame to the client's MAC with IPv4 destination `yiaddr` (lwIP installs a temporary static ARP entry;
//! the TCP/IP stack here has no such call, and a client that does not hold its address yet cannot answer ARP), a broadcast reply goes to ff:ff:ff:ff:ff:ff. The frame is built by
//! `tdongle_dhcp::frame` and handed to the Wi-Fi driver on the AP interface; embassy-net's socket only receives.

use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::Stack;
use embassy_time::{Instant, Timer};

pub async fn task(stack: Stack<'static>, ap_mac: [u8; 6]) -> ! {
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
    let mut frame = [0u8; tdongle_dhcp::frame::HEADERS + tdongle_dhcp::MIN_REPLY + 64];
    loop {
        let Ok((n, _from)) = socket.recv_from(&mut request).await else { continue };
        if let Some(r) = server.handle(&request[..n], Instant::now().as_millis() as u32, &mut reply) {
            if let Some(n) = tdongle_dhcp::frame::build(&r, &reply[..r.len], tdongle_dhcp::Config::setup_ap().server_ip, ap_mac, &mut frame) {
                if !crate::l2::tx_ap(&frame[..n]) {
                    crate::init_note("setup: DHCP reply not sent");
                }
            }
        }
    }
}
