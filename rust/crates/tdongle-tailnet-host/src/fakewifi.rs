//! A fake Wi-Fi data path for the Internet passthrough: the real NAT table (`tdongle-tailnet-usbnet::Napt`) and a "remote Internet" that answers every UDP
//! datagram and ICMP echo it is sent by reflecting it. It stands where `tdongle-tailnet-wifimux` stands on the device.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tdongle_tailnet_runtime::usb::build_udp;
use tdongle_tailnet_runtime::wifi::WifiRaw;
use tdongle_tailnet_types::Millis;
use tdongle_tailnet_usbnet::csum::{fill_header, finish, sum};
use tdongle_tailnet_usbnet::napt::{Napt, NaptConfig, Verdict, WifiAddr};
use tdongle_tailnet_usbnet::wire::{rd16, rd32, wr16, wr32};

/// Counters.
#[derive(Debug, Default)]
pub struct WifiCounters {
    /// Packets the runtime sent to "Wi-Fi".
    pub sent: AtomicU64,
    /// Replies queued for the host.
    pub replied: AtomicU64,
}

/// The fake.
pub struct FakeWifi {
    napt: Mutex<Napt<64>>,
    wifi_ip: u32,
    inbox: Mutex<VecDeque<Vec<u8>>>,
    wake: tokio::sync::Notify,
    /// Counters.
    pub counters: Arc<WifiCounters>,
    /// The remote end of every flow seen: `(address, port)`.
    pub seen: Mutex<Vec<(u32, u16)>>,
}

impl std::fmt::Debug for FakeWifi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeWifi")
    }
}

impl FakeWifi {
    /// A station at `wifi_ip` (host order).
    pub fn new(wifi_ip: u32) -> Self {
        let mut rng = crate::OsRng;
        let mut napt = Napt::new(NaptConfig::C, &mut rng);
        napt.set_wifi(Some(WifiAddr { ip: wifi_ip, mask: 0xffff_ff00 }));
        FakeWifi {
            napt: Mutex::new(napt),
            wifi_ip,
            inbox: Mutex::new(VecDeque::new()),
            wake: tokio::sync::Notify::new(),
            counters: Arc::default(),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn reflect(&self, now: Millis, pkt: &[u8]) {
        let ihl = usize::from(pkt[0] & 15) * 4;
        let (src, dst) = (rd32(pkt, 12), rd32(pkt, 16));
        let mut reply = vec![0u8; 1500];
        let n = match pkt[9] {
            17 => {
                let (sport, dport) = (rd16(pkt, ihl), rd16(pkt, ihl + 2));
                self.seen.lock().unwrap().push((dst, dport));
                build_udp(dst, dport, src, sport, &pkt[ihl + 8..], &mut reply)
            }
            1 if pkt[ihl] == 8 => {
                let total = usize::from(rd16(pkt, 2));
                reply[..total].copy_from_slice(&pkt[..total]);
                wr32(&mut reply, 12, dst);
                wr32(&mut reply, 16, src);
                fill_header(&mut reply, ihl);
                reply[ihl] = 0;
                wr16(&mut reply, ihl + 2, 0);
                let c = finish(sum(&reply[ihl..total], 0));
                wr16(&mut reply, ihl + 2, c);
                Some(total)
            }
            _ => None,
        };
        let Some(n) = n else { return };
        reply.truncate(n);
        if let Verdict::Forward { len, .. } = self.napt.lock().unwrap().inbound(now, &mut reply) {
            reply.truncate(usize::from(len));
            self.inbox.lock().unwrap().push_back(reply);
            self.counters.replied.fetch_add(1, Ordering::Relaxed);
            self.wake.notify_one();
        }
    }
}

impl WifiRaw for FakeWifi {
    fn nat_outbound(&self, now: Millis, packet: &mut [u8]) -> Verdict {
        self.napt.lock().unwrap().outbound(now, packet)
    }
    fn try_send(&self, l3: &[u8]) -> bool {
        self.counters.sent.fetch_add(1, Ordering::Relaxed);
        assert_eq!(rd32(l3, 12), self.wifi_ip, "the NAT put the station's address on the packet");
        self.reflect(0, l3);
        true
    }
    async fn next_to_host(&self, buf: &mut [u8]) -> usize {
        loop {
            if let Some(n) = self.try_next_to_host(buf) {
                return n;
            }
            self.wake.notified().await;
        }
    }
    fn try_next_to_host(&self, buf: &mut [u8]) -> Option<usize> {
        let p = self.inbox.lock().unwrap().pop_front()?;
        buf[..p.len()].copy_from_slice(&p);
        Some(p.len())
    }
    fn nat_tick(&self, now: Millis) -> usize {
        self.napt.lock().unwrap().expire(now)
    }
    fn stack_config_changed(&self) {}
    fn new_association(&self) {}
}
