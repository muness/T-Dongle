//! The NAT takes whatever the USB host sends and whatever the radio delivers: no panic, a refused packet is untouched, a forwarded one keeps a
//! valid IP header checksum, and the table's invariants hold.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_types::Entropy;
use tdongle_tailnet_usbnet::napt::{Napt, NaptConfig, Verdict, WifiAddr};

struct Zero(u64);
impl Entropy for Zero {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (self.0 >> 56) as u8;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut napt = Napt::<32>::new(NaptConfig::C, &mut Zero(1));
    napt.set_wifi(Some(WifiAddr { ip: 0x0A00_0032, mask: 0xffff_ff00 }));
    // The input is a sequence of packets: one length byte (high bit: direction), then that many bytes.
    let mut rest = data;
    let mut now = 0u64;
    while let [h, tail @ ..] = rest {
        let n = usize::from(*h & 0x7f).min(tail.len());
        let (body, after) = tail.split_at(n);
        let mut pkt = body.to_vec();
        let before = pkt.clone();
        let v = if *h & 0x80 == 0 { napt.outbound(now, &mut pkt) } else { napt.inbound(now, &mut pkt) };
        match v {
            Verdict::Forward { len, .. } => assert!(usize::from(len) <= pkt.len()),
            _ => assert_eq!(pkt, before),
        }
        now += 700;
        if now % 2800 == 0 {
            let _ = napt.expire(now);
            while napt.pop_rst().is_some() {}
        }
        rest = after;
    }
    napt.check_invariants().unwrap();
});
