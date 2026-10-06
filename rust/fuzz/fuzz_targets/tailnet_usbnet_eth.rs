//! The whole USB side on arbitrary frames from the host (Ethernet filter, ARP, DHCP, NAT): no panic and the NAT table stays sound.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_types::Entropy;
use tdongle_tailnet_usbnet::UsbNet;
use tdongle_tailnet_usbnet::arp::{ARP_FRAME, Resolve};

struct Lcg(u64);
impl Entropy for Lcg {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 56) as u8;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut usb = UsbNet::<32, 8, 4>::new([2, 1, 2, 3, 4, 5], &mut Lcg(7));
    let mut reply = [0u8; 400];
    let mut now = 0u64;
    let mut rest = data;
    while rest.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]]) & 0x7ff).min(rest.len() - 2);
        let (frame, after) = rest[2..].split_at(n);
        let mut f = frame.to_vec();
        let _ = usb.host_frame(now, &mut f, &mut reply);
        let mut req = [0u8; ARP_FRAME];
        let _: Resolve = usb.arp.resolve(now, 0xC0A8_4D02, &mut req);
        now += 900;
        let _ = usb.tick(now);
        rest = after;
    }
    usb.napt.check_invariants().unwrap();
});
