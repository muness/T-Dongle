//! Synthetic end-to-end datagram: Android L3 envelope -> serial -> reused NAT ->
//! simulated Wi-Fi peer -> NAT -> serial -> Android. No claimed hardware evidence.
use tdongle_serial_ip::*;
use tdongle_tailnet_usbnet::{
    csum,
    napt::{Napt, NaptConfig, Verdict, WifiAddr},
};
struct Random;
impl tdongle_tailnet_types::Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) {
        for (i, v) in b.iter_mut().enumerate() {
            *v = (i + 17) as u8;
        }
    }
}
fn serial_copy(packet: &[u8]) -> Vec<u8> {
    let mut wire = [0; MAX_WIRE];
    let n = encode(IP, 42, packet, &mut wire).unwrap();
    let mut d = Decoder::new();
    for &b in &wire[..n] {
        if let Some(f) = d.feed(b) {
            assert_eq!(f.session, 42);
            return f.payload.to_vec();
        }
    }
    panic!("No complete frame");
}
#[test]
fn udp_reply_and_network_change_flush() {
    let mut napt = Napt::<8>::new(NaptConfig::C, &mut Random);
    napt.set_wifi(Some(WifiAddr { ip: u32::from_be_bytes([10, 0, 0, 2]), mask: 0xffffff00 }));
    let mut p = vec![0u8; 32];
    p[0] = 0x45;
    p[3] = 32;
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&HOST);
    p[16..20].copy_from_slice(&[1, 1, 1, 1]);
    p[20..22].copy_from_slice(&53000u16.to_be_bytes());
    p[22..24].copy_from_slice(&53u16.to_be_bytes());
    p[25] = 12;
    p[28..].copy_from_slice(b"test");
    csum::fill_header(&mut p, 20);
    assert!(ipv4(&p, true));
    let mut forwarded = serial_copy(&p);
    assert!(matches!(napt.outbound(1, &mut forwarded), Verdict::Forward { .. }));
    assert_eq!(&forwarded[12..16], &[10, 0, 0, 2]);
    assert!(csum::header_ok(&forwarded, 20));
    let mut reply = forwarded.clone();
    reply[12..16].copy_from_slice(&forwarded[16..20]);
    reply[16..20].copy_from_slice(&forwarded[12..16]);
    reply[20..22].copy_from_slice(&forwarded[22..24]);
    reply[22..24].copy_from_slice(&forwarded[20..22]);
    csum::fill_header(&mut reply, 20);
    let stale = reply.clone();
    assert!(matches!(napt.inbound(2, &mut reply), Verdict::Forward { .. }));
    let delivered = serial_copy(&reply);
    assert!(ipv4(&delivered, false));
    assert_eq!(&delivered[22..24], &53000u16.to_be_bytes());
    assert_eq!(&delivered[28..], b"test");
    assert!(csum::header_ok(&delivered, 20));
    napt.set_wifi(None);
    napt.set_wifi(Some(WifiAddr { ip: u32::from_be_bytes([10, 0, 0, 2]), mask: 0xffffff00 }));
    assert!(!matches!(napt.inbound(3, &mut stale.clone()), Verdict::Forward { .. }));
}

#[test]
fn shared_java_rust_wire_vector() {
    let text = include_str!("wire.hex").trim();
    let expected: Vec<u8> = (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect();
    let mut out = [0; MAX_WIRE];
    let n = encode(IP, 0x0102030405060708, &[0xc0, 0xdb, 0, 255], &mut out).unwrap();
    assert_eq!(&out[..n], expected);
}
