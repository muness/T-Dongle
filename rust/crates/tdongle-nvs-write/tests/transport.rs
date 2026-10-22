use tdongle_nvs_write::{
    Nvs, SimFlash, Tear,
    transport::{self, Transport},
};
const SIZE: u32 = 0x10000;
#[test]
fn invalid_mode_is_rejected_without_replacing_it() {
    let mut n = Nvs::open(SimFlash::new(SIZE as usize), SIZE).unwrap();
    assert_eq!(transport::load(&mut n).unwrap(), Transport::Usb);
    n.set_u8(transport::NAMESPACE, "mode", 255).unwrap();
    assert!(transport::load(&mut n).is_err());
    assert_eq!(n.get_u8(transport::NAMESPACE, "mode").unwrap(), Some(255));
    assert_eq!(Transport::parse("wireless"), Some(Transport::Wireless));
    assert_eq!(Transport::parse("wireless\nreset"), None);
}
#[test]
fn interrupted_transport_switch_preserves_registry_and_identities() {
    for old in [Transport::Usb, Transport::Wireless] {
        let new = if old == Transport::Usb { Transport::Wireless } else { Transport::Usb };
        let mut n = Nvs::open(SimFlash::new(SIZE as usize), SIZE).unwrap();
        transport::save(&mut n, old).unwrap();
        n.set_blob("tn_settings", "members", b"three memberships").unwrap();
        for slot in 0..3 {
            n.set_blob("tailnet", &format!("identity{slot}"), &[slot; 300]).unwrap();
        }
        let image = n.flash().data.clone();
        for budget in 0..100 {
            for tear in [Tear::Prefix, Tear::Bits(12345)] {
                let mut n = Nvs::open(SimFlash::from_image(image.clone()), SIZE).unwrap();
                n.flash_mut().arm(budget, tear);
                let _ = transport::save(&mut n, new);
                let mut recovered = Nvs::open(SimFlash::from_image(n.flash().data.clone()), SIZE).unwrap();
                let mode = transport::load(&mut recovered).unwrap();
                assert!(mode == old || mode == new);
                let mut registry = [0; 17];
                assert_eq!(recovered.get_blob("tn_settings", "members", &mut registry).unwrap(), Some(17));
                assert_eq!(&registry, b"three memberships");
                for slot in 0..3 {
                    let mut key = [0; 300];
                    recovered.get_blob("tailnet", &format!("identity{slot}"), &mut key).unwrap();
                    assert_eq!(key, [slot; 300]);
                }
            }
        }
    }
}
