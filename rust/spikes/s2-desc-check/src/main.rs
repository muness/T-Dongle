#![allow(dead_code)]
#[path = "../../s2-usb-ncm/src/acm.rs"]
mod acm;
#[path = "../../s2-usb-ncm/src/ncm.rs"]
mod ncm;

use embassy_usb::driver::*;
use embassy_usb::{Builder, UsbVersion};

struct Ep(EndpointInfo);
impl Endpoint for Ep {
    fn info(&self) -> &EndpointInfo { &self.0 }
    async fn wait_enabled(&mut self) {}
}
impl EndpointOut for Ep {
    async fn read(&mut self, _b: &mut [u8]) -> Result<usize, EndpointError> { Ok(0) }
}
impl EndpointIn for Ep {
    async fn write(&mut self, _b: &[u8]) -> Result<(), EndpointError> { Ok(()) }
}
struct Cp;
impl ControlPipe for Cp {
    fn max_packet_size(&self) -> usize { 64 }
    async fn setup(&mut self) -> [u8; 8] { [0; 8] }
    async fn data_out(&mut self, _: &mut [u8], _: bool, _: bool) -> Result<usize, EndpointError> { Ok(0) }
    async fn data_in(&mut self, _: &[u8], _: bool, _: bool) -> Result<(), EndpointError> { Ok(()) }
    async fn accept(&mut self) {}
    async fn reject(&mut self) {}
    async fn accept_set_address(&mut self, _: u8) {}
}
struct B;
impl Bus for B {
    async fn enable(&mut self) {}
    async fn disable(&mut self) {}
    async fn poll(&mut self) -> Event { Event::Reset }
    fn endpoint_set_enabled(&mut self, _: EndpointAddress, _: bool) {}
    fn endpoint_set_stalled(&mut self, _: EndpointAddress, _: bool) {}
    fn endpoint_is_stalled(&mut self, _: EndpointAddress) -> bool { false }
    async fn remote_wakeup(&mut self) -> Result<(), Unsupported> { Ok(()) }
}
/// Mimics embassy-usb-synopsys-otg's allocator: honours a requested address, else first free index per direction.
#[derive(Default)]
struct D { used_in: [bool; 7], used_out: [bool; 7] }
impl D {
    fn alloc(&mut self, t: EndpointType, a: Option<EndpointAddress>, mps: u16, iv: u8, dir: Direction) -> Result<Ep, EndpointAllocError> {
        let used = if dir == Direction::In { &mut self.used_in } else { &mut self.used_out };
        let idx = match a { Some(a) => a.index(), None => (1..7).find(|i| !used[*i]).ok_or(EndpointAllocError)? };
        if used[idx] { return Err(EndpointAllocError); }
        used[idx] = true;
        Ok(Ep(EndpointInfo { addr: EndpointAddress::from_parts(idx, dir), ep_type: t, max_packet_size: mps, interval_ms: iv }))
    }
}
impl<'a> Driver<'a> for D {
    type EndpointOut = Ep; type EndpointIn = Ep; type ControlPipe = Cp; type Bus = B;
    fn alloc_endpoint_out(&mut self, t: EndpointType, a: Option<EndpointAddress>, m: u16, i: u8) -> Result<Ep, EndpointAllocError> { self.alloc(t, a, m, i, Direction::Out) }
    fn alloc_endpoint_in(&mut self, t: EndpointType, a: Option<EndpointAddress>, m: u16, i: u8) -> Result<Ep, EndpointAllocError> { self.alloc(t, a, m, i, Direction::In) }
    fn start(self, _: u16) -> (B, Cp) { (B, Cp) }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ") }

/// Split a configuration descriptor into (offset, descriptor) records.
fn records(d: &[u8]) -> Vec<(usize, &[u8])> {
    let mut v = vec![]; let mut o = 0;
    while o < d.len() { let l = d[o] as usize; v.push((o, &d[o..o + l])); o += l; }
    v
}

fn main() {
    let mut config = embassy_usb::Config::new(0x303A, 0x4001);
    config.bcd_usb = UsbVersion::Two;
    config.device_release = 0x0100;
    config.manufacturer = Some("T-Dongle Adapter Project");
    config.product = Some("T-Dongle-S3 NCM");
    config.serial_number = Some("AABBCCDDEEFF");
    config.max_power = 500;
    let cfg: &'static mut [u8] = Box::leak(Box::new([0u8; 256]));
    let cfg_ptr = cfg.as_ptr();
    let bos: &'static mut [u8] = Box::leak(Box::new([0u8; 16]));
    let ctrl: &'static mut [u8] = Box::leak(Box::new([0u8; 64]));
    let mut b = Builder::new(D::default(), config, cfg, bos, &mut [], ctrl);
    let _acm = acm::build(&mut b, 64);
    let _ncm = ncm::build(&mut b, 64);
    let _dev = b.build();
    let mine_full = unsafe { std::slice::from_raw_parts(cfg_ptr, 256) };
    let total = u16::from_le_bytes([mine_full[2], mine_full[3]]) as usize;
    let mine = &mine_full[..total];

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/tdongle-usb-descriptors/tests/golden/");
    let golden = std::fs::read(format!("{dir}c_config_descriptor_fs.bin")).unwrap();
    println!("generated {} bytes, golden {} bytes", mine.len(), golden.len());
    if mine == &golden[..] { println!("CONFIG DESCRIPTOR: BYTE-IDENTICAL"); }
    else {
        println!("CONFIG DESCRIPTOR: DIFFERS");
        let (a, g) = (records(mine), records(&golden));
        for i in 0..a.len().max(g.len()) {
            let (x, y) = (a.get(i), g.get(i));
            if x.map(|r| r.1) != y.map(|r| r.1) {
                println!("  rec {i}: mine   {}", x.map(|r| hex(r.1)).unwrap_or("-".into()));
                println!("         golden {}", y.map(|r| hex(r.1)).unwrap_or("-".into()));
            }
        }
    }
    println!("mine:\n{}", hex(mine));

    // ---- upstream embassy-usb 0.6.0 classes with upstream defaults, same mock allocator ----
    use embassy_usb::class::{cdc_acm, cdc_ncm};
    let mut config = embassy_usb::Config::new(0x303A, 0x4001);
    config.manufacturer = Some("x");
    let cfg: &'static mut [u8] = Box::leak(Box::new([0u8; 256]));
    let cfg_ptr = cfg.as_ptr();
    let bos: &'static mut [u8] = Box::leak(Box::new([0u8; 64]));
    let ctrl: &'static mut [u8] = Box::leak(Box::new([0u8; 64]));
    let mut b = Builder::new(D::default(), config, cfg, bos, &mut [], ctrl);
    let st1: &'static mut cdc_acm::State = Box::leak(Box::new(cdc_acm::State::new()));
    let st2: &'static mut cdc_ncm::State = Box::leak(Box::new(cdc_ncm::State::new()));
    let _a = cdc_acm::CdcAcmClass::new(&mut b, st1, 64);
    let _n = cdc_ncm::CdcNcmClass::new(&mut b, st2, [0; 6], 64);
    let _dev = b.build();
    let up_full = unsafe { std::slice::from_raw_parts(cfg_ptr, 256) };
    let total = u16::from_le_bytes([up_full[2], up_full[3]]) as usize;
    let up = &up_full[..total];
    println!("\nUPSTREAM embassy-usb 0.6.0 (CdcAcmClass + CdcNcmClass, defaults): {} bytes", up.len());
    let (a, g) = (records(up), records(&golden));
    println!("{:<4} {:<48} | {}", "rec", "upstream", "C golden");
    for i in 0..a.len().max(g.len()) {
        let (x, y) = (a.get(i).map(|r| hex(r.1)), g.get(i).map(|r| hex(r.1)));
        let mark = if x == y { " " } else { "*" };
        println!("{mark}{i:<3} {:<48} | {}", x.unwrap_or("-".into()), y.unwrap_or("-".into()));
    }
}
