//! Property tests and a deterministic mini-fuzz of the receive classifier and the mux's receive/transmit bookkeeping.

use proptest::prelude::*;
use tdongle_tailnet_wifimux::fuzzing::Bench;
use tdongle_tailnet_wifimux::{FRAME_MAX, RxClass, RxDrop, classify_rx};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x50];

/// A frame that is mostly well-formed so the interesting branches are reached.
fn frame_strategy() -> impl Strategy<Value = Vec<u8>> {
    let hdr = (
        prop_oneof![Just(MAC), Just([0xff; 6]), Just([1, 0, 0x5e, 0, 0, 1]), any::<[u8; 6]>()],
        prop_oneof![Just([2, 0, 0, 0, 0, 1]), any::<[u8; 6]>()],
        prop_oneof![Just(0x0800u16), Just(0x0806), Just(0x86dd), any::<u16>()],
    );
    let ip = (
        prop_oneof![Just(0x45u8), Just(0x4f), Just(0x65), any::<u8>()],
        prop_oneof![0u16..80, any::<u16>()],
        any::<u16>(),
        prop_oneof![Just(0xC0A8_0101u32), Just(0xC0A8_0132), any::<u32>()],
        prop_oneof![Just(0xC0A8_0132u32), any::<u32>()],
        prop_oneof![Just(17u8), Just(6), Just(1), any::<u8>()],
    );
    (hdr, ip, prop::collection::vec(any::<u8>(), 0..120), prop::bool::weighted(0.15), any::<bool>()).prop_map(
        |((d, s, ty), (v, tl, ff, sip, dip, pr), body, raw, trunc)| {
            let mut f = Vec::new();
            f.extend_from_slice(&d);
            f.extend_from_slice(&s);
            f.extend_from_slice(&ty.to_be_bytes());
            if raw {
                f.extend_from_slice(&body);
            } else {
                f.push(v);
                f.push(0);
                f.extend_from_slice(&tl.to_be_bytes());
                f.extend_from_slice(&[0, 0]);
                f.extend_from_slice(&ff.to_be_bytes());
                f.extend_from_slice(&[64, pr, 0, 0]);
                f.extend_from_slice(&sip.to_be_bytes());
                f.extend_from_slice(&dip.to_be_bytes());
                f.extend_from_slice(&body);
            }
            if trunc && !f.is_empty() {
                let n = f.len() / 2;
                f.truncate(n);
            }
            f
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn classifier_never_panics_and_obeys_its_contract(f in frame_strategy()) {
        let c = classify_rx(&f, &MAC);
        match c {
            RxClass::Drop(RxDrop::Runt) => prop_assert!(f.len() < 14),
            RxClass::Drop(RxDrop::Oversize) => prop_assert!(f.len() > FRAME_MAX),
            RxClass::Drop(RxDrop::BadSource) => prop_assert!(f[6] & 1 == 1),
            RxClass::Drop(RxDrop::NotForUs) => prop_assert!(f[0] & 1 == 0 && f[0..6] != MAC),
            RxClass::Drop(RxDrop::BadIpv4) => prop_assert!(f[12..14] == [8, 0]),
            RxClass::Drop(_) => prop_assert!(false, "classifier produced a tap/queue drop"),
            RxClass::Ipv4 { unicast, .. } => {
                prop_assert!(f.len() >= 34 && f[14] >> 4 == 4);
                let ihl = usize::from(f[14] & 15) * 4;
                let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
                prop_assert!(ihl >= 20 && total >= ihl && total <= f.len() - 14);
                prop_assert_eq!(unicast, f[0..6] == MAC);
            }
            RxClass::Arp => prop_assert!(f[12..14] == [8, 6]),
            RxClass::Other => prop_assert!(f[12..14] != [8, 0] && f[12..14] != [8, 6]),
        }
    }

    #[test]
    fn every_frame_is_accounted_exactly_once(frames in prop::collection::vec(frame_strategy(), 1..60)) {
        let mut b = Bench::new();
        for (i, f) in frames.iter().enumerate() {
            let _ = b.rx(i as u64 * 100, f);
            prop_assert!(b.accounted());
        }
    }

    #[test]
    fn mixed_traffic_never_panics_and_queues_stay_bounded(
        ops in prop::collection::vec((0u8..4, frame_strategy(), 0u32..8000), 1..200)
    ) {
        let mut b = Bench::new();
        let mut now = 0u64;
        for (op, f, dt) in ops {
            now += u64::from(dt);
            match op {
                0 | 1 => { let _ = b.rx(now, &f); }
                2 => {
                    // a packet from the runtime: the IP part of the generated frame
                    if f.len() > 14 { let _ = b.send(&f[14..]); }
                }
                _ => { for _ in 0..3 { let _ = b.tx_step(now); } }
            }
            prop_assert!(b.accounted());
        }
    }
}

/// Deterministic mutation fuzz that runs in plain `cargo test`: mutate real frames byte by byte.
#[test]
fn mini_fuzz_mutated_frames() {
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut rnd = move || {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        seed.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let base = {
        let mut p = vec![0x45u8, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0, 192, 168, 1, 1, 192, 168, 1, 50];
        p.extend_from_slice(&[0u8; 20]);
        let mut f = MAC.to_vec();
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1, 8, 0]);
        f.extend_from_slice(&p);
        f
    };
    let mut b = Bench::new();
    for i in 0..200_000u64 {
        let mut f = base.clone();
        for _ in 0..(rnd() % 4) {
            let at = (rnd() % f.len() as u64) as usize;
            f[at] = rnd() as u8;
        }
        match rnd() % 8 {
            0 => f.truncate((rnd() % f.len() as u64) as usize),
            1 => f.extend((0..rnd() % 1600).map(|_| rnd() as u8)),
            _ => {}
        }
        let _ = b.rx(i, &f);
        if i % 7 == 0 {
            let _ = b.send(&f[f.len().min(14)..]);
            let _ = b.tx_step(i);
        }
    }
    assert!(b.accounted());
}

/// Sizes the ADR needs (printed with `--nocapture`): the queue memory is (TXQ + RXQ) x 1500 B, everything else is a few hundred bytes.
#[test]
fn report_sizes() {
    use tdongle_tailnet_wifimux::{NoTap, WifiMux};
    type M<const T: usize, const R: usize> = WifiMux<Dummy, NoTap, T, R>;
    let base = M::<1, 1>::STATE_BYTES;
    let per_tx = M::<2, 1>::STATE_BYTES - base;
    let per_rx = M::<1, 2>::STATE_BYTES - base;
    std::println!(
        "host: WifiMux<_,NoTap,8,16> = {} B; per TXQ slot {per_tx} B, per RXQ slot {per_rx} B; fixed part {} B",
        M::<8, 16>::STATE_BYTES,
        base - per_tx - per_rx
    );
    assert_eq!(per_tx, 1504);
    assert_eq!(per_rx, 1504);
    assert_eq!(M::<8, 16>::QUEUE_BYTES, 24 * 1500);
}

struct Dummy;
impl embassy_net_driver::Driver for Dummy {
    type RxToken<'a> = Tok;
    type TxToken<'a> = Tok;
    fn receive(&mut self, _: &mut std::task::Context<'_>) -> Option<(Tok, Tok)> {
        None
    }
    fn transmit(&mut self, _: &mut std::task::Context<'_>) -> Option<Tok> {
        None
    }
    fn link_state(&mut self, _: &mut std::task::Context<'_>) -> embassy_net_driver::LinkState {
        embassy_net_driver::LinkState::Down
    }
    fn capabilities(&self) -> embassy_net_driver::Capabilities {
        embassy_net_driver::Capabilities::default()
    }
    fn hardware_address(&self) -> embassy_net_driver::HardwareAddress {
        embassy_net_driver::HardwareAddress::Ethernet([2, 0, 0, 0, 0, 1])
    }
}
struct Tok;
impl embassy_net_driver::RxToken for Tok {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, f: F) -> R {
        f(&mut [])
    }
}
impl embassy_net_driver::TxToken for Tok {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, _: usize, f: F) -> R {
        f(&mut [])
    }
}
