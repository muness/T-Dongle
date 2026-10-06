//! Host micro-benchmark of the forwarding path (port of tests/bench_router.c): 64 aliases, 64 live flows, traffic spread over all of them.
//! Prints ns per packet net of the copy that stands in for the harness, and packets per second. Host numbers: use the ratios between rows and
//! against the C figures printed by the same scenario, not the absolutes.
#[path = "../tests/common/mod.rs"]
mod common;
use common::*;
use std::hint::black_box;
use std::time::Instant;
use tdongle_tailnet_router::tables::AliasRecord;
use tdongle_tailnet_router::*;

fn setup() -> GatewayRouter {
    let mut r = GatewayRouter::new();
    let mut s = MemberSet::<16>::new();
    s.insert(Member { id: 1, vpn_ip: 0x6440_0001, ready: true });
    s.insert(Member { id: 2, vpn_ip: 0x6440_0002, ready: true });
    r.publish(s);
    for i in 0..64u32 {
        r.alias_insert(AliasRecord { id: 1 + (i & 1), peer: 0x6450_0000 + i, alias: ALIAS_BASE + i });
    }
    r
}

fn bench(label: &str, payload: usize, proto: u8) {
    let mut rng = Rng(42);
    let mut r = setup();
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut back: Vec<Vec<u8>> = Vec::new();
    for k in 0..64u32 {
        let p = build(&mut rng, 0xc0a8_4d02, ALIAS_BASE + k, proto, 2000 + k as u16, 80, payload, false, false);
        let mut w = p.clone();
        let g = r.usb_generation();
        let HostOutcome::Forwarded { .. } = r.host_packet(&mut w, 0, g) else { panic!() };
        let (vpn, peer, mapped) = (common::rd32(&w, 12), common::rd32(&w, 16), common::rd16(&w, 20));
        back.push(build(&mut rng, peer, vpn, proto, 80, mapped, payload, false, false));
        out.push(p);
    }
    let n = 2_000_000u32;
    let mut work = vec![0u8; 1500];
    let time = |f: &mut dyn FnMut(usize)| {
        let mut best = f64::MAX;
        for _ in 0..7 {
            let t = Instant::now();
            for i in 0..n {
                f(i as usize & 63);
            }
            best = best.min(t.elapsed().as_nanos() as f64 / f64::from(n));
        }
        best
    };
    let copy = {
        let (o, w) = (&out, &mut work);
        time(&mut |k| {
            w[..o[k].len()].copy_from_slice(&o[k]);
            black_box(&w[0]);
        })
    };
    let fwd = {
        let (o, w, r) = (&out, &mut work, &mut r);
        time(&mut |k| {
            let l = o[k].len();
            w[..l].copy_from_slice(&o[k]);
            black_box(r.host_packet(&mut w[..l], 1000, 1));
        })
    };
    let rep = {
        let (b, w, r) = (&back, &mut work, &mut r);
        // member id of flow k is 1 + (k & 1)
        time(&mut |k| {
            let l = b[k].len();
            w[..l].copy_from_slice(&b[k]);
            black_box(r.tunnel_packet(1 + (k as u32 & 1), &mut w[..l], 1000));
        })
    };
    println!(
        "{label:>22}: copy {copy:5.0} ns | USB->tunnel {fwd:5.0} ns (net {:4.0}, {:6.2} Mpps) | tunnel->USB {rep:5.0} ns (net {:4.0}, {:6.2} Mpps) | {} B packets",
        fwd - copy,
        1000.0 / (fwd - copy),
        rep - copy,
        1000.0 / (rep - copy),
        out[0].len()
    );
}

fn main() {
    println!("GatewayRouter state = {} B", GatewayRouter::STATE_BYTES);
    bench("UDP 20 B payload", 20, 17);
    bench("UDP 1360 B payload", 1360, 17);
    bench("TCP 1340 B payload", 1340, 6);
}
