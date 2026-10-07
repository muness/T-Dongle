//! Entry points the libfuzzer targets (`rust/fuzz/fuzz_targets/tailnet_disco_*.rs`) and the in-crate mini-fuzz tests share. Each takes arbitrary bytes,
//! must never panic, and asserts the invariants of its module; a panic here is a finding. Not part of the firmware's API (the linker drops it).

use crate::addr::Ep;
use crate::envelope::{self, PeerId, PeerResolver, RxCounters, RxOutcome};
use crate::msg::{self, Message, ParseError};
use crate::path::*;
use crate::stun::{self, StunError};
use crate::stun_sched::{Servers, StunScheduler};
use tdongle_tailnet_crypto::{nacl, x25519};
use tdongle_tailnet_types::test_util::TestRng;
use tdongle_tailnet_types::{Entropy, Key32};

/// The fixed receiver secret of the fuzz harness.
const RX_SECRET: [u8; 32] = [0x42; 32];

struct AnySender {
    secret: Key32,
}

impl PeerResolver for AnySender {
    fn resident(&mut self, sender: &[u8; 32]) -> Option<(PeerId, Key32)> {
        nacl::precompute(&self.secret, &Key32(*sender)).map(|k| (1, k))
    }
    fn candidate(&mut self, _: &[u8; 32]) -> Option<(u32, Key32)> {
        None
    }
    fn activate(&mut self, _: u32) -> Option<PeerId> {
        None
    }
}

/// DISCO plaintext parsing: any bytes. Whatever parses can be walked and, for a ping, encoded back to the same bytes.
pub fn message(data: &[u8]) {
    match msg::parse(data) {
        Ok(Message::Ping(p)) => {
            let mut out = [0u8; 2048];
            let n = msg::encode_ping(&mut out, &p).expect("a parsed ping re-encodes");
            // A zero "key" is padding: re-encoding is canonical, so compare the parsed forms.
            assert_eq!(msg::parse(&out[..n]), Ok(Message::Ping(p)));
        }
        Ok(Message::Pong(p)) => {
            let mut out = [0u8; 64];
            let n = msg::encode_pong(&mut out, &p).unwrap();
            // the version byte is ignored on receive and written as 0
            assert_eq!((out[0], &out[2..n]), (data[0], &data[2..n]));
        }
        Ok(Message::CallMeMaybe { endpoints, lax }) => {
            assert_eq!(endpoints.iter().count(), endpoints.len());
            assert!(!(lax && !endpoints.is_empty()));
        }
        Ok(Message::Unsupported(t)) => assert!((4..=9).contains(&t)),
        Err(ParseError::Short | ParseError::UnknownType(_)) => {}
    }
}

/// The whole receive pipeline. First byte selects: odd, seal the rest as a plaintext with the harness keys (the envelope must then always open, and
/// only the message parse may refuse it); even, the rest is a raw datagram (it may be refused for any counted reason, and when it is accepted it was
/// a real box).
pub fn envelope(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else { return };
    let mut counters = RxCounters::new();
    let mut res = AnySender { secret: Key32(RX_SECRET) };
    if mode & 1 == 1 {
        let sender_secret = Key32([0x24; 32]);
        let sender_pub = x25519::public(&sender_secret);
        let rx_pub = x25519::public(&Key32(RX_SECRET));
        let shared = nacl::precompute(&sender_secret, &rx_pub).expect("fixed keys");
        let plain = &rest[..rest.len().min(1400)];
        let mut buf = [0u8; envelope::MAX_PACKET + 64];
        let n = envelope::seal_with(&mut buf, &sender_pub, &shared, &[mode; 24], |b| {
            b[..plain.len()].copy_from_slice(plain);
            Ok(plain.len())
        })
        .expect("fits");
        let r = envelope::process(&mut buf[..n], &mut res);
        counters.record_result(&r);
        match r {
            Ok(_) => {}
            Err(RxOutcome::Short | RxOutcome::UnknownType) => {}
            Err(e) => panic!("a sealed packet was refused: {e:?}"),
        }
    } else {
        let mut buf = [0u8; 2048];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        let r = envelope::process(&mut buf[..n], &mut res);
        counters.record_result(&r);
        if rest.len() > envelope::MAX_PACKET {
            assert_eq!(r.map(|_| ()), Err(RxOutcome::TooLong));
        }
    }
    assert_eq!(counters.total(), 1);
}

/// STUN response parsing and the scheduler's and netcheck's handling of it.
pub fn stun_response(data: &[u8]) {
    let r = stun::parse_response(data);
    if let Ok(resp) = r {
        assert_eq!(&resp.txid[..], &data[8..20]);
        // an XOR-mapped answer rebuilt by the builder parses to the same endpoint
        let mut out = [0u8; stun::MAX_BUILT_RESPONSE];
        let n = stun::build_response(&resp.txid, &resp.mapped, &mut out).unwrap();
        let again = stun::parse_response(&out[..n]).unwrap();
        assert_eq!(again.mapped, resp.mapped);
    } else if let Err(e) = r {
        assert_ne!(e, StunError::BufferTooSmall);
    }
    let _ = stun::check_fingerprint(data);
    let mut rng = TestRng(0x5eed);
    let mut s = StunScheduler::default();
    s.set_servers(Servers { primary4: Some(Ep::v4([1, 1, 1, 1], 3478)), fallback4: Some(Ep::v4([2, 2, 2, 2], 19302)), primary6: None });
    s.begin(0, &mut rng, &mut |_| {});
    let _ = s.on_datagram(10, data, &mut rng, &mut |_| {});
    let mut nc = crate::netcheck::Netcheck::<2>::new();
    nc.add_region(1, Ep::v4([1, 1, 1, 1], 3478));
    nc.start(0);
    nc.poll(0, &mut rng, &mut |_| {});
    let _ = nc.on_datagram(5, data);
}

/// STUN request parsing.
pub fn stun_request(data: &[u8]) {
    let _ = stun::is_stun(data);
    if let Ok(tx) = stun::parse_binding_request(data) {
        // accepted: a STUN message whose last attribute is a correct FINGERPRINT over everything before it
        assert!(stun::is_stun(data));
        assert_eq!(&tx[..], &data[8..20]);
    }
}

/// A byte-driven sequence of events against one peer's path state with a shared probe table. Asserts the table and counter invariants after each.
pub fn path(data: &[u8]) {
    const N: usize = 6;
    let cfg = PathConfig::DEFAULT;
    let mut probes = ProbeTable::<N>::new();
    let mut counters = PathCounters::default();
    let mut rng = TestRng(0xfeed);
    let mut paths = [PathState::<4>::new(), PathState::<4>::new()];
    let mut burst = AddBurst::new();
    let mut now: u64 = 1;
    let mut recent: [TxId; 8] = [[0; 12]; 8];
    let mut rn = 0usize;
    let mut it = data.iter().copied();
    let mut eps_pool = [Ep::NONE; 6];
    for (i, e) in eps_pool.iter_mut().enumerate() {
        *e = Ep::v4([10, 0, 0, i as u8 + 1], 1000 + i as u16);
    }
    let mut sink = ActionBuf::<32>::new();
    while let Some(op) = it.next() {
        let a = it.next().unwrap_or(0);
        let id = (a & 1) as usize;
        let pid = id as u8;
        sink.clear();
        let mut env = Env { cfg: &cfg, probes: &mut probes, rng: &mut rng, counters: &mut counters };
        let from = if a & 2 == 0 { RxFrom::Direct(eps_pool[usize::from(a >> 4) % 6]) } else { RxFrom::Derp(u16::from(a >> 4)) };
        match op % 9 {
            0 => now = now.saturating_add(u64::from(a) * u64::from(a) * 3),
            1 => {
                let k = usize::from(a >> 4) % 7;
                let pick: [Ep; 6] = core::array::from_fn(|i| eps_pool[(i + usize::from(a)) % 6]);
                paths[id].set_endpoints(&pick[..k.min(6)], &cfg, env.counters);
            }
            2 => {
                paths[id].send_pings(pid, now, a & 4 != 0, a & 8 != 0, PingKind::Discovery, &mut env, &mut sink);
            }
            3 => {
                paths[id].on_ping(now, from, [a; 12], &mut env, &mut sink);
            }
            4 => {
                let tx = if a & 4 != 0 { recent[usize::from(a >> 4) % 8] } else { [a; 12] };
                paths[id].on_pong(pid, now, from, &tx, a & 8 != 0, &mut env, &mut sink);
            }
            5 => {
                let mut raw = [0u8; 2 + 18 * 3];
                raw[0] = 3;
                for (i, e) in eps_pool.iter().take(3).enumerate() {
                    e.write_wire(&mut raw[2 + 18 * i..]);
                }
                if let Ok(Message::CallMeMaybe { endpoints, .. }) = msg::parse(&raw[..2 + 18 * (usize::from(a >> 4) % 4).min(3)]) {
                    paths[id].on_call_me_maybe(pid, now, endpoints, a & 8 != 0, &mut env, &mut sink);
                }
            }
            6 => {
                let inp = TickInput {
                    online: a & 4 != 0,
                    allowed: a & 8 != 0,
                    udp_ok: a & 16 != 0,
                    session_up: a & 32 != 0,
                    wg_present: a & 64 != 0,
                    data_age_ms: if a & 128 != 0 { Some(u64::from(a) * 300) } else { None },
                };
                let mut b = TickBudget::new(&cfg);
                paths[id].tick(pid, now, &inp, &mut b, &mut env, &mut sink);
            }
            7 => paths[id].on_added(pid, now, a & 4 != 0, &mut burst, &mut env, &mut sink),
            _ => {
                expire_probes(env.probes, now, &cfg, env.counters);
            }
        }
        for act in sink.iter() {
            match act {
                Action::SendPing { txid, .. } => {
                    recent[rn % 8] = txid;
                    rn += 1;
                }
                Action::WgSetEndpoint(ep) => assert!(ep.is_usable() && ep.is_v4()),
                _ => {}
            }
        }
        assert!(probes.len() <= N);
        for p in 0..2u8 {
            assert!(probes.outstanding(p) <= cfg.max_outstanding_per_peer);
        }
        for p in &paths {
            let s = p.status(now);
            if let Route::Direct(ep) = p.route(now) {
                assert!(s.has_direct && ep == s.best && ep.is_usable());
            }
            assert!(usize::from(s.endpoints) <= 4);
        }
    }
}

/// Fill `out` from a deterministic generator (for the in-crate mini-fuzz).
pub fn fill(rng: &mut TestRng, out: &mut [u8]) {
    rng.fill(out);
}
