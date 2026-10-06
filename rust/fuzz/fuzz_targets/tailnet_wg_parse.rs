//! Every WireGuard message parser and the whole handshake receive side (MAC screen, static-key decryption, consume of initiation, response and cookie reply) on
//! arbitrary datagrams: nothing may panic, every outcome is a value.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use tdongle_tailnet_types::{Entropy, Key32};
use tdongle_tailnet_wg::cookie::{CookieChecker, Screen, screen};
use tdongle_tailnet_wg::msg::{CookieReply, Initiation, MsgType, Response, TransportHeader, classify};
use tdongle_tailnet_wg::{Identity, PeerCold, PeerHot};

struct Rng(u64);
impl Entropy for Rng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (self.0 >> 56) as u8;
        }
    }
}

struct State {
    id: Identity,
    cold: PeerCold,
    hot: PeerHot,
    checker: CookieChecker,
    rng: Rng,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new({
        let id = Identity::new(&Key32([0x11; 32])).unwrap();
        let peer = Identity::new(&Key32([0x22; 32])).unwrap();
        let cold = PeerCold::new(&id, peer.public().clone(), None).unwrap();
        State { id, cold, hot: PeerHot::new(), checker: CookieChecker::new(), rng: Rng(1) }
    });
}

fuzz_target!(|data: &[u8]| {
    let _ = Initiation::parse(data);
    let _ = Response::parse(data);
    let _ = CookieReply::parse(data);
    let _ = TransportHeader::parse(data);
    let Ok(t) = classify(data) else { return };
    STATE.with(|s| {
        let s = &mut *s.borrow_mut();
        let now = u64::from(data.len() as u32) * 1000;
        let under_load = data.get(5).is_some_and(|b| b & 1 == 1);
        match t {
            MsgType::Initiation | MsgType::Response => {
                if let Screen::Pass = screen(&s.id, &mut s.checker, data, &[1, 2, 3, 4, 0, 80], under_load, now, &mut s.rng) {
                    if t == MsgType::Initiation {
                        let m = Initiation::parse(data).unwrap();
                        if let Ok(st) = s.id.consume_initiation_stage1(&m) {
                            let _ = s.hot.consume_initiation(&st, &s.cold, now);
                        }
                    } else {
                        let m = Response::parse(data).unwrap();
                        let _ = s.hot.consume_response(&s.id, &s.cold, &m, now);
                    }
                }
            }
            MsgType::CookieReply => {
                let _ = s.hot.consume_cookie_reply(&s.cold, &CookieReply::parse(data).unwrap(), now);
            }
            MsgType::Transport => {
                let mut v = data.to_vec();
                let _ = s.hot.decrypt(&mut v, now);
            }
        }
        let _ = s.hot.poll(now);
        let _ = s.hot.next_wake(now);
    });
});
