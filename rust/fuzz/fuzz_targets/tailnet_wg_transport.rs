//! The transport receive path on arbitrary datagrams against established sessions, in the three-step form and the one-call form, with arbitrary times
//! (session expiry) and counters (replay window and limits): nothing may panic, and nothing that is not a genuine datagram may authenticate.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use tdongle_tailnet_wg::msg::TransportHeader;
use tdongle_tailnet_wg::Session;

thread_local! {
    static RX: RefCell<Session> = RefCell::new(Session::from_keys([5; 32], [6; 32], false, 7, 8, 0));
}

fuzz_target!(|data: &[u8]| {
    let (now, rest) = match data.split_first_chunk::<8>() {
        Some((n, r)) => (u64::from_le_bytes(*n) % 400_000, r),
        None => return,
    };
    let Ok(h) = TransportHeader::parse(rest) else { return };
    RX.with(|s| {
        let mut s = s.borrow_mut();
        if let Ok(t) = s.rx_peek(h.counter, now) {
            let mut v = rest.to_vec();
            if t.open(&mut v).is_ok() {
                // a forged tag cannot verify: reaching here means the fuzzer found a collision in 128-bit Poly1305
                panic!("forged datagram authenticated");
            }
        }
        // a Session on the sending side of the same key pair accepts exactly what it sealed
        let mut tx = Session::from_keys([6; 32], [5; 32], true, 8, 7, 0);
        if let Ok(t) = tx.tx_reserve(now) {
            let mut buf = vec![0u8; 16 + 64 + 16];
            let n = rest.len().min(64);
            buf[16..16 + n].copy_from_slice(&rest[..n]);
            let len = t.seal(&mut buf, n).unwrap();
            let hh = TransportHeader::parse(&buf[..len]).unwrap();
            let rt = s.rx_peek(hh.counter, now).unwrap_or_else(|_| panic!("fresh counter refused"));
            assert_eq!(rt.open(&mut buf[..len]).unwrap(), (n + 15) & !15);
            assert_eq!(&buf[16..16 + n], &rest[..n]);
            let _ = s.rx_commit(hh.counter);
        }
    });
});
