//! The patched OUT path against a model of the DWC2 core in slave mode, for any NTB sizes, any interleaving of the interrupt and the reading task, and while the class
//! holds the endpoint (backpressure): no byte is lost, duplicated or reordered, and every NTB comes out whole.

use proptest::prelude::*;
use std::collections::VecDeque;
use tdongle_usb_out::{Chunk, NtbCollector, Step, Transfer};

const MPS: usize = 64;
const NTB_MAX: usize = 3200;

/// The host: NTBs cut into MPS packets, a short packet or ZLP after each.
fn packets(ntbs: &[Vec<u8>]) -> VecDeque<Vec<u8>> {
    let mut out = VecDeque::new();
    for ntb in ntbs {
        for c in ntb.chunks(MPS) {
            out.push_back(c.to_vec());
        }
        if ntb.len() % MPS == 0 {
            out.push_back(Vec::new()); // ZLP
        }
    }
    out
}

/// The core: while armed it ACKs packets into the RX FIFO, ends the transfer when `PKTCNT` reaches 0 or on a short packet, then NAKs until re-armed.
struct Core {
    armed: bool,
    pktcnt: u32,
    rx_fifo: VecDeque<Vec<u8>>,
    fifo_words: usize,
    done_pending: bool,
}

impl Core {
    fn host_sends(&mut self, host: &mut VecDeque<Vec<u8>>) -> bool {
        let Some(p) = host.front() else { return false };
        let words: usize = self.rx_fifo.iter().map(|q| q.len().div_ceil(4) + 1).sum();
        if !self.armed || self.done_pending || words + p.len().div_ceil(4) + 2 > self.fifo_words {
            return false; // NAK: the host retries the same packet
        }
        let p = host.pop_front().unwrap();
        let short = p.len() < MPS;
        self.rx_fifo.push_back(p);
        self.pktcnt -= 1;
        if short || self.pktcnt == 0 {
            self.armed = false;
            self.done_pending = true;
        }
        true
    }
}

fn run(ntbs: Vec<Vec<u8>>, schedule: Vec<u8>, hold_every: u8) -> Vec<Vec<u8>> {
    let mut host = packets(&ntbs);
    let mut xfer = Transfer::new(MPS as u16, NTB_MAX as u16);
    let mut core = Core { armed: false, pktcnt: 0, rx_fifo: VecDeque::new(), fifo_words: 48, done_pending: false };
    let mut buffer = vec![0u8; NTB_MAX];
    let mut chunk_ready: Option<(usize, bool)> = None;
    let mut ntb_buf = vec![0u8; NTB_MAX];
    let mut collector = NtbCollector::new(MPS, NTB_MAX);
    let mut out = Vec::new();
    let arm = |core: &mut Core, xfer: &Transfer| {
        let (_xfrsiz, pktcnt) = xfer.arm();
        core.pktcnt = pktcnt;
        core.armed = true;
        core.done_pending = false;
    };
    arm(&mut core, &xfer); // the endpoint is armed when enabled
    let mut held = 0u32;
    let mut hold_left = 0u32;
    // A random schedule of host/interrupt/task turns, made weakly fair: every sixth turn is a round of all three (a real system cannot starve one of them for good).
    let turns = schedule.iter().cycle().take(300_000).enumerate().map(|(i, s)| if i % 6 == 5 { 3 + (i / 6 % 3) as u8 } else { *s % 3 });
    for step in turns {
        let step = step % 3;
        match step {
            0 => {
                core.host_sends(&mut host);
            }
            1 => {
                // the interrupt: drain the RX FIFO (and, after the last packet, the transfer-completed status)
                while let Some(p) = core.rx_fifo.pop_front() {
                    let at = xfer.packet(p.len() as u16).expect("fits");
                    buffer[at..at + p.len()].copy_from_slice(&p);
                }
                if core.done_pending && core.rx_fifo.is_empty() && chunk_ready.is_none() {
                    let c = xfer.done().expect("no overflow");
                    chunk_ready = Some((usize::from(c.len), c.short));
                }
            }
            _ => {
                // the task: read the chunk if there is one, unless the class is holding the endpoint
                if hold_left > 0 {
                    hold_left -= 1; // the class is holding the endpoint (backpressure): it does not read, so nothing is re-armed and the host is NAKed
                    held += 1;
                    continue;
                }
                if let Some((n, short)) = chunk_ready.take() {
                    let room = collector.room();
                    assert!(n <= room.len(), "chunk {n} > room {room:?}; ntb lens {:?}", ntbs.iter().map(Vec::len).collect::<Vec<_>>());
                    ntb_buf[room.start..room.start + n].copy_from_slice(&buffer[..n]);
                    if let Step::Complete(len) = collector.chunk(n, short) {
                        out.push(ntb_buf[..len].to_vec());
                    }
                    arm(&mut core, &xfer); // re-arm immediately after the read
                    hold_left = u32::from(hold_every);
                }
            }
        }
        if host.is_empty() && chunk_ready.is_none() && !core.done_pending && core.rx_fifo.is_empty() && out.len() == ntbs.len() {
            break;
        }
    }
    let _ = held;
    out
}

fn ntb_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // sizes that straddle the interesting boundaries
        Just(0usize), Just(1), Just(63), Just(64), Just(65), Just(1542), Just(3135), Just(3136), Just(3199), Just(3200), 1usize..=3200
    ]
    .prop_flat_map(|n| proptest::collection::vec(any::<u8>(), n))
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, cases: 200, ..ProptestConfig::default() })]

    #[test]
    fn every_ntb_arrives_whole_in_order(ntbs in proptest::collection::vec(ntb_strategy(), 1..12), schedule in proptest::collection::vec(any::<u8>(), 8..64), hold in 0u8..9) {
        // An NTB of 0 bytes is a lone ZLP: the collector reports it as a zero-length NTB, which is what the class sees from the stock driver too.
        let got = run(ntbs.clone(), schedule, hold);
        prop_assert_eq!(got.iter().map(Vec::len).collect::<Vec<_>>(), ntbs.iter().map(Vec::len).collect::<Vec<_>>());
        prop_assert!(got == ntbs);
    }
}

#[test]
fn arming_covers_the_whole_ntb_buffer() {
    let t = Transfer::new(64, 3200);
    assert_eq!(t.arm(), (3200, 50));
    assert_eq!(Transfer::new(64, 3201).arm(), (3200, 50), "rounded down to whole packets");
    assert_eq!(Transfer::new(64, 10).arm(), (64, 1), "at least one packet");
    assert_eq!(Transfer::new(64, 64).arm(), (64, 1), "the stock one-packet transfer is the special case");
}

#[test]
fn a_zlp_ends_an_ntb_that_fills_the_buffer_exactly() {
    let mut c = NtbCollector::new(64, 3200);
    assert_eq!(c.room(), 0..3200);
    assert_eq!(c.chunk(3200, false), Step::More); // 50 full packets, no short one
    assert_eq!(c.room(), 3200..3200);
    assert_eq!(c.chunk(0, true), Step::Complete(3200)); // the ZLP
    assert_eq!(c.room(), 0..3200);
}

#[test]
fn overflowing_packets_are_refused_and_the_transfer_is_dropped() {
    let mut t = Transfer::new(64, 128);
    assert_eq!(t.packet(64), Ok(0));
    assert_eq!(t.packet(64), Ok(64));
    assert!(t.packet(1).is_err());
    assert!(t.done().is_err());
    assert_eq!(t.packet(10), Ok(0), "the next transfer starts clean");
    assert_eq!(t.done(), Ok(Chunk { len: 10, short: true }));
    assert!(Transfer::new(64, 128).packet(65).is_err(), "a packet larger than MPS is refused");
}

#[test]
fn a_mid_stream_short_packet_ends_the_chunk() {
    let mut c = NtbCollector::new(64, 3200);
    assert_eq!(c.chunk(1280, false), Step::More);
    assert_eq!(c.room(), 1280..3200);
    assert_eq!(c.chunk(262, true), Step::Complete(1542));
}

#[test]
fn an_ntb_of_exactly_one_packet_is_ended_by_its_zlp_inside_the_same_transfer() {
    // The case a length-only interface cannot express: one 64-byte packet then a ZLP end the transfer together, a 64-byte chunk that IS a complete NTB.
    let mut t = Transfer::new(64, 3200);
    t.packet(64).unwrap();
    t.packet(0).unwrap();
    let c = t.done().unwrap();
    assert_eq!(c, Chunk { len: 64, short: true });
    let mut collector = NtbCollector::new(64, 3200);
    assert_eq!(collector.chunk(usize::from(c.len), c.short), Step::Complete(64));
    // A full buffer is not short.
    let mut t = Transfer::new(64, 128);
    t.packet(64).unwrap();
    t.packet(64).unwrap();
    assert_eq!(t.done().unwrap(), Chunk { len: 128, short: false });
}

#[test]
fn fixed_cases() {
    for len in [0usize, 1, 63, 64, 65, 3135, 3136, 3199, 3200] {
        let ntb = vec![0xa5u8; len];
        let got = run(vec![ntb.clone()], vec![0, 1, 2], 0);
        assert_eq!(got.len(), 1, "len {len}");
        assert_eq!(got[0], ntb, "len {len}");
    }
}
