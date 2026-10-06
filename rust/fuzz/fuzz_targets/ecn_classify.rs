//! The ECN/IPv4/IPv6 extension-header classifier must never panic or read out of bounds on any bytes, and marking a CAPABLE frame must leave a
//! frame the classifier calls CE and change nothing but the ECN byte (and, for IPv4, the header checksum).
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_aqm::{EcnClass, classify, mark_ce, tcp_ecn_syn};

fuzz_target!(|data: &[u8]| {
    let class = classify(data);
    let _ = tcp_ecn_syn(data);
    if class == EcnClass::Capable {
        let mut marked = data.to_vec();
        mark_ce(&mut marked);
        assert_eq!(classify(&marked), EcnClass::Ce);
        let changed = data.iter().zip(&marked).filter(|(a, b)| a != b).count();
        assert!(changed <= 3, "marking touched {changed} bytes");
    }
});
