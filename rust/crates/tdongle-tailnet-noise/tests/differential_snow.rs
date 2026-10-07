//! Differential tests against the `snow` crate (Noise_IK_25519_ChaChaPoly_BLAKE2s, same prologue, same fixed ephemerals): identical bytes both ways.
//!
//! Transport: snow's counter nonce is little-endian, Tailscale's big-endian, so snow's stateless transport is driven with `counter.swap_bytes()`
//! to reproduce Tailscale's nonce; that makes every counter value comparable, not only counter 0.
mod common;
use common::*;
use snow::{Builder, params::NoiseParams};
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_noise::{Initiator, responder};
use tdongle_tailnet_types::Key32;
use tdongle_tailnet_types::test_util::TestRng;

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

fn prologue(version: u16) -> Vec<u8> {
    format!("Tailscale Control Protocol v{version}").into_bytes()
}

struct Keys {
    mpriv: Key32,
    cpriv: Key32,
    cpub: Key32,
    meph: Key32,
    ceph: Key32,
}

fn keys(seed: u64) -> Keys {
    let mut rng = TestRng(seed | 1);
    let mpriv = x25519::generate(&mut rng);
    let cpriv = x25519::generate(&mut rng);
    let cpub = x25519::public(&cpriv);
    Keys { mpriv, cpriv, cpub, meph: x25519::generate(&mut rng), ceph: x25519::generate(&mut rng) }
}

fn snow_initiator(k: &Keys, version: u16, eph: Option<&Key32>) -> snow::HandshakeState {
    let params: NoiseParams = PATTERN.parse().unwrap();
    let pro = prologue(version);
    let mut b = Builder::new(params).prologue(&pro).unwrap().local_private_key(&k.mpriv.0).unwrap().remote_public_key(&k.cpub.0).unwrap();
    if let Some(e) = eph {
        b = b.fixed_ephemeral_key_for_testing_only(&e.0);
    }
    b.build_initiator().unwrap()
}

fn snow_responder(k: &Keys, version: u16, eph: Option<&Key32>) -> snow::HandshakeState {
    let params: NoiseParams = PATTERN.parse().unwrap();
    let pro = prologue(version);
    let mut b = Builder::new(params).prologue(&pro).unwrap().local_private_key(&k.cpriv.0).unwrap();
    if let Some(e) = eph {
        b = b.fixed_ephemeral_key_for_testing_only(&e.0);
    }
    b.build_responder().unwrap()
}

#[test]
fn handshake_bytes_and_hash_identical_to_snow() {
    for seed in 1..=48u64 {
        let version = [1u16, 131, 65535, 9, 100][(seed % 5) as usize];
        let k = keys(seed * 7919);
        // snow both sides
        let mut si = snow_initiator(&k, version, Some(&k.meph));
        let mut sr = snow_responder(&k, version, Some(&k.ceph));
        let mut m1 = [0u8; 200];
        let n1 = si.write_message(&[], &mut m1).unwrap();
        assert_eq!(n1, 96);
        let mut tmp = [0u8; 200];
        assert_eq!(sr.read_message(&m1[..n1], &mut tmp).unwrap(), 0);
        let mut m2 = [0u8; 200];
        let n2 = sr.write_message(&[], &mut m2).unwrap();
        assert_eq!(n2, 48);
        assert_eq!(si.read_message(&m2[..n2], &mut tmp).unwrap(), 0);
        assert_eq!(si.get_handshake_hash(), sr.get_handshake_hash());

        // ours
        let (init, msg1) = Initiator::with_ephemeral(&k.mpriv, &k.cpub, version, k.meph.clone()).unwrap();
        assert_eq!(&msg1[..2], &version.to_be_bytes());
        assert_eq!(&msg1[2..5], &[1, 0, 96]);
        assert_eq!(&msg1[5..], &m1[..n1], "msg1 bytes, seed {seed}");
        let acc = responder::accept_with_ephemeral(&k.cpriv, &msg1, k.ceph.clone()).unwrap();
        assert_eq!(&acc.response[..3], &[2, 0, 48]);
        assert_eq!(&acc.response[3..], &m2[..n2], "msg2 bytes, seed {seed}");
        let mut client = init.finish(&acc.response).unwrap();
        let mut server = acc.session;
        assert_eq!(&client.handshake_hash()[..], si.get_handshake_hash());
        assert_eq!(server.handshake_hash(), client.handshake_hash());

        // transport, every counter, both directions
        let ti = si.into_stateless_transport_mode().unwrap();
        let tr = sr.into_stateless_transport_mode().unwrap();
        let mut rng = TestRng(seed + 99);
        for counter in 0..6u64 {
            let len = [0usize, 1, 15, 16, 17, 1000, 4077][((seed + counter) % 7) as usize];
            let plain = rand_bytes(&mut rng, len);
            let mut ours = vec![0u8; 4096];
            let n = client.seal_into(&plain, &mut ours).unwrap();
            let mut theirs = vec![0u8; len + 16];
            ti.write_message(counter.swap_bytes(), &plain, &mut theirs).unwrap();
            assert_eq!(&ours[3..n], &theirs[..], "c2s ct, counter {counter}, seed {seed}");
            // snow decrypts ours, we decrypt snow's
            let mut back = vec![0u8; len];
            assert_eq!(tr.read_message(counter.swap_bytes(), &ours[3..n], &mut back).unwrap(), len);
            assert_eq!(back, plain);
            let mut rec = ours[..n].to_vec();
            let r = server.open_record(&mut rec).unwrap();
            assert_eq!(&rec[r], &plain[..]);

            let n = server.seal_into(&plain, &mut ours).unwrap();
            tr.write_message(counter.swap_bytes(), &plain, &mut theirs).unwrap();
            assert_eq!(&ours[3..n], &theirs[..], "s2c ct, counter {counter}");
            let mut rec = ours[..n].to_vec();
            let r = client.open_record(&mut rec).unwrap();
            assert_eq!(&rec[r], &plain[..]);
        }
    }
}

#[test]
fn our_initiator_against_snow_responder_with_random_ephemeral() {
    for seed in 1..=16u64 {
        let k = keys(seed * 104729);
        let mut rng = TestRng(seed + 5);
        let (init, msg1) = Initiator::new(&k.mpriv, &k.cpub, 131, &mut rng).unwrap();
        let mut sr = snow_responder(&k, 131, None); // snow draws its own ephemeral from getrandom
        let mut tmp = [0u8; 200];
        assert_eq!(sr.read_message(&msg1[5..], &mut tmp).unwrap(), 0);
        let mut m2 = [0u8; 200];
        let n2 = sr.write_message(&[], &mut m2).unwrap();
        let mut wire = vec![2u8, 0, 48];
        wire.extend_from_slice(&m2[..n2]);
        let client = init.finish(&wire).unwrap();
        assert_eq!(&client.handshake_hash()[..], sr.get_handshake_hash());
        // remote static as snow learned it is the machine key
        assert_eq!(sr.get_remote_static().unwrap(), x25519::public(&k.mpriv).as_bytes());
    }
}

#[test]
fn snow_initiator_against_our_responder() {
    for seed in 1..=16u64 {
        let k = keys(seed * 1299709);
        let mut si = snow_initiator(&k, 131, None);
        let mut m1 = [0u8; 200];
        let n1 = si.write_message(&[], &mut m1).unwrap();
        let mut wire = vec![0, 131, 1, 0, 96];
        wire.extend_from_slice(&m1[..n1]);
        let mut rng = TestRng(seed);
        let acc = responder::accept(&k.cpriv, &wire, &mut rng).unwrap();
        assert_eq!(acc.machine_pub, x25519::public(&k.mpriv));
        let mut tmp = [0u8; 200];
        assert_eq!(si.read_message(&acc.response[3..], &mut tmp).unwrap(), 0);
        assert_eq!(si.get_handshake_hash(), &acc.session.handshake_hash()[..]);
    }
}
