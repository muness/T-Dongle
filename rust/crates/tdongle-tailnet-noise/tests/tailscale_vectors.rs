//! Known-answer tests: every byte below was produced by Tailscale's `control/controlbase` (v1.104.0) code with fixed keys.
mod common;
use common::*;
use tdongle_tailnet_noise::{Initiator, Role, responder};

fn check_version(p: &str, version: u16, with_records: bool) {
    let v = vectors();
    let get = |n: &str| v.get(&format!("{p}{n}")).unwrap_or_else(|| panic!("missing {p}{n}")).clone();
    let (mpriv, cpriv) = (key(&get("machine_priv")), key(&get("control_priv")));
    let (meph, ceph) = (key(&get("machine_eph_priv")), key(&get("control_eph_priv")));
    let (mpub, cpub) = (key(&get("machine_pub")), key(&get("control_pub")));

    // client side
    let (init, msg1) = Initiator::with_ephemeral(&mpriv, &cpub, version, meph).unwrap();
    assert_eq!(msg1.to_vec(), get("msg1"));
    let mut client = init.finish(&get("msg2")).unwrap();
    assert_eq!(client.handshake_hash().to_vec(), get("handshake_hash"));
    assert_eq!(client.peer(), &cpub);
    assert_eq!(client.version(), version);

    // server side
    let acc = responder::accept_with_ephemeral(&cpriv, &get("msg1"), ceph).unwrap();
    assert_eq!(acc.response.to_vec(), get("msg2"));
    assert_eq!(acc.machine_pub, mpub);
    assert_eq!(acc.version, version);
    let mut server = acc.session;
    assert_eq!(server.role(), Role::Responder);
    assert_eq!(server.handshake_hash().to_vec(), get("handshake_hash"));

    if !with_records {
        return;
    }
    let plains = record_plaintexts();
    for (i, plain) in plains.iter().enumerate() {
        // client -> server: our seal equals Go's record, Go's record opens on our server
        let mut buf = vec![0u8; 4096];
        let n = client.seal_into(plain, &mut buf).unwrap();
        assert_eq!(buf[..n], get(&format!("c2s_rec{i}"))[..], "c2s record {i}");
        let mut rec = get(&format!("c2s_rec{i}"));
        let r = server.open_record(&mut rec).unwrap();
        assert_eq!(&rec[r], &plain[..], "server opens Go's c2s record {i}");
        // server -> client
        let n = server.seal_into(plain, &mut buf).unwrap();
        assert_eq!(buf[..n], get(&format!("s2c_rec{i}"))[..], "s2c record {i}");
        let mut rec = get(&format!("s2c_rec{i}"));
        let r = client.open_record(&mut rec).unwrap();
        assert_eq!(&rec[r], &plain[..], "client opens Go's s2c record {i}");
    }
    assert_eq!((client.tx_nonce(), client.rx_nonce()), (5, 5));
    assert_eq!(client.stats().auth_failures.get(), 0);
}

#[test]
fn version_131_handshake_and_records_match_tailscale() {
    check_version("v131_", 131, true);
}

#[test]
fn version_1_handshake_matches_tailscale() {
    check_version("v1_", 1, false);
}

#[test]
fn prologue_binds_the_version() {
    // Go's msg1 for v131 must not be accepted as v1: flip the announced version, the prologue no longer matches.
    let v = vectors();
    let mut m = v["v131_msg1"].clone();
    m[1] = 1;
    let r = responder::accept_with_ephemeral(&key(&v["v131_control_priv"]), &m, key(&v["v131_control_eph_priv"]));
    assert!(matches!(r, Err(tdongle_tailnet_noise::HandshakeError::AuthFailed)));
}
