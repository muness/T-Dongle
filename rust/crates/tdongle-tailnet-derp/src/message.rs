//! Typed views of a received frame body, as Go's `Client.Recv` interprets them: tolerant of older servers (fields missing) and newer servers (trailing
//! fields), never panicking on a short body.

use crate::frame::FrameType;
use crate::{KEY_LEN, MAGIC};

/// Why a peer is gone (`derp.PeerGoneReasonType`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PeerGoneReason(pub u8);

impl PeerGoneReason {
    /// The peer disconnected from this server (also the value for an old server's reasonless frame).
    pub const DISCONNECTED: PeerGoneReason = PeerGoneReason(0x00);
    /// This server does not know the peer.
    pub const NOT_HERE: PeerGoneReason = PeerGoneReason(0x01);
}

/// `PeerPresentFlags`: regular client.
pub const PEER_PRESENT_IS_REGULAR: u8 = 1 << 0;
/// Mesh peer.
pub const PEER_PRESENT_IS_MESH_PEER: u8 = 1 << 1;
/// Prober.
pub const PEER_PRESENT_IS_PROBER: u8 = 1 << 2;
/// The client said this server is not its ideal node.
pub const PEER_PRESENT_NOT_IDEAL: u8 = 1 << 3;

/// A frame body, interpreted. Borrows the body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Message<'a> {
    /// The greeting: the server's public key, and any bytes a future server appends.
    ServerKey {
        /// The server key.
        key: &'a [u8; KEY_LEN],
        /// Bytes after the key.
        extra: &'a [u8],
    },
    /// 24-byte nonce then the box (opened by [`crate::handshake::open_server_info`]).
    ServerInfo(&'a [u8]),
    /// A relayed packet.
    RecvPacket {
        /// The sender's node key.
        src: &'a [u8; KEY_LEN],
        /// The packet.
        payload: &'a [u8],
    },
    /// A keep-alive.
    KeepAlive,
    /// A peer is no longer reachable through this server.
    PeerGone {
        /// The peer.
        peer: &'a [u8; KEY_LEN],
        /// Why.
        reason: PeerGoneReason,
    },
    /// A peer is present (mesh servers send these to watchers; a regular client never receives them).
    PeerPresent {
        /// The peer.
        peer: &'a [u8; KEY_LEN],
        /// The 16-byte (IPv4-mapped IPv6) address and port, if the server sent them.
        ip_port: Option<([u8; 16], u16)>,
        /// Flags, if present.
        flags: Option<u8>,
        /// The app name, if present, complete, and valid ([`valid_app_name`]).
        app_name: Option<&'a [u8]>,
    },
    /// A ping: echo the bytes in a pong.
    Ping(&'a [u8]),
    /// A pong.
    Pong(&'a [u8]),
    /// Server-declared health: empty means healthy.
    Health(&'a [u8]),
    /// The server is about to restart.
    Restarting {
        /// Advisory: wait this long before reconnecting.
        reconnect_in_ms: u32,
        /// Advisory: keep trying for this long.
        try_for_ms: u32,
    },
    /// A type this client does not know: skipped.
    Unknown(FrameType, &'a [u8]),
    /// A known type whose body is too short to interpret (Go logs and drops these).
    Malformed(FrameType),
}

/// `derp.ValidAppName`: at most 32 bytes, all printable ASCII.
pub fn valid_app_name(name: &[u8]) -> bool {
    name.len() <= 32 && name.iter().all(|&b| (b' '..=b'~').contains(&b))
}

fn key_at(b: &[u8]) -> Option<&[u8; KEY_LEN]> {
    b.get(..KEY_LEN)?.try_into().ok()
}

impl<'a> Message<'a> {
    /// Interpret a frame. Never fails: a body that does not fit its type is [`Message::Malformed`].
    pub fn parse(ty: FrameType, body: &'a [u8]) -> Message<'a> {
        match ty {
            FrameType::SERVER_KEY => {
                if body.len() < 8 + KEY_LEN || body[..8] != MAGIC {
                    return Message::Malformed(ty);
                }
                match key_at(&body[8..]) {
                    Some(key) => Message::ServerKey { key, extra: &body[8 + KEY_LEN..] },
                    None => Message::Malformed(ty),
                }
            }
            FrameType::SERVER_INFO => Message::ServerInfo(body),
            FrameType::RECV_PACKET => match key_at(body) {
                Some(src) => Message::RecvPacket { src, payload: &body[KEY_LEN..] },
                None => Message::Malformed(ty),
            },
            FrameType::KEEP_ALIVE => Message::KeepAlive,
            FrameType::PEER_GONE => match key_at(body) {
                Some(peer) => {
                    let reason = body.get(KEY_LEN).map_or(PeerGoneReason::DISCONNECTED, |&r| PeerGoneReason(r));
                    Message::PeerGone { peer, reason }
                }
                None => Message::Malformed(ty),
            },
            FrameType::PEER_PRESENT => {
                let Some(peer) = key_at(body) else { return Message::Malformed(ty) };
                let mut m = Message::PeerPresent { peer, ip_port: None, flags: None, app_name: None };
                let rest = &body[KEY_LEN..];
                let Some(addr) = rest.get(..18) else { return m };
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&addr[..16]);
                let port = u16::from_be_bytes([addr[16], addr[17]]);
                let rest = &rest[18..];
                let Some(&flags) = rest.first() else {
                    if let Message::PeerPresent { ip_port, .. } = &mut m {
                        *ip_port = Some((ip, port));
                    }
                    return m;
                };
                let mut app_name = None;
                if let Some(&n) = rest.get(1)
                    && let Some(name) = rest.get(2..2 + n as usize)
                    && valid_app_name(name)
                {
                    app_name = Some(name);
                }
                Message::PeerPresent { peer, ip_port: Some((ip, port)), flags: Some(flags), app_name }
            }
            FrameType::PING if body.len() >= 8 => Message::Ping(body),
            FrameType::PONG if body.len() >= 8 => Message::Pong(body),
            FrameType::PING | FrameType::PONG => Message::Malformed(ty),
            FrameType::HEALTH => Message::Health(body),
            FrameType::RESTARTING => {
                if body.len() < 8 {
                    return Message::Malformed(ty);
                }
                Message::Restarting {
                    reconnect_in_ms: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
                    try_for_ms: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                }
            }
            other => Message::Unknown(other, body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_body(ty: FrameType, fields: &[&[u8]]) -> std::vec::Vec<u8> {
        let _ = ty;
        fields.iter().flat_map(|f| f.iter().copied()).collect()
    }

    /// `client_test.go` `TestClientRecv`.
    #[test]
    fn go_recv_vectors() {
        let p = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(Message::parse(FrameType::PING, &p), Message::Ping(&p));
        assert_eq!(Message::parse(FrameType::PONG, &p), Message::Pong(&p));
        assert_eq!(Message::parse(FrameType::HEALTH, b"BAD"), Message::Health(b"BAD"));
        assert_eq!(Message::parse(FrameType::HEALTH, b""), Message::Health(b""));
        assert_eq!(Message::parse(FrameType::RESTARTING, &[0, 0, 0, 1, 0, 0, 0, 2]), Message::Restarting { reconnect_in_ms: 1, try_for_ms: 2 });
        // the frame the fuzz corpus carries: reconnect in 3.6 s, try for 15 s
        assert_eq!(
            Message::parse(FrameType::RESTARTING, &[0, 0, 0x0e, 0x10, 0, 0, 0x3a, 0x98]),
            Message::Restarting { reconnect_in_ms: 3600, try_for_ms: 15000 }
        );
    }

    #[test]
    fn short_bodies_are_malformed_not_panics() {
        assert_eq!(Message::parse(FrameType::PING, &[1; 7]), Message::Malformed(FrameType::PING));
        assert_eq!(Message::parse(FrameType::PONG, &[]), Message::Malformed(FrameType::PONG));
        assert_eq!(Message::parse(FrameType::RESTARTING, &[0; 7]), Message::Malformed(FrameType::RESTARTING));
        assert_eq!(Message::parse(FrameType::PEER_GONE, &[0; 31]), Message::Malformed(FrameType::PEER_GONE));
        assert_eq!(Message::parse(FrameType::PEER_PRESENT, &[0; 31]), Message::Malformed(FrameType::PEER_PRESENT));
        assert_eq!(Message::parse(FrameType::RECV_PACKET, &[0; 31]), Message::Malformed(FrameType::RECV_PACKET));
        assert_eq!(Message::parse(FrameType::SERVER_KEY, &[0; 39]), Message::Malformed(FrameType::SERVER_KEY));
        assert_eq!(Message::parse(FrameType(0x7e), &[9]), Message::Unknown(FrameType(0x7e), &[9]));
    }

    #[test]
    fn peer_gone_old_and_new() {
        let k = [7u8; 32];
        assert_eq!(Message::parse(FrameType::PEER_GONE, &k), Message::PeerGone { peer: &k, reason: PeerGoneReason::DISCONNECTED });
        let mut b = k.to_vec();
        b.push(1);
        assert!(matches!(Message::parse(FrameType::PEER_GONE, &b), Message::PeerGone { reason: PeerGoneReason::NOT_HERE, .. }));
    }

    #[test]
    fn server_key_with_trailing_future_bytes() {
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&[9u8; 32]);
        b.extend_from_slice(b"future");
        match Message::parse(FrameType::SERVER_KEY, &b) {
            Message::ServerKey { key, extra } => {
                assert_eq!(key, &[9u8; 32]);
                assert_eq!(extra, b"future");
            }
            m => panic!("{m:?}"),
        }
        b[0] ^= 1;
        assert_eq!(Message::parse(FrameType::SERVER_KEY, &b), Message::Malformed(FrameType::SERVER_KEY));
    }

    /// `client_test.go` `TestClientRecvPeerPresent`, every case.
    #[test]
    fn go_peer_present_vectors() {
        let keyb = [1u8; 32];
        let ip_port = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4, 0x12, 0x34];
        let ip: [u8; 16] = ip_port[..16].try_into().unwrap();
        let regular = [PEER_PRESENT_IS_REGULAR];
        let t = |fields: &[&[u8]]| frame_body(FrameType::PEER_PRESENT, fields);

        let b = t(&[&keyb]);
        assert_eq!(Message::parse(FrameType::PEER_PRESENT, &b), Message::PeerPresent { peer: &keyb, ip_port: None, flags: None, app_name: None });
        let b = t(&[&keyb, &ip_port]);
        assert_eq!(Message::parse(FrameType::PEER_PRESENT, &b), Message::PeerPresent { peer: &keyb, ip_port: Some((ip, 0x1234)), flags: None, app_name: None });
        let b = t(&[&keyb, &ip_port, &regular]);
        assert_eq!(
            Message::parse(FrameType::PEER_PRESENT, &b),
            Message::PeerPresent { peer: &keyb, ip_port: Some((ip, 0x1234)), flags: Some(1), app_name: None }
        );
        let b = t(&[&keyb, &ip_port, &regular, &[3, b'a', b'b', b'c']]);
        let want = Message::PeerPresent { peer: &keyb, ip_port: Some((ip, 0x1234)), flags: Some(1), app_name: Some(b"abc") };
        assert_eq!(Message::parse(FrameType::PEER_PRESENT, &b), want);
        // extra fields from a newer server are ignored
        let b = t(&[&keyb, &ip_port, &regular, &[3, b'a', b'b', b'c'], &[0xde, 0xad]]);
        assert_eq!(Message::parse(FrameType::PEER_PRESENT, &b), want);
        // truncated app name: ignored
        let b = t(&[&keyb, &ip_port, &regular, &[200, b'a', b'b', b'c']]);
        assert_eq!(
            Message::parse(FrameType::PEER_PRESENT, &b),
            Message::PeerPresent { peer: &keyb, ip_port: Some((ip, 0x1234)), flags: Some(1), app_name: None }
        );
        // invalid app name: ignored
        let b = t(&[&keyb, &ip_port, &regular, &[3, 1, 2, 3]]);
        assert_eq!(
            Message::parse(FrameType::PEER_PRESENT, &b),
            Message::PeerPresent { peer: &keyb, ip_port: Some((ip, 0x1234)), flags: Some(1), app_name: None }
        );
    }

    /// `derp_test.go` `TestValidAppName`.
    #[test]
    fn go_valid_app_name() {
        assert!(valid_app_name(b""));
        assert!(valid_app_name(b"some-client"));
        assert!(valid_app_name(b"app with spaces 123!"));
        assert!(valid_app_name(&[b'x'; 32]));
        assert!(!valid_app_name(&[b'x'; 33]));
        assert!(!valid_app_name(b"new\nline"));
        assert!(!valid_app_name(b"nul\x00"));
        assert!(!valid_app_name("emoji\u{1F431}".as_bytes()));
    }
}
