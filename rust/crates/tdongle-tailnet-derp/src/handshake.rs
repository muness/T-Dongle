//! The connection handshake: the HTTP upgrade (`GET /derp`, `Upgrade: DERP`, `101`), then ServerKey, ClientInfo and ServerInfo.

use crate::{HTTP_MAX, KEY_LEN, NONCE_LEN};
use tdongle_tailnet_crypto::nacl;
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_types::Key32;

/// Why a handshake step failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandshakeError {
    /// The output buffer is too small.
    OutputTooSmall,
    /// The host name contains a byte that must not appear in a header value.
    BadHost,
    /// The box could not be sealed (a small-order server key).
    Seal,
    /// The box did not open: wrong key or a corrupted frame.
    Open,
    /// The frame is too short to hold a nonce and a tag.
    Short,
}

/// Write the upgrade request (`derphttp_client.go`: `GET /derp`, `Upgrade: DERP`, `Connection: Upgrade`). Returns its length.
pub fn write_upgrade_request(host: &str, out: &mut [u8]) -> Result<usize, HandshakeError> {
    if host.bytes().any(|b| b < 0x21 || b == 0x7f) {
        return Err(HandshakeError::BadHost);
    }
    let parts: [&[u8]; 3] = [b"GET /derp HTTP/1.1\r\nHost: ", host.as_bytes(), b"\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n"];
    let total: usize = parts.iter().map(|p| p.len()).sum();
    if out.len() < total {
        return Err(HandshakeError::OutputTooSmall);
    }
    let mut at = 0;
    for p in parts {
        out[at..at + p.len()].copy_from_slice(p);
        at += p.len();
    }
    Ok(total)
}

/// What the response scanner decided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpgradeStatus {
    /// The blank line has not arrived yet.
    NeedMore,
    /// `HTTP/1.x 101` and the header block is complete: the DERP stream starts at the next byte.
    Upgraded,
    /// Not a 101 (the server refused, or the answer is not HTTP).
    Refused,
    /// The header block is longer than [`HTTP_MAX`].
    TooLong,
}

/// Reads the HTTP response a byte at a time so that nothing of the DERP stream behind it is consumed. The status is the code on the status line, not
/// any "101" in the headers.
#[derive(Clone, Copy, Debug, Default)]
pub struct UpgradeScanner {
    tail: [u8; 4],
    line: [u8; 16],
    seen: u16,
}

impl UpgradeScanner {
    /// A scanner at the start of a response.
    pub const fn new() -> Self {
        Self { tail: [0; 4], line: [0; 16], seen: 0 }
    }

    /// Forget everything.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Consume bytes up to and including the end of the header block (or the first reason to give up). Returns the bytes consumed and the verdict.
    pub fn feed(&mut self, data: &[u8]) -> (usize, UpgradeStatus) {
        for (i, &b) in data.iter().enumerate() {
            if (self.seen as usize) < self.line.len() {
                self.line[self.seen as usize] = b;
            }
            self.seen = self.seen.saturating_add(1);
            self.tail = [self.tail[1], self.tail[2], self.tail[3], b];
            if self.seen >= 4 && self.tail == *b"\r\n\r\n" {
                let ok = self.seen >= 12 && &self.line[..7] == b"HTTP/1." && self.line[8] == b' ' && &self.line[9..12] == b"101";
                return (i + 1, if ok { UpgradeStatus::Upgraded } else { UpgradeStatus::Refused });
            }
            if self.seen as usize >= HTTP_MAX {
                return (i + 1, UpgradeStatus::TooLong);
            }
        }
        (data.len(), UpgradeStatus::NeedMore)
    }
}

/// The JSON the C announces (`ml_derp.c`): version 2, can ack pings, not a prober.
pub const CLIENT_INFO_JSON: &[u8] = br#"{"Version":2,"CanAckPings":true,"IsProber":false}"#;
/// Length of the ClientInfo frame body: our key, the nonce, the box.
pub const CLIENT_INFO_BODY_LEN: usize = KEY_LEN + NONCE_LEN + nacl::TAG_LEN + CLIENT_INFO_JSON.len();

/// Build the ClientInfo frame body: `public (32) || nonce (24) || nacl_box(json)` with the box made from our node secret to the server key
/// (`derp_client.go` `sendClientKey`). Returns the length ([`CLIENT_INFO_BODY_LEN`]).
pub fn client_info_body(secret: &Key32, server_key: &Key32, nonce: &[u8; NONCE_LEN], out: &mut [u8]) -> Result<usize, HandshakeError> {
    if out.len() < CLIENT_INFO_BODY_LEN {
        return Err(HandshakeError::OutputTooSmall);
    }
    let public = x25519::public(secret);
    out[..KEY_LEN].copy_from_slice(&public.0);
    out[KEY_LEN..KEY_LEN + NONCE_LEN].copy_from_slice(nonce);
    let boxed = &mut out[KEY_LEN + NONCE_LEN..CLIENT_INFO_BODY_LEN];
    boxed[nacl::TAG_LEN..].copy_from_slice(CLIENT_INFO_JSON);
    nacl::box_seal(secret, server_key, nonce, boxed).map_err(|_| HandshakeError::Seal)?;
    Ok(CLIENT_INFO_BODY_LEN)
}

/// Open the ServerInfo body (`nonce (24) || box`) in place with our node secret and the server key. Returns the JSON.
pub fn open_server_info<'a>(secret: &Key32, server_key: &Key32, body: &'a mut [u8]) -> Result<&'a [u8], HandshakeError> {
    if body.len() < NONCE_LEN + nacl::TAG_LEN {
        return Err(HandshakeError::Short);
    }
    let (nonce, boxed) = body.split_at_mut(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = (&*nonce).try_into().map_err(|_| HandshakeError::Short)?;
    nacl::box_open(secret, server_key, &nonce, boxed).map_err(|_| HandshakeError::Open)?;
    Ok(&boxed[nacl::TAG_LEN..])
}

/// The numbers a ServerInfo JSON may carry (`derp.ServerInfo`). Zero means absent.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ServerInfo {
    /// `version`.
    pub version: u32,
    /// `TokenBucketBytesPerSecond`: the server's send rate limit for this client.
    pub bytes_per_second: u32,
    /// `TokenBucketBytesBurst`.
    pub burst: u32,
}

fn json_u32(json: &[u8], key: &[u8]) -> u32 {
    // `"key":` followed by optional spaces and digits. A scanner, not a JSON parser: the three fields are flat integers.
    let mut i = 0;
    while i + key.len() + 2 <= json.len() {
        if json[i] == b'"' && &json[i + 1..i + 1 + key.len()] == key && json[i + 1 + key.len()] == b'"' {
            let mut j = i + key.len() + 2;
            while j < json.len() && json[j] == b' ' {
                j += 1;
            }
            if json.get(j) != Some(&b':') {
                i += 1;
                continue;
            }
            j += 1;
            while j < json.len() && json[j] == b' ' {
                j += 1;
            }
            let mut v: u32 = 0;
            while j < json.len() && json[j].is_ascii_digit() {
                v = v.saturating_mul(10).saturating_add((json[j] - b'0') as u32);
                j += 1;
            }
            return v;
        }
        i += 1;
    }
    0
}

/// Pull the known numbers out of a ServerInfo JSON. Unknown fields and a malformed document yield zeros.
pub fn parse_server_info(json: &[u8]) -> ServerInfo {
    ServerInfo {
        version: json_u32(json, b"version"),
        bytes_per_second: json_u32(json, b"TokenBucketBytesPerSecond"),
        burst: json_u32(json, b"TokenBucketBytesBurst"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn key(seed: u8) -> Key32 {
        Key32(core::array::from_fn(|i| seed.wrapping_mul(17).wrapping_add(i as u8 * 5 + 1)))
    }

    #[test]
    fn upgrade_request_text_is_what_the_c_sends() {
        let mut out = [0u8; 256];
        let n = write_upgrade_request("derp4.tailscale.com", &mut out).unwrap();
        assert_eq!(&out[..n], b"GET /derp HTTP/1.1\r\nHost: derp4.tailscale.com\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n".as_slice());
        assert_eq!(write_upgrade_request("a b", &mut out), Err(HandshakeError::BadHost));
        assert_eq!(write_upgrade_request("a\r\nX: y", &mut out), Err(HandshakeError::BadHost));
        assert_eq!(write_upgrade_request("h", &mut out[..10]), Err(HandshakeError::OutputTooSmall));
    }

    fn scan(chunks: &[&[u8]]) -> UpgradeStatus {
        let mut s = UpgradeScanner::new();
        let mut last = UpgradeStatus::NeedMore;
        for c in chunks {
            let (_, st) = s.feed(c);
            last = st;
            if st != UpgradeStatus::NeedMore {
                break;
            }
        }
        last
    }

    #[test]
    fn upgrade_scanner_accepts_101_only_on_the_status_line() {
        let ok = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
        assert_eq!(scan(&[ok]), UpgradeStatus::Upgraded);
        // one byte at a time
        let singles: Vec<&[u8]> = ok.chunks(1).collect();
        assert_eq!(scan(&singles), UpgradeStatus::Upgraded);
        assert_eq!(scan(&[b"HTTP/1.0 101 x\r\n\r\n"]), UpgradeStatus::Upgraded);
        // "101" elsewhere is not a 101
        assert_eq!(scan(&[b"HTTP/1.1 200 OK\r\nX-Note: 101\r\n\r\n"]), UpgradeStatus::Refused);
        assert_eq!(scan(&[b"HTTP/1.1 403 Forbidden\r\n\r\n"]), UpgradeStatus::Refused);
        assert_eq!(scan(&[b"HTTP/2 101\r\n\r\n"]), UpgradeStatus::Refused);
        assert_eq!(scan(&[b"\r\n\r\n"]), UpgradeStatus::Refused);
        assert_eq!(scan(&[b"HTTP/1.1 101 ok\r\nUpgrade: DERP\r\n"]), UpgradeStatus::NeedMore);
    }

    #[test]
    fn upgrade_scanner_stops_at_the_blank_line_and_bounds_the_header() {
        let mut s = UpgradeScanner::new();
        let mut data = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        let used = data.len();
        data.extend_from_slice(&[0x01, 0, 0, 0, 40]);
        let (n, st) = s.feed(&data);
        assert_eq!((n, st), (used, UpgradeStatus::Upgraded));
        let mut s = UpgradeScanner::new();
        let junk = [b'x'; 2000];
        let (n, st) = s.feed(&junk);
        assert_eq!((n, st), (HTTP_MAX, UpgradeStatus::TooLong));
    }

    #[test]
    fn client_info_roundtrip_and_layout() {
        let (me, srv) = (key(1), key(2));
        let srv_pub = x25519::public(&srv);
        let nonce = [7u8; NONCE_LEN];
        let mut out = [0u8; 200];
        let n = client_info_body(&me, &srv_pub, &nonce, &mut out).unwrap();
        assert_eq!(n, CLIENT_INFO_BODY_LEN);
        assert_eq!(n, 32 + 24 + 16 + CLIENT_INFO_JSON.len());
        assert_eq!(&out[..32], &x25519::public(&me).0);
        assert_eq!(&out[32..56], &nonce);
        // the server opens it with its secret and our public key
        let mut boxed = out[56..n].to_vec();
        nacl::box_open(&srv, &x25519::public(&me), &nonce, &mut boxed).unwrap();
        assert_eq!(&boxed[16..], CLIENT_INFO_JSON);
        assert_eq!(client_info_body(&me, &srv_pub, &nonce, &mut out[..n - 1]), Err(HandshakeError::OutputTooSmall));
    }

    #[test]
    fn server_info_open() {
        let (me, srv) = (key(3), key(4));
        let (me_pub, srv_pub) = (x25519::public(&me), x25519::public(&srv));
        let json = br#"{"version":2,"TokenBucketBytesPerSecond":65536,"TokenBucketBytesBurst":131072}"#;
        let nonce = [9u8; NONCE_LEN];
        let mut body = std::vec![0u8; 24 + 16 + json.len()];
        body[..24].copy_from_slice(&nonce);
        body[40..].copy_from_slice(json);
        nacl::box_seal(&srv, &me_pub, &nonce, &mut body[24..]).unwrap();
        let mut ok = body.clone();
        let plain = open_server_info(&me, &srv_pub, &mut ok).unwrap();
        assert_eq!(plain, json);
        assert_eq!(parse_server_info(plain), ServerInfo { version: 2, bytes_per_second: 65536, burst: 131072 });
        let mut bad = body.clone();
        bad[50] ^= 1;
        assert_eq!(open_server_info(&me, &srv_pub, &mut bad), Err(HandshakeError::Open));
        assert_eq!(open_server_info(&me, &srv_pub, &mut [0u8; 39]), Err(HandshakeError::Short));
    }

    #[test]
    fn server_info_json_scanner() {
        assert_eq!(parse_server_info(b""), ServerInfo::default());
        assert_eq!(parse_server_info(b"{}"), ServerInfo::default());
        assert_eq!(parse_server_info(br#"{"version" : 2 }"#).version, 2);
        assert_eq!(parse_server_info(br#"{"TokenBucketBytesPerSecond":99999999999999}"#).bytes_per_second, u32::MAX);
        assert_eq!(parse_server_info(b"\"version\"").version, 0);
        assert_eq!(parse_server_info(br#"{"xversion":7}"#).version, 0);
    }
}
