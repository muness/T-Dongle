//! Versioned IP-over-serial framing for the Android VPN transport. No allocation.
//! SLIP escaping provides recovery after truncation/boot messages; CRC detects corruption.
#![no_std]
#![forbid(unsafe_code)]

pub const MTU: usize = 1500;
pub const HEADER: usize = 14;
pub const MAX_RAW: usize = HEADER + MTU + 2;
pub const MAX_WIRE: usize = 2 * MAX_RAW + 2;
pub const END: u8 = 0xc0;
const ESC: u8 = 0xdb;
pub const HELLO: u8 = 1;
pub const IDENTITY: u8 = 2;
pub const JOIN: u8 = 3;
pub const STATUS: u8 = 4;
pub const IP: u8 = 5;
pub const STOP: u8 = 6;
pub const PING: u8 = 7;
/// One printable owner-console command; never arbitrary binary input.
pub const COMMAND: u8 = 8;
/// A chunk of the same dispatcher reply used by the S3 console.
pub const REPLY: u8 = 9;
pub const GATEWAY: [u8; 4] = [192, 168, 77, 1];
pub const BOARD: &[u8] = b"TDONGLE-C5 0.4.0-rc2 serial-ip/2";
pub const HOST: [u8; 4] = [192, 168, 77, 2];

pub fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &b in bytes {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

#[derive(Debug)]
pub struct Frame<'a> {
    pub kind: u8,
    pub session: u64,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub struct Decoder {
    raw: [u8; MAX_RAW],
    len: usize,
    escaped: bool,
    discard: bool,
}
impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}
impl Decoder {
    pub const fn new() -> Self {
        Self { raw: [0; MAX_RAW], len: 0, escaped: false, discard: true }
    }
    /// The returned frame borrows storage until the next byte is fed.
    pub fn feed(&mut self, b: u8) -> Option<Frame<'_>> {
        if b == END {
            let n = self.len;
            let valid = !self.discard && !self.escaped && n >= HEADER + 2;
            self.len = 0;
            self.escaped = false;
            self.discard = false;
            if !valid || self.raw[..3] != [b'T', b'D', 1] {
                return None;
            }
            let size = usize::from(u16::from_be_bytes([self.raw[12], self.raw[13]]));
            if n != HEADER + size + 2 || crc16(&self.raw[..n - 2]) != u16::from_be_bytes([self.raw[n - 2], self.raw[n - 1]]) {
                return None;
            }
            let session = u64::from_be_bytes(self.raw[4..12].try_into().ok()?);
            return Some(Frame { kind: self.raw[3], session, payload: &self.raw[HEADER..n - 2] });
        }
        if self.discard {
            return None;
        }
        let byte = if self.escaped {
            self.escaped = false;
            match b {
                0xdc => END,
                0xdd => ESC,
                _ => {
                    self.discard = true;
                    return None;
                }
            }
        } else if b == ESC {
            self.escaped = true;
            return None;
        } else {
            b
        };
        if self.len == MAX_RAW {
            self.discard = true;
        } else {
            self.raw[self.len] = byte;
            self.len += 1;
        }
        None
    }
}

pub fn encode(kind: u8, session: u64, payload: &[u8], out: &mut [u8; MAX_WIRE]) -> Option<usize> {
    if payload.len() > MTU {
        return None;
    }
    let mut raw = [0u8; MAX_RAW];
    raw[..4].copy_from_slice(&[b'T', b'D', 1, kind]);
    raw[4..12].copy_from_slice(&session.to_be_bytes());
    raw[12..14].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    raw[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    let n = HEADER + payload.len();
    let crc = crc16(&raw[..n]).to_be_bytes();
    raw[n..n + 2].copy_from_slice(&crc);
    let mut w = 1;
    out[0] = END;
    for &b in &raw[..n + 2] {
        match b {
            END => {
                out[w] = ESC;
                out[w + 1] = 0xdc;
                w += 2;
            }
            ESC => {
                out[w] = ESC;
                out[w + 1] = 0xdd;
                w += 2;
            }
            _ => {
                out[w] = b;
                w += 1;
            }
        }
    }
    out[w] = END;
    Some(w + 1)
}

/// Validate the complete IPv4 envelope before handing it to the existing NAT.
pub fn ipv4(packet: &[u8], outbound: bool) -> bool {
    if packet.len() < 20 || packet.len() > MTU || packet[0] >> 4 != 4 {
        return false;
    }
    let ihl = usize::from(packet[0] & 15) * 4;
    ihl >= 20
        && ihl <= packet.len()
        && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
        && if outbound { packet[12..16] == HOST } else { packet[16..20] == HOST }
}

/// Printable ASCII matches the existing companion profile contract. Never Debug secrets.
pub fn credentials(payload: &[u8]) -> Option<(&str, &str)> {
    let (&ssid_len, bytes) = payload.split_first()?;
    let n = usize::from(ssid_len);
    if !(1..=32).contains(&n) || bytes.len() < n {
        return None;
    }
    let (ssid, pass) = bytes.split_at(n);
    if !pass.is_empty() && !(8..=63).contains(&pass.len()) {
        return None;
    }
    if bytes.iter().any(|b| !(32..=126).contains(b)) {
        return None;
    }
    Some((core::str::from_utf8(ssid).ok()?, core::str::from_utf8(pass).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_all_bytes_and_boundary() {
        let mut data = [0; MTU];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut out = [0; MAX_WIRE];
        let n = encode(IP, 0x102030405060708, &data, &mut out).unwrap();
        let mut d = Decoder::new();
        let mut seen = 0;
        for &b in &out[..n] {
            if let Some(f) = d.feed(b) {
                assert_eq!(f.payload, data);
                assert_eq!(f.kind, IP);
                assert_eq!(f.session, 0x102030405060708);
                seen += 1;
            }
        }
        assert_eq!(seen, 1);
    }
    #[test]
    fn corrupt_truncated_oversized_and_noise_recover() {
        let mut out = [0; MAX_WIRE];
        let n = encode(HELLO, 42, b"hello", &mut out).unwrap();
        let mut d = Decoder::new();
        for _ in 0..MAX_RAW + 20 {
            assert!(d.feed(42).is_none());
        }
        for &b in &out[..n / 2] {
            assert!(d.feed(b).is_none());
        }
        let mut bad = out;
        bad[5] ^= 1;
        for &b in &bad[..n] {
            assert!(d.feed(b).is_none());
        }
        let mut seen = 0;
        for &b in &out[..n] {
            if let Some(f) = d.feed(b) {
                assert_eq!(f.session, 42);
                seen += 1;
            }
        }
        assert_eq!(seen, 1);
    }
    #[test]
    fn crc_reference() {
        assert_eq!(crc16(b"123456789"), 0x29b1);
    }
    #[test]
    fn credentials_are_bounded() {
        assert_eq!(credentials(b"\x04homepassword"), Some(("home", "password")));
        for invalid in [b"".as_slice(), b"\x00", b"\x20short", b"\x04homebad", b"\x04hom\npassword"] {
            assert!(credentials(invalid).is_none());
        }
    }
    #[test]
    fn packet_envelope_and_host_binding() {
        let mut p = [0u8; 20];
        p[0] = 0x45;
        p[3] = 20;
        p[12..16].copy_from_slice(&HOST);
        assert!(ipv4(&p, true));
        assert!(!ipv4(&p, false));
        p[3] = 21;
        assert!(!ipv4(&p, true));
    }
}
