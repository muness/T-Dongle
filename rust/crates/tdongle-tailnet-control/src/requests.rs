//! The control requests (`RegisterRequest`, `MapRequest`) as bounded JSON writers with the C's exact field set and order, and the `RegisterResponse`
//! reader. Field names follow Go's `tailcfg`; the values and their order follow `ml_coord.c` (`do_register_locked`, `do_map_exchange`,
//! `do_start_long_poll`, `do_send_endpoint_update`).

use crate::http::{CAPABILITY_VERSION, JSON_DEPTH_REGISTER, Out};
use crate::json::{self, JsonWriter, Overflow, Value};
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_types::{FixedStr, Key32};

/// HTTP/2 stream of the register request.
pub const STREAM_REGISTER: u32 = 1;
/// HTTP/2 stream of the initial non-streaming map fetch.
pub const STREAM_MAP_FETCH: u32 = 3;
/// HTTP/2 stream of the long-poll map request.
pub const STREAM_LONG_POLL: u32 = 5;
/// First HTTP/2 stream of an endpoint update (then 9, 11, ...).
pub const FIRST_UPDATE_STREAM: u32 = 7;

/// `tailcfg.EndpointLocal`.
pub const ENDPOINT_LOCAL: u8 = 1;
/// `tailcfg.EndpointSTUN`.
pub const ENDPOINT_STUN: u8 = 2;

/// `Hostinfo`: the same on every message that carries one (the control plane keeps the last it sees).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hostinfo<'a> {
    /// `Hostname`.
    pub hostname: &'a str,
    /// `IPNVersion` (omitted if empty).
    pub ipn_version: &'a str,
    /// `OS` (the C: "linux").
    pub os: &'a str,
    /// `OSVersion` (the C: "ESP-IDF").
    pub os_version: &'a str,
    /// `GoArch` (the C: "arm").
    pub go_arch: &'a str,
    /// Advertised routes, one per line (CR/LF separated, blanks trimmed); the key is written when this is non-empty. At most 255 bytes are read.
    pub routable_ips: &'a str,
    /// `NetInfo.PreferredDERP`.
    pub preferred_derp: u32,
    /// `NetInfo.MappingVariesByDestIP`, written only once STUN has run (`Some`).
    pub mapping_varies_by_dest_ip: Option<bool>,
}

impl<'a> Hostinfo<'a> {
    /// The C's Hostinfo for `hostname` with the given preferred DERP region.
    pub const fn new(hostname: &'a str, preferred_derp: u32) -> Self {
        Self {
            hostname,
            ipn_version: "",
            os: "linux",
            os_version: "ESP-IDF",
            go_arch: "arm",
            routable_ips: "",
            preferred_derp,
            mapping_varies_by_dest_ip: None,
        }
    }

    fn write(&self, w: &mut JsonWriter<'_>) {
        w.key("Hostinfo");
        w.begin_object();
        w.field_str("Hostname", self.hostname);
        if !self.ipn_version.is_empty() {
            w.field_str("IPNVersion", self.ipn_version);
        }
        w.field_str("OS", self.os);
        w.field_str("OSVersion", self.os_version);
        w.field_str("GoArch", self.go_arch);
        if !self.routable_ips.is_empty() {
            w.key("RoutableIPs");
            w.begin_array();
            let mut n = self.routable_ips.len().min(255);
            while !self.routable_ips.is_char_boundary(n) {
                n -= 1;
            }
            for line in self.routable_ips[..n].split(['\r', '\n']) {
                let line = line.trim_matches([' ', '\t']);
                if !line.is_empty() {
                    w.string(line);
                }
            }
            w.end_array();
        }
        w.key("NetInfo");
        w.begin_object();
        w.field_num("PreferredDERP", self.preferred_derp as u64);
        if let Some(v) = self.mapping_varies_by_dest_ip {
            w.field_bool("MappingVariesByDestIP", v);
        }
        w.end_object();
        w.end_object();
    }
}

/// An endpoint address as the map request lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointAddr {
    /// `a.b.c.d:port`.
    V4 {
        /// Address.
        ip: [u8; 4],
        /// Port.
        port: u16,
    },
    /// `[xxxx:...:xxxx]:port`, eight full groups (the C's format).
    V6 {
        /// Address.
        ip: [u8; 16],
        /// Port.
        port: u16,
    },
}

/// One `Endpoints` entry with its `EndpointTypes` code ([`ENDPOINT_LOCAL`], [`ENDPOINT_STUN`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Address.
    pub addr: EndpointAddr,
    /// `tailcfg.EndpointType`.
    pub kind: u8,
}

impl Endpoint {
    /// A STUN-discovered IPv6 endpoint, or `None` for an IPv4-mapped address (redundant with the IPv4 one, as the C skips it).
    pub fn stun_v6(ip: [u8; 16], port: u16) -> Option<Endpoint> {
        const V4MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
        (ip[..12] != V4MAPPED).then_some(Endpoint { addr: EndpointAddr::V6 { ip, port }, kind: ENDPOINT_STUN })
    }

    fn format<'b>(&self, buf: &'b mut [u8; 64]) -> &'b str {
        let mut o = Out::new(buf);
        match self.addr {
            EndpointAddr::V4 { ip, port } => {
                for (i, b) in ip.iter().enumerate() {
                    if i > 0 {
                        let _ = o.put(b".");
                    }
                    let _ = o.dec(*b as u32);
                }
                let _ = o.put(b":");
                let _ = o.dec(port as u32);
            }
            EndpointAddr::V6 { ip, port } => {
                let _ = o.put(b"[");
                for (i, pair) in ip.chunks(2).enumerate() {
                    if i > 0 {
                        let _ = o.put(b":");
                    }
                    let mut h = [0u8; 4];
                    tdongle_tailnet_types::hex_encode(pair, &mut h);
                    let _ = o.put(&h);
                }
                let _ = o.put(b"]:");
                let _ = o.dec(port as u32);
            }
        }
        let n = o.len();
        core::str::from_utf8(&buf[..n]).unwrap_or("")
    }
}

fn write_endpoints(w: &mut JsonWriter<'_>, eps: &[Endpoint]) {
    w.key("Endpoints");
    w.begin_array();
    for e in eps {
        let mut b = [0u8; 64];
        w.string(e.format(&mut b));
    }
    w.end_array();
    w.key("EndpointTypes");
    w.begin_array();
    for e in eps {
        w.number(e.kind as u64);
    }
    w.end_array();
}

/// `RegisterRequest` (stream 1 of a connection).
#[derive(Clone, Copy, Debug)]
pub struct RegisterRequest<'a> {
    /// `NodeKey` (WireGuard public key).
    pub node_key: &'a Key32,
    /// `OldNodeKey`, when rotating (omitted if `None`).
    pub old_node_key: Option<&'a Key32>,
    /// `NLKey` (tailnet-lock public key, `nlpub:`), omitted if `None`.
    pub nl_key: Option<&'a Key32>,
    /// `Followup`: the AuthURL of a pending interactive login (omitted if empty).
    pub followup: &'a str,
    /// `Auth.AuthKey` (omitted if empty).
    pub auth_key: &'a str,
    /// `Hostinfo`.
    pub hostinfo: Hostinfo<'a>,
    /// `NodeKeyChallengeResponse` (`chalresp:`) from [`node_key_challenge_response`], when the server sent a challenge.
    pub challenge_response: Option<&'a Key32>,
    /// `Ephemeral`.
    pub ephemeral: bool,
    /// `Tailnet`: the tailnet to join (omitted if empty).
    pub tailnet: &'a str,
}

impl<'a> RegisterRequest<'a> {
    /// A request carrying only what the C's does.
    pub const fn new(node_key: &'a Key32, hostinfo: Hostinfo<'a>) -> Self {
        Self { node_key, old_node_key: None, nl_key: None, followup: "", auth_key: "", hostinfo, challenge_response: None, ephemeral: false, tailnet: "" }
    }

    /// Write the JSON into `out`; returns its length.
    pub fn write_json(&self, out: &mut [u8]) -> Result<usize, Overflow> {
        let mut w = JsonWriter::new(out);
        w.begin_object();
        w.field_num("Version", CAPABILITY_VERSION as u64);
        w.key("NodeKey");
        w.key_string("nodekey:", self.node_key);
        if let Some(k) = self.old_node_key {
            w.key("OldNodeKey");
            w.key_string("nodekey:", k);
        }
        if let Some(k) = self.nl_key {
            w.key("NLKey");
            w.key_string("nlpub:", k);
        }
        if !self.followup.is_empty() {
            w.field_str("Followup", self.followup);
        }
        if !self.auth_key.is_empty() {
            w.key("Auth");
            w.begin_object();
            w.field_str("AuthKey", self.auth_key);
            w.end_object();
        }
        if self.ephemeral {
            w.field_bool("Ephemeral", true);
        }
        if !self.tailnet.is_empty() {
            w.field_str("Tailnet", self.tailnet);
        }
        self.hostinfo.write(&mut w);
        if let Some(k) = self.challenge_response {
            w.key("NodeKeyChallengeResponse");
            w.key_string("chalresp:", k);
        }
        w.end_object();
        w.finish()
    }
}

/// The response to the server's `nodeKeyChallenge`: `X25519(wg_private, challenge_public)`. `None` for a low-order challenge key.
pub fn node_key_challenge_response(wg_private: &Key32, challenge: &Key32) -> Option<Key32> {
    let mut c = challenge.clone();
    c.0[31] &= 0x7f; // RFC 7748: the high bit is ignored
    x25519::shared(wg_private, &c)
}

/// Which `MapRequest` to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapKind {
    /// The initial non-streaming fetch (stream 3): `Stream:false`, with endpoints.
    Fetch,
    /// The long-poll stream (stream 5): `Stream:true`, `KeepAlive:true`; `omit_peers` is false for the initial stream (it must request the peers).
    /// Version >= 68 servers ignore endpoints and Hostinfo changes on a streaming request, so none are sent.
    LongPoll {
        /// `OmitPeers`.
        omit_peers: bool,
    },
    /// A lite endpoint update (stream 7, 9, ...): `Stream:false`, `OmitPeers:true`, with endpoints.
    EndpointUpdate,
}

/// `MapRequest`.
#[derive(Clone, Copy, Debug)]
pub struct MapRequest<'a> {
    /// `NodeKey`.
    pub node_key: &'a Key32,
    /// `DiscoKey`.
    pub disco_key: &'a Key32,
    /// `Hostinfo`.
    pub hostinfo: Hostinfo<'a>,
    /// Which request.
    pub kind: MapKind,
    /// `Endpoints` / `EndpointTypes` (used by [`MapKind::Fetch`] and [`MapKind::EndpointUpdate`]).
    pub endpoints: &'a [Endpoint],
}

impl<'a> MapRequest<'a> {
    /// Write the JSON into `out`; returns its length.
    pub fn write_json(&self, out: &mut [u8]) -> Result<usize, Overflow> {
        let mut w = JsonWriter::new(out);
        w.begin_object();
        w.field_num("Version", CAPABILITY_VERSION as u64);
        w.key("NodeKey");
        w.key_string("nodekey:", self.node_key);
        w.key("DiscoKey");
        w.key_string("discokey:", self.disco_key);
        match self.kind {
            MapKind::Fetch => {
                w.field_bool("Stream", false);
                w.field_bool("KeepAlive", true);
                w.field_str("Compress", "");
                self.hostinfo.write(&mut w);
                write_endpoints(&mut w, self.endpoints);
            }
            MapKind::LongPoll { omit_peers } => {
                self.hostinfo.write(&mut w);
                w.field_bool("Stream", true);
                w.field_bool("KeepAlive", true);
                w.field_str("Compress", "");
                w.field_bool("OmitPeers", omit_peers);
            }
            MapKind::EndpointUpdate => {
                w.field_bool("Stream", false);
                w.field_bool("KeepAlive", true);
                w.field_bool("OmitPeers", true);
                w.field_str("Compress", "");
                self.hostinfo.write(&mut w);
                write_endpoints(&mut w, self.endpoints);
            }
        }
        w.end_object();
        w.finish()
    }

    /// The HTTP/2 stream the C uses for this request, given the next free update stream.
    pub const fn default_stream(&self, next_update: u32) -> u32 {
        match self.kind {
            MapKind::Fetch => STREAM_MAP_FETCH,
            MapKind::LongPoll { .. } => STREAM_LONG_POLL,
            MapKind::EndpointUpdate => next_update,
        }
    }
}

/// FNV-1a over a request body (the C hashes the whole endpoint update to send it only when it changed).
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = 2_166_136_261u32;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(16_777_619);
    }
    h
}

/// Longest `AuthURL` kept (`auth_url[384]`).
pub const AUTH_URL_BYTES: usize = 383;
/// Longest `Error` text kept.
pub const ERROR_TEXT_BYTES: usize = 127;

/// What a `RegisterResponse` says.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // one value per registration, held on the stack; boxing would need an allocator
pub enum RegisterOutcome {
    /// Registered (`MachineAuthorized` is the control plane's view: false means an admin still has to approve the machine).
    Registered {
        /// `MachineAuthorized`.
        machine_authorized: bool,
    },
    /// Interactive login required: visit this URL, then register again with it as `Followup`.
    AuthUrl(FixedStr<AUTH_URL_BYTES>),
    /// `Error` was non-empty: refused (the other fields are to be ignored, per tailcfg).
    Refused(FixedStr<ERROR_TEXT_BYTES>),
    /// `NodeKeyExpired`: the node key has to be replaced.
    NodeKeyExpired,
}

/// Why a register response could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// No `{` within the first eight bytes.
    NoJson,
    /// Nested deeper than [`JSON_DEPTH_REGISTER`].
    TooDeep,
    /// Not a JSON object.
    Malformed,
}

/// Read a `RegisterResponse` body (the DATA of stream 1). As the C: a binary prefix of up to seven bytes before the `{` is skipped; `Error` wins over
/// `NodeKeyExpired`, which wins over `AuthURL`.
pub fn parse_register_response(body: &[u8]) -> Result<RegisterOutcome, RegisterError> {
    let start = body.iter().take(8).position(|&b| b == b'{').ok_or(RegisterError::NoJson)?;
    let doc = &body[start..];
    if !json::nesting_within(doc, JSON_DEPTH_REGISTER) {
        return Err(RegisterError::TooDeep);
    }
    let mut v = [None; 4];
    json::scan_top(doc, JSON_DEPTH_REGISTER, true, &["Error", "NodeKeyExpired", "AuthURL", "MachineAuthorized"], &mut v).map_err(|e| match e {
        json::JsonError::TooDeep => RegisterError::TooDeep,
        _ => RegisterError::Malformed,
    })?;
    fn text<const N: usize>(v: Option<Value<'_>>) -> Option<FixedStr<N>> {
        let Some(Value::Str(raw)) = v else { return None };
        if raw.is_empty() {
            return None;
        }
        let mut scratch = [0u8; 1024];
        let mut s = FixedStr::new();
        match json::unescape(raw, &mut scratch) {
            Some(n) => s.set(core::str::from_utf8(&scratch[..n]).unwrap_or("")),
            None => s.set("(unreadable)"),
        };
        Some(s)
    }
    if let Some(e) = text::<ERROR_TEXT_BYTES>(v[0]) {
        return Ok(RegisterOutcome::Refused(e));
    }
    if v[1] == Some(Value::Bool(true)) {
        return Ok(RegisterOutcome::NodeKeyExpired);
    }
    if let Some(u) = text::<AUTH_URL_BYTES>(v[2]) {
        return Ok(RegisterOutcome::AuthUrl(u));
    }
    Ok(RegisterOutcome::Registered { machine_authorized: v[3] == Some(Value::Bool(true)) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::{format, string::String, string::ToString, vec, vec::Vec};

    fn nk() -> Key32 {
        Key32([0x11; 32])
    }
    fn dk() -> Key32 {
        Key32([0x22; 32])
    }
    fn s(b: &[u8]) -> &str {
        core::str::from_utf8(b).unwrap()
    }

    #[test]
    fn long_poll_matches_map_request_c_test() {
        let (n, d) = (nk(), dk());
        let mut b = [0u8; 512];
        let mut req =
            MapRequest { node_key: &n, disco_key: &d, hostinfo: Hostinfo::new("tdongle", 4), kind: MapKind::LongPoll { omit_peers: false }, endpoints: &[] };
        let len = req.write_json(&mut b).unwrap();
        let expect = format!(
            "{{\"Version\":131,\"NodeKey\":\"nodekey:{}\",\"DiscoKey\":\"discokey:{}\",\"Hostinfo\":{{\"Hostname\":\"tdongle\",\"OS\":\"linux\",\"OSVersion\":\"ESP-IDF\",\"GoArch\":\"arm\",\"NetInfo\":{{\"PreferredDERP\":4}}}},\"Stream\":true,\"KeepAlive\":true,\"Compress\":\"\",\"OmitPeers\":false}}",
            "11".repeat(32),
            "22".repeat(32)
        );
        assert_eq!(s(&b[..len]), expect);
        req.kind = MapKind::LongPoll { omit_peers: true };
        let len = req.write_json(&mut b).unwrap();
        assert!(s(&b[..len]).ends_with("\"OmitPeers\":true}"));
        // The Go interop harness requires Stream==true, OmitPeers==false and Version==131; the document must be valid JSON.
        let mut v = [None; 4];
        json::scan_top(&b[..len], 4, false, &["Stream", "OmitPeers", "Version", "Hostinfo"], &mut v).unwrap();
        assert_eq!(v[0], Some(Value::Bool(true)));
        assert_eq!(v[2], Some(Value::Number(b"131")));
    }

    #[test]
    fn fetch_and_update_carry_endpoints() {
        let (n, d) = (nk(), dk());
        let mut ip6 = [0u8; 16];
        ip6[0] = 0x20;
        ip6[1] = 0x01;
        ip6[15] = 1;
        let eps = [
            Endpoint { addr: EndpointAddr::V4 { ip: [192, 168, 1, 7], port: 41641 }, kind: ENDPOINT_LOCAL },
            Endpoint { addr: EndpointAddr::V4 { ip: [203, 0, 113, 9], port: 5 }, kind: ENDPOINT_STUN },
            Endpoint::stun_v6(ip6, 1234).unwrap(),
        ];
        let mut hi = Hostinfo::new("h", 1);
        hi.mapping_varies_by_dest_ip = Some(true);
        let mut b = [0u8; 700];
        let r = MapRequest { node_key: &n, disco_key: &d, hostinfo: hi, kind: MapKind::Fetch, endpoints: &eps };
        let len = r.write_json(&mut b).unwrap();
        let t = s(&b[..len]);
        assert!(t.contains("\"Stream\":false,\"KeepAlive\":true,\"Compress\":\"\",\"Hostinfo\""));
        assert!(t.contains("\"MappingVariesByDestIP\":true"));
        assert!(t.ends_with(
            "\"Endpoints\":[\"192.168.1.7:41641\",\"203.0.113.9:5\",\"[2001:0000:0000:0000:0000:0000:0000:0001]:1234\"],\"EndpointTypes\":[1,2,2]}"
        ));
        let r = MapRequest { kind: MapKind::EndpointUpdate, ..r };
        let len = r.write_json(&mut b).unwrap();
        assert!(s(&b[..len]).contains("\"Stream\":false,\"KeepAlive\":true,\"OmitPeers\":true,\"Compress\":\"\",\"Hostinfo\""));
        assert_eq!(r.default_stream(9), 9);
        assert_eq!(MapRequest { kind: MapKind::Fetch, ..r }.default_stream(9), 3);
        assert_eq!(fnv1a32(b""), 2_166_136_261);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
        // IPv4-mapped IPv6 is not an endpoint.
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        assert!(Endpoint::stun_v6(mapped, 1).is_none());
        // Every truncation fails cleanly.
        for cut in 0..len {
            assert!(r.write_json(&mut b[..cut]).is_err());
        }
    }

    #[test]
    fn register_request_fields_and_order() {
        let n = nk();
        let chal = Key32([0x33; 32]);
        let mut hi = Hostinfo::new("dongle \"x\"", 2);
        hi.ipn_version = "1.2.3";
        hi.routable_ips = " 10.0.0.0/24 \r\n\r\n192.168.0.0/16\t\n";
        let mut b = [0u8; 600];
        let mut r = RegisterRequest::new(&n, hi);
        r.auth_key = "tskey-auth-abc";
        r.challenge_response = Some(&chal);
        r.followup = "https://login/a?b=1&c=2";
        r.ephemeral = true;
        let old = Key32([0x44; 32]);
        r.old_node_key = Some(&old);
        let len = r.write_json(&mut b).unwrap();
        let t = s(&b[..len]);
        let order = [
            "\"Version\":131",
            "\"NodeKey\"",
            "\"OldNodeKey\"",
            "\"Followup\"",
            "\"Auth\":{\"AuthKey\":\"tskey-auth-abc\"}",
            "\"Ephemeral\":true",
            "\"Hostinfo\"",
            "\"NodeKeyChallengeResponse\":\"chalresp:3333",
        ];
        let mut at = 0;
        for k in order {
            let i = t[at..].find(k).unwrap_or_else(|| panic!("{k} in {t}"));
            at += i;
        }
        assert!(t.contains("\"Hostname\":\"dongle \\\"x\\\"\",\"IPNVersion\":\"1.2.3\""));
        assert!(t.contains("\"RoutableIPs\":[\"10.0.0.0/24\",\"192.168.0.0/16\"]"));
        json::scan_top(&b[..len], 4, false, &[], &mut []).unwrap();
        // Minimal form (the C's with no auth key and no challenge).
        let len = RegisterRequest::new(&n, Hostinfo::new("h", 0)).write_json(&mut b).unwrap();
        assert!(!s(&b[..len]).contains("Auth") && !s(&b[..len]).contains("Challenge"));
    }

    #[test]
    fn challenge_response_is_x25519() {
        let wg = Key32([9; 32]);
        let challenge = x25519::public(&Key32([7; 32]));
        let a = node_key_challenge_response(&wg, &challenge).unwrap();
        // DH symmetry: the server computes the same value with its private key and our public key.
        let b = x25519::shared(&Key32([7; 32]), &x25519::public(&wg)).unwrap();
        assert_eq!(a, b);
        // The high bit of the challenge is ignored.
        let mut hi = challenge.clone();
        hi.0[31] |= 0x80;
        assert_eq!(node_key_challenge_response(&wg, &hi).unwrap(), a);
        assert!(node_key_challenge_response(&wg, &Key32::ZERO).is_none());
    }

    #[test]
    fn register_response_reader() {
        let ok = br#"{"User":{"ID":1},"NodeKeyExpired":false,"MachineAuthorized":true,"AuthURL":"","Error":""}"#;
        assert_eq!(parse_register_response(ok), Ok(RegisterOutcome::Registered { machine_authorized: true }));
        assert_eq!(parse_register_response(b"{}"), Ok(RegisterOutcome::Registered { machine_authorized: false }));
        match parse_register_response(br#"{"AuthURL":"https://login.example/a?x=1&y=2"}"#).unwrap() {
            RegisterOutcome::AuthUrl(u) => assert_eq!(u.as_str(), "https://login.example/a?x=1&y=2"),
            o => panic!("{o:?}"),
        }
        match parse_register_response(br#"{"Error":"nope","AuthURL":"https://x","NodeKeyExpired":true}"#).unwrap() {
            RegisterOutcome::Refused(e) => assert_eq!(e.as_str(), "nope"),
            o => panic!("{o:?}"),
        }
        assert_eq!(parse_register_response(br#"{"NodeKeyExpired":true,"AuthURL":"https://x"}"#), Ok(RegisterOutcome::NodeKeyExpired));
        // A short binary prefix before the object is skipped; 8 bytes of junk is not.
        assert!(parse_register_response(b"\0\0\0\0\0\0\0{}").is_ok());
        assert_eq!(parse_register_response(b"\0\0\0\0\0\0\0\0{}"), Err(RegisterError::NoJson));
        assert_eq!(parse_register_response(b"{\"a\""), Err(RegisterError::Malformed));
        let deep = format!("{}1{}", "[".repeat(20), "]".repeat(20));
        assert_eq!(parse_register_response(format!("{{\"a\":{deep}}}").as_bytes()), Err(RegisterError::TooDeep));
        // A long AuthURL is cut, not refused.
        let long = format!("{{\"AuthURL\":\"https://{}\"}}", "a".repeat(450));
        match parse_register_response(long.as_bytes()).unwrap() {
            RegisterOutcome::AuthUrl(u) => assert_eq!(u.len(), AUTH_URL_BYTES),
            o => panic!("{o:?}"),
        }
    }
}
