//! The plaintext HTTP/1.1 half of the control client (it runs over TCP port 80 or inside TLS, before any Noise): the `/key` fetch, the ts2021 upgrade
//! request and the bounded parser of the `101 Switching Protocols` answer.

use crate::{base64, json};
use tdongle_tailnet_types::{Counter, FixedStr, Key32, Millis};

/// The capability version the C sends everywhere (`ML_CTRL_PROTOCOL_VER`): `/key?v=`, every `Version` field.
pub const CAPABILITY_VERSION: u32 = 131;
/// Longest response header block the upgrade reader accepts, terminator included (the C reads at most 2048 bytes).
pub const UPGRADE_HEADER_MAX: usize = 2048;
/// `CTRL_KEY_REQUEST_MAX`.
pub const KEY_REQUEST_MAX: usize = 256;
/// `CTRL_KEY_RESPONSE_MAX`: a `/key` answer must be strictly smaller.
pub const KEY_RESPONSE_MAX: usize = 1536;
/// `ML_JSON_DEPTH_KEY`: nesting allowed in the `/key` document.
pub const JSON_DEPTH_KEY: u32 = 4;
/// `ML_JSON_DEPTH_REGISTER`: nesting allowed in a `RegisterResponse`.
pub const JSON_DEPTH_REGISTER: u32 = 16;

/// Why a login-server string was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlError {
    /// Empty host, or longer than 63 bytes.
    BadHost,
    /// Empty, non-numeric, longer than 7 digits or above 65535.
    BadPort,
}

/// A parsed `[http[s]://]host[:port]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPort {
    /// Bare host (no scheme, port or path).
    pub host: FixedStr<63>,
    /// TCP port.
    pub port: u16,
    /// TLS? `https://` and a bare host are; only an explicit `http://` is plain.
    pub tls: bool,
}

impl HostPort {
    /// The `Host:` header value: the host, plus `:port` when the port is not the scheme's default.
    pub fn host_header(&self) -> FixedStr<72> {
        let mut out = FixedStr::<72>::new();
        let mut buf = [0u8; 72];
        let mut o = Out::new(&mut buf);
        let _ = o.put(self.host.as_str().as_bytes());
        if self.port != if self.tls { 443 } else { 80 } {
            let _ = o.put(b":");
            let _ = o.dec(self.port as u32);
        }
        let n = o.len();
        out.set(core::str::from_utf8(&buf[..n]).unwrap_or(""));
        out
    }
}

/// Port of `parse_host_port`: no scheme means https (secure by default), `http://` is plain, a `:port` overrides the default, a path is ignored.
pub fn parse_host_port(input: &str) -> Result<HostPort, UrlError> {
    let b = input.as_bytes();
    let starts = |p: &[u8]| b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p);
    let (mut tls, mut default_port, mut rest) = (true, 443u16, b);
    if starts(b"http://") {
        tls = false;
        default_port = 80;
        rest = &b[7..];
    } else if starts(b"https://") {
        rest = &b[8..];
    }
    let slash = rest.iter().position(|&c| c == b'/');
    let authority = &rest[..slash.unwrap_or(rest.len())];
    let colon = authority.iter().position(|&c| c == b':');
    let host = &authority[..colon.unwrap_or(authority.len())];
    if host.is_empty() || host.len() > 63 {
        return Err(UrlError::BadHost);
    }
    let host = core::str::from_utf8(host).map_err(|_| UrlError::BadHost)?;
    let port = match colon {
        None => default_port,
        Some(c) => {
            let digits = &authority[c + 1..];
            if digits.is_empty() || digits.len() > 7 || !digits.iter().all(u8::is_ascii_digit) {
                return Err(UrlError::BadPort);
            }
            let mut v = 0u32;
            for &d in digits {
                v = v * 10 + (d - b'0') as u32;
            }
            u16::try_from(v).map_err(|_| UrlError::BadPort)?
        }
    };
    let mut h = FixedStr::<63>::new();
    h.set(host);
    Ok(HostPort { host: h, port, tls })
}

/// A request did not fit the buffer, or a field would break the header framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The output slice is too small.
    TooSmall,
    /// A host or value contains CR, LF or a control byte.
    BadField,
}

/// A bounded byte appender over a caller slice.
#[derive(Debug)]
pub(crate) struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Out<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }
    pub(crate) fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn put(&mut self, b: &[u8]) -> Result<(), BuildError> {
        if self.buf.len() - self.len < b.len() {
            return Err(BuildError::TooSmall);
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        Ok(())
    }
    pub(crate) fn dec(&mut self, mut n: u32) -> Result<(), BuildError> {
        let mut t = [0u8; 10];
        let mut i = t.len();
        loop {
            i -= 1;
            t[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        self.put(&t[i..])
    }
}

fn clean(s: &str) -> Result<(), BuildError> {
    if s.is_empty() || s.bytes().any(|c| c < 0x20 || c == 0x7f) { Err(BuildError::BadField) } else { Ok(()) }
}

/// `GET /key?v=131` exactly as `ctrl_key_fetch` sends it. Returns the length; the C caps the request at 256 bytes ([`KEY_REQUEST_MAX`]).
pub fn build_key_request(host_header: &str, out: &mut [u8]) -> Result<usize, BuildError> {
    clean(host_header)?;
    let cap = out.len().min(KEY_REQUEST_MAX);
    let out = &mut out[..cap];
    let mut o = Out::new(out);
    o.put(b"GET /key?v=")?;
    o.dec(CAPABILITY_VERSION)?;
    o.put(b" HTTP/1.1\r\nHost: ")?;
    o.put(host_header.as_bytes())?;
    o.put(b"\r\nUser-Agent: microlink\r\nConnection: close\r\n\r\n")?;
    Ok(o.len())
}

/// The ts2021 upgrade request carrying the Noise initiation (101 bytes from the Noise layer) base64-encoded in `X-Tailscale-Handshake`, byte for byte
/// the C's. Returns the length.
pub fn build_upgrade_request(host_header: &str, initiation: &[u8], out: &mut [u8]) -> Result<usize, BuildError> {
    clean(host_header)?;
    let mut o = Out::new(out);
    o.put(b"POST /ts2021 HTTP/1.1\r\nHost: ")?;
    o.put(host_header.as_bytes())?;
    o.put(b"\r\nUpgrade: tailscale-control-protocol\r\nConnection: Upgrade\r\nUser-Agent: Tailscale\r\nX-Tailscale-Handshake: ")?;
    let at = o.len;
    let n = base64::encode(initiation, &mut o.buf[at..]).ok_or(BuildError::TooSmall)?;
    o.len += n;
    o.put(b"\r\nContent-Length: 0\r\n\r\n")?;
    Ok(o.len())
}

/// Why the upgrade answer was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeError {
    /// No blank line within [`UPGRADE_HEADER_MAX`] bytes.
    TooLong,
    /// Complete, but not `HTTP/1.x 101 `.
    NotSwitching,
}

/// Where the upgrade reader is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeStatus {
    /// Feed more bytes.
    NeedMore,
    /// `101` seen and the blank line consumed; everything after the returned count is the Noise server message.
    Switched,
}

/// Reads the answer to the upgrade request up to and including the blank line and never past it, so the first Noise bytes that arrived in the same TCP
/// segment stay with the caller. Memory is a 13-byte status prefix and a rolling four-byte window, not the header block.
#[derive(Clone, Debug)]
pub struct UpgradeReader {
    prefix: [u8; 13],
    used: u16,
    last4: u32,
    done: bool,
    /// Header blocks refused (too long or not `101`).
    pub refused: Counter,
}

impl Default for UpgradeReader {
    fn default() -> Self {
        Self::new()
    }
}

impl UpgradeReader {
    /// Fresh.
    pub const fn new() -> Self {
        Self { prefix: [0; 13], used: 0, last4: 0, done: false, refused: Counter(0) }
    }

    /// Consume bytes of `data` up to the terminator. Returns how many were consumed (all of them unless the terminator was found) and the status.
    pub fn push(&mut self, data: &[u8]) -> Result<(usize, UpgradeStatus), UpgradeError> {
        if self.done {
            return Ok((0, UpgradeStatus::Switched));
        }
        for (i, &b) in data.iter().enumerate() {
            if (self.used as usize) < self.prefix.len() {
                self.prefix[self.used as usize] = b;
            }
            self.used += 1;
            self.last4 = (self.last4 << 8) | b as u32;
            if self.used >= 4 && self.last4 == 0x0d0a_0d0a {
                self.done = true;
                let ok = self.used >= 13 && (&self.prefix == b"HTTP/1.1 101 " || &self.prefix == b"HTTP/1.0 101 ");
                if ok {
                    return Ok((i + 1, UpgradeStatus::Switched));
                }
                self.refused.bump();
                return Err(UpgradeError::NotSwitching);
            }
            if self.used as usize >= UPGRADE_HEADER_MAX {
                self.done = true;
                self.refused.bump();
                return Err(UpgradeError::TooLong);
            }
        }
        Ok((data.len(), UpgradeStatus::NeedMore))
    }
}

/// Why a `/key` answer was refused (no key is stored on any of these).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// More than [`KEY_RESPONSE_MAX`]-1 bytes (or the caller buffer): refused, never truncated into something parseable.
    TooLarge,
    /// Nothing arrived.
    Empty,
    /// No blank line, or not `HTTP/1.0|1.1`.
    NotHttp,
    /// Status other than 200.
    Status,
    /// A chunked body without a size line.
    Body,
    /// The document nests deeper than [`JSON_DEPTH_KEY`].
    TooDeep,
    /// Not JSON, or no `publicKey` string.
    NoKey,
    /// `publicKey` is not 64 hex digits after an optional `mkey:`.
    BadKey,
}

/// Collects a `/key` answer into a caller buffer (size it [`KEY_RESPONSE_MAX`]) and parses it.
#[derive(Debug)]
pub struct KeyResponse<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> KeyResponse<'a> {
    /// Collect into `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Append bytes read from the connection. The answer must stay strictly below the buffer's size.
    pub fn push(&mut self, data: &[u8]) -> Result<(), KeyError> {
        if data.len() >= self.buf.len() - self.len {
            return Err(KeyError::TooLarge);
        }
        self.buf[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
        Ok(())
    }

    /// Parse what was collected (the connection is closed by now): `HTTP/1.x 200`, headers, optional chunked framing, then the JSON `publicKey`.
    pub fn finish(&self) -> Result<Key32, KeyError> {
        parse_key_response(&self.buf[..self.len])
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Parse a complete `/key` answer. See [`KeyResponse::finish`].
pub fn parse_key_response(resp: &[u8]) -> Result<Key32, KeyError> {
    if resp.is_empty() {
        return Err(KeyError::Empty);
    }
    if resp.len() >= KEY_RESPONSE_MAX {
        return Err(KeyError::TooLarge);
    }
    let end = find(resp, b"\r\n\r\n").ok_or(KeyError::NotHttp)?;
    let (head, mut body) = (&resp[..end], &resp[end + 4..]);
    if head.len() < 12 || &head[..7] != b"HTTP/1." || !matches!(head[7], b'0' | b'1') || head[8] != b' ' {
        return Err(KeyError::NotHttp);
    }
    if &head[9..12] != b"200" || head.get(12).is_some_and(|&c| c != b' ' && c != b'\r') {
        return Err(KeyError::Status);
    }
    let mut chunked = false;
    for line in head.split(|&c| c == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&c| c == b':') else { continue };
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"transfer-encoding") && value.eq_ignore_ascii_case(b"chunked") {
            chunked = true;
        }
    }
    if chunked {
        // As the C: the first chunk-size line is skipped and the document is parsed from there (reverse proxies send one chunk for a body this small).
        let nl = find(body, b"\r\n").ok_or(KeyError::Body)?;
        let size = core::str::from_utf8(&body[..nl]).ok().and_then(|s| usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16).ok());
        body = &body[nl + 2..];
        if let Some(sz) = size {
            body = &body[..sz.min(body.len())];
        }
    }
    // Content-Length is not enforced (the C ignores it, its own test fixture states a wrong one); a truncated body fails as a JSON document.
    if !json::nesting_within(body, JSON_DEPTH_KEY) {
        return Err(KeyError::TooDeep);
    }
    let mut v = [None; 1];
    json::scan_top(body, JSON_DEPTH_KEY, true, &["publicKey"], &mut v)
        .map_err(|e| if e == json::JsonError::TooDeep { KeyError::TooDeep } else { KeyError::NoKey })?;
    let Some(json::Value::Str(raw)) = v[0] else { return Err(KeyError::NoKey) };
    let s = raw.strip_prefix(b"mkey:").unwrap_or(raw);
    Key32::from_hex(s).ok_or(KeyError::BadKey)
}

/// Who vouches for the Noise key the client will use (`ctrl_key_auth`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySource {
    /// No key yet.
    None,
    /// Tailscale SaaS: the key compiled into the Noise crate; nothing is fetched.
    PinnedBuiltin,
    /// An operator-supplied key.
    PinnedConfig,
    /// Fetched over TLS with the certificate verified.
    TlsVerified,
    /// Fetched over plain HTTP: not authenticated.
    Plaintext,
}

/// What `ensure` decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPlan {
    /// Use the built-in Tailscale key (pass no key to the Noise layer).
    Builtin,
    /// Use the cached or pinned key.
    Cached,
    /// Fetch `/key` over TLS (certificate and host name verified, no fallback to plain).
    FetchTls,
    /// Fetch `/key` over plain HTTP (an explicit `http://` server).
    FetchPlain,
    /// An https key must wait for the wall clock (a certificate cannot be judged before SNTP).
    WaitForClock,
}

/// A fetched key is a cache, not a pin: after this many consecutive failed Noise handshakes it is dropped and fetched again.
pub const KEY_DROP_AFTER: u8 = 2;
/// Smallest gap between drops.
pub const KEY_DROP_MIN_MS: u32 = 30_000;
/// Largest gap between drops.
pub const KEY_DROP_MAX_MS: u32 = 600_000;

/// The key cache and its rotation policy: port of `ctrl_key_ensure` (as a plan) and `ctrl_key_note_handshake`.
#[derive(Clone, Debug)]
pub struct KeyCache {
    key: Key32,
    valid: bool,
    /// Who vouches for the key.
    pub source: KeySource,
    failures: u8,
    drop_backoff_ms: u32,
    next_drop_ms: Millis,
    /// Times a fetched key was dropped to be re-fetched.
    pub refetches: Counter,
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyCache {
    /// Empty.
    pub const fn new() -> Self {
        Self { key: Key32::ZERO, valid: false, source: KeySource::None, failures: 0, drop_backoff_ms: 0, next_drop_ms: 0, refetches: Counter(0) }
    }

    /// An operator-supplied key: any scheme, never fetched, never dropped.
    pub fn pin(&mut self, key: Key32) {
        self.key = key;
        self.valid = true;
        self.source = KeySource::PinnedConfig;
    }

    /// The usable key, if any.
    pub fn key(&self) -> Option<&Key32> {
        self.valid.then_some(&self.key)
    }

    /// Decide what to do before connecting. `login_server_empty` is the SaaS case; `tls` is the login server's scheme; `clock_valid` is whether SNTP has set the clock.
    pub fn plan(&mut self, login_server_empty: bool, tls: bool, clock_valid: bool) -> KeyPlan {
        if login_server_empty {
            self.source = KeySource::PinnedBuiltin;
            return KeyPlan::Builtin;
        }
        if self.valid {
            return KeyPlan::Cached;
        }
        if tls { if clock_valid { KeyPlan::FetchTls } else { KeyPlan::WaitForClock } } else { KeyPlan::FetchPlain }
    }

    /// Store a key fetched as [`KeyPlan::FetchTls`] (`tls = true`) or [`KeyPlan::FetchPlain`].
    pub fn store_fetched(&mut self, key: Key32, tls: bool) {
        self.key = key;
        self.valid = true;
        self.source = if tls { KeySource::TlsVerified } else { KeySource::Plaintext };
    }

    /// Report a Noise handshake result. Only fetched keys are ever dropped, and drops are spaced by a doubling gap (30 s to 10 min).
    pub fn note_handshake(&mut self, ok: bool, now: Millis) {
        if ok {
            self.failures = 0;
            return;
        }
        if !matches!(self.source, KeySource::TlsVerified | KeySource::Plaintext) {
            return;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures < KEY_DROP_AFTER || now < self.next_drop_ms {
            return;
        }
        self.valid = false;
        self.failures = 0;
        self.refetches.bump();
        self.drop_backoff_ms = if self.drop_backoff_ms == 0 {
            KEY_DROP_MIN_MS
        } else if self.drop_backoff_ms >= KEY_DROP_MAX_MS / 2 {
            KEY_DROP_MAX_MS
        } else {
            self.drop_backoff_ms * 2
        };
        self.next_drop_ms = now + self.drop_backoff_ms as Millis;
    }

    /// Current gap between drops (for tests and status).
    pub fn drop_backoff_ms(&self) -> u32 {
        self.drop_backoff_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use std::{format, string::String, string::ToString, vec, vec::Vec};

    const KEYHEX: &str = "7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b";
    const GOOD: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 160\r\nConnection: close\r\n\r\n{\"legacyPublicKey\":\"mkey:9e5156a4c65121306dd2d8ed8f92cb8d738e2533011344b522c5d28409bc4970\",\"publicKey\":\"mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b\"}";

    fn key() -> Key32 {
        Key32::from_hex(KEYHEX.as_bytes()).unwrap()
    }

    fn fetch(resp: &[u8], piece: usize) -> Result<Key32, KeyError> {
        let mut buf = [0u8; KEY_RESPONSE_MAX];
        let mut r = KeyResponse::new(&mut buf);
        for c in resp.chunks(piece.max(1)) {
            r.push(c)?;
        }
        r.finish()
    }

    #[test]
    fn host_port_cases_from_c_test() {
        let p = |s| parse_host_port(s);
        let a = p("hs.example.com").unwrap();
        assert!(a.tls && a.port == 443 && a.host.as_str() == "hs.example.com");
        assert!(p("hs.example.com:8443").unwrap().tls && p("hs.example.com:8443").unwrap().port == 8443);
        assert_eq!(p("https://hs.example.com").unwrap().port, 443);
        let c = p("HTTPS://hs.example.com:9/x").unwrap();
        assert!(c.tls && c.port == 9 && c.host.as_str() == "hs.example.com");
        let d = p("http://hs.lan").unwrap();
        assert!(!d.tls && d.port == 80);
        assert_eq!(p("http://hs.lan:8080").unwrap().port, 8080);
        assert_eq!(p("http://"), Err(UrlError::BadHost));
        assert_eq!(p("hs:99999999"), Err(UrlError::BadPort));
        assert_eq!(p("hs:80a"), Err(UrlError::BadPort));
        assert_eq!(p("hs:"), Err(UrlError::BadPort));
        assert_eq!(p("hs:65536"), Err(UrlError::BadPort));
        assert_eq!(p(""), Err(UrlError::BadHost));
        let long = "h".repeat(64);
        assert_eq!(p(&long), Err(UrlError::BadHost));
        assert_eq!(p("hs.example.com:8443").unwrap().host_header().as_str(), "hs.example.com:8443");
        assert_eq!(p("hs.example.com:443").unwrap().host_header().as_str(), "hs.example.com");
        assert_eq!(p("http://hs.lan:80").unwrap().host_header().as_str(), "hs.lan");
        assert_eq!(p("http://hs.lan:443").unwrap().host_header().as_str(), "hs.lan:443");
    }

    #[test]
    fn key_request_bytes() {
        let mut b = [0u8; 256];
        let n = build_key_request("hs.example.com", &mut b).unwrap();
        assert_eq!(&b[..n], b"GET /key?v=131 HTTP/1.1\r\nHost: hs.example.com\r\nUser-Agent: microlink\r\nConnection: close\r\n\r\n");
        assert_eq!(build_key_request("a\r\nb", &mut b), Err(BuildError::BadField));
        assert_eq!(build_key_request("h", &mut b[..20]), Err(BuildError::TooSmall));
    }

    #[test]
    fn upgrade_request_bytes() {
        let init = [7u8; 101];
        let mut b = [0u8; 512];
        let n = build_upgrade_request("localhost", &init, &mut b).unwrap();
        let s = core::str::from_utf8(&b[..n]).unwrap();
        assert!(s.starts_with("POST /ts2021 HTTP/1.1\r\nHost: localhost\r\nUpgrade: tailscale-control-protocol\r\nConnection: Upgrade\r\nUser-Agent: Tailscale\r\nX-Tailscale-Handshake: "));
        assert!(s.ends_with("\r\nContent-Length: 0\r\n\r\n"));
        let line = s.lines().find(|l| l.starts_with("X-Tailscale-Handshake: ")).unwrap();
        let b64 = &line["X-Tailscale-Handshake: ".len()..];
        assert_eq!(b64.len(), 136);
        let mut d = [0u8; 101];
        assert_eq!(base64::decode(b64.as_bytes(), &mut d), Some(101));
        assert_eq!(d, init);
        assert_eq!(build_upgrade_request("h", &init, &mut b[..100]), Err(BuildError::TooSmall));
    }

    #[test]
    fn upgrade_reader_every_split_keeps_the_tail() {
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n\x02\x00\x30tail";
        let head = resp.len() - 7;
        for split in 0..resp.len() {
            let mut r = UpgradeReader::new();
            let mut consumed = 0;
            let mut st = UpgradeStatus::NeedMore;
            for part in [&resp[..split], &resp[split..]] {
                let mut off = 0;
                while off < part.len() && st == UpgradeStatus::NeedMore {
                    let (n, s) = r.push(&part[off..]).unwrap();
                    off += n;
                    consumed += n;
                    st = s;
                }
            }
            assert_eq!((st, consumed), (UpgradeStatus::Switched, head), "{split}");
        }
        let mut r = UpgradeReader::new();
        for &b in &resp[..head] {
            assert!(r.push(&[b]).is_ok());
        }
    }

    #[test]
    fn upgrade_reader_refusals() {
        let mut r = UpgradeReader::new();
        assert_eq!(r.push(b"HTTP/1.1 200 OK\r\n\r\n"), Err(UpgradeError::NotSwitching));
        assert_eq!(r.refused.get(), 1);
        let mut r = UpgradeReader::new();
        assert_eq!(r.push(b"HTTP/1.1 101\r\n\r\n"), Err(UpgradeError::NotSwitching));
        let mut r = UpgradeReader::new();
        let big = [b'a'; 3000];
        assert_eq!(r.push(&big), Err(UpgradeError::TooLong));
        // Exactly 2048 bytes including the terminator is accepted if it is a 101.
        let mut h = [b'x'; 2048];
        h[..13].copy_from_slice(b"HTTP/1.0 101 ");
        h[2044..].copy_from_slice(b"\r\n\r\n");
        assert_eq!(UpgradeReader::new().push(&h), Ok((2048, UpgradeStatus::Switched)));
        h[2044..].copy_from_slice(b"\r\n\r\r");
        assert_eq!(UpgradeReader::new().push(&h), Err(UpgradeError::TooLong));
    }

    #[test]
    fn good_key_response_any_piece_size() {
        assert_eq!(GOOD.split("\r\n\r\n").nth(1).unwrap().len(), 175); // the C fixture says Content-Length: 160, which nothing checks
        for piece in [1, 7, 100, 1000] {
            assert_eq!(fetch(GOOD.as_bytes(), piece).unwrap(), key());
        }
    }

    #[test]
    fn hostile_key_responses_from_c_test() {
        let doc = format!("{{\"publicKey\":\"mkey:{KEYHEX}\"}}");
        let cases: [(&str, String, KeyError); 9] = [
            ("error status", format!("HTTP/1.1 400 Bad Request\r\n\r\n{doc}"), KeyError::Status),
            ("redirect", format!("HTTP/1.1 302 Found\r\nLocation: http://evil/\r\n\r\n{doc}"), KeyError::Status),
            ("not http", doc.clone(), KeyError::NotHttp),
            ("no headers end", format!("HTTP/1.1 200 OK\r\n{doc}"), KeyError::NotHttp),
            ("not json", "HTTP/1.1 200 OK\r\n\r\nhello".into(), KeyError::NoKey),
            ("no key", format!("HTTP/1.1 200 OK\r\n\r\n{{\"legacyPublicKey\":\"mkey:{KEYHEX}\"}}"), KeyError::NoKey),
            ("short key", "HTTP/1.1 200 OK\r\n\r\n{\"publicKey\":\"mkey:7d2792f9\"}".into(), KeyError::BadKey),
            ("non hex", format!("HTTP/1.1 200 OK\r\n\r\n{{\"publicKey\":\"mkey:zz{}\"}}", &KEYHEX[2..]), KeyError::BadKey),
            ("empty", String::new(), KeyError::Empty),
        ];
        for (label, resp, want) in cases {
            assert_eq!(fetch(resp.as_bytes(), 100), Err(want), "{label}");
        }
        let mut big = vec![b'a'; 3999];
        big[..GOOD.len()].copy_from_slice(GOOD.as_bytes());
        assert_eq!(fetch(&big, 100), Err(KeyError::TooLarge));
        let deep = format!("HTTP/1.1 200 OK\r\n\r\n{{\"a\":[[[[1]]]],\"publicKey\":\"mkey:{KEYHEX}\"}}");
        assert_eq!(fetch(deep.as_bytes(), 100), Err(KeyError::TooDeep));
        // A truncated body is not a document.
        let cut = &GOOD[..GOOD.len() - 5];
        assert_eq!(fetch(cut.as_bytes(), 100), Err(KeyError::NoKey));
        assert_eq!(fetch(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5", 100), Err(KeyError::Body));
        // A bare key without the prefix is accepted (the C strips `mkey:` if present).
        let bare = format!("HTTP/1.0 200 OK\r\n\r\n{{\"publicKey\":\"{KEYHEX}\"}}");
        assert_eq!(fetch(bare.as_bytes(), 100).unwrap(), key());
    }

    #[test]
    fn chunked_key_response() {
        let r = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nA5\r\n{{\"publicKey\":\"mkey:{KEYHEX}\"}}\r\n0\r\n\r\n");
        assert_eq!(fetch(r.as_bytes(), 9).unwrap(), key());
        let r = format!("HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n55\r\n{{\"publicKey\":\"mkey:{KEYHEX}\"}}\r\n0\r\n\r\n");
        assert_eq!(fetch(r.as_bytes(), 9).unwrap(), key());
    }

    #[test]
    fn key_plan_and_rotation_from_c_test() {
        let mut c = KeyCache::new();
        assert_eq!(c.plan(true, true, false), KeyPlan::Builtin);
        assert_eq!(c.source, KeySource::PinnedBuiltin);
        let mut c = KeyCache::new();
        assert_eq!(c.plan(false, true, false), KeyPlan::WaitForClock);
        assert_eq!(c.plan(false, true, true), KeyPlan::FetchTls);
        assert_eq!(c.plan(false, false, false), KeyPlan::FetchPlain);
        c.store_fetched(key(), true);
        assert_eq!((c.plan(false, true, true), c.source), (KeyPlan::Cached, KeySource::TlsVerified));
        // rotation
        c.note_handshake(false, 1000);
        assert!(c.key().is_some());
        c.note_handshake(true, 1100);
        c.note_handshake(false, 1200);
        assert!(c.key().is_some());
        c.note_handshake(false, 1300);
        assert!(c.key().is_none() && c.refetches.get() == 1);
        c.store_fetched(key(), true);
        c.note_handshake(true, 2000);
        c.note_handshake(false, 5000);
        c.note_handshake(false, 5100);
        assert!(c.key().is_some() && c.refetches.get() == 1);
        c.note_handshake(false, 1300 + KEY_DROP_MIN_MS as u64 + 1);
        c.note_handshake(false, 1300 + KEY_DROP_MIN_MS as u64 + 2);
        assert!(c.key().is_none() && c.refetches.get() == 2 && c.drop_backoff_ms() == 2 * KEY_DROP_MIN_MS);
        let mut t = 1_000_000u64;
        for _ in 0..20 {
            c.store_fetched(key(), true);
            c.note_handshake(false, t);
            c.note_handshake(false, t);
            t += 10_000_000;
            assert!(c.drop_backoff_ms() <= KEY_DROP_MAX_MS);
        }
        // plaintext keys drop too; pins and the built-in key never
        let mut h = KeyCache::new();
        h.store_fetched(key(), false);
        h.note_handshake(false, 10);
        h.note_handshake(false, 11);
        assert!(h.key().is_none());
        let mut p = KeyCache::new();
        p.pin(key());
        for i in 0..50 {
            p.note_handshake(false, 100_000_000 * i);
        }
        assert!(p.key().is_some() && p.refetches.get() == 0);
        assert_eq!(p.plan(false, true, true), KeyPlan::Cached);
        let mut s = KeyCache::new();
        s.plan(true, true, true);
        for i in 0..50 {
            s.note_handshake(false, 100_000_000 * i);
        }
        assert_eq!(s.refetches.get(), 0);
    }
}
