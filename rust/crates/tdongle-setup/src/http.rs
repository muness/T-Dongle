//! A minimal HTTP/1.x request parser that behaves like `esp_http_server` (IDF v5.5.5, `httpd_parse.c` over nodejs `http_parser`) as the
//! dongle configures it (`HTTPD_DEFAULT_CONFIG`: 512 byte URI limit, 1024 byte request-head limit, 5 s receive timeout in a setup boot).
//!
//! What is kept:
//! * request line `METHOD SP URL SP HTTP/major.minor`, LF or CRLF line ends; an unknown method or a malformed line is `400`; a version
//!   other than 1.0 and 1.1 is `505`; a request line that does not fit in 512 bytes is `414`; the request head (line and headers) larger
//!   than 1024 bytes is `431`;
//! * header names are tokens (anything else is `400`); a header value is the raw text after `:` with only spaces skipped; the C looks a
//!   header up **by first match, case-insensitively**, copies it into a fixed buffer and reports truncation: [`Request::header`] does the
//!   same, including the quirk that a value of exactly the buffer size is silently cut by one byte and reported OK;
//! * `Content-Length` is a single run of digits (a duplicate or non-digit is `400`); a `chunked` request has `content_len` 0 in the C
//!   (the router then answers "Request is too large") and here the connection is also marked to be closed, because the C would parse the
//!   chunk bytes as the next request (which ends in a `400` and a close);
//! * `Upgrade` requests (`Connection: upgrade` with an `Upgrade` header, or `CONNECT`) are `400` (WebSocket support is off);
//! * the path is the URL up to `?` or `#`, matched exactly against the registered handlers, never decoded.
//!
//! Deliberate differences (stricter than the C, never looser): an obsolete line fold (a header line starting with space or tab) and a
//! bare CR are `400`.
//!
//! [`Reader`] is the incremental, allocation free form: bytes arrive in any chunking and the outcome is the same; a receive timeout
//! while the head is incomplete is `408` and a close (the C's default 408 handler).

/// `CONFIG_HTTPD_MAX_URI_LEN`.
pub const MAX_URI: usize = 512;
/// `CONFIG_HTTPD_MAX_REQ_HDR_LEN`.
pub const MAX_HEAD: usize = 1024;
/// The largest body the `/command` handler accepts (`content_len > 1024` is refused).
pub const MAX_BODY: usize = 1024;
/// `recv_wait_timeout` of a setup boot, in milliseconds: the longest the server waits for the next bytes of one receive call.
pub const RECV_TIMEOUT_MS: u32 = 5_000;

/// The request methods `http_parser` knows (an unknown token is a `400`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `HEAD`
    Head,
    /// `PUT`
    Put,
    /// `DELETE`
    Delete,
    /// `OPTIONS`
    Options,
    /// Any other method `http_parser` accepts (`PATCH`, `TRACE`, WebDAV ...): never registered, so always `405` on a known path.
    Other,
}

/// Why a request is refused before any handler runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpError {
    /// 400 "Bad request syntax"
    BadRequest,
    /// 408 "Server closed this connection"
    Timeout,
    /// 414 "URI is too long"
    UriTooLong,
    /// 431 "Header fields are too long"
    HeadTooLarge,
    /// 505 "HTTP version not supported by server"
    Version,
}

const METHODS: &[(&[u8], Method)] = &[
    (b"GET", Method::Get),
    (b"POST", Method::Post),
    (b"HEAD", Method::Head),
    (b"PUT", Method::Put),
    (b"DELETE", Method::Delete),
    (b"OPTIONS", Method::Options),
    (b"CONNECT", Method::Other),
    (b"TRACE", Method::Other),
    (b"COPY", Method::Other),
    (b"LOCK", Method::Other),
    (b"MKCOL", Method::Other),
    (b"MOVE", Method::Other),
    (b"PROPFIND", Method::Other),
    (b"PROPPATCH", Method::Other),
    (b"SEARCH", Method::Other),
    (b"UNLOCK", Method::Other),
    (b"BIND", Method::Other),
    (b"REBIND", Method::Other),
    (b"UNBIND", Method::Other),
    (b"ACL", Method::Other),
    (b"REPORT", Method::Other),
    (b"MKACTIVITY", Method::Other),
    (b"CHECKOUT", Method::Other),
    (b"MERGE", Method::Other),
    (b"M-SEARCH", Method::Other),
    (b"NOTIFY", Method::Other),
    (b"SUBSCRIBE", Method::Other),
    (b"UNSUBSCRIBE", Method::Other),
    (b"PATCH", Method::Other),
    (b"PURGE", Method::Other),
    (b"MKCALENDAR", Method::Other),
    (b"LINK", Method::Other),
    (b"UNLINK", Method::Other),
    (b"SOURCE", Method::Other),
];

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The value of a header as `httpd_req_get_hdr_value_str` returns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderValue<'a> {
    /// No such header.
    Missing,
    /// `ESP_ERR_HTTPD_RESULT_TRUNC`: longer than the buffer (the caller treats it as absent).
    Truncated,
    /// `ESP_OK`; may be one byte shorter than the header when it was exactly the buffer size.
    Value(&'a [u8]),
}

impl<'a> HeaderValue<'a> {
    /// `Some(value)` only for `ESP_OK`.
    #[must_use]
    pub fn ok(self) -> Option<&'a [u8]> {
        if let Self::Value(v) = self { Some(v) } else { None }
    }
}

/// A parsed request head.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The method.
    pub method: Method,
    /// The URL exactly as sent.
    pub uri: &'a [u8],
    /// The path part (`None` for an absolute URL without a path: the C closes the connection silently).
    pub path: Option<&'a [u8]>,
    /// The query string after `?`, before `#`.
    pub query: Option<&'a [u8]>,
    /// `req->content_len`: the `Content-Length`, or 0 when absent or chunked.
    pub content_len: u64,
    /// The request used `Transfer-Encoding: chunked`.
    pub chunked: bool,
    headers: &'a [u8],
}

impl<'a> Request<'a> {
    /// `httpd_req_get_hdr_value_str(req, name, buf, cap)`: the first header called `name` (ASCII case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str, cap: usize) -> HeaderValue<'a> {
        for line in lines(self.headers) {
            let Some(colon) = line.iter().position(|&b| b == b':') else { break };
            if !line[..colon].eq_ignore_ascii_case(name.as_bytes()) {
                continue;
            }
            let mut value = &line[colon + 1..];
            while let Some((&b' ', rest)) = value.split_first() {
                value = rest;
            }
            // The C copies a C string: a NUL ends it.
            if let Some(nul) = value.iter().position(|&b| b == 0) {
                value = &value[..nul];
            }
            if cap < value.len() {
                return HeaderValue::Truncated;
            }
            // strlcpy keeps at most cap - 1 bytes; a value of exactly cap bytes is cut by one and still OK.
            return HeaderValue::Value(&value[..value.len().min(cap.saturating_sub(1))]);
        }
        HeaderValue::Missing
    }

    /// `httpd_req_get_hdr_value_len`: the length of the value, 0 when absent or empty.
    #[must_use]
    pub fn header_len(&self, name: &str) -> usize {
        match self.header(name, usize::MAX) {
            HeaderValue::Value(v) => v.len(),
            _ => 0,
        }
    }
}

/// The header lines of a header block (without line terminators).
fn lines(block: &[u8]) -> impl Iterator<Item = &[u8]> {
    block.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l)).filter(|l| !l.is_empty())
}

struct Head {
    method: Method,
    uri: (usize, usize),
    path: Option<(usize, usize)>,
    query: Option<(usize, usize)>,
    content_len: u64,
    chunked: bool,
    headers: (usize, usize),
    len: usize,
}

enum Parse {
    NeedMore,
    Done(Head),
    Err(HttpError),
}

/// Walk the bytes in stream order, reporting the first error the C parser would hit.
fn parse_head(buf: &[u8]) -> Parse {
    use HttpError::{BadRequest, HeadTooLarge, UriTooLong, Version};
    // --- request line
    let Some(sp) = buf.iter().position(|&b| b == b' ') else {
        // No method end yet: the bytes so far must be a prefix of some method token.
        if buf.iter().any(|&b| !(b.is_ascii_uppercase() || b == b'-')) {
            return Parse::Err(BadRequest);
        }
        return if METHODS.iter().any(|(m, _)| m.starts_with(buf)) || buf.is_empty() { Parse::NeedMore } else { Parse::Err(BadRequest) };
    };
    let Some(&(_, method)) = METHODS.iter().find(|(m, _)| *m == &buf[..sp]) else { return Parse::Err(BadRequest) };
    if method == Method::Other && &buf[..sp] == b"CONNECT" {
        return Parse::Err(BadRequest);
    }
    let url_start = sp + 1;
    let mut i = url_start;
    while i < buf.len() && !matches!(buf[i], b' ' | b'\r' | b'\n') {
        if matches!(buf[i], 0 | b'\t' | 0x0c) {
            return Parse::Err(BadRequest);
        }
        i += 1;
        if i - url_start > MAX_URI {
            return Parse::Err(UriTooLong);
        }
    }
    if i >= buf.len() {
        return Parse::NeedMore;
    }
    let url_end = i;
    if url_end == url_start || buf[i] != b' ' {
        return Parse::Err(BadRequest);
    }
    // version "HTTP/d.d"
    let version_start = i + 1;
    let Some(eol) = buf[version_start..].iter().position(|&b| b == b'\n').map(|p| p + version_start) else {
        // Validate the prefix while waiting.
        let prefix = &buf[version_start..];
        return if prefix.iter().all(|&b| b != b'\r') || prefix.ends_with(b"\r") { check_version_prefix(prefix) } else { Parse::Err(BadRequest) };
    };
    let mut vend = eol;
    if vend > version_start && buf[vend - 1] == b'\r' {
        vend -= 1;
    }
    let version = &buf[version_start..vend];
    let Some((major, minor)) = parse_version(version) else { return Parse::Err(BadRequest) };
    if eol + 1 > MAX_URI {
        // The request line plus the byte after it did not fit in the 512 byte URI window of the scratch buffer.
        return Parse::Err(UriTooLong);
    }
    if !(major == 1 && (minor == 0 || minor == 1)) {
        return Parse::Err(Version);
    }
    // --- the URL
    let uri = &buf[url_start..url_end];
    let (path, query) = match split_url(uri) {
        Some(x) => x,
        None => return Parse::Err(BadRequest),
    };
    // --- headers
    let headers_start = eol + 1;
    let mut pos = headers_start;
    let mut content_len: Option<u64> = None;
    let mut chunked = false;
    let mut connection_upgrade = false;
    let mut has_upgrade = false;
    let end;
    loop {
        let Some(rel) = buf[pos..].iter().position(|&b| b == b'\n') else {
            // incomplete line: check what is there is not already an error
            let partial = &buf[pos..];
            if partial.first().is_some_and(|&b| b == b' ' || b == b'\t') {
                return Parse::Err(BadRequest);
            }
            if let Some(c) = partial.iter().position(|&b| b == b':') {
                if !partial[..c].iter().all(|&b| is_token(b)) || c == 0 {
                    return Parse::Err(BadRequest);
                }
            } else if !partial.iter().all(|&b| is_token(b) || b == b'\r') || partial.iter().take(partial.len().saturating_sub(1)).any(|&b| b == b'\r') {
                return Parse::Err(BadRequest);
            }
            return if buf.len() >= MAX_HEAD { Parse::Err(HeadTooLarge) } else { Parse::NeedMore };
        };
        let line_end = pos + rel;
        let mut line = &buf[pos..line_end];
        if let Some(l) = line.strip_suffix(b"\r") {
            line = l;
        }
        if line.is_empty() {
            end = line_end + 1;
            break;
        }
        if line.contains(&b'\r') || line[0] == b' ' || line[0] == b'\t' {
            return Parse::Err(BadRequest);
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else { return Parse::Err(BadRequest) };
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_token(b)) {
            return Parse::Err(BadRequest);
        }
        let value = trim_ows(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            if content_len.is_some() || value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Parse::Err(BadRequest);
            }
            let mut n: u64 = 0;
            for d in value {
                n = match n.checked_mul(10).and_then(|n| n.checked_add(u64::from(d - b'0'))) {
                    Some(n) => n,
                    None => return Parse::Err(BadRequest),
                };
            }
            content_len = Some(n);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            chunked = contains_token(value, b"chunked");
        } else if name.eq_ignore_ascii_case(b"connection") {
            connection_upgrade |= contains_token(value, b"upgrade");
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            has_upgrade = true;
        }
        pos = line_end + 1;
        if pos > MAX_HEAD {
            return Parse::Err(HeadTooLarge);
        }
    }
    if end > MAX_HEAD {
        return Parse::Err(HeadTooLarge);
    }
    if connection_upgrade && has_upgrade {
        return Parse::Err(BadRequest);
    }
    Parse::Done(Head {
        method,
        uri: (url_start, url_end),
        path: path.map(|(a, b)| (url_start + a, url_start + b)),
        query: query.map(|(a, b)| (url_start + a, url_start + b)),
        content_len: if chunked { 0 } else { content_len.unwrap_or(0) },
        chunked,
        headers: (headers_start, end),
        len: end,
    })
}

fn check_version_prefix(prefix: &[u8]) -> Parse {
    const WANT: &[u8] = b"HTTP/";
    let p = prefix.strip_suffix(b"\r").unwrap_or(prefix);
    let n = p.len().min(WANT.len());
    if p[..n] != WANT[..n] {
        return Parse::Err(HttpError::BadRequest);
    }
    if p.len() > WANT.len() && !p[WANT.len()..].iter().all(|&b| b.is_ascii_digit() || b == b'.') {
        return Parse::Err(HttpError::BadRequest);
    }
    Parse::NeedMore
}

fn parse_version(v: &[u8]) -> Option<(u32, u32)> {
    let rest = v.strip_prefix(b"HTTP/")?;
    let dot = rest.iter().position(|&b| b == b'.')?;
    let (a, b) = (&rest[..dot], &rest[dot + 1..]);
    let num = |s: &[u8]| -> Option<u32> {
        if s.is_empty() || s.len() > 3 || !s.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(s.iter().fold(0, |n, d| n * 10 + u32::from(d - b'0')))
    };
    Some((num(a)?, num(b)?))
}

/// `http_parser_parse_url` for a request URL: `(path, query)` as ranges inside `uri`; the outer `None` is a parse failure.
#[allow(clippy::type_complexity)]
fn split_url(uri: &[u8]) -> Option<(Option<(usize, usize)>, Option<(usize, usize)>)> {
    let mut start = 0;
    if uri.first() != Some(&b'/') && uri.first() != Some(&b'*') {
        // absolute form: scheme "://" host [":" port] then a path
        let scheme = uri.iter().position(|&b| !(b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.'))?;
        if scheme == 0 || !uri[0].is_ascii_alphabetic() || !uri[scheme..].starts_with(b"://") {
            return None;
        }
        let host = scheme + 3;
        let rest = uri[host..].iter().position(|&b| matches!(b, b'/' | b'?' | b'#')).map(|p| p + host);
        match rest {
            None => return if host < uri.len() { Some((None, None)) } else { None },
            Some(p) if uri[p] == b'/' => start = p,
            Some(_) => return Some((None, None)),
        }
    }
    let stop = uri[start..].iter().position(|&b| b == b'?' || b == b'#').map_or(uri.len(), |p| p + start);
    let query = if uri.get(stop) == Some(&b'?') {
        let qs = stop + 1;
        let qe = uri[qs..].iter().position(|&b| b == b'#').map_or(uri.len(), |p| p + qs);
        Some((qs, qe))
    } else {
        None
    };
    Some((Some((start, stop)), query))
}

fn trim_ows(v: &[u8]) -> &[u8] {
    let mut v = v;
    while let Some((&(b' ' | b'\t'), r)) = v.split_first() {
        v = r;
    }
    while let Some((&(b' ' | b'\t'), r)) = v.split_last() {
        v = r;
    }
    v
}

fn contains_token(value: &[u8], token: &[u8]) -> bool {
    value.split(|&b| b == b',').any(|t| trim_ows(t).eq_ignore_ascii_case(token))
}

/// Capacity of [`Reader`]'s head buffer.
pub const HEAD_CAP: usize = MAX_HEAD + 1;

/// What the reader needs next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Feed more bytes.
    More,
    /// The head (and, for a body that fits, the body) is complete: call [`Reader::request`].
    Ready,
    /// Answer this error and close.
    Reject(HttpError),
}

/// Incremental request reader with fixed buffers (no allocation).
#[derive(Debug)]
pub struct Reader {
    head: [u8; HEAD_CAP],
    head_len: usize,
    body: [u8; MAX_BODY],
    body_len: usize,
    parsed: Option<ParsedHead>,
    last_activity_ms: u32,
    body_timed_out: bool,
}

#[derive(Clone, Copy, Debug)]
struct ParsedHead {
    method: Method,
    uri: (usize, usize),
    path: Option<(usize, usize)>,
    query: Option<(usize, usize)>,
    content_len: u64,
    chunked: bool,
    headers: (usize, usize),
    len: usize,
}

impl Reader {
    /// A reader for a new request; `now_ms` starts the receive timeout.
    #[must_use]
    pub fn new(now_ms: u32) -> Self {
        Self { head: [0; HEAD_CAP], head_len: 0, body: [0; MAX_BODY], body_len: 0, parsed: None, last_activity_ms: now_ms, body_timed_out: false }
    }

    /// Feed received bytes. Returns how many were used (the rest belongs to the next request on a kept-alive connection) and what to do.
    pub fn push(&mut self, data: &[u8], now_ms: u32) -> (usize, Step) {
        self.last_activity_ms = now_ms;
        let mut used = 0;
        if self.parsed.is_none() {
            // Take bytes one block at a time until the head is complete or fails.
            while used < data.len() && self.parsed.is_none() {
                if self.head_len == HEAD_CAP {
                    // 1025 bytes without an end of head: report what the stream did first.
                    return (
                        used,
                        Step::Reject(match parse_head(&self.head[..self.head_len]) {
                            Parse::Err(e) => e,
                            _ => HttpError::HeadTooLarge,
                        }),
                    );
                }
                self.head[self.head_len] = data[used];
                self.head_len += 1;
                used += 1;
                match parse_head(&self.head[..self.head_len]) {
                    Parse::NeedMore => {}
                    Parse::Err(e) => return (used, Step::Reject(e)),
                    Parse::Done(h) => {
                        self.parsed = Some(ParsedHead {
                            method: h.method,
                            uri: h.uri,
                            path: h.path,
                            query: h.query,
                            content_len: h.content_len,
                            chunked: h.chunked,
                            headers: h.headers,
                            len: h.len,
                        });
                        // Everything the head scan buffered past its end is body: only the byte-wise loop above runs, so none is.
                    }
                }
            }
        }
        if let Some(h) = self.parsed {
            let want = usize::try_from(h.content_len).unwrap_or(usize::MAX);
            if want <= MAX_BODY {
                let take = (want - self.body_len).min(data.len() - used);
                self.body[self.body_len..self.body_len + take].copy_from_slice(&data[used..used + take]);
                self.body_len += take;
                used += take;
                if self.body_len < want {
                    return (used, Step::More);
                }
            }
            return (used, Step::Ready);
        }
        (used, Step::More)
    }

    /// The receive timeout: call when no bytes arrived for [`RECV_TIMEOUT_MS`]. Before the head is complete it is a `408` and a close;
    /// after it, the body is cut short and the handler sees an incomplete body (the C: `httpd_req_recv` fails, "Incomplete request").
    pub fn timeout(&mut self, now_ms: u32) -> Step {
        if now_ms.wrapping_sub(self.last_activity_ms) < RECV_TIMEOUT_MS {
            return if self.parsed.is_some() { Step::Ready } else { Step::More };
        }
        if self.parsed.is_none() {
            return Step::Reject(HttpError::Timeout);
        }
        self.body_timed_out = true;
        Step::Ready
    }

    /// The parsed request, once [`Step::Ready`].
    #[must_use]
    pub fn request(&self) -> Option<Request<'_>> {
        let h = self.parsed?;
        let r = |(a, b): (usize, usize)| &self.head[a..b];
        Some(Request {
            method: h.method,
            uri: r(h.uri),
            path: h.path.map(r),
            query: h.query.map(r),
            content_len: h.content_len,
            chunked: h.chunked,
            headers: &self.head[h.headers.0..h.headers.1.min(h.len)],
        })
    }

    /// The body bytes received (complete unless [`Reader::body_incomplete`] or larger than [`MAX_BODY`]).
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body[..self.body_len]
    }

    /// The body did not arrive in full (a receive timeout, or a body larger than the buffer that the handler refuses unread).
    #[must_use]
    pub fn body_incomplete(&self) -> bool {
        self.parsed.is_some_and(|h| (self.body_len as u64) < h.content_len)
    }

    /// The connection must be closed after the answer (a chunked body would be misread as the next request).
    #[must_use]
    pub fn must_close(&self) -> bool {
        self.parsed.is_some_and(|h| h.chunked) || self.body_timed_out
    }
}
