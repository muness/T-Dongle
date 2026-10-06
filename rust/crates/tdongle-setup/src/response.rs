//! The response builder: bytes identical to `esp_http_server` (`httpd_resp_send`, `httpd_resp_send_chunk`, `httpd_resp_send_err`).
//!
//! `HTTP/1.1 <status>\r\nContent-Type: <type>\r\nContent-Length: <n>\r\n` (or `Transfer-Encoding: chunked`), then every header set with
//! `httpd_resp_set_hdr` in call order as `Name: value\r\n`, then `\r\n` and the body. There is no `Connection` or `Date` header.

/// A response ready to be written to the socket.
#[derive(Clone, Copy, Debug)]
pub struct Response<'a> {
    /// The status text, e.g. `200 OK`.
    pub status: &'static str,
    /// `Content-Type`.
    pub content_type: &'static str,
    headers: [(&'static str, &'static str); 4],
    header_count: usize,
    body: Body<'a>,
    /// Close the connection after sending (the C returns `ESP_FAIL` from the handler).
    pub close: bool,
    /// Send nothing and close (`httpd_uri` returning `ESP_FAIL` without a response).
    pub silent: bool,
}

#[derive(Clone, Copy, Debug)]
enum Body<'a> {
    Sized(&'a [u8]),
    Sized2(&'a [u8], &'a [u8]),
    Chunked([&'a [u8]; 3]),
}

/// The error classes of `httpd_resp_send_err` the portal uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrCode {
    /// 400
    BadRequest,
    /// 403
    Forbidden,
    /// 404
    NotFound,
    /// 405
    MethodNotAllowed,
    /// 408
    Timeout,
    /// 414
    UriTooLong,
    /// 431
    HeadTooLarge,
    /// 500
    Internal,
    /// 505
    Version,
}

impl ErrCode {
    const fn status_and_default(self) -> (&'static str, &'static str) {
        match self {
            Self::BadRequest => ("400 Bad Request", "Bad request syntax"),
            Self::Forbidden => ("403 Forbidden", "Request forbidden -- authorization will not help"),
            Self::NotFound => ("404 Not Found", "Nothing matches the given URI"),
            Self::MethodNotAllowed => ("405 Method Not Allowed", "Specified method is invalid for this resource"),
            Self::Timeout => ("408 Request Timeout", "Server closed this connection"),
            Self::UriTooLong => ("414 URI Too Long", "URI is too long"),
            Self::HeadTooLarge => ("431 Request Header Fields Too Large", "Header fields are too long"),
            Self::Internal => ("500 Internal Server Error", "Server has encountered an unexpected error"),
            Self::Version => ("505 Version Not Supported", "HTTP version not supported by server"),
        }
    }
}

impl From<crate::http::HttpError> for ErrCode {
    fn from(e: crate::http::HttpError) -> Self {
        use crate::http::HttpError as H;
        match e {
            H::BadRequest => Self::BadRequest,
            H::Timeout => Self::Timeout,
            H::UriTooLong => Self::UriTooLong,
            H::HeadTooLarge => Self::HeadTooLarge,
            H::Version => Self::Version,
        }
    }
}

impl<'a> Response<'a> {
    /// A `200 OK` `text/html` response with a sized body (the defaults of a new request).
    #[must_use]
    pub const fn ok(body: &'a [u8]) -> Self {
        Self { status: "200 OK", content_type: "text/html", headers: [("", ""); 4], header_count: 0, body: Body::Sized(body), close: false, silent: false }
    }

    /// `httpd_resp_send_err(req, code, msg)` (`msg` `None`: the default text). Parse-level errors also close the connection.
    #[must_use]
    pub const fn error(code: ErrCode, msg: Option<&'static str>, close: bool) -> Response<'static> {
        let (status, default) = code.status_and_default();
        let text = match msg {
            Some(m) => m,
            None => default,
        };
        Response { status, content_type: "text/html", headers: [("", ""); 4], header_count: 0, body: Body::Sized(text.as_bytes()), close, silent: false }
    }

    /// Nothing is sent and the connection is closed.
    #[must_use]
    pub const fn silent_close() -> Response<'static> {
        Response { status: "", content_type: "", headers: [("", ""); 4], header_count: 0, body: Body::Sized(b""), close: true, silent: true }
    }

    /// A chunked body of three chunks (`httpd_resp_send_chunk` x3 then the terminating empty chunk).
    #[must_use]
    pub const fn chunked(parts: [&'a [u8]; 3]) -> Self {
        Self { status: "200 OK", content_type: "text/html", headers: [("", ""); 4], header_count: 0, body: Body::Chunked(parts), close: false, silent: false }
    }

    /// A `200 OK` response whose sized body is two slices (the USB page and the NUL of its text embed).
    #[must_use]
    pub const fn ok2(a: &'a [u8], b: &'a [u8]) -> Self {
        Self { status: "200 OK", content_type: "text/html", headers: [("", ""); 4], header_count: 0, body: Body::Sized2(a, b), close: false, silent: false }
    }

    /// `httpd_resp_set_status`.
    #[must_use]
    pub const fn status(mut self, status: &'static str) -> Self {
        self.status = status;
        self
    }

    /// `httpd_resp_set_type`.
    #[must_use]
    pub const fn content_type(mut self, t: &'static str) -> Self {
        self.content_type = t;
        self
    }

    /// `httpd_resp_set_hdr` (order is kept; at most four).
    #[must_use]
    pub const fn header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers[self.header_count] = (name, value);
        self.header_count += 1;
        self
    }

    /// The additional headers in order.
    #[must_use]
    pub fn headers(&self) -> &[(&'static str, &'static str)] {
        &self.headers[..self.header_count]
    }

    /// Write the whole response through `sink` (which returns false on a send failure; writing then stops and `false` is returned).
    pub fn write(&self, sink: &mut dyn FnMut(&[u8]) -> bool) -> bool {
        if self.silent {
            return true;
        }
        let mut num = [0u8; 20];
        let ok = |sink: &mut dyn FnMut(&[u8]) -> bool, b: &[u8]| sink(b);
        if !ok(sink, b"HTTP/1.1 ") || !ok(sink, self.status.as_bytes()) || !ok(sink, b"\r\nContent-Type: ") || !ok(sink, self.content_type.as_bytes()) {
            return false;
        }
        match self.body {
            Body::Sized(b) => {
                if !ok(sink, b"\r\nContent-Length: ") || !ok(sink, dec(b.len(), &mut num)) || !ok(sink, b"\r\n") {
                    return false;
                }
            }
            Body::Sized2(a, b) => {
                if !ok(sink, b"\r\nContent-Length: ") || !ok(sink, dec(a.len() + b.len(), &mut num)) || !ok(sink, b"\r\n") {
                    return false;
                }
            }
            Body::Chunked(_) => {
                if !ok(sink, b"\r\nTransfer-Encoding: chunked\r\n") {
                    return false;
                }
            }
        }
        for (n, v) in self.headers() {
            if !ok(sink, n.as_bytes()) || !ok(sink, b": ") || !ok(sink, v.as_bytes()) || !ok(sink, b"\r\n") {
                return false;
            }
        }
        if !ok(sink, b"\r\n") {
            return false;
        }
        match self.body {
            Body::Sized(b) => b.is_empty() || ok(sink, b),
            Body::Sized2(a, b) => ok(sink, a) && ok(sink, b),
            Body::Chunked(parts) => {
                for p in parts {
                    if !ok(sink, hex(p.len(), &mut num)) || !ok(sink, b"\r\n") || !ok(sink, p) || !ok(sink, b"\r\n") {
                        return false;
                    }
                }
                ok(sink, b"0\r\n") && ok(sink, b"\r\n")
            }
        }
    }

    /// Write into a buffer; returns the length, or `None` when it does not fit.
    #[must_use]
    pub fn write_into(&self, out: &mut [u8]) -> Option<usize> {
        let mut n = 0;
        let done = self.write(&mut |b| {
            if n + b.len() > out.len() {
                return false;
            }
            out[n..n + b.len()].copy_from_slice(b);
            n += b.len();
            true
        });
        done.then_some(n)
    }
}

fn dec(mut v: usize, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            return &buf[i..];
        }
    }
}

fn hex(mut v: usize, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b"0123456789abcdef"[v & 15];
        v >>= 4;
        if v == 0 {
            return &buf[i..];
        }
    }
}
