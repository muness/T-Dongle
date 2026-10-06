//! The pure rules the C applies while it takes the snapshot for `/status`, so the glue does not re-derive them: the peer page and its query, the
//! `routing_ready` conjunction, which error text a membership reports, and which stack readings are known.

/// `CONFIG_ML_MAX_PEERS` (sdkconfig.defaults): peers listed per membership per page.
pub const ML_MAX_PEERS: usize = 8;
/// `if (peer_offset > 100000) peer_offset = 0`.
pub const MAX_PEER_OFFSET: u32 = 100_000;
/// The query buffer of the handler (`char query[64]`): a longer query string is not read at all.
pub const QUERY_BUFFER: usize = 64;
/// The value buffer for a query value (`char offset_text[16]`): a longer value is ignored.
pub const VALUE_BUFFER: usize = 16;

/// `?peer_offset=N&peer_member=ID`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerQuery {
    /// Where the page of `peer_member` starts (already 0 if above [`MAX_PEER_OFFSET`]).
    pub offset: u32,
    /// The membership the offset applies to (0: none; ids start at 1).
    pub member: u32,
}

/// `httpd_query_key_value`: the value of `key` in `query` (keys compare ignoring case), or None when absent or when the value does not fit `capacity`
/// bytes with its NUL (ESP_ERR_HTTPD_RESULT_TRUNC).
pub fn query_value<'a>(query: &'a [u8], key: &str, capacity: usize) -> Option<&'a [u8]> {
    let query = &query[..query.iter().position(|&b| b == 0).unwrap_or(query.len())];
    let mut rest = query;
    while !rest.is_empty() {
        let eq = rest.iter().position(|&b| b == b'=')?;
        let name = &rest[..eq];
        let after = &rest[eq + 1..];
        let end = after.iter().position(|&b| b == b'&').unwrap_or(after.len());
        if name.len() == key.len() && name.eq_ignore_ascii_case(key.as_bytes()) {
            let value = &after[..end];
            return if value.len() < capacity { Some(value) } else { None };
        }
        // The next pair starts after the '&' that follows this '='.
        let amp = after.iter().position(|&b| b == b'&')?;
        rest = &after[amp + 1..];
    }
    None
}

/// `strtoul(text, NULL, 10)` on a 32-bit `unsigned long` (the ESP32-S3), assigned to an `unsigned`.
pub fn strtoul10(text: &[u8]) -> u32 {
    let text = &text[..text.iter().position(|&b| b == 0).unwrap_or(text.len())];
    let mut i = 0;
    while i < text.len() && matches!(text[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut negative = false;
    if i < text.len() && (text[i] == b'+' || text[i] == b'-') {
        negative = text[i] == b'-';
        i += 1;
    }
    let mut value: u64 = 0;
    let mut overflow = false;
    while i < text.len() && text[i].is_ascii_digit() {
        value = value * 10 + u64::from(text[i] - b'0');
        if value > u64::from(u32::MAX) {
            overflow = true;
            value = u64::from(u32::MAX);
        }
        i += 1;
    }
    if overflow {
        u32::MAX
    } else if negative {
        (value as u32).wrapping_neg()
    } else {
        value as u32
    }
}

impl PeerQuery {
    /// What `status()` reads from the request: `query` is the URL's query string if the request has one (None: no query).
    pub fn parse(query: Option<&[u8]>) -> PeerQuery {
        // httpd_req_get_url_query_str fails (and leaves the buffer zeroed) when the query does not fit 64 bytes with its NUL.
        let q: &[u8] = match query {
            Some(q) if q.len() < QUERY_BUFFER => q,
            _ => &[],
        };
        let mut r = PeerQuery::default();
        if let Some(v) = query_value(q, "peer_offset", VALUE_BUFFER) {
            r.offset = strtoul10(v);
        }
        if let Some(v) = query_value(q, "peer_member", VALUE_BUFFER) {
            r.member = strtoul10(v);
        }
        if r.offset > MAX_PEER_OFFSET {
            r.offset = 0;
        }
        r
    }

    /// `v->page_start = peer_member == m->id ? peer_offset : 0`.
    pub fn page_start(&self, member_id: u32) -> u32 {
        if self.member == member_id { self.offset } else { 0 }
    }
}

/// Collect one page of the peer directory: walk `start..count`, call `at(i)` (true when record `i` was read and its peer appended by the caller),
/// stop at `max` peers. Returns (peers collected, `next_peer_offset`): the offset after the last record taken, or `start` when none was.
pub fn fill_page(count: u32, start: u32, max: usize, mut at: impl FnMut(u32) -> bool) -> (usize, u32) {
    let (mut peers, mut next) = (0usize, start);
    let mut i = start;
    while i < count && peers < max {
        if at(i) {
            peers += 1;
            next = i + 1;
        }
        i += 1;
    }
    (peers, next)
}

/// `routing_ready`: the membership is enabled, has a WireGuard netif, is connected (`ML_STATE_CONNECTED`), its key is not expired, it has no protocol error and its
/// directory session is valid. False without a client.
pub fn routing_ready(enabled: bool, wg_netif: bool, connected: bool, key_expired: bool, last_error_empty: bool, session_valid: bool) -> bool {
    enabled && wg_netif && connected && !key_expired && last_error_empty && session_valid
}

/// `protocol_error`: `last_error` if it is not empty, else `transport_error`.
pub fn protocol_error<'a>(last_error: &'a [u8], transport_error: &'a [u8]) -> &'a [u8] {
    if last_error.first().is_some_and(|&b| b != 0) { last_error } else { transport_error }
}

/// The five `stack_free_bytes` readings: `net_io`, `derp_tx` and `wg_mgr` are the shared tasks (known only while the client is attached to the shared runtime and not
/// stopping), `derp_rx` no longer exists (always unknown), `coord` is the client's own task. Unknown is `u32::MAX` (printed null). `values` are the high-water marks in
/// the same order.
pub fn stack_free(rt_attached: bool, stop_incomplete: bool, has_coord_task: bool, values: [u32; 5]) -> [u32; 5] {
    let known = !stop_incomplete;
    let mut out = [u32::MAX; 5];
    if known && rt_attached {
        out[0] = values[0];
        out[1] = values[1];
        out[4] = values[4];
    }
    if known && has_coord_task {
        out[3] = values[3];
    }
    out
}
