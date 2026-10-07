//! Resolver resilience. A home network's DHCP-provided resolvers can drop one client's queries for minutes (a NextDNS linked-IP rule, a rate limit), and the gateway needs
//! names for its clock (SNTP) and its control and relay dials before anything else works. The candidates are tried in this order after the one that answered last: the DHCP
//! servers, the DHCP gateway (home routers usually run DNS), then 1.1.1.1, 8.8.8.8 and 9.9.9.9. Per-query timeouts are short ([`QUERY_MS`]), one resend each.
//!
//! The state is atomics in one static, so the firmware's status line and the DNS forwarder's task read the same facts as the dial path.

use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

/// Candidate slots: three DHCP servers, the gateway, three public resolvers.
pub const SLOTS: usize = 7;
const DYNAMIC: usize = 4;
/// How long one query waits for its answer before the next candidate is tried (one resend at half of it).
pub const QUERY_MS: u64 = 2000;
/// The well-known public resolvers at the end of the list.
pub const PUBLIC: [u32; 3] = [u32::from_be_bytes([1, 1, 1, 1]), u32::from_be_bytes([8, 8, 8, 8]), u32::from_be_bytes([9, 9, 9, 9])];

/// The candidate resolvers and what each did.
#[derive(Debug)]
pub struct Resolvers {
    addr: [AtomicU32; SLOTS],
    ok: [AtomicU32; SLOTS],
    fail: [AtomicU32; SLOTS],
    /// Slot that answered last (`SLOTS` = none yet).
    last_ok: AtomicU32,
    /// The forwarder's current upstream (0: the engine's choice stands) and when its oldest unanswered query went out (0: none outstanding).
    fwd_upstream: AtomicU32,
    fwd_since_ms: AtomicU32,
}

/// The image's one set.
pub static RESOLVERS: Resolvers = Resolvers::new();

impl Resolvers {
    /// Public resolvers filled in, the rest empty.
    pub const fn new() -> Self {
        let mut addr = [const { AtomicU32::new(0) }; SLOTS];
        addr[4] = AtomicU32::new(PUBLIC[0]);
        addr[5] = AtomicU32::new(PUBLIC[1]);
        addr[6] = AtomicU32::new(PUBLIC[2]);
        Resolvers {
            addr,
            ok: [const { AtomicU32::new(0) }; SLOTS],
            fail: [const { AtomicU32::new(0) }; SLOTS],
            last_ok: AtomicU32::new(SLOTS as u32),
            fwd_upstream: AtomicU32::new(0),
            fwd_since_ms: AtomicU32::new(0),
        }
    }

    /// Forget the network-derived candidates (a new association): the public ones and the history stay.
    pub fn new_network(&self) {
        for a in &self.addr[..DYNAMIC] {
            a.store(0, Relaxed);
        }
        if self.last_ok.load(Relaxed) < DYNAMIC as u32 {
            self.last_ok.store(SLOTS as u32, Relaxed);
        }
        self.fwd_upstream.store(0, Relaxed);
        self.fwd_since_ms.store(0, Relaxed);
    }

    /// Add a network-derived resolver (a DHCP server, or the gateway with `gateway`) unless it is already a candidate. Returns false if there was no room.
    pub fn add(&self, ip: u32, gateway: bool) -> bool {
        if ip == 0 || self.addr.iter().any(|a| a.load(Relaxed) == ip) {
            return true;
        }
        let range = if gateway { DYNAMIC - 1..DYNAMIC } else { 0..DYNAMIC - 1 };
        for i in range {
            if self.addr[i].load(Relaxed) == 0 {
                self.addr[i].store(ip, Relaxed);
                return true;
            }
        }
        false
    }

    /// The candidates in the order to try them: the one that answered last, then the rest in list order. `out` gets up to [`SLOTS`] addresses; returns how many.
    pub fn order(&self, out: &mut [u32; SLOTS]) -> usize {
        let first = self.last_ok.load(Relaxed) as usize;
        let mut n = 0;
        if first < SLOTS && self.addr[first].load(Relaxed) != 0 {
            out[n] = self.addr[first].load(Relaxed);
            n += 1;
        }
        for i in 0..SLOTS {
            let a = self.addr[i].load(Relaxed);
            if a != 0 && i != first {
                out[n] = a;
                n += 1;
            }
        }
        n
    }

    fn slot(&self, ip: u32) -> Option<usize> {
        self.addr.iter().position(|a| a.load(Relaxed) == ip)
    }

    /// `ip` answered.
    pub fn note_ok(&self, ip: u32) {
        if let Some(i) = self.slot(ip) {
            self.ok[i].fetch_add(1, Relaxed);
            self.last_ok.store(i as u32, Relaxed);
        }
    }

    /// `ip` did not answer in time.
    pub fn note_fail(&self, ip: u32) {
        if let Some(i) = self.slot(ip) {
            self.fail[i].fetch_add(1, Relaxed);
        }
    }

    /// The upstream the DNS forwarder should use for its next query: the engine's choice (`requested`, the DHCP server) until a candidate has answered or the current one has been
    /// silent for [`QUERY_MS`] while queries went out, then the next candidate. `now` is the millisecond clock.
    pub fn forward_target(&self, requested: u32, now: u32) -> u32 {
        let mut cur = self.fwd_upstream.load(Relaxed);
        if cur == 0 {
            cur = requested;
        }
        let since = self.fwd_since_ms.load(Relaxed);
        if since != 0 && now.wrapping_sub(since) >= QUERY_MS as u32 {
            // a query has gone unanswered for a whole timeout: the current upstream is dropping this client's queries
            self.note_fail(cur);
            let mut o = [0u32; SLOTS];
            let n = self.order(&mut o);
            let next = (0..n).position(|i| o[i] == cur).map_or(0, |i| (i + 1) % n.max(1));
            if n != 0 {
                cur = o[next];
            }
            self.fwd_since_ms.store(0, Relaxed);
        }
        self.fwd_upstream.store(cur, Relaxed);
        if self.fwd_since_ms.load(Relaxed) == 0 {
            self.fwd_since_ms.store(now.max(1), Relaxed);
        }
        cur
    }

    /// A reply came from `ip` for the forwarder.
    pub fn forward_reply(&self, ip: u32) {
        self.note_ok(ip);
        self.fwd_since_ms.store(0, Relaxed);
        self.fwd_upstream.store(ip, Relaxed);
    }

    /// For the status line: `(address, ok, fail)` of each filled slot and the slot that answered last.
    pub fn snapshot(&self, mut f: impl FnMut(usize, u32, u32, u32, bool)) {
        let last = self.last_ok.load(Relaxed) as usize;
        for i in 0..SLOTS {
            let a = self.addr[i].load(Relaxed);
            if a != 0 {
                f(i, a, self.ok[i].load(Relaxed), self.fail[i].load(Relaxed), i == last);
            }
        }
    }

    /// The forwarder's current upstream (0 when the engine's choice stands).
    pub fn forwarder(&self) -> u32 {
        self.fwd_upstream.load(Relaxed)
    }
}

impl Default for Resolvers {
    fn default() -> Self {
        Self::new()
    }
}

/// An A query for `name` with transaction `id`: `out[..n]`. `None` for a name that does not fit or has an empty or over-long label.
pub fn build_query(id: u16, name: &str, out: &mut [u8; 272]) -> Option<usize> {
    out[..12].fill(0);
    out[0..2].copy_from_slice(&id.to_be_bytes());
    out[2] = 0x01; // recursion desired
    out[5] = 1; // one question
    let mut n = 12;
    for label in name.trim_end_matches('.').split('.') {
        let l = label.len();
        if l == 0 || l > 63 || n + 1 + l + 5 > out.len() {
            return None;
        }
        out[n] = l as u8;
        out[n + 1..n + 1 + l].copy_from_slice(label.as_bytes());
        n += 1 + l;
    }
    out[n] = 0;
    out[n + 1..n + 5].copy_from_slice(&[0, 1, 0, 1]); // A, IN
    Some(n + 5)
}

fn skip_name(m: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *m.get(i)?;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xc0 == 0xc0 {
            return Some(i + 2);
        }
        i += 1 + usize::from(l);
    }
}

/// The first A record of an answer to a query with transaction `id`, `None` for anything else (another id, an error code, no address).
pub fn parse_answer(id: u16, m: &[u8]) -> Option<[u8; 4]> {
    if m.len() < 12 || u16::from_be_bytes([m[0], m[1]]) != id || m[2] & 0x80 == 0 || m[3] & 0x0f != 0 {
        return None;
    }
    let (qd, an) = (u16::from_be_bytes([m[4], m[5]]), u16::from_be_bytes([m[6], m[7]]));
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(m, i)? + 4;
    }
    for _ in 0..an {
        i = skip_name(m, i)?;
        let h = m.get(i..i + 10)?;
        let (ty, rdlen) = (u16::from_be_bytes([h[0], h[1]]), usize::from(u16::from_be_bytes([h[8], h[9]])));
        i += 10;
        if ty == 1 && rdlen == 4 {
            let r = m.get(i..i + 4)?;
            return Some([r[0], r[1], r[2], r[3]]);
        }
        i += rdlen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_starts_with_the_last_answerer_and_covers_everything_once() {
        let r = Resolvers::new();
        assert!(r.add(0xc0a8_0101, true));
        assert!(r.add(0x2d5a_1c9f, false));
        assert!(r.add(0x2d5a_1c9f, false), "a duplicate is not a second candidate");
        let mut o = [0; SLOTS];
        assert_eq!(r.order(&mut o), 5);
        assert_eq!(o[..2], [0x2d5a_1c9f, 0xc0a8_0101], "DHCP server, then the gateway");
        assert_eq!(o[2..5], PUBLIC);
        r.note_ok(PUBLIC[1]);
        assert_eq!(r.order(&mut o), 5);
        assert_eq!(o[0], PUBLIC[1], "the one that answered goes first");
        let mut all = o[..5].to_vec();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn a_silent_forwarder_upstream_rotates_after_a_timeout_and_a_reply_pins_it() {
        let r = Resolvers::new();
        r.add(0x2d5a_1c9f, false);
        r.add(0xc0a8_0101, true);
        let dhcp = 0x2d5a_1c9f;
        assert_eq!(r.forward_target(dhcp, 1000), dhcp);
        assert_eq!(r.forward_target(dhcp, 2000), dhcp, "not a whole timeout yet");
        assert_eq!(r.forward_target(dhcp, 3500), 0xc0a8_0101, "silent for 2 s: the gateway");
        r.forward_reply(0xc0a8_0101);
        assert_eq!(r.forward_target(dhcp, 9000), 0xc0a8_0101, "the one that answered stays");
        let mut seen = 0;
        r.snapshot(|_, _, ok, fail, _| seen += ok + fail);
        assert_eq!(seen, 2);
    }

    #[test]
    fn query_and_answer_round_trip_with_compression_and_a_cname() {
        let mut q = [0u8; 272];
        let n = build_query(0xbeef, "pool.ntp.org", &mut q).unwrap();
        assert_eq!(&q[12..n], b"\x04pool\x03ntp\x03org\x00\x00\x01\x00\x01");
        let mut a = q[..n].to_vec();
        a[2] = 0x81;
        a[3] = 0x80;
        a[7] = 2;
        a.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c]); // a CNAME first
        a.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
        assert_eq!(parse_answer(0xbeef, &a), Some([203, 0, 113, 9]));
        assert_eq!(parse_answer(0xbef0, &a), None, "another id");
        a[3] = 0x83; // NXDOMAIN
        assert_eq!(parse_answer(0xbeef, &a), None);
        assert!(build_query(1, "a..b", &mut q).is_none());
    }
}
