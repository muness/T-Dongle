//! The responder state machine. See the crate documentation.

use crate::directory::Directory;
use crate::wire::{self, NAME_MAX, ParseError, rd16, wr16};
use crate::{ANSWER_TTL, CACHE_ENTRIES, CACHE_NAME_MAX, CACHE_TTL_MS, PENDING, UPSTREAM_TIMEOUT_MS, USB_NET};
use tdongle_tailnet_types::Millis;

/// The asker: a host of the USB network and its UDP source port. Replies go back to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Client {
    /// IPv4 address.
    pub addr: u32,
    /// UDP port.
    pub port: u16,
}

/// What to do with a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send `out[..len]` back to the asker.
    Answer {
        /// Response length.
        len: usize,
    },
    /// Send `out[..len]` (the query with a rewritten ID) to `upstream`:53 from the upstream socket, which the runtime keeps `connect`ed to the
    /// resolver. `reset_socket` means the resolver changed since the last forward: close and reopen the upstream socket first (pending queries
    /// were already forgotten). If the send fails call [`Responder::forward_failed`] with `slot`.
    Forward {
        /// Upstream resolver address.
        upstream: u32,
        /// Datagram length.
        len: usize,
        /// Close and reopen the upstream socket before sending.
        reset_socket: bool,
        /// The pending-table slot that now tracks this query.
        slot: usize,
    },
    /// No reply (counted).
    Drop(DropReason),
}

/// Why a query got no reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// Shorter than a DNS header.
    TooShort,
    /// Not from the USB network.
    NotUsbHost,
    /// QDCOUNT is not 1.
    QuestionCount,
    /// The QR bit is set: a response, not a query.
    IsResponse,
    /// The question does not parse (bad or compressed label, name too long, truncated).
    BadQuestion(ParseError),
    /// The datagram does not fit the output buffer.
    TooLarge,
    /// An ordinary name, but the Wi-Fi has no resolver (yet).
    NoUpstream,
}

/// A reply to hand to the asker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Who asked.
    pub client: Client,
    /// Length of the response in the buffer given to [`Responder::handle_upstream`].
    pub len: usize,
}

macro_rules! stat_enum {
    ($($(#[$d:meta])* $v:ident = $n:literal),+ $(,)?) => {
        /// A counter (the C's `dns_stats[]`, same order; `MaxLookupTicks` is runtime-measured and never moved here).
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u8)]
        pub enum Stat { $($(#[$d])* $v),+ }
        impl Stat {
            /// Number of counters (11).
            pub const COUNT: usize = [$(Stat::$v),+].len();
            /// Printed name.
            pub const fn name(self) -> &'static str { match self { $(Stat::$v => $n),+ } }
        }
    };
}
stat_enum! {
    /// Tailnet queries answered.
    Queries = "queries",
    /// Resolved from the answer cache.
    CacheHits = "cache_hits",
    /// The directory was busy (membership lock not taken).
    LockFailures = "lock_failures",
    /// SERVFAIL for a name inside a tailnet domain.
    Temporary = "temporary",
    /// NXDOMAIN for an `A` query inside a tailnet domain.
    Absent = "absent",
    /// SERVFAIL because four forwards are already in flight.
    UpstreamBusy = "upstream_busy",
    /// Longest local lookup in ticks (the runtime records it; never moved by this crate).
    MaxLookupTicks = "max_lookup_ticks",
    /// Queries forwarded upstream.
    Forwarded = "forwarded",
    /// Upstream replies relayed to the asker.
    Relayed = "relayed",
    /// Forwarded queries that timed out.
    Timeouts = "timeouts",
    /// Most forwards in flight at once.
    MaxPending = "max_pending",
}

/// The counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    c: [u32; Stat::COUNT],
    /// Queries dropped without a reply, per [`DropReason`] class: too short, not USB, question count, response, bad question, too large, no upstream.
    pub dropped: [u32; 7],
}

impl Stats {
    /// Value of a counter.
    pub fn get(&self, s: Stat) -> u32 {
        self.c[s as usize]
    }
    fn bump(&mut self, s: Stat) {
        self.c[s as usize] = self.c[s as usize].saturating_add(1);
    }
    /// Raise a high-water counter.
    pub fn raise(&mut self, s: Stat, v: u32) {
        if v > self.c[s as usize] {
            self.c[s as usize] = v;
        }
    }
}

#[derive(Clone, Copy)]
struct CacheEntry {
    name: [u8; CACHE_NAME_MAX],
    name_len: u8,
    member: u32,
    generation: u32,
    alias: u32,
    used: u32,
    expires: Millis,
}

#[derive(Clone, Copy)]
struct Pending {
    active: bool,
    client: Client,
    original_id: u16,
    wire_id: u16,
    hash: u32,
    started: Millis,
}

/// Which form a name takes for a membership.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    None,
    Qualified,
    Magic,
}

#[derive(Default)]
struct Match {
    matches: u32,
    temporary: bool,
    member: u32,
    generation: u32,
    alias: u32,
}

/// The DNS responder/forwarder state: a four-entry answer cache, four pending forwards, the ID counter and the upstream in use.
pub struct Responder {
    cache: [CacheEntry; CACHE_ENTRIES],
    clock: u32,
    pending: [Pending; PENDING],
    next_id: u16,
    upstream: Option<u32>,
    stats: Stats,
}

impl core::fmt::Debug for Responder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Responder").field("pending", &self.pending_count()).field("upstream", &self.upstream).finish()
    }
}

impl Default for Responder {
    fn default() -> Self {
        Self::new()
    }
}

fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// True when `name` ends with `.tailnet` (ASCII case-insensitive), as the C's `len >= 8 && !strcasecmp(name + len - 8, ".tailnet")`.
fn is_qualified(name: &[u8]) -> bool {
    name.len() >= 8 && eq_ci(&name[name.len() - 8..], b".tailnet")
}

/// The MagicDNS domain of a membership: its published name without the first label and the trailing dot; empty when it has none.
pub fn domain_of(self_name: &str) -> &str {
    let mut s = self_name.as_bytes();
    if let [rest @ .., b'.'] = s {
        s = rest;
    }
    let Some(dot) = s.iter().position(|&c| c == b'.') else { return "" };
    if dot == 0 || dot + 1 >= s.len() {
        return "";
    }
    // s is a prefix of a &str cut at ASCII bytes: still valid UTF-8
    core::str::from_utf8(&s[dot + 1..]).unwrap_or("")
}

/// `name` is `<label>.<suffix>` with at least one label before the suffix (case-insensitive).
fn in_domain(name: &[u8], suffix: &str) -> bool {
    let (n, len) = (suffix.len(), name.len());
    n > 0 && len > n + 1 && name[len - n - 1] == b'.' && eq_ci(&name[len - n..], suffix.as_bytes())
}

fn name_form(label: &str, self_dns_name: &str, name: &[u8]) -> Form {
    let (l, len) = (label.len(), name.len());
    if len > l + 9 && name[len - l - 9] == b'.' && eq_ci(&name[len - l - 8..len - 8], label.as_bytes()) && eq_ci(&name[len - 8..], b".tailnet") {
        return Form::Qualified;
    }
    if in_domain(name, domain_of(self_dns_name)) {
        return Form::Magic;
    }
    Form::None
}

impl Responder {
    /// Bytes of one responder.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// A responder with an empty cache and nothing in flight.
    pub const fn new() -> Self {
        let e = CacheEntry { name: [0; CACHE_NAME_MAX], name_len: 0, member: 0, generation: 0, alias: 0, used: 0, expires: 0 };
        let p = Pending { active: false, client: Client { addr: 0, port: 0 }, original_id: 0, wire_id: 0, hash: 0, started: 0 };
        Self { cache: [e; CACHE_ENTRIES], clock: 0, pending: [p; PENDING], next_id: 0, upstream: None, stats: Stats { c: [0; Stat::COUNT], dropped: [0; 7] } }
    }
    /// Counters.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
    /// Forwards in flight.
    pub fn pending_count(&self) -> usize {
        self.pending.iter().filter(|p| p.active).count()
    }

    fn drop_query(&mut self, r: DropReason) -> Action {
        let i = match r {
            DropReason::TooShort => 0,
            DropReason::NotUsbHost => 1,
            DropReason::QuestionCount => 2,
            DropReason::IsResponse => 3,
            DropReason::BadQuestion(_) => 4,
            DropReason::TooLarge => 5,
            DropReason::NoUpstream => 6,
        };
        self.stats.dropped[i] = self.stats.dropped[i].saturating_add(1);
        Action::Drop(r)
    }

    /// Handle one datagram from the USB network. `q` is the datagram, `from` its sender, `upstream` the Wi-Fi resolver (`None` or 0 when
    /// there is none) and `out` the buffer the answer or the forwarded datagram is built in (the runtime's 1500-byte packet buffer: it must
    /// hold the query; an answer needs 16 more bytes, without them it is sent without the answer section, as the C).
    pub fn handle_query<D: Directory + ?Sized>(&mut self, q: &[u8], from: Client, now: Millis, dir: &D, upstream: Option<u32>, out: &mut [u8]) -> Action {
        let n = q.len();
        if n < wire::HEADER {
            return self.drop_query(DropReason::TooShort);
        }
        if from.addr & 0xffff_ff00 != USB_NET {
            return self.drop_query(DropReason::NotUsbHost);
        }
        if rd16(q, 4) != 1 {
            return self.drop_query(DropReason::QuestionCount);
        }
        if q[2] & 0x80 != 0 {
            return self.drop_query(DropReason::IsResponse);
        }
        if n > out.len() {
            return self.drop_query(DropReason::TooLarge);
        }
        let mut name_buf = [0u8; NAME_MAX];
        let question = match wire::parse_question(q, &mut name_buf) {
            Ok(x) => x,
            Err(e) => return self.drop_query(DropReason::BadQuestion(e)),
        };
        let name = &name_buf[..question.name_len];
        out[..n].copy_from_slice(q);

        // Is the name ours? The qualified form needs no directory; a MagicDNS name counts the memberships whose domain contains it.
        let qualified = is_qualified(name);
        let claims = if qualified { 0 } else { self.magic_claims(dir, name) };
        let tailnet = qualified || claims != 0;
        if !tailnet {
            return self.forward(q, from, now, upstream, question.end, out);
        }
        let lookup = question.qtype == 1 && question.qclass == 1;
        let mut alias = 0u32;
        let mut temporary = false;
        if lookup {
            if dir.busy() {
                temporary = true;
                self.stats.bump(Stat::LockFailures);
            } else {
                (alias, temporary) = self.resolve(dir, name, claims, now);
            }
        }
        self.stats.bump(Stat::Queries);
        if temporary {
            self.stats.bump(Stat::Temporary);
        } else if alias == 0 && question.qtype == 1 {
            self.stats.bump(Stat::Absent);
        }
        let mut pos = question.end;
        out[2] = 0x81;
        // AAAA (any non-A type) for an existing or absent name is NODATA, not NXDOMAIN.
        out[3] = if alias != 0 {
            0x80
        } else if temporary {
            0x82
        } else if question.qtype != 1 {
            0x80
        } else {
            0x83
        };
        wr16(out, 6, u16::from(alias != 0));
        wr16(out, 8, 0);
        wr16(out, 10, 0);
        if alias != 0 && pos + 16 <= out.len() {
            let a = alias.to_be_bytes();
            let answer = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, (ANSWER_TTL >> 8) as u8, ANSWER_TTL as u8, 0, 4, a[0], a[1], a[2], a[3]];
            out[pos..pos + 16].copy_from_slice(&answer);
            pos += 16;
        }
        Action::Answer { len: pos }
    }

    fn magic_claims<D: Directory + ?Sized>(&self, dir: &D, name: &[u8]) -> u32 {
        let mut claims = 0;
        for i in 0..dir.member_count() {
            if let Some(m) = dir.member(i) {
                claims += u32::from(name_form(m.label, m.self_dns_name, name) == Form::Magic);
            }
        }
        claims
    }

    /// Resolve a tailnet name to its alias: `(alias or 0, temporary)`. A MagicDNS domain claimed by two memberships is ambiguous even when only
    /// one has the peer.
    fn resolve<D: Directory + ?Sized>(&mut self, dir: &D, name: &[u8], claims: u32, now: Millis) -> (u32, bool) {
        if claims > 1 {
            return (0, false);
        }
        let mut r = Match::default();
        for i in 0..dir.member_count() {
            let Some(m) = dir.member(i) else { continue };
            let form = name_form(m.label, m.self_dns_name, name);
            if form != Form::None {
                self.match_member(dir, i, form, name, now, &mut r);
            }
        }
        if r.matches != 1 || r.temporary {
            return (0, r.temporary);
        }
        if r.member != 0 {
            self.cache_store(name, &r, now);
        }
        (r.alias, false)
    }

    fn match_member<D: Directory + ?Sized>(&mut self, dir: &D, index: usize, form: Form, name: &[u8], now: Millis, r: &mut Match) {
        let Some(m) = dir.member(index) else { return };
        if !m.connected || !m.session_valid {
            r.temporary = true;
            return;
        }
        let generation = m.generation;
        for c in 0..CACHE_ENTRIES {
            let e = &self.cache[c];
            if e.alias != 0 && e.member == m.id && e.generation == generation && e.expires > now && eq_ci(&e.name[..usize::from(e.name_len)], name) {
                r.alias = e.alias;
                self.clock = self.clock.wrapping_add(1);
                self.cache[c].used = self.clock;
                r.matches += 1;
                self.stats.bump(Stat::CacheHits);
                return;
            }
        }
        let suffix = if form == Form::Magic { domain_of(m.self_dns_name) } else { "" };
        for j in 0..m.peer_count {
            let Some(p) = dir.peer(index, j) else {
                r.temporary = true;
                continue;
            };
            // the C copies the hostname into a 64-byte buffer
            let host = &p.hostname.as_bytes()[..p.hostname.len().min(63)];
            let dot = host.iter().position(|&c| c == b'.');
            let mut buf = [0u8; 128];
            let cand: Option<usize> = match (form, dot) {
                (Form::Qualified, _) => {
                    let first = &host[..dot.unwrap_or(host.len())];
                    join(&mut buf, &[first, b".", m.label.as_bytes(), b".tailnet"])
                }
                (_, Some(_)) => join(&mut buf, &[host]), // the directory stores the full MagicDNS name
                (_, None) => join(&mut buf, &[host, b".", suffix.as_bytes()]), // peers restored from the NVS cache keep only their first label
            };
            // the C's buffer is 128 bytes with a terminator: a candidate of 128 or more bytes never matches
            let Some(l) = cand else { continue };
            if !eq_ci(name, &buf[..l]) || p.vpn_ip == 0 {
                continue;
            }
            r.matches += 1;
            match dir.alias(m.id, p.vpn_ip) {
                Some(a) if a != 0 => {
                    r.alias = a;
                    r.member = m.id;
                    r.generation = generation;
                }
                _ => r.temporary = true,
            }
        }
        if generation != dir.generation(index) {
            r.temporary = true;
        }
    }

    fn cache_store(&mut self, name: &[u8], r: &Match, now: Millis) {
        let mut victim = 0;
        for c in 0..CACHE_ENTRIES {
            if self.cache[c].alias == 0 || self.cache[c].used < self.cache[victim].used {
                victim = c;
            }
        }
        if name.len() > CACHE_NAME_MAX {
            return;
        }
        self.clock = self.clock.wrapping_add(1);
        let e = &mut self.cache[victim];
        e.name[..name.len()].copy_from_slice(name);
        e.name_len = name.len() as u8;
        e.member = r.member;
        e.generation = r.generation;
        e.alias = r.alias;
        e.used = self.clock;
        e.expires = now + CACHE_TTL_MS;
    }

    fn forward(&mut self, q: &[u8], from: Client, now: Millis, upstream: Option<u32>, qend: usize, out: &mut [u8]) -> Action {
        let n = q.len();
        let Some(resolver) = upstream.filter(|&a| a != 0) else { return self.drop_query(DropReason::NoUpstream) };
        let Some(slot) = self.pending.iter().position(|p| !p.active) else {
            // four in flight: answer SERVFAIL at once
            self.stats.bump(Stat::UpstreamBusy);
            out[2] = 0x81;
            out[3] = 0x82;
            wr16(out, 6, 0);
            wr16(out, 8, 0);
            wr16(out, 10, 0);
            return Action::Answer { len: qend };
        };
        let mut reset = false;
        if self.upstream.is_some_and(|u| u != resolver) {
            for p in self.pending.iter_mut() {
                p.active = false;
            }
            reset = true;
        }
        // the slot may have been the only free one before the reset; either way it is free now
        self.upstream = Some(resolver);
        let original = rd16(q, 0);
        self.next_id = self.next_id.wrapping_add(1);
        let mut wire_id = self.next_id;
        // at most four IDs coexist; skip any live ID after the 16-bit wrap
        let mut i = 0;
        while i < PENDING {
            if self.pending[i].active && self.pending[i].wire_id == wire_id {
                self.next_id = self.next_id.wrapping_add(1);
                wire_id = self.next_id;
                i = 0;
            } else {
                i += 1;
            }
        }
        let hash = wire::question_hash(q);
        wr16(out, 0, wire_id);
        self.pending[slot] = Pending { active: true, client: from, original_id: original, wire_id, hash, started: now };
        self.stats.bump(Stat::Forwarded);
        let count = self.pending_count() as u32;
        self.stats.raise(Stat::MaxPending, count);
        Action::Forward { upstream: resolver, len: n, reset_socket: reset, slot }
    }

    /// The send of a [`Action::Forward`] failed: forget it (nothing was sent, no reply will come).
    pub fn forward_failed(&mut self, slot: usize) {
        if let Some(p) = self.pending.get_mut(slot) {
            p.active = false;
        }
    }

    /// Handle a datagram received on the upstream socket (the runtime drains at most [`crate::UPSTREAM_DRAIN`] per poll). A response whose rewritten
    /// ID and question hash match a pending forward gets its original ID restored in place and comes back as the [`Reply`] to send; anything
    /// else (too short, not a response, unknown ID, different question) is ignored.
    pub fn handle_upstream(&mut self, resp: &mut [u8]) -> Option<Reply> {
        if resp.len() < wire::HEADER || resp[2] & 0x80 == 0 {
            return None;
        }
        let hash = wire::question_hash(resp);
        let id = rd16(resp, 0);
        let p = self.pending.iter_mut().find(|p| p.active && p.wire_id == id && p.hash == hash)?;
        wr16(resp, 0, p.original_id);
        let client = p.client;
        p.active = false;
        self.stats.bump(Stat::Relayed);
        Some(Reply { client, len: resp.len() })
    }

    /// Time out forwards older than 2 s. Returns `true` when nothing is pending any more: the runtime may close the upstream socket (it is
    /// reopened by the next forward).
    pub fn expire(&mut self, now: Millis) -> bool {
        let mut any = false;
        for i in 0..PENDING {
            if self.pending[i].active && now.saturating_sub(self.pending[i].started) >= UPSTREAM_TIMEOUT_MS {
                self.pending[i].active = false;
                self.stats.bump(Stat::Timeouts);
            }
            any |= self.pending[i].active;
        }
        !any
    }

    /// The runtime closed the upstream socket (idle or error): forget the resolver binding and any pending forwards.
    pub fn upstream_closed(&mut self) {
        self.upstream = None;
        for p in self.pending.iter_mut() {
            p.active = false;
        }
    }

    /// Earliest time [`Self::expire`] has work to do, if anything is pending.
    pub fn next_deadline(&self) -> Option<Millis> {
        self.pending.iter().filter(|p| p.active).map(|p| p.started + UPSTREAM_TIMEOUT_MS).min()
    }
}

/// Concatenate `parts` into `buf` leaving room for a terminator (the C's `snprintf` into 128 bytes fails at 128 or more). `None` when it does
/// not fit.
fn join(buf: &mut [u8; 128], parts: &[&[u8]]) -> Option<usize> {
    let mut n = 0;
    for p in parts {
        if n + p.len() >= buf.len() {
            return None;
        }
        buf[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    Some(n)
}
