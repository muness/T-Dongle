//! Port of tests/test_dns.c: the responder against a mock directory, with the same names, outcomes and counters.
#![allow(clippy::type_complexity, clippy::too_many_arguments, clippy::assertions_on_constants)]
use std::cell::Cell;
use tdongle_tailnet_dns::*;

const HOST: Client = Client { addr: 0xc0a8_4d02, port: 1000 };
const UP: u32 = 0x0808_0808;

struct Mem {
    id: u32,
    label: String,
    self_name: String,
    connected: bool,
    session_valid: bool,
    generation: Cell<u32>,
    peers: Vec<String>,
}
struct Dir {
    members: Vec<Mem>,
    busy: bool,
    peers_ok: Cell<bool>,
    change_generation: Cell<bool>,
    reads: Cell<u32>,
    alias_calls: Cell<u32>,
    alias_ok: bool,
}
impl Dir {
    fn new() -> Self {
        Dir {
            members: vec![],
            busy: false,
            peers_ok: Cell::new(true),
            change_generation: Cell::new(false),
            reads: Cell::new(0),
            alias_calls: Cell::new(0),
            alias_ok: true,
        }
    }
    fn member(id: u32, label: &str, self_name: &str, peers: &[&str]) -> Mem {
        Mem {
            id,
            label: label.into(),
            self_name: self_name.into(),
            connected: true,
            session_valid: true,
            generation: Cell::new(0),
            peers: peers.iter().map(|s| s.to_string()).collect(),
        }
    }
}
impl Directory for Dir {
    fn member_count(&self) -> usize {
        self.members.len()
    }
    fn member(&self, i: usize) -> Option<MemberView<'_>> {
        let m = &self.members[i];
        Some(MemberView {
            id: m.id,
            label: &m.label,
            self_dns_name: &m.self_name,
            connected: m.connected,
            session_valid: m.session_valid,
            generation: m.generation.get(),
            peer_count: m.peers.len(),
        })
    }
    fn peer(&self, i: usize, j: usize) -> Option<PeerView<'_>> {
        self.reads.set(self.reads.get() + 1);
        if !self.peers_ok.get() {
            return None;
        }
        if self.change_generation.get() {
            let g = &self.members[i].generation;
            g.set(g.get() + 1);
        }
        Some(PeerView { hostname: &self.members[i].peers[j], vpn_ip: 0x6440_0001 + j as u32 })
    }
    fn generation(&self, i: usize) -> u32 {
        self.members[i].generation.get()
    }
    fn alias(&self, id: u32, peer: u32) -> Option<u32> {
        self.alias_calls.set(self.alias_calls.get() + 1);
        self.alias_ok.then(|| 0xc612_0002 + (id - 1) * 0x100 + (peer & 0xff))
    }
    fn busy(&self) -> bool {
        self.busy
    }
}

fn question(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.').filter(|l| !l.is_empty()) {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, (qtype >> 8) as u8, qtype as u8, 0, 1]);
    q
}

struct T {
    r: Responder,
    now: u64,
}
#[derive(Debug, PartialEq)]
enum Got {
    Answer { rcode: u8, answers: u16, alias: Option<[u8; 4]>, len: usize },
    Forward,
    Drop,
}
impl T {
    fn new() -> Self {
        T { r: Responder::new(), now: 1000 }
    }
    fn ask_raw(&mut self, d: &Dir, q: &[u8]) -> (Action, Vec<u8>) {
        let mut out = vec![0u8; 1500];
        let a = self.r.handle_query(q, HOST, self.now, d, Some(UP), &mut out);
        (a, out)
    }
    fn ask(&mut self, d: &Dir, name: &str, qtype: u16) -> Got {
        let q = question(name, qtype);
        let (a, out) = self.ask_raw(d, &q);
        match a {
            Action::Answer { len } => Got::Answer {
                rcode: out[3] & 15,
                answers: u16::from_be_bytes([out[6], out[7]]),
                alias: (out[7] == 1).then(|| out[len - 4..len].try_into().unwrap()),
                len,
            },
            Action::Forward { slot, .. } => {
                // an ordinary name: free the slot as the test harness resets the workspace
                self.r.forward_failed(slot);
                Got::Forward
            }
            Action::Drop(_) => Got::Drop,
        }
    }
}
fn ans(rcode: u8, alias: Option<[u8; 4]>) -> impl Fn(&Got) -> bool {
    move |g| matches!(g, Got::Answer { rcode: r, alias: a, .. } if *r == rcode && *a == alias)
}

fn base() -> Dir {
    let mut d = Dir::new();
    d.members.push(Dir::member(1, "work", "dongle.example.ts.net.", &["server.example.ts.net"]));
    d
}

#[test]
fn ordinary_forwarding_and_id_rewrite() {
    let d = Dir::new();
    let mut t = T::new();
    let q = question("example.com", 1);
    let (a, out) = t.ask_raw(&d, &q);
    let Action::Forward { upstream, len, reset_socket, slot } = a else { panic!("{a:?}") };
    assert_eq!((upstream, len, reset_socket, slot), (UP, q.len(), false, 0));
    assert_eq!(&out[2..len], &q[2..], "only the ID changes");
    let wire = u16::from_be_bytes([out[0], out[1]]);
    assert_eq!(wire, 1);
    assert_eq!(t.r.pending_count(), 1);
    // the upstream reply: same question, QR set; ID restored, sent to the asker
    let mut resp = out[..len].to_vec();
    resp[2] |= 0x80;
    let rep = t.r.handle_upstream(&mut resp).unwrap();
    assert_eq!((rep.client, rep.len), (HOST, resp.len()));
    assert_eq!(&resp[0..2], &[0x12, 0x34]);
    assert_eq!(t.r.pending_count(), 0);
    assert_eq!(t.r.stats().get(Stat::Forwarded), 1);
    assert_eq!(t.r.stats().get(Stat::Relayed), 1);
    // no upstream: dropped, not answered
    let mut o = vec![0u8; 1500];
    assert_eq!(t.r.handle_query(&q, HOST, 0, &d, None, &mut o), Action::Drop(DropReason::NoUpstream));
    assert_eq!(t.r.handle_query(&q, HOST, 0, &d, Some(0), &mut o), Action::Drop(DropReason::NoUpstream));
}

#[test]
fn qualified_answer_shape_cache_and_generation() {
    let d = base();
    let mut t = T::new();
    let q = question("server.work.tailnet", 1);
    let (a, out) = t.ask_raw(&d, &q);
    assert_eq!(a, Action::Answer { len: q.len() + 16 });
    assert_eq!(&out[2..4], &[0x81, 0x80]);
    assert_eq!(u16::from_be_bytes([out[6], out[7]]), 1);
    assert_eq!(&out[q.len()..q.len() + 12], &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
    assert_eq!(&out[q.len() + 12..q.len() + 16], &[0xc6, 0x12, 0x00, 0x03]);
    assert_eq!(&out[..2], &[0x12, 0x34], "the ID is the query's");
    // cached: no directory reads
    d.reads.set(0);
    assert!(ans(0, Some([0xc6, 0x12, 0, 3]))(&t.ask(&d, "server.work.tailnet", 1)));
    assert_eq!(d.reads.get(), 0);
    assert_eq!(t.r.stats().get(Stat::CacheHits), 1);
    // directory generation change invalidates
    d.members[0].generation.set(1);
    assert!(ans(0, Some([0xc6, 0x12, 0, 3]))(&t.ask(&d, "server.work.tailnet", 1)));
    assert_eq!(d.reads.get(), 1);
    // 30 s expiry
    d.reads.set(0);
    t.now += 30_001;
    t.ask(&d, "server.work.tailnet", 1);
    assert_eq!(d.reads.get(), 1);
}

#[test]
fn temporary_failures_are_servfail_never_nxdomain_or_forward() {
    let mut t = T::new();
    let mut d = base();
    d.members[0].connected = false;
    assert!(ans(2, None)(&t.ask(&d, "server.work.tailnet", 1)));
    d.members[0].connected = true;
    d.members[0].session_valid = false;
    assert!(ans(2, None)(&t.ask(&d, "server.example.ts.net", 1)));
    d.members[0].session_valid = true;
    d.busy = true;
    assert!(ans(2, None)(&t.ask(&d, "server.work.tailnet", 1)));
    assert!(ans(2, None)(&t.ask(&d, "server.example.ts.net", 1)));
    assert_eq!(t.ask(&d, "example.com", 1), Got::Forward, "ordinary names never wait on the lock");
    assert!(ans(0, None)(&t.ask(&d, "server.example.ts.net", 28)), "AAAA is NODATA even when busy");
    assert_eq!(t.r.stats().get(Stat::LockFailures), 2);
    d.busy = false;
    d.peers_ok.set(false);
    assert!(ans(2, None)(&t.ask(&d, "server.work.tailnet", 1)));
    d.peers_ok.set(true);
    d.change_generation.set(true);
    assert!(ans(2, None)(&t.ask(&d, "server.work.tailnet", 1)), "generation changed while scanning");
    d.change_generation.set(false);
    let mut d2 = base();
    d2.alias_ok = false;
    assert!(ans(2, None)(&t.ask(&d2, "server.work.tailnet", 1)), "alias store failure");
    // no members at all: absent
    assert!(ans(3, None)(&t.ask(&Dir::new(), "server.work.tailnet", 1)));
    assert!(t.r.stats().get(Stat::Temporary) >= 6);
}

#[test]
fn nodata_aaaa_and_absent_names() {
    let d = base();
    let mut t = T::new();
    assert!(ans(0, None)(&t.ask(&d, "server.work.tailnet", 28)));
    assert!(ans(0, None)(&t.ask(&d, "nobody.example.ts.net", 28)));
    assert!(ans(3, None)(&t.ask(&d, "missing.work.tailnet", 1)));
    // class != IN with type A: no lookup, NXDOMAIN-shaped (the C's rule: only type decides NODATA)
    let mut q = question("server.work.tailnet", 1);
    let l = q.len();
    q[l - 1] = 3;
    let (a, out) = t.ask_raw(&d, &q);
    assert!(matches!(a, Action::Answer { .. }) && out[3] & 15 == 3 && out[7] == 0);
    assert_eq!(t.r.stats().get(Stat::Absent), 2);
}

#[test]
fn cache_holds_four_least_recently_used_evicted() {
    let mut d = Dir::new();
    d.members.push(Dir::member(
        1,
        "work",
        "dongle.example.ts.net.",
        &["peer0.example.ts.net", "peer1.example.ts.net", "peer2.example.ts.net", "peer3.example.ts.net", "peer4.example.ts.net"],
    ));
    let mut t = T::new();
    for i in 0..5 {
        assert!(matches!(t.ask(&d, &format!("peer{i}.work.tailnet"), 1), Got::Answer { rcode: 0, answers: 1, .. }));
    }
    d.reads.set(0);
    t.ask(&d, "peer4.work.tailnet", 1);
    t.ask(&d, "peer3.work.tailnet", 1);
    assert_eq!(d.reads.get(), 0, "the four most recent are cached");
    t.ask(&d, "peer0.work.tailnet", 1);
    assert!(d.reads.get() > 0, "the oldest was evicted");
}

#[test]
fn malformed_queries_are_dropped_silently() {
    let d = base();
    let mut t = T::new();
    for n in 0..12 {
        let q = vec![0u8; n];
        assert_eq!(t.ask_raw(&d, &q).0, Action::Drop(DropReason::TooShort));
    }
    let mut q = question("server.work.tailnet", 1);
    q[12] = 255;
    assert!(matches!(t.ask_raw(&d, &q).0, Action::Drop(DropReason::BadQuestion(ParseError::BadLabel))));
    let mut q = question("server.work.tailnet", 1);
    q.truncate(q.len() - 3);
    assert!(matches!(t.ask_raw(&d, &q).0, Action::Drop(DropReason::BadQuestion(_))));
    // a compression pointer in the question is invalid
    let mut q = question("example.com", 1);
    q[12] = 0xc0;
    assert!(matches!(t.ask_raw(&d, &q).0, Action::Drop(DropReason::BadQuestion(ParseError::BadLabel))));
    // response bit, question count, non-USB source
    let mut q = question("example.com", 1);
    q[2] |= 0x80;
    assert_eq!(t.ask_raw(&d, &q).0, Action::Drop(DropReason::IsResponse));
    let mut q = question("example.com", 1);
    q[5] = 2;
    assert_eq!(t.ask_raw(&d, &q).0, Action::Drop(DropReason::QuestionCount));
    let q = question("example.com", 1);
    let mut out = vec![0u8; 1500];
    for addr in [0xc0a8_0102, 0x0808_0808, 0xc0a8_4e02] {
        assert_eq!(t.r.handle_query(&q, Client { addr, port: 1 }, 0, &d, Some(UP), &mut out), Action::Drop(DropReason::NotUsbHost));
    }
    // too big for the buffer
    let mut small = [0u8; 20];
    assert_eq!(t.r.handle_query(&q, HOST, 0, &d, Some(UP), &mut small), Action::Drop(DropReason::TooLarge));
    // the KNOWN corner: tail of a query truncated to a 1-byte missing class
    let mut q = question("server.work.tailnet", 1);
    q.truncate(q.len() - 1);
    assert!(matches!(t.ask_raw(&d, &q).0, Action::Drop(_)));
    // very long names stay bounded: 63+63+63+50 label bytes + dots is over 254
    let long = format!("{}.{}.{}.{}.example.ts.net", "b".repeat(63), "c".repeat(63), "d".repeat(63), "e".repeat(50));
    let q = question(&long, 1);
    assert!(matches!(t.ask_raw(&d, &q).0, Action::Drop(DropReason::BadQuestion(ParseError::TooLong))));
    // a 63-byte label in the domain is a normal, absent name
    let l = format!("{}.example.ts.net", "a".repeat(63));
    assert!(ans(3, None)(&t.ask(&d, &l, 1)));
}

#[test]
fn magicdns_names_and_domains() {
    let mut d = Dir::new();
    d.members.push(Dir::member(
        1,
        "work",
        "dongle.example.ts.net.",
        &["server.example.ts.net", "alpha.example.ts.net", "beta.example.ts.net", "server.other.ts.net"],
    ));
    d.members.push(Dir::member(2, "home", "gw.corp.ts.net", &["server.corp.ts.net"]));
    let mut t = T::new();
    let a3 = Some([0xc6, 0x12, 0, 4]);
    // qualified and MagicDNS forms
    assert!(ans(0, a3)(&t.ask(&d, "alpha.work.tailnet", 1)));
    assert!(ans(0, a3)(&t.ask(&d, "alpha.example.ts.net", 1)));
    // two peers share a first label: qualified is ambiguous, MagicDNS names are exact
    assert!(ans(3, None)(&t.ask(&d, "server.work.tailnet", 1)));
    assert!(ans(0, Some([0xc6, 0x12, 0, 3]))(&t.ask(&d, "server.example.ts.net", 1)));
    assert!(ans(0, Some([0xc6, 0x12, 0, 3]))(&t.ask(&d, "SERVER.Example.TS.net", 1)));
    assert!(ans(0, Some([0xc6, 0x12, 0, 5]))(&t.ask(&d, "beta.example.ts.net", 1)));
    // another peer's domain never matches this peer; forwarded
    assert_eq!(t.ask(&d, "server.other.ts.net", 1), Got::Forward);
    assert_eq!(t.ask(&d, "alpha.other.ts.net", 1), Got::Forward);
    assert!(ans(3, None)(&t.ask(&d, "gamma.example.ts.net", 1)));
    assert!(ans(3, None)(&t.ask(&d, "a.alpha.example.ts.net", 1)));
    // the second membership resolves to its own alias (membership 2)
    assert!(ans(0, Some([0xc6, 0x12, 1, 3]))(&t.ask(&d, "server.corp.ts.net", 1)));
    // apex, bare domain, first label alone, look-alikes: forwarded
    for n in ["example.ts.net", "ts.net", "server", "server.example.ts.net.evil.com", "xexample.ts.net", "server.xexample.ts.net", "example.com"] {
        assert_eq!(t.ask(&d, n, 1), Got::Forward, "{n}");
    }
    // a name inside a domain is never forwarded for non-A types either
    assert!(ans(0, None)(&t.ask(&d, "server.example.ts.net", 28)));
    // a connected client without a DNS name yet owns no domain; "dongle" (no domain) neither
    d.members[0].self_name = String::new();
    assert_eq!(t.ask(&d, "server.example.ts.net", 1), Got::Forward);
    d.members[0].self_name = "dongle".into();
    assert_eq!(t.ask(&d, "server.example.ts.net", 1), Got::Forward);
    d.members[0].self_name = "dongle.example.ts.net".into();
    assert!(ans(0, Some([0xc6, 0x12, 0, 3]))(&t.ask(&d, "server.example.ts.net", 1)));
    // duplicate domain across memberships is ambiguous even when only one has the peer, and costs no alias allocation
    d.members[1].self_name = "other.example.ts.net.".into();
    assert!(ans(3, None)(&t.ask(&d, "server.example.ts.net", 1)));
    assert!(ans(3, None)(&t.ask(&d, "alpha.example.ts.net", 1)));
    let before = d.alias_calls.get();
    assert!(ans(3, None)(&t.ask(&d, "server.example.ts.net", 1)));
    assert_eq!(d.alias_calls.get(), before);
    assert!(ans(0, a3)(&t.ask(&d, "alpha.work.tailnet", 1)), "the qualified form still works");
    d.members[1].connected = false;
    assert!(ans(3, None)(&t.ask(&d, "server.example.ts.net", 1)));
    d.members[1].connected = true;
    d.members[1].self_name = "gw.corp.ts.net".into();
    // short hostnames (peers restored from the NVS cache) are completed with the membership's domain
    d.members[0].peers = vec!["cached".into()];
    d.members[0].generation.set(d.members[0].generation.get() + 1);
    assert!(ans(0, Some([0xc6, 0x12, 0, 3]))(&t.ask(&d, "cached.example.ts.net", 1)));
    assert!(ans(0, Some([0xc6, 0x12, 0, 3]))(&t.ask(&d, "cached.work.tailnet", 1)));
    // a 63-byte first label in a peer's name is matched, a candidate over 127 bytes never
    let long_peer = format!("{}.example.ts.net", "a".repeat(63));
    d.members[0].peers = vec![long_peer.clone()];
    d.members[0].generation.set(d.members[0].generation.get() + 1);
    assert!(ans(0, Some([0xc6, 0x12, 0, 3]))(&t.ask(&d, &long_peer, 1)));
}

#[test]
fn domain_of_cases() {
    use tdongle_tailnet_dns::responder::domain_of;
    assert_eq!(domain_of("gw.corp.ts.net."), "corp.ts.net");
    assert_eq!(domain_of("gw.corp.ts.net"), "corp.ts.net");
    assert_eq!(domain_of("dongle"), "");
    assert_eq!(domain_of(""), "");
    assert_eq!(domain_of(".corp.ts.net"), "");
    assert_eq!(domain_of("gw."), "");
    assert_eq!(domain_of("gw.x."), "x");
}

#[test]
fn upstream_pending_limits_ids_timeouts_and_resolver_change() {
    let d = Dir::new();
    let mut t = T::new();
    let mut outs = vec![];
    for i in 0..4u16 {
        let mut q = question("example.com", 1);
        q[0] = 0x12;
        q[1] = 0x34;
        let mut out = vec![0u8; 1500];
        let c = Client { addr: 0xc0a8_4d02, port: 1000 + i };
        let a = t.r.handle_query(&q, c, t.now, &d, Some(UP), &mut out);
        assert!(matches!(a, Action::Forward { slot, .. } if slot == usize::from(i)));
        outs.push(out[..q.len()].to_vec());
    }
    // four independent transactions with equal client IDs
    let ids: Vec<u16> = outs.iter().map(|o| u16::from_be_bytes([o[0], o[1]])).collect();
    for i in 0..4 {
        for j in 0..i {
            assert_ne!(ids[i], ids[j]);
        }
    }
    assert_eq!(t.r.stats().get(Stat::MaxPending), 4);
    // the fifth gets SERVFAIL at once
    let q = question("example.com", 1);
    let mut out = vec![0u8; 1500];
    let a = t.r.handle_query(&q, HOST, t.now, &d, Some(UP), &mut out);
    assert_eq!(a, Action::Answer { len: q.len() });
    assert_eq!(&out[2..4], &[0x81, 0x82]);
    assert_eq!(t.r.stats().get(Stat::UpstreamBusy), 1);
    // reply with a different question: ignored; right one: relayed to the right asker
    let mut r = outs[2].clone();
    r[2] |= 0x80;
    r[13] ^= 1;
    assert!(t.r.handle_upstream(&mut r).is_none());
    r[13] ^= 1;
    let rep = t.r.handle_upstream(&mut r).unwrap();
    assert_eq!(rep.client.port, 1002);
    assert_eq!(&r[..2], &[0x12, 0x34]);
    // a duplicate of the same reply is ignored; a non-response or short packet too
    let mut again = outs[2].clone();
    again[2] |= 0x80;
    assert!(t.r.handle_upstream(&mut again).is_none());
    assert!(t.r.handle_upstream(&mut outs[0].clone()).is_none());
    assert!(t.r.handle_upstream(&mut [0u8; 5]).is_none());
    // timeouts
    t.now += 1999;
    assert!(!t.r.expire(t.now));
    t.now += 1;
    assert!(t.r.expire(t.now), "all timed out: the socket may close");
    assert_eq!(t.r.stats().get(Stat::Timeouts), 3);
    // the resolver changes: pending forgotten, socket reset
    let mut out = vec![0u8; 1500];
    let a = t.r.handle_query(&q, HOST, t.now, &d, Some(UP), &mut out);
    assert!(matches!(a, Action::Forward { reset_socket: false, .. }));
    let a = t.r.handle_query(&q, HOST, t.now, &d, Some(0x0101_0101), &mut out);
    assert!(matches!(a, Action::Forward { reset_socket: true, upstream: 0x0101_0101, .. }));
    assert_eq!(t.r.pending_count(), 1);
    // a failed send frees the slot
    let Action::Forward { slot, .. } = t.r.handle_query(&q, HOST, t.now, &d, Some(0x0101_0101), &mut out) else { panic!() };
    t.r.forward_failed(slot);
    assert_eq!(t.r.pending_count(), 1);
    assert_eq!(t.r.next_deadline(), Some(t.now + UPSTREAM_TIMEOUT_MS));
    t.r.upstream_closed();
    assert_eq!(t.r.pending_count(), 0);
}

#[test]
fn id_counter_wrap_skips_live_ids() {
    let d = Dir::new();
    let mut t = T::new();
    t.r = Responder::new();
    let q = question("example.com", 1);
    let mut seen = std::collections::HashSet::new();
    for i in 0..200_000u32 {
        let mut out = vec![0u8; 1500];
        let a = t.r.handle_query(&q, HOST, i as u64 * 10_000, &d, Some(UP), &mut out);
        let Action::Forward { slot, .. } = a else { panic!() };
        let id = u16::from_be_bytes([out[0], out[1]]);
        if i < 3 {
            seen.insert(id);
        }
        // complete immediately
        let mut r = out[..q.len()].to_vec();
        r[2] |= 0x80;
        assert!(t.r.handle_upstream(&mut r).is_some());
        let _ = slot;
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn state_size_and_stat_names() {
    println!("Responder = {} B", Responder::STATE_BYTES);
    assert_eq!(Stat::COUNT, 11);
    assert_eq!(Stat::Queries.name(), "queries");
    assert_eq!(Stat::MaxPending as usize, 10);
    assert!(Responder::STATE_BYTES < 1200);
}
