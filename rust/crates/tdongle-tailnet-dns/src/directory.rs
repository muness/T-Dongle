//! What the responder needs to know about the memberships: a read-only view the runtime builds (from the peer directory and the control
//! clients) and passes with every query. It replaces the C's `members` list, `members_lock`, the seqlocked published names and the lock-free
//! domain snapshot: a view is consistent by construction, so only [`Directory::busy`] and [`Directory::generation`] remain as the two ways a
//! lookup can be temporarily impossible.

/// One membership as the resolver sees it.
#[derive(Clone, Copy, Debug)]
pub struct MemberView<'a> {
    /// Membership id (also what the router's alias allocation is keyed by).
    pub id: u32,
    /// Short label ("work"): names `<peer>.<label>.tailnet` belong to this membership.
    pub label: &'a str,
    /// The membership's own MagicDNS name as the control server published it ("gw.corp.ts.net." or empty). Its domain is everything after the first
    /// label, without the trailing dot.
    pub self_dns_name: &'a str,
    /// The client is connected.
    pub connected: bool,
    /// The peer directory belongs to a valid session.
    pub session_valid: bool,
    /// Directory generation when the view was taken; a change while a lookup scans makes the lookup temporary.
    pub generation: u32,
    /// Peers in the directory.
    pub peer_count: usize,
}

/// One peer of a membership.
#[derive(Clone, Copy, Debug)]
pub struct PeerView<'a> {
    /// Stored hostname: the full MagicDNS name ("server.corp.ts.net") or only its first label for peers restored from the NVS cache.
    pub hostname: &'a str,
    /// The peer's tailnet IPv4 address (0 = none, never matches).
    pub vpn_ip: u32,
}

/// The read-only view of all memberships.
pub trait Directory {
    /// Number of memberships.
    fn member_count(&self) -> usize;
    /// Membership `i` (`i < member_count()`).
    fn member(&self, i: usize) -> Option<MemberView<'_>>;
    /// Peer `j` of membership `i`; `None` when the record cannot be read right now (counts as a temporary failure).
    fn peer(&self, member: usize, j: usize) -> Option<PeerView<'_>>;
    /// Current directory generation of membership `i` (re-read after a scan to detect a concurrent change).
    fn generation(&self, member: usize) -> u32;
    /// The USB alias address (198.18.x.y) for a peer of a membership, allocating it if needed; `None` when none can be had (store failure).
    fn alias(&self, member_id: u32, peer_ip: u32) -> Option<u32>;
    /// The runtime could not take the membership lock in time: lookups inside a tailnet domain answer SERVFAIL, they are never forwarded.
    fn busy(&self) -> bool {
        false
    }
}

impl<D: Directory + ?Sized> Directory for &D {
    fn member_count(&self) -> usize {
        (**self).member_count()
    }
    fn member(&self, i: usize) -> Option<MemberView<'_>> {
        (**self).member(i)
    }
    fn peer(&self, member: usize, j: usize) -> Option<PeerView<'_>> {
        (**self).peer(member, j)
    }
    fn generation(&self, member: usize) -> u32 {
        (**self).generation(member)
    }
    fn alias(&self, member_id: u32, peer_ip: u32) -> Option<u32> {
        (**self).alias(member_id, peer_ip)
    }
    fn busy(&self) -> bool {
        (**self).busy()
    }
}

/// A directory with no memberships (every name is forwarded).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDirectory;

impl Directory for NoDirectory {
    fn member_count(&self) -> usize {
        0
    }
    fn member(&self, _: usize) -> Option<MemberView<'_>> {
        None
    }
    fn peer(&self, _: usize, _: usize) -> Option<PeerView<'_>> {
        None
    }
    fn generation(&self, _: usize) -> u32 {
        0
    }
    fn alias(&self, _: u32, _: u32) -> Option<u32> {
        None
    }
}
