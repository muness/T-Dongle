//! The peer directory the engine reads: every peer of every membership's tailnet (hundreds), of which only the working set of eight is resident
//! (ADR 0012). In the firmware it is the flash directory (`tdongle_tailnet_peers::directory`: two-bank image codec, delta application, alias log) behind
//! this trait; [`RamDirectory`] is the same rules on arrays, for the tests and for boards without the flash partition.
//!
//! (Aliases are not here: they are the engine's [`crate::alias::AliasBook`].)
//!
//! The trait takes `&mut self` for lookups because a flash read needs a buffer; the engine never holds a record across calls.

extern crate alloc;

use alloc::vec::Vec;
use tdongle_tailnet_map::directory::is_storable;
use tdongle_tailnet_map::types::{PeerAction, PeerRecord};
use tdongle_tailnet_peers::directory::{self as dirfmt, Op, OpLog, RecordFile};
use tdongle_tailnet_peers::record::{Action, DirRecord, Endpoint, MICROLINK_MAX_PEER_ROUTES, ML_MAX_ENDPOINTS, PubKey, Route};

/// The directory refused (staging area full, no space, I/O): the map fails and the previous directory stays in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirError;

/// A directory record, as much of it as the diagnostics print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Tailnet address.
    pub ip: u32,
    /// First four bytes of the WireGuard public key.
    pub key: [u8; 4],
    /// Home DERP region, 0 = unknown.
    pub derp_region: u16,
    /// Endpoints carried.
    pub endpoints: u8,
    /// Subnet routes carried.
    pub routes: u8,
    /// `Node.Online`, if the map said.
    pub online: Option<bool>,
}

/// Peer records, per membership slot (`member` is the engine's slot index, not the router id).
pub trait PeerDirectory {
    /// The record whose WireGuard key is `key`.
    fn find_by_key(&mut self, member: usize, key: &PubKey) -> Option<DirRecord>;
    /// The record whose tailnet address is `ip`.
    fn find_by_ip(&mut self, member: usize, ip: u32) -> Option<DirRecord>;
    /// The record whose DISCO key is `key`.
    fn find_by_disco(&mut self, member: usize, key: &PubKey) -> Option<DirRecord>;
    /// Stage one update of the map being received (`ml_directory_stage`).
    fn stage(&mut self, member: usize, rec: &PeerRecord) -> Result<(), DirError>;
    /// Apply the staged updates as the next generation (`ml_directory_commit`). `authoritative`: the map carried the whole list.
    fn commit(&mut self, member: usize, authoritative: bool) -> Result<(), DirError>;
    /// Discard the staged updates.
    fn abort(&mut self, member: usize);
    /// Bind a slot to a node public key. Persistent directories may restore only
    /// records belonging to this key; other directories start empty.
    fn attach(&mut self, member: usize, _owner: &PubKey) -> bool {
        self.clear(member);
        true
    }
    /// Forget everything of a membership.
    fn clear(&mut self, member: usize);
    /// Live records.
    fn count(&self, member: usize) -> usize;
    /// The `j`-th live record's hostname and address (for DNS).
    fn peer_view(&self, member: usize, j: usize) -> Option<(&str, u32)>;
    /// What the `j`-th live record carries, for diagnostics.
    fn peer_info(&self, _member: usize, _j: usize) -> Option<PeerInfo> {
        None
    }
    /// Call `f` with the hostname and summary of every live record, until it returns false (status page, diagnostics).
    fn for_each_peer(&self, member: usize, f: &mut dyn FnMut(&str, PeerInfo) -> bool) {
        for j in 0..self.count(member) {
            if let (Some((name, _)), Some(info)) = (self.peer_view(member, j), self.peer_info(member, j))
                && !f(name, info)
            {
                return;
            }
        }
    }
    /// Call `f` with the hostname and address of the live records whose hostname's first label (of its first 63 bytes) is `label`, ignoring ASCII case; it
    /// may be called for others too (DNS checks the full name). `false`: a record could not be read (the lookup is temporary).
    fn for_each_named(&self, member: usize, label: &[u8], f: &mut dyn FnMut(&str, u32)) -> bool {
        let mut ok = true;
        for j in 0..self.count(member) {
            match self.peer_view(member, j) {
                Some((name, ip)) => f(name, ip),
                None => ok = false,
            }
        }
        let _ = label;
        ok
    }
    /// The WireGuard-resident peers of `member` (their records are kept cached, never evicted): the whole set, replacing the previous one.
    fn pin(&mut self, _member: usize, _keys: &[PubKey]) {}
    /// One bounded step of background work (at most one flash sector erase); true while there is more. The engine calls it once a tick.
    fn maintain(&mut self) -> bool {
        false
    }
    /// [`PeerDirectory::maintain`] has work.
    fn wants_maintenance(&self) -> bool {
        false
    }
    /// Generation counter of the live records (bumped by every commit).
    fn generation(&self, member: usize) -> u32;
    /// Peers the last commit had no room for, and updates dropped because staging was full (both counted overflow, never a failed map).
    fn overflow(&self, _member: usize) -> (u32, u32) {
        (0, 0)
    }
    /// Bytes the next [`PeerDirectory::stage`] may take from the heap (0 for a directory that does not use it). The engine refuses the update, counted, when the
    /// heap would fall below the elastic floor (ADR 0022): the directory is an elastic consumer like the others.
    fn stage_cost(&self) -> usize {
        0
    }
    /// Bytes the next [`PeerDirectory::commit`] of `member` may take from the heap (the next bank, built beside the live one).
    fn commit_cost(&self, _member: usize) -> usize {
        0
    }
}

/// `PeerRecord` (the map projector's) to `DirRecord` (the directory's), as the C's `ml_directory_stage` does.
pub fn to_dir_record(r: &PeerRecord) -> DirRecord {
    let mut d = DirRecord { vpn_ip: r.vpn_ip, public_key: r.node_key.0, disco_key: r.disco_key.0, derp_region: r.home_derp, ..DirRecord::default() };
    d.hostname.set(r.name.as_str());
    d.endpoint_count = if r.endpoints_present { i32::from(r.endpoint_count) } else { -1 };
    for (i, e) in r.endpoint_list().iter().take(ML_MAX_ENDPOINTS).enumerate() {
        d.endpoints[i] = Endpoint { ip: e.ip, port: e.port, is_ipv6: false };
    }
    d.is_exit_node = r.is_exit_node;
    for (i, rt) in r.route_list().iter().take(MICROLINK_MAX_PEER_ROUTES).enumerate() {
        d.subnet_routes[i] = Route { network: rt.network, prefix_len: rt.prefix_len };
        d.subnet_route_count = (i + 1) as u8;
    }
    d.has_online = r.online.is_some();
    d.online = r.online.unwrap_or(false);
    d.has_node_id = r.node_id.is_some();
    d.node_id = r.node_id.unwrap_or(0);
    d
}

pub(crate) const fn action_of(a: PeerAction) -> Action {
    match a {
        PeerAction::Add => Action::Add,
        PeerAction::Remove => Action::Remove,
        PeerAction::Patch => Action::UpdateEndpoint,
    }
}

/// A bank of at most `N` records (a `RecordFile`), each a heap block of its own: a tailnet of ten peers holds ten records (2.9 KB), not `N` (6.9 KB at 24). Growth
/// is exact and fallible: a bank that cannot get the memory reports [`DirError`], which the engine turns into "the map failed, the previous directory stays in
/// force" like any other directory failure.
#[derive(Clone)]
struct Bank<const N: usize> {
    recs: Vec<DirRecord>,
    /// Records the bank had no room for (counted, not an error: a tailnet bigger than the directory keeps what fits).
    dropped: u32,
}

impl<const N: usize> Bank<N> {
    const fn new() -> Self {
        Self { recs: Vec::new(), dropped: 0 }
    }
    fn live(&self) -> impl Iterator<Item = &DirRecord> {
        self.recs.iter().filter(|r| r.vpn_ip != 0)
    }
    /// Room for `more` records, or why not: the cap `N` and the allocator are both refusals.
    fn reserve(&mut self, more: usize) -> Result<(), DirError> {
        if self.recs.len() + more > N {
            return Err(DirError);
        }
        self.recs.try_reserve_exact(more).map_err(|_| DirError)
    }
}

impl<const N: usize> RecordFile for Bank<N> {
    type Error = DirError;
    fn count(&self) -> usize {
        self.recs.len()
    }
    fn read(&mut self, i: usize) -> Result<DirRecord, DirError> {
        self.recs.get(i).cloned().ok_or(DirError)
    }
    fn write(&mut self, i: usize, r: &DirRecord) -> Result<(), DirError> {
        *self.recs.get_mut(i).ok_or(DirError)? = r.clone();
        Ok(())
    }
    fn append(&mut self, r: &DirRecord) -> Result<(), DirError> {
        if self.recs.len() >= N {
            // the C with a bounded directory keeps what fits and counts the rest; the map is not refused for it
            self.dropped = self.dropped.saturating_add(1);
            return Ok(());
        }
        // exact growth, one record at a time (a bank built by `commit` is reserved up front, so this is no reallocation there)
        self.recs.try_reserve_exact(1).map_err(|_| DirError)?;
        self.recs.push(r.clone());
        Ok(())
    }
}

struct OpBuf<'a> {
    ops: &'a [Op],
}

impl OpLog for OpBuf<'_> {
    type Error = DirError;
    fn replay(&mut self, f: &mut dyn FnMut(&Op) -> Result<(), DirError>) -> Result<(), DirError> {
        self.ops.iter().try_for_each(f)
    }
}

/// An in-RAM directory: `M` memberships of up to `N` records each, `S` staged updates per membership; **every record and every staged update is a heap block**,
/// so the directory costs what the tailnets hold (and a map in flight), not `M x N` and `M x S` records up front. `N` records of 288 bytes each per membership: size
/// the limit for the board, not for a 500-node tailnet (the C keeps the directory in flash).
pub struct RamDirectory<const M: usize, const N: usize, const S: usize> {
    live: [Bank<N>; M],
    staged: [Vec<Op>; M],
    generation: [u32; M],
    /// Peers the last commit of each membership had no room for, and staged updates dropped for want of staging room: counted overflow.
    overflow: [u32; M],
    stage_dropped: [u32; M],
}

impl<const M: usize, const N: usize, const S: usize> Default for RamDirectory<M, N, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const M: usize, const N: usize, const S: usize> RamDirectory<M, N, S> {
    /// Bytes of the directory value itself (the records are heap blocks on top of this).
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// Bytes the directory can hold at most: `M` live banks, one bank being built by a commit, `S` staged updates per membership.
    pub const MAX_HEAP_BYTES: usize = (M + 1) * N * core::mem::size_of::<DirRecord>() + M * S * core::mem::size_of::<Op>();
    /// Empty.
    #[inline(always)]
    pub const fn new() -> Self {
        Self { live: [const { Bank::new() }; M], staged: [const { Vec::new() }; M], generation: [0; M], overflow: [0; M], stage_dropped: [0; M] }
    }
    /// Staged updates waiting for a commit.
    pub fn staged(&self, member: usize) -> usize {
        self.staged.get(member).map_or(0, Vec::len)
    }
    /// Heap bytes the directory holds now (live records and staged updates, by capacity).
    pub fn heap_bytes(&self) -> usize {
        self.live.iter().map(|b| b.recs.capacity() * core::mem::size_of::<DirRecord>()).sum::<usize>()
            + self.staged.iter().map(|s| s.capacity() * core::mem::size_of::<Op>()).sum::<usize>()
    }
    /// Insert a record directly (tests: a netmap without the event path).
    pub fn insert(&mut self, member: usize, rec: &DirRecord) -> Result<(), DirError> {
        let bank = self.live.get_mut(member).ok_or(DirError)?;
        dirfmt::apply(bank, Action::Add, rec)
    }
    fn find(&self, member: usize, pred: impl Fn(&DirRecord) -> bool) -> Option<DirRecord> {
        self.live.get(member)?.live().find(|r| pred(r)).cloned()
    }
}

impl<const M: usize, const N: usize, const S: usize> PeerDirectory for RamDirectory<M, N, S> {
    fn find_by_key(&mut self, member: usize, key: &PubKey) -> Option<DirRecord> {
        self.find(member, |r| dirfmt::matches(r, 0, 0, Some(key), None))
    }
    fn find_by_ip(&mut self, member: usize, ip: u32) -> Option<DirRecord> {
        self.find(member, |r| dirfmt::matches(r, ip, 0, None, None))
    }
    fn find_by_disco(&mut self, member: usize, key: &PubKey) -> Option<DirRecord> {
        self.find(member, |r| dirfmt::matches(r, 0, 0, None, Some(key)))
    }
    fn stage(&mut self, member: usize, rec: &PeerRecord) -> Result<(), DirError> {
        if member >= M {
            return Err(DirError);
        }
        // a peer without an address cannot be stored (the C skips it); patches and removals carry none and are fine
        if rec.action == PeerAction::Add && !is_storable(rec) {
            return Ok(());
        }
        let staged = &mut self.staged[member];
        if staged.len() >= S {
            // Full: keep the peers that matter. An online (or addressed-and-active) peer takes the place of a staged add that is not online; otherwise this
            // update is dropped and counted. The map is not refused (a real tailnet has hundreds of peers).
            let online = |r: &DirRecord| r.has_online && r.online;
            let incoming = to_dir_record(rec);
            if rec.action == PeerAction::Add && online(&incoming) {
                if let Some(slot) = staged.iter_mut().find(|o| o.action == Action::Add && !online(&o.record)) {
                    *slot = Op { group: rec.group as u32, action: action_of(rec.action), record: incoming };
                }
            }
            self.stage_dropped[member] = self.stage_dropped[member].saturating_add(1);
            return Ok(());
        }
        staged.try_reserve(1).map_err(|_| DirError)?;
        staged.push(Op { group: rec.group as u32, action: action_of(rec.action), record: to_dir_record(rec) });
        Ok(())
    }
    fn commit(&mut self, member: usize, authoritative: bool) -> Result<(), DirError> {
        if member >= M {
            return Err(DirError);
        }
        // the next generation is built beside the live one (a failure leaves the live bank untouched), with room for every record it can hold: the live records and
        // what the staged updates can add; the old bank is freed when the new one replaces it
        let mut next = Bank::<N>::new();
        let ops = core::mem::take(&mut self.staged[member]);
        let room = (self.live[member].recs.len() + ops.len()).min(N);
        let r = next.reserve(room).and_then(|()| {
            let mut log = OpBuf { ops: &ops[..] };
            dirfmt::commit(&mut next, Some(&mut self.live[member]), &mut log, authoritative)
        });
        // staging is consumed either way (the vector's memory goes back with `ops`)
        drop(ops);
        r?;
        self.overflow[member] = next.dropped;
        self.live[member] = next;
        self.generation[member] = self.generation[member].wrapping_add(1);
        Ok(())
    }
    fn abort(&mut self, member: usize) {
        if member < M {
            self.staged[member] = Vec::new();
        }
    }
    fn clear(&mut self, member: usize) {
        if member < M {
            self.abort(member);
            self.live[member] = Bank::new();
            self.generation[member] = self.generation[member].wrapping_add(1);
        }
    }
    fn count(&self, member: usize) -> usize {
        self.live.get(member).map_or(0, |b| b.live().count())
    }
    fn peer_view(&self, member: usize, j: usize) -> Option<(&str, u32)> {
        self.live.get(member)?.live().nth(j).map(|r| (r.hostname.as_str(), r.vpn_ip))
    }
    fn peer_info(&self, member: usize, j: usize) -> Option<PeerInfo> {
        self.live.get(member)?.live().nth(j).map(|r| PeerInfo {
            ip: r.vpn_ip,
            key: [r.public_key[0], r.public_key[1], r.public_key[2], r.public_key[3]],
            derp_region: r.derp_region,
            endpoints: r.endpoint_count.max(0) as u8,
            routes: r.subnet_route_count,
            online: if r.has_online { Some(r.online) } else { None },
        })
    }
    fn generation(&self, member: usize) -> u32 {
        self.generation.get(member).copied().unwrap_or(0)
    }
    fn overflow(&self, member: usize) -> (u32, u32) {
        (self.overflow.get(member).copied().unwrap_or(0), self.stage_dropped.get(member).copied().unwrap_or(0))
    }
    fn stage_cost(&self) -> usize {
        core::mem::size_of::<Op>() + 16
    }
    fn commit_cost(&self, member: usize) -> usize {
        let have = self.live.get(member).map_or(0, |b| b.recs.len()) + self.staged.get(member).map_or(0, Vec::len);
        have.min(N) * core::mem::size_of::<DirRecord>() + 16
    }
}

impl<const M: usize, const N: usize, const S: usize> core::fmt::Debug for RamDirectory<M, N, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "RamDirectory({M} members)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tdongle_tailnet_map::types::Group;
    use tdongle_tailnet_types::Key32;

    fn rec(ip: u32, key: u8, id: u64) -> PeerRecord {
        let mut r = PeerRecord::new(PeerAction::Add, Group::Peers);
        r.vpn_ip = ip;
        r.node_key = Key32([key; 32]);
        r.disco_key = Key32([key ^ 0x55; 32]);
        r.node_id = Some(id);
        r.name.set("host");
        r
    }

    #[test]
    fn stage_commit_find_and_authoritative_removal() {
        let mut d = RamDirectory::<2, 8, 8>::new();
        d.stage(0, &rec(0x64400002, 2, 2)).unwrap();
        d.stage(0, &rec(0x64400003, 3, 3)).unwrap();
        assert!(d.find_by_ip(0, 0x64400002).is_none(), "not visible before commit");
        d.commit(0, true).unwrap();
        assert_eq!(d.count(0), 2);
        assert!(d.find_by_key(0, &[3; 32]).is_some());
        assert!(d.find_by_disco(0, &[3 ^ 0x55; 32]).is_some());
        assert!(d.find_by_ip(1, 0x64400002).is_none(), "per membership");
        // an authoritative map that omits peer 3 removes it
        d.stage(0, &rec(0x64400002, 2, 2)).unwrap();
        d.commit(0, true).unwrap();
        assert_eq!(d.count(0), 1);
        assert!(d.find_by_ip(0, 0x64400003).is_none());
        // a partial map keeps the rest and applies a removal
        d.stage(0, &rec(0x64400004, 4, 4)).unwrap();
        d.commit(0, false).unwrap();
        assert_eq!(d.count(0), 2);
        let mut rm = PeerRecord::new(PeerAction::Remove, Group::Removed);
        rm.node_id = Some(2);
        d.stage(0, &rm).unwrap();
        d.commit(0, false).unwrap();
        assert_eq!(d.count(0), 1);
        // a patch updates endpoints in place
        let mut p = PeerRecord::new(PeerAction::Patch, Group::Patch);
        p.node_id = Some(4);
        p.home_derp = 9;
        d.stage(0, &p).unwrap();
        d.commit(0, false).unwrap();
        assert_eq!(d.find_by_ip(0, 0x64400004).unwrap().derp_region, 9);
        assert_eq!(d.generation(0), 5);
    }

    #[test]
    fn staging_full_drops_counted_and_abort_discards() {
        let mut d = RamDirectory::<1, 4, 2>::new();
        d.stage(0, &rec(0x64400002, 2, 2)).unwrap();
        d.stage(0, &rec(0x64400003, 3, 3)).unwrap();
        // a real tailnet has more peers than the staging holds: the update is dropped and counted, the map is not refused
        assert_eq!(d.stage(0, &rec(0x64400004, 4, 4)), Ok(()));
        assert_eq!((d.staged(0), d.overflow(0)), (2, (0, 1)));
        d.abort(0);
        assert_eq!(d.staged(0), 0);
        d.commit(0, true).unwrap();
        assert_eq!(d.count(0), 0);
    }

    #[test]
    fn the_directory_costs_what_the_tailnet_holds_and_gives_it_back() {
        let mut d = RamDirectory::<1, 24, 32>::new();
        assert_eq!(d.heap_bytes(), 0, "an empty directory holds nothing");
        for i in 0..5u8 {
            d.stage(0, &rec(0x64400002 + u32::from(i), i + 1, u64::from(i) + 2)).unwrap();
        }
        assert!(d.heap_bytes() >= 5 * core::mem::size_of::<Op>(), "staged updates are blocks");
        d.commit(0, true).unwrap();
        // five peers: five records (and nothing staged any more), not 24
        let rec_bytes = core::mem::size_of::<DirRecord>();
        assert_eq!(d.count(0), 5);
        assert!(d.heap_bytes() >= 5 * rec_bytes && d.heap_bytes() < 8 * rec_bytes, "{} B for 5 records of {rec_bytes}", d.heap_bytes());
        assert!(d.heap_bytes() < RamDirectory::<1, 24, 32>::MAX_HEAP_BYTES / 3);
        d.clear(0);
        assert_eq!((d.count(0), d.heap_bytes()), (0, 0), "clear gives the records back");
    }

    #[test]
    fn a_map_bigger_than_the_directory_keeps_what_fits_and_counts_the_rest() {
        let mut d = RamDirectory::<1, 4, 16>::new();
        for i in 0..3u8 {
            d.stage(0, &rec(0x64400002 + u32::from(i), i + 1, u64::from(i) + 2)).unwrap();
        }
        d.commit(0, true).unwrap();
        let before = d.generation(0);
        // an authoritative map of six peers into a directory of four: the C keeps what fits (the first four) and counts the rest; the map is not refused
        for i in 0..6u8 {
            d.stage(0, &rec(0x64400010 + u32::from(i), 0x40 + i, u64::from(i) + 20)).unwrap();
        }
        assert_eq!(d.commit(0, true), Ok(()));
        assert_eq!(d.generation(0), before.wrapping_add(1));
        assert_eq!((d.count(0), d.overflow(0).0), (4, 2));
        assert!(d.find_by_ip(0, 0x64400010).is_some() && d.find_by_ip(0, 0x64400013).is_some() && d.find_by_ip(0, 0x64400014).is_none());
        assert_eq!(d.staged(0), 0);
    }

    #[test]
    fn a_full_staging_area_prefers_online_peers() {
        let mut d = RamDirectory::<1, 8, 2>::new();
        let mut off = |ip: u32, k: u8| {
            let mut r = rec(ip, k, u64::from(k));
            r.online = Some(false);
            r
        };
        d.stage(0, &off(0x64400002, 2)).unwrap();
        d.stage(0, &off(0x64400003, 3)).unwrap();
        let mut on = rec(0x64400004, 4, 4);
        on.online = Some(true);
        d.stage(0, &on).unwrap();
        d.commit(0, true).unwrap();
        assert!(d.find_by_ip(0, 0x64400004).is_some(), "the online peer took an offline one's place");
        assert_eq!(d.count(0), 2);
    }
}
