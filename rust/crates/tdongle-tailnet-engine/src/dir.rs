//! The peer directory the engine reads: every peer of every membership's tailnet (hundreds), of which only the working set of eight is resident
//! (ADR 0012). In the firmware it is the flash directory (`tdongle_tailnet_peers::directory`: two-bank image codec, delta application, alias log) behind
//! this trait; [`RamDirectory`] is the same rules on arrays, for the tests and for boards without the flash partition.
//!
//! (Aliases are not here: they are the engine's [`crate::alias::AliasBook`].)
//!
//! The trait takes `&mut self` for lookups because a flash read needs a buffer; the engine never holds a record across calls.

use tdongle_tailnet_map::directory::is_storable;
use tdongle_tailnet_map::types::{PeerAction, PeerRecord};
use tdongle_tailnet_peers::directory::{self as dirfmt, Op, OpLog, RecordFile};
use tdongle_tailnet_peers::record::{Action, DirRecord, Endpoint, MICROLINK_MAX_PEER_ROUTES, ML_MAX_ENDPOINTS, PubKey, Route};

/// The directory refused (staging area full, no space, I/O): the map fails and the previous directory stays in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirError;

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
    /// Forget everything of a membership.
    fn clear(&mut self, member: usize);
    /// Live records.
    fn count(&self, member: usize) -> usize;
    /// The `j`-th live record's hostname and address (for DNS).
    fn peer_view(&self, member: usize, j: usize) -> Option<(&str, u32)>;
    /// Generation counter of the live records (bumped by every commit).
    fn generation(&self, member: usize) -> u32;
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

const fn action_of(a: PeerAction) -> Action {
    match a {
        PeerAction::Add => Action::Add,
        PeerAction::Remove => Action::Remove,
        PeerAction::Patch => Action::UpdateEndpoint,
    }
}

/// A fixed bank of records (a `RecordFile`).
#[derive(Clone)]
struct Bank<const N: usize> {
    recs: [DirRecord; N],
    count: usize,
}

impl<const N: usize> Bank<N> {
    const fn new() -> Self {
        Self { recs: [const { DirRecord::new() }; N], count: 0 }
    }
    fn live(&self) -> impl Iterator<Item = &DirRecord> {
        self.recs[..self.count].iter().filter(|r| r.vpn_ip != 0)
    }
}

impl<const N: usize> RecordFile for Bank<N> {
    type Error = DirError;
    fn count(&self) -> usize {
        self.count
    }
    fn read(&mut self, i: usize) -> Result<DirRecord, DirError> {
        self.recs.get(i).filter(|_| i < self.count).cloned().ok_or(DirError)
    }
    fn write(&mut self, i: usize, r: &DirRecord) -> Result<(), DirError> {
        if i >= self.count {
            return Err(DirError);
        }
        self.recs[i] = r.clone();
        Ok(())
    }
    fn append(&mut self, r: &DirRecord) -> Result<(), DirError> {
        if self.count >= N {
            return Err(DirError);
        }
        self.recs[self.count] = r.clone();
        self.count += 1;
        Ok(())
    }
}

struct OpBuf<'a> {
    ops: &'a [Option<Op>],
}

impl OpLog for OpBuf<'_> {
    type Error = DirError;
    fn replay(&mut self, f: &mut dyn FnMut(&Op) -> Result<(), DirError>) -> Result<(), DirError> {
        for op in self.ops.iter().flatten() {
            f(op)?;
        }
        Ok(())
    }
}

/// An in-RAM directory: `M` memberships of up to `N` records each, `S` staged updates per membership. `N` records of 288 bytes each
/// per membership: size it for the tests, not for a 500-node tailnet.
pub struct RamDirectory<const M: usize, const N: usize, const S: usize> {
    live: [Bank<N>; M],
    spare: Bank<N>,
    staged: [[Option<Op>; S]; M],
    staged_n: [usize; M],
    generation: [u32; M],
}

impl<const M: usize, const N: usize, const S: usize> Default for RamDirectory<M, N, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const M: usize, const N: usize, const S: usize> RamDirectory<M, N, S> {
    /// Bytes of the whole directory.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// Empty.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            live: [const { Bank::new() }; M],
            spare: Bank::new(),
            staged: [const { [const { None }; S] }; M],
            staged_n: [0; M],
            generation: [0; M],
        }
    }
    /// Staged updates waiting for a commit.
    pub fn staged(&self, member: usize) -> usize {
        self.staged_n.get(member).copied().unwrap_or(0)
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
        let n = self.staged_n[member];
        if n >= S {
            return Err(DirError);
        }
        self.staged[member][n] = Some(Op { group: rec.group as u32, action: action_of(rec.action), record: to_dir_record(rec) });
        self.staged_n[member] = n + 1;
        Ok(())
    }
    fn commit(&mut self, member: usize, authoritative: bool) -> Result<(), DirError> {
        if member >= M {
            return Err(DirError);
        }
        self.spare.count = 0;
        let n = self.staged_n[member];
        let mut log = OpBuf { ops: &self.staged[member][..n] };
        let r = dirfmt::commit(&mut self.spare, Some(&mut self.live[member]), &mut log, authoritative);
        // staging is consumed either way
        for s in &mut self.staged[member][..n] {
            *s = None;
        }
        self.staged_n[member] = 0;
        r?;
        core::mem::swap(&mut self.live[member], &mut self.spare);
        self.generation[member] = self.generation[member].wrapping_add(1);
        Ok(())
    }
    fn abort(&mut self, member: usize) {
        if member < M {
            self.staged[member].fill(None);
            self.staged_n[member] = 0;
        }
    }
    fn clear(&mut self, member: usize) {
        if member < M {
            self.abort(member);
            self.live[member].count = 0;
            self.generation[member] = self.generation[member].wrapping_add(1);
        }
    }
    fn count(&self, member: usize) -> usize {
        self.live.get(member).map_or(0, |b| b.live().count())
    }
    fn peer_view(&self, member: usize, j: usize) -> Option<(&str, u32)> {
        self.live.get(member)?.live().nth(j).map(|r| (r.hostname.as_str(), r.vpn_ip))
    }
    fn generation(&self, member: usize) -> u32 {
        self.generation.get(member).copied().unwrap_or(0)
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
    fn staging_full_refuses_and_abort_discards() {
        let mut d = RamDirectory::<1, 4, 2>::new();
        d.stage(0, &rec(0x64400002, 2, 2)).unwrap();
        d.stage(0, &rec(0x64400003, 3, 3)).unwrap();
        assert_eq!(d.stage(0, &rec(0x64400004, 4, 4)), Err(DirError));
        d.abort(0);
        assert_eq!(d.staged(0), 0);
        d.commit(0, true).unwrap();
        assert_eq!(d.count(0), 0);
    }
}
