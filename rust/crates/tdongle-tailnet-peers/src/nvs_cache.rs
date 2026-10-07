//! The NVS peer cache (`ml_peer_nvs.c`): a single blob `ml_peers/tbl` of up to 64 packed peer entries, so DISCO probing can start at boot before the
//! control plane answers. Byte-compatible with the C's v3 schema: a 12-byte header `{magic "MLPR" (0x4D4C5052), version 3, count, lru_clock, pad}`
//! (little endian) and `count` entries of 118 bytes. A blob of another magic or version is discarded and rebuilt.

use crate::Millis;
use crate::record::{DirRecord, Endpoint, PubKey};
use crate::table::{Peer, PeerMeta};

/// `PEER_NVS_MAGIC`.
pub const PEER_NVS_MAGIC: u32 = 0x4D4C_5052;
/// `PEER_NVS_VERSION`.
pub const PEER_NVS_VERSION: u16 = 3;
/// `ML_NVS_MAX_PEERS`.
pub const ML_NVS_MAX_PEERS: usize = 64;
/// Header bytes.
pub const HEADER_BYTES: usize = 12;
/// `sizeof(peer_nvs_entry_t)`: 118.
pub const ENTRY_BYTES: usize = 118;
/// Bytes of the short hostname field.
pub const HOSTNAME_SHORT: usize = 32;

/// One cached peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Tailnet IPv4 address; zero = unused.
    pub vpn_ip: u32,
    /// WireGuard public key.
    pub public_key: PubKey,
    /// DISCO public key.
    pub disco_key: PubKey,
    /// Home DERP region.
    pub derp_region: u16,
    /// Up to two IPv4 endpoints.
    pub endpoints: [(u32, u16); 2],
    /// How many are valid.
    pub endpoint_count: u8,
    /// First DNS label of the hostname, NUL padded (31 bytes at most plus a NUL).
    pub hostname_short: [u8; HOSTNAME_SHORT],
    /// Higher = more recently saved.
    pub lru_counter: u16,
    /// Tailnet exit node.
    pub is_exit_node: bool,
}

const EMPTY: Entry = Entry {
    vpn_ip: 0,
    public_key: [0; 32],
    disco_key: [0; 32],
    derp_region: 0,
    endpoints: [(0, 0); 2],
    endpoint_count: 0,
    hostname_short: [0; HOSTNAME_SHORT],
    lru_counter: 0,
    is_exit_node: false,
};

impl Entry {
    /// The hostname as text (up to the NUL; a cut inside a multibyte character is trimmed).
    #[must_use]
    pub fn hostname(&self) -> &str {
        let end = self.hostname_short.iter().position(|&c| c == 0).unwrap_or(HOSTNAME_SHORT);
        match core::str::from_utf8(&self.hostname_short[..end]) {
            Ok(s) => s,
            Err(e) => core::str::from_utf8(&self.hostname_short[..e.valid_up_to()]).unwrap_or(""),
        }
    }

    fn encode(&self, o: &mut [u8]) {
        o[0..4].copy_from_slice(&self.vpn_ip.to_le_bytes());
        o[4..36].copy_from_slice(&self.public_key);
        o[36..68].copy_from_slice(&self.disco_key);
        o[68..70].copy_from_slice(&self.derp_region.to_le_bytes());
        for (i, (ip, port)) in self.endpoints.iter().enumerate() {
            o[70 + 6 * i..74 + 6 * i].copy_from_slice(&ip.to_le_bytes());
            o[74 + 6 * i..76 + 6 * i].copy_from_slice(&port.to_le_bytes());
        }
        o[82] = self.endpoint_count;
        o[83..115].copy_from_slice(&self.hostname_short);
        o[115..117].copy_from_slice(&self.lru_counter.to_le_bytes());
        o[117] = u8::from(self.is_exit_node);
    }

    fn decode(b: &[u8]) -> Entry {
        let mut e = EMPTY;
        e.vpn_ip = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        e.public_key.copy_from_slice(&b[4..36]);
        e.disco_key.copy_from_slice(&b[36..68]);
        e.derp_region = u16::from_le_bytes([b[68], b[69]]);
        for i in 0..2 {
            e.endpoints[i] =
                (u32::from_le_bytes([b[70 + 6 * i], b[71 + 6 * i], b[72 + 6 * i], b[73 + 6 * i]]), u16::from_le_bytes([b[74 + 6 * i], b[75 + 6 * i]]));
        }
        e.endpoint_count = b[82].min(2);
        e.hostname_short.copy_from_slice(&b[83..115]);
        e.lru_counter = u16::from_le_bytes([b[115], b[116]]);
        e.is_exit_node = b[117] != 0;
        e
    }

    /// `ml_peer_nvs_load_all`'s per-entry restore: an active, presumed-online peer without a WireGuard slot.
    #[must_use]
    pub fn to_peer(&self, now: Millis) -> Peer {
        let mut meta = PeerMeta {
            derp_region: self.derp_region,
            is_exit_node: self.is_exit_node,
            online: true,
            endpoint_count: self.endpoint_count,
            ..PeerMeta::default()
        };
        meta.hostname.set(self.hostname());
        for i in 0..usize::from(self.endpoint_count.min(2)) {
            meta.endpoints[i] = Endpoint { ip: self.endpoints[i].0, port: self.endpoints[i].1, is_ipv6: false };
        }
        Peer { active: true, vpn_ip: self.vpn_ip, public_key: self.public_key, disco_key: self.disco_key, peer_added_ms: now, meta, ..Peer::default() }
    }
}

/// What `save` stores of a peer.
#[derive(Debug, Clone, Copy)]
pub struct SaveInput<'a> {
    /// Tailnet IP.
    pub vpn_ip: u32,
    /// WireGuard key.
    pub public_key: &'a PubKey,
    /// DISCO key.
    pub disco_key: &'a PubKey,
    /// Home DERP region.
    pub derp_region: u16,
    /// Known endpoints (only IPv4, non-zero ones are kept, the first two).
    pub endpoints: &'a [Endpoint],
    /// Full hostname (the first DNS label is kept).
    pub hostname: &'a str,
    /// Exit node.
    pub is_exit_node: bool,
}

impl<'a> SaveInput<'a> {
    /// From a directory record.
    #[must_use]
    pub fn from_record(r: &'a DirRecord) -> Self {
        let n = r.endpoint_count.clamp(0, r.endpoints.len() as i32) as usize;
        Self {
            vpn_ip: r.vpn_ip,
            public_key: &r.public_key,
            disco_key: &r.disco_key,
            derp_region: r.derp_region,
            endpoints: &r.endpoints[..n],
            hostname: r.hostname.as_str(),
            is_exit_node: r.is_exit_node,
        }
    }
}

/// The cache table.
#[derive(Debug, Clone)]
pub struct PeerCache<const N: usize = ML_NVS_MAX_PEERS> {
    entries: [Entry; N],
    count: u16,
    lru_clock: u16,
}

impl<const N: usize> Default for PeerCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PeerCache<N> {
    /// Bytes of the working copy (the C keeps it in PSRAM; this board has none).
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();
    /// Largest blob this table can produce.
    pub const MAX_BLOB_BYTES: usize = HEADER_BYTES + N * ENTRY_BYTES;

    /// Empty.
    #[must_use]
    pub const fn new() -> Self {
        Self { entries: [EMPTY; N], count: 0, lru_clock: 0 }
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }
    /// Empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    /// The entries.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries[..self.len()]
    }

    /// `load_table`: parse a blob read from NVS. A wrong magic, version or count (or a short read) gives an EMPTY table and `false`: the cache is
    /// discarded and rebuilt from the control plane.
    #[must_use]
    pub fn from_blob(blob: &[u8]) -> (Self, bool) {
        let mut t = Self::new();
        if blob.len() < HEADER_BYTES {
            return (t, false);
        }
        let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
        let version = u16::from_le_bytes([blob[4], blob[5]]);
        let count = usize::from(u16::from_le_bytes([blob[6], blob[7]]));
        if magic != PEER_NVS_MAGIC || version != PEER_NVS_VERSION || count > N || blob.len() < HEADER_BYTES + count * ENTRY_BYTES {
            return (t, false);
        }
        t.count = count as u16;
        t.lru_clock = u16::from_le_bytes([blob[8], blob[9]]);
        for i in 0..count {
            t.entries[i] = Entry::decode(&blob[HEADER_BYTES + i * ENTRY_BYTES..HEADER_BYTES + (i + 1) * ENTRY_BYTES]);
        }
        (t, true)
    }

    /// `flush_table`: the blob to write (`HEADER_BYTES + count * ENTRY_BYTES`). `None` if `out` is too small.
    pub fn to_blob(&self, out: &mut [u8]) -> Option<usize> {
        let size = HEADER_BYTES + self.len() * ENTRY_BYTES;
        if out.len() < size {
            return None;
        }
        out[0..4].copy_from_slice(&PEER_NVS_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&PEER_NVS_VERSION.to_le_bytes());
        out[6..8].copy_from_slice(&self.count.to_le_bytes());
        out[8..10].copy_from_slice(&self.lru_clock.to_le_bytes());
        out[10..12].copy_from_slice(&[0, 0]);
        for (i, e) in self.entries[..self.len()].iter().enumerate() {
            e.encode(&mut out[HEADER_BYTES + i * ENTRY_BYTES..HEADER_BYTES + (i + 1) * ENTRY_BYTES]);
        }
        Some(size)
    }

    /// `ml_peer_nvs_save` (the table part): update the entry with the same IP or key, else append, else evict the least recently saved one.
    /// Returns the slot used.
    pub fn save(&mut self, p: &SaveInput<'_>) -> usize {
        self.lru_clock = self.lru_clock.wrapping_add(1);
        let mut e = EMPTY;
        e.vpn_ip = p.vpn_ip;
        e.public_key = *p.public_key;
        e.disco_key = *p.disco_key;
        e.derp_region = p.derp_region;
        e.lru_counter = self.lru_clock;
        let mut stored = 0;
        for ep in p.endpoints {
            if stored < 2 && !ep.is_ipv6 && ep.ip != 0 {
                e.endpoints[stored] = (ep.ip, ep.port);
                stored += 1;
            }
        }
        e.endpoint_count = stored as u8;
        // The first DNS label only, at most 31 bytes (a cut inside a multibyte character is trimmed on read).
        let label = p.hostname.split('.').next().unwrap_or("");
        let n = label.len().min(HOSTNAME_SHORT - 1);
        e.hostname_short[..n].copy_from_slice(&label.as_bytes()[..n]);
        e.is_exit_node = p.is_exit_node;

        let cnt = self.len();
        if let Some(i) = self.entries[..cnt].iter().position(|x| x.vpn_ip == p.vpn_ip || x.public_key == *p.public_key) {
            self.entries[i] = e;
            i
        } else if cnt < N {
            self.entries[cnt] = e;
            self.count += 1;
            cnt
        } else {
            let mut lru = 0;
            for i in 1..cnt {
                if self.entries[i].lru_counter < self.entries[lru].lru_counter {
                    lru = i;
                }
            }
            self.entries[lru] = e;
            lru
        }
    }

    /// `ml_peer_nvs_load_all`: the entries with a non-zero IP, restored as resident peers, at most `max`.
    pub fn load_all<'a>(&'a self, max: usize, now: Millis) -> impl Iterator<Item = Peer> + 'a {
        self.entries[..self.len()].iter().filter(|e| e.vpn_ip != 0).take(max).map(move |e| e.to_peer(now))
    }

    /// `ml_peer_nvs_remove`: drop the entry with this key, compacting. False if there is none.
    pub fn remove(&mut self, key: &PubKey) -> bool {
        let cnt = self.len();
        let Some(slot) = self.entries[..cnt].iter().position(|e| e.public_key == *key) else { return false };
        for i in slot..cnt - 1 {
            self.entries[i] = self.entries[i + 1];
        }
        self.entries[cnt - 1] = EMPTY;
        self.count -= 1;
        true
    }

    /// `ml_peer_nvs_clear`.
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

const _: () = assert!(ENTRY_BYTES == 4 + 32 + 32 + 2 + 12 + 1 + HOSTNAME_SHORT + 2 + 1);
