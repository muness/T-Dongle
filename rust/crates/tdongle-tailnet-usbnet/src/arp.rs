//! ARP for the USB side: answer who-has for 192.168.77.1, learn the host from ARP, and ask for the host's address when the dongle has to send to it.
//! lwIP's `etharp.c` with the pieces this gateway uses (`ARP_TABLE_SIZE` 10, `ARP_MAXAGE` 300 s, `ARP_MAXPENDING` 5). Nothing else is resolved: only
//! addresses of the USB subnet, and there is no proxy ARP.
//!
//! What `etharp_input` does, and is kept: a request or reply is only parsed when hardware type is Ethernet, address lengths are 6 and 4 and the
//! protocol is IPv4; a packet whose target is the dongle teaches the table the sender (a new entry may be made), any other packet only refreshes an
//! entry that exists; a request for the dongle's address is answered unicast to the sender's hardware address from the ARP payload; a probe
//! (sender 0.0.0.0) is answered the same way and teaches nothing. Kept from the host's point of view: the dongle never answers for another address.
//!
//! Added: a sender with a group hardware address or a group/zero IP address never enters the table; a request whose sender IP is the dongle's own is an
//! address conflict and is counted, not answered.

use crate::wire::{BROADCAST_MAC, ETHERTYPE_ARP, Mac, mac_is_group, rd16, rd32, wr16, wr32, write_eth};
use tdongle_tailnet_types::{Counter, Millis};

/// An ARP-over-Ethernet-IPv4 packet is 28 bytes; with the Ethernet header 42.
pub const ARP_FRAME: usize = 42;
/// Entries unused for this long are dropped (`ARP_MAXAGE`, 300 s).
pub const MAX_AGE_MS: u64 = 300_000;
/// A used entry older than this is refreshed with a broadcast request (`ARP_AGE_REREQUEST_USED_BROADCAST`, 285 s).
pub const REFRESH_AGE_MS: u64 = 285_000;
/// Spacing of retries for an unresolved address (`ARP_TMR_INTERVAL`, 1 s).
pub const RETRY_MS: u64 = 1_000;
/// Requests sent for an address before giving up (`ARP_MAXPENDING`, 5).
pub const MAX_TRIES: u8 = 5;

/// Why an ARP packet got neither a reply nor an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpIgnore {
    /// Shorter than 28 bytes.
    Runt,
    /// Not Ethernet / IPv4, or address lengths other than 6 and 4.
    BadHeader,
    /// An opcode other than request (1) and reply (2).
    BadOpcode,
    /// A request from our own IP address with another hardware address (counted as a conflict).
    AddressConflict,
    /// For another station and nothing we hold changed.
    NotForUs,
}

impl ArpIgnore {
    /// Number of variants.
    pub const COUNT: usize = 5;
    /// Dense index (exhaustive).
    pub const fn index(self) -> usize {
        match self {
            ArpIgnore::Runt => 0,
            ArpIgnore::BadHeader => 1,
            ArpIgnore::BadOpcode => 2,
            ArpIgnore::AddressConflict => 3,
            ArpIgnore::NotForUs => 4,
        }
    }
}

/// What handling one ARP packet did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum ArpOutcome {
    /// A reply frame of `len` bytes is in the output buffer; send it to the host.
    Replied {
        /// Frame length (42).
        len: usize,
    },
    /// The sender's address was learned or refreshed; nothing to send.
    Learned,
    /// Nothing done.
    Ignored(ArpIgnore),
}

/// Result of asking for the hardware address of an IPv4 address on the USB subnet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Resolve {
    /// Known: send the frame to this address.
    Hit(Mac),
    /// Known, and the entry is close to expiry: send to the address and also send the request frame (`len` bytes in the output buffer).
    HitRefresh {
        /// The hardware address.
        mac: Mac,
        /// Length of the request frame to broadcast.
        len: usize,
    },
    /// Unknown: broadcast the request frame (`len` bytes in the output buffer); hold or drop the packet.
    Request {
        /// Length of the request frame.
        len: usize,
    },
    /// A request is outstanding and its retry time has not come.
    Pending,
    /// Five requests got no answer; the entry is gone. The next call starts again.
    Failed,
    /// The address is not on the USB subnet (or is ours, or a broadcast): nothing to resolve.
    OffLink,
}

/// Counters of the ARP layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpStats {
    /// Packets handled.
    pub packets: Counter,
    /// Replies sent.
    pub replies: Counter,
    /// Table updates (new or refreshed).
    pub learned: Counter,
    /// Senders refused as table entries (group or zero address).
    pub learn_refused: Counter,
    /// Requests built by [`Neighbors::resolve`].
    pub requests: Counter,
    /// Addresses given up on.
    pub gave_up: Counter,
    /// Entries aged out.
    pub expired: Counter,
    /// Packets ignored, by [`ArpIgnore::index`].
    pub ignored: [Counter; ArpIgnore::COUNT],
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Empty,
    Pending { tries: u8, sent: Millis },
    Stable { refreshed: Millis },
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    state: State,
    ip: u32,
    mac: Mac,
    /// Last time this slot was touched (for choosing a victim).
    used: Millis,
    /// Last time a refresh request was handed out for this entry.
    asked: Millis,
}

/// Addressing of the USB netif.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpConfig {
    /// The netif's Ethernet address.
    pub mac: Mac,
    /// Its IPv4 address (192.168.77.1).
    pub ip: u32,
    /// Its netmask.
    pub mask: u32,
}

/// The neighbour table of the USB netif: `N` entries (10 in lwIP; the USB side has one host, 4 is plenty).
#[derive(Debug)]
pub struct Neighbors<const N: usize> {
    cfg: ArpConfig,
    slots: [Slot; N],
    stats: ArpStats,
}

impl<const N: usize> Neighbors<N> {
    /// Size of the table in bytes.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// An empty table.
    pub const fn new(cfg: ArpConfig) -> Self {
        const { assert!(N > 0) };
        Neighbors {
            cfg,
            slots: [Slot { state: State::Empty, ip: 0, mac: [0; 6], used: 0, asked: 0 }; N],
            stats: ArpStats {
                packets: Counter(0),
                replies: Counter(0),
                learned: Counter(0),
                learn_refused: Counter(0),
                requests: Counter(0),
                gave_up: Counter(0),
                expired: Counter(0),
                ignored: [Counter(0); ArpIgnore::COUNT],
            },
        }
    }

    /// The counters.
    pub fn stats(&self) -> &ArpStats {
        &self.stats
    }
    /// The addressing.
    pub fn config(&self) -> &ArpConfig {
        &self.cfg
    }

    /// The known hardware address of `ip`, without side effects (no request, no expiry).
    pub fn peek(&self, ip: u32) -> Option<Mac> {
        self.slots.iter().find(|s| s.ip == ip && matches!(s.state, State::Stable { .. })).map(|s| s.mac)
    }

    /// The first known neighbour (the USB host) as `(ip, mac)`: the one the dongle talks to unprompted.
    pub fn host(&self) -> Option<(u32, Mac)> {
        self.slots.iter().find(|s| matches!(s.state, State::Stable { .. })).map(|s| (s.ip, s.mac))
    }

    fn valid_sender(&self, ip: u32, mac: &Mac) -> bool {
        ip != 0 && ip != u32::MAX && ip >> 28 != 14 && ip | self.cfg.mask != u32::MAX && !mac_is_group(mac) && *mac != [0; 6]
    }

    /// `etharp_update_arp_entry`: refresh the entry of `ip`; make one only when `create`.
    fn learn(&mut self, now: Millis, ip: u32, mac: Mac, create: bool) -> bool {
        if !self.valid_sender(ip, &mac) {
            self.stats.learn_refused.bump();
            return false;
        }
        if let Some(s) = self.slots.iter_mut().find(|s| s.ip == ip && s.state != State::Empty) {
            s.mac = mac;
            s.state = State::Stable { refreshed: now };
            s.used = now;
            self.stats.learned.bump();
            return true;
        }
        if !create {
            return false;
        }
        let i = self.victim();
        self.slots[i] = Slot { state: State::Stable { refreshed: now }, ip, mac, used: now, asked: 0 };
        self.stats.learned.bump();
        true
    }

    /// An empty slot, else a pending one, else the least recently used.
    fn victim(&self) -> usize {
        if let Some(i) = self.slots.iter().position(|s| s.state == State::Empty) {
            return i;
        }
        if let Some(i) = self.slots.iter().position(|s| matches!(s.state, State::Pending { .. })) {
            return i;
        }
        let mut v = 0;
        for (i, s) in self.slots.iter().enumerate() {
            if s.used < self.slots[v].used {
                v = i;
            }
        }
        v
    }

    fn build(&self, out: &mut [u8], op: u16, dst: Mac, tha: Mac, tpa: u32) -> usize {
        write_eth(out, dst, self.cfg.mac, ETHERTYPE_ARP);
        let a = &mut out[14..ARP_FRAME];
        wr16(a, 0, 1);
        wr16(a, 2, 0x0800);
        a[4] = 6;
        a[5] = 4;
        wr16(a, 6, op);
        a[8..14].copy_from_slice(&self.cfg.mac);
        wr32(a, 14, self.cfg.ip);
        a[18..24].copy_from_slice(&tha);
        wr32(a, 24, tpa);
        ARP_FRAME
    }

    /// Handle an ARP packet (`payload` is what follows the Ethernet header). A reply, if any, is built into `out` (at least [`ARP_FRAME`] bytes).
    pub fn handle(&mut self, now: Millis, payload: &[u8], out: &mut [u8]) -> ArpOutcome {
        self.stats.packets.bump();
        let o = self.handle_inner(now, payload, out);
        match o {
            ArpOutcome::Replied { .. } => self.stats.replies.bump(),
            ArpOutcome::Learned => {}
            ArpOutcome::Ignored(r) => self.stats.ignored[r.index()].bump(),
        }
        o
    }

    fn handle_inner(&mut self, now: Millis, a: &[u8], out: &mut [u8]) -> ArpOutcome {
        use ArpOutcome::Ignored as I;
        if a.len() < 28 {
            return I(ArpIgnore::Runt);
        }
        if rd16(a, 0) != 1 || rd16(a, 2) != 0x0800 || a[4] != 6 || a[5] != 4 {
            return I(ArpIgnore::BadHeader);
        }
        let op = rd16(a, 6);
        if op != 1 && op != 2 {
            return I(ArpIgnore::BadOpcode);
        }
        let sha: Mac = [a[8], a[9], a[10], a[11], a[12], a[13]];
        let spa = rd32(a, 14);
        let tpa = rd32(a, 24);
        let for_us = tpa == self.cfg.ip;
        let from_us = spa == self.cfg.ip;
        let learned = self.learn(now, spa, sha, for_us);
        if op == 1 && for_us && !from_us && out.len() >= ARP_FRAME {
            let len = self.build(out, 2, sha, sha, spa);
            return ArpOutcome::Replied { len };
        }
        if op == 1 && for_us && from_us {
            return I(ArpIgnore::AddressConflict);
        }
        if learned { ArpOutcome::Learned } else { I(ArpIgnore::NotForUs) }
    }

    /// Where to send an IPv4 packet for `ip` on the USB subnet. Builds a request into `out` (at least [`ARP_FRAME`] bytes) when one is due.
    pub fn resolve(&mut self, now: Millis, ip: u32, out: &mut [u8]) -> Resolve {
        if ip & self.cfg.mask != self.cfg.ip & self.cfg.mask || ip == self.cfg.ip || ip | self.cfg.mask == u32::MAX || out.len() < ARP_FRAME {
            return Resolve::OffLink;
        }
        let Some(i) = self.slots.iter().position(|s| s.ip == ip && s.state != State::Empty) else {
            let i = self.victim();
            self.slots[i] = Slot { state: State::Pending { tries: 1, sent: now }, ip, mac: [0; 6], used: now, asked: 0 };
            self.stats.requests.bump();
            return Resolve::Request { len: self.build(out, 1, BROADCAST_MAC, [0; 6], ip) };
        };
        self.slots[i].used = now;
        match self.slots[i].state {
            State::Empty => Resolve::OffLink,
            State::Stable { refreshed } => {
                let age = now.saturating_sub(refreshed);
                let mac = self.slots[i].mac;
                if age > MAX_AGE_MS {
                    self.slots[i].state = State::Pending { tries: 1, sent: now };
                    self.stats.expired.bump();
                    self.stats.requests.bump();
                    Resolve::Request { len: self.build(out, 1, BROADCAST_MAC, [0; 6], ip) }
                } else if age >= REFRESH_AGE_MS && (self.slots[i].asked == 0 || now.saturating_sub(self.slots[i].asked) >= RETRY_MS) {
                    // Ask again, at most once a second, while the entry still works.
                    self.slots[i].asked = now.max(1);
                    self.stats.requests.bump();
                    Resolve::HitRefresh { mac, len: self.build(out, 1, BROADCAST_MAC, [0; 6], ip) }
                } else {
                    Resolve::Hit(mac)
                }
            }
            State::Pending { tries, sent } => {
                if now.saturating_sub(sent) < RETRY_MS {
                    Resolve::Pending
                } else if tries >= MAX_TRIES {
                    self.slots[i] = Slot { state: State::Empty, ip: 0, mac: [0; 6], used: 0, asked: 0 };
                    self.stats.gave_up.bump();
                    Resolve::Failed
                } else {
                    self.slots[i].state = State::Pending { tries: tries + 1, sent: now };
                    self.stats.requests.bump();
                    Resolve::Request { len: self.build(out, 1, BROADCAST_MAC, [0; 6], ip) }
                }
            }
        }
    }
}
