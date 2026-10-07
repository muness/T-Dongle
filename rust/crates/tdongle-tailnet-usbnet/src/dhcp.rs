//! The DHCP server of the USB side (RFC 2131 subset): what ESP-IDF's `components/lwip/apps/dhcpserver/dhcpserver.c` does for the C gateway's
//! `usb_interface`, as sans-IO code (`handle_frame(&[u8]) -> reply frame`).
//!
//! # The C's configuration, as found
//!
//! * Server, router and DNS: 192.168.77.1 (`start_network`: `base.ip_info = {192.168.77.1/24, gw = ip}`, `esp_netif_set_dns_info(MAIN, 192.168.77.1)`,
//!   `esp_netif_dhcps_option(ESP_NETIF_DOMAIN_NAME_SERVER, 1)`). Subnet mask 255.255.255.0, broadcast 192.168.77.255.
//! * **Pool 192.168.77.2 to 192.168.77.101.** Nothing sets `ESP_NETIF_REQUESTED_IP_ADDRESS`, so `dhcps_poll_set` takes the larger side of the
//!   subnet around the server (.2 to .254) and cuts it to `DHCPS_MAX_LEASE` (0x64 = 100) addresses.
//! * **Lease time 7200 s** (`DHCPS_LEASE_TIME_DEF` 120 times `CONFIG_LWIP_DHCPS_LEASE_UNIT` 60 s), advertised in option 51. There is no T1/T2.
//! * **Table of 8** (`CONFIG_LWIP_DHCPS_MAX_STATION_NUM`): when more leases exist the one with the smallest remaining timer is removed.
//! * The server's own bookkeeping decrements each lease's timer once per **`DHCP_COARSE_TIMER_MSECS` = 60 s** although the timer is initialised
//!   in seconds (7200), so a silent client's lease is kept for 7200 minutes (5 days), not the 2 hours it was told. That is an ESP-IDF unit mix-up;
//!   [`DhcpConfig::hold_ms`] reproduces it ([`C_HOLD_MS`]) because with one USB host it is harmless and keeps the host on the same address. The
//!   table is trimmed to 8 at once here, not once a minute.
//! * Options in a reply, in this order: 53 type, 1 mask, 51 lease (not in the answer to an INFORM), 54 server id, 3 router, 6 DNS (one address),
//!   28 broadcast address, 26 interface MTU **1500**, 31 router discovery 0, 43 vendor data `01 04 00 00 00 02`. **No domain name** (option 15),
//!   no NTP, no hostname, no captive-portal URI on this interface. A NAK carries only 53 (and, here, 54 as RFC 2131 requires).
//!
//! # Behaviour kept from the C
//!
//! The reply is addressed as `dhcps_response_ip_set` does with `ETHARP_SUPPORT_STATIC_ENTRIES`: to `ciaddr` when the client has one, else to
//! `yiaddr` (by the client's hardware address) unless the client set the broadcast flag, else to 255.255.255.255; a NAK is always broadcast. The
//! address of a returning MAC is reused; a new MAC gets the next address after the last one handed out, wrapping to the first free one. A REQUEST
//! naming an address other than the one the server holds for that MAC is NAKed **and the lease is dropped**. RELEASE and DECLINE drop the lease and
//! get no reply. An INFORM from an address in the subnet is ACKed with no lease; any other INFORM is ignored.
//!
//! # Deviations (all in the direction of RFC 2131, none visible to a normal host)
//!
//! * Only BOOTREQUEST with Ethernet hardware type is answered, and a REQUEST that names another server (option 54) is ignored, where the C
//!   answers everything that has the magic cookie.
//! * A REQUEST for an address the server has no record of (the dongle rebooted, the host kept its lease) is ACKed when the address is in the pool
//!   and free, instead of NAKed unless it happens to be the next address the C would hand out.
//! * A lease is created at DISCOVER only for a client that will be offered it; unrelated or malformed packets create nothing (the C allocates
//!   before it parses the options).
//! * Replies are padded to the 300-byte BOOTP minimum, not to the 548 bytes of `struct dhcps_msg`, with `ciaddr` 0 (except for an INFORM answer),
//!   `siaddr` 0, `hops` 0, `secs` 0; a relayed request (`giaddr` set) is ignored (nothing relays on a USB link).

use crate::csum::{fill_header, finish, pseudo, sum};
use crate::wire::{BROADCAST_MAC, ETHERTYPE_IPV4, Mac, USB_IP, USB_MASK, rd16, rd32, wr16, wr32, write_eth};
use tdongle_tailnet_types::{Counter, Millis};

/// The C's effective lease retention, 7200 minutes (see the module docs).
pub const C_HOLD_MS: u64 = 7200 * 60_000;
/// Lease time advertised in option 51, seconds.
pub const C_LEASE_SECS: u32 = 7200;
/// Leases kept (`CONFIG_LWIP_DHCPS_MAX_STATION_NUM`).
pub const C_TABLE: usize = 8;
/// Smallest reply frame buffer [`DhcpServer::handle_frame`] needs: 14 + 20 + 8 + 300.
pub const REPLY_BUF: usize = 342;
/// Largest client message accepted (the C drops anything over 1500).
pub const MAX_MESSAGE: usize = 1500;

const MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const HEADER: usize = 240;
const MIN_REPLY_PAYLOAD: usize = 300;

const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const DECLINE: u8 = 4;
const ACK: u8 = 5;
const NAK: u8 = 6;
const RELEASE: u8 = 7;
const INFORM: u8 = 8;

/// Configuration of the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpConfig {
    /// The server's address (also the router and DNS server offered, see the fields below).
    pub server_ip: u32,
    /// The subnet mask.
    pub mask: u32,
    /// First address of the pool.
    pub pool_start: u32,
    /// Last address of the pool.
    pub pool_end: u32,
    /// Lease time advertised, seconds.
    pub lease_secs: u32,
    /// How long a lease is kept without a message from its client.
    pub hold_ms: u64,
    /// Option 3, or `None` to omit it.
    pub router: Option<u32>,
    /// Option 6.
    pub dns: u32,
    /// Option 26.
    pub mtu: u16,
    /// The server's Ethernet address (source of the replies).
    pub server_mac: Mac,
}

/// The pool `dhcps_poll_set` derives when none is configured: the larger side of the subnet around the server, at most 100 addresses.
pub const fn lwip_pool(server_ip: u32, mask: u32) -> (u32, u32) {
    let net = server_ip & mask;
    let bcast = net | !mask;
    let (start, mut end) = if server_ip - net > bcast - server_ip { (net + 1, server_ip - 1) } else { (server_ip + 1, bcast - 1) };
    if end - start + 1 > 100 {
        end = start + 99;
    }
    if end < start {
        end = start;
    }
    (start, end)
}

impl DhcpConfig {
    /// The C gateway's configuration, for a dongle whose USB netif has `server_mac`.
    pub const fn c(server_mac: Mac) -> DhcpConfig {
        let (pool_start, pool_end) = lwip_pool(USB_IP, USB_MASK);
        DhcpConfig {
            server_ip: USB_IP,
            mask: USB_MASK,
            pool_start,
            pool_end,
            lease_secs: C_LEASE_SECS,
            hold_ms: C_HOLD_MS,
            router: Some(USB_IP),
            dns: USB_IP,
            mtu: 1500,
            server_mac,
        }
    }
    fn pool_size(&self) -> u32 {
        self.pool_end.wrapping_sub(self.pool_start).wrapping_add(1)
    }
    fn in_pool(&self, ip: u32) -> bool {
        ip >= self.pool_start && ip <= self.pool_end
    }
    fn broadcast(&self) -> u32 {
        (self.server_ip & self.mask) | !self.mask
    }
}

/// The kind of reply produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyKind {
    /// DHCPOFFER.
    Offer,
    /// DHCPACK to a REQUEST.
    Ack,
    /// DHCPNAK.
    Nak,
    /// DHCPACK to an INFORM (no address, no lease time).
    InformAck,
}

impl ReplyKind {
    const fn index(self) -> usize {
        match self {
            ReplyKind::Offer => 0,
            ReplyKind::Ack => 1,
            ReplyKind::Nak => 2,
            ReplyKind::InformAck => 3,
        }
    }
}

/// Why no reply was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Silent {
    /// Not an IPv4 frame, or a header that fails validation (length, version, checksum).
    BadFrame,
    /// An IP fragment.
    Fragment,
    /// Not UDP to port 67.
    NotDhcp,
    /// UDP length or checksum wrong.
    BadUdp,
    /// Shorter than the 240-byte BOOTP header with the cookie.
    TooShort,
    /// Longer than [`MAX_MESSAGE`].
    TooLong,
    /// `op` is not BOOTREQUEST.
    NotRequest,
    /// Hardware type is not Ethernet with a 6-byte address.
    BadHardware,
    /// Magic cookie missing.
    BadCookie,
    /// No message-type option (or a malformed option area before it).
    NoMessageType,
    /// A type a server does not receive (OFFER, ACK, NAK) or an unknown one.
    UnexpectedType,
    /// A REQUEST that names another server.
    OtherServer,
    /// `giaddr` set: relayed requests are not served.
    Relayed,
    /// The pool has no free address.
    PoolExhausted,
    /// RELEASE processed.
    Released,
    /// DECLINE processed.
    Declined,
    /// INFORM from an address outside the subnet or with `ciaddr` 0.
    InformInvalid,
    /// The output buffer is shorter than [`REPLY_BUF`].
    OutputTooSmall,
}

impl Silent {
    /// Number of variants.
    pub const COUNT: usize = 18;
    /// Dense index (exhaustive).
    pub const fn index(self) -> usize {
        match self {
            Silent::BadFrame => 0,
            Silent::Fragment => 1,
            Silent::NotDhcp => 2,
            Silent::BadUdp => 3,
            Silent::TooShort => 4,
            Silent::TooLong => 5,
            Silent::NotRequest => 6,
            Silent::BadHardware => 7,
            Silent::BadCookie => 8,
            Silent::NoMessageType => 9,
            Silent::UnexpectedType => 10,
            Silent::OtherServer => 11,
            Silent::Relayed => 12,
            Silent::PoolExhausted => 13,
            Silent::Released => 14,
            Silent::Declined => 15,
            Silent::InformInvalid => 16,
            Silent::OutputTooSmall => 17,
        }
    }
}

/// Result of handling one frame. Every frame ends as one variant and one counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum DhcpOutcome {
    /// A complete Ethernet frame of `len` bytes is in the output buffer; send it on the USB interface.
    Reply {
        /// Frame length.
        len: usize,
        /// What it is.
        kind: ReplyKind,
    },
    /// Nothing to send.
    Silent(Silent),
}

/// Counters of the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpStats {
    /// Frames offered.
    pub frames: Counter,
    /// Replies, by offer, ack, nak, inform-ack.
    pub replies: [Counter; 4],
    /// Frames that got no reply, by [`Silent::index`].
    pub silent: [Counter; Silent::COUNT],
    /// Leases created.
    pub leases_created: Counter,
    /// Leases removed to make room for a new client.
    pub leases_evicted: Counter,
    /// Leases removed after `hold_ms` of silence.
    pub leases_expired: Counter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Lease {
    mac: Mac,
    ip: u32,
    touched: Millis,
}

/// The server. `N` leases are kept (8 in the C).
pub struct DhcpServer<const N: usize> {
    cfg: DhcpConfig,
    leases: [Option<Lease>; N],
    next_off: u32,
    declined: u32,
    stats: DhcpStats,
}

impl<const N: usize> core::fmt::Debug for DhcpServer<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DhcpServer").field("leases", &self.lease_count()).finish()
    }
}

/// What the client's message asked, extracted once.
struct Msg<'a> {
    kind: u8,
    requested: u32,
    server_id: u32,
    ciaddr: u32,
    flags: u16,
    mac: Mac,
    raw: &'a [u8],
}

/// Walk the option area (bounded, as the C does: a length that overruns ends the scan, keeping what was found).
fn scan_options(opts: &[u8]) -> (u8, u32, u32) {
    let (mut kind, mut requested, mut server) = (0u8, 0u32, 0u32);
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => {
                i += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        if i + 1 >= opts.len() {
            break;
        }
        let code = opts[i];
        let len = usize::from(opts[i + 1]);
        if i + 2 + len > opts.len() {
            break;
        }
        let body = &opts[i + 2..i + 2 + len];
        match code {
            53 if len >= 1 && kind == 0 => kind = body[0],
            50 if len >= 4 => requested = rd32(body, 0),
            54 if len >= 4 => server = rd32(body, 0),
            _ => {}
        }
        i += 2 + len;
    }
    (kind, requested, server)
}

impl<const N: usize> DhcpServer<N> {
    /// Size of the server state in bytes.
    pub const STATE_BYTES: usize = core::mem::size_of::<Self>();

    /// A server with no leases.
    pub fn new(cfg: DhcpConfig) -> Self {
        const { assert!(N > 0) };
        DhcpServer {
            cfg,
            leases: [None; N],
            next_off: 0,
            declined: 0,
            stats: DhcpStats {
                frames: Counter(0),
                replies: [Counter(0); 4],
                silent: [Counter(0); Silent::COUNT],
                leases_created: Counter(0),
                leases_evicted: Counter(0),
                leases_expired: Counter(0),
            },
        }
    }

    /// The configuration.
    pub fn config(&self) -> &DhcpConfig {
        &self.cfg
    }
    /// The counters.
    pub fn stats(&self) -> &DhcpStats {
        &self.stats
    }
    /// Leases held.
    pub fn lease_count(&self) -> usize {
        self.leases.iter().flatten().count()
    }
    /// The address leased to `mac`, if any (`dhcp_search_ip_on_mac`).
    pub fn lease_of(&self, mac: &Mac) -> Option<u32> {
        self.leases.iter().flatten().find(|l| &l.mac == mac).map(|l| l.ip)
    }
    /// The leases as `(mac, ip)`.
    pub fn leases(&self) -> impl Iterator<Item = (Mac, u32)> + '_ {
        self.leases.iter().flatten().map(|l| (l.mac, l.ip))
    }

    fn expire(&mut self, now: Millis) {
        for s in &mut self.leases {
            if matches!(s, Some(l) if now.saturating_sub(l.touched) > self.cfg.hold_ms) {
                *s = None;
                self.stats.leases_expired.bump();
            }
        }
    }
    fn slot_of_mac(&self, mac: &Mac) -> Option<usize> {
        self.leases.iter().position(|s| matches!(s, Some(l) if &l.mac == mac))
    }
    fn ip_taken(&self, ip: u32) -> bool {
        self.leases.iter().flatten().any(|l| l.ip == ip)
    }
    fn release_mac(&mut self, mac: &Mac) {
        if let Some(i) = self.slot_of_mac(mac) {
            self.leases[i] = None;
        }
    }
    /// A slot for a new lease: a free one, else the least recently heard from is evicted.
    fn free_slot(&mut self) -> usize {
        if let Some(i) = self.leases.iter().position(Option::is_none) {
            return i;
        }
        let mut oldest = 0;
        for (i, s) in self.leases.iter().enumerate() {
            if let (Some(a), Some(b)) = (s, &self.leases[oldest])
                && a.touched < b.touched
            {
                oldest = i;
            }
        }
        self.stats.leases_evicted.bump();
        self.leases[oldest] = None;
        oldest
    }
    fn add_lease(&mut self, now: Millis, mac: Mac, ip: u32) -> usize {
        let i = self.free_slot();
        self.leases[i] = Some(Lease { mac, ip, touched: now });
        self.stats.leases_created.bump();
        i
    }
    /// The next free pool address after the last one handed out (wrapping), skipping an address just declined.
    fn pick_address(&mut self) -> Option<u32> {
        let size = self.cfg.pool_size();
        if size == 0 || size > 65_536 {
            return None;
        }
        for pass in 0..2 {
            for k in 0..size {
                let off = (self.next_off + k) % size;
                let ip = self.cfg.pool_start + off;
                if self.ip_taken(ip) || (pass == 0 && ip == self.declined) {
                    continue;
                }
                self.next_off = (off + 1) % size;
                return Some(ip);
            }
        }
        None
    }

    /// Handle one Ethernet frame received on the USB interface. If it is a DHCP request for this server, build the answer into `out`
    /// (at least [`REPLY_BUF`] bytes) and return [`DhcpOutcome::Reply`].
    pub fn handle_frame(&mut self, now: Millis, frame: &[u8], out: &mut [u8]) -> DhcpOutcome {
        self.stats.frames.bump();
        let o = self.handle_inner(now, frame, out);
        match o {
            DhcpOutcome::Reply { kind, .. } => self.stats.replies[kind.index()].bump(),
            DhcpOutcome::Silent(s) => self.stats.silent[s.index()].bump(),
        }
        o
    }

    fn handle_inner(&mut self, now: Millis, frame: &[u8], out: &mut [u8]) -> DhcpOutcome {
        use DhcpOutcome::Silent as S;
        if out.len() < REPLY_BUF {
            return S(Silent::OutputTooSmall);
        }
        if frame.len() < 14 + 20 + 8 || rd16(frame, 12) != ETHERTYPE_IPV4 {
            return S(Silent::BadFrame);
        }
        let src_mac: Mac = [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]];
        let ip = &frame[14..];
        let ihl = usize::from(ip[0] & 15) * 4;
        let total = usize::from(rd16(ip, 2));
        if ip[0] >> 4 != 4 || ihl < 20 || total < ihl + 8 || total > ip.len() || finish(sum(&ip[..ihl], 0)) != 0 {
            return S(Silent::BadFrame);
        }
        if rd16(ip, 6) & 0x3fff != 0 {
            return S(Silent::Fragment);
        }
        if ip[9] != 17 {
            return S(Silent::NotDhcp);
        }
        let udp = &ip[ihl..total];
        if rd16(udp, 2) != 67 {
            return S(Silent::NotDhcp);
        }
        let ulen = usize::from(rd16(udp, 4));
        if ulen < 8 || ulen > udp.len() {
            return S(Silent::BadUdp);
        }
        let udp = &udp[..ulen];
        if rd16(udp, 6) != 0 && finish(sum(udp, pseudo(rd32(ip, 12), rd32(ip, 16), 17, ulen as u16))) != 0 {
            return S(Silent::BadUdp);
        }
        let msg = &udp[8..];
        if msg.len() > MAX_MESSAGE {
            return S(Silent::TooLong);
        }
        if msg.len() < HEADER {
            return S(Silent::TooShort);
        }
        if msg[0] != 1 {
            return S(Silent::NotRequest);
        }
        if msg[1] != 1 || msg[2] != 6 {
            return S(Silent::BadHardware);
        }
        if msg[236..240] != MAGIC {
            return S(Silent::BadCookie);
        }
        if rd32(msg, 24) != 0 {
            return S(Silent::Relayed);
        }
        let (kind, requested, server_id) = scan_options(&msg[HEADER..]);
        if kind == 0 {
            return S(Silent::NoMessageType);
        }
        let m = Msg {
            kind,
            requested,
            server_id,
            ciaddr: rd32(msg, 12),
            flags: rd16(msg, 10),
            mac: [msg[28], msg[29], msg[30], msg[31], msg[32], msg[33]],
            raw: msg,
        };
        self.expire(now);
        self.decide(now, &m, src_mac, out)
    }

    fn decide(&mut self, now: Millis, m: &Msg<'_>, src_mac: Mac, out: &mut [u8]) -> DhcpOutcome {
        use DhcpOutcome::Silent as S;
        match m.kind {
            DISCOVER => {
                let slot = match self.slot_of_mac(&m.mac) {
                    Some(i) => i,
                    None => {
                        let Some(ip) = self.pick_address() else { return S(Silent::PoolExhausted) };
                        self.add_lease(now, m.mac, ip)
                    }
                };
                let ip = match &mut self.leases[slot] {
                    Some(l) => {
                        l.touched = now;
                        l.ip
                    }
                    None => return S(Silent::PoolExhausted),
                };
                self.reply(m, ReplyKind::Offer, ip, src_mac, out)
            }
            REQUEST => {
                if m.server_id != 0 && m.server_id != self.cfg.server_ip {
                    return S(Silent::OtherServer);
                }
                let target = if m.requested != 0 { m.requested } else { m.ciaddr };
                if target == 0 {
                    self.release_mac(&m.mac);
                    return self.reply(m, ReplyKind::Nak, 0, src_mac, out);
                }
                match self.slot_of_mac(&m.mac) {
                    Some(i) if self.leases[i].is_some_and(|l| l.ip == target) => {
                        if let Some(l) = &mut self.leases[i] {
                            l.touched = now;
                        }
                        self.reply(m, ReplyKind::Ack, target, src_mac, out)
                    }
                    Some(_) => {
                        self.release_mac(&m.mac);
                        self.reply(m, ReplyKind::Nak, 0, src_mac, out)
                    }
                    None if self.cfg.in_pool(target) && !self.ip_taken(target) => {
                        self.add_lease(now, m.mac, target);
                        self.reply(m, ReplyKind::Ack, target, src_mac, out)
                    }
                    None => self.reply(m, ReplyKind::Nak, 0, src_mac, out),
                }
            }
            RELEASE => {
                self.release_mac(&m.mac);
                S(Silent::Released)
            }
            DECLINE => {
                if let Some(i) = self.slot_of_mac(&m.mac) {
                    self.declined = self.leases[i].map_or(0, |l| l.ip);
                    self.leases[i] = None;
                }
                if m.requested != 0 {
                    self.declined = m.requested;
                }
                S(Silent::Declined)
            }
            INFORM => {
                if m.ciaddr == 0 || m.ciaddr & self.cfg.mask != self.cfg.server_ip & self.cfg.mask {
                    return S(Silent::InformInvalid);
                }
                self.reply(m, ReplyKind::InformAck, 0, src_mac, out)
            }
            _ => S(Silent::UnexpectedType),
        }
    }

    /// Build the reply frame.
    fn reply(&self, m: &Msg<'_>, kind: ReplyKind, yiaddr: u32, src_mac: Mac, out: &mut [u8]) -> DhcpOutcome {
        let cfg = &self.cfg;
        // Destination: dhcps_response_ip_set (with static ARP entries) and send_nak.
        let (dst_ip, dst_mac) = match kind {
            ReplyKind::Nak => (u32::MAX, BROADCAST_MAC),
            ReplyKind::InformAck => (m.ciaddr, src_mac),
            ReplyKind::Offer | ReplyKind::Ack => {
                if m.ciaddr != 0 {
                    (m.ciaddr, m.mac)
                } else if m.flags & 0x8000 == 0 {
                    (yiaddr, m.mac)
                } else {
                    (u32::MAX, BROADCAST_MAC)
                }
            }
        };
        let o = &mut out[..REPLY_BUF];
        o.fill(0);
        write_eth(o, dst_mac, cfg.server_mac, ETHERTYPE_IPV4);
        let p = 14 + 20 + 8; // BOOTP starts here
        {
            let b = &mut o[p..];
            b[0] = 2;
            b[1] = 1;
            b[2] = 6;
            b[4..8].copy_from_slice(&m.raw[4..8]); // xid
            b[10..12].copy_from_slice(&m.raw[10..12]); // flags
            if kind == ReplyKind::InformAck {
                wr32(b, 12, m.ciaddr);
            }
            wr32(b, 16, yiaddr);
            b[28..44].copy_from_slice(&m.raw[28..44]); // chaddr
            b[236..240].copy_from_slice(&MAGIC);
        }
        let mut n = HEADER;
        {
            let b = &mut o[p..];
            let mut put = |bytes: &[u8]| {
                b[n..n + bytes.len()].copy_from_slice(bytes);
                n += bytes.len();
            };
            let ty = match kind {
                ReplyKind::Offer => OFFER,
                ReplyKind::Ack | ReplyKind::InformAck => ACK,
                ReplyKind::Nak => NAK,
            };
            put(&[53, 1, ty]);
            if kind != ReplyKind::Nak {
                put(&[1, 4]);
                put(&cfg.mask.to_be_bytes());
                if kind != ReplyKind::InformAck {
                    put(&[51, 4]);
                    put(&cfg.lease_secs.to_be_bytes());
                }
            }
            put(&[54, 4]);
            put(&cfg.server_ip.to_be_bytes());
            if kind != ReplyKind::Nak {
                if let Some(r) = cfg.router {
                    put(&[3, 4]);
                    put(&r.to_be_bytes());
                }
                put(&[6, 4]);
                put(&cfg.dns.to_be_bytes());
                put(&[28, 4]);
                put(&cfg.broadcast().to_be_bytes());
                put(&[26, 2]);
                put(&cfg.mtu.to_be_bytes());
                put(&[31, 1, 0]);
                put(&[43, 6, 1, 4, 0, 0, 0, 2]);
            }
            put(&[255]);
        }
        let payload = n.max(MIN_REPLY_PAYLOAD);
        let udp_len = 8 + payload;
        let total = 20 + udp_len;
        {
            let ip = &mut o[14..14 + total];
            ip[0] = 0x45;
            wr16(ip, 2, total as u16);
            ip[8] = 64;
            ip[9] = 17;
            wr32(ip, 12, cfg.server_ip);
            wr32(ip, 16, dst_ip);
            fill_header(ip, 20);
            wr16(ip, 20, 67);
            wr16(ip, 22, 68);
            wr16(ip, 24, udp_len as u16);
            let mut c = finish(sum(&ip[20..], pseudo(cfg.server_ip, dst_ip, 17, udp_len as u16)));
            if c == 0 {
                c = 0xffff;
            }
            wr16(ip, 26, c);
        }
        DhcpOutcome::Reply { len: 14 + total, kind }
    }
}
