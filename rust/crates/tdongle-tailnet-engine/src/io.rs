//! The engine's interface: inputs in, outputs out. No I/O, no clock, no entropy inside.
//!
//! One call, [`crate::Engine::handle`], takes one [`Input`] and may call [`Output::emit`] any number of times (each with a borrowed [`Out`]); the last
//! `emit` of every call is [`Out::Wake`]: the ONE time the runtime must call `handle(.., Input::Tick, ..)` next if nothing else happens first.

use tdongle_tailnet_disco::Ep;
use tdongle_tailnet_disco::stun_sched::SockKind;
use tdongle_tailnet_dns::Client;
use tdongle_tailnet_map::types::{DerpMap, DnsConfig, PeerRecord, SelfNode};
use tdongle_tailnet_types::{FixedStr, Key32, Millis};

/// A membership's id as the router and the control plane know it (nonzero, never reused). Not a slot index.
pub type MemberId = u32;

/// Longest membership label the engine keeps (the DNS label of `<peer>.<label>.tailnet`).
pub const LABEL_MAX: usize = 31;

/// What the runtime tells the engine when it creates a membership. The node key IS the WireGuard key; the machine key is the control plane's and only
/// kept for the status snapshot (never used here).
#[derive(Clone)]
pub struct MemberConfig {
    /// Router membership id.
    pub id: MemberId,
    /// WireGuard (node) private key.
    pub node_private: Key32,
    /// DISCO private key.
    pub disco_private: Key32,
    /// DNS label of the membership (`<peer>.<label>.tailnet`).
    pub label: FixedStr<LABEL_MAX>,
    /// The peer that is never evicted (`config.priority_peer_ip`), 0 = none.
    pub priority_peer_ip: u32,
    /// Persistent keepalive for every peer, seconds (0 = off).
    pub persistent_keepalive_s: u16,
    /// Start enabled.
    pub enabled: bool,
}

impl core::fmt::Debug for MemberConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MemberConfig(id={}, label={})", self.id, self.label)
    }
}

/// An owned map event (what [`crate::NetmapSink`] translates the projector's borrowed events into, so a control task can queue them for the engine task).
#[derive(Clone, Debug)]
pub enum NetmapEvent {
    /// A staged peer update (add, remove, patch).
    Peer(PeerRecord),
    /// The self node (at commit time).
    SelfNode(SelfNode),
    /// The DERP regions.
    Derp(DerpMap),
    /// The DNS configuration (the engine keeps the first search domain).
    Dns(DnsConfig),
    /// The tailnet's MagicDNS domain.
    Domain(FixedStr<63>),
    /// The control plane's clock reading (Unix seconds, nanoseconds): the engine derives the wall clock for TAI64N timestamps from it.
    ControlTime {
        /// Seconds.
        secs: i64,
        /// Nanoseconds.
        nanos: u32,
    },
    /// Apply what was staged. `authoritative`: the map carried the whole peer list. `self_expired`: the node key expired.
    Commit {
        /// The map was the whole truth.
        authoritative: bool,
        /// The node's key expired.
        self_expired: bool,
    },
    /// Discard what was staged.
    Abort,
}

/// What a runtime-owned DERP link reports to the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerpNote {
    /// The link is ready to relay.
    Connected,
    /// The link left ready.
    Disconnected,
    /// An attempt failed.
    ConnectFailed,
}

/// One input.
#[derive(Debug)]
pub enum Input<'a> {
    /// An IPv4 packet from the USB host, already de-framed. `buf[..len]` is the packet; it is rewritten in place (the ICMP reply is built in it).
    HostPacket {
        /// The packet buffer (at least `len` bytes; 1500 recommended).
        buf: &'a mut [u8],
        /// The packet's length.
        len: usize,
    },
    /// A datagram on member `member`'s UDP socket (DISCO, WireGuard or STUN, told apart by the first bytes as the C's `net_io` does). Decrypted in place.
    Udp {
        /// The membership whose socket received it.
        member: MemberId,
        /// Where it came from.
        src: Ep,
        /// The datagram.
        data: &'a mut [u8],
    },
    /// A packet the member's DERP link delivered (`Action::DeliverPacket`).
    DerpPacket {
        /// The membership.
        member: MemberId,
        /// The sender's node key.
        src: &'a [u8; 32],
        /// The packet.
        data: &'a mut [u8],
    },
    /// The DERP link of `member` changed state.
    DerpLinkEvent {
        /// The membership.
        member: MemberId,
        /// What happened.
        event: DerpNote,
    },
    /// A map event of `member`.
    Netmap {
        /// The membership.
        member: MemberId,
        /// The event.
        event: &'a NetmapEvent,
    },
    /// A DNS query from the USB host (192.168.77.1:53).
    Dns {
        /// The asking host.
        client: Client,
        /// The query.
        data: &'a [u8],
    },
    /// A reply on the upstream resolver socket.
    DnsUpstreamReply {
        /// The reply (the transaction id is restored in place).
        data: &'a mut [u8],
    },
    /// The Wi-Fi-provided resolver (host-order IPv4), or none.
    DnsUpstream(Option<u32>),
    /// Create a membership.
    MemberAdded(&'a MemberConfig),
    /// Start (or restart) a membership.
    MemberEnabled {
        /// The membership.
        member: MemberId,
    },
    /// Stop a membership: router suspended, WireGuard slots released, parked packets dropped; the netmap is kept.
    MemberDisabled {
        /// The membership.
        member: MemberId,
    },
    /// Destroy a membership (the ADR 0013 detach order, see [`crate::Engine`]).
    MemberRemoved {
        /// The membership.
        member: MemberId,
    },
    /// The member's own UDP endpoints changed (local interface addresses; the STUN-learned public one is kept by the engine).
    EndpointsChanged {
        /// The membership.
        member: MemberId,
        /// Local endpoints (at most four are kept).
        endpoints: &'a [Ep],
    },
    /// Is the wall clock plausibly set? (Passed on to nothing here but the status snapshot and the DERP glue; WireGuard timestamps never fail on it.)
    ClockValid(bool),
    /// The USB link went away: every flow and held packet of the old link is stale.
    UsbDetach,
    /// Time passed (or the wake deadline was reached).
    Tick,
}

/// Which negotiation-token phase a member wants (`ml_negotiation.h` phases that the engine's own work can ask for).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenPhase {
    /// The DERP link's TLS negotiation.
    Derp,
}

/// One output. Borrowed from the engine's scratch buffers: copy it before returning if it must outlive the call.
#[derive(Debug)]
pub enum Out<'a> {
    /// Send `data` from member `member`'s UDP socket to `dst`.
    SendUdp {
        /// The membership.
        member: MemberId,
        /// Destination.
        dst: Ep,
        /// The datagram.
        data: &'a [u8],
    },
    /// Send a STUN request (`sock` says which socket it leaves from; `Disco4` and `Netcheck` are the member's UDP socket).
    SendStun {
        /// The membership.
        member: MemberId,
        /// Which socket.
        sock: SockKind,
        /// Destination.
        dst: Ep,
        /// The 40-byte request.
        data: &'a [u8],
    },
    /// Queue `data` on the member's DERP link for the peer with node key `dst` (`Link::send_packet`).
    DerpSend {
        /// The membership.
        member: MemberId,
        /// The peer's node key.
        dst: &'a [u8; 32],
        /// The peer's home DERP region (0: not known; the member's own relay then). A relay server only forwards to clients connected to it, so the packet has to go to the region
        /// the peer is homed on.
        region: u16,
        /// The packet.
        data: &'a [u8],
    },
    /// An IPv4 packet for the USB host.
    HostPacket {
        /// The packet.
        data: &'a [u8],
    },
    /// A DNS answer for `client`.
    DnsAnswer {
        /// The asking host.
        client: Client,
        /// The answer.
        data: &'a [u8],
    },
    /// A DNS query to forward to the upstream resolver.
    DnsForward {
        /// The resolver, host-order IPv4.
        upstream: u32,
        /// The query.
        data: &'a [u8],
        /// The runtime should reopen the upstream socket first.
        reset_socket: bool,
    },
    /// The membership's DERP link should connect to this node (the home region changed or the first map arrived).
    DerpConnect {
        /// The membership.
        member: MemberId,
        /// Region id.
        region: u16,
        /// Host name of the region's first node.
        host: &'a str,
        /// TCP port.
        port: u16,
    },
    /// The membership's DERP link should close (disabled or removed).
    DerpClose {
        /// The membership.
        member: MemberId,
    },
    /// The control plane should be told the home DERP region (`PreferredDERP`).
    HomeDerp {
        /// The membership.
        member: MemberId,
        /// Region id.
        region: u16,
    },
    /// STUN learned (or changed) the public endpoint; the control plane wants it in its next endpoint update.
    EndpointLearned {
        /// The membership.
        member: MemberId,
        /// The public endpoint.
        ep: Ep,
    },
    /// The membership needs the global negotiation token for `phase` (bridge to `tdongle_tailnet_admission::negotiation`).
    WantToken {
        /// The membership.
        member: MemberId,
        /// Why.
        phase: TokenPhase,
    },
    /// The membership gives the token back.
    ReleaseToken {
        /// The membership.
        member: MemberId,
    },
    /// A membership became ready for traffic (or stopped being).
    MemberReady {
        /// The membership.
        member: MemberId,
        /// Ready now?
        ready: bool,
    },
    /// A removed membership is completely gone (nothing of it is left in the engine).
    MemberGone {
        /// The membership.
        member: MemberId,
    },
    /// The next time the runtime must call `handle(.., Input::Tick, ..)` (`None`: nothing is scheduled). Emitted last in every call.
    Wake(Option<Millis>),
}

/// Where outputs go. Return `false` to refuse the output (a full queue): the engine counts it and the packet ends as `TxRefused` / `HostTxRefused`.
/// Closures implement it.
pub trait Output {
    /// Take one output.
    fn emit(&mut self, o: Out<'_>) -> bool;
}

impl<F: FnMut(Out<'_>) -> bool> Output for F {
    fn emit(&mut self, o: Out<'_>) -> bool {
        self(o)
    }
}

/// An output sink that accepts and discards everything.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullOutput;
impl Output for NullOutput {
    fn emit(&mut self, _: Out<'_>) -> bool {
        true
    }
}
