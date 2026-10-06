//! One membership's DERP connection as a sans-IO state machine (`ml_derp_link.c`).
//!
//! ADR 0013: one task serves every membership, which is only sound if no step of a link can wait on its server. The link therefore never blocks and
//! never owns a socket: the driver feeds it [`Event`]s (a DNS answer, a connect result, TLS done, bytes that arrived, a write that finished, the clock)
//! and carries out the [`Action`]s it emits through a [`Sink`]. Every wait has a deadline kept in the link: a record that started must finish within
//! [`Timing::rx_frame_ms`], a write that makes no progress for [`Timing::tx_stall_ms`] is a dead link, a connect attempt ends after
//! [`Timing::connect_ms`], so one dead server costs its own membership a reconnect and nobody else anything.
//!
//! ```text
//!  Idle -> Waiting -> Token -> Dns -> Connecting -> Tls -> Upgrade -> ServerKey -> ClientInfo -> ServerInfo -> Ready
//!            ^  (retry ladder,  |  Action::WantToken   Dial   Connected   StartTls   Send(GET /derp)         Send(ClientInfo)         NotePreferred
//!            |   wall clock)    |  Event::TokenGranted Dns    Connected   TlsDone    Bytes(101 ... ServerKey)  TxDone                  Bytes(ServerInfo)
//!            +------------------+------------------------------ any failure: Close, ReleaseToken, back off ------------------------------+
//! ```
//!
//! # Driver contract
//!
//! * `Action::Send(bytes)`: write all of `bytes` to the stream (the TLS session once the upgrade started). The bytes stay valid until the next call
//!   into the link. Exactly one send is outstanding at a time. Report [`Event::TxProgress`] whenever some bytes were accepted and [`Event::TxDone`]
//!   when all were; a send that sees no progress for `tx_stall_ms` kills the link. The driver copies or starts writing before returning.
//! * Deliver [`Event::TxDone`] before any [`Event::Bytes`] read after that write completed (a reply cannot precede its request, so a driver that
//!   reports in causal order satisfies this; a violation is counted in `order_errors` and drops the link).
//! * `Bytes` may be cut at any boundary. The link bounds its own work per call by the size of the chunk; slice the transport reads to bound the time.
//! * Call [`Link::next_deadline_ms`] after every call and arrange an [`Event::Timer`] that late. There is no fixed polling period.
//! * [`Event::ClockValid`] tells the link whether the wall clock is set (certificates cannot be judged without it). It starts false.
//! * The negotiation token (`ml_negotiation.h`): the link emits [`Action::WantToken`] on entering the token state and [`Link::want_token`] stays true
//!   until the driver reports [`Event::TokenGranted`]. The link emits [`Action::ReleaseToken`] at ready and on any teardown while it holds the token.
//!   A grant that arrives when the link no longer wants it is answered with an immediate `ReleaseToken`.

use crate::frame::{FrameInfo, FrameReader, FrameType, Poll, ReadError, encode_header};
use crate::handshake::{self, ServerInfo, UpgradeScanner, UpgradeStatus};
use crate::message::{Message, PeerGoneReason};
use crate::pace::Pace;
use crate::txq::{TxDrop, TxPolicy, TxQueue};
use crate::{FRAME_HEADER_LEN, KEY_LEN, NONCE_LEN, PONG_MAX};
use tdongle_tailnet_crypto::x25519;
use tdongle_tailnet_types::{Counter, Entropy, FixedStr, Key32, Millis};

/// Where to dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The DERP region id (for the driver's bookkeeping and logs).
    pub region: u16,
    /// The node's `HostName`: DNS name, SNI and `Host:` header.
    pub host: FixedStr<64>,
    /// TCP port (443 unless the DERPNode says otherwise).
    pub port: u16,
}

impl Target {
    /// A target; the host is cut at 64 bytes.
    pub fn new(region: u16, host: &str, port: u16) -> Self {
        let mut h = FixedStr::new();
        h.set(host);
        Self { region, host: h, port }
    }
}

/// Every deadline and the retry shape. [`Timing::DEFAULT`] is the C's values (`ml_derp_link.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// A record that started must finish within this (`ML_DERP_RX_FRAME_MS`).
    pub rx_frame_ms: u32,
    /// A write that makes no progress for this long is a dead link (`ML_DERP_TX_STALL_MS`).
    pub tx_stall_ms: u32,
    /// One handshake phase: upgrade, ServerKey, ServerInfo (`ML_DERP_PHASE_MS`).
    pub phase_ms: u32,
    /// The whole attempt, token granted to ready (`ML_DERP_CONNECT_MS`).
    pub connect_ms: u32,
    /// Nothing received at all (`ML_DERP_STALE_MS`; server keepalives come every 15 to 60 s).
    pub stale_ms: u32,
    /// First rung of the retry ladder.
    pub retry_min_ms: u32,
    /// Ceiling of the retry ladder.
    pub retry_max_ms: u32,
    /// Quick retries after a first connect request before the ladder.
    pub connect_burst: u8,
    /// Gap between those.
    pub connect_gap_ms: u32,
    /// Delay before the redial of an established relay that dropped or was asked to reconnect.
    pub flap_delay_ms: u32,
    /// Quick retries after such a drop.
    pub flap_burst: u8,
    /// Gap between those.
    pub flap_gap_ms: u32,
}

impl Timing {
    /// The C's values: 5 s record, 3 s write, 10 s phase, 30 s attempt, 90 s stale, 5 to 60 s ladder, three attempts 2 s apart on a first connect,
    /// 200 ms then three attempts 500 ms apart after a flap.
    pub const DEFAULT: Timing = Timing {
        rx_frame_ms: 5000,
        tx_stall_ms: 3000,
        phase_ms: 10_000,
        connect_ms: 30_000,
        stale_ms: 90_000,
        retry_min_ms: 5000,
        retry_max_ms: 60_000,
        connect_burst: 2,
        connect_gap_ms: 2000,
        flap_delay_ms: 200,
        flap_burst: 2,
        flap_gap_ms: 500,
    };
}

impl Default for Timing {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The link's state (`ml_derp_link_state_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// Not wanted.
    Idle,
    /// Wanted; backoff, burst spacing or the wall clock.
    Waiting,
    /// Wanted and ready; waiting for the negotiation token.
    Token,
    /// Resolving the host.
    Dns,
    /// TCP connect.
    Connecting,
    /// TLS handshake.
    Tls,
    /// `GET /derp` sent, waiting for the 101.
    Upgrade,
    /// Waiting for the ServerKey frame.
    ServerKey,
    /// Our ClientInfo frame is going out.
    ClientInfo,
    /// Waiting for the ServerInfo frame.
    ServerInfo,
    /// Relaying.
    Ready,
}

impl State {
    /// A short name for the status output (`ml_derp_link_state_name`).
    pub fn name(self) -> &'static str {
        match self {
            State::Idle => "idle",
            State::Waiting => "waiting",
            State::Token => "token",
            State::Dns => "dns",
            State::Connecting => "connecting",
            State::Tls => "tls",
            State::Upgrade => "upgrade",
            State::ServerKey => "server_key",
            State::ClientInfo => "client_info",
            State::ServerInfo => "server_info",
            State::Ready => "ready",
        }
    }

    /// True from the token grant until ready: an attempt is in flight (the span `ml_derp_link_busy` calls work that wants a fast CPU).
    pub fn is_connecting(self) -> bool {
        self >= State::Dns && self < State::Ready
    }
}

/// What the link reports to its owner (`ml_derp_event_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkEvent {
    /// Ready entered.
    Connected,
    /// Ready left.
    Disconnected,
    /// An attempt ended before ready.
    ConnectFailed,
    /// The staleness watchdog fired (also followed by `Disconnected`).
    RxStale,
    /// The first attempt is held back for the wall clock.
    ClockDeferred,
}

/// An input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// The control plane wants a relay (`ML_EVT_DERP_CONNECT_REQ`).
    Connect,
    /// Drop the current connection and dial again (`ML_EVT_DERP_RECONNECT`).
    Reconnect,
    /// Tear down and stop wanting a relay. Idempotent.
    Close,
    /// Is the wall clock plausibly set?
    ClockValid(bool),
    /// The negotiation token was granted to this link.
    TokenGranted,
    /// The name resolved (`true`) or did not.
    Dns(bool),
    /// The TCP connection is up (`true`) or failed.
    Connected(bool),
    /// The TLS handshake finished (`true`) or failed.
    TlsDone(bool),
    /// Bytes arrived on the stream, in any chunking.
    Bytes(&'a [u8]),
    /// Some bytes of the outstanding send were accepted.
    TxProgress,
    /// The outstanding send was written in full.
    TxDone,
    /// Time passed; nothing else happened.
    Timer,
}

/// An output the driver carries out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action<'a> {
    /// Something the owner wants to know.
    Notify(LinkEvent),
    /// The link wants the negotiation token: report [`Event::TokenGranted`] when it is granted.
    WantToken,
    /// Resolve `host`, connect to `port`, and report [`Event::Dns`] then [`Event::Connected`].
    Dial {
        /// The region id.
        region: u16,
        /// Host name.
        host: &'a str,
        /// TCP port.
        port: u16,
    },
    /// Start the TLS handshake with SNI `host`; report [`Event::TlsDone`].
    StartTls {
        /// Server name.
        host: &'a str,
    },
    /// Write all of these bytes (see the module's driver contract).
    Send(&'a [u8]),
    /// Close the transport. Idempotent for the driver.
    Close,
    /// Give the negotiation token back.
    ReleaseToken,
    /// A relayed packet from `src_key`. The payload is valid for the duration of the call only.
    DeliverPacket {
        /// The sender's node key.
        src_key: &'a [u8; KEY_LEN],
        /// The packet.
        payload: &'a [u8],
    },
    /// A peer is gone from this server.
    PeerGone {
        /// The peer.
        peer: &'a [u8; KEY_LEN],
        /// Why.
        reason: PeerGoneReason,
    },
    /// The server's health message (empty = healthy).
    Health(&'a [u8]),
    /// The server will restart; the link does not act on this itself (its own retry ladder reconnects).
    ServerRestarting {
        /// Advisory.
        reconnect_in_ms: u32,
        /// Advisory.
        try_for_ms: u32,
    },
}

/// Where actions go. Closures implement it.
pub trait Sink {
    /// Take one action.
    fn action(&mut self, a: Action<'_>);
}

impl<F: FnMut(Action<'_>)> Sink for F {
    fn action(&mut self, a: Action<'_>) {
        self(a)
    }
}

/// Every count the link keeps. Nothing is dropped silently (ADR 0001 rule 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Frames received and dispatched.
    pub frames_rx: Counter,
    /// Frames written in full (relay phase).
    pub frames_tx: Counter,
    /// Times ready was reached.
    pub connects: Counter,
    /// Attempts that ended before ready.
    pub connect_failures: Counter,
    /// A record or the ServerKey/ServerInfo phase timed out.
    pub rx_timeouts: Counter,
    /// A write made no progress for `tx_stall_ms`.
    pub tx_stalls: Counter,
    /// A frame length beyond the bounds.
    pub oversize: Counter,
    /// A relayed packet read off the wire and dropped because the admission hook refused it.
    pub rx_refused: Counter,
    /// A malformed handshake or response.
    pub protocol_errors: Counter,
    /// The staleness watchdog fired.
    pub stale: Counter,
    /// Server pings answered.
    pub pings_answered: Counter,
    /// Server pings not answered (short, long, or a control frame was already queued).
    pub pings_dropped: Counter,
    /// Relay packets refused by `send_packet`: not ready.
    pub tx_drop_not_ready: Counter,
    /// ... larger than [`crate::MAX_FRAME`].
    pub tx_drop_too_big: Counter,
    /// ... over the soft byte budget.
    pub tx_drop_over_budget: Counter,
    /// ... no room in the ring.
    pub tx_drop_no_space: Counter,
    /// Queued packets discarded when the connection went away.
    pub tx_flushed: Counter,
    /// KeepAlive frames.
    pub keepalives: Counter,
    /// Pong frames.
    pub pongs_rx: Counter,
    /// Frames of a type we do not know, skipped.
    pub unknown_frames: Counter,
    /// Frames of a known type too short to use, skipped.
    pub malformed_frames: Counter,
    /// A ServerInfo whose box did not open.
    pub server_info_bad: Counter,
    /// An event that does not apply in the current state, ignored.
    pub stray_events: Counter,
    /// Bytes that arrived in a state that reads none (before the upgrade request was written), dropped.
    pub stray_bytes: Counter,
    /// A driver ordering violation (see the module's contract).
    pub order_errors: Counter,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TxOut {
    None,
    Ctl,
    Queue,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ctl {
    None,
    Queued,
    Sending,
}

const CTL_MAX: usize = 256;

/// One membership's relay connection. `TXQ` is the byte capacity of the transmit ring.
pub struct Link<const TXQ: usize> {
    secret: Key32,
    target: Target,
    timing: Timing,
    state: State,
    wanted: bool,
    clock_valid: bool,
    pace: Pace,
    burst_left: u8,
    burst_gap_ms: u32,
    next_attempt_ms: Millis,
    connect_started_ms: Millis,
    phase_started_ms: Millis,
    last_recv_ms: Millis,
    token_held: bool,
    transport_open: bool,
    scan: UpgradeScanner,
    server_key: Key32,
    got_server_info: bool,
    server_info: ServerInfo,
    reader: FrameReader,
    rx_started: Option<Millis>,
    tx_out: TxOut,
    tx_progress_ms: Millis,
    ctl_state: Ctl,
    ctl_len: u16,
    ctl: [u8; CTL_MAX],
    txq: TxQueue<TXQ>,
    rx_admit: Option<fn(usize) -> bool>,
    stats: Stats,
}

impl<const TXQ: usize> core::fmt::Debug for Link<TXQ> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Link").field("region", &self.target.region).field("state", &self.state).field("wanted", &self.wanted).finish()
    }
}

impl<const TXQ: usize> Link<TXQ> {
    /// Bytes of the whole link (reader, transmit ring, control buffer and bookkeeping): the ADR's bytes per membership for the relay.
    pub const STATE_BYTES: usize = core::mem::size_of::<Link<TXQ>>();

    /// A link for the node key `secret` that will dial `target`. It starts idle with the wall clock marked unset.
    pub fn new(secret: Key32, target: Target, timing: Timing) -> Self {
        Self {
            secret,
            target,
            timing,
            state: State::Idle,
            wanted: false,
            clock_valid: false,
            pace: Pace::new(timing.retry_min_ms),
            burst_left: 0,
            burst_gap_ms: 0,
            next_attempt_ms: 0,
            connect_started_ms: 0,
            phase_started_ms: 0,
            last_recv_ms: 0,
            token_held: false,
            transport_open: false,
            scan: UpgradeScanner::new(),
            server_key: Key32::ZERO,
            got_server_info: false,
            server_info: ServerInfo::default(),
            reader: FrameReader::new(),
            rx_started: None,
            tx_out: TxOut::None,
            tx_progress_ms: 0,
            ctl_state: Ctl::None,
            ctl_len: 0,
            ctl: [0; CTL_MAX],
            txq: TxQueue::new(),
            rx_admit: None,
            stats: Stats::default(),
        }
    }

    /// The current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Relaying?
    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }

    /// Does the control plane want a relay?
    pub fn is_wanted(&self) -> bool {
        self.wanted
    }

    /// Counters.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// The retry ladder (for status output and tests).
    pub fn pace(&self) -> &Pace {
        &self.pace
    }

    /// What the server announced in ServerInfo (zeros before ready or when it announced nothing).
    pub fn server_info(&self) -> ServerInfo {
        self.server_info
    }

    /// The node's public key (what the server knows this client as).
    pub fn public_key(&self) -> Key32 {
        x25519::public(&self.secret)
    }

    /// Where this link dials.
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Point the link at another node. Takes effect at the next attempt.
    pub fn set_target(&mut self, target: Target) {
        self.target = target;
    }

    /// The transmit policy: soft byte budget and the small-datagram exemption (`ML_HB_RX_SMALL_BYTES`).
    pub fn set_tx_policy(&mut self, p: TxPolicy) {
        self.txq.set_policy(p);
    }

    /// Frames waiting in the transmit ring.
    pub fn tx_queued(&self) -> usize {
        self.txq.len()
    }

    /// Admission check for a relayed packet of the given payload length, asked before the packet is delivered (the heap budget, ADR 0022). False:
    /// the packet is dropped and counted in `rx_refused`; the stream stays in sync. `None` admits everything.
    pub fn set_rx_admit(&mut self, f: Option<fn(usize) -> bool>) {
        self.rx_admit = f;
    }

    /// Is the link waiting for the negotiation token?
    pub fn want_token(&self) -> bool {
        self.state == State::Token
    }

    /// An attempt is in flight (TLS, key exchange): the work that wants a fast CPU. An established idle relay does not.
    pub fn is_busy(&self) -> bool {
        self.state.is_connecting()
    }

    /// Report that the negotiation token was granted (shorthand for [`Event::TokenGranted`]).
    pub fn token_granted(&mut self, now: Millis, rng: &mut dyn Entropy, sink: &mut dyn Sink) {
        self.handle(now, Event::TokenGranted, rng, sink);
    }

    /// Queue a packet for `dest` and start sending it if the link is idle. `Err` means it was dropped and counted.
    pub fn send_packet(&mut self, now: Millis, dest: &[u8; KEY_LEN], payload: &[u8], sink: &mut dyn Sink) -> Result<(), TxDrop> {
        let r = if self.state != State::Ready { Err(TxDrop::NotReady) } else { self.txq.push_send_packet(dest, payload) };
        match r {
            Ok(()) => {
                self.pump_tx(now, sink);
                Ok(())
            }
            Err(e) => {
                match e {
                    TxDrop::NotReady => self.stats.tx_drop_not_ready.bump(),
                    TxDrop::TooBig => self.stats.tx_drop_too_big.bump(),
                    TxDrop::OverBudget => self.stats.tx_drop_over_budget.bump(),
                    TxDrop::NoSpace => self.stats.tx_drop_no_space.bump(),
                }
                Err(e)
            }
        }
    }

    /// Feed one event and run the state machine until it settles. `now` is the monotonic clock; `rng` supplies the ClientInfo nonce.
    pub fn handle(&mut self, now: Millis, ev: Event<'_>, rng: &mut dyn Entropy, sink: &mut dyn Sink) {
        match ev {
            Event::Connect => self.cmd_connect(now),
            Event::Reconnect => self.cmd_reconnect(now, sink),
            Event::Close => self.cmd_close(sink),
            Event::ClockValid(v) => self.clock_valid = v,
            Event::TokenGranted => {
                if self.state == State::Token {
                    self.token_held = true;
                    self.connect_started_ms = now;
                    self.transport_open = true;
                    self.set_state(State::Dns, now);
                    sink.action(Action::Dial { region: self.target.region, host: self.target.host.as_str(), port: self.target.port });
                } else {
                    self.stats.stray_events.bump();
                    sink.action(Action::ReleaseToken);
                }
            }
            Event::Dns(ok) => {
                if self.state != State::Dns {
                    self.stats.stray_events.bump();
                } else if ok {
                    self.set_state(State::Connecting, now);
                } else {
                    self.fail(now, sink);
                }
            }
            Event::Connected(ok) => {
                if self.state != State::Connecting {
                    self.stats.stray_events.bump();
                } else if ok {
                    self.set_state(State::Tls, now);
                    sink.action(Action::StartTls { host: self.target.host.as_str() });
                } else {
                    self.fail(now, sink);
                }
            }
            Event::TlsDone(ok) => {
                if self.state != State::Tls {
                    self.stats.stray_events.bump();
                } else if ok {
                    self.begin_upgrade(now, sink);
                } else {
                    self.fail(now, sink);
                }
            }
            Event::Bytes(b) => self.on_bytes(now, b, rng, sink),
            Event::TxProgress => {
                if self.tx_out != TxOut::None {
                    self.tx_progress_ms = now;
                } else {
                    self.stats.stray_events.bump();
                }
            }
            Event::TxDone => self.on_tx_done(now, sink),
            Event::Timer => {}
        }
        self.advance(now, sink);
    }

    /// Milliseconds until the link needs a [`Event::Timer`] although nothing external happens; `None` = never (idle). Computed from the deadlines the
    /// link keeps, so an established relay with nothing to say needs no polling. A link in the token state asks again in 50 ms, like the C.
    pub fn next_deadline_ms(&self, now: Millis) -> Option<u32> {
        let until = |deadline: Millis| -> u32 { if deadline >= now { (deadline - now).saturating_add(1).min(u32::MAX as u64) as u32 } else { 0 } };
        let t = &self.timing;
        let mut best: Option<u32> = None;
        let mut take = |v: u32| best = Some(best.map_or(v, |b| b.min(v)));
        match self.state {
            State::Idle => return None,
            State::Waiting => {
                if !self.clock_valid {
                    return Some(1000);
                }
                let due = if self.burst_left > 0 { self.next_attempt_ms } else { self.pace.next_ms };
                return Some(if due == 0 { 0 } else { until(due).saturating_sub(1) });
            }
            State::Token => return Some(50),
            _ => {}
        }
        if self.state.is_connecting() {
            take(until(self.connect_started_ms + t.connect_ms as Millis));
            if matches!(self.state, State::Upgrade | State::ServerKey | State::ServerInfo) {
                take(until(self.phase_started_ms + t.phase_ms as Millis));
            }
        }
        if self.state >= State::ServerKey
            && let Some(s) = self.rx_started
        {
            take(until(s + t.rx_frame_ms as Millis));
        }
        if self.tx_out != TxOut::None {
            take(until(self.tx_progress_ms + t.tx_stall_ms as Millis));
        }
        if self.state == State::Ready {
            take(until(self.last_recv_ms + t.stale_ms as Millis));
        }
        best
    }

    // ---------------------------------------------------------------------------------------------------------------------------------------------
    // state helpers

    fn set_state(&mut self, s: State, now: Millis) {
        self.state = s;
        self.phase_started_ms = now;
    }

    fn teardown(&mut self, sink: &mut dyn Sink) {
        if self.transport_open {
            sink.action(Action::Close);
            self.transport_open = false;
        }
        self.reader.reset();
        self.rx_started = None;
        self.tx_out = TxOut::None;
        self.ctl_state = Ctl::None;
        self.scan.reset();
        self.got_server_info = false;
        let flushed = self.txq.clear();
        self.stats.tx_flushed.0 = self.stats.tx_flushed.0.saturating_add(flushed as u32);
        if self.token_held {
            sink.action(Action::ReleaseToken);
            self.token_held = false;
        }
    }

    /// An attempt or an established connection ended. Schedule what comes next.
    fn fail(&mut self, now: Millis, sink: &mut dyn Sink) {
        let was_ready = self.state == State::Ready;
        self.teardown(sink);
        let t = self.timing;
        if was_ready {
            sink.action(Action::Notify(LinkEvent::Disconnected));
            // a transient flap costs sub-second: a short delay, a few quick attempts, then the ladder
            self.pace.reset(t.retry_min_ms);
            self.burst_left = t.flap_burst;
            self.burst_gap_ms = t.flap_gap_ms;
            self.next_attempt_ms = now + t.flap_delay_ms as Millis;
        } else {
            self.stats.connect_failures.bump();
            sink.action(Action::Notify(LinkEvent::ConnectFailed));
            if self.burst_left > 0 {
                self.burst_left -= 1;
                self.next_attempt_ms = now + self.burst_gap_ms as Millis;
            } else {
                self.pace.failed(now, t.retry_max_ms);
            }
        }
        let s = if self.wanted { State::Waiting } else { State::Idle };
        self.set_state(s, now);
    }

    fn cmd_connect(&mut self, now: Millis) {
        if self.state == State::Ready {
            return;
        }
        self.wanted = true;
        if matches!(self.state, State::Idle | State::Waiting) {
            self.pace.reset(self.timing.retry_min_ms);
            self.burst_left = self.timing.connect_burst;
            self.burst_gap_ms = self.timing.connect_gap_ms;
            self.next_attempt_ms = now;
            self.set_state(State::Waiting, now);
        }
    }

    fn cmd_reconnect(&mut self, now: Millis, sink: &mut dyn Sink) {
        let was_ready = self.state == State::Ready;
        self.teardown(sink);
        if was_ready {
            sink.action(Action::Notify(LinkEvent::Disconnected));
        }
        self.wanted = true;
        self.pace.reset(self.timing.retry_min_ms);
        self.burst_left = self.timing.flap_burst;
        self.burst_gap_ms = self.timing.flap_gap_ms;
        self.next_attempt_ms = now + self.timing.flap_delay_ms as Millis;
        self.set_state(State::Waiting, now);
    }

    fn cmd_close(&mut self, sink: &mut dyn Sink) {
        let was_ready = self.state == State::Ready;
        self.wanted = false;
        self.teardown(sink);
        self.state = State::Idle;
        if was_ready {
            sink.action(Action::Notify(LinkEvent::Disconnected));
        }
    }

    // ---------------------------------------------------------------------------------------------------------------------------------------------
    // transmit

    fn send_ctl(&mut self, now: Millis, sink: &mut dyn Sink) {
        self.ctl_state = Ctl::Sending;
        self.tx_out = TxOut::Ctl;
        self.tx_progress_ms = now;
        sink.action(Action::Send(&self.ctl[..self.ctl_len as usize]));
    }

    fn begin_upgrade(&mut self, now: Millis, sink: &mut dyn Sink) {
        match handshake::write_upgrade_request(self.target.host.as_str(), &mut self.ctl) {
            Ok(n) => {
                self.ctl_len = n as u16;
                self.scan.reset();
                self.set_state(State::Upgrade, now);
                self.send_ctl(now, sink);
            }
            Err(_) => self.fail(now, sink),
        }
    }

    fn pump_tx(&mut self, now: Millis, sink: &mut dyn Sink) {
        if self.state != State::Ready || self.tx_out != TxOut::None {
            return;
        }
        if self.ctl_state == Ctl::Queued {
            self.send_ctl(now, sink);
        } else if let Some(f) = self.txq.front() {
            self.tx_out = TxOut::Queue;
            self.tx_progress_ms = now;
            sink.action(Action::Send(f));
        }
    }

    fn on_tx_done(&mut self, now: Millis, sink: &mut dyn Sink) {
        match core::mem::replace(&mut self.tx_out, TxOut::None) {
            TxOut::None => self.stats.stray_events.bump(),
            TxOut::Ctl => {
                self.ctl_state = Ctl::None;
                match self.state {
                    State::ClientInfo => {
                        if self.got_server_info {
                            self.enter_ready(now, sink);
                        } else {
                            self.set_state(State::ServerInfo, now);
                        }
                    }
                    State::Ready => {
                        self.stats.frames_tx.bump();
                        self.pump_tx(now, sink);
                    }
                    _ => {}
                }
            }
            TxOut::Queue => {
                self.txq.pop();
                self.stats.frames_tx.bump();
                self.pump_tx(now, sink);
            }
        }
    }

    // ---------------------------------------------------------------------------------------------------------------------------------------------
    // receive

    fn on_bytes(&mut self, now: Millis, mut data: &[u8], rng: &mut dyn Entropy, sink: &mut dyn Sink) {
        if data.is_empty() {
            return;
        }
        if !matches!(self.state, State::Upgrade | State::ServerKey | State::ClientInfo | State::ServerInfo | State::Ready) {
            self.stats.stray_bytes.bump();
            return;
        }
        self.last_recv_ms = now;
        while !data.is_empty() {
            match self.state {
                State::Upgrade => {
                    let (n, st) = self.scan.feed(data);
                    data = &data[n..];
                    match st {
                        UpgradeStatus::NeedMore => {}
                        UpgradeStatus::Upgraded => {
                            if self.tx_out != TxOut::None {
                                self.stats.order_errors.bump();
                                self.fail(now, sink);
                                return;
                            }
                            self.reader.reset();
                            self.set_state(State::ServerKey, now);
                        }
                        UpgradeStatus::Refused | UpgradeStatus::TooLong => {
                            self.stats.protocol_errors.bump();
                            self.fail(now, sink);
                            return;
                        }
                    }
                }
                State::ServerKey | State::ClientInfo | State::ServerInfo | State::Ready => {
                    let (n, p) = self.reader.feed(data);
                    data = &data[n..];
                    match p {
                        Poll::NeedMore => {
                            if self.rx_started.is_none() && self.reader.in_frame() {
                                self.rx_started = Some(now);
                            }
                        }
                        Poll::Frame(info) => {
                            self.rx_started = None;
                            if !self.on_frame(now, info, rng, sink) {
                                return;
                            }
                        }
                        Poll::Error(e) => {
                            match e {
                                ReadError::Oversize { .. } => self.stats.oversize.bump(),
                                ReadError::ShortRecvPacket { .. } => self.stats.oversize.bump(),
                            }
                            self.fail(now, sink);
                            return;
                        }
                    }
                }
                _ => return,
            }
        }
    }

    /// A complete frame. False when the link failed (the caller stops reading).
    fn on_frame(&mut self, now: Millis, info: FrameInfo, rng: &mut dyn Entropy, sink: &mut dyn Sink) -> bool {
        if self.state == State::ServerKey {
            let Message::ServerKey { key, .. } = Message::parse(info.ty, self.reader.body()) else {
                self.stats.protocol_errors.bump();
                self.fail(now, sink);
                return false;
            };
            self.server_key = Key32(*key);
            self.reader.reset();
            let mut nonce = [0u8; NONCE_LEN];
            rng.fill(&mut nonce);
            self.ctl[..FRAME_HEADER_LEN].copy_from_slice(&encode_header(FrameType::CLIENT_INFO, handshake::CLIENT_INFO_BODY_LEN as u32));
            match handshake::client_info_body(&self.secret, &self.server_key, &nonce, &mut self.ctl[FRAME_HEADER_LEN..]) {
                Ok(n) => {
                    self.ctl_len = (FRAME_HEADER_LEN + n) as u16;
                    self.set_state(State::ClientInfo, now);
                    self.send_ctl(now, sink);
                    return true;
                }
                Err(_) => {
                    self.stats.protocol_errors.bump();
                    self.fail(now, sink);
                    return false;
                }
            }
        }

        self.stats.frames_rx.bump();
        let mut server_info_ok = false;
        if info.ty == FrameType::SERVER_INFO {
            if matches!(self.state, State::ClientInfo | State::ServerInfo) {
                match handshake::open_server_info(&self.secret, &self.server_key, self.reader.body_mut()) {
                    Ok(json) => {
                        self.server_info = handshake::parse_server_info(json);
                        self.got_server_info = true;
                        server_info_ok = self.state == State::ServerInfo;
                    }
                    Err(_) => {
                        self.stats.server_info_bad.bump();
                        self.fail(now, sink);
                        return false;
                    }
                }
            }
        } else {
            let body = self.reader.body();
            match Message::parse(info.ty, body) {
                Message::RecvPacket { src, payload } => {
                    if self.rx_admit.is_some_and(|f| !f(payload.len())) {
                        self.stats.rx_refused.bump();
                    } else {
                        sink.action(Action::DeliverPacket { src_key: src, payload });
                    }
                }
                Message::Ping(b) => {
                    if b.len() <= PONG_MAX && self.ctl_state == Ctl::None {
                        self.ctl[..FRAME_HEADER_LEN].copy_from_slice(&encode_header(FrameType::PONG, b.len() as u32));
                        self.ctl[FRAME_HEADER_LEN..FRAME_HEADER_LEN + b.len()].copy_from_slice(b);
                        self.ctl_len = (FRAME_HEADER_LEN + b.len()) as u16;
                        self.ctl_state = Ctl::Queued;
                        self.stats.pings_answered.bump();
                    } else {
                        self.stats.pings_dropped.bump();
                    }
                }
                Message::KeepAlive => self.stats.keepalives.bump(),
                Message::Pong(_) => self.stats.pongs_rx.bump(),
                Message::PeerGone { peer, reason } => sink.action(Action::PeerGone { peer, reason }),
                Message::Health(h) => sink.action(Action::Health(h)),
                Message::Restarting { reconnect_in_ms, try_for_ms } => sink.action(Action::ServerRestarting { reconnect_in_ms, try_for_ms }),
                Message::PeerPresent { .. } => {}
                Message::Unknown(..) => self.stats.unknown_frames.bump(),
                Message::Malformed(t) => {
                    if t == FrameType::PING {
                        self.stats.pings_dropped.bump();
                    }
                    self.stats.malformed_frames.bump();
                }
                Message::ServerKey { .. } | Message::ServerInfo(_) => self.stats.unknown_frames.bump(),
            }
        }
        if server_info_ok {
            self.enter_ready(now, sink);
        }
        true
    }

    fn enter_ready(&mut self, now: Millis, sink: &mut dyn Sink) {
        self.scan.reset();
        self.got_server_info = false;
        self.set_state(State::Ready, now);
        self.last_recv_ms = now;
        self.stats.connects.bump();
        self.pace.reset(self.timing.retry_min_ms);
        self.burst_left = 0;
        if self.token_held {
            sink.action(Action::ReleaseToken);
            self.token_held = false;
        }
        // this is our preferred DERP
        if self.ctl_state == Ctl::None {
            self.ctl[..FRAME_HEADER_LEN].copy_from_slice(&encode_header(FrameType::NOTE_PREFERRED, 1));
            self.ctl[FRAME_HEADER_LEN] = 1;
            self.ctl_len = (FRAME_HEADER_LEN + 1) as u16;
            self.ctl_state = Ctl::Queued;
        }
        sink.action(Action::Notify(LinkEvent::Connected));
        self.pump_tx(now, sink);
    }

    // ---------------------------------------------------------------------------------------------------------------------------------------------
    // timers and the state machine

    fn advance(&mut self, now: Millis, sink: &mut dyn Sink) {
        for _ in 0..16 {
            let t = self.timing;
            if self.state.is_connecting() && now.saturating_sub(self.connect_started_ms) > t.connect_ms as Millis {
                self.fail(now, sink);
                continue;
            }
            if self.tx_out != TxOut::None && now.saturating_sub(self.tx_progress_ms) > t.tx_stall_ms as Millis {
                self.stats.tx_stalls.bump();
                self.fail(now, sink);
                continue;
            }
            if self.state >= State::ServerKey
                && let Some(s) = self.rx_started
                && now.saturating_sub(s) > t.rx_frame_ms as Millis
            {
                self.stats.rx_timeouts.bump();
                self.fail(now, sink);
                continue;
            }
            let phase_over = now.saturating_sub(self.phase_started_ms) > t.phase_ms as Millis;
            match self.state {
                State::Idle => return,
                State::Waiting => {
                    let clock = self.clock_valid;
                    if !clock || self.burst_left == 0 {
                        // the ladder; a wall clock that is not set holds the connect back without counting as a relay failure
                        let deferrals = self.pace.deferrals;
                        let due = self.pace.due(now, clock, t.retry_min_ms);
                        if !clock {
                            if self.pace.deferrals != deferrals {
                                sink.action(Action::Notify(LinkEvent::ClockDeferred));
                            }
                            return;
                        }
                        if !due {
                            return;
                        }
                    } else if now < self.next_attempt_ms {
                        return;
                    }
                    self.set_state(State::Token, now);
                    sink.action(Action::WantToken);
                    return;
                }
                State::Token | State::Dns | State::Connecting | State::Tls | State::ClientInfo => return,
                State::Upgrade => {
                    if phase_over {
                        self.fail(now, sink);
                        continue;
                    }
                    return;
                }
                State::ServerKey => {
                    if phase_over {
                        self.stats.rx_timeouts.bump();
                        self.fail(now, sink);
                        continue;
                    }
                    return;
                }
                State::ServerInfo => {
                    if phase_over {
                        // no ServerInfo: carry on, as the blocking client did; mid-frame it would desync the stream
                        if self.reader.in_frame() {
                            self.stats.rx_timeouts.bump();
                            self.fail(now, sink);
                        } else {
                            self.enter_ready(now, sink);
                        }
                        continue;
                    }
                    return;
                }
                State::Ready => {
                    if self.last_recv_ms != 0 && now > self.last_recv_ms && now - self.last_recv_ms > t.stale_ms as Millis {
                        // server keepalives arrive every 15 to 60 s: prolonged silence means the relay is gone even though TCP looks alive
                        self.stats.stale.bump();
                        sink.action(Action::Notify(LinkEvent::RxStale));
                        self.fail(now, sink);
                        continue;
                    }
                    self.pump_tx(now, sink);
                    return;
                }
            }
        }
    }
}
