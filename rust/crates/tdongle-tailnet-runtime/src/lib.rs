//! The async runtime of the T-Dongle tailnet gateway: **one set of tasks shared by every membership**, around the sans-IO engine
//! (`tdongle-tailnet-engine`), plus the `TailnetApi` the firmware image calls (`tdongle-tailnet-fw`).
//!
//! It replaces the C's `ml_runtime.c` / `ml_rt_core.c` / `ml_mux.c` / `ml_net_io.c` (shared net_io, derp and wg_mgr tasks), `ml_coord.c` (one control task per
//! membership) and the manager, admission and start / stop code of `gateway_main.c` (ADR 0013), without a FreeRTOS task, stack or TCB per membership.
//!
//! ```text
//!                       +--------------------------- Shared (one static) ----------------------------+
//!  USB host <-> usb ----+  engine  (one, behind a blocking mutex; Output only enqueues)                |
//!  (UsbNet: ARP, DHCP,  |  slots[3]: run state, identity, UDP queue, DERP queue, control session state  |
//!   alias router, DNS)  |  host queue, DNS queue, negotiation token, TLS record lease, control Bulk,    |
//!         |             |  scratch, registry                                                           |
//!         |             +-------------------------------------------------------------------------------+
//!         +-- WifiRaw (NAT to Wi-Fi: tdongle-tailnet-wifimux)
//!  tasks (joined into ONE future by `run` on the host; the firmware spawns them one by one, each built in place):
//!    control x3   tdongle_tailnet_ctl::run_session per membership (key fetch, ts2021, register, streaming map) -> NetmapSink -> engine
//!    derp    x3   tdongle_tailnet_derp::Link over TCP + TLS with per-record leases from the pool, token (phase B) around the handshake
//!    udp     x3   one socket per membership: DISCO / WireGuard / STUN -> engine, engine -> socket
//!    usb          frames <-> UsbNet <-> engine (alias traffic, DNS) / NAT (everything else)
//!    supervisor   registry (NVS), identities, admission, start / stop / enable / disable / remove in ADR 0013's order
//!    engine timer exactly ONE timer, for the one Out::Wake deadline
//!    link watch   association generation, address, wall clock -> every task and the engine
//!    dns upstream the host's DNS forwarder (one UDP socket)
//! ```
//!
//! # The rules the design keeps
//!
//! * **The engine never waits and never re-enters.** [`Shared::feed`] locks it, hands it the heap reading and the clock, and calls `Engine::handle`; its
//!   [`shared::OutSink`] copies every output into a bounded [`queue::ByteQueue`] or a cell and returns (a full queue refuses: the engine counts the packet).
//!   The DERP links are owned by the DERP tasks, so a relayed packet reaches the engine *inline* from the link's callback (the engine never calls a link).
//! * **A lock is never held across an `.await`** and never taken while the engine lock is held except by the sink, on leaf cells and queues.
//! * **Every wait is cancel-safe**; a dropped future leaves nothing behind (the token key is released, the socket closed, the slot bit cleared).
//! * **Backpressure, not loss** (ADR 0023): the USB task holds a frame for a tailnet peer until its membership's egress queues have room (at most 100 ms), and
//!   the UDP and DERP tasks do not read their sockets while the host queue is full, so a slow side slows the TCP connection or the host's driver instead of
//!   the gateway dropping what it already accepted. What is still refused is counted (`RtStats::out_refused`, the engine's `TxRefused`).
//! * **The negotiation token** serialises phase A (start allocations, Noise, registration, initial map; one key per membership: the start path hands the token to
//!   the control task by key) and phase B (the DERP TLS handshake). `RtStats::neg_max` is the observed invariant (at most one negotiation in flight).
//!
//! # Memory (see [`sizes`], `size-table.sh`, and `cargo test -p tdongle-tailnet-host --test memory -- --nocapture`)
//!
//! The runtime's state is [`shared::Shared`] (one value, **`const`-constructible**: the firmware keeps it as a `const` item and copies it from flash into a heap
//! block when tailnet mode starts, because a value of that size built at run time is a stack frame the board does not have, see `rust/tools/check_stack.py`) and
//! the tasks' futures. Per membership slot (xtensa, [`sizes`]): the control, DERP and UDP futures, the [`shared::Slot`] (control session state, two egress queues,
//! status, identity) and the engine's per-membership record. The shared parts: the engine's shared half, the USB task, the supervisor, the host and DNS queues.
//! **Everything that is only used while something runs comes from the pool** ([`tdongle_tailnet_pool`], ADR 0002 "RAM fit"): the socket windows
//! (`net_embassy::Windows::PER_MEMBER`, 22.5 KB per membership, taken at `connect` / `bind` and given back at `release` / `close`), the TLS records
//! (one block of the record's own length, about 2 KB, per record) and the control workspace ([`tdongle_tailnet_ctl::Bulk`], 17.7 KB, per negotiation or map
//! message). Each allocation is admitted like every elastic consumer of the C (the free heap must stay at `ML_HB_FLOOR`, a negotiation down to the recovery reserve),
//! and a refusal is counted backpressure: the connection backs off, the read waits, the datagram is dropped; nothing panics. The ADR table is printed by
//! `size-table.sh` and `cargo test -p tdongle-tailnet-host --test memory -- --nocapture`, labelled M-host / M-elf.
//!
//! **The control workspace is taken, not owned.** `tdongle_tailnet_ctl::run_session_leased` takes the big buffers (record reader, sealed-record buffer, request /
//! response JSON, the map projector) through [`shared::BulkSource`] from the pool, from the first byte of a record until the message it carries is applied (and for
//! the whole negotiation, which the token already serialises), and gives them back whenever the session waits for the server with nothing in progress, which is
//! nearly always. Each membership keeps only its [`tdongle_tailnet_ctl::SessionBuf`] (the TCP input buffer and the counters, about 1.1 KB) in its slot. A server that
//! goes quiet in the middle of a record or a message ends *its own* session after `Timeouts::lease_stall_ms` (5 s; the C's "a stalled server costs only its own
//! membership a redial"). The other shared buffer is the **scratch** ([`shared::SCRATCH`], 4 KB): the datagram being handled by the UDP, DNS and DERP tasks, the USB
//! side's reply frame and host record, the registry's JSON, each held only inside synchronous code, so no task keeps such a buffer across a wait.
//!
//! # Admission
//!
//! `Params::rust` with measured `MemberSizes` is the arithmetic (shared tasks charged to the first membership, one negotiation peak, the recovery reserve, the
//! router floor, the largest block), **but** the runtime's own state is a heap block taken before any membership starts (the firmware's start admission checks it
//! against the heap and the elastic floor), so charging it per membership would count it twice.
//! [`Config::charge_static_bytes`] (default off) switches the charge on for the boards or the ADR that want the C's conservative reading. With it off the
//! requirement is the C's dynamic part only (16,384 + 13,500 + 2,800 B) and a membership is refused for the heap, the largest block, a busy token (retry in
//! 10 s), no free slot, or an identity that cannot be had. Every decision is in the `members` serial report, every refusal on the setup page.
//!
//! # Divergences from the C (all deliberate)
//!
//! * The control workspace is taken from the pool per record / message, with a stall bound (above); the C allocates and frees it on the heap per negotiation.
//! * **No STUN probe before the first negotiation** (`COORD_STUN_PROBE`): the first session's `PreferredDERP` is 0; the engine homes the node from the first
//!   DERP map and the region reaches the control plane in the next endpoint update (an additive `EndpointSource::preferred_derp` hook in `ctl`).
//! * **Stop is split**: `TailnetApi::member_action` does the router suspend (engine `MemberDisabled`) synchronously and the rest (tasks, `MemberRemoved`,
//!   secrets, slot) in the supervisor; the identity namespace of a removed membership is erased by the action at once (the keys are in RAM). The C waits for
//!   the whole stop; here "retry shortly" (`DISCONNECT_PENDING`, `REMOVAL_PENDING`) only answers a second stop of a membership whose first is still finishing.
//! * **Starts react at once** to an action (the C's manager wakes every 10 s); a refused start is retried every 10 s as in the C.
//! * **The provisioning key is dropped from NVS with a retry**: the C clears it in RAM, saves once, and never saves again if that save failed.
//! * **No socket-descriptor admission** (`gateway_socket_admit`): a membership's three sockets are created on its slot's tasks, so "no free slot" is the cap
//!   ([`shared::MAX_RUN`]; 1 in the firmware's tailnet image), and their windows are admitted by the pool (a refusal is a counted retry).
//! * **Datagrams are handled where they arrive**: there is no `ml_wg_rx` queue between the socket and the engine; `Engine::rx_enqueue` is called around each
//!   handle for the heap-floor check and the byte budget (counted `WgCopy`), and the relay link's `rx_admit` hook is unused.
//! * **IPv6 STUN** (`SockKind::Stun6`) and IPv6 endpoints are not sent (the stack is IPv4-only); the engine's requests for them are dropped silently.
//! * **`render_status`** fills what the runtime knows; the image-owned fields (chip temperature, power, `wifi_link`, saved networks, reset reason, Wi-Fi pin
//!   accounting) are defaults, and the peer list is the first page (the seam passes no query).
//! * A re-association restarts every session at once (no backoff); a failed session backs off `1000 << min(n, 4)` ms, capped at 30 s, as the C.
//!
//! # What the firmware image provides
//!
//! * [`tdongle_tailnet_fw::Platform`], [`tdongle_tailnet_fw::Storage`] (NVS; the namespace `tn_settings` key `members`, and `tn_%08x` / `identity_v1`), and the
//!   peer directory (`tdongle_tailnet_engine::PeerDirectory`: a RAM directory today) when it builds [`Shared::new`], which is `const`: keep the value as a `const`
//!   item and `Box::new` it where it should live (a `static`, or a heap block the firmware admits first).
//! * [`tdongle_tailnet_fw::UsbFrames`], and a raw mutex `R` for the shared state: **not** a plain critical section if engine calls (a WireGuard handshake is two
//!   X25519, tens of milliseconds) must not mask interrupts; any `Sync` lock that is safe between the executor and the HTTP task works.
//! * [`net::Net`]: `net_embassy::EmbassyNet` with a `net_embassy::SockMem` (the firmware's is `tdongle-tailnet-sockmem`, over the pool) and a
//!   `net_embassy::LinkGen` over the radio's association generation; the stack's `Runner` must run. The embassy-net stack must be built with `proto-ipv4`, `tcp`, `udp`, `dns`, `dhcpv4`.
//! * [`wifi::WifiRaw`]: `wifi_mux::MuxWifi` (feature `wifimux`) over `tdongle-tailnet-wifimux`'s `RawPort`, `SharedNapt` and the stack's `StackInfo`, or
//!   [`wifi::NoWifi`] for a gateway without passthrough. TCP client ports chosen by embassy-net can fall in the NAT's mapped range (49152..=61439): reserve
//!   them through the mux or move `NaptConfig::port_start` (see `net_embassy`).
//! * Time: an `embassy-time` driver and a `critical-section` implementation; entropy through `Platform::fill_random` (the hardware RNG with the radio on).
//! * `tdongle_tailnet_fw::TailnetApi` is implemented by [`Shared`]: register `&'static Shared` with the HTTP server and the console, spawn
//!   [`run`]`(shared, net, usb, wifi)` once, and keep `Mode::Tailnet` out of safe mode and the setup access point.
//!
//! The seam (`tdongle-tailnet-fw`) is unchanged; the one additive difference from its documentation is that [`run`] takes the shared state first and the
//! platform and storage live inside it, so that `TailnetApi` (synchronous, any task) can reach them.
//!
//! # Fixes in sibling crates (all additive; their tests pass)
//!
//! `tdongle-tailnet-tls`: `LeasedTlsDerp::wait_record` (the cancel-safe wait for the next record's header, which `read_with` hid). `tdongle-tailnet-ctl`:
//! `EndpointSource::preferred_derp` (default `None`) and its use in the endpoint update.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(test)]
extern crate std;
pub mod api;
pub mod control;
pub mod control_url;
pub mod derp;
pub mod identity;
pub mod members;
pub mod net;
pub mod resolver;
#[cfg(feature = "embassy-net")]
pub mod net_embassy;
#[cfg(feature = "embassy-net")]
pub mod sntp;
#[cfg(feature = "size-probe")]
pub mod probe;
pub mod queue;
pub mod runner;
pub mod shared;
pub mod sizes;
pub mod tasks;
pub mod taskutil;
#[cfg(test)]
mod testutil;
pub mod token;
pub mod udp;
pub mod usb;
pub mod util;
pub mod wifi;
#[cfg(feature = "wifimux")]
pub mod wifi_mux;

pub use runner::run;
pub use shared::{Config, Shared};
