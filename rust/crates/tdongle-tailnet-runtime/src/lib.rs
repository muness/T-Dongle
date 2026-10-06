//! The async runtime of the T-Dongle tailnet gateway: **one set of tasks shared by every membership**, around the sans-IO engine
//! (`tdongle-tailnet-engine`), plus the `TailnetApi` the firmware image calls (`tdongle-tailnet-fw`).
//!
//! It replaces the C's `ml_runtime.c` / `ml_rt_core.c` / `ml_mux.c` / `ml_net_io.c` (shared net_io, derp and wg_mgr tasks), `ml_coord.c` (one control task per
//! membership) and the manager, admission and start / stop code of `gateway_main.c` (ADR 0013), without a FreeRTOS task, stack or TCB per membership.
//!
//! ```text
//!                       +--------------------------- Shared (one static) ----------------------------+
//!  USB host <-> usb ----+  engine  (one, behind a blocking mutex; Output only enqueues)                |
//!  (UsbNet: ARP, DHCP,  |  slots[3]: run state, identity, UDP queue, DERP queue, control workspace     |
//!   alias router, DNS)  |  host queue, DNS queue, negotiation token, TLS record lease, registry        |
//!         |             +-------------------------------------------------------------------------------+
//!         +-- WifiRaw (NAT to Wi-Fi: tdongle-tailnet-wifimux)
//!  tasks (all joined into ONE future by `run`):
//!    control x3   tdongle_tailnet_ctl::run_session per membership (key fetch, ts2021, register, streaming map) -> NetmapSink -> engine
//!    derp    x3   tdongle_tailnet_derp::Link over TCP + the shared-lease TLS, token (phase B) around the handshake
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
//! Everything the runtime owns is static or part of the one joined future: **no heap**. Per membership slot (xtensa, [`sizes`]): the control, DERP and UDP
//! futures, the [`shared::Slot`] static (control workspace, two egress queues, status, identity), the engine's per-membership record and the socket buffers
//! the `Net` keeps ([`net_embassy::GatewayBuffers`]). The shared parts: the engine's shared half, the USB task, the supervisor, the TLS record lease (one
//! 16,640-byte buffer for all DERP connections), the host and DNS queues. The ADR table is printed by the two commands above, labelled M-host / M-elf.
//!
//! **The one shared Workspace the brief asked for does not exist, and cannot with `tdongle_tailnet_ctl::run_session` as written.** The driver borrows
//! the `Workspace` (record reader, sealed-record buffer, request / response JSON, the map projector: 19,928 B on xtensa) for the *whole* session, and a session
//! is a long poll that stays open for ever. The negotiation token is released after the first map, but the session (and its borrow) goes on. So each slot owns
//! one, and that is the largest single item of the per-membership figure. The remedy is in `ctl`, not here: lease the workspace per map message (hold it
//! from the first byte of a record until the message is applied, release it while waiting for the next one, with the TLS lease's stall bound), which would
//! leave one workspace plus about 1.1 KiB of per-session state per membership (the host test prints the saving as EST). It is the first thing to do for the
//! multi-tailnet memory win.
//!
//! # Admission
//!
//! `Params::rust` with measured `MemberSizes` is the arithmetic (shared tasks charged to the first membership, one negotiation peak, the recovery reserve, the
//! router floor, the largest block), **but** the runtime's own state is in `.bss`, not in the heap the check compares with; charging it would count it twice.
//! [`Config::charge_static_bytes`] (default off) switches the charge on for the boards or the ADR that want the C's conservative reading. With it off the
//! requirement is the C's dynamic part only (16,384 + 13,500 + 2,800 B) and a membership is refused for the heap, the largest block, a busy token (retry in
//! 10 s), no free slot, or an identity that cannot be had. Every decision is in the `members` serial report, every refusal on the setup page.
//!
//! # Divergences from the C (all deliberate)
//!
//! * One control workspace per slot, not one shared (above).
//! * **No STUN probe before the first negotiation** (`COORD_STUN_PROBE`): the first session's `PreferredDERP` is 0; the engine homes the node from the first
//!   DERP map and the region reaches the control plane in the next endpoint update (an additive `EndpointSource::preferred_derp` hook in `ctl`).
//! * **Stop is split**: `TailnetApi::member_action` does the router suspend (engine `MemberDisabled`) synchronously and the rest (tasks, `MemberRemoved`,
//!   secrets, slot) in the supervisor; the identity namespace of a removed membership is erased by the action at once (the keys are in RAM). The C waits for
//!   the whole stop; here "retry shortly" (`DISCONNECT_PENDING`, `REMOVAL_PENDING`) only answers a second stop of a membership whose first is still finishing.
//! * **Starts react at once** to an action (the C's manager wakes every 10 s); a refused start is retried every 10 s as in the C.
//! * **The provisioning key is dropped from NVS with a retry**: the C clears it in RAM, saves once, and never saves again if that save failed.
//! * **No socket-descriptor admission** (`gateway_socket_admit`): sockets are static per slot, so "no free slot" is the cap ([`shared::MAX_RUN`] = 3).
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
//!   peer directory (`tdongle_tailnet_engine::PeerDirectory`: the flash directory) when it builds [`Shared::new`]; place the `Shared` with
//!   `StaticCell::init_with` (`Shared::new` is not `const`: the control workspace contains the map projector, whose constructor is not).
//! * [`tdongle_tailnet_fw::UsbFrames`], and a raw mutex `R` for the shared state: **not** a plain critical section if engine calls (a WireGuard handshake is two
//!   X25519, tens of milliseconds) must not mask interrupts; any `Sync` lock that is safe between the executor and the HTTP task works.
//! * [`net::Net`]: [`net_embassy::EmbassyNet`] with a [`net_embassy::NetBuffers`] static and a [`net_embassy::LinkGen`] over the radio's association
//!   generation; the stack's `Runner` must run. The embassy-net stack must be built with `proto-ipv4`, `tcp`, `udp`, `dns`, `dhcpv4`.
//! * [`wifi::WifiRaw`]: [`wifi_mux::MuxWifi`] (feature `wifimux`) over `tdongle-tailnet-wifimux`'s `RawPort`, `SharedNapt` and the stack's `StackInfo`, or
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
#[cfg(test)]
extern crate std;
pub mod api;
pub mod control;
pub mod derp;
pub mod identity;
pub mod members;
pub mod net;
#[cfg(feature = "embassy-net")]
pub mod net_embassy;
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
