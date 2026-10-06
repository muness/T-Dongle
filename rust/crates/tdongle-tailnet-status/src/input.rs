//! What `/status` reports, as plain data. The field names are the C's (`ml_rt_status_t`, `ml_wg_pool_status_t`, `ml_neg_status_t`, `ml_adm_budget_t`,
//! `ml_rng_stats_t`, `tdongle_pm_status_t`, `tdongle_temperature`, `gateway_socket_stats`, `status_member`); the integration glue maps the other crates
//! onto them. Text fields are C strings (`&[u8]`, read up to the first NUL).

/// Number of shared tasks reported (`ML_RT_TASK_COUNT`: net_io, derp, wg_mgr).
pub const RT_TASKS: usize = 3;
/// Names of the shared tasks, in `ml_rt_task_t` order.
pub const RT_TASK_NAMES: [&str; RT_TASKS] = ["net_io", "derp", "wg_mgr"];
/// `TDONGLE_PM_MAX_BURSTS`.
pub const PM_MAX_BURSTS: usize = 8;
/// `TDONGLE_TEMPERATURE_STEP_TENTHS`: the sensor moves in whole degrees.
pub const TEMPERATURE_STEP_TENTHS: u32 = 10;
/// The per-member diagnostic keys, in `v->diagnostics[]` order.
pub const DIAGNOSTIC_NAMES: [&str; 21] = [
    "map_attempts",
    "map_failures",
    "map_error",
    "map_bytes",
    "map_declared_bytes",
    "map_projected_bytes",
    "map_heap_before",
    "map_heap_after",
    "map_largest_before",
    "map_stream_id",
    "map_frame_type",
    "noise_error",
    "noise_frame_bytes",
    "map_generation",
    "h2_error",
    "h2_last_stream",
    "read_expected",
    "read_received",
    "read_elapsed_ms",
    "read_errno",
    "read_tls_result",
];
/// The per-member stack keys, in `v->stack_free[]` order (`derp_rx` has not existed since the I/O tasks merged: it is always null).
pub const STACK_NAMES: [&str; 5] = ["net_io", "derp_tx", "derp_rx", "coord", "wg_mgr"];

/// `tdongle_temperature` (the sensor snapshot).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Temperature {
    /// The latest sample succeeded.
    pub valid: bool,
    /// Tenths of a degree C (signed in C; a negative value prints as a 64-bit wrapped number, as the C does).
    pub current_tenths: i32,
    /// Peak since boot.
    pub peak_tenths: i32,
    /// Uptime of the latest successful sample.
    pub sampled_at_ms: u32,
    /// Successful samples.
    pub samples: u32,
    /// Uptime when `current` last changed.
    pub changed_at_ms: u32,
    /// Snapshot time minus `sampled_at_ms` (UINT32_MAX before the first sample; not printed then).
    pub age_ms: u32,
    /// Failed samples.
    pub errors: u32,
}

/// `ml_adm_budget_t` as `/status` prints it (the C casts each to `uint32_t`), plus the charged peer slots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Admission {
    /// `required`: free heap needed to admit the next membership.
    pub required: u32,
    /// `shared_runtime`.
    pub shared_runtime: u32,
    /// `member_start`.
    pub member_start: u32,
    /// `member_growth`.
    pub member_growth: u32,
    /// `member_steady`.
    pub member_steady: u32,
    /// `negotiation`.
    pub negotiation: u32,
    /// `recovery`.
    pub recovery: u32,
    /// `largest_block`.
    pub largest_block: u32,
    /// `ML_ADM_PEER_SLOTS`.
    pub peer_slots_charged: u32,
    /// `ml_wg_slot_bytes()`.
    pub peer_slot_bytes: u32,
}

/// `ml_neg_phase_t`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NegPhase {
    /// `ML_NEG_PHASE_NONE`.
    #[default]
    None,
    /// `ML_NEG_PHASE_START`.
    Start,
    /// `ML_NEG_PHASE_CONTROL`.
    Control,
    /// `ML_NEG_PHASE_DERP`.
    Derp,
}

impl NegPhase {
    /// `ml_neg_phase_name`.
    pub fn name(self) -> &'static str {
        match self {
            NegPhase::Start => "start",
            NegPhase::Control => "control",
            NegPhase::Derp => "derp",
            NegPhase::None => "none",
        }
    }
}

/// `ml_neg_status_t`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Negotiation {
    /// `holder != 0` with the phase it holds; `None` when nobody holds the token (reported as "none").
    pub holder: Option<NegPhase>,
    /// `held_ms`.
    pub held_ms: u32,
    /// `waiting`.
    pub waiting: u32,
    /// `grants`.
    pub grants: u32,
    /// `timeouts`.
    pub timeouts: u32,
    /// `lease_expired`.
    pub lease_expired: u32,
    /// `stale_dropped`.
    pub stale_dropped: u32,
    /// `refused_full`.
    pub refused_full: u32,
    /// `max_wait_ms`.
    pub max_wait_ms: u32,
    /// `max_hold_ms`.
    pub max_hold_ms: u32,
}

/// `ml_rt_status_t` (the shared tasks).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedRuntime {
    /// `running`.
    pub running: bool,
    /// `members`.
    pub members: u32,
    /// `starts`.
    pub starts: u32,
    /// `stops`.
    pub stops: u32,
    /// `attach_failures`.
    pub attach_failures: u32,
    /// `detach_failures`.
    pub detach_failures: u32,
    /// `stack_bytes[]`.
    pub stack_bytes: [u32; RT_TASKS],
    /// `stack_free[]` (UINT32_MAX: not running, printed null).
    pub stack_free: [u32; RT_TASKS],
    /// `passes[]`.
    pub passes: [u32; RT_TASKS],
    /// `max_service_ms[]`.
    pub max_service_ms: [u32; RT_TASKS],
    /// `slow_services[]`.
    pub slow_services: [u32; RT_TASKS],
    /// `detach_timeouts[]`.
    pub detach_timeouts: [u32; RT_TASKS],
    /// `negotiation`.
    pub negotiation: Negotiation,
}

/// `ml_wg_pool_status_t`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WgPool {
    /// `capacity`.
    pub capacity: u32,
    /// `used`.
    pub used: u32,
    /// `peak`.
    pub peak: u32,
    /// `refused_full`.
    pub refused_full: u32,
    /// `refused_nomem`.
    pub refused_nomem: u32,
    /// `evictions_own`.
    pub evictions_own: u32,
    /// `evictions_other`.
    pub evictions_other: u32,
    /// `rejected`.
    pub rejected: u32,
    /// `refused_largest`.
    pub refused_largest: u32,
    /// `refused_heap`.
    pub refused_heap: u32,
    /// `largest_low` (UINT32_MAX: none yet, printed null).
    pub largest_low: u32,
    /// `slot_bytes`.
    pub slot_bytes: u32,
    /// `device_bytes`.
    pub device_bytes: u32,
}

/// `ml_rng_stats_t`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedRng {
    /// `users`.
    pub users: u32,
    /// `bytes_resident`.
    pub bytes_resident: u32,
    /// `seedings`.
    pub seedings: u32,
    /// `failures`.
    pub failures: u32,
}

/// `tdongle_pm_burst_stats_t` (one CPU-max lock).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PmLock<'a> {
    /// `name`.
    pub name: &'a [u8],
    /// `depth`.
    pub depth: u32,
    /// `acquires`.
    pub acquires: u32,
    /// `releases`.
    pub releases: u32,
    /// `held_us`.
    pub held_us: u32,
    /// `max_depth`.
    pub max_depth: u32,
    /// `underflows`.
    pub underflows: u32,
    /// `forced_releases`.
    pub forced_releases: u32,
    /// `backend_failures`.
    pub backend_failures: u32,
    /// `isr_rejects`.
    pub isr_rejects: u32,
}

/// `tdongle_pm_status_t` and the Wi-Fi power-save mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Power<'a> {
    /// `scaling`.
    pub scaling: bool,
    /// `cpu_mhz`.
    pub cpu_mhz: u32,
    /// `max_mhz`.
    pub max_mhz: u32,
    /// `min_mhz`.
    pub min_mhz: u32,
    /// `configure_error` (an `esp_err_t`, printed signed).
    pub configure_error: i32,
    /// `lock_create_failures`.
    pub lock_create_failures: u32,
    /// `wifi_ps_mode()`: -1 when not readable.
    pub wifi_ps: i32,
    /// The locks, `bursts` of them (at most [`PM_MAX_BURSTS`]).
    pub locks: &'a [PmLock<'a>],
}

/// `gateway_socket_stats` and the build constants beside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sockets {
    /// `CONFIG_LWIP_MAX_SOCKETS`.
    pub limit: u32,
    /// `GATEWAY_SOCKET_RECOVERY`.
    pub recovery_reserve: u32,
    /// `open`.
    pub open: u32,
    /// `peak`.
    pub peak: u32,
    /// `failures`.
    pub failures: u32,
    /// `last_errno`.
    pub last_errno: u32,
    /// `last_operation`.
    pub last_operation: u32,
    /// `last_at_ms`.
    pub last_at_ms: u32,
}

/// The clock section (`gw_clock_state` and the SNTP supervision).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Clock<'a> {
    /// `gw_clock_state(...)`.
    pub state: &'a [u8],
    /// `ml_derp_clock_valid()`.
    pub valid: bool,
    /// `sntp_clock.restarts`.
    pub sntp_restarts: u32,
    /// `sntp_clock.retry_in_ms`.
    pub retry_in_ms: u32,
    /// `gw_clock_server_name[...]`.
    pub server: &'a [u8],
}

/// The heap budget (ADR 0022).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeapBudget {
    /// `ML_HB_FLOOR`.
    pub floor: u32,
    /// `ML_HB_RESERVE`.
    pub reserve: u32,
    /// `ML_HB_PIN_BUFFERS`.
    pub pin_buffers: u32,
    /// `usb_rx_budget.dropped_heap`.
    pub refused_usb_rx: u32,
    /// `ml_hb_refused[ML_HB_JIT]` (reported as `refused_pending`).
    pub refused_pending: u32,
    /// `ml_hb_refused[ML_HB_DERP_TX]`.
    pub refused_derp_tx: u32,
    /// `ml_hb_refused[ML_HB_RX_CTRL]`.
    pub refused_rx_ctrl: u32,
    /// `ml_hb_refused[ML_HB_DERP_RX]`.
    pub refused_derp_rx: u32,
    /// `ml_hb_refused[ML_HB_WG_COPY]`.
    pub refused_wg_copy: u32,
}

/// The Wi-Fi driver buffers pinned by the data path (ADR 0022 amendment 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WifiPins {
    /// `wifi_pins_installed`.
    pub installed: bool,
    /// `wifi_pins_tx_done_ok` (reported as `tx_done_cb`).
    pub tx_done_cb: bool,
    /// `wifi_pins_rx_hooked`.
    pub rx_hooked: bool,
    /// `GATEWAY_WIFI_TX_POOL`.
    pub tx_pool: u32,
    /// `GATEWAY_WIFI_BAND_TOTAL`.
    pub band_total: u32,
    /// `GATEWAY_WIFI_TX_BAND_MAX`.
    pub tx_band_max: u32,
    /// `GATEWAY_WIFI_RX_BAND_MAX`.
    pub rx_band_max: u32,
    /// `wifi_pins_tx_outstanding()`.
    pub tx_inflight: u32,
    /// `tx_high_water`.
    pub tx_high_water: u32,
    /// `tx_charged`.
    pub tx_charged: u32,
    /// `tx_done`.
    pub tx_done: u32,
    /// `tx_aborted`.
    pub tx_aborted: u32,
    /// `tx_flushed`.
    pub tx_flushed: u32,
    /// `tx_stale`.
    pub tx_stale: u32,
    /// `tx_unmatched`.
    pub tx_unmatched: u32,
    /// `tx` band admits (reported as `tx_band_admits`).
    pub tx_band: u32,
    /// `tx` elastic admits (reported as `tx_elastic_admits`).
    pub tx_elastic: u32,
    /// `tx_refused_pool`.
    pub tx_refused_pool: u32,
    /// `tx_refused_heap`.
    pub tx_refused_heap: u32,
    /// `wifi_pins_rx_inflight()`.
    pub rx_inflight: u32,
    /// `rx_high_water`.
    pub rx_high_water: u32,
    /// `rx` band admits (reported as `rx_band_admits`).
    pub rx_band: u32,
    /// `rx` elastic admits (reported as `rx_elastic_admits`).
    pub rx_elastic: u32,
    /// `rx_released`.
    pub rx_released: u32,
    /// `rx_unmatched`.
    pub rx_unmatched: u32,
    /// `rx_dropped`.
    pub rx_dropped: u32,
}

/// One peer of a membership's page.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Peer<'a> {
    /// The directory hostname (`record.hostname`); the short name is what precedes its first dot.
    pub name: &'a [u8],
    /// The address the gateway presents (`gateway_alias(m->id, vpn_ip)`), host order.
    pub address: u32,
}

/// The live client of a membership (present when `m->client` is).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Client<'a> {
    /// `c->vpn_ip` (0: none yet).
    pub vpn_ip: u32,
    /// The published DNS name (empty: none).
    pub dns: &'a [u8],
    /// `v->diagnostics[]`, keyed by [`DIAGNOSTIC_NAMES`]; the last one is a signed `int32`.
    pub diagnostics: [u32; 21],
    /// `v->stack_free[]`, keyed by [`STACK_NAMES`] (UINT32_MAX: unknown, printed null).
    pub stack_free: [u32; 5],
    /// `c->auth_url`.
    pub login_url: &'a [u8],
    /// `c->last_error` or, when empty, `c->transport_error`.
    pub protocol_error: &'a [u8],
    /// `c->h2_debug`.
    pub h2_debug: &'a [u8],
    /// `c->control_stage`.
    pub control_stage: u32,
    /// `c->derp.tls_verify_failures`.
    pub derp_tls_verify_failures: u32,
    /// `c->derp.tls_deferred`.
    pub derp_tls_deferred: u32,
    /// `ml_derp_link_state_name(c->derp.link.state)`.
    pub derp_state: &'a [u8],
    /// `frames_rx`.
    pub frames_rx: u32,
    /// `frames_tx`.
    pub frames_tx: u32,
    /// `rx_timeouts` (reported as `record_timeouts`).
    pub record_timeouts: u32,
    /// `tx_stalls` (reported as `write_stalls`).
    pub write_stalls: u32,
    /// `alloc_drops`.
    pub alloc_drops: u32,
    /// `connects`.
    pub connects: u32,
    /// `c->ctrl_key_auth`.
    pub control_key_auth: u32,
    /// `c->jit_hits`.
    pub jit_hits: u32,
    /// `c->jit_misses`.
    pub jit_misses: u32,
    /// `c->jit_evictions`.
    pub jit_evictions: u32,
    /// `c->jit_rejected`.
    pub jit_rejected: u32,
    /// `c->jit_dropped`.
    pub jit_dropped: u32,
    /// `c->directory.count`.
    pub directory_records: u32,
    /// The next page offset (`v->peer_offset`).
    pub next_peer_offset: u32,
    /// The page start (`v->page_start`).
    pub peer_page_start: u32,
    /// The peers of this page.
    pub peers: &'a [Peer<'a>],
}

/// One membership (`status_member`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Member<'a> {
    /// `id`.
    pub id: u32,
    /// `start_heap_before`.
    pub start_heap_before: u64,
    /// `start_heap_after`.
    pub start_heap_after: u64,
    /// `label`.
    pub label: &'a [u8],
    /// `enabled`.
    pub enabled: bool,
    /// `error` (the membership's own runtime error, see the members crate).
    pub error: &'a [u8],
    /// `state` (`ml_state_t`; 0 without a client).
    pub state: u32,
    /// `routing_ready`: enabled, WireGuard netif up, connected, key not expired, no error, directory session valid.
    pub routing_ready: bool,
    /// The client, when there is one.
    pub client: Option<Client<'a>>,
}

/// The whole `/status` body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status<'a> {
    /// `GATEWAY_VERSION`.
    pub firmware: &'a [u8],
    /// `tdongle_mode_name(runtime_mode)`.
    pub mode: &'a [u8],
    /// The sensor.
    pub chip_temperature: Temperature,
    /// `gateway_boot_recovery()`.
    pub recovery: bool,
    /// `member_start_budget()`.
    pub membership_start_budget: u64,
    /// `sizeof(microlink_t)`.
    pub membership_context_bytes: u64,
    /// The admission arithmetic.
    pub admission: Admission,
    /// The shared tasks.
    pub shared_runtime: SharedRuntime,
    /// The WireGuard peer pool.
    pub wg_pool: WgPool,
    /// The shared RNG.
    pub shared_rng: SharedRng,
    /// Power.
    pub power: Power<'a>,
    /// Sockets.
    pub sockets: Sockets,
    /// `esp_reset_reason()`.
    pub reset_reason: u32,
    /// `online`.
    pub wifi: bool,
    /// The `wifi_link` object as `wifi_link_json` rendered it (without a key); `None` when it did not fit (the key is then omitted).
    pub wifi_link: Option<&'a [u8]>,
    /// The clock.
    pub clock: Clock<'a>,
    /// `wifi_saved.profiles[i].ssid`.
    pub saved_wifi: &'a [&'a [u8]],
    /// `route_storage_ok`.
    pub route_storage_ok: bool,
    /// `esp_get_free_heap_size()`.
    pub free_memory: u32,
    /// `heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL)`.
    pub largest_free_block: u32,
    /// `heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL)`.
    pub minimum_free_memory: u32,
    /// The heap budget.
    pub heap_budget: HeapBudget,
    /// The Wi-Fi pins.
    pub wifi_pins: WifiPins,
    /// The memberships, newest first.
    pub members: &'a [Member<'a>],
}
