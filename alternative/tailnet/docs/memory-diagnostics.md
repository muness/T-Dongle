# Memory diagnostics profile

Evidence tooling for the multi-tailnet memory overhaul (epic #22; issues #7, #8, #9, #10). It builds the instruments only. Measurement runs and their results go in `docs/diagnostics/`.

The profile is a Kconfig option, `CONFIG_TDONGLE_MEMORY_DIAGNOSTICS` (component `tdongle_runtime`), **off by default**. With it off, every hook compiles to the plain allocator call, the console has no new commands and `capabilities` is unchanged. Never ship a diagnostics image.

## Build and flash

```sh
. ~/.cache/tdongle/esp-idf-v5.5.5/export.sh
alternative/tailnet/tools/build-diagnostics.sh                  # build-diagnostics/
alternative/tailnet/tools/build-diagnostics.sh --queue-depth 4  # build-diagnostics-q4/ (sweep: 1, 2, 4, 8)
```

The script runs the equivalent of:

```sh
idf.py -B build-diagnostics -D IDF_TARGET=esp32s3 \
  -D SDKCONFIG=$PWD/build-diagnostics/sdkconfig \
  -D "SDKCONFIG_DEFAULTS=$PWD/alternative/tailnet/sdkconfig.defaults;$PWD/alternative/tailnet/sdkconfig.diagnostics" build size
```

Flash app-only (keeps NVS and the saved memberships). Use DIO at 40 MHz as shown, not the 80 MHz that `idf.py` may print: this board's W25Q128 boot-loops at QIO 80 MHz (`docs/REFERENCE.md`).

```sh
python -m esptool --chip esp32s3 -b 460800 --before default_reset --after hard_reset write_flash \
  --flash_mode dio --flash_size 16MB --flash_freq 40m 0x20000 build-diagnostics/tdongle_unified.bin
```

Check the profile before trusting a result: the default build must say `# CONFIG_TDONGLE_MEMORY_DIAGNOSTICS is not set` in `sdkconfig.unified`, and a diagnostics image answers `capabilities` with `memory_diagnostics` in its feature list.

| Option | Default in the fragment | Meaning |
|---|---|---|
| `TDONGLE_MEMORY_DIAGNOSTICS` | y (n elsewhere) | The whole profile |
| `TDONGLE_MEMORY_GUARD_FLOOR_BYTES` | 12288 | Free-heap floor for tagged allocations and task stacks. Runtime: `memory guard <bytes>` |
| `TDONGLE_MEMORY_ADMISSION_OVERRIDE` | y | Start memberships past `member_start_budget()` |
| `TDONGLE_QUEUE_DEPTH_SWEEP` | 0 | 1, 2, 4 or 8 sets DERP TX / DISCO RX / WG RX depth (STUN RX is `min(N, 4)`); 0 keeps 8/8/8/4 |

## What changes at run time

- **Admission override.** A membership that fails the 107 KB budget or the 24,000 B largest-block gate is started anyway when free heap is at least the guard floor. Failures stay bounded: the guard refuses tagged allocations that would leave less than the floor, `microlink_start` refuses to create the task stacks if they would do the same, and a failed attempt is retried at most once a minute. Every decision is recorded (see `members`). On the current build, with about 36 KB free after one membership, expect the second attempt to end as `start_failed` before the tasks exist (the four stacks alone are 36,864 B). That is itself the measurement. `memory guard 0` removes the floor for the stacks and for tagged allocations, so FreeRTOS fails the stack that does not fit and the attempt still ends cleanly.
- **Guard denials replace low-memory crashes.** With the guard on, traffic that would have taken the heap to 6 KB (see `docs/diagnostics/baseline-0.2.22-2026-10-05.md`) is dropped at the allocator and counted (`owners.*.denied`). **Take throughput baselines on the release image, or run `memory guard 0`.** The tagged allocator also adds a few instructions per allocation; `memory bench` measures them.

## Serial commands

All reports are one JSON line each, plain ASCII, with `"schema":1`. They contain no keys, auth keys, login URLs, labels or host names. Lines are followed by the usual `done>`.

| Command | Prints |
|---|---|
| `memory` | `heap`, `attribution`, `lwip` |
| `members` | one `phases` per membership slot (up to 3), then `admission` |
| `memory guard <0-65536>` | `guard` after setting the floor |
| `memory bench` | `bench` |
| `route` | `route`: the router's cumulative counters (forwarding, tunnel->USB reject reasons, `usb_tx`) |
| `inbound` | `inbound`: every inbound drop point from the UDP socket to the USB transmit, cumulative (below) |

### `heap`

`uptime_ms`, `firmware`, `free`, `min` (lowest since boot), `largest`, `total` (internal heap size), `guard_floor`, `underflows`, `ledger_bytes`, `queue_depth{derp_tx,disco_rx,wg_rx,stun_rx}`, `owners{<owner>:{live,peak,allocs,frees,failed,denied}}`, `drops{...}`.

Owners: `other`, `tls`, `control`, `map`, `peer`, `wg`, `packet`, `context`.

| Owner | Covers |
|---|---|
| `tls` | Every mbedTLS allocation (DERP, control-key fetch, esp-tls), through `mbedtls_platform_set_calloc_free` |
| `control` | Noise/HTTP2 control channel: frame, request and response buffers, early-payload cursor, `h2_acc` |
| `map` | Every cJSON allocation (the cJSON hooks are global): map parsing, request and reply JSON |
| `peer` | Peer update records and map batches |
| `wg` | The WireGuard device (`wireguardif_init`, 14.7 KB), the netif, queued host packets |
| `packet` | Relay and receive payloads, DERP frames, UDP output wrapper |
| `context` | The `microlink_t` instance |
| `other` | DISCO scratch, DERP ClientInfo scratch, the bench buffer |

`allocs - frees` is the number of blocks outstanding. A tag that grows while the tunnel is idle means a free site was missed. `underflows` counts frees of blocks the ledger never saw. Both are visible by design: a missed site leaves the memory safe and the ledger wrong in a way you can see, which a block header could not promise (see below).

`drops` counts packets discarded at a full queue: `derp_tx_evict` (oldest evicted for a new packet), `derp_tx_full`, `derp_rx_full`, `net_disco_full`, `net_wg_full`, `net_stun_full`, `router_ingress` (USB host packet dropped before routing). Counters wrap; diff two samples.

### `attribution`

`allocated` (internal heap in use), `tagged` (sum of owner `live`), `synthetic` (task stacks, TCBs and queue storage computed from the configured sizes of every live task), `unattributed = allocated - tagged - synthetic`, `members_omitted`, `members[{id,tasks,stacks,tcbs,queues,stack_free[net_io,derp_tx,coord,wg_mgr]}]` and `n2{...}`.

`unattributed` includes Wi-Fi, lwIP, USB, the HTTP server and block headers, so it is a baseline, not a per-membership number. **Read the per-membership remainder as the difference between ladder steps.** The review trigger for issue #8 is that difference exceeding 10 KB.

### `phases`

One line per membership slot: `member`, `attempt`, `owner_order`, and `phases{<phase>:{t,free,min,largest,exact,peak[8]}}` for the phases reached. Phases, in order:

| Phase | Mark |
|---|---|
| `start` | Admission passed, before `microlink_init` |
| `control` | TCP connect to the control server done |
| `noise` | Noise handshake done |
| `register` | Registration done |
| `map` | Initial netmap applied (VPN IP and generation known) |
| `derp` | DERP TLS and ClientInfo done (marks again on every DERP reconnect) |
| `steady` | 60 s after `map` |

A record describes the interval since the previous mark: `free` at the mark, `min` the lowest free heap in the interval, `largest` the largest free block at the mark, `peak[]` the peak live bytes per owner in the interval, in `owner_order`. `min` is exact (`"exact":1`) when the heap-wide minimum fell during the interval, because the minimum only ever falls. Otherwise it is the lowest value seen at an allocation or boundary, which can miss a dip made by lwIP or Wi-Fi. For `start`, `min` is sampled only. Joins overlapping in time share owner peaks and minima, which is what the concurrent-join measurement (#9) wants. The low-water ring that `status` prints also gets a record per mark, with `operation = 16 + phase`.

### `admission`

`guard_floor`, `override`, `slot_evictions`, `attempts[{t,member,free,largest,budget,sockets,socket_limit,active,verdict}]` (the last six). Verdicts: `ok`, `refused_budget`, `refused_largest`, `refused_sockets`, `override`, `refused_floor`, `start_failed`. A `start_failed` is logged after the admission entry for the same attempt.

### `lwip`

The effective settings of this build, read from the preprocessed lwIP headers of the unified build (0.2.22 configuration, `sdkconfig.unified`):

| Setting | Value | Note |
|---|---|---|
| `TCP_WND` (per connection receive window) | 5,760 B | 4 x MSS; no window scaling (`LWIP_WND_SCALE` 0). A 16 KB TLS record needs three window refills |
| `TCP_SND_BUF` (per connection) | 5,760 B | `TCP_SND_QUEUELEN` 16, `MEMP_NUM_TCP_SEG` 16 |
| `TCP_MSS` | 1,440 B | |
| `PBUF_POOL_SIZE` x `PBUF_POOL_BUFSIZE` | 16 x 1,496 B | `MEM_LIBC_MALLOC` is 1: pool elements come from the heap |
| `MEMP_NUM_TCP_PCB` / `MEMP_NUM_PBUF` | 16 / 16 | |
| Wi-Fi buffers | 6 static RX, 16 dynamic RX, 16 dynamic TX | |
| Sockets | 20 | |

The firmware prints the same values (`lwip` line) so a result file records the build it came from.

### `inbound`

Cumulative counters (never reset; subtract two samples) for every place an inbound datagram can be lost or refused between the Wi-Fi interface and the USB host, plus the ones that count it arriving, so each hop can be reconciled against the next. Fields: `udp_recvmbox`, `drain_cap`, `wg_rx_queue_depth`, `replay_window` (configuration); `lwip` {`udp_recv`, `udp_drop`, `udp_memerr`, `udp_err`}; `ml` (net_io, the queues, wg_mgr: `ml_rx_stats.h`); `wg` (the WireGuard receive path, one terminal counter per datagram: `wireguard_stats.h`); `route` (tunnel to USB reject reasons, `forwarded_in`, `usb_tx`, `usb_tx_err`, `tx_fail`). lwIP counts a UDP datagram in `udp_recv` before the socket mailbox and frees it silently when the mailbox is full, so `udp_recv - ml.udp_rx` is the mailbox loss. `tools/inbound_accounting.py` takes two snapshots around an `iperf3 -u -R` run and prints the whole chain, the counted drops and what is left unattributed. docs/adr/0019-inbound-loss.md explains each counter.

### `bench`

`plain_ns_per_pair` and `tagged_ns_per_pair`: a 64 B malloc+free, plain and through the ledger. `chacha20poly1305_ns_per_packet` and `copy_ns_per_packet`: the WireGuard cipher (the reference C implementation in `wireguard_lwip`, not mbedTLS) over one 1,400 B packet and a plain copy of the same size; `cipher_ceiling_kbit_s` is the throughput one core would reach doing nothing else. This is the CPU split issue #10 asks for.

## N2': are `lp_acc` and the 64 KB H2 window real memory in gateway mode?

**No.** (`attribution.n2` reports it live.)

- `lp_acc` (`CONFIG_ML_JSON_BUFFER_SIZE_KB=64`, 65,536 B) is **never allocated**. Nothing assigns it; `microlink_destroy` only frees it. The field costs 8 bytes in `microlink_t`. `n2.lp_acc_allocated` is false on every membership.
- The 64 KB H2 setting (`CONFIG_ML_H2_BUFFER_SIZE_KB=64`) is **not a buffer**. `ml_h2.c` and `do_h2_preface` use it only as the advertised HTTP/2 flow-control window (`SETTINGS_INITIAL_WINDOW_SIZE` and the connection `WINDOW_UPDATE`, at registration). It lets the server send 64 KB unacknowledged. The bytes are consumed as they arrive.
- What is allocated for the control channel: the shared static workspaces `gateway_plain` (20,496 B) and `gateway_json` (16,384 B), both in `.bss` and shared by every membership under `gateway_lock`; per-membership `h2_acc` carry-over of at most 4,096 B (`n2.h2_acc_live_max` shows it) and transient `control` buffers (`json + 512 + 16` for each request).

So the "64 KB + 64 KB" in the budget arithmetic is not paid. Sizing the window "to the workspace" (S&T step N2') changes only how much the server may send ahead; it frees no heap. Whether a smaller window stalls the control server is untested.

## Choosing the attribution mechanism

Constraint from issue #8: the trace must cost under about 2 KB and must not shift behaviour.

| Mechanism | Verdict |
|---|---|
| `CONFIG_HEAP_USE_HOOKS` (global alloc/free hooks) | Sees every allocation, but `esp_heap_trace_free_hook(ptr)` runs after `multi_heap_free` (`heap_caps_base.c`), so size and owner are gone. A ledger needs a pointer-to-owner table with one entry per live block, hundreds of entries. Rejected. |
| `CONFIG_HEAP_TRACING_STANDALONE` | A `heap_trace_record_t` is about 44 B (ccount, address, size, freed flag, two call stacks of depth 2, list and hash links). A few hundred live blocks cost 20-35 KB of the heap being measured. Rejected. |
| `CONFIG_HEAP_TASK_TRACKING` | 4 B per block everywhere (about 3 KB for 800 blocks), attributes by task, not by purpose, and cannot tell TLS from packets inside the DERP task. Good fallback if more than 10 KB stays unattributed: it names the owning task for the remainder. |
| Header on tagged blocks | Needs every `free` site to know about the header. Blocks cross files and components (`router.c`, lwIP custom pbufs) and `cJSON_PrintUnformatted` results are freed with plain `free`, so one missed site corrupts the heap. Rejected. |
| **Tagged wrappers (chosen)** | `tdongle_heap_tag(owner, malloc(...))` and `tdongle_heap_free(owner, ptr)` at microlink's allocation sites, `mbedtls_platform_set_calloc_free` for TLS, size read with `heap_caps_get_allocated_size` at free time. No per-block storage. A missed or mismatched free site cannot corrupt memory; it shows as `allocs - frees` drift or `underflows`. |

Overhead, from `idf.py size` against the same tree without the profile (origin/overhaul/multi-tailnet at abf47c1):

| | Release | Diagnostics | Delta |
|---|---|---|---|
| Static RAM (`.bss`) | 83,040 B | 84,752 B | **+1,712 B**: the ledger is 1,696 B (`heap.ledger_bytes`), the rest is the lock and counters; `.data` grows by 16 B |
| Heap per tagged block | 0 | 0 | none |
| Flash code | 820,712 B | 826,636 B | +5,924 B |
| Flash data (`.rodata`) | 277,120 B | 278,720 B | +1,600 B |

With the option off the image differs from the unmodified tree by +36 B of flash code (the cJSON free wrapper) and no RAM.

Time per tagged allocation is measured on the board by `memory bench`; it was not measured in this change (no hardware access).

### Coverage and known gaps

Tagged: every `malloc`, `calloc` and `ml_psram_*` site in `ml_coord.c`, `ml_derp.c`, `ml_net_io.c`, `ml_wg_mgr.c`, `microlink.c`, the `gateway_*.inc` files and the gateway's cJSON users. Not tagged, and therefore in `unattributed`:

- FreeRTOS task stacks, TCBs, queues and event groups: computed into `synthetic` from their configured sizes instead.
- The per-peer and per-packet allocations inside the vendored `wireguard_lwip` library (the library is hash-pinned, so it is not edited). The 14.7 KB device is adopted into `wg` right after `wireguardif_init`.
- lwIP sockets, PCBs and pbufs, the Wi-Fi driver, USB, the HTTP server, NVS, the esp-tls handle structs.
- `ml_tcp.c`, `ml_udp.c`, `ml_peer_nvs.c`, cellular, AT sockets and the config HTTP server: compiled but not used by the gateway.
- Per-membership TLS bytes: the mbedTLS hook cannot see which membership it serves. Difference the `tls` owner between ladder steps.

## Running the ladder (#7, #8, #9)

Hardware belongs to the coordinator; run these with the diagnostics image flashed.

```sh
python3 -m pip install -r tools/requirements.txt          # pyserial
T=alternative/tailnet/tools
$T/memory_ladder.py capture --label 0m --interval 5 --max-duration 60                 # Wi-Fi up, no membership enabled
$T/memory_ladder.py capture --label 1m --until-steady 1 --interval 5                  # enable membership 1, then run
$T/memory_ladder.py capture --label 2m --until-steady 2 --interval 5 --max-duration 400  # enable membership 2
$T/memory_ladder.py compare alternative/tailnet/docs/diagnostics/ladder-0m-*.jsonl \
    alternative/tailnet/docs/diagnostics/ladder-1m-*.jsonl alternative/tailnet/docs/diagnostics/ladder-2m-*.jsonl
```

Each capture refuses to run on a release image, writes `docs/diagnostics/ladder-<label>-<UTC>.jsonl` (a `meta` record, one `sample` per interval holding every report, `event` records for console errors, device resets and timeouts, and a closing `summary`) and exits on its own once N memberships are steady and one more sample has been taken. `compare` prints the free, largest-block, unattributed and per-owner deltas between consecutive files: that is the marginal cost 0 to 1 and 1 to 2. Keep every file; do not edit them.

Join peaks (#9): start `capture` before enabling the memberships; `phases[].phases.*.min` and `peak` give each phase, and the heap line's `min` the overall low point. A Wi-Fi reconnect storm is toggled on the access point while a capture with `--interval 2` runs; `device_reset` events flag a crash.

## Throughput and latency (#10)

```sh
iperf3 -s                                  # on the reference peer
$T/tailnet_throughput.py 198.18.0.86 --path direct --bind 192.168.77.2 --serial /dev/cu.usbmodem1101 --label depth8
```

Runs TCP up, TCP down and UDP up three times each (`--repeats`, minimum 3), measures RTT after each repeat and writes `docs/diagnostics/throughput-<path>-<UTC>.json` with per-run values, median/min/max, p50/p99 RTT and, with `--serial`, heap, drop-counter deltas and queue depth. The gateway answers TCP and UDP only, so ICMP usually fails; the script then times TCP connects to the iperf3 port. `--path` is a label: you arrange the path (direct on a shared LAN; DERP-only with `TS_DEBUG_ALWAYS_USE_DERP=1` on the peer's tailscaled, or by blocking its UDP) and check it with `tailscale ping`. For the queue sweep build 1, 2, 4 and 8 with `build-diagnostics.sh --queue-depth N`, and run once per image with `--label depthN`. Use `memory guard 0` for these runs so allocator denials do not mask the drop counters you are measuring, or accept that denied packets are counted under `owners.*.denied`.

## Tests

`components/tdongle_runtime/tests/run.sh` builds the recorder, ledger, phase capture, drop counters and admission ring on the host under ASan/UBSan, including wraparound of the uptime clock and rings, peak tracking, underflow and the guard, and fails if any recording path touches `malloc`, `calloc`, `realloc` or `strdup`. `alternative/tailnet/tools/test-measurement-scripts.py` exercises the serial framing, ladder capture and compare, and the throughput statistics against a fake console. `alternative/tailnet/tools/test-memory-report.py` compiles `main/memory_diagnostics.inc` against host stubs and checks that every report is one valid, bounded JSON line with the documented fields. Both run from `alternative/tailnet/tools/test-gateway.sh`.
