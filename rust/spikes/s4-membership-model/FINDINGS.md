# S4: memory model of one tailnet membership (no_std embassy task set) vs the C's budget

(Written by the coordinator from the spike agent's report; the agent's Write tool was refused.)

`s4.bin` builds (merged 16 MiB image, app 885,712 B) but **has never run on a board** (QEMU here has no ESP32-S3 machine). The shared model code ran on the
host, where every handshake verified; the firmware glue compiled and linked. Tags: M-elf = measured from the xtensa ELF, M-host = measured on the 64-bit host
(requested bytes), EST = derived arithmetic. Real crates are used: `snow` 0.10 Noise IK, `embedded-tls` 0.19 against a recorded rustls server transcript,
`mbedtls-rs` 0.3 (real mbedTLS client+server handshake over in-memory pipes), `smoltcp` 0.14 sockets, WireGuard on `chacha20poly1305` / `blake2` / `x25519-dalek`.

## Verdict

The no_std model does **not** cost less per membership than the C. Leaner per-membership state does not buy N=2; the only route to N=2 is a larger starting heap.

| N | std (Rust on ESP-IDF; TLS and lwIP stay the C's) | no_std, default buffers | no_std, small socket buffers |
|---|---|---|---|
| 1 | fits (+1.5 KB over the floor at the join dip) | fits | fits |
| 2 | does not fit (short 24.4 KB steady, 37.9 KB at the join dip) | marginal (clears 29,884 B only if the starting heap is in the top quarter of its estimate) | fits, marginal at the low end |
| 3 | does not fit | does not fit | does not fit (best case 9 KB free) |

* std: the numbers are the C's own arithmetic (ADR 0013:74, 0021). Of a further membership's 39.4 KB, 10.6 KB is C code that stays (TLS 1,336 + lwIP 9,300). N=2
  needs the Rust-owned remainder (29.1 KB) cut to 4.4 KB; the model's own Rust-owned coordination + WireGuard state is already 13.5 KB.
* no_std, free heap with F0 = estimated starting heap 168.8 to 213.8 KB (EST, about +-30 KB; the radio's heap use was never measured because the radio is not started):
  N=1 78.0 to 123.0 KB (default) / 94.6 to 139.6 KB (small sockets); N=2 -3.7 to 41.3 / 29.5 to 74.5; N=3 -85.4 to -40.4 / -35.7 to 9.3.

## Per membership, model vs C

| Item | Model (B) | Tag | C (B) |
|---|---|---|---|
| Coord receive buffers (streaming window) | 6,403 | M-host | one static pair shared by all memberships (36,880 once, 0 marginal) |
| Peer table, 8 records | 3,584 | M-elf | 3,712 |
| Coord task | 944 (task-pool slot) | M-elf | stack 8,704 + TCB 340 |
| DERP TLS steady | 22,320 (16,640 read buffer + 4,096 write + config + task slot) | M-host/M-elf | 1,336 |
| DERP TLS handshake heap peak | 0 (stack 31,120 static bound; handshake future 9,032 once) | M-host/M-elf | 13,500 heap, 7,680 stack |
| WireGuard device + 2 peers | 2,168 (+496 task slot) | M-elf | 2,420 |
| WireGuard, all 8 peers | 7,872 | M-host | 8,768 |
| 5 sockets, TCP windows = C's 8,640 | 35,488 (preallocated) | M-host | lwIP 9,300 |
| 5 sockets, small windows | 18,904 | M-host | not throughput-validated |
| DISCO/STUN queues (inline 1.5 KB slots, 8+4) | 18,456 | M-host | |
| **Per membership, default** | **81,731** | | 39,380 to 40,900 further; 62.9 KB first |
| **Per membership, small sockets** | **65,147** | | |

Worse than the C: TLS record buffers (+21 KB, structural: `embedded-tls` pins its 16,640 B read buffer for the connection's life and Go's `crypto/tls` ignores
`max_fragment_length`) and preallocated sockets (+26 KB default, +9.6 KB small). Same or slightly better: WireGuard state, peer table, no per-membership stack, no
heap handshake peak. `mbedtls-rs` steady cost is about 21 KB per connection (EST; no IDF-style dynamic buffer free). Pooling the TLS read buffer across memberships
would make N=3 with small sockets marginal (needs a TLS library with lease-per-read; not built).

## Platform baseline (free heap when membership 1 starts)

* std: F0 = 107.8 KB after USB start (ADR 0015); the board boots with 128.6 KB free, so IDF services consume about 106 KB.
* no_std (EST): SRAM1 415,504 - IRAM with esp-radio linked 41,960 - HAL/rtos/radio data 22,104 - USB buffers 17,128 - bridge queue + ring 24,576 - executor stack 40,960
  = 268,776 B for heap, Wi-Fi and net runtime, minus Wi-Fi driver + embassy-net heap (EST 55 to 100 KB) = 168.8 to 213.8 KB.

## Crate findings

* `embedded-tls` `webpki` feature does not build (`rustls-webpki` 0.101 pulls `ring` -> `getrandom` 0.2, unsupported target); `rustpki` + `p384` works.
* `mbedtls-rs` builds only with `use-gcc` (the default CMake path calls host clang with `-mcpu=esp32s3`); it leaves `snprintf`/`vsnprintf`/`printf`/`puts` undefined
  (stubbed in `src/libc_stubs.rs`); no hardware-accel hooks; certificate dates not checked.
* `rustls-rustcrypto` 0.0.2-alpha builds only with a `getrandom` 0.2 `custom` shim; no handshake was run, rustls memory is unmeasured.
* `hmac` 0.13 does not accept `Blake2s256` (HMAC-BLAKE2s is hand-written); `snow` needs a custom RNG resolver. Working: embedded-tls, snow, x25519-dalek 3.0,
  chacha20poly1305 0.11, blake2 0.11, smoltcp 0.14.
* Not modelled (all push cost up): NAPT (smoltcp has none), DNS, router queues, HTTP portal, a real map projector, fragmentation, CPU time and throughput.

## What to read from a board run (`s4.bin`, serial output from boot; waits 3 s for a monitor)

`S4 MEMBERSHIP n retained=` for n=1..3 (host: about 68,627 each); `S4 PHASE tls.handshake+verify... peak=` (expect 0) and `stack_below_call` (static bound 31,120);
`S4 TAG ... poll_stack_max=`; real mbedTLS: `S4 TAG mbedtls-client heap_peak=` (C 13,500), `S4 MBED client steady` heap_now (C 1,336); every `S4 DONE ... ok=true` and
`alloc_fails=0`. Free heap with the radio and USB up needs another spike. Raw data: `results/`.
