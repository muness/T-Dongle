# WireGuard Implementation for lwIP

This project is a C implementation of the [WireGuard&reg;](https://www.wireguard.com/) protocol intended to be used with the [lwIP IP stack](https://www.nongnu.org/lwip/)

# Motivation

There is a desire to use secure communication in smaller embedded devices to communicate with off-premises devices; WireGuard&reg; seems perfect for this task due to its small code base and secure nature

This project tackles the problem of using WireGuard&reg; on embedded systems in that it is:
- malloc-free so fits into a fixed RAM size
- written entirely in C
- has low memory requirements in terms of stack size, flash storage and RAM
- compatible with the popular lwIP IP stack

# Code Layout

The code is split into four main portions

- wireguard.c contains the bulk of the WireGuard&reg; protocol code and is not specific to any particular IP stack
- wireguardif.c contains the lwIP integration code and makes a netif network interface and handles periodic tasks such as keepalive/expiration timers
- wireguard-platform.h contains the definition of the four functions to be implemented per platform (a sample implementation is given in wireguard-platform.sample)
- crypto code (see below)

## Crypto Code

The supplied cryptographic routines are written entirely in C and are not optimised for any particular platform. These work and use little memory but will probably be slow on your platform.

You probably want to swap out the suplied versions for optimised C or assembly versions or those available throught the O/S or crypto libraries on your platform. Simply edit the crypto.h header file to point at the routines you want to use.

The crypto routines supplied are:
- BLAKE2S - adapted from the implementation in the RFC itself at https://tools.ietf.org/html/rfc7693
- CHACHA20 - adapted from code at https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c; the block function was rewritten for ESP32-S3 (see below)
- HCHACHA20 - implemented from scratch following description here https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html
- POLY1305 - state handling from https://github.com/floodyberry/poly1305-donna; the arithmetic core was rewritten for ESP32-S3 (5 x 32-bit limbs, branch-free carries, see below)
- CHACHA20POLY1305 - implemented from scratch following description here https://tools.ietf.org/html/rfc7539
- AEAD_XChaCha20_Poly1305 - implemented from scratch following description here https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html
- X25519 - taken from STROBE project at https://sourceforge.net/p/strobe, in addition there is a version optimised for Cortex-M0 processors which requires very little stack taken from https://munacl.cryptojedi.org/curve25519-cortexm0.shtml

### ESP32-S3 performance notes (Xtensa LX7)

The portable code above was 60 instructions per byte on the LX7 (one 1400-byte seal ~ 85k instructions) and
the compiler-generated Poly1305 carried 25 data-dependent branches per block at `-Os`. The version in
`src/crypto/refc` is about 43 instructions per byte, branch-free, and works at any alignment:

- ChaCha20: the 16 state words are locals (no pointer-indirect state, no out-of-line round function),
  rotates are `ssai`+`src`, and the keystream is XORed a word at a time when both buffers are 4-byte aligned.
- Poly1305: 5 x 32-bit limbs (16 MULL/MULUH pairs per block instead of 25); carries are unsigned compares
  (`saltu`), never branches. The aligned/unaligned decision is made outside the loops because GCC for
  Xtensa merges an in-loop word-load/byte-load `if` into the byte-wise arm and silently drops the fast path.
- Misaligned input (an IP packet at the +14 offset behind an Ethernet header) works and costs ~8% more.

Tools (all in this tree):

- `crypto bench` on the serial console: RFC self-test, then cycles for ChaCha20, Poly1305, seal and open at
  64/512/1400 bytes plus a misaligned seal/open. `min` is best-of-8 with interrupts masked (the intrinsic cost);
  `avg` is the mean with interrupts enabled (what the running system pays). A large avg/min gap means
  preemption or flash-cache eviction; `CONFIG_WG_CRYPTO_IRAM` moves the per-packet code (~3 KB) to IRAM.
  `CONFIG_WG_CRYPTO_BENCH_BASELINE` adds the original implementation as an A/B column.
- `tools/xtensa-insn-count/run.sh [-Os|-O2] [len] [offset] [new|legacy|mbedtls]`: compiles the real code with the
  Espressif GCC for ESP32-S3, executes it on a small Xtensa emulator, checks the output against a host oracle
  and prints exact executed-instruction counts (plus a documented cycle estimate) and the conditional-branch
  count of the secret-dependent functions (loop control only is expected).
- `alternative/tailnet/tests/test_wg_crypto.c` (host, sanitised): RFC 8439 vectors, differential tests against
  the original code and mbedTLS, tag-failure semantics. `alternative/tailnet/tools/bench-wg-crypto.sh`: host bench.

`src/crypto/legacy/wg_crypto_legacy.c` is the original implementation kept as the test oracle and the bench
baseline; it is not linked into the firmware unless `CONFIG_WG_CRYPTO_BENCH_BASELINE` is set.

# Integrating into your platform

You will need to implement a platform file that provides four functions
- a monotonic counter used for calculating time differences - e.g. sys_now() from lwIP
- a tain64n timestamp function, although there are workarounds if you don't have access to a realtime clock
- an indication of whether the system is currently under load and should generate cookie reply messages
- a good random number generator

# lwIP Code Example
(note error checking omitted)

    #include "wireguardif.h"

    static struct netif wg_netif_struct = {0};
    static struct netif *wg_netif = NULL;
    static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

    static void wireguard_setup() {
        struct wireguard_interface wg;
        struct wireguardif_peer peer;
        ip_addr_t ipaddr = IPADDR4_INIT_BYTES(192, 168, 40, 10);
        ip_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
        ip_addr_t gateway = IPADDR4_INIT_BYTES(192, 168, 40, 1);

        // Setup the WireGuard device structure
        wg.private_key = "8BU1giso23adjCk93dnpLJnK788bRAtpZxs8d+Jo+Vg=";
        wg.listen_port = 51820;
        wg.bind_netif = NULL;

        // Register the new WireGuard network interface with lwIP
        wg_netif = netif_add(&wg_netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);

        // Mark the interface as administratively up, link up flag is set automatically when peer connects
        netif_set_up(wg_netif);

        // Initialise the first WireGuard peer structure
        wireguardif_peer_init(&peer);
        peer.public_key = "cDfetaDFWnbxts2Pbz4vFYreikPEEVhTlV/sniIEBjo=";
        peer.preshared_key = NULL;
        // Allow all IPs through tunnel
        peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        peer.allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);

        // If we know the endpoint's address can add here
        peer.endpoint_ip = IPADDR4_INIT_BYTES(10, 0, 0, 12);
        peer.endport_port = 12345;

        // Register the new WireGuard peer with the netwok interface
        wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);

        if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
            // Start outbound connection to peer
            wireguardif_connect(wg_net, wireguard_peer_index);
        }
    }


# More Information

WireGuard&reg; was created and developed by Jason A. Donenfeld. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. See https://www.wireguard.com/ for more information

This project is not approved, sponsored or affiliated with WireGuard or with the community.

- The whitepaper https://www.wireguard.com/papers/wireguard.pdf
- The Wikipedia page https://en.wikipedia.org/wiki/WireGuard

# License

The code is copyrighted under BSD 3 clause Copyright (c) 2021 Daniel Hope (www.floorsense.nz)

See LICENSE for details

# Contact

Daniel Hope at Smartalock
