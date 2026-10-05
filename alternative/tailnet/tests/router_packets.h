#pragma once
/* Packet construction and independent verification helpers shared by the router
 * host tests. Deliberately simple and unrelated to the router's own code. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#ifdef PK_SHORT_NAMES
#define rd16 pk_rd16
#define rd32 pk_rd32
#define wr16 pk_wr16
#define wr32 pk_wr32
#define sum pk_sum
#define finish pk_finish
#define rnd pk_rnd
#endif
static _Thread_local uint64_t rng_state = 88172645463325252ull;
static uint32_t pk_rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 11);
}
static uint16_t pk_rd16(const uint8_t *p) { return p[0] << 8 | p[1]; }
static uint32_t pk_rd32(const uint8_t *p) { return (uint32_t)pk_rd16(p) << 16 | pk_rd16(p + 2); }
static void pk_wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void pk_wr32(uint8_t *p, uint32_t v) { pk_wr16(p, v >> 16); pk_wr16(p + 2, v); }
static uint32_t pk_sum(const uint8_t *p, size_t n, uint32_t s) {
    for (; n > 1; p += 2, n -= 2)
        s += pk_rd16(p);
    if (n)
        s += p[0] << 8;
    return s;
}
static uint16_t pk_finish(uint32_t s) {
    while (s >> 16)
        s = (s & 65535) + (s >> 16);
    return ~s;
}
static void fill_checksums(uint8_t *b, size_t n, unsigned h, bool udp_none) {
    pk_wr16(b + 10, 0);
    pk_wr16(b + 10, pk_finish(pk_sum(b, h, 0)));
    unsigned offset = b[9] == 6 ? 16 : 6;
    pk_wr16(b + h + offset, 0);
    if (udp_none)
        return;
    uint16_t c = pk_finish(pk_sum(b + h, n - h, pk_sum(b + 12, 8, 0) + b[9] + (n - h)));
    pk_wr16(b + h + offset, c ? c : 0xffff);
}
static bool l4_valid(const uint8_t *b, size_t n, unsigned h) {
    if (b[9] == 17 && !pk_rd16(b + h + 6))
        return true;
    return pk_finish(pk_sum(b + h, n - h, pk_sum(b + 12, 8, 0) + b[9] + (n - h))) == 0;
}

/* Build a valid IPv4 TCP/UDP packet. `syn` adds an MSS option. */
static size_t build_packet(uint8_t *b, uint32_t src, uint32_t dst, uint8_t proto, uint16_t sport, uint16_t dport, size_t payload, bool syn, bool udp_none) {
    unsigned tcp_h = syn ? 24 : 20, h = 20;
    size_t n = h + (proto == 6 ? tcp_h : 8) + payload;
    memset(b, 0, n);
    b[0] = 0x45;
    b[8] = 2 + pk_rnd() % 62;
    b[9] = proto;
    pk_wr16(b + 2, n);
    pk_wr16(b + 4, pk_rnd());
    pk_wr32(b + 12, src);
    pk_wr32(b + 16, dst);
    pk_wr16(b + h, sport);
    pk_wr16(b + h + 2, dport);
    if (proto == 6) {
        pk_wr32(b + h + 4, pk_rnd());
        pk_wr32(b + h + 8, pk_rnd());
        b[h + 12] = (tcp_h / 4) << 4;
        b[h + 13] = syn ? 2 : 0x10;
        pk_wr16(b + h + 14, pk_rnd());
        if (syn) {
            b[h + 20] = 2;
            b[h + 21] = 4;
            pk_wr16(b + h + 22, pk_rnd() % 3 ? 1460 : 536 + pk_rnd() % 900);
        }
    } else
        pk_wr16(b + h + 4, n - h);
    for (size_t i = n - payload; i < n; i++)
        b[i] = pk_rnd();
    fill_checksums(b, n, h, udp_none);
    return n;
}
