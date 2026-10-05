#pragma once
#include <stddef.h>
#include <stdint.h>
#define CAP_MAX 64
/* One packet the router emitted: kind 0 = to a membership's tunnel (member = id,
 * next_hop = tunnel peer), kind 1 = to the USB host (next_hop = host). */
typedef struct {
    int kind;
    uint32_t member, next_hop;
    size_t n;
    uint8_t bytes[1500];
} cap_t;
/* Flow-table contents, for slot-by-slot comparison of the two implementations. */
typedef struct {
    uint32_t id, peer, host, alias, generation;
    uint16_t local, remote, mapped;
    uint8_t proto;
    int64_t touched;
} flow_row;
#define IMPL_API(P) \
    void P##setup(void); \
    void P##add_member(uint32_t id, uint32_t vpn_ip); \
    void P##remove_member(uint32_t id); \
    void P##set_state(uint32_t id, int state); \
    uint32_t P##alias(uint32_t id, uint32_t peer); \
    void P##suspend(uint32_t id); \
    void P##forget(uint32_t id); \
    void P##detach(void); \
    void P##set_clock(int64_t us); \
    int P##host_packet(const uint8_t *b, size_t n); \
    void P##tunnel_packet(uint32_t id, const uint8_t *b, size_t n); \
    unsigned P##captured(void); \
    const cap_t *P##capture(unsigned i); \
    void P##clear(void); \
    void P##debug(uint32_t dest); \
    void P##flows(flow_row rows[64]);
