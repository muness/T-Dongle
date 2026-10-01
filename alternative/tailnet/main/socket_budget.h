#pragma once
#include <stdbool.h>
#include <stdint.h>
/* 3 HTTP server internals + 2 HTTP clients + DNS listener/forwarder +
 * SNTP. Each membership reserves DISCO, IPv6 STUN, control TCP, DERP TCP
 * and one transient key-fetch/netcheck socket. No product membership cap. */
enum { GATEWAY_SOCKET_RECOVERY = 8, GATEWAY_SOCKETS_PER_MEMBER = 5 };
static inline bool gateway_socket_admit(unsigned total, unsigned active,
                                         unsigned used) {
    return total >= GATEWAY_SOCKET_RECOVERY && used <= total &&
           total - used >= GATEWAY_SOCKETS_PER_MEMBER &&
           active < (total - GATEWAY_SOCKET_RECOVERY) / GATEWAY_SOCKETS_PER_MEMBER;
}
typedef struct {
    uint32_t open, peak, failures, last_errno, last_operation, last_at_ms;
} gateway_socket_stats;
gateway_socket_stats gateway_sockets_snapshot(void);
