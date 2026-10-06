/* The screen applied to DERP-relayed packets before an unknown sender may be
 * given a trial slot: it must accept exactly a 148-byte WireGuard initiation
 * whose mac1 (over the first 116 bytes) is valid for our key, and nothing else.
 * The function under test is the real one from ml_wg_mgr.c. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define ESP_PLATFORM 1
#define WIREGUARD_COOKIE_LEN 16
#define WIREGUARD_AUTHTAG_LEN 16
#define WIREGUARD_TAI64N_LEN 12
#define MESSAGE_HANDSHAKE_INITIATION 1
struct message_handshake_initiation {
    uint8_t type;
    uint8_t reserved[3];
    uint32_t sender;
    uint8_t ephemeral[32];
    uint8_t enc_static[32 + WIREGUARD_AUTHTAG_LEN];
    uint8_t enc_timestamp[WIREGUARD_TAI64N_LEN + WIREGUARD_AUTHTAG_LEN];
    uint8_t mac1[WIREGUARD_COOKIE_LEN];
    uint8_t mac2[WIREGUARD_COOKIE_LEN];
} __attribute__((__packed__));
struct wireguard_device { int valid; };
struct netif { void *state; };
typedef struct { struct netif *wg_netif; } microlink_t;
typedef struct { uint8_t *data; size_t len; } ml_rx_packet_t;
static unsigned checks; static bool mac_ok;
static bool wireguard_check_mac1(struct wireguard_device *d, const uint8_t *data, size_t len, const uint8_t *mac1) {
    checks++;
    assert(len == offsetof(struct message_handshake_initiation, mac1) && mac1 == data + len);
    return mac_ok;
}
#include "wg_initiation.inc"
int main(void) {
    struct wireguard_device dev = {1};
    struct netif nif = {&dev};
    microlink_t ml = {&nif};
    uint8_t buf[2000] = {MESSAGE_HANDSHAKE_INITIATION};
    ml_rx_packet_t p = {buf, sizeof(struct message_handshake_initiation)};
    assert(sizeof(struct message_handshake_initiation) == 148);
    mac_ok = true;
    assert(wg_initiation_plausible(&ml, &p) && checks == 1);
    mac_ok = false;                                   /* wrong mac1: not for our key */
    assert(!wg_initiation_plausible(&ml, &p));
    mac_ok = true; checks = 0;
    for (size_t n = 0; n < 2000; n++) {               /* every other length is refused before any hash */
        if (n == 148) continue;
        p.len = n;
        assert(!wg_initiation_plausible(&ml, &p));
    }
    assert(checks == 0);
    p.len = 148;
    for (unsigned type = 0; type < 256; type++) {     /* data, response, cookie, garbage */
        buf[0] = (uint8_t)type;
        assert(wg_initiation_plausible(&ml, &p) == (type == MESSAGE_HANDSHAKE_INITIATION));
    }
    buf[0] = MESSAGE_HANDSHAKE_INITIATION;
    for (unsigned i = 1; i <= 3; i++) {               /* reserved bytes must be zero */
        buf[i] = 1;
        assert(!wg_initiation_plausible(&ml, &p));
        buf[i] = 0;
    }
    ml.wg_netif = NULL;                               /* no interface: nothing to check against */
    assert(!wg_initiation_plausible(&ml, &p));
    nif.state = NULL; ml.wg_netif = &nif;
    assert(!wg_initiation_plausible(&ml, &p));
    puts("WG initiation screen: exact size, type, zero reserved bytes and mac1 over the first 116 bytes");
    return 0;
}
