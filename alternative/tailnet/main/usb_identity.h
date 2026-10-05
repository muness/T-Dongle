#pragma once
#include <stdint.h>
#include <string.h>
/* Router mode is a two-ended Ethernet link: the host adopts the NCM
 * iMACAddress as its own address, and lwIP's USB netif is the other end.
 * Both are locally administered unicast addresses derived from the Wi-Fi
 * station MAC, and they must differ: a host that sees its own address as
 * an ARP sender (macOS) discards every reply from the gateway. */
static inline void gateway_usb_macs(const uint8_t station[6], uint8_t device[6],
                                    uint8_t host[6]) {
    memcpy(device, station, 6);
    device[0] = (uint8_t)((device[0] | 2) & ~1);
    memcpy(host, device, 6);
    host[5] ^= 1;
}
