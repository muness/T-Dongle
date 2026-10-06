#pragma once
#include <stdbool.h>
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
/* The USB product string (what macOS shows as the network service name, and what keys its service order).
 *
 * Per mode, on purpose. In Wi-Fi bridge mode it is "T-Dongle-S3 NCM", byte for byte what v0.1.x enumerated as, so a Mac or Pi that
 * already knows the adapter keeps its service name and its position in the service order across the upgrade. In tailnet gateway
 * mode it is "T-Dongle-S3 tailnet gateway" as before: that mode has its own USB MAC pair (gateway_usb_macs) and its own subnet, so
 * a host sees it as a different interface anyway, and the longer name says what it is. Manufacturer and serial (the station MAC)
 * are the same in both modes. Documented in docs/REFERENCE.md and ADR 0024. */
static inline const char *gateway_usb_product(bool tailnet_mode) {
    return tailnet_mode ? "T-Dongle-S3 tailnet gateway" : "T-Dongle-S3 NCM";
}
