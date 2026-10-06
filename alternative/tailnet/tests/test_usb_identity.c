#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../main/usb_identity.h"
static void check(const uint8_t station[6]) {
    uint8_t device[6], host[6], again[6], again_host[6];
    gateway_usb_macs(station, device, host);
    assert((device[0] & 3) == 2 && (host[0] & 3) == 2);
    assert(memcmp(device, host, 6) != 0);
    assert(memcmp(device + 1, station + 1, 4) == 0 && memcmp(host + 1, station + 1, 4) == 0);
    assert(device[5] == station[5] && host[5] == (uint8_t)(station[5] ^ 1));
    gateway_usb_macs(station, again, again_host);
    assert(!memcmp(device, again, 6) && !memcmp(host, again_host, 6));
}
int main(void) {
    const uint8_t board[6] = {0x30, 0xed, 0xa0, 0xd7, 0x88, 0xbc};
    uint8_t device[6], host[6];
    gateway_usb_macs(board, device, host);
    const uint8_t want_device[6] = {0x32, 0xed, 0xa0, 0xd7, 0x88, 0xbc};
    const uint8_t want_host[6] = {0x32, 0xed, 0xa0, 0xd7, 0x88, 0xbd};
    assert(!memcmp(device, want_device, 6) && !memcmp(host, want_host, 6));
    for (unsigned b0 = 0; b0 < 256; b0++)
        for (unsigned b5 = 0; b5 < 256; b5 += 17) {
            const uint8_t s[6] = {(uint8_t)b0, 1, 2, 3, 4, (uint8_t)b5};
            check(s);
        }
    /* The product string, per mode (usb_identity.h): the bridge enumerates exactly as v0.1.x did, so a host keeps its network service name. */
    assert(!strcmp(gateway_usb_product(false), "T-Dongle-S3 NCM"));
    assert(!strcmp(gateway_usb_product(true), "T-Dongle-S3 tailnet gateway"));
    assert(strlen(gateway_usb_product(false)) < 31 && strlen(gateway_usb_product(true)) < 31);   /* a USB string descriptor holds 31 UTF-16 characters */
    puts("USB identity: device and host MACs are distinct, unicast, locally administered and stable; product string per mode");
}
