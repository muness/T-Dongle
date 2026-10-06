// SPDX-License-Identifier: MIT
/* Counts every Ethernet frame that crosses the USB network interface, in both modes, without touching either data path.
 *
 * TinyUSB's NCM class driver calls two functions that the network glue (components/esp_tinyusb/tinyusb_net.c) implements: tud_network_recv_cb
 * for each datagram the host sent, and tud_network_xmit_cb to copy each datagram for the host into an IN transfer block. The linker
 * wraps both (-Wl,--wrap=..., main/CMakeLists.txt): calls from the class driver land here, the real function runs unchanged, and the
 * frame is counted when it was accepted. That is the one place where both modes' frames pass, whatever feeds them (the transparent
 * bridge's copied-frame pool, the tailnet transmit ring), so the Traffic screen and the `status` traffic line do not depend on either.
 * Cost: one relaxed atomic add per frame (traffic.h). */
#include "traffic.h"
#include <stdbool.h>
#include <stdint.h>

bool __real_tud_network_recv_cb(const uint8_t *src, uint16_t size);
uint16_t __real_tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg);

/* A datagram from the host. The real callback returns false when it could not take it yet (the class driver offers it again): count
 * only what was taken. */
bool __wrap_tud_network_recv_cb(const uint8_t *src, uint16_t size) {
    bool taken = __real_tud_network_recv_cb(src, size);
    if (taken) traffic_count_up(size);
    return taken;
}
/* A datagram copied into the IN block for the host: the real callback returns its length. */
uint16_t __wrap_tud_network_xmit_cb(uint8_t *dst, void *ref, uint16_t arg) {
    uint16_t length = __real_tud_network_xmit_cb(dst, ref, arg);
    if (length) traffic_count_down(length);
    return length;
}
