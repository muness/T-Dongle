#include "socket_budget.h"
#include "sdkconfig.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "lwip/sockets.h"
#include <errno.h>
/* Link wrappers observe all BSD allocations, including TLS and HTTP internals.
 * No heap, I/O or journal write inside an allocator/close callback. */
static portMUX_TYPE socket_lock = portMUX_INITIALIZER_UNLOCKED;
static gateway_socket_stats stats;
static void allocated(int fd, unsigned operation, int failure) {
    portENTER_CRITICAL(&socket_lock);
    if (fd < 0) {
        stats.failures++; stats.last_errno = failure; stats.last_operation = operation;
        stats.last_at_ms = esp_timer_get_time() / 1000;
    } else {
        stats.open++;
        unsigned observed = stats.open < CONFIG_LWIP_MAX_SOCKETS ? stats.open : CONFIG_LWIP_MAX_SOCKETS;
        if (observed > stats.peak) stats.peak = observed;
    }
    portEXIT_CRITICAL(&socket_lock);
}
extern int __real_lwip_socket(int, int, int);
extern int __real_lwip_accept(int, struct sockaddr *, socklen_t *);
extern int __real_lwip_close(int);
int __wrap_lwip_socket(int domain, int type, int protocol) {
    int fd = __real_lwip_socket(domain, type, protocol), saved = errno;
    allocated(fd, 1, saved); errno = saved; return fd;
}
int __wrap_lwip_accept(int listener, struct sockaddr *address, socklen_t *size) {
    int fd = __real_lwip_accept(listener, address, size), saved = errno;
    /* Nonblocking EAGAIN is readiness, not allocation failure. */
    if (fd >= 0 || (saved != EAGAIN && saved != EWOULDBLOCK)) allocated(fd, 2, saved);
    errno = saved; return fd;
}
int __wrap_lwip_close(int fd) {
    int result = __real_lwip_close(fd), saved = errno;
    if (!result) {
        portENTER_CRITICAL(&socket_lock);
        if (stats.open) stats.open--;
        portEXIT_CRITICAL(&socket_lock);
    }
    errno = saved; return result;
}
gateway_socket_stats gateway_sockets_snapshot(void) {
    portENTER_CRITICAL(&socket_lock);
    gateway_socket_stats snapshot = stats;
    portEXIT_CRITICAL(&socket_lock);
    return snapshot;
}
