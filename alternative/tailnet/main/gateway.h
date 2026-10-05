#pragma once
#include "esp_netif.h"
#include "microlink_internal.h"
typedef struct membership {
    struct membership *next;
    uint32_t id;
    size_t start_heap_before,start_heap_after;
    char label[24], ns[16], key[160], hostname[48], error[64];
    bool enabled;
    microlink_t *client;
#ifdef CONFIG_TDONGLE_MEMORY_ADMISSION_OVERRIDE
    uint32_t next_attempt_ms; /* diagnostics: an over-budget attempt is retried at most once a minute */
#endif
} membership_t;
/* Core 1 task priorities, highest first: Wi-Fi/tcpip are on core 0 (23, 18). usb_routes (forwarding) outranks the shared
 * wg_mgr (ML_TASK_WG_MGR_PRIO) so a packet never waits behind a handshake, and wg_mgr outranks coord. On core 0 the shared
 * net_io (7) outranks the shared derp task (5). Asserted in gateway_main.c; documented in ADR 0013/0015. */
#define GATEWAY_TASK_USB_ROUTES_PRIO 8
#define GATEWAY_TASK_USB_ROUTES_CORE 1
/* usb_txq (esp_tinyusb transmit-ring worker): a notify-then-defer relay, a few hundred stack bytes. Core 1 with the TinyUSB task
 * (priority 5, TINYUSB_DEFAULT_TASK_AFFINITY = 1), so its usbd_defer_func wakes a task on its own core. Above the TinyUSB task
 * and coord (5), below wg_mgr (7) and usb_routes (8): a published frame reaches the TinyUSB queue promptly and the worker can
 * never delay forwarding or a handshake. Its 1,536 B stack, 340 B TCB and 4,576 B ring are allocated at USB start, before
 * admission, so they are already out of the free heap that admission measures (ADR 0015). */
#define GATEWAY_TASK_USB_TX_PRIO 6
#define GATEWAY_TASK_USB_TX_CORE 1
extern membership_t *members;
extern esp_netif_t *usb_interface;
extern SemaphoreHandle_t members_lock;
int gateway_host_input(struct pbuf *, struct netif *);
uint32_t gateway_alias(uint32_t id, uint32_t peer);
void gateway_forget(uint32_t id);
/* Router counters (route_table.h RT_STAT_*), for the serial `route` report. */
uint32_t gateway_route_stat(unsigned which);
/* Republish the memberships' MagicDNS domains for the DNS task; members_lock held. */
void gateway_dns_domains_refresh(void);

bool gateway_tailnet_mode(void);

bool gateway_serial_command(const char *line);
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
bool gateway_memory_command(const char *line);
#else
static inline bool gateway_memory_command(const char *line) { (void)line; return false; }
#endif
