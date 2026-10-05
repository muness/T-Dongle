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
/* The USB IN pipe is served by two tasks that must not wait behind forwarding work (ADR 0022). A full-speed IN transfer ends,
 * the controller interrupt queues an event, and until the TinyUSB task has run the next NTB is not on the bus: the host's polls
 * are NAKed and the wire idles. Under an inbound flood wg_mgr (7) and usb_routes (8) are runnable for most of the core, and a
 * TinyUSB task at 5 ran only when they blocked: board UDP -R drained ~2.6 Mbit/s of a 9 Mbit/s pipe (two 1,242 B datagrams per
 * 3,200 B NTB, one NTB per ~7 ms) while the bridge, with nothing competing, drained 6. So on core 1 the order is
 *   usb_txq relay 10 > TinyUSB 9 > usb_routes 8 > wg_mgr 7 > usb_txq heap work 6 > coord 5.
 * The relay (notify, then usbd_defer_func) is a few microseconds and must outrank the producers on its core so the first frame of
 * a burst is not held behind a decrypt run. Both together cost the forwarding path a few microseconds per USB event (an NTB
 * is 2 to 5 datagrams): the TinyUSB task's own work is an NTB copy and, for upload, a malloc+memcpy per received datagram,
 * about 3 % of the core at the 12 Mbit/s bus limit. The worker's heap work (growth heap walks, idle shrink) drops to 6 while
 * it runs (tinyusb_net_tx_config_t.work_priority) so that it never delays the tasks it serves. 9 and 10 are below the IDF
 * system tasks on core 1 (ipc 24, esp_timer 22). The legacy bridge keeps TinyUSB at its default (5). */
#define GATEWAY_TASK_TINYUSB_PRIO 9
#define GATEWAY_TASK_USB_TX_PRIO 10
#define GATEWAY_TASK_USB_TX_WORK_PRIO 6
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
