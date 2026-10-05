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
