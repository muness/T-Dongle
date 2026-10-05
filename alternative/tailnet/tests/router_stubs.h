#pragma once
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* usleep/sched_yield under -std=c11 on glibc */
#endif
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef int err_t;
#define ERR_MEM -1
#define ERR_OK 0
#define PBUF_IP 0
#define PBUF_RAM 0
#define pdTRUE 1
#define pdMS_TO_TICKS(ms) (ms)
typedef struct {
    uint32_t addr;
} ip4_addr_t;
struct pbuf {
    size_t tot_len;
    void *payload;
};
struct netif {
    err_t (*output)(struct netif *, struct pbuf *, const ip4_addr_t *);
};
typedef struct {
    struct netif *wg_netif;
    uint32_t vpn_ip;
    int state;
    unsigned magic; /* tests: set while the client is alive, cleared before it is freed */
} microlink_t;
typedef struct membership {
    struct membership *next;
    uint32_t id;
    microlink_t *client;
} membership_t;
#define ML_STATE_CONNECTED 4
static membership_t *members;
static struct netif usb;
static void *usb_interface;
static int members_lock;
/* members_lock: a real mutex so concurrent tests exercise the real contract;
 * `members_lock_free = false` models another task holding it for good. */
#include <pthread.h>
#include <unistd.h>
static bool members_lock_free = true;
static pthread_mutex_t members_mutex = PTHREAD_MUTEX_INITIALIZER;
static int xSemaphoreTake(int lock, int ticks) {
    (void)lock;
    if (!members_lock_free)
        return 0;
    for (int waited = 0; pthread_mutex_trylock(&members_mutex); waited++) {
        if (waited >= ticks * 10)
            return 0;
        usleep(100);
    }
    return 1;
}
static void xSemaphoreGive(int lock) {
    (void)lock;
    pthread_mutex_unlock(&members_mutex);
}
static void *esp_netif_get_netif_impl(void *ignored) { return &usb; }
static int64_t clock_us = 1000;
static int64_t esp_timer_get_time(void) { return clock_us; }
static struct pbuf *pbuf_alloc(int kind, size_t size, int memory) {
    struct pbuf *p = malloc(sizeof(*p));
    p->tot_len = size;
    p->payload = calloc(1, size);
    return p;
}
static void pbuf_free(struct pbuf *p) {
    free(p->payload);
    free(p);
}
static int pbuf_copy_partial(struct pbuf *p, void *out, size_t n, size_t offset) {
    if (offset + n > p->tot_len)
        return 0;
    memcpy(out, (uint8_t *)p->payload + offset, n);
    return n;
}
static void pbuf_take(struct pbuf *p, const void *in, size_t n) {
    assert(n <= p->tot_len);
    memcpy(p->payload, in, n);
}

/* Flash-directory double. Every call is counted so tests can assert that the
 * forwarding path performs none. */
typedef struct {
    uint32_t id, peer, alias;
} ml_directory_alias_t;
static ml_directory_alias_t flash_records[1024];
static unsigned flash_count, flash_finds, flash_saves, flash_scans;
static bool flash_fail_save;
static bool ml_directory_alias_find(uint32_t id, uint32_t peer, uint32_t alias, ml_directory_alias_t *out) {
    flash_finds++;
    for (unsigned i = 0; i < flash_count; i++)
        if ((alias && flash_records[i].alias == alias) || (!alias && flash_records[i].id == id && flash_records[i].peer == peer)) {
            *out = flash_records[i];
            return true;
        }
    return false;
}
static bool ml_directory_alias_save(const ml_directory_alias_t *record) {
    flash_saves++;
    if (flash_fail_save || flash_count == sizeof(flash_records) / sizeof(flash_records[0]))
        return false;
    flash_records[flash_count++] = *record;
    return true;
}
static bool ml_directory_alias_scan(void (*visit)(void *, const ml_directory_alias_t *), void *context) {
    flash_scans++;
    for (unsigned i = 0; i < flash_count; i++)
        visit(context, &flash_records[i]);
    return true;
}
/* Persistent alias counter double (NVS in firmware). */
#ifndef STUB_FIRST_ALIAS
#define STUB_FIRST_ALIAS 64
#endif
static uint32_t stub_next_alias = STUB_FIRST_ALIAS;
static bool alias_reserve(uint32_t *index) {
    *index = stub_next_alias++;
    return true;
}
