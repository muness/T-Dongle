#pragma once
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
static int xSemaphoreTake(int lock, int ticks) { return 1; }
static void xSemaphoreGive(int lock) {}
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
