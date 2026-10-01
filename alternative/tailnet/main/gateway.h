#pragma once
#include "esp_netif.h"
#include "microlink_internal.h"
typedef struct membership {
    struct membership *next;
    uint32_t id;
    char label[24], ns[16], key[160], hostname[48], error[64];
    bool enabled;
    microlink_t *client;
} membership_t;
extern membership_t *members;
extern esp_netif_t *usb_interface;
extern SemaphoreHandle_t members_lock;
int gateway_host_input(struct pbuf *, struct netif *);
uint32_t gateway_alias(uint32_t id, uint32_t peer);
void gateway_forget(uint32_t id);
