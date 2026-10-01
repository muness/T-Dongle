#pragma once
struct pbuf;
struct netif;
int gateway_host_input(struct pbuf *, struct netif *);
#define LWIP_HOOK_IP4_INPUT(p, n) gateway_host_input((p), (n))
