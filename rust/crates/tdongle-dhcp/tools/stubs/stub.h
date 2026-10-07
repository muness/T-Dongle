/* Host stubs for the few lwIP/ESP-IDF symbols dhcpserver.c uses; the DHCP logic itself is the real, unmodified file. */
#ifndef DHCP_STUB_H
#define DHCP_STUB_H
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <arpa/inet.h>

typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int8_t err_t;
#define ERR_OK 0
#define ERR_VAL -6
#define ERR_ARG -16
#define ESP_DHCPS 1
#define LWIP_ASSERT(msg, c) do { } while (0)
#define PP_HTONL(x) htonl(x)
#define LWIP_MAKEU32(a, b, c, d) (((u32_t)((a) & 0xff) << 24) | ((u32_t)((b) & 0xff) << 16) | ((u32_t)((c) & 0xff) << 8) | (u32_t)((d) & 0xff))

typedef struct ip4_addr { u32_t addr; } ip4_addr_t;
typedef ip4_addr_t ip_addr_t;
#define IPADDR4_INIT(a) { a }
#define ip_2_ip4(p) ((ip4_addr_t *)(p))
extern const ip_addr_t ip_addr_any_instance;
#define IP_ADDR_ANY (&ip_addr_any_instance)
#define ip4_addr1(ip) (((const u8_t *)(&(ip)->addr))[0])
#define ip4_addr2(ip) (((const u8_t *)(&(ip)->addr))[1])
#define ip4_addr3(ip) (((const u8_t *)(&(ip)->addr))[2])
#define ip4_addr4(ip) (((const u8_t *)(&(ip)->addr))[3])
#define ip4_addr_isany_val(a) ((a).addr == 0)
#define ip4_addr_isany(p) ((p) == NULL || (p)->addr == 0)
#define ip4_addr_set(d, s) ((d)->addr = (s)->addr)
#define ip4_addr_netcmp(a, b, m) (((a)->addr & (m)->addr) == ((b)->addr & (m)->addr))
#define IP4_ADDR(ip, a, b, c, d) ((ip)->addr = PP_HTONL(LWIP_MAKEU32(a, b, c, d)))

struct netif { ip_addr_t ip_addr; ip_addr_t netmask; ip_addr_t gw; int up; };
#define netif_is_up(n) ((n)->up)

struct eth_addr { u8_t addr[6]; };
#define ETHARP_SUPPORT_STATIC_ENTRIES 1
err_t etharp_add_static_entry(const ip4_addr_t *ip, struct eth_addr *mac);
err_t etharp_remove_static_entry(const ip4_addr_t *ip);

#define PBUF_TRANSPORT 0
#define PBUF_RAM 0
struct pbuf { struct pbuf *next; void *payload; u16_t tot_len; u16_t len; u16_t ref; };
struct pbuf *pbuf_alloc(int layer, u16_t len, int type);
void pbuf_free(struct pbuf *p);
u16_t pbuf_copy_partial(const struct pbuf *p, void *dst, u16_t len, u16_t off);
#define mem_calloc(n, s) calloc(n, s)
#define mem_free(p) free(p)

struct udp_pcb { int dummy; };
struct udp_pcb *udp_new(void);
void udp_remove(struct udp_pcb *p);
err_t udp_disconnect(struct udp_pcb *p);
err_t udp_bind(struct udp_pcb *p, const ip_addr_t *ip, u16_t port);
void udp_bind_netif(struct udp_pcb *p, struct netif *n);
typedef void (*udp_recv_fn)(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
void udp_recv(struct udp_pcb *p, udp_recv_fn fn, void *arg);
err_t udp_sendto(struct udp_pcb *p, struct pbuf *b, const ip_addr_t *ip, u16_t port);

#define DHCP_COARSE_TIMER_MSECS 1000
typedef void (*sys_timeout_handler)(void *arg);
void sys_timeout(u32_t ms, sys_timeout_handler h, void *arg);
void sys_untimeout(sys_timeout_handler h, void *arg);
#endif
