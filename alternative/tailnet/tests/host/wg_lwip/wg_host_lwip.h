/* Minimal IPv4-only host stand-in for the lwIP surface used by wireguard.c and
 * wireguardif.c (type/shape compatible with lwIP 2.2 for the pieces used). It lets the
 * REAL library sources be compiled and exercised on the host; the pbuf and udp layers
 * are tiny in-memory fakes (see wg_host_lwip.c). Test-only: never built into firmware. */
#ifndef WG_HOST_LWIP_H
#define WG_HOST_LWIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
typedef int8_t err_t;
#define ERR_OK 0
#define ERR_MEM (-1)
#define ERR_RTE (-4)
#define ERR_CONN (-11)
#define ERR_VAL (-6)
#define ERR_ARG (-16)

#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_ASSERT(msg, cond) do { if (!(cond)) { fprintf(stderr, "LWIP_ASSERT: %s\n", msg); abort(); } } while (0)
#define PP_NTOHS(x) ((u16_t)((((x) & 0xff) << 8) | (((x) >> 8) & 0xff)))
#define lwip_ntohl(x) __builtin_bswap32(x)
#define PP_NTOHL(x) __builtin_bswap32(x)
#define LWIP_UNUSED_ARG(x) (void)(x)

/* ---- addresses (IPv4 only: ip_addr_t == ip4_addr_t, as in lwIP with LWIP_IPV6=0) ---- */
typedef struct ip4_addr { u32_t addr; } ip4_addr_t;
typedef ip4_addr_t ip_addr_t;
typedef struct ip6_addr { u32_t addr[4]; } ip6_addr_t;
#define IPADDR_TYPE_V4 0
#define IP_SET_TYPE_VAL(ipaddr, t) do { (void)(t); } while (0)
#define IP_IS_V4(a) (1)
#define IP_IS_V6(a) (0)
#define ip_2_ip4(a) (a)
#define ip_2_ip6(a) ((const ip6_addr_t *)(a))
#define IP6_ADDR_BLOCK1(a) 0
#define IP6_ADDR_BLOCK2(a) 0
#define IP6_ADDR_BLOCK3(a) 0
#define IP6_ADDR_BLOCK4(a) 0
#define IP6_ADDR_BLOCK5(a) 0
#define IP6_ADDR_BLOCK6(a) 0
#define IP6_ADDR_BLOCK7(a) 0
#define IP6_ADDR_BLOCK8(a) 0
#define ip4_addr_get_u32(a) ((a)->addr)
#define ip4_addr_set_u32(a, v) ((a)->addr = (v))
#define ip_addr_set_any(is6, a) ((a)->addr = 0)
#define ip_addr_isany(a) ((a)->addr == 0)
#define ip_addr_cmp(a, b) ((a)->addr == (b)->addr)
#define ip_addr_copy_from_ip4(dst, src) ((dst).addr = (src).addr)
#define ip_addr_netcmp(a, b, m) (((a)->addr & (m)->addr) == ((b)->addr & (m)->addr))
#define ip4_addr1_16(a) ((u16_t)(ip4_addr_get_u32(a) & 0xff))
#define ip4_addr2_16(a) ((u16_t)((ip4_addr_get_u32(a) >> 8) & 0xff))
#define ip4_addr3_16(a) ((u16_t)((ip4_addr_get_u32(a) >> 16) & 0xff))
#define ip4_addr4_16(a) ((u16_t)((ip4_addr_get_u32(a) >> 24) & 0xff))
extern const ip_addr_t ip_addr_any;
#define IP_ADDR_ANY (&ip_addr_any)
const char *ipaddr_ntoa(const ip_addr_t *addr);

/* ---- pbuf ---- */
typedef enum { PBUF_TRANSPORT = 0 } pbuf_layer;
typedef enum { PBUF_RAM = 0 } pbuf_type;
struct pbuf { void *payload; u16_t tot_len; u16_t len; struct pbuf *next; };
struct pbuf *pbuf_alloc(pbuf_layer layer, u16_t length, pbuf_type type);
u8_t pbuf_free(struct pbuf *p);
err_t pbuf_take(struct pbuf *p, const void *data, u16_t len);
u16_t pbuf_copy_partial(const struct pbuf *p, void *dst, u16_t len, u16_t offset);
u8_t pbuf_get_at(const struct pbuf *p, u16_t offset);

/* ---- IP header (only used by the RX decap path) ---- */
struct ip_hdr { u8_t _v_hl; u8_t _tos; u16_t _len; u16_t _id; u16_t _offset; u8_t _ttl; u8_t _proto; u16_t _chksum; ip4_addr_t src; ip4_addr_t dest; };
#define IPH_V(h) ((h)->_v_hl >> 4)
#define IPH_LEN(h) ((h)->_len)

/* ---- netif / udp ---- */
struct netif;
struct udp_pcb;
typedef err_t (*netif_output_fn)(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);
typedef err_t (*netif_linkoutput_fn)(struct netif *netif, struct pbuf *p);
struct netif {
    void *state;
    char name[2];
    u8_t hwaddr_len;
    u16_t mtu;
    u8_t flags;
    netif_output_fn output;
    netif_linkoutput_fn linkoutput;
    err_t (*input)(struct pbuf *p, struct netif *inp);
    int link_up; /* host-only observable */
};
#define NETIF_FLAG_LINK_UP 0x04U
#define LWIP_CHECKSUM_CTRL_PER_NETIF 0
#define NETIF_SET_CHECKSUM_CTRL(n, f) do {} while (0)
#define NETIF_CHECKSUM_ENABLE_ALL 0
void netif_set_link_up(struct netif *netif);
void netif_set_link_down(struct netif *netif);
typedef err_t (*netif_input_fn)(struct pbuf *p, struct netif *inp);
err_t tcpip_input(struct pbuf *p, struct netif *inp);

typedef void (*udp_recv_fn)(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
struct udp_pcb { int unused; };
struct udp_pcb *udp_new(void);
err_t udp_bind(struct udp_pcb *pcb, const ip_addr_t *ipaddr, u16_t port);
void udp_bind_netif(struct udp_pcb *pcb, const struct netif *netif);
void udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *arg);
void udp_remove(struct udp_pcb *pcb);
err_t udp_sendto(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst, u16_t port);

/* ---- mem / timeouts ---- */
void *mem_malloc(size_t n);
void *mem_calloc(size_t count, size_t size);
void mem_free(void *p);
typedef void (*sys_timeout_handler)(void *arg);
void sys_timeout(u32_t msecs, sys_timeout_handler handler, void *arg);
void sys_untimeout(sys_timeout_handler handler, void *arg);

/* ---- esp_heap_caps ---- */
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
void *heap_caps_malloc(size_t n, uint32_t caps);
void heap_caps_free(void *p);

#endif
