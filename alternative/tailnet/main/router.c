#include <stdatomic.h>
#ifdef GATEWAY_HOST_TEST
#include "router_stubs.h"
#else
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_timer.h"
#include "gateway.h"
#include "boot_health.h"
#include "lwip/inet.h"
#include "lwip/tcpip.h"
#endif
/* Each alias is bound to an identity and peer. No tailnet shares a routing
 * table. */
typedef struct {
    uint32_t id, peer, alias;
} alias_t;
static alias_t aliases[64];
#ifndef GATEWAY_HOST_TEST
#include "nvs.h"
static nvs_handle_t route_store;
static bool routes_ready;
static QueueHandle_t route_queue;
static void route_task(void *context);

bool gateway_routes_init(void) {
    if (nvs_open("tn_routes", NVS_READWRITE, &route_store) != ESP_OK)
        return false;
    size_t n = sizeof(aliases);
    esp_err_t err = nvs_get_blob(route_store, "aliases", aliases, &n);
    routes_ready =
        err == ESP_ERR_NVS_NOT_FOUND || (err == ESP_OK && n == sizeof(aliases));
    for (unsigned i = 0; routes_ready && i < 64; i++)
        if (aliases[i].alias && aliases[i].alias != 0xc6120001 + i)
            routes_ready = false;
    /* Migrate existing addresses before replacing the RAM table with a cache. */
    for(unsigned i=0;routes_ready && i<64;i++)if(aliases[i].alias) {
        ml_directory_alias_t record={aliases[i].id,aliases[i].peer,aliases[i].alias},old;
        if(!ml_directory_alias_find(record.id,record.peer,record.alias,&old) && !ml_directory_alias_save(&record))routes_ready=false;
    }
    if(!routes_ready)return false;
    route_queue=xQueueCreate(4,sizeof(struct {struct pbuf *packet;struct netif *input;unsigned generation;}));
    if(!route_queue)return false;
    if(xTaskCreate(route_task,"usb_routes",4096,NULL,3,NULL)!=pdPASS){vQueueDelete(route_queue);route_queue=NULL;routes_ready=false;}
    return routes_ready;
}
#else
static bool persist_aliases(void) { return true; }
#endif
typedef struct {
    uint32_t id, peer, host, alias;
    uint16_t local, remote, mapped;
    uint8_t proto;
    int64_t touched;
} flow_t;
static flow_t flows[64];
static uint32_t flow_generations[64];
static atomic_uint usb_generation = 1;
void gateway_usb_detach(void) { atomic_fetch_add(&usb_generation, 1); }
static uint16_t rd16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)rd16(p) << 16) | rd16(p + 2);
}
static void wr16(uint8_t *p, uint16_t v) {
    p[0] = v >> 8;
    p[1] = v;
}
static void wr32(uint8_t *p, uint32_t v) {
    wr16(p, v >> 16);
    wr16(p + 2, v);
}
#ifndef GATEWAY_HOST_TEST
static unsigned alias_hand;
uint32_t gateway_alias(uint32_t id,uint32_t peer) {
    for(unsigned i=0;i<64;i++)if(aliases[i].id==id && aliases[i].peer==peer)return aliases[i].alias;
    ml_directory_alias_t record;
    if(!ml_directory_alias_find(id,peer,0,&record)) {
        if(!routes_ready)return 0;
        uint32_t next=64;esp_err_t err=nvs_get_u32(route_store,"next_alias",&next);
        if(err!=ESP_OK && err!=ESP_ERR_NVS_NOT_FOUND)return 0;
        if(next>=0x1fffe)return 0;
        /* Reserve before exposing: even an interrupted write never reuses an IP. */
        if(nvs_set_u32(route_store,"next_alias",next+1)!=ESP_OK || nvs_commit(route_store)!=ESP_OK)return 0;
        record=(ml_directory_alias_t){id,peer,0xc6120001+next};
        if(!ml_directory_alias_save(&record))return 0;
    }
    aliases[alias_hand++%64]=(alias_t){record.id,record.peer,record.alias};return record.alias;
}
#else
uint32_t gateway_alias(uint32_t id, uint32_t peer) {
    for (unsigned i = 0; i < 64; i++)
        if (aliases[i].id == id && aliases[i].peer == peer)
            return aliases[i].alias;
    for (unsigned i = 0; i < 64; i++)
        if (!aliases[i].alias) {
            aliases[i] = (alias_t){id, peer, 0xc6120001 + i};
            if (!persist_aliases()) {
                memset(&aliases[i], 0, sizeof(aliases[i]));
                return 0;
            }
            return aliases[i].alias;
        }
    return 0;
}
#endif
void gateway_suspend(uint32_t id) {
    for (unsigned i = 0; i < 64; i++)
        if (flows[i].id == id)
            memset(&flows[i], 0, sizeof(flows[i]));
}
void gateway_forget(uint32_t id) {
    for (unsigned i = 0; i < 64; i++) {
        if (aliases[i].id == id)
            aliases[i].id = 0;
        if (flows[i].id == id)
            memset(&flows[i], 0, sizeof(flows[i]));
    }
#ifdef GATEWAY_HOST_TEST
    persist_aliases();
#endif
}
static uint32_t sum(const uint8_t *p, size_t n, uint32_t s) {
    while (n > 1) {
        s += rd16(p);
        p += 2;
        n -= 2;
    }
    if (n)
        s += p[0] << 8;
    return s;
}
static uint16_t finish(uint32_t s) {
    while (s >> 16)
        s = (s & 65535) + (s >> 16);
    return ~s;
}
static void checksums(uint8_t *b, size_t n, unsigned h) {
    wr16(b + 10, 0);
    wr16(b + 10, finish(sum(b, h, 0)));
    unsigned offset = b[9] == 6 ? 16 : 6;
    uint8_t *t = b + h;
    unsigned length = n - h;
    wr16(t + offset, 0);
    uint32_t s = sum(b + 12, 8, 0) + b[9] + length;
    s = sum(t, length, s);
    uint16_t c = finish(s);
    wr16(t + offset, c ? c : 65535);
}
/* Clamp both SYN directions so ordinary TCP data fits the queue/WG MTU.
 * Never enlarge an existing smaller offer; malformed options fail closed. */
static bool clamp_mss(uint8_t *b,size_t n,unsigned h) {
    if(b[9]!=6 || !(b[h+13]&2))return true;
    unsigned end=h+(b[h+12]>>4)*4;
    if(end>n)return false;
    for(unsigned pos=h+20;pos<end;) {
        unsigned kind=b[pos];if(!kind)break;if(kind==1){pos++;continue;}
        if(pos+2>end || b[pos+1]<2 || pos+b[pos+1]>end)return false;
        if(kind==2) {if(b[pos+1]!=4)return false;if(rd16(b+pos+2)>1360)wr16(b+pos+2,1360);}
        pos+=b[pos+1];
    }
    return true;
}
static bool valid(uint8_t *b, size_t n, unsigned *h) {
    if (n < 20 || b[0] >> 4 != 4)
        return false;
    *h = (b[0] & 15) * 4;
    if (*h < 20 || *h > n || rd16(b + 2) != n || (rd16(b + 6) & 0x3fff))
        return false;
    if (b[9] != 6 && b[9] != 17)
        return false;
    if (n < *h + (b[9] == 6 ? 20 : 8))
        return false;
    if (b[9] == 6 &&
        ((b[*h + 12] >> 4) * 4 < 20 || (b[*h + 12] >> 4) * 4 > n - *h))
        return false;
    if (b[9] == 17 && rd16(b + *h + 4) != n - *h)
        return false;
    return finish(sum(b, *h, 0)) == 0;
}
/* Synthetic USB traffic runs on usb_routes; non-USB ingress is filtered in lwIP. */
static int gateway_process_host_input(struct pbuf *p, struct netif *input) {
    if(!usb_interface){pbuf_free(p);return 1;}
    uint8_t first[20];
    if (p->tot_len < 20 || pbuf_copy_partial(p, first, 20, 0) != 20)
        return 0;
    uint32_t dest = rd32(first + 16);
    /* Enforce the ingress interface before HTTP/DNS reaches the socket
     * stack. Source-address checks alone cannot establish USB provenance. */
    if (input != esp_netif_get_netif_impl(usb_interface)) {
        bool management = dest == 0xc0a84d01;
#ifndef GATEWAY_HOST_TEST
        uint8_t ports[4];
        unsigned h = (first[0] & 15) * 4;
        if (dest == ntohl(ip4_addr_get_u32(netif_ip4_addr(input))) && h >= 20 &&
            p->tot_len >= h + 4 && (first[9] == 6 || first[9] == 17) &&
            pbuf_copy_partial(p, ports, 4, h) == 4)
            management =
                management || rd16(ports + 2) == 80 || rd16(ports + 2) == 53;
#endif
        if (management) {
            pbuf_free(p);
            return 1;
        }
    }
    if ((dest & 0xfffe0000) != 0xc6120000)
        return 0;
    if (input != esp_netif_get_netif_impl(usb_interface)) {
        pbuf_free(p);
        return 1;
    }
    uint8_t *b = malloc(p->tot_len);
    if (!b) {
        pbuf_free(p);
        return 1;
    }
    size_t n = p->tot_len;
    pbuf_copy_partial(p, b, n, 0);
    pbuf_free(p);
    unsigned h;
    if (!valid(b, n, &h) || !clamp_mss(b,n,h) || b[8] < 2)
        goto drop;
    if (xSemaphoreTake(members_lock, 0) != pdTRUE)
        goto drop;
    alias_t *a = NULL;
    for (unsigned i = 0; i < 64; i++)
        if (aliases[i].alias == dest && aliases[i].id) {
            a = &aliases[i];
            break;
        }
#ifndef GATEWAY_HOST_TEST
    alias_t cold;
    if(!a) {
        ml_directory_alias_t stored;
        if(ml_directory_alias_find(0,0,dest,&stored)) {cold=(alias_t){stored.id,stored.peer,stored.alias};a=&cold;}
    }
#endif
    if(!a) {xSemaphoreGive(members_lock);goto drop;}
    membership_t *m = members;
    while (m && m->id != a->id)
        m = m->next;
    if (!m || !m->client || !m->client->wg_netif ||
#ifndef GATEWAY_HOST_TEST
        !m->enabled ||
#endif
        m->client->state != ML_STATE_CONNECTED
#ifndef GATEWAY_HOST_TEST
        || m->client->key_expired || m->client->last_error[0]
#endif
    ) {
        xSemaphoreGive(members_lock);
        goto drop;
    }
    uint32_t host = rd32(b + 12);
    if ((host & 0xffffff00) != 0xc0a84d00 || host == 0xc0a84d01 ||
        host == 0xc0a84dff) {
        xSemaphoreGive(members_lock);
        goto drop;
    }
    uint16_t local = rd16(b + h), remote = rd16(b + h + 2);
    flow_t *f = NULL;
    int64_t now = esp_timer_get_time();
    for (unsigned i = 0; i < 64; i++)
        if (flow_generations[i] == atomic_load(&usb_generation) &&
            flows[i].id == a->id && flows[i].peer == a->peer &&
            flows[i].host == host && flows[i].local == local &&
            flows[i].remote == remote && flows[i].proto == b[9]) {
            f = &flows[i];
            break;
        }
    if (!f)
        for (unsigned i = 0; i < 64; i++)
            if (!flows[i].id ||
                flow_generations[i] != atomic_load(&usb_generation) ||
                now - flows[i].touched > 120000000) {
                f = &flows[i];
                *f = (flow_t){
                    a->id,
                    a->peer,
                    host,
                    dest,
                    local,
                    remote,
                    40000 + i + 64 * ((atomic_load(&usb_generation) - 1) % 300),
                    b[9],
                    now};
                flow_generations[i] = atomic_load(&usb_generation);
                break;
            }
    if (f) {
        f->touched = now;
        wr32(b + 12, m->client->vpn_ip);
        wr32(b + 16, a->peer);
        wr16(b + h, f->mapped);
        b[8]--;
        checksums(b, n, h);
#ifndef GATEWAY_HOST_TEST
        gateway_route_mark(1,m->id);
#endif
        ml_gateway_queue_packet(m->client,a->peer,b,n);
#ifndef GATEWAY_HOST_TEST
        gateway_route_mark(0,0);
#endif
    }
    xSemaphoreGive(members_lock);
drop:
    free(b);
    return 1;
}
/* WireGuard already authenticated its sender and checked AllowedIPs. Accept
 * only exact replies to a USB-origin flow belonging to this same membership. */
err_t gateway_tunnel_input(struct pbuf *p, struct netif *wg) {
    uint8_t *b = malloc(p->tot_len);
    if (!b) {
        pbuf_free(p);
        return ERR_MEM;
    }
    size_t n = p->tot_len;
    pbuf_copy_partial(p, b, n, 0);
    pbuf_free(p);
    /* The decryptor passes authenticated WireGuard padding with the IP
     * packet. Normally lwIP trims it; our custom input bypasses that path.
     * Use the inner IPv4 length without relaxing USB-side packet validation. */
    if (n < 20 || b[0] >> 4 != 4 || rd16(b + 2) > n)
        goto drop;
    n = rd16(b + 2);
    unsigned h;
    if (!valid(b, n, &h) || !clamp_mss(b,n,h))
        goto drop;
    if (xSemaphoreTake(members_lock, 0) != pdTRUE)
        goto drop;
    membership_t *m = members;
    while (m && (!m->client || m->client->wg_netif != wg))
        m = m->next;
    if (!m) {
        xSemaphoreGive(members_lock);
        goto drop;
    }
    for (unsigned i = 0; i < 64; i++) {
        flow_t *f = &flows[i];
        if (flow_generations[i] == atomic_load(&usb_generation) &&
            f->id == m->id && f->peer == rd32(b + 12) &&
            m->client->vpn_ip == rd32(b + 16) && f->remote == rd16(b + h) &&
            f->mapped == rd16(b + h + 2) && f->proto == b[9] &&
            esp_timer_get_time() - f->touched < 120000000) {
            f->touched = esp_timer_get_time();
            wr32(b + 12, f->alias);
            wr32(b + 16, f->host);
            wr16(b + h + 2, f->local);
            checksums(b, n, h);
            struct pbuf *out = pbuf_alloc(PBUF_IP, n, PBUF_RAM);
            if (out) {
                pbuf_take(out, b, n);
                ip4_addr_t ip = {.addr = htonl(f->host)};
                struct netif *usb = esp_netif_get_netif_impl(usb_interface);
                if(usb)usb->output(usb, out, &ip);
                pbuf_free(out);
            }
            break;
        }
    }
    xSemaphoreGive(members_lock);
drop:
    free(b);
    return ERR_OK;
}

#ifndef GATEWAY_HOST_TEST
typedef struct {struct pbuf *packet;struct netif *input;unsigned generation;} route_item;
static void route_task(void *context) {
    route_item item;
    for(;;)if(xQueueReceive(route_queue,&item,portMAX_DELAY)==pdTRUE) {
        if(item.generation!=atomic_load(&usb_generation))pbuf_free(item.packet);
        else if(!gateway_process_host_input(item.packet,item.input))pbuf_free(item.packet);
    }
}
#endif
int gateway_host_input(struct pbuf *p,struct netif *input) {
#ifndef GATEWAY_HOST_TEST
    uint8_t first[20];
    if(usb_interface && input==esp_netif_get_netif_impl(usb_interface) &&
       pbuf_copy_partial(p,first,20,0)==20 && (rd32(first+16)&0xfffe0000)==0xc6120000) {
        route_item item={p,input,atomic_load(&usb_generation)};
        if(p->tot_len>1400 || !routes_ready || !route_queue || xQueueSend(route_queue,&item,0)!=pdTRUE)pbuf_free(p);
        return 1;
    }
#endif
    return gateway_process_host_input(p,input);
}
