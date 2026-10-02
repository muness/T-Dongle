#include "lwip/dns.h"
#include "gateway.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include <strings.h>
static uint16_t read16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static void write16(uint8_t *p, uint16_t n) {
    p[0] = n >> 8;
    p[1] = n;
}
/* Owned by the DNS task for its lifetime. Keep packet/directory workspace off
 * its stack: socket, FAT and flash calls need that stack while resolving. */
typedef struct {
    int sock;
    uint8_t packet[1500];
    char name[256], peer[64], qualified[128];
    ml_peer_update_t record;
    struct { char name[128]; uint32_t member, generation, alias; uint32_t used; TickType_t expires; } cache[4];
    uint32_t clock;
    int upstream_sock;
    uint16_t upstream_id;
    struct sockaddr_in upstream_host;
    socklen_t upstream_host_len;
    TickType_t upstream_started;

} dns_workspace;
static TaskHandle_t dns_handle;
/* Queries, cache hits, lock failures, temporary failures, absent names,
 * upstream-busy rejections, maximum local lookup duration in ticks. */
static uint32_t dns_stats[7];
unsigned gateway_dns_count(unsigned index) { return index<7 ? __atomic_load_n(&dns_stats[index],__ATOMIC_RELAXED) : 0; }
static void dns_count(unsigned index) { __atomic_fetch_add(&dns_stats[index],1,__ATOMIC_RELAXED); }

unsigned gateway_dns_stack_free(void) {
    return dns_handle ? (unsigned)uxTaskGetStackHighWaterMark(dns_handle) : 0;
}
static void dns_task(void *arg) {
    dns_workspace *work=arg;
    int sock=work->sock;
    uint8_t *packet=work->packet;
    for (;;) {
        /* One bounded pending upstream query; never block local tailnet DNS. */
        if (work->upstream_sock >= 0) {
            int count=recv(work->upstream_sock,packet,sizeof(work->packet),MSG_DONTWAIT);
            if(count>=12 && read16(packet)==work->upstream_id && (packet[2]&128)) {
                sendto(sock,packet,count,0,(struct sockaddr *)&work->upstream_host,work->upstream_host_len);
                close(work->upstream_sock);work->upstream_sock=-1;
            } else if ((TickType_t)(xTaskGetTickCount()-work->upstream_started)>=pdMS_TO_TICKS(2000)) {
                close(work->upstream_sock);work->upstream_sock=-1;
            }
        }
        struct sockaddr_in host;
        socklen_t sl = sizeof(host);
        int n = recvfrom(sock, packet, sizeof(work->packet), 0, (struct sockaddr *)&host, &sl);
        if (n < 12 || (ntohl(host.sin_addr.s_addr) & 0xffffff00) != 0xc0a84d00 ||
            read16(packet + 4) != 1 || packet[2] & 128)
            continue;
        char *name=work->name;
        size_t pos = 12, len = 0;
        bool invalid = false;
        while (pos < (size_t)n && packet[pos]) {
            unsigned size = packet[pos++];
            if (size > 63 || pos + size > (size_t)n || len + size + 1 >= sizeof(work->name)) {
                invalid = true;
                break;
            }
            if (len)
                name[len++] = '.';
            memcpy(name + len, packet + pos, size);
            len += size;
            pos += size;
        }
        if (invalid || pos + 5 > (size_t)n)
            continue;
        name[len] = 0;
        pos++;
        unsigned type = read16(packet + pos), klass = read16(packet + pos + 2);
        pos += 4;
        bool tailnet = len >= 8 && !strcasecmp(name + len - 8, ".tailnet");
        TickType_t lookup_started=xTaskGetTickCount();
        uint32_t alias = 0;
        bool temporary=false;
        if (tailnet && type == 1 && klass == 1 &&
            xSemaphoreTake(members_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
            unsigned matches = 0;
            uint32_t found_member=0,found_generation=0;
            for (membership_t *m = members; m; m = m->next) {
                size_t label_len=strlen(m->label);
                if(len<=label_len+9 || name[len-label_len-9]!='.' || strncasecmp(name+len-label_len-8,m->label,label_len))continue;
                if (!m->client || m->client->state != ML_STATE_CONNECTED || !m->client->directory.session_valid) {temporary=true;continue;}
                uint32_t generation=__atomic_load_n(&m->client->directory.generation,__ATOMIC_ACQUIRE);
                bool cached=false;
                for(unsigned c=0;c<4;c++)if(work->cache[c].alias && work->cache[c].member==m->id && work->cache[c].generation==generation && (int32_t)(work->cache[c].expires-xTaskGetTickCount())>0 && !strcasecmp(work->cache[c].name,name)) {
                    alias=work->cache[c].alias;work->cache[c].used=++work->clock;matches++;cached=true;break;
                }
                if(cached){dns_count(1);continue;}
                for (unsigned i = 0; i < m->client->directory.count; i++) {
                        ml_peer_update_t *p=&work->record;
                        if(!ml_directory_at(m->client,i,p)){temporary=true;continue;}
                        char *peer=work->peer, *qualified=work->qualified;
                        strlcpy(peer, p->hostname, sizeof(work->peer));
                        char *dot = strchr(peer, '.');
                        if (dot)
                            *dot = 0;
                        snprintf(qualified, sizeof(work->qualified), "%s.%s.tailnet", peer, m->label);
                        if (!strcasecmp(name, qualified) && p->vpn_ip) {
                            matches++;
                            alias = gateway_alias(m->id, p->vpn_ip);
                            if(!alias){temporary=true;continue;}
                            found_member=m->id;found_generation=generation;

                        }
                    }
                if(generation!=__atomic_load_n(&m->client->directory.generation,__ATOMIC_ACQUIRE))temporary=true;
            }
            if (matches != 1 || temporary)
                alias = 0;
            else if(found_member) {
                unsigned victim=0;
                for(unsigned c=0;c<4;c++)if(!work->cache[c].alias || work->cache[c].used<work->cache[victim].used)victim=c;
                if(strlen(name)<sizeof(work->cache[victim].name)) {
                    strlcpy(work->cache[victim].name,name,sizeof(work->cache[victim].name));
                    work->cache[victim].member=found_member;work->cache[victim].generation=found_generation;
                    work->cache[victim].alias=alias;work->cache[victim].used=++work->clock;work->cache[victim].expires=xTaskGetTickCount()+pdMS_TO_TICKS(30000);
                }
            }
            xSemaphoreGive(members_lock);
        } else if(tailnet && type==1 && klass==1) {temporary=true;dns_count(2);}
        if (tailnet) {
            dns_count(0);
            if(temporary)dns_count(3);else if(!alias && type==1)dns_count(4);
            uint32_t elapsed=xTaskGetTickCount()-lookup_started;
            if(elapsed>gateway_dns_count(6))__atomic_store_n(&dns_stats[6],elapsed,__ATOMIC_RELAXED);
            packet[2] = 0x81;
            /* AAAA for an existing IPv4 name is NODATA, not NXDOMAIN. */
            packet[3] = alias ? 0x80 : (temporary ? 0x82 : (type!=1 ? 0x80 : 0x83));
            write16(packet + 6, alias ? 1 : 0);
            write16(packet + 8, 0);
            write16(packet + 10, 0);
            if (alias && pos + 16 <= sizeof(work->packet)) {
                uint8_t answer[] = {0xc0, 0x0c, 0, 1, 0,           1,           0,          0,
                                    0,    30,   0, 4, alias >> 24, alias >> 16, alias >> 8, alias};
                memcpy(packet + pos, answer, 16);
                pos += 16;
            }
            sendto(sock, packet, pos, 0, (struct sockaddr *)&host, sl);
            continue;
        }
        /* Forward ordinary DNS only to the Wi-Fi-provided resolver. Match the
         * reply's transaction ID; connect() pins the resolver source. */
        const ip_addr_t *resolver = dns_getserver(0);
        if (ip_addr_isany(resolver) || !IP_IS_V4(resolver))
            continue;
        struct sockaddr_in upstream = {.sin_family = AF_INET,
                                       .sin_port = htons(53),
                                       .sin_addr.s_addr = ip4_addr_get_u32(ip_2_ip4(resolver))};
        if(work->upstream_sock>=0) {
            dns_count(5);packet[2]=0x81;packet[3]=0x82;
            write16(packet+6,0);write16(packet+8,0);write16(packet+10,0);
            sendto(sock,packet,pos,0,(struct sockaddr *)&host,sl);continue;
        }
        int out = socket(AF_INET, SOCK_DGRAM, 0);
        if (out < 0)
            continue;
        if (connect(out,(struct sockaddr *)&upstream,sizeof(upstream))==0 && send(out,packet,n,0)==n) {
            work->upstream_sock=out;work->upstream_id=read16(packet);
            work->upstream_host=host;work->upstream_host_len=sl;work->upstream_started=xTaskGetTickCount();
        } else close(out);
    }
}
esp_err_t gateway_dns_start(void) {
    dns_workspace *work=calloc(1,sizeof(*work));
    if(!work)return ESP_ERR_NO_MEM;
    int sock=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(53),.sin_addr.s_addr=htonl(0xc0a84d01)};
    if(sock<0){free(work);return ESP_ERR_NO_MEM;}
    if(bind(sock,(struct sockaddr *)&local,sizeof(local))<0){close(sock);free(work);return ESP_FAIL;}
    struct timeval poll_timeout={.tv_sec=0,.tv_usec=50000};
    if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&poll_timeout,sizeof(poll_timeout))<0){close(sock);free(work);return ESP_FAIL;}
    work->sock=sock;work->upstream_sock=-1;
    if(xTaskCreate(dns_task,"gateway_dns",4096,work,3,&dns_handle)!=pdPASS){close(sock);free(work);return ESP_ERR_NO_MEM;}
    return ESP_OK;
}
