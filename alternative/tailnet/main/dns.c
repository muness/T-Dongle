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
    uint32_t upstream_resolver;
    uint16_t next_id;
    struct {
        bool active;
        uint16_t original_id, wire_id;
        uint32_t question_hash;
        struct sockaddr_in host;
        socklen_t host_len;
        TickType_t started;
    } pending[4];

} dns_workspace;
static TaskHandle_t dns_handle;
/* Queries, cache hits, lock failures, temporary failures, absent names,
 * upstream-busy rejections, maximum local lookup duration in ticks. */
static uint32_t dns_stats[11];
unsigned gateway_dns_count(unsigned index) { return index<11 ? __atomic_load_n(&dns_stats[index],__ATOMIC_RELAXED) : 0; }
static void dns_count(unsigned index) { __atomic_fetch_add(&dns_stats[index],1,__ATOMIC_RELAXED); }

unsigned gateway_dns_stack_free(void) {
    return dns_handle ? (unsigned)uxTaskGetStackHighWaterMark(dns_handle) : 0;
}
/* Match the entire uncompressed question as well as our rewritten ID. */
static uint32_t dns_question_hash(const uint8_t *packet,size_t n) {
    if(n<17 || read16(packet+4)!=1)return 0;
    size_t pos=12;
    while(pos<n && packet[pos]) {
        unsigned len=packet[pos++];
        if(len>63 || pos+len>=n)return 0;
        pos+=len;
    }
    if(pos+5>n)return 0;
    uint32_t hash=2166136261u;
    for(size_t i=12;i<pos+5;i++)hash=(hash^packet[i])*16777619u;
    return hash ? hash : 1;
}
static void dns_poll_upstream(dns_workspace *work) {
    if(work->upstream_sock<0)return;
    /* Bounded draining preserves service fairness under unsolicited packets. */
    for(unsigned attempt=0;attempt<4;attempt++) {
        int count=recv(work->upstream_sock,work->packet,sizeof(work->packet),MSG_DONTWAIT);
        if(count<0)break;
        if(count<12 || !(work->packet[2]&128))continue;
        uint32_t hash=dns_question_hash(work->packet,count);
        for(unsigned i=0;i<4;i++)if(work->pending[i].active && read16(work->packet)==work->pending[i].wire_id && hash==work->pending[i].question_hash) {
            write16(work->packet,work->pending[i].original_id);
            sendto(work->sock,work->packet,count,0,(struct sockaddr *)&work->pending[i].host,work->pending[i].host_len);
            work->pending[i].active=false;dns_count(8);break;
        }
    }
    bool active=false;
    for(unsigned i=0;i<4;i++) {
        if(work->pending[i].active && (TickType_t)(xTaskGetTickCount()-work->pending[i].started)>=pdMS_TO_TICKS(2000)){work->pending[i].active=false;dns_count(9);}
        active|=work->pending[i].active;
    }
    if(!active){close(work->upstream_sock);work->upstream_sock=-1;}
}
/* A name reaches a membership in one of two forms: "<peer>.<label>.tailnet"
 * or the peer's MagicDNS name "<peer>.<tailnet-domain>", where the domain is
 * the membership's own DNS name without its first label and trailing dot. */
typedef enum { DNS_NAME_NONE, DNS_NAME_QUALIFIED, DNS_NAME_MAGIC } dns_form;
/* The domain of a DNS name: everything after its first label, no trailing dot. */
static size_t dns_domain_of(const char *self, size_t cap, const char **suffix) {
    size_t n=strnlen(self,cap);
    if(n==cap)return 0;
    if(n && self[n-1]=='.')n--;
    const char *dot=memchr(self,'.',n);
    if(!dot || dot==self || (size_t)(dot-self)+1>=n)return 0;
    *suffix=dot+1;
    return n-(size_t)(dot+1-self);
}
static size_t dns_magic_suffix(const membership_t *m, const char **suffix) {
    if(!m->client)return 0;
    return dns_domain_of(m->client->self_dns_name,sizeof(m->client->self_dns_name),suffix);
}
/* name is "<label>.<suffix>" with at least one label before the suffix. */
static bool dns_in_domain(const char *name, size_t len, const char *suffix, size_t n) {
    return n && len>n+1 && name[len-n-1]=='.' && !strncasecmp(name+len-n,suffix,n);
}
static dns_form dns_name_form(const membership_t *m, const char *name, size_t len) {
    size_t label_len=strlen(m->label);
    if(len>label_len+9 && name[len-label_len-9]=='.' && !strncasecmp(name+len-label_len-8,m->label,label_len) && !strcasecmp(name+len-8,".tailnet"))return DNS_NAME_QUALIFIED;
    const char *suffix;
    size_t n=dns_magic_suffix(m,&suffix);
    if(dns_in_domain(name,len,suffix,n))return DNS_NAME_MAGIC;
    return DNS_NAME_NONE;
}
/* Lock-free view of the MagicDNS domains the memberships currently report, so
 * ordinary host queries never touch members_lock (held for map application and
 * membership start/stop). Single writer at a time (callers hold members_lock),
 * readers are the DNS task: a sequence counter, odd while rewriting, makes a
 * torn read detectable. The snapshot only decides "is this name ours?"; the
 * answer itself is always computed under members_lock. */
#define DNS_DOMAINS 6
static struct {
    uint32_t seq;
    bool overflow; /* more memberships than slots: absence proves nothing */
    uint8_t count;
    struct { uint8_t len; char name[128]; } domain[DNS_DOMAINS];
} dns_domains, dns_domains_next; /* _next is scratch, guarded by members_lock */
typedef enum { DNS_DOMAIN_NO, DNS_DOMAIN_YES, DNS_DOMAIN_UNKNOWN } dns_domain_result;
static dns_domain_result dns_domain_lookup(const char *name, size_t len) {
    for(unsigned attempt=0;attempt<4;attempt++) {
        uint32_t before=__atomic_load_n(&dns_domains.seq,__ATOMIC_ACQUIRE);
        if(before&1)continue;
        bool hit=false;
        unsigned count=dns_domains.count;
        bool overflow=dns_domains.overflow;
        if(count>DNS_DOMAINS)count=DNS_DOMAINS;
        for(unsigned i=0;i<count && !hit;i++)hit=dns_in_domain(name,len,dns_domains.domain[i].name,dns_domains.domain[i].len&127);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if(__atomic_load_n(&dns_domains.seq,__ATOMIC_RELAXED)!=before)continue;
        return hit ? DNS_DOMAIN_YES : (overflow ? DNS_DOMAIN_UNKNOWN : DNS_DOMAIN_NO);
    }
    return DNS_DOMAIN_UNKNOWN;
}
/* Republish the memberships' MagicDNS domains. Call with members_lock held
 * after anything that can change them: adding, removing or stopping a
 * membership, and periodically, because map updates rewrite self_dns_name in
 * the control task without a notification. A domain not yet published is
 * answered by the upstream resolver, so keep the calls frequent. */
void gateway_dns_domains_refresh(void) {
    __typeof__(dns_domains_next) *next=&dns_domains_next;
    memset(next,0,sizeof(*next));
    for(membership_t *m=members;m;m=m->next) {
        const char *suffix;
        size_t n=dns_magic_suffix(m,&suffix);
        if(!n)continue;
        if(next->count==DNS_DOMAINS){next->overflow=true;continue;}
        next->domain[next->count].len=n;
        memcpy(next->domain[next->count].name,suffix,n);
        next->count++;
        /* The control task rewrites the name unlocked; drop a torn copy. */
        const char *again;
        if(dns_magic_suffix(m,&again)!=n || memcmp(again,suffix,n))return;
    }
    if(next->count==dns_domains.count && next->overflow==dns_domains.overflow && !memcmp(next->domain,dns_domains.domain,sizeof(next->domain)))return;
    uint32_t seq=dns_domains.seq;
    __atomic_store_n(&dns_domains.seq,seq+1,__ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    dns_domains.count=next->count;dns_domains.overflow=next->overflow;
    memcpy(dns_domains.domain,next->domain,sizeof(next->domain));
    __atomic_store_n(&dns_domains.seq,seq+2,__ATOMIC_RELEASE);
}
/* Number of memberships whose MagicDNS domain contains name. Lock held. */
static unsigned dns_magic_claims(const char *name, size_t len) {
    unsigned claims=0;
    for(membership_t *m=members;m;m=m->next)claims+=dns_name_form(m,name,len)==DNS_NAME_MAGIC;
    return claims;
}
typedef struct { unsigned matches; bool temporary; uint32_t member, generation, alias; } dns_match;
/* Look for one peer of m whose name in the given form equals name. Cached and
 * fresh matches both count so that duplicates stay ambiguous. */
static void dns_match_member(dns_workspace *work, membership_t *m, const char *name, dns_form form, dns_match *r) {
    if (!m->client || m->client->state != ML_STATE_CONNECTED || !m->client->directory.session_valid) {r->temporary=true;return;}
    uint32_t generation=__atomic_load_n(&m->client->directory.generation,__ATOMIC_ACQUIRE);
    for(unsigned c=0;c<4;c++)if(work->cache[c].alias && work->cache[c].member==m->id && work->cache[c].generation==generation && (int32_t)(work->cache[c].expires-xTaskGetTickCount())>0 && !strcasecmp(work->cache[c].name,name)) {
        r->alias=work->cache[c].alias;work->cache[c].used=++work->clock;r->matches++;dns_count(1);return;
    }
    const char *suffix=NULL;
    size_t suffix_len=form==DNS_NAME_MAGIC ? dns_magic_suffix(m,&suffix) : 0;
    for (unsigned i = 0; i < m->client->directory.count; i++) {
        ml_peer_update_t *p=&work->record;
        if(!ml_directory_at(m->client,i,p)){r->temporary=true;continue;}
        char *peer=work->peer, *candidate=work->qualified;
        strlcpy(peer, p->hostname, sizeof(work->peer));
        char *dot = strchr(peer, '.');
        int written;
        if(form==DNS_NAME_QUALIFIED) {
            if (dot)
                *dot = 0;
            written=snprintf(candidate, sizeof(work->qualified), "%s.%s.tailnet", peer, m->label);
        } else if(dot) /* the directory stores the full MagicDNS name */
            written=snprintf(candidate, sizeof(work->qualified), "%s", peer);
        else /* peers restored from the NVS cache keep only their first label */
            written=snprintf(candidate, sizeof(work->qualified), "%s.%.*s", peer, (int)suffix_len, suffix);
        if (written>=(int)sizeof(work->qualified) || strcasecmp(name, candidate) || !p->vpn_ip)continue;
        r->matches++;
        uint32_t alias=gateway_alias(m->id, p->vpn_ip);
        if(!alias){r->temporary=true;continue;}
        r->alias=alias;r->member=m->id;r->generation=generation;
    }
    if(generation!=__atomic_load_n(&m->client->directory.generation,__ATOMIC_ACQUIRE))r->temporary=true;
}
static void dns_cache_store(dns_workspace *work, const char *name, const dns_match *r) {
    unsigned victim=0;
    for(unsigned c=0;c<4;c++)if(!work->cache[c].alias || work->cache[c].used<work->cache[victim].used)victim=c;
    if(strlen(name)>=sizeof(work->cache[victim].name))return;
    strlcpy(work->cache[victim].name,name,sizeof(work->cache[victim].name));
    work->cache[victim].member=r->member;work->cache[victim].generation=r->generation;
    work->cache[victim].alias=r->alias;work->cache[victim].used=++work->clock;work->cache[victim].expires=xTaskGetTickCount()+pdMS_TO_TICKS(30000);
}
/* Resolve a tailnet name to its USB alias, or 0 (NXDOMAIN, or SERVFAIL when
 * *temporary). Lock held. A MagicDNS domain claimed by two memberships is
 * ambiguous even if only one of them has the peer. */
static uint32_t dns_resolve(dns_workspace *work, const char *name, size_t len, unsigned claims, bool *temporary) {
    dns_match r={0};
    if(claims>1)return 0;
    for (membership_t *m = members; m; m = m->next) {
        dns_form form=dns_name_form(m,name,len);
        if(form!=DNS_NAME_NONE)dns_match_member(work,m,name,form,&r);
    }
    *temporary=r.temporary;
    if (r.matches != 1 || r.temporary)return 0;
    if(r.member)dns_cache_store(work,name,&r);
    return r.alias;
}
static void dns_task(void *arg) {
    dns_workspace *work=arg;
    int sock=work->sock;
    uint8_t *packet=work->packet;
    for (;;) {
        dns_poll_upstream(work);
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
        /* Names of ".tailnet" or inside a membership's MagicDNS domain are
         * answered here. The domain list is a lock-free snapshot, so ordinary
         * names never wait on members_lock; only a name inside a known domain
         * takes it, and a busy lock is then SERVFAIL, never a forward. */
        bool maybe = false;
        if (!tailnet) {
            dns_domain_result domain = dns_domain_lookup(name, len);
            tailnet = domain == DNS_DOMAIN_YES;
            maybe = domain == DNS_DOMAIN_UNKNOWN; /* snapshot unusable: ask under the lock */
        }
        bool lookup = tailnet && type == 1 && klass == 1;
        bool locked = (lookup || maybe) && xSemaphoreTake(members_lock, pdMS_TO_TICKS(50)) == pdTRUE;
        if (locked && (tailnet || maybe)) {
            /* Re-check ownership: the domain may have gone since the snapshot. */
            bool qualified = len >= 8 && !strcasecmp(name + len - 8, ".tailnet");
            unsigned claims = qualified ? 0 : dns_magic_claims(name, len);
            tailnet = qualified || claims != 0;
            lookup = tailnet && type == 1 && klass == 1;
            if (lookup)
                alias = dns_resolve(work, name, len, claims, &temporary);
        } else if (lookup) {temporary=true;dns_count(2);}
        if (locked)
            xSemaphoreGive(members_lock);
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
        int slot=-1;
        for(unsigned i=0;i<4;i++)if(!work->pending[i].active){slot=i;break;}
        if(slot<0) {
            dns_count(5);packet[2]=0x81;packet[3]=0x82;
            write16(packet+6,0);write16(packet+8,0);write16(packet+10,0);
            sendto(sock,packet,pos,0,(struct sockaddr *)&host,sl);continue;
        }
        uint32_t resolver_address=upstream.sin_addr.s_addr;
        if(work->upstream_sock>=0 && work->upstream_resolver!=resolver_address) {
            close(work->upstream_sock);work->upstream_sock=-1;
            for(unsigned i=0;i<4;i++)work->pending[i].active=false;
        }
        if(work->upstream_sock<0) {
            int out=socket(AF_INET,SOCK_DGRAM,0);
            if(out<0)continue;
            if(connect(out,(struct sockaddr *)&upstream,sizeof(upstream))<0){close(out);continue;}
            work->upstream_sock=out;work->upstream_resolver=resolver_address;
        }
        uint16_t original=read16(packet),wire=++work->next_id;
        /* At most four IDs coexist; skip any live ID after uint16 wrap. */
        for(unsigned i=0;i<4;i++)if(work->pending[i].active && work->pending[i].wire_id==wire){wire=++work->next_id;i=(unsigned)-1;}
        uint32_t hash=dns_question_hash(packet,n);
        write16(packet,wire);
        if(send(work->upstream_sock,packet,n,MSG_DONTWAIT)==n) {
            work->pending[slot].active=true;work->pending[slot].original_id=original;work->pending[slot].wire_id=wire;
            work->pending[slot].question_hash=hash;work->pending[slot].host=host;work->pending[slot].host_len=sl;
            work->pending[slot].started=xTaskGetTickCount();dns_count(7);
            unsigned pending=0;for(unsigned i=0;i<4;i++)pending+=work->pending[i].active;
            if(pending>gateway_dns_count(10))__atomic_store_n(&dns_stats[10],pending,__ATOMIC_RELAXED);
        }

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
