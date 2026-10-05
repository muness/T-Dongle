#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "../components/microlink/include/ml_published_name.h"
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM -2
#define pdPASS 1
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define ML_STATE_CONNECTED 4
typedef unsigned TickType_t;
static unsigned ticks;static unsigned xTaskGetTickCount(void){return ticks;}
typedef int esp_err_t;
typedef void *TaskHandle_t;
typedef struct {char hostname[64];uint32_t vpn_ip;} ml_peer_update_t;
typedef struct {int state;struct {bool session_valid;unsigned count,generation;} directory;ml_published_name_t self_dns_name;const char *const *records;} client_t;
typedef struct membership {struct membership *next;client_t *client;uint32_t id;char label[24];} membership_t;
static membership_t *members;static int members_lock;
static int lock_ok=1,lock_takes;static int xSemaphoreTake(int lock,int wait){lock_takes++;return lock_ok;}
static void xSemaphoreGive(int lock){}
static int reads,closes,sends,forwards,live,fail_at;static size_t task_stack;
static void *task_arg;static void (*task_fn)(void *);static jmp_buf finished;
static unsigned char query[1500],response[1500],upstream_reply[1500];static size_t upstream_reply_size;static uint16_t client_port=1000,response_port;static size_t query_size,response_size;
static unsigned uxTaskGetStackHighWaterMark(void *handle){return 3000;}
static void *allocate(size_t n,size_t size){if(fail_at==1)return NULL;void *p=calloc(n,size);if(p)live++;return p;}
static void release(void *p){if(p){live--;free(p);}}
static int create_task(void (*fn)(void *),const char *name,unsigned stack,void *arg,int priority,void **handle){if(fail_at==4)return 0;task_fn=fn;task_arg=arg;task_stack=stack;*handle=arg;return 1;}
static int make_socket(int d,int t,int p){return fail_at==2?-1:7;}
static int bind_socket(int fd,const struct sockaddr *a,socklen_t n){return fail_at==3?-1:0;}
static int close_socket(int fd){closes++;return 0;}
static int receive_from(int fd,void *p,size_t n,int flags,struct sockaddr *host,socklen_t *len){
    if(reads++)longjmp(finished,1);
    assert(n==1500 && query_size<=n);memcpy(p,query,query_size);
    ((struct sockaddr_in *)host)->sin_addr.s_addr=htonl(0xc0a84d02);((struct sockaddr_in *)host)->sin_port=htons(client_port);return query_size;
}
static int send_to(int fd,const void *p,size_t n,int flags,const struct sockaddr *host,socklen_t len){assert(n<=1500);response_port=ntohs(((const struct sockaddr_in *)host)->sin_port);memcpy(response,p,n);response_size=n;sends++;return n;}
typedef struct {uint32_t addr;} ip_addr_t;
static ip_addr_t resolver;
static const ip_addr_t *dns_getserver(int i){resolver.addr=htonl(0x08080808);return &resolver;}
#define ip_addr_isany(p) (!(p)->addr)
#define IP_IS_V4(p) 1
#define ip_2_ip4(p) (p)
#define ip4_addr_get_u32(p) ((p)->addr)
static int connect_socket(int fd,const struct sockaddr *a,socklen_t n){return fail_at==6?-1:0;}
static int option(int fd,int l,int key,const void *v,socklen_t n){return fail_at==5?-1:0;}
static int send_packet(int fd,const void *p,size_t n,int flags){forwards++;return fail_at==7?-1:n;}
static bool upstream_ready=false;
static int receive_packet(int fd,void *p,size_t n,int flags){if(!upstream_ready)return -1;assert(n==1500);memcpy(p,upstream_reply,upstream_reply_size);upstream_ready=false;return upstream_reply_size;}
static int directory_reads;static bool directory_ok=true,change_generation=false;static const char *record_name="server.example.ts.net";
static bool ml_directory_at(client_t *c,unsigned i,ml_peer_update_t *out){directory_reads++;if(!directory_ok)return false;if(change_generation)c->directory.generation++;strcpy(out->hostname,c->records?c->records[i]:record_name);out->vpn_ip=0x64400001+i;return true;}
static unsigned alias_calls;static uint32_t gateway_alias(uint32_t id,uint32_t peer){alias_calls++;assert(id>=1 && id<=3);return 0xc6120002+(id-1)*0x100+(peer&0xff);}
#define calloc allocate
#define free release
#define xTaskCreate create_task
#define socket make_socket
#define bind bind_socket
#define close close_socket
#define recvfrom receive_from
#define sendto send_to
#define connect connect_socket
#define setsockopt option
#define send send_packet
#define recv receive_packet
#include "dns.inc"
#undef calloc
#undef free
static void question(const char *name){
    memset(query,0,sizeof(query));query[0]=0x12;query[1]=0x34;query[2]=1;query[5]=1;size_t n=12;
    for(const char *s=name;*s;){const char *dot=strchr(s,'.');size_t len=dot?(size_t)(dot-s):strlen(s);query[n++]=len;memcpy(query+n,s,len);n+=len;s+=len;if(*s)s++;}
    query[n++]=0;query[n++]=0;query[n++]=1;query[n++]=0;query[n++]=1;query_size=n;
}
#define SYNC() gateway_dns_domains_refresh()
static void w_reset(dns_workspace *w){w->upstream_sock=-1;for(unsigned i=0;i<4;i++)w->pending[i].active=false;}
static void run(void){reads=sends=forwards=0;response_size=0;if(!setjmp(finished))task_fn(task_arg);}
int main(void){
    for(fail_at=1;fail_at<=5;fail_at++){closes=0;assert(gateway_dns_start()!=0);assert(live==0);assert(closes==(fail_at>=3));}
    fail_at=0;assert(gateway_dns_start()==0 && live==1 && task_stack==4096);assert(gateway_dns_stack_free()==3000);
    question("example.com");run();assert(forwards==1);((dns_workspace *)task_arg)->upstream_sock=-1;((dns_workspace *)task_arg)->pending[0].active=false;
    client_t client={.state=4,.directory={.session_valid=true,.count=1},.self_dns_name={.text="dongle.example.ts.net."}};
    membership_t member={.client=&client,.id=1,.label="work"};members=&member;SYNC();
    question("server.work.tailnet");run();assert(sends==1 && forwards==0 && response[7]==1 && response_size==query_size+16);
    assert(!memcmp(response+response_size-4,"\xc6\x12\x00\x03",4));
    directory_reads=0;question("server.work.tailnet");run();assert(response[7]==1 && directory_reads==0);
    client.directory.generation++;run();assert(response[7]==1 && directory_reads==1);
    ticks=30001;directory_reads=0;run();assert(directory_reads==1);ticks=0;
    upstream_ready=false;((dns_workspace *)task_arg)->upstream_sock=8;((dns_workspace *)task_arg)->pending[0].active=true;directory_reads=0;
    run();assert(response[7]==1 && forwards==0);assert(((dns_workspace *)task_arg)->upstream_sock==8);
    ticks=2001;run();assert(((dns_workspace *)task_arg)->upstream_sock==-1);ticks=0;upstream_ready=false;
    client.state=0;run();assert((response[3]&15)==2 && response[7]==0);client.state=4;
    lock_ok=0;run();assert((response[3]&15)==2);lock_ok=1;
    client.directory.generation++;directory_ok=false;run();assert((response[3]&15)==2);directory_ok=true;
    question("server.work.tailnet");query[query_size-3]=28;run();assert((response[3]&15)==0 && response[7]==0);
    question("server.work.tailnet");client.directory.generation++;change_generation=true;run();assert((response[3]&15)==2);change_generation=false;
    members=NULL;run();assert((response[3]&15)==3 && response[7]==0);members=&member;
    for(unsigned i=0;i<5;i++){char name[64],record[64];snprintf(name,sizeof(name),"peer%u.work.tailnet",i);snprintf(record,sizeof(record),"peer%u.example.ts.net",i);record_name=record;question(name);run();assert(response[7]==1);}
    record_name="peer0.example.ts.net";question("peer0.work.tailnet");directory_reads=0;run();assert(directory_reads==1);
    record_name="server.example.ts.net";
    question("missing.work.tailnet");run();assert(sends==1 && (response[3]&15)==3 && forwards==0);
    for(size_t n=0;n<12;n++){query_size=n;run();assert(!sends && !forwards);}
    question("server.work.tailnet");query[12]=255;run();assert(!sends && !forwards);

    /* MagicDNS names: the names /status displays resolve like the qualified form. */
    {
    dns_workspace *wk=task_arg;
    const char *const peers_a[]={"server.example.ts.net","alpha.example.ts.net","beta.example.ts.net","server.other.ts.net"};
    client_t second={.state=4,.directory={.session_valid=true,.count=1},.self_dns_name={.text="gw.corp.ts.net"},.records=(const char *const[]){"server.corp.ts.net"}};
    membership_t other={.client=&second,.id=2,.label="home"};member.next=&other;SYNC();
    client.records=peers_a;client.directory.count=4;client.directory.generation++;
    #define EXPECT_ALIAS(n,a) do{question(n);run();assert(sends==1&&forwards==0&&(response[3]&15)==0&&response[7]==1&&!memcmp(response+response_size-4,(a),4));}while(0)
    #define EXPECT_RCODE(n,rc) do{question(n);run();assert(sends==1&&forwards==0&&(response[3]&15)==(rc)&&response[7]==0);}while(0)
    #define EXPECT_UPSTREAM(n) do{question(n);run();assert(sends==0&&forwards==1);w_reset(wk);}while(0)
    EXPECT_ALIAS("alpha.work.tailnet","\xc6\x12\x00\x04");
    EXPECT_ALIAS("alpha.example.ts.net","\xc6\x12\x00\x04");
    /* Two peers share a first label: the qualified form is ambiguous, MagicDNS names are exact. */
    EXPECT_RCODE("server.work.tailnet",3);
    EXPECT_ALIAS("server.example.ts.net","\xc6\x12\x00\x03");
    EXPECT_ALIAS("SERVER.Example.TS.net","\xc6\x12\x00\x03");
    EXPECT_ALIAS("alpha.example.ts.net","\xc6\x12\x00\x04");
    EXPECT_ALIAS("beta.example.ts.net","\xc6\x12\x00\x05");
    /* Same first label in another peer's domain never matches this peer. */
    EXPECT_UPSTREAM("server.other.ts.net");
    EXPECT_UPSTREAM("alpha.other.ts.net");
    EXPECT_RCODE("gamma.example.ts.net",3);
    EXPECT_RCODE("a.alpha.example.ts.net",3);
    /* The second membership's domain resolves to its own alias (membership 2). */
    EXPECT_ALIAS("server.corp.ts.net","\xc6\x12\x01\x03");
    /* Cached lookups answer without reading the directory. */
    directory_reads=0;question("alpha.example.ts.net");run();assert(response[7]==1 && directory_reads==0);
    /* Domain apex, bare domain and the first label alone are not peers. */
    EXPECT_UPSTREAM("example.ts.net");EXPECT_UPSTREAM("ts.net");EXPECT_UPSTREAM("server");
    EXPECT_UPSTREAM("server.example.ts.net.evil.com");EXPECT_UPSTREAM("xexample.ts.net");EXPECT_UPSTREAM("server.xexample.ts.net");
    EXPECT_UPSTREAM("example.com");
    /* AAAA is NODATA, also for names that do not exist. */
    question("server.example.ts.net");query[query_size-3]=28;run();assert((response[3]&15)==0 && response[7]==0 && sends==1);
    question("nobody.example.ts.net");query[query_size-3]=28;run();assert((response[3]&15)==0 && response[7]==0 && sends==1);
    /* Disconnected membership: temporary failure, never NXDOMAIN or upstream. */
    client.directory.generation++;client.state=0;EXPECT_RCODE("server.example.ts.net",2);EXPECT_RCODE("server.work.tailnet",2);
    EXPECT_ALIAS("server.corp.ts.net","\xc6\x12\x01\x03");client.state=4;
    client.directory.session_valid=false;EXPECT_RCODE("server.example.ts.net",2);client.directory.session_valid=true;
    /* Generation change while scanning is temporary. */
    client.directory.generation++;change_generation=true;EXPECT_RCODE("alpha.example.ts.net",2);change_generation=false;
    lock_ok=0;EXPECT_RCODE("server.work.tailnet",2);EXPECT_UPSTREAM("example.com");lock_ok=1;
    directory_ok=false;client.directory.generation++;EXPECT_RCODE("server.example.ts.net",2);directory_ok=true;
    /* A connected client without a DNS name yet owns no MagicDNS domain. */
    ml_published_name_set(&client.self_dns_name,"");SYNC();client.directory.generation++;EXPECT_UPSTREAM("server.example.ts.net");
    ml_published_name_set(&client.self_dns_name,"dongle");SYNC();EXPECT_UPSTREAM("server.example.ts.net");
    ml_published_name_set(&client.self_dns_name,"dongle.example.ts.net");SYNC();EXPECT_ALIAS("server.example.ts.net","\xc6\x12\x00\x03");
    /* Duplicate domain across memberships is ambiguous even when only one has the peer. */
    ml_published_name_set(&second.self_dns_name,"other.example.ts.net.");SYNC();
    EXPECT_RCODE("server.example.ts.net",3);EXPECT_RCODE("alpha.example.ts.net",3);
    unsigned before=alias_calls;EXPECT_RCODE("server.example.ts.net",3);assert(alias_calls==before);
    EXPECT_ALIAS("alpha.work.tailnet","\xc6\x12\x00\x04");
    second.state=0;EXPECT_RCODE("server.example.ts.net",3);second.state=4;
    ml_published_name_set(&second.self_dns_name,"gw.corp.ts.net");SYNC();
    /* Short hostnames (NVS-cached peers) are completed with the membership's domain. */
    {const char *const short_names[]={"cached"};client.records=short_names;client.directory.count=1;client.directory.generation++;
     EXPECT_ALIAS("cached.example.ts.net","\xc6\x12\x00\x03");EXPECT_ALIAS("cached.work.tailnet","\xc6\x12\x00\x03");}
    client.records=peers_a;client.directory.count=4;client.directory.generation++;
    /* Long, malformed and label-edge names stay bounded. */
    {char longname[300];memset(longname,'a',63);longname[63]=0;strcat(longname,".example.ts.net");EXPECT_RCODE(longname,3);
     memset(longname,'b',63);longname[63]='.';memset(longname+64,'c',63);longname[127]='.';memset(longname+128,'d',63);longname[191]='.';memset(longname+192,'e',50);strcpy(longname+242,".example.ts.net");
     question(longname);run();assert(sends==0 && forwards==0);}
    question("server.example.ts.net");query[12]=255;run();assert(!sends && !forwards);
    question("server.example.ts.net");query_size-=3;run();assert(!sends && !forwards);
    question("server.example.ts.net");query[query_size-1]=3;run();assert(sends==1 && (response[3]&15)==3);
    member.next=NULL;SYNC();client.records=NULL;client.directory.count=1;client.directory.generation++;
    EXPECT_UPSTREAM("server.corp.ts.net");
    /* Ordinary names never take members_lock; only names inside a domain do. */
    {
    member.next=&other;SYNC();client.records=peers_a;client.directory.count=4;client.directory.generation++;
    lock_takes=0;
    EXPECT_UPSTREAM("example.com");EXPECT_UPSTREAM("server");EXPECT_UPSTREAM("server.other.ts.net");
    EXPECT_UPSTREAM("example.ts.net");EXPECT_UPSTREAM("xexample.ts.net");
    question("example.com");query[query_size-3]=28;run();assert(forwards==1);w_reset(wk);
    assert(lock_takes==0);
    EXPECT_ALIAS("alpha.example.ts.net","\xc6\x12\x00\x04");assert(lock_takes==1);
    /* AAAA inside a domain is NODATA without the lock as well. */
    lock_takes=0;question("alpha.example.ts.net");query[query_size-3]=28;run();assert(response[7]==0 && (response[3]&15)==0 && lock_takes==0);
    /* A busy lock is a temporary failure for names inside a known domain, never a forward. */
    lock_ok=0;lock_takes=0;
    EXPECT_RCODE("alpha.example.ts.net",2);EXPECT_RCODE("server.corp.ts.net",2);EXPECT_RCODE("alpha.work.tailnet",2);
    EXPECT_UPSTREAM("example.com");EXPECT_UPSTREAM("server.other.ts.net");
    lock_ok=1;
    /* The snapshot follows membership changes and domain renames. */
    ml_published_name_set(&second.self_dns_name,"gw.moved.ts.net");SYNC();
    lock_takes=0;EXPECT_UPSTREAM("server.corp.ts.net");assert(lock_takes==0);
    lock_takes=0;EXPECT_RCODE("server.moved.ts.net",3);assert(lock_takes==1);
    member.next=NULL;SYNC();
    lock_takes=0;EXPECT_UPSTREAM("server.moved.ts.net");assert(lock_takes==0);
    lock_ok=0;EXPECT_UPSTREAM("server.moved.ts.net");lock_ok=1;
    member.next=&other;ml_published_name_set(&second.self_dns_name,"gw.corp.ts.net");SYNC();
    EXPECT_ALIAS("server.corp.ts.net","\xc6\x12\x01\x03");
    /* A stale snapshot (domain gone, not yet republished) falls back to upstream, not NXDOMAIN. */
    ml_published_name_set(&second.self_dns_name,"");lock_takes=0;EXPECT_UPSTREAM("server.corp.ts.net");assert(lock_takes==1);
    ml_published_name_set(&second.self_dns_name,"gw.corp.ts.net");SYNC();
    /* An odd sequence (writer mid-update) is unusable: the lock decides, ordinary names still pass. */
    dns_domains.seq++;lock_takes=0;
    EXPECT_ALIAS("server.corp.ts.net","\xc6\x12\x01\x03");assert(lock_takes==1);
    EXPECT_UPSTREAM("example.com");assert(lock_takes==2);
    dns_domains.seq++;
    /* More memberships than slots: absence of a domain proves nothing. */
    {membership_t extra[DNS_DOMAINS+1];client_t clients[DNS_DOMAINS+1];membership_t *tail=&other;
     for(unsigned i=0;i<DNS_DOMAINS+1;i++){memset(&extra[i],0,sizeof(extra[i]));clients[i]=(client_t){.state=4,.directory={.session_valid=true}};
      {char n[40];snprintf(n,sizeof(n),"x.z%u.ts.net",i);ml_published_name_set(&clients[i].self_dns_name,n);}extra[i].client=&clients[i];extra[i].id=3;strcpy(extra[i].label,"e");tail->next=&extra[i];tail=&extra[i];}
     SYNC();assert(dns_domains.overflow && dns_domains.count==DNS_DOMAINS);
     EXPECT_RCODE("a.z6.ts.net",3);
     EXPECT_RCODE("a.z0.ts.net",3);
     other.next=NULL;SYNC();assert(!dns_domains.overflow);}
    member.next=NULL;SYNC();client.records=NULL;client.directory.count=1;client.directory.generation++;
    }
    }
    question("example.com");dns_workspace *w=task_arg;w->upstream_sock=8;
    for(unsigned i=0;i<4;i++){w->pending[i].active=true;w->pending[i].started=0;}
    run();assert((response[3]&15)==2 && forwards==0);
    for(unsigned i=0;i<4;i++)w->pending[i].active=false;
    w->upstream_sock=-1;
    fail_at=6;run();assert(w->upstream_sock==-1);fail_at=7;run();assert(!w->pending[0].active);fail_at=0;dns_poll_upstream(w);assert(w->upstream_sock==-1);
    w->next_id=65535;
    /* Four independent transactions coexist on one socket, even with equal client IDs. */
    for(unsigned i=0;i<4;i++){client_port=1000+i;run();assert(forwards==1 && w->pending[i].active);assert(w->pending[i].original_id==0x1234);}
    assert(w->pending[0].wire_id!=w->pending[1].wire_id);
    memcpy(upstream_reply,query,query_size);upstream_reply_size=query_size;upstream_reply[2]|=128;
    write16(upstream_reply,w->pending[2].wire_id);upstream_reply[13]^=1;upstream_ready=true;dns_poll_upstream(w);assert(w->pending[2].active);
    upstream_reply[13]^=1;upstream_ready=true;dns_poll_upstream(w);assert(!w->pending[2].active && response_port==1002 && read16(response)==0x1234);
    write16(upstream_reply,w->pending[0].wire_id);upstream_ready=true;dns_poll_upstream(w);assert(!w->pending[0].active && response_port==1000);
    question("server.work.tailnet");run();assert(response[7]==1 && forwards==0);
    ticks=2001;dns_poll_upstream(w);assert(w->upstream_sock==-1);
    for(unsigned i=0;i<4;i++)assert(!w->pending[i].active);
    assert(sizeof(w->pending)<=192);
    assert(gateway_dns_count(7)>=4 && gateway_dns_count(8)==2 && gateway_dns_count(9)>=2 && gateway_dns_count(10)==4);


    assert(sizeof(((dns_workspace *)task_arg)->cache)<=640);
    assert(gateway_dns_count(1)>0 && gateway_dns_count(2)>0 && gateway_dns_count(3)>0);
    release(task_arg);assert(live==0);
    puts("DNS: ordinary forwarding and flash-directory aliases use full workspace; malformed queries and every startup allocation/socket/task failure are bounded");
}
