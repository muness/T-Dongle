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
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM -2
#define pdPASS 1
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define ML_STATE_CONNECTED 4
typedef int esp_err_t;
typedef void *TaskHandle_t;
typedef struct {char hostname[64];uint32_t vpn_ip;} ml_peer_update_t;
typedef struct {int state;struct {bool session_valid;unsigned count;} directory;} client_t;
typedef struct membership {struct membership *next;client_t *client;uint32_t id;char label[24];} membership_t;
static membership_t *members;static int members_lock;
static int xSemaphoreTake(int lock,int wait){return 1;}
static void xSemaphoreGive(int lock){}
static int reads,closes,sends,forwards,live,fail_at;static size_t task_stack;
static void *task_arg;static void (*task_fn)(void *);static jmp_buf finished;
static unsigned char query[1500],response[1500];static size_t query_size,response_size;
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
    ((struct sockaddr_in *)host)->sin_addr.s_addr=htonl(0xc0a84d02);return query_size;
}
static int send_to(int fd,const void *p,size_t n,int flags,const struct sockaddr *host,socklen_t len){assert(n<=1500);memcpy(response,p,n);response_size=n;sends++;return n;}
typedef struct {uint32_t addr;} ip_addr_t;
static ip_addr_t resolver;
static const ip_addr_t *dns_getserver(int i){resolver.addr=htonl(0x08080808);return &resolver;}
#define ip_addr_isany(p) (!(p)->addr)
#define IP_IS_V4(p) 1
#define ip_2_ip4(p) (p)
#define ip4_addr_get_u32(p) ((p)->addr)
static int connect_socket(int fd,const struct sockaddr *a,socklen_t n){return 0;}
static int option(int fd,int l,int key,const void *v,socklen_t n){return 0;}
static int send_packet(int fd,const void *p,size_t n,int flags){forwards++;return n;}
static int receive_packet(int fd,void *p,size_t n,int flags){assert(n==1500);memcpy(p,query,query_size);((uint8_t *)p)[2]|=128;return query_size;}
static bool ml_directory_at(client_t *c,unsigned i,ml_peer_update_t *out){strcpy(out->hostname,"server.example.ts.net");out->vpn_ip=0x64400001;return true;}
static uint32_t gateway_alias(uint32_t id,uint32_t peer){assert(id==1 && peer==0x64400001);return 0xc6120003;}
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
static void run(void){reads=sends=forwards=0;response_size=0;if(!setjmp(finished))task_fn(task_arg);}
int main(void){
    for(fail_at=1;fail_at<=4;fail_at++){closes=0;assert(gateway_dns_start()!=0);assert(live==0);assert(closes==(fail_at>=3));}
    fail_at=0;assert(gateway_dns_start()==0 && live==1 && task_stack==4096);assert(gateway_dns_stack_free()==3000);
    question("example.com");run();assert(sends==1 && forwards==1 && response_size==query_size);
    client_t client={.state=4,.directory={.session_valid=true,.count=1}};
    membership_t member={.client=&client,.id=1,.label="work"};members=&member;
    question("server.work.tailnet");run();assert(sends==1 && forwards==0 && response[7]==1 && response_size==query_size+16);
    assert(!memcmp(response+response_size-4,"\xc6\x12\x00\x03",4));
    question("missing.work.tailnet");run();assert(sends==1 && (response[3]&15)==3 && forwards==0);
    for(size_t n=0;n<12;n++){query_size=n;run();assert(!sends && !forwards);}
    question("server.work.tailnet");query[12]=255;run();assert(!sends && !forwards);
    release(task_arg);assert(live==0);
    puts("DNS: ordinary forwarding and flash-directory aliases use full workspace; malformed queries and every startup allocation/socket/task failure are bounded");
}
