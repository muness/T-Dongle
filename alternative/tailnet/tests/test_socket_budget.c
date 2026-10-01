#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "../main/socket_budget.h"
#define CONFIG_LWIP_MAX_SOCKETS 20
static pthread_mutex_t account_lock=PTHREAD_MUTEX_INITIALIZER, allocation_lock=PTHREAD_MUTEX_INITIALIZER;
typedef pthread_mutex_t portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED PTHREAD_MUTEX_INITIALIZER
#define portENTER_CRITICAL(p) pthread_mutex_lock(p)
#define portEXIT_CRITICAL(p) pthread_mutex_unlock(p)
static int64_t esp_timer_get_time(void) {return 1000000;}
static unsigned live;
static int __real_lwip_socket(int d,int t,int p) {
    pthread_mutex_lock(&allocation_lock);
    int fd;if(live==20){errno=EMFILE;fd=-1;}else {fd=socket(d,t,p);if(fd>=0)live++;}
    pthread_mutex_unlock(&allocation_lock);return fd;
}
static int __real_lwip_accept(int fd,struct sockaddr *a,socklen_t *n) {
    pthread_mutex_lock(&allocation_lock);
    int result;if(live==20){errno=ENFILE;result=-1;}else {result=accept(fd,a,n);if(result>=0)live++;}
    pthread_mutex_unlock(&allocation_lock);return result;
}
static int __real_lwip_close(int fd) {
    pthread_mutex_lock(&allocation_lock);int result=close(fd);if(!result){assert(live);live--;}
    pthread_mutex_unlock(&allocation_lock);return result;
}
#include "socket_accounting.inc"
static int allocate(void) {int fd=__wrap_lwip_socket(AF_INET,SOCK_DGRAM,0);assert(fd>=0);return fd;}
static void *http(void *arg) {
    int client=__wrap_lwip_accept(*(int*)arg,NULL,NULL);assert(client>=0);
    char request[128]={0};assert(read(client,request,sizeof(request))>0);
    const char reply[]="HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    assert(write(client,reply,sizeof(reply)-1)==sizeof(reply)-1);assert(!__wrap_lwip_close(client));return NULL;
}
static void management_request(int listener,struct sockaddr_in address) {
    pthread_t server;assert(!pthread_create(&server,NULL,http,&listener));
    int phone=socket(AF_INET,SOCK_STREAM,0);assert(phone>=0&&!connect(phone,(struct sockaddr*)&address,sizeof(address)));
    const char request[]="GET /status HTTP/1.1\r\nHost: 192.168.77.1\r\n\r\n";
    assert(write(phone,request,sizeof(request)-1)==sizeof(request)-1);
    char response[128]={0};assert(read(phone,response,sizeof(response))>0&&strstr(response,"200 OK"));close(phone);pthread_join(server,NULL);
}
int main(void) {
    // Raising the descriptor total without reservation does not pass admission.
    assert(!gateway_socket_admit(10,1,7));assert(gateway_socket_admit(20,0,5));
    assert(gateway_socket_admit(20,1,9));assert(!gateway_socket_admit(20,2,13));
    assert(gateway_socket_admit(32,3,20));assert(!gateway_socket_admit(32,4,24));
    int baseline[5],members[8],pressure[4];
    baseline[0]=__wrap_lwip_socket(AF_INET,SOCK_STREAM,0);assert(baseline[0]>=0);
    struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(baseline[0],(struct sockaddr*)&address,sizeof(address))&&!listen(baseline[0],2));socklen_t n=sizeof(address);getsockname(baseline[0],(struct sockaddr*)&address,&n);
    for(unsigned i=1;i<5;i++)baseline[i]=allocate(); // HTTP controls, DNS, SNTP
    for(unsigned active=0;active<2;active++){
        assert(gateway_socket_admit(20,active,gateway_sockets_snapshot().open));
        for(unsigned i=0;i<4;i++)members[active*4+i]=allocate();
    }
    assert(!gateway_socket_admit(20,2,gateway_sockets_snapshot().open));
    for(unsigned i=0;i<4;i++)pressure[i]=allocate(); // DNS forward, two per-member transients, other HTTP client
    management_request(baseline[0],address); // Recovery works while admitted memberships and transient sockets remain.
    int last[3];for(unsigned i=0;i<3;i++)last[i]=allocate();errno=0;assert(__wrap_lwip_socket(AF_INET,SOCK_DGRAM,0)<0&&errno==EMFILE);
    gateway_socket_stats s=gateway_sockets_snapshot();assert(s.open==20&&s.peak==20&&s.failures==1&&s.last_errno==EMFILE&&s.last_operation==1);
    errno=0;assert(__wrap_lwip_accept(baseline[0],NULL,NULL)<0&&errno==ENFILE);
    s=gateway_sockets_snapshot();assert(s.failures==2&&s.last_operation==2&&s.last_errno==ENFILE);
    for(unsigned i=0;i<3;i++)assert(!__wrap_lwip_close(last[i]));
    management_request(baseline[0],address); // Failure injection also leaves recovery possible.
    for(unsigned i=0;i<4;i++)assert(!__wrap_lwip_close(pressure[i]));
    for(unsigned i=0;i<8;i++)assert(!__wrap_lwip_close(members[i]));
    assert(gateway_socket_admit(20,0,gateway_sockets_snapshot().open));
    // No-client case: malicious/stale HTTP occupancy cannot admit a member.
    assert(!gateway_socket_admit(20,0,16));management_request(baseline[0],address);
    for(unsigned i=0;i<5;i++)assert(!__wrap_lwip_close(baseline[i]));
    assert(!gateway_sockets_snapshot().open&&!live);
    puts("Sockets: 0/1/n admission, peak/error accounting, pressure and recovery HTTP passed");
}
