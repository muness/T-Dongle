#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
typedef struct {unsigned read_expected,read_received,read_elapsed_ms,read_errno;int read_tls_result,conn_tls_result;} microlink_t;
static int64_t clock_us;
static int64_t esp_timer_get_time(void){return clock_us;}
#define pdMS_TO_TICKS(x) (x)
static void vTaskDelay(int n){clock_us+=n*1000;}
static unsigned offset,chunk,mode,calls;
static int ml_conn_read(microlink_t *ml,uint8_t *out,size_t len){
 calls++;clock_us+=1000;
 if(mode==1 && calls%17==1){errno=EAGAIN;return -1;}
 if(mode==2 && offset>=100)return 0;
 if(mode==3){errno=EAGAIN;return -1;}
 if(mode==4 && offset>=100){errno=EIO;ml->conn_tls_result=-1234;return -1;}
 size_t n=len<chunk?len:chunk;for(size_t i=0;i<n;i++)out[i]=(uint8_t)(offset+i);offset+=n;return n;
}
#include "../components/microlink/src/coord_read.inc"
int main(void){
 uint8_t body[4093];microlink_t ml={0};
 for(chunk=1;chunk<=4093;chunk+=17){offset=calls=clock_us=0;mode=1;assert(!coord_recv_committed(&ml,body,sizeof(body)));for(unsigned i=0;i<sizeof(body);i++)assert(body[i]==(uint8_t)i);}
 chunk=100;offset=calls=clock_us=0;mode=2;assert(coord_recv_committed(&ml,body,sizeof(body))<0);assert(ml.read_received==100 && ml.read_errno==ECONNRESET);
 offset=calls=clock_us=0;mode=3;assert(coord_recv_committed(&ml,body,sizeof(body))<0);assert(ml.read_received==0 && ml.read_errno==ETIMEDOUT && clock_us<10100000);
 offset=calls=clock_us=0;mode=3;assert(coord_recv(&ml,body,3)<0 && errno==EAGAIN && clock_us<10000);
 offset=calls=clock_us=0;mode=4;assert(coord_recv_committed(&ml,body,sizeof(body))<0 && ml.read_tls_result==-1234);
 mode=0;offset=calls=clock_us=0;assert(!coord_recv_committed(&ml,body,sizeof(body)));assert(ml.read_tls_result==-1234); /* Evidence survives successful retries. */
}
