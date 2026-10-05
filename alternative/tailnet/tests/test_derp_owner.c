#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "tdongle_memory.h"
#define pdTRUE 1
#define DERP_FRAME_SEND_PACKET 4
#define ML_EVT_DERP_RECONNECT 2
typedef struct {int frame_type;uint8_t dest_pubkey[32];uint8_t *data;size_t len;} ml_derp_tx_item_t;
typedef struct {int derp_tx_queue,events;struct {bool connected;uint64_t last_recv_ms;} derp;} microlink_t;
static unsigned tx_left,rx_left,reconnects,tls_depth,tx_calls,rx_calls,pong_calls;
static int fail_write,fail_read;
static uint64_t now,write_delay;
static uint64_t ml_get_time_ms(void){return now;}
static int xQueueReceive(int q,ml_derp_tx_item_t *item,int wait){assert(!wait);if(!tx_left)return 0;tx_left--;*item=(ml_derp_tx_item_t){.frame_type=4,.data=malloc(1),.len=1};return 1;}
static void xEventGroupSetBits(int events,int bits){assert(bits==2);reconnects++;}
static int derp_send_packet(microlink_t *ml,const uint8_t *key,const uint8_t *data,size_t len){assert(ml->derp.connected && !tls_depth++);tx_calls++;now+=write_delay;tls_depth--;return fail_write?-1:0;}
static int derp_write_frame(microlink_t *ml,int type,const uint8_t *data,size_t len){assert(!tls_depth++);pong_calls++;tls_depth--;return 0;}
static int poll_derp_read(microlink_t *ml){assert(ml->derp.connected && !tls_depth++);rx_calls++;tls_depth--;if(fail_read)return -1;if(!rx_left)return 0;rx_left--;derp_write_frame(ml,0,NULL,0);return 1;}
#include "../components/microlink/src/derp_service.inc"
int main(void) {
    microlink_t m={.derp.connected=true};uint32_t tx=0,rx=0;
    tx_left=rx_left=100;derp_service_io(&m,&tx,&rx);
    assert(tx==4 && rx==8 && pong_calls==8 && tx_left==96 && rx_left==92);
    write_delay=40;derp_service_io(&m,&tx,&rx);assert(tx==5 && rx==16); // slow TX cannot starve RX
    fail_write=1;unsigned before_rx=rx_calls;derp_service_io(&m,&tx,&rx);
    assert(!m.derp.connected && reconnects==1 && rx_calls==before_rx); // no TLS use after failure
    fail_write=0;write_delay=0;m.derp.connected=true;tx_left=0;fail_read=1;
    derp_service_io(&m,&tx,&rx);assert(!m.derp.connected && reconnects==2);
    puts("DERP owner: fair bounded duplex work, PING replies serialized with writes, no further TLS calls after read/write failure");
}
