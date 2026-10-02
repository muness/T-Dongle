#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "tdongle_l2.h"
#include "freertos/queue.h"
struct queue {unsigned entries[32],n;};
static jmp_buf idle;
static unsigned freed,sent,tx,queue_calls,fail_queue;static int send_error,tx_error;static bool ready=true,fail_task,fail_alloc;
static unsigned char observed[1514];static size_t observed_len;
static void *allocate(size_t n,size_t size){return fail_alloc?NULL:calloc(n,size);}
#define calloc allocate
#include "../l2.c"
#undef calloc
QueueHandle_t xQueueCreate(unsigned n,unsigned s){if(++queue_calls==fail_queue)return NULL;return calloc(1,sizeof(struct queue));}
int xQueueSend(QueueHandle_t q,const void *p,unsigned t){if(q->n==32)return 0;q->entries[q->n++]=*(unsigned*)p;return 1;}
int xQueueReceive(QueueHandle_t q,void *p,unsigned t){if(!q->n){if(t==portMAX_DELAY)longjmp(idle,1);return 0;}*(unsigned*)p=q->entries[0];memmove(q->entries,q->entries+1,--q->n*sizeof(unsigned));return 1;}
void vQueueDelete(QueueHandle_t q){free(q);}
int xTaskCreate(void(*f)(void*),const char*n,unsigned s,void*a,unsigned p,void*h){return !fail_task;}
void vTaskDelay(unsigned n){}
bool tud_ready(void){return ready;}
void tud_network_link_state(int i,bool c){}
void esp_wifi_internal_free_rx_buffer(void*p){freed++;}
esp_err_t esp_wifi_internal_reg_rxcb(int i,esp_err_t(*f)(void*,uint16_t,void*)){return 0;}
esp_err_t esp_wifi_internal_tx(int i,void*b,uint16_t n){tx++;memcpy(observed,b,n);observed_len=n;return tx_error;}
esp_err_t tinyusb_net_send_sync(void*b,size_t n,void*c,unsigned t){sent++;memcpy(observed,b,n);observed_len=n;if(!send_error)tdongle_l2_release(c);return send_error;}
static void drain(void){if(!setjmp(idle))transmit(NULL);}
int main(void){
 unsigned char mac[6]={2,1,2,3,4,5},packet[1514]={0};
 fail_alloc=true;assert(tdongle_l2_start(mac)==ESP_ERR_NO_MEM && !pool && !available && !pending);fail_alloc=false;
 for(unsigned i=1;i<=2;i++){queue_calls=0;fail_queue=i;assert(tdongle_l2_start(mac)==ESP_ERR_NO_MEM && !pool && !available && !pending);}fail_queue=0;fail_task=true;assert(tdongle_l2_start(mac)==ESP_ERR_NO_MEM);fail_task=false;
 assert(tdongle_l2_start(mac)==ESP_OK);tdongle_l2_link(true);
 /* ARP, IPv4 DHCP and IPv6 retain every byte; no address rewriting. */
 for(unsigned protocol=0;protocol<3;protocol++){packet[6]=9;packet[12]=protocol==0?8:protocol==1?8:0x86;packet[13]=protocol==0?6:protocol==1?0:0xdd;packet[20]=protocol;receive(packet,600,(void*)1);drain();assert(observed_len==600 && !memcmp(observed,packet,600) && available->n==32);}
 memcpy(packet+6,mac,6);unsigned before=sent;receive(packet,600,(void*)1);drain();assert(sent==before);tdongle_l2_host(packet,600);assert(tx==1 && !memcmp(observed,packet,600));
 packet[6]=9;receive(packet,600,(void*)1);tdongle_l2_link(false);drain();assert(sent==before && available->n==32);tdongle_l2_link(true);
 send_error=-1;receive(packet,600,(void*)1);drain();assert(sent==before+30 && available->n==32);send_error=0;
 unsigned drops=freed;receive(packet,13,(void*)1);receive(packet,1515,(void*)1);ready=false;receive(packet,600,(void*)1);assert(freed==drops+3 && available->n==32);ready=true;
 for(unsigned i=0;i<35;i++)receive(packet,600,(void*)1);assert(pending->n==32 && available->n==0);drain();assert(available->n==32);
 memcpy(packet+6,mac,6);tx=0;tx_error=-1;tdongle_l2_host(packet,600);assert(tx==20);free(pool);vQueueDelete(available);vQueueDelete(pending);
 return 0;
}
