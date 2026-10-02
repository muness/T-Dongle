/* Transparent forwarding derived from main/bridge.c. The copied-frame pool
 * exists only in bridge mode; Wi-Fi RX never blocks on USB backpressure. */
#include "tdongle_l2.h"
#include "esp_private/wifi.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "tinyusb_net.h"
#include "tusb.h"
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#define SLOTS 32
#define FRAME_MAX 1514
typedef struct {uint16_t len;unsigned generation;uint8_t bytes[FRAME_MAX];} frame;
static frame *pool;
static QueueHandle_t available,pending;
static uint8_t identity[6];
static atomic_uint epoch;
static atomic_bool linked;
void tdongle_l2_release(void *cookie){unsigned i=(unsigned)(uintptr_t)cookie;if(i<SLOTS && available)xQueueSend(available,&i,0);}
static esp_err_t receive(void *buffer,uint16_t len,void *driver_buffer){
 unsigned i;
 if(len>=14 && len<=FRAME_MAX && memcmp((uint8_t*)buffer+6,identity,6) && atomic_load(&linked) && tud_ready() && xQueueReceive(available,&i,0)==pdTRUE){
  pool[i].generation=atomic_load(&epoch);pool[i].len=len;memcpy(pool[i].bytes,buffer,len);
  if(xQueueSend(pending,&i,0)!=pdTRUE)tdongle_l2_release((void*)(uintptr_t)i);
 }
 esp_wifi_internal_free_rx_buffer(driver_buffer);return ESP_OK;
}
static void transmit(void *unused){
 unsigned i;
 for(;;)if(xQueueReceive(pending,&i,portMAX_DELAY)==pdTRUE){
  esp_err_t result=ESP_FAIL;
  for(unsigned attempt=0;attempt<30 && atomic_load(&linked) && pool[i].generation==atomic_load(&epoch) && tud_ready();attempt++){
   result=tinyusb_net_send_sync(pool[i].bytes,pool[i].len,(void*)(uintptr_t)i,pdMS_TO_TICKS(20));
   if(result==ESP_OK){break;}
   vTaskDelay(pdMS_TO_TICKS(1));
  }
  if(result!=ESP_OK)tdongle_l2_release((void*)(uintptr_t)i);
 }
}
esp_err_t tdongle_l2_start(const uint8_t mac[6]){
 memcpy(identity,mac,6);pool=calloc(SLOTS,sizeof(frame));available=xQueueCreate(SLOTS,sizeof(unsigned));pending=xQueueCreate(SLOTS,sizeof(unsigned));
 if(!pool || !available || !pending)goto failed;
 for(unsigned i=0;i<SLOTS;i++)xQueueSend(available,&i,0);
 if(xTaskCreate(transmit,"l2-usb",3072,NULL,5,NULL)!=pdPASS)goto failed;
 return ESP_OK;
failed:
 if(available){vQueueDelete(available);}
 if(pending){vQueueDelete(pending);}
 available=pending=NULL;free(pool);pool=NULL;return ESP_ERR_NO_MEM;
}
void tdongle_l2_link(bool connected){atomic_store(&linked,connected);atomic_fetch_add(&epoch,1);esp_wifi_internal_reg_rxcb(ESP_IF_WIFI_STA,connected?receive:NULL);tud_network_link_state(0,connected);}
esp_err_t tdongle_l2_host(void *buffer,uint16_t len){
 if(!pool || len<14 || len>FRAME_MAX || memcmp((uint8_t*)buffer+6,identity,6) || !atomic_load(&linked))return ESP_OK;
 for(unsigned attempt=0;attempt<20 && atomic_load(&linked);attempt++){if(esp_wifi_internal_tx(ESP_IF_WIFI_STA,buffer,len)==ESP_OK)break;vTaskDelay(pdMS_TO_TICKS(1));}
 return ESP_OK;
}
