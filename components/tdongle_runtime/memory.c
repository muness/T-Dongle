#include "tdongle_memory.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
static tdongle_memory_record entries[16];
static unsigned count,next;
static portMUX_TYPE lock=portMUX_INITIALIZER_UNLOCKED;
void tdongle_memory_note(unsigned operation,size_t requested,int failed){
 tdongle_memory_record r={(uint32_t)(esp_timer_get_time()/1000),operation,(uint32_t)requested,heap_caps_get_free_size(MALLOC_CAP_INTERNAL),heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),!!failed};
 portENTER_CRITICAL(&lock);
 /* Preserve low-water transitions and failures; ordinary traffic cannot evict them. */
 if(!count || failed || r.minimum_bytes<entries[(next+15)%16].minimum_bytes){entries[next]=r;next=(next+1)%16;if(count<16)count++;}
 portEXIT_CRITICAL(&lock);
}
unsigned tdongle_memory_count(void){portENTER_CRITICAL(&lock);unsigned n=count;portEXIT_CRITICAL(&lock);return n;}
tdongle_memory_record tdongle_memory_get(unsigned offset){portENTER_CRITICAL(&lock);tdongle_memory_record r={0};if(offset<count)r=entries[(next+16-count+offset)%16];portEXIT_CRITICAL(&lock);return r;}
