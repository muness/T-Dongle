#pragma once
#include <stddef.h>
#include <stdint.h>
typedef struct {uint32_t uptime_ms,operation,requested,free_bytes,minimum_bytes,largest_bytes,failed;} tdongle_memory_record;
void tdongle_memory_note(unsigned operation,size_t requested,int failed);
unsigned tdongle_memory_count(void);
tdongle_memory_record tdongle_memory_get(unsigned offset);
