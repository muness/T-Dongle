/* Route every mbedTLS allocation (DERP and control-key TLS, esp-tls) through the TLS owner. */
#include "tdongle_memory.h"
#include "esp_mem.h"
#include "mbedtls/platform.h"
static void *tls_calloc(size_t n,size_t size){return tdongle_heap_note_alloc(TDONGLE_OWNER_TLS,esp_mbedtls_mem_calloc(n,size));}
static void tls_free(void *block){tdongle_heap_note_free(TDONGLE_OWNER_TLS,block);esp_mbedtls_mem_free(block);}
void tdongle_memory_diagnostics_init(void){mbedtls_platform_set_calloc_free(tls_calloc,tls_free);}
