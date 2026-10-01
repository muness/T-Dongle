#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
typedef int esp_err_t;
typedef unsigned nvs_handle_t;
#define ESP_OK 0
#define NVS_READWRITE 1
#define ESP_ERR_NVS_NOT_FOUND -1
#define ESP_ERR_INVALID_SIZE -2
typedef struct {char identity_namespace[16];uint8_t machine_private_key[32],machine_public_key[32],wg_private_key[32],wg_public_key[32],disco_private_key[32],disco_public_key[32];bool identity_persistent;} microlink_t;
static struct {char name[16];uint8_t saved[96],pending[96];bool present,dirty;} namespaces[8];
static bool fail_commit,fail_open;static uint8_t random_byte;
static void esp_fill_random(void *out,size_t n){for(size_t i=0;i<n;i++)((uint8_t*)out)[i]=++random_byte;}
static void ml_x25519_base(uint8_t *out,const uint8_t *in,int length){for(int i=0;i<32;i++)out[i]=in[i]^0xa5;}
static int nvs_open(const char *name,int mode,nvs_handle_t *handle){if(fail_open)return -3;for(unsigned i=0;i<8;i++)if(!namespaces[i].name[0]||!strcmp(namespaces[i].name,name)){strcpy(namespaces[i].name,name);*handle=i;return 0;}return -3;}
static int nvs_get_blob(nvs_handle_t h,const char *key,void *out,size_t *n){assert(!strcmp(key,"identity_v1"));if(!namespaces[h].present)return -1;assert(*n>=96);memcpy(out,namespaces[h].saved,96);*n=96;return 0;}
static int nvs_set_blob(nvs_handle_t h,const char *key,const void *in,size_t n){assert(n==96&&!strcmp(key,"identity_v1"));memcpy(namespaces[h].pending,in,96);namespaces[h].dirty=true;return 0;}
static int nvs_commit(nvs_handle_t h){if(fail_commit)return -4;memcpy(namespaces[h].saved,namespaces[h].pending,96);namespaces[h].present=true;namespaces[h].dirty=false;return 0;}
static void nvs_close(nvs_handle_t h){namespaces[h].dirty=false;}
#include "identity_core.inc"
int main(void){
    microlink_t a={.identity_namespace="tn_00000001"},b={.identity_namespace="tn_00000002"},c={.identity_namespace="tn_00000003"};
    assert(load_or_generate_keys(&a)==0&&a.identity_persistent);assert(load_or_generate_keys(&b)==0&&b.identity_persistent);assert(load_or_generate_keys(&c)==0&&c.identity_persistent);
    assert(memcmp(a.machine_private_key,b.machine_private_key,32)&&memcmp(b.wg_private_key,c.wg_private_key,32));
    microlink_t reboot={.identity_namespace="tn_00000002"};assert(load_or_generate_keys(&reboot)==0);assert(!memcmp(reboot.machine_private_key,b.machine_private_key,32)&&!memcmp(reboot.wg_public_key,b.wg_public_key,32));
    fail_commit=true;microlink_t bad={.identity_namespace="tn_00000004"};assert(load_or_generate_keys(&bad)!=0&&!bad.identity_persistent);fail_commit=false;assert(load_or_generate_keys(&bad)==0&&bad.identity_persistent);
    fail_open=true;microlink_t unavailable={.identity_namespace="tn_00000005"};assert(load_or_generate_keys(&unavailable)!=0&&!unavailable.identity_persistent);return 0;
}
