#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "cJSON.h"
#include "tdongle_memory.h"
#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 2
#define ESP_ERR_INVALID_SIZE 3
typedef int esp_err_t;
typedef struct membership {struct membership *next;uint32_t id;char label[24],ns[16],key[160],hostname[48];bool enabled;} membership_t;
static membership_t *members;
static bool settings_ok=true;
static uint32_t next_id=3;
static int store;
static char persisted[16384];
static unsigned writes, allocations, fail_at;
static void *test_malloc(size_t n){if(++allocations==fail_at)return NULL;return malloc(n);}
static void *test_calloc(size_t n,size_t bytes){void *p=test_malloc(n*bytes);if(p)memset(p,0,n*bytes);return p;}
static int nvs_set_str(int h,const char *key,const char *s){assert(strlen(s)<sizeof(persisted));strcpy(persisted,s);writes++;return 0;}
static int nvs_get_str(int h,const char *key,char *s,size_t *n){if(!persisted[0])return ESP_ERR_NVS_NOT_FOUND;if(s)memcpy(s,persisted,strlen(persisted)+1);*n=strlen(persisted)+1;return 0;}
static int nvs_commit(int h){return 0;}
#define malloc test_malloc
#define calloc test_calloc
#include "settings.inc"
#undef malloc
#undef calloc
static void clear_loaded(void){while(members){membership_t *next=members->next;free(members);members=next;}}
int main(void) {
    cJSON_Hooks hooks={test_malloc,free};cJSON_InitHooks(&hooks);
    membership_t b={.id=2,.label="personal",.key="test-key",.enabled=true},a={.id=1,.label="work",.next=&b};
    char good[16384];unsigned maximum=0;
    members=&a;assert(save_members());strcpy(good,persisted);maximum=allocations;
    // Every allocation failure in object construction AND JSON rendering must
    // leave the complete persisted settings byte-for-byte unchanged.
    for(unsigned i=1;i<=maximum;i++) {
        allocations=0;fail_at=i;writes=0;strcpy(persisted,good);
        assert(!save_members());assert(!writes && !strcmp(persisted,good));
    }
    fail_at=0;members=NULL;allocations=0;assert(load_members());maximum=allocations;clear_loaded();
    for(unsigned i=1;i<=maximum;i++) {
        allocations=0;fail_at=i;members=NULL;next_id=99;
        assert(!load_members());assert(!members && next_id==99 && !strcmp(persisted,good));
    }
    fail_at=0;strcpy(persisted,"{\"next_id\":3,\"members\":[{\"id\":1,\"label\":\"work\",\"key\":\"\",\"enabled\":true},{\"id\":1,\"label\":\"bad\",\"key\":\"\",\"enabled\":true}]}");
    assert(!load_members() && !members);
    strcpy(persisted,"not JSON");assert(!load_members() && !members);
    persisted[0]=0;assert(load_members());
    settings_ok=false;writes=0;assert(!save_members() && !writes);
    cJSON_InitHooks(NULL);
    puts("Settings: allocation failure at every save/load point cannot replace stored identities with a partial list; corrupt/duplicate records block writes");
}
