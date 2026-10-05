#include "tdongle_memory.h"
#define _POSIX_C_SOURCE 200809L
#define GATEWAY_FLASH_DIRECTORY 1
#define main legacy_main
#include "test_semantic_map.c"
#undef main
#include <sys/stat.h>
static void consume_directory_batch(microlink_t *m) {
    assert(batch && !batch->count);release(batch);batch=NULL;m->map_batch_pending=false;allocations=0;
}
int main(void) {
    mkdir(ROOT,0700);microlink_t m={.wg_public_key={3}};
    prepare(&m);char pathbuf[160];
    for(unsigned i=0;i<2;i++){path(&m.directory,pathbuf,i?".b":".a");unlink(pathbuf);}
    m.directory=(ml_directory_t){0};reset();
    char *json=calloc(1,300000);strcpy(json,"{\"Peers\":[");size_t used=strlen(json);
    for(unsigned i=1;i<=1000;i++)used+=snprintf(json+used,300000-used,
        "%s{\"ID\":%u,\"Key\":\"nodekey:%064x\",\"Name\":\"peer-%u.example.ts.net\",\"Addresses\":[\"100.64.%u.%u/32\"]}",i>1?",":"",i,i,i,i/256,i%256);
    strcpy(json+used,"]}");assert(feed(&m,json));consume_directory_batch(&m);
    ml_peer_update_t out;assert(ml_directory_find(&m,0,NULL,NULL,1000,&out));assert(out.vpn_ip==0x644003e8);
    assert(m.directory.count==1000);
    /* Malformed tail cannot expose an already parsed replacement peer. */
    assert(!feed(&m,"{\"Peers\":[{\"ID\":2000,\"Key\":\"nodekey:0101010101010101010101010101010101010101010101010101010101010101\",\"Addresses\":[\"100.64.9.1/32\"]}],\"Bad\":}"));
    ml_directory_abort(&m);assert(!ml_directory_find(&m,0,NULL,NULL,2000,&out));assert(ml_directory_find(&m,0,NULL,NULL,1000,&out));
    /* More than eight removals is legitimate even with few warm peers. */
    assert(feed(&m,"{\"PeersRemoved\":[1,2,3,4,5,6,7,8,9,10,11,12] }"));consume_directory_batch(&m);
    assert(!ml_directory_find(&m,0,NULL,NULL,12,&out));assert(ml_directory_find(&m,0,NULL,NULL,1000,&out));
    assert(feed(&m,"{\"PeersChanged\":[{\"ID\":1000,\"Expired\":true}]}"));consume_directory_batch(&m);
    assert(!ml_directory_find(&m,0,NULL,NULL,1000,&out));
    free(json);puts("semantic flash map: 1000 peers, 12 removals, malformed rollback passed");
}
