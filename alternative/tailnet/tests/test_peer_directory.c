#include "tdongle_memory.h"
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define ML_DIRECTORY_HOST_TEST 1
#define ROOT "/tmp/tdongle-directory-test"
#define ML_MAX_ENDPOINTS 8
#define MICROLINK_MAX_PEER_ROUTES 8
#define ML_MAX_DERP_NODES 2
#define ML_MAX_DERP_REGIONS 4
typedef struct {uint32_t network;uint8_t prefix_len;} microlink_route_t;
#include "semantic_types.inc"
typedef struct microlink_s microlink_t;
#include "ml_directory.h"
struct microlink_s {uint8_t wg_public_key[32];ml_directory_t directory;};
static int fail_write_after=-1;
static size_t checked_write(const void *p,size_t size,size_t count,FILE *f) {
    if(fail_write_after==0)return 0;
    if(fail_write_after>0)fail_write_after--;
    return fwrite(p,size,count,f);
}
#define fwrite checked_write
#include "../components/microlink/src/ml_directory.c"
#undef fwrite
#include <sys/stat.h>
static ml_peer_update_t peer(unsigned id) {
    ml_peer_update_t p={.action=ML_PEER_ADD,.vpn_ip=0x64400000+id,.has_node_id=true,.node_id=id,.endpoint_count=1};
    memcpy(p.public_key,&id,sizeof(id));p.disco_key[0]=id;p.endpoints[0].ip=id;
    snprintf(p.hostname,sizeof(p.hostname),"peer-%u",id);return p;
}
int main(void) {
    mkdir(ROOT,0700);microlink_t a={.wg_public_key={1}},b={.wg_public_key={2}};
    char name[160];prepare(&a);prepare(&b);
    for(unsigned i=0;i<2;i++) {path(&a.directory,name,i?".b":".a");unlink(name);path(&b.directory,name,i?".b":".a");unlink(name);}
    a.directory=(ml_directory_t){0};b.directory=(ml_directory_t){0};
    assert(ml_directory_begin(&a));
    for(unsigned i=1;i<=1000;i++) {ml_peer_update_t p=peer(i);assert(ml_directory_stage(&a,2,&p));}
    assert(ml_directory_commit(&a,true));assert(a.directory.count==1000);
    ml_peer_update_t out;assert(ml_directory_find(&a,0x644003e8,NULL,NULL,0,&out));assert(out.node_id==1000);
    /* Identical IP in independent membership cannot see A's directory. */
    assert(!ml_directory_find(&b,out.vpn_ip,NULL,NULL,0,&out));assert(ml_directory_begin(&b));
    ml_peer_update_t p=peer(1000);p.public_key[0]=77;assert(ml_directory_stage(&b,2,&p));assert(ml_directory_commit(&b,true));
    assert(ml_directory_find(&b,p.vpn_ip,NULL,NULL,0,&out));assert(out.public_key[0]==77);
    /* Incomplete transaction is never visible. */
    assert(ml_directory_begin(&a));p=peer(1001);assert(ml_directory_stage(&a,6,&p));ml_directory_abort(&a);
    assert(!ml_directory_find(&a,p.vpn_ip,NULL,NULL,0,&out));
    /* Removal, rotation, absent endpoints and explicit empty endpoints. */
    assert(ml_directory_begin(&a));p=peer(10);p.action=ML_PEER_REMOVE;assert(ml_directory_stage(&a,3,&p));
    p=peer(1000);p.action=ML_PEER_UPDATE_ENDPOINT;p.endpoint_count=-1;p.public_key[0]=99;
    assert(ml_directory_stage(&a,4,&p));assert(ml_directory_commit(&a,false));
    assert(!ml_directory_find(&a,0x6440000a,NULL,NULL,0,&out));
    assert(ml_directory_find(&a,0,NULL,NULL,1000,&out));assert(out.public_key[0]==99 && out.endpoint_count==1);
    assert(ml_directory_begin(&a));p.endpoint_count=0;assert(ml_directory_stage(&a,4,&p));assert(ml_directory_commit(&a,false));
    assert(ml_directory_find(&a,0,NULL,NULL,1000,&out));assert(out.endpoint_count==0);
    /* Reboot validates banks rather than trusting RAM pointers. */
    a.directory=(ml_directory_t){0};assert(ml_directory_find(&a,0,NULL,NULL,1000,&out));assert(out.endpoint_count==0);
    uint32_t gen=a.directory.generation;int bank=a.directory.bank;
    /* Tear newest generation; recovery selects previous complete generation. */
    FILE *f=open_bank(&a.directory,bank,"r+b");assert(f);assert(!fseek(f,-2,SEEK_END));fputc(123,f);fclose(f);
    a.directory=(ml_directory_t){0};assert(ml_directory_find(&a,0,NULL,NULL,1000,&out));assert(a.directory.generation==gen-1);assert(out.endpoint_count==1);
    /* Authoritative omission removes all prior records, not merely warm peers. */
    assert(ml_directory_begin(&a));p=peer(2000);assert(ml_directory_stage(&a,2,&p));assert(ml_directory_commit(&a,true));
    assert(!ml_directory_find(&a,0,NULL,NULL,1000,&out));assert(ml_directory_find(&a,p.vpn_ip,NULL,NULL,0,&out));
    uint32_t before=a.directory.generation;
    assert(ml_directory_begin(&a));p=peer(3000);assert(ml_directory_stage(&a,6,&p));
    fail_write_after=1;assert(!ml_directory_commit(&a,false));fail_write_after=-1;
    assert(a.directory.generation==before);assert(!ml_directory_find(&a,p.vpn_ip,NULL,NULL,0,&out));
    assert(ml_directory_find(&a,0,NULL,NULL,2000,&out));
    /* Alias persistence exceeds the old 64-entry cache and survives a torn tail. */
    unlink(ROOT "/aliases");
    for(unsigned i=1;i<=1000;i++) {ml_directory_alias_t alias={1,i,0xc6120000+i};assert(ml_directory_alias_save(&alias));}
    ml_directory_alias_t alias;
    assert(ml_directory_alias_find(1,1000,0,&alias));assert(alias.alias==0xc61203e8);
    FILE *tail=fopen(ROOT "/aliases","ab");assert(tail);fputc(1,tail);fclose(tail);
    alias=(ml_directory_alias_t){2,1000,0xc6130001};assert(ml_directory_alias_save(&alias));
    assert(ml_directory_alias_find(0,0,alias.alias,&alias));assert(alias.id==2);
    printf("peer directory: 1000 records, isolation, abort, delta/rotation, reboot and torn generation passed; record=%zu bytes\n",sizeof(p));
}
