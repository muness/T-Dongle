/* Bounded-RAM, two-generation flash directory. No persisted private keys.
 * A map is staged separately; only a checksummed, synced generation is published.
 * This module's lock protects FILE operations, not network/handshake work. */
#ifndef ML_DIRECTORY_HOST_TEST
#include "microlink_internal.h"
#include "esp_vfs_fat.h"
#include "wear_levelling.h"
#include "esp_partition.h"
#include <unistd.h>
static SemaphoreHandle_t directory_lock;
static StaticSemaphore_t directory_lock_storage;
static wl_handle_t directory_wl = WL_INVALID_HANDLE;
#define LOCK() xSemaphoreTake(directory_lock, portMAX_DELAY)
#define UNLOCK() xSemaphoreGive(directory_lock)
#define ROOT "/peers"
bool ml_directory_mount(void) {
    directory_lock = xSemaphoreCreateMutexStatic(&directory_lock_storage);
    const esp_partition_t *partition=esp_partition_find_first(ESP_PARTITION_TYPE_DATA,ESP_PARTITION_SUBTYPE_DATA_FAT,"peerstore");
    if(!partition)return false;
    /* Only a completely blank, never-used partition may be formatted. A bad
     * mount must not silently erase peer records or stable USB alias mappings. */
    bool blank=true;uint8_t bytes[256];
    for(size_t offset=0;blank && offset<partition->size;offset+=sizeof(bytes)) {
        size_t n=partition->size-offset;if(n>sizeof(bytes))n=sizeof(bytes);
        if(esp_partition_read(partition,offset,bytes,n)!=ESP_OK)return false;
        for(size_t i=0;i<n;i++)if(bytes[i]!=0xff){blank=false;break;}
        if(!(offset%16384))vTaskDelay(1);
    }
    esp_vfs_fat_mount_config_t config = {
        .format_if_mount_failed = blank, .max_files = 4,
        .allocation_unit_size = 4096};
    return esp_vfs_fat_spiflash_mount_rw_wl(ROOT, "peerstore", &config,
                                           &directory_wl) == ESP_OK;
}
#else
#include <unistd.h>
#define LOCK() ((void)0)
#define UNLOCK() ((void)0)
#endif
#include <string.h>
#include <stdlib.h>
#include <limits.h>
/* Native structs are a versioned local format, never a wire format. */
typedef struct { uint32_t magic, version, size, generation; } dir_header;
typedef struct { uint32_t group; ml_peer_update_t record; } dir_operation;
#define DIRECTORY_MAGIC 0x50445231u
#define DIRECTORY_VERSION 1u
static uint32_t crc_bytes(uint32_t crc, const void *data, size_t len) {
    const unsigned char *p = data;
    while (len--) {
        crc ^= *p++;
        for (unsigned b=0;b<8;b++) crc=(crc>>1)^(0xedb88320u & (0u-(crc&1u)));
    }
    return crc;
}
static void path(ml_directory_t *d, char *out, const char *suffix) {
    snprintf(out, 160, "%s%s", d->base, suffix);
}
static FILE *open_bank(ml_directory_t *d, int bank, const char *mode) {
    char name[160]; path(d,name,bank ? ".b" : ".a"); return fopen(name,mode);
}
static bool validate(FILE *f, uint32_t *generation, uint32_t *count) {
    if (!f) return false;
    dir_header h; uint32_t crc=~0u, stored;
    if (fread(&h,sizeof(h),1,f)!=1 || h.magic!=DIRECTORY_MAGIC ||
        h.version!=DIRECTORY_VERSION || h.size!=sizeof(ml_peer_update_t)) return false;
    if (fseek(f,0,SEEK_END)) return false;
    long n=ftell(f);
    if (n<(long)(sizeof(h)+4) || (n-sizeof(h)-4)%sizeof(ml_peer_update_t)) return false;
    *count=(n-sizeof(h)-4)/sizeof(ml_peer_update_t);
    rewind(f); unsigned char chunk[256]; size_t remaining=n-4;
    while(remaining) { size_t take=remaining<sizeof(chunk)?remaining:sizeof(chunk);
        if(fread(chunk,1,take,f)!=take)return false;
        crc=crc_bytes(crc,chunk,take); remaining-=take; }
    if(fread(&stored,4,1,f)!=1 || stored!=~crc)return false;
    *generation=h.generation; return true;
}
static bool prepare(microlink_t *ml) {
    ml_directory_t *d=&ml->directory;
    if(d->ready)return true;
    snprintf(d->base,sizeof(d->base),ROOT "/");
    size_t n=strlen(d->base);
    for(unsigned i=0;i<32;i++)snprintf(d->base+n+2*i,3,"%02x",ml->wg_public_key[i]);
    d->bank=-1;
    for(int bank=0;bank<2;bank++) {
        FILE *f=open_bank(d,bank,"rb"); uint32_t gen=0,count=0;
        bool good=validate(f,&gen,&count); if(f)fclose(f);
        if(good && (d->bank<0 || gen>d->generation)) {d->bank=bank;d->generation=gen;d->count=count;}
    }
    d->ready=true; return true;
}
void ml_directory_abort(microlink_t *ml) {
    LOCK(); if(ml->directory.stage) {
        fclose(ml->directory.stage);ml->directory.stage=NULL;
        char tx[160];path(&ml->directory,tx,".tx");unlink(tx);
    } UNLOCK();
}
bool ml_directory_begin(microlink_t *ml) {
    LOCK(); prepare(ml); ml_directory_t *d=&ml->directory;
    if(d->stage)fclose(d->stage);
    char name[160];path(d,name,".tx"); d->stage=fopen(name,"w+b");
    bool ok=d->stage!=NULL; UNLOCK(); return ok;
}
bool ml_directory_stage(microlink_t *ml,unsigned group,const ml_peer_update_t *record) {
    LOCK(); dir_operation op={.group=group,.record=*record};
    bool ok=ml->directory.stage && fwrite(&op,sizeof(op),1,ml->directory.stage)==1;
    UNLOCK();return ok;
}
static bool same(const ml_peer_update_t *a,const ml_peer_update_t *b) {
    return (a->has_node_id && b->has_node_id && a->node_id==b->node_id) ||
           (!b->has_node_id && !memcmp(a->public_key,b->public_key,32));
}
static bool apply(FILE *f,const ml_peer_update_t *u) {
    ml_peer_update_t old; long found=-1,empty=-1;
    if(fseek(f,sizeof(dir_header),SEEK_SET))return false;
    while(fread(&old,sizeof(old),1,f)==1) {
        long at=ftell(f)-sizeof(old);
        if(!old.vpn_ip) {if(empty<0)empty=at;continue;}
        if(same(&old,u)) {found=at;break;}
    }
    if(ferror(f))return false;
    if(u->action!=ML_PEER_ADD && found<0)return true;
    ml_peer_update_t value=*u;
    if(u->action==ML_PEER_REMOVE)memset(&value,0,sizeof(value));
    else if(u->action==ML_PEER_UPDATE_ENDPOINT) {
        value=old;
        static const uint8_t zero[32]={0};
        if(memcmp(u->public_key,zero,32))memcpy(value.public_key,u->public_key,32);
        if(memcmp(u->disco_key,zero,32))memcpy(value.disco_key,u->disco_key,32);
        if(u->endpoint_count>=0) {value.endpoint_count=u->endpoint_count;memcpy(value.endpoints,u->endpoints,sizeof(value.endpoints));}
        if(u->derp_region)value.derp_region=u->derp_region;
        if(u->has_online) {value.has_online=true;value.online=u->online;}
    }
    value.action=ML_PEER_ADD;
    long at=found>=0?found:empty;
    if(fseek(f,at>=0?at:0,at>=0?SEEK_SET:SEEK_END))return false;
    return fwrite(&value,sizeof(value),1,f)==1;
}
bool ml_directory_commit(microlink_t *ml,bool authoritative) {
    LOCK(); ml_directory_t *d=&ml->directory; FILE *out=NULL,*previous=NULL;
    bool ok=false; int next=d->bank==0?1:0;
    if(!d->stage || d->generation==UINT32_MAX)goto done;
    out=open_bank(d,next,"w+b"); if(!out)goto done;
    dir_header h={DIRECTORY_MAGIC,DIRECTORY_VERSION,sizeof(ml_peer_update_t),d->generation+1};
    if(fwrite(&h,sizeof(h),1,out)!=1)goto done;
    if(!authoritative && d->bank>=0) {
        previous=open_bank(d,d->bank,"rb");if(!previous)goto done;
        if(fseek(previous,sizeof(h),SEEK_SET))goto done;
        ml_peer_update_t record;
        for(uint32_t i=0;i<d->count;i++) {
            if(fread(&record,sizeof(record),1,previous)!=1)goto done;
            if(record.vpn_ip && fwrite(&record,sizeof(record),1,out)!=1)goto done;
        }
        fclose(previous);previous=NULL;
    }
    for(unsigned pass=0;pass<3;pass++) {
        rewind(d->stage); dir_operation op;
        while(fread(&op,sizeof(op),1,d->stage)==1) {
            if(authoritative && op.group==6)continue;
            unsigned order=op.record.action==ML_PEER_ADD?0:op.record.action==ML_PEER_REMOVE?1:2;
            if(pass==order) {
                if(authoritative && op.group==2 && op.record.action==ML_PEER_ADD) {
                    if(fseek(out,0,SEEK_END) || fwrite(&op.record,sizeof(op.record),1,out)!=1)goto done;
                } else if(!apply(out,&op.record))goto done;
            }
        }
        if(ferror(d->stage))goto done;
    }
    if(fflush(out) || fseek(out,0,SEEK_END))goto done;
    long size=ftell(out);if(size<(long)sizeof(h))goto done;
    uint32_t count=(size-sizeof(h))/sizeof(ml_peer_update_t),crc=~0u;
    rewind(out);unsigned char chunk[256];long remaining=size;
    while(remaining) {size_t take=remaining<(long)sizeof(chunk)?remaining:sizeof(chunk);
        if(fread(chunk,1,take,out)!=take)goto done;
        crc=crc_bytes(crc,chunk,take);remaining-=take;}
    crc=~crc;
    if(fseek(out,0,SEEK_END) || fwrite(&crc,4,1,out)!=1 || fflush(out) || fsync(fileno(out)))goto done;
    if(fclose(out)) {out=NULL;goto done;} out=NULL;
    d->bank=next;d->count=count;
    __atomic_store_n(&d->generation,h.generation,__ATOMIC_RELEASE);ok=true;
done:
    if(previous)fclose(previous);
    if(out)fclose(out);
    if(d->stage) {fclose(d->stage);d->stage=NULL;}
    char tx[160];path(d,tx,".tx");unlink(tx);
    if(ok && authoritative)d->session_valid=true;
    UNLOCK();return ok;
}
bool ml_directory_find(microlink_t *ml,uint32_t ip,const uint8_t *key,const uint8_t *disco,uint64_t id,ml_peer_update_t *out) {
    LOCK();prepare(ml);ml_directory_t *d=&ml->directory;
    FILE *f=d->bank<0?NULL:open_bank(d,d->bank,"rb");bool found=false;
    if(f && !fseek(f,sizeof(dir_header),SEEK_SET))
        for(uint32_t i=0;i<d->count && fread(out,sizeof(*out),1,f)==1;i++)
            if(out->vpn_ip && ((ip && out->vpn_ip==ip) || (id && out->node_id==id) ||
               (key && !memcmp(key,out->public_key,32)) || (disco && !memcmp(disco,out->disco_key,32)))) {found=true;break;}
    if(f)fclose(f);
    UNLOCK();return found;
}
bool ml_directory_at(microlink_t *ml,unsigned index,ml_peer_update_t *out) {
    LOCK();prepare(ml);ml_directory_t *d=&ml->directory;
    FILE *f=d->bank<0?NULL:open_bank(d,d->bank,"rb");bool ok=false;
    if(f && index<d->count && !fseek(f,sizeof(dir_header)+index*sizeof(*out),SEEK_SET))
        ok=fread(out,sizeof(*out),1,f)==1 && out->vpn_ip;
    if(f)fclose(f);
    UNLOCK();return ok;
}

bool ml_directory_alias_find(uint32_t id,uint32_t peer,uint32_t alias,ml_directory_alias_t *out) {
    LOCK(); FILE *f=fopen(ROOT "/aliases","rb");bool found=false;
    struct {ml_directory_alias_t record;uint32_t crc;} entry;
    while(f && fread(&entry,sizeof(entry),1,f)==1) {
        if(entry.crc!=~crc_bytes(~0u,&entry.record,sizeof(entry.record)))continue;
        if((alias && entry.record.alias==alias) || (!alias && entry.record.id==id && entry.record.peer==peer)) {
            *out=entry.record;found=true;break;
        }
    }
    if(f)fclose(f);
    UNLOCK();return found;
}
bool ml_directory_alias_scan(void (*visit)(void *context, const ml_directory_alias_t *record), void *context) {
    LOCK();FILE *f=fopen(ROOT "/aliases","rb");bool ok=f!=NULL;
    struct {ml_directory_alias_t record;uint32_t crc;} entry;
    while(f && fread(&entry,sizeof(entry),1,f)==1)
        if(entry.crc==~crc_bytes(~0u,&entry.record,sizeof(entry.record)))visit(context,&entry.record);
    if(f)fclose(f);
    UNLOCK();return ok;
}
bool ml_directory_alias_save(const ml_directory_alias_t *record) {
    LOCK();FILE *f=fopen(ROOT "/aliases","a+b");bool ok=false;
    struct {ml_directory_alias_t record;uint32_t crc;} entry={.record=*record};
    entry.crc=~crc_bytes(~0u,record,sizeof(*record));
    if(f && !fseek(f,0,SEEK_END)) {
        long n=ftell(f),whole=n-(n%sizeof(entry));
        if(n>=0 && !ftruncate(fileno(f),whole) && !fseek(f,whole,SEEK_SET))
            ok=fwrite(&entry,sizeof(entry),1,f)==1 && !fflush(f) && !fsync(fileno(f));
    }
    if(f && fclose(f))ok=false;
    UNLOCK();return ok;
}
