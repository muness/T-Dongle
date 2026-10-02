#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define ESP_PARTITION_TYPE_DATA 1
#define ESP_PARTITION_SUBTYPE_DATA_FAT 2
#define ESP_OK 0
#define ROOT "/peers"
typedef struct {size_t size;} esp_partition_t;
typedef struct {bool format_if_mount_failed;unsigned max_files,allocation_unit_size;} esp_vfs_fat_mount_config_t;
static int directory_lock,directory_lock_storage,directory_wl;
static uint8_t disk[8192];static unsigned mounts,formats;static bool read_error,mount_bad;
static int xSemaphoreCreateMutexStatic(int *s){return 1;}
static void vTaskDelay(int ticks){}
static const esp_partition_t *esp_partition_find_first(int type,int subtype,const char *name){static esp_partition_t p={sizeof(disk)};return &p;}
static int esp_partition_read(const esp_partition_t *p,size_t at,void *out,size_t n){if(read_error)return -1;assert(at+n<=sizeof(disk));memcpy(out,disk+at,n);return 0;}
static int esp_vfs_fat_spiflash_mount_rw_wl(const char *root,const char *name,const esp_vfs_fat_mount_config_t *config,int *wl){mounts++;if(mount_bad){if(!config->format_if_mount_failed)return -1;formats++;}return 0;}
#include "directory_mount.inc"
int main(void) {
    memset(disk,255,sizeof(disk));mount_bad=true;
    assert(ml_directory_mount() && formats==1);
    disk[sizeof(disk)-1]=0; // Checking only a prefix would silently erase this existing store.
    assert(!ml_directory_mount() && formats==1);
    mount_bad=false;assert(ml_directory_mount() && formats==1);
    unsigned before=mounts;read_error=true;assert(!ml_directory_mount() && mounts==before);
    puts("Peer storage: only a completely blank partition may format; damaged existing data and flash-read errors never auto-format");
}
