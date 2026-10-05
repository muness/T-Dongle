#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef struct ml_directory {
    char base[128];
    uint32_t generation, count;
    int bank;
    bool ready, session_valid;
    FILE *stage;
} ml_directory_t;
bool ml_directory_mount(void);
bool ml_directory_begin(microlink_t *ml);
bool ml_directory_stage(microlink_t *ml, unsigned group, const ml_peer_update_t *record);
bool ml_directory_commit(microlink_t *ml, bool authoritative);
void ml_directory_abort(microlink_t *ml);
bool ml_directory_find(microlink_t *ml, uint32_t ip, const uint8_t *key, const uint8_t *disco, uint64_t id, ml_peer_update_t *out);
bool ml_directory_at(microlink_t *ml, unsigned index, ml_peer_update_t *out);

typedef struct { uint32_t id, peer, alias; } ml_directory_alias_t;
bool ml_directory_alias_find(uint32_t id,uint32_t peer,uint32_t alias,ml_directory_alias_t *out);
bool ml_directory_alias_save(const ml_directory_alias_t *record);
/* Read-only walk of every valid record in file order (boot-time cache preload).
 * Returns false when the file cannot be read. Not for the forwarding path. */
bool ml_directory_alias_scan(void (*visit)(void *context, const ml_directory_alias_t *record), void *context);
