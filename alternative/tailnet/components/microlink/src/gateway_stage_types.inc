#include <limits.h>
#include "gateway_record.inc"
#define GATEWAY_STAGE_UPDATES (4 * ML_MAX_PEERS)
typedef struct {
#ifdef GATEWAY_FLASH_DIRECTORY
    ml_peer_update_t scratch;
#else
    ml_peer_update_t updates[GATEWAY_STAGE_UPDATES];
#endif
    unsigned char group[GATEWAY_STAGE_UPDATES];
    unsigned count, group_now, group_count[7], seen_fields;
    bool failed, authoritative, derp_present, expired, has_ip, has_name;
    uint32_t vpn_ip;
    char dns[128];
    ml_derp_region_t regions[ML_MAX_DERP_REGIONS];
    unsigned region_count;
    char record[4096];
    size_t record_used, total;
    unsigned capture_parent, kind;
    bool capture;
    gr_reader reader;
    void *reader_context;
    const char *failure;
} gateway_stage;
static gateway_stage *gateway_capture;
static ml_peer_update_t *gateway_peer_alloc(void) {
    if (!gateway_capture)
        return ml_psram_calloc(1, sizeof(ml_peer_update_t));
    gateway_stage *s = gateway_capture;
#ifdef GATEWAY_FLASH_DIRECTORY
    memset(&gateway_capture->scratch,0,sizeof(gateway_capture->scratch));
    return &gateway_capture->scratch;
#else
    if (s->count == GATEWAY_STAGE_UPDATES) {
        s->failed = true;
        return NULL;
    }
    unsigned n = s->count++;
    s->group[n] = s->group_now;
    memset(&s->updates[n], 0, sizeof(s->updates[n]));
    return &s->updates[n];
#endif
}
static bool gateway_peer_publish(microlink_t *ml, ml_peer_update_t **update) {
#ifdef GATEWAY_FLASH_DIRECTORY
    if (gateway_capture) {
        if ((!gateway_capture->count && !ml_directory_begin(ml)) || !ml_directory_stage(ml,gateway_capture->group_now,*update)) {
            gateway_capture->failed=true;
            gateway_capture->failure="Peer flash staging failed; previous directory retained";
            return true; /* scratch is not a heap allocation */
        }
        gateway_capture->count++;
        return true;
    }
#endif
    return gateway_capture || xQueueSend(ml->peer_update_queue, update,
                                         pdMS_TO_TICKS(100)) == pdTRUE;
}
