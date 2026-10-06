#include "esp_log.h"
#include "tdongle_temperature.h"
#include "tdongle_pm.h"
#include "tdongle_mode.h"
#include "tdongle_mode_store.h"
#include "tdongle_l2.h"
#include "tdongle_memory.h"
#include "cJSON.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_mac.h"
#include "usb_identity.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "gateway.h"
#include "ml_runtime.h"
#include "ml_admission.h"
#include "ml_wg_rx_budget.h"
#include "route_table.h"
#include "boot_health.h"
#include "lcd.h"
#include "lcd_view.h"
#include "socket_budget.h"
#include "clock_sync.h"
#include "esp_system.h"
#include "lwip/inet.h"
#include "lwip/tcpip.h"
#include "nvs_flash.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_net.h"
#include "usb_rx_budget.h"
#include "wifi_pin_budget.h"
#include "tcp_window_budget.h"
/* Tunnel-to-USB transmit ring (ADR 0015). Three full frames are permanent (3 x 1524 B, allocated once at USB start,
 * paid for by the two IN NTBs being 3,200 B rather than 6,400 B). On top of that the worker task adds elastic chunks
 * of TINYUSB_NET_TX_CHUNK_SLABS frames, up to GATEWAY_USB_TX_MAX_CHUNKS, while a burst needs them, and gives them back
 * when idle or when a membership is being admitted or negotiated (ml_negotiation.h). Cap: 3 + 10 x 2 = 23 frames, 35 KB.
 * Why 23: a burst of B bytes arriving at the Wi-Fi rate (about 20 Mbit/s) against the USB full-speed drain (about 7 Mbit/s)
 * leaves 65% of B queued, so C bytes of ring absorb B = C / 0.65: 23 frames = 35 KB absorb a 54 KB burst, about 38 TCP
 * segments, and a full ring is 40 ms of USB time, below TCP's 200 ms minimum timeout. The three permanent frames absorbed
 * 7 KB: the 180 drops in 15 s that motivated this. Tune from tx_dropped_full and tx_high_water_slabs. */
#define GATEWAY_USB_TX_BASE_FRAMES 3u
#define GATEWAY_USB_TX_MAX_CHUNKS 10u
#define GATEWAY_USB_TX_MAX_FRAMES (GATEWAY_USB_TX_BASE_FRAMES + GATEWAY_USB_TX_MAX_CHUNKS * TINYUSB_NET_TX_CHUNK_SLABS)
/* Growth keeps free internal heap above one negotiation peak plus the recovery reserve, and the largest free block above
 * the admission floor, before and after each chunk. Admission itself needs far more free heap than that (it reclaims
 * the elastic part first), but these two are what a join already in progress and HTTP/control recovery cannot do without. */
#define GATEWAY_USB_TX_FLOOR_FREE (ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES)
#define GATEWAY_USB_TX_FLOOR_LARGEST ML_ADM_LARGEST_BLOCK
#define GATEWAY_USB_TX_IDLE_MS 10000u
/* Reclaim for admission waits for chunks that still hold frames: a full ring drains at 875 B/ms (7 Mbit/s). */
#define GATEWAY_USB_TX_RECLAIM_WAIT_MS 150u
/* Boot-heap neutrality (ADR 0015): before the ring the IN NTBs held 2 x 6,400 B. The permanent ring, its
 * worker stack (1,536) and TCB (340) must fit in what the smaller NTBs gave back, plus 512 B. */
_Static_assert(CONFIG_TINYUSB_NCM_IN_NTB_BUFFS_COUNT * CONFIG_TINYUSB_NCM_IN_NTB_BUFF_MAX_SIZE +
               GATEWAY_USB_TX_BASE_FRAMES * TINYUSB_NET_TX_SLAB_BYTES + 1536 + 340 <= 2 * 6400 + 512,
               "permanent USB transmit buffering grew past the admission-margin budget");
_Static_assert(CONFIG_TINYUSB_NCM_IN_NTB_BUFF_MAX_SIZE >= 2 * (1518 + 4) + 64, "an IN NTB must hold two frames");
_Static_assert(GATEWAY_USB_TX_BASE_FRAMES >= 3, "the permanent ring must hold three full frames");
_Static_assert(GATEWAY_USB_TX_MAX_FRAMES >= 16 && GATEWAY_USB_TX_MAX_FRAMES <= 24, "elastic cap: 16 to 24 frames (ADR 0015)");
_Static_assert(GATEWAY_USB_TX_MAX_CHUNKS * TINYUSB_NET_TX_CHUNK_BYTES <= 32 * 1024, "the elastic part must stay within 32 KB");
_Static_assert(CONFIG_LWIP_UDP_RECVMBOX_SIZE <= ML_HB_PIN_BUFFERS, "a UDP socket mailbox can pin more Wi-Fi RX buffers than the heap budget allows (ml_heap_budget.h)");
/* The Wi-Fi TX pool is no longer held to the pin burst by its size: wifi_pin_budget.h counts the buffers in flight at the one place
 * they start and admits them to a band (paid for by the floor) or to the heap above the floor, so the pool can be the driver's
 * 16 (ADR 0022 amendment 2). What the pool must do is hold the band and fit the FIFO that follows it (asserted there). */
_Static_assert(CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM >= GATEWAY_WIFI_TX_BAND_MAX && CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM <= GW_WTX_RING,
               "the Wi-Fi TX pool must hold the TX band and fit the pin budget's FIFO (wifi_pin_budget.h)");
_Static_assert(GATEWAY_WIFI_TX_POOL == CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM, "the pin budget must follow the configured TX pool");
/* The transparent bridge's ring (ADR 0023). Same mechanism, same floors, no gate (there is no negotiation). Its heap is the tailnet's
 * 38 KB plus the ~68 KB the first membership would have taken, and the buffer it replaces held 32 frames permanently (the original
 * bridge's copy pool, 48,768 B), so the cap is the same 32 frames, of which only GATEWAY_BRIDGE_TX_BASE_FRAMES are permanent:
 * 8 x 1,524 B is two full NTBs of burst plus the frames in a worker wake-up. 32 slabs is also the most the ring can address. */
#define GATEWAY_BRIDGE_TX_BASE_FRAMES 8u
#define GATEWAY_BRIDGE_TX_MAX_CHUNKS 12u
#define GATEWAY_BRIDGE_TX_MAX_FRAMES (GATEWAY_BRIDGE_TX_BASE_FRAMES + GATEWAY_BRIDGE_TX_MAX_CHUNKS * TINYUSB_NET_TX_CHUNK_SLABS)
_Static_assert(GATEWAY_BRIDGE_TX_BASE_FRAMES >= 2 && GATEWAY_BRIDGE_TX_BASE_FRAMES <= TINYUSB_NET_TX_MAX_BASE_SLABS &&
               GATEWAY_BRIDGE_TX_MAX_CHUNKS <= TINYUSB_NET_TX_MAX_CHUNKS && GATEWAY_BRIDGE_TX_MAX_FRAMES == 32,
               "the bridge ring keeps the original bridge's 32 frames of capacity, within what the ring can address");
/* Boot-heap neutrality against the original bridge: its permanent buffering was 32 pool frames, its worker's stack and TCB. */
_Static_assert(GATEWAY_BRIDGE_TX_BASE_FRAMES * TINYUSB_NET_TX_SLAB_BYTES + 1536 + 340 +
               TDONGLE_L2_HOST_SLOTS * TDONGLE_L2_SLOT_BYTES + GATEWAY_BRIDGE_TASK_STACK + 340 <=
               32 * 1524 + 3072 + 340,   /* the original l2.c: 32 pool frames of 1,524 B, the 3,072 B stack of its worker, its TCB */
               "the bridge's permanent buffering (ring base, ring worker, host queue, forwarder) grew past what the original bridge held");
/* Bridge task scheme (gateway.h): the same core and the same constants as the tailnet mode, with the l2 forwarder where usb_routes is. */
_Static_assert(GATEWAY_TASK_BRIDGE_CORE == TINYUSB_DEFAULT_TASK_AFFINITY && GATEWAY_TASK_BRIDGE_CORE == GATEWAY_TASK_USB_TX_CORE &&
               GATEWAY_TASK_USB_TX_PRIO > GATEWAY_TASK_TINYUSB_PRIO && GATEWAY_TASK_TINYUSB_PRIO > GATEWAY_TASK_BRIDGE_PRIO &&
               GATEWAY_TASK_BRIDGE_PRIO > GATEWAY_TASK_USB_TX_WORK_PRIO,
               "bridge, core 1: usb_txq relay > TinyUSB > l2 forwarder > usb_txq heap work");
_Static_assert(GATEWAY_TASK_BRIDGE_PRIO == GATEWAY_TASK_USB_ROUTES_PRIO && GATEWAY_TASK_BRIDGE_CORE == GATEWAY_TASK_USB_ROUTES_CORE,
               "the bridge's forwarder takes usb_routes' place in the scheme: one set of constants for both modes");
_Static_assert(GATEWAY_TASK_BRIDGE_PRIO < 22, "the bridge's tasks stay below the IDF system tasks (esp_timer 22, ipc 24) and the Wi-Fi task (23)");
_Static_assert(GATEWAY_USB_TX_FLOOR_FREE == ML_HB_FLOOR, "the USB ring grows only above the one elastic floor");
_Static_assert(GATEWAY_USB_TX_FLOOR_FREE >= ML_ADM_RECOVERY_BYTES + ML_ADM_NEG_PEAK_BYTES,
               "growth must leave one negotiation peak and the recovery reserve");
_Static_assert(GATEWAY_USB_TX_FLOOR_LARGEST >= ML_ADM_LARGEST_BLOCK, "growth must keep the admission largest-block floor");
_Static_assert(GATEWAY_USB_TX_FLOOR_FREE == ML_WG_RX_JOIN_FLOOR_FREE && GATEWAY_USB_TX_FLOOR_FREE == 16384 + 13500,
               "the elastic buffers (USB ring growth, WireGuard receive queue during a join) leave the same recovery reserve and negotiation peak");
_Static_assert(3 * (GATEWAY_USB_TX_MAX_FRAMES * TINYUSB_NET_TX_SLAB_BYTES / 875) <= GATEWAY_USB_TX_RECLAIM_WAIT_MS,
               "reclaim must wait long enough to drain a full ring three times over at USB speed");
#include <ctype.h>
#include <strings.h>
#include <time.h>
membership_t *members;
esp_netif_t *usb_interface;
SemaphoreHandle_t members_lock;
static void usb_event(tinyusb_event_t *event, void *arg) {
    if (event->id == TINYUSB_EVENT_DETACHED) {
        extern void gateway_usb_detach(void);
        gateway_usb_detach();
        tinyusb_net_tx_ring_link_down();    /* frames queued for the host that left are stale: flush, release the PM lock */
    }
}
static bool online;
/* SNTP supervision: written by the manager task, read (word sized fields) by /status and the console. */
static gw_clock_t sntp_clock;
static tdongle_mode runtime_mode=TDONGLE_TAILNET_GATEWAY;
bool gateway_tailnet_mode(void){return runtime_mode==TDONGLE_TAILNET_GATEWAY;}
static volatile bool wifi_scan_pauses_reconnect;
static SemaphoreHandle_t wifi_scan_lock;
static bool route_storage_ok;
static bool settings_ok, wifi_ready;
static StaticSemaphore_t members_mutex, scan_mutex;
bool gateway_online(void) { return online; }
static uint32_t next_id = 1;
static nvs_handle_t store;
static nvs_handle_t diag_store;
static SemaphoreHandle_t diag_lock;
enum { DIAG_RING_MAGIC = 0x54444732, DIAG_RING_COUNT = 8 };
typedef struct {
    uint32_t uptime_ms, member_id, event, detail, state, map_attempts;
    uint32_t map_bytes, map_error, h2_error, h2_stream, heap_free, heap_largest;
    char reason[64], h2_debug[49];
    uint32_t stage, noise_error, noise_frame_bytes, reset_reason, wifi;
    uint32_t sockets_open, sockets_peak, socket_failures, socket_errno, socket_operation;
} gateway_diag_record_t;
typedef struct {
    uint32_t magic;
    uint8_t count, next;
    gateway_diag_record_t entries[DIAG_RING_COUNT];
} gateway_diag_ring_t;
/* Import the previous small journal on firmware update without erasing NVS. */
static void gateway_diag_load(gateway_diag_ring_t *ring) {
    memset(ring, 0, sizeof(*ring)); ring->magic = DIAG_RING_MAGIC;
    size_t length = sizeof(*ring);
    if (nvs_get_blob(diag_store, "events2", ring, &length) == ESP_OK &&
        length == sizeof(*ring) && ring->magic == DIAG_RING_MAGIC &&
        ring->count <= DIAG_RING_COUNT && ring->next < DIAG_RING_COUNT) return;
    memset(ring, 0, sizeof(*ring)); ring->magic = DIAG_RING_MAGIC;
    struct { uint32_t magic; uint8_t count, next; uint32_t entries[8][12]; } old;
    length = sizeof(old);
    if (nvs_get_blob(diag_store, "events", &old, &length) == ESP_OK &&
        length == sizeof(old) && old.magic == 0x54444731 && old.count <= 8 && old.next < 8) {
        ring->count = old.count; ring->next = old.next;
        for (unsigned i = 0; i < 8; i++) memcpy(&ring->entries[i], old.entries[i], sizeof(old.entries[i]));
    }
}
static void gateway_diag_write(const microlink_t *ml, uint32_t member_id,
                               uint32_t event, uint32_t detail) {
    if (!diag_lock || xSemaphoreTake(diag_lock, pdMS_TO_TICKS(20)) != pdTRUE) return;
    gateway_diag_ring_t *ring = malloc(sizeof(*ring));
    tdongle_memory_note(TDONGLE_MEMORY_OP_DIAG_WRITE,sizeof(*ring),ring==NULL);
    if (!ring) { xSemaphoreGive(diag_lock); return; }
    gateway_diag_load(ring);
    uint32_t uptime = (uint32_t)(esp_timer_get_time() / 1000);
    for (unsigned i = 0; event != GATEWAY_DIAG_BOOT && event != GATEWAY_DIAG_UPSTREAM && i < ring->count; i++) {
        gateway_diag_record_t *prev = &ring->entries[i];
        if (prev->member_id == member_id && prev->event == event &&
            prev->detail == detail && (uint32_t)(uptime - prev->uptime_ms) < 30000) {
            free(ring); xSemaphoreGive(diag_lock); return;
        }
    }
    gateway_socket_stats sockets = gateway_sockets_snapshot();
    gateway_diag_record_t *entry = &ring->entries[ring->next];
    *entry = (gateway_diag_record_t){
        .uptime_ms = uptime, .member_id = member_id, .event = event, .detail = detail,
        .state = ml ? ml->state : 0, .map_attempts = ml ? ml->map_attempts : 0,
        .map_bytes = ml ? ml->map_bytes : 0, .map_error = ml ? ml->map_error : 0,
        .h2_error = ml ? ml->map_h2_error : 0, .h2_stream = ml ? ml->map_h2_last_stream : 0,
        .stage = ml ? ml->control_stage : 0, .noise_error = ml ? ml->noise_error : 0,
        .noise_frame_bytes = ml ? ml->noise_frame_bytes : 0,
        .heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
        .heap_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
        .reset_reason = esp_reset_reason(), .wifi = online,
        .sockets_open = sockets.open, .sockets_peak = sockets.peak,
        .socket_failures = sockets.failures, .socket_errno = sockets.last_errno,
        .socket_operation = sockets.last_operation};
    if (ml) {
        strlcpy(entry->reason, ml->transport_error, sizeof(entry->reason));
        for (unsigned i=0; entry->reason[i]; i++)
            if (entry->reason[i] == '"' || entry->reason[i] == '\\' || (unsigned char)entry->reason[i] < 32)
                entry->reason[i] = ' ';
        strlcpy(entry->h2_debug, ml->h2_debug, sizeof(entry->h2_debug));
    }
    if(ml && ml->noise_error==5){
        uint32_t read[7]={uptime,member_id,ml->read_expected,ml->read_received,ml->read_elapsed_ms,ml->read_errno,(uint32_t)ml->read_tls_result};
        nvs_set_blob(diag_store,"last_read",read,sizeof(read));
    }
    ring->next = (ring->next + 1) % DIAG_RING_COUNT;
    if (ring->count < DIAG_RING_COUNT) ring->count++;
    if (nvs_set_blob(diag_store, "events2", ring, sizeof(*ring)) == ESP_OK)
        nvs_commit(diag_store);
    free(ring);
    xSemaphoreGive(diag_lock);
}
void gateway_diag_record(const microlink_t *ml, uint32_t event, uint32_t detail) {
    if (ml) gateway_diag_write(ml, ml->config.diagnostic_id, event, detail);
}
void gateway_diag_membership(uint32_t member_id, uint32_t event, uint32_t detail) {
    gateway_diag_write(NULL, member_id, event, detail);
}
static wifi_config_t wifi_config;
#include "core.h"
#include "wifi_policy.h"
#include "wifi_profiles.inc"
#include "wifi_link.inc"
#include "wifi_pins.inc"
#include "bridge_status.inc"
void gateway_bridge_status(void){if(!gateway_tailnet_mode())bridge_status_lines();}
#include "serial_setup.inc"

extern const char setup_html_start[] asm("_binary_setup_html_start");
extern const char setup_html_end[] asm("_binary_setup_html_end");
static bool save_members(void) {
    if(!settings_ok)return false;
    cJSON *root=cJSON_CreateObject(), *list=NULL;
    bool ok=root && (list=cJSON_AddArrayToObject(root,"members")) &&
        cJSON_AddNumberToObject(root,"next_id",next_id);
    for(membership_t *m=members;ok && m;m=m->next) {
        cJSON *j=cJSON_CreateObject();
        ok=j && cJSON_AddNumberToObject(j,"id",m->id) &&
            cJSON_AddStringToObject(j,"label",m->label) &&
            cJSON_AddStringToObject(j,"key",m->key) &&
            cJSON_AddBoolToObject(j,"enabled",m->enabled) && cJSON_AddItemToArray(list,j);
        if(!ok)cJSON_Delete(j);
    }
    char *json=ok?cJSON_PrintUnformatted(root):NULL;
    cJSON_Delete(root);
    if(!json)return false;
    bool fits=strlen(json)<16384;
    esp_err_t result=fits?nvs_set_str(store,"members",json):ESP_ERR_INVALID_SIZE;
    tdongle_heap_free(TDONGLE_OWNER_MAP,json);
    return result==ESP_OK && nvs_commit(store)==ESP_OK;
}
static void identify(membership_t *m) {
    snprintf(m->ns, sizeof(m->ns), "tn_%08lx", (unsigned long)m->id);
    snprintf(m->hostname, sizeof(m->hostname), "tdongle-%s-%lx", m->label,
             (unsigned long)m->id);
}
static bool load_members(void) {
    size_t n=0;esp_err_t result=nvs_get_str(store,"members",NULL,&n);
    if(result==ESP_ERR_NVS_NOT_FOUND)return true;
    if(result!=ESP_OK || n<2 || n>16384)return false;
    char *s=malloc(n);if(!s)return false;
    if(nvs_get_str(store,"members",s,&n)!=ESP_OK){free(s);return false;}
    cJSON *root=cJSON_Parse(s);free(s);
    if(!root)return false;
    cJSON *id=cJSON_GetObjectItem(root,"next_id"), *list=cJSON_GetObjectItem(root,"members");
    bool ok=cJSON_IsNumber(id) && id->valuedouble>=1 && id->valuedouble<UINT32_MAX &&
        id->valuedouble==(uint32_t)id->valuedouble && cJSON_IsArray(list);
    membership_t *loaded=NULL;
    cJSON *j;
    cJSON_ArrayForEach(j,list) {
        if(!ok)break;
        cJSON *label=cJSON_GetObjectItem(j,"label"),*key=cJSON_GetObjectItem(j,"key"),
              *mid=cJSON_GetObjectItem(j,"id"),*enabled=cJSON_GetObjectItem(j,"enabled");
        ok=cJSON_IsString(label) && label->valuestring[0] && strlen(label->valuestring)<=20 &&
           cJSON_IsString(key) && strlen(key->valuestring)<160 && cJSON_IsBool(enabled) &&
           cJSON_IsNumber(mid) && mid->valuedouble>=1 && mid->valuedouble<id->valuedouble &&
           mid->valuedouble==(uint32_t)mid->valuedouble;
        if(!ok)break;
        for(membership_t *m=loaded;m;m=m->next)
            if(m->id==(uint32_t)mid->valuedouble || !strcasecmp(m->label,label->valuestring))ok=false;
        if(!ok)break;
        membership_t *m=calloc(1,sizeof(*m));if(!m){ok=false;break;}
        m->id=(uint32_t)mid->valuedouble;strlcpy(m->label,label->valuestring,sizeof(m->label));
        strlcpy(m->key,key->valuestring,sizeof(m->key));m->enabled=cJSON_IsTrue(enabled);
        identify(m);m->next=loaded;loaded=m;
    }
    if(ok){members=loaded;next_id=(uint32_t)id->valuedouble;}
    else while(loaded){membership_t *next=loaded->next;memset(loaded,0,sizeof(*loaded));free(loaded);loaded=next;}
    cJSON_Delete(root);return ok;
}
static bool stop_member(membership_t *m) {
    extern void gateway_suspend(uint32_t id);
    gateway_suspend(m->id);
    if (!m->client)
        return true;
    microlink_stop(m->client);
    if (m->client->stop_incomplete) {
        strlcpy(m->error, "Shutdown is still running; retry after it finishes",
                sizeof(m->error));
        return false;
    }
    microlink_destroy(m->client);
    m->client = NULL;
    return true;
}
/* Admission (ADR 0013, N1.2). What it costs to add one more membership is derived from the sizes the compiler
 * knows and the constants measured on the board (ml_admission.h): the shared tasks' stacks are charged to the first
 * membership only, a membership's own start allocations and steady growth are charged to each, and exactly ONE
 * negotiation peak is reserved however many memberships there are, because negotiations are serialised by the
 * token (ml_negotiation.h). Shared registration/map byte buffers are static, not charged per member. The decision
 * inputs are all in /status. */
_Static_assert(GATEWAY_USB_RX_INFLIGHT_MAX >= ROUTE_QUEUE_DEPTH + ROUTE_HOLD_SLOTS + 4, "USB receive slots must leave room beyond what the router can hold");
_Static_assert(ROUTE_HEAP_RESERVE == ML_HB_FLOOR && ROUTE_HEAP_RESERVE >= ML_ADM_RECOVERY_BYTES, "the router queue must stop at the one elastic floor (ml_heap_budget.h)");
_Static_assert(GATEWAY_TASK_USB_ROUTES_CORE == ML_TASK_WG_MGR_CORE && GATEWAY_TASK_USB_ROUTES_PRIO > ML_TASK_WG_MGR_PRIO &&
               ML_TASK_WG_MGR_PRIO > ML_TASK_COORD_PRIO && ML_TASK_COORD_CORE == ML_TASK_WG_MGR_CORE,
               "core 1: usb_routes > wg_mgr > coord");
_Static_assert(ML_TASK_NET_IO_CORE == ML_TASK_DERP_TX_CORE && ML_TASK_NET_IO_PRIO > ML_TASK_DERP_TX_PRIO,
               "core 0: net_io > derp");
_Static_assert(GATEWAY_TASK_USB_TX_CORE == TINYUSB_DEFAULT_TASK_AFFINITY && GATEWAY_TASK_USB_TX_CORE == ML_TASK_WG_MGR_CORE &&
               GATEWAY_TASK_USB_TX_PRIO > GATEWAY_TASK_TINYUSB_PRIO && GATEWAY_TASK_TINYUSB_PRIO > GATEWAY_TASK_USB_ROUTES_PRIO &&
               GATEWAY_TASK_USB_ROUTES_PRIO > ML_TASK_WG_MGR_PRIO && GATEWAY_TASK_USB_TX_WORK_PRIO < ML_TASK_WG_MGR_PRIO &&
               GATEWAY_TASK_USB_TX_WORK_PRIO > ML_TASK_COORD_PRIO,
               "core 1: usb_txq relay > TinyUSB > usb_routes > wg_mgr > usb_txq heap work > coord");
_Static_assert(GATEWAY_TASK_USB_TX_PRIO < 22, "the USB tasks stay below the IDF system tasks (esp_timer 22, ipc 24)");
static size_t member_queue_bytes(void) {
    return ML_DERP_TX_QUEUE_DEPTH * sizeof(ml_derp_tx_item_t) +
           (ML_DISCO_RX_QUEUE_DEPTH + ML_WG_RX_QUEUE_DEPTH +
            ML_STUN_RX_QUEUE_DEPTH) * sizeof(ml_rx_packet_t) +
           ML_COORD_CMD_QUEUE_DEPTH * sizeof(ml_coord_cmd_t) +
           ML_PEER_UPDATE_QUEUE_DEPTH * sizeof(ml_peer_update_t *) + 6 * sizeof(StaticQueue_t);
}
static ml_adm_budget_t admission_budget(void) {
    ml_adm_sizes_t sizes = {
        .context = sizeof(microlink_t),
        .coord_stack = ML_TASK_COORD_STACK,
        .task_tcb = sizeof(StaticTask_t),
        .queues = member_queue_bytes(),
        .wg_device = ml_wg_device_bytes(),
        .wg_slot = ml_wg_slot_bytes(),
        .shared_stacks = ML_RT_SHARED_STACK_BYTES,
        .shared_tasks = ML_RT_TASK_COUNT,
        .route_queue_min = ROUTE_QUEUE_BYTES_MIN,
    };
    ml_adm_budget_t budget;
    ml_adm_budget(&sizes, ml_rt_start_bytes() == 0, &budget);   /* 0: the shared tasks are already running */
    return budget;
}
static size_t member_start_budget(void) { return admission_budget().required; }
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
static void admission_note(const membership_t *m, tdongle_admit_verdict verdict, size_t free_now,
                           size_t largest, unsigned active, const gateway_socket_stats *sockets) {
    tdongle_admission_record r = {(uint32_t)(esp_timer_get_time() / 1000), m->id, free_now, largest,
                                  member_start_budget(), sockets->open, CONFIG_LWIP_MAX_SOCKETS,
                                  active, verdict};
    tdongle_memory_admission_note(&r);
}
#else
#define admission_note(m, verdict, free_now, largest, active, sockets) ((void)0)
#endif
#if defined(CONFIG_TDONGLE_MEMORY_DIAGNOSTICS) && defined(CONFIG_TDONGLE_MEMORY_ADMISSION_OVERRIDE)
/* Diagnostics only: past the budget the guard floor is the sole admission rule, so the
 * cost of a further membership is measured instead of refused. */
/* "memory guard 0" disables the allocator guard; the override still never starts below this. */
enum { ADMISSION_OVERRIDE_MIN_FREE = 8192 };
static bool admission_override(const membership_t *m, size_t free_now) {
    return (int32_t)((uint32_t)(esp_timer_get_time() / 1000) - m->next_attempt_ms) >= 0 &&
           free_now >= (tdongle_heap_guard_floor() > ADMISSION_OVERRIDE_MIN_FREE ? tdongle_heap_guard_floor() : ADMISSION_OVERRIDE_MIN_FREE);
}
static void admission_failed(membership_t *m) {
    m->next_attempt_ms = (uint32_t)(esp_timer_get_time() / 1000) + 60000;
}
#else
#define admission_override(m, free_now) false
#define admission_failed(m) ((void)0)
#endif
static bool start_member_holding_token(membership_t *m);
static void start_member(membership_t *m) {
    if (!gateway_tailnet_mode() || !m->enabled || m->client || !online)
        return;
    if (!route_storage_ok) {
        strlcpy(m->error,
                "Routing storage is damaged; tailnet access is disabled",
                sizeof(m->error));
        gateway_diag_membership(m->id, GATEWAY_DIAG_START_BLOCKED, 1);
        return;
    }
    /* Start, Noise, registration, the initial map and the DERP TLS handshake are one negotiation at a time across
     * all memberships (ml_negotiation.h). The token is taken BEFORE the heap is measured: another membership's
     * negotiation moves free memory by its peak, so a reading taken beside it would lie. A busy token is a
     * retryable refusal, not a failure: the manager comes back in ten seconds. It is released on every path out
     * of here; the membership's control task takes it again for its own negotiation. */
    ml_neg_t *neg = ml_rt_negotiation();
    const uintptr_t key = ml_neg_key(m->id, ML_NEG_PHASE_START);
    if (!ml_neg_acquire(neg, key, ML_NEG_PRIO_START, ML_NEG_PHASE_START, 1500)) {
        strlcpy(m->error, "Waiting for another membership to finish joining", sizeof(m->error));
        gateway_diag_membership(m->id, GATEWAY_DIAG_START_BLOCKED, 4);
        return;
    }
    /* Handed over, not released and re-acquired: on success the control task (same phase-A key) already holds the token
     * and keeps it through its negotiation states, so no other membership can start in the gap between microlink_start
     * and the control task's first request. Every path that did not start a control task releases here, and
     * microlink_stop releases the key again as a backstop. */
    if (!start_member_holding_token(m))
        ml_neg_release(neg, key);
}
static bool start_member_holding_token(membership_t *m) {
    /* The token is held, so the USB transmit buffer's gate is closed and it will not grow: give back the elastic chunks
     * (waiting for those that still hold frames to drain) so the measurement below sees the heap admission is meant to see. */
    tinyusb_net_tx_elastic_reclaim(GATEWAY_USB_TX_RECLAIM_WAIT_MS);
    /* Reserve for parsed JSON, networking and recovery HTTP. Shared receive
     * buffers are static. Runtime peak sufficiency needs board qualification. */
    /* The WireGuard receive queue is elastic memory like the transmit ring: datagrams that wait in it at this instant (at most
     * ML_WG_RX_QUEUE_BYTES) are heap the next wg_mgr pass returns, and the token held here has already closed the queue's growth
     * (ml_wgrx_admit_gated), so they are counted as free. Without this a burst in flight during a second join could refuse it. */
    size_t free_now = heap_caps_get_free_size(MALLOC_CAP_INTERNAL) + ml_wgrx_queued(&ml_wgrx_budget);
    size_t largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
    unsigned active = 0;
    for (membership_t *other = members; other; other = other->next)
        if (other->client) active++;
    gateway_socket_stats sockets = gateway_sockets_snapshot();
    ml_adm_budget_t budget = admission_budget();
    ml_adm_verdict_t verdict = ml_adm_decide(&budget, free_now, largest);
    bool within_budget = verdict == ML_ADM_OK;
    if (!within_budget && !admission_override(m, free_now)) {
        strlcpy(m->error, "Not enough free memory to activate this membership",
                sizeof(m->error));
        admission_note(m, verdict == ML_ADM_REFUSED_BUDGET ? TDONGLE_ADMIT_REFUSED_BUDGET
                                                           : TDONGLE_ADMIT_REFUSED_LARGEST,
                       free_now, largest, active, &sockets);
        gateway_diag_membership(m->id, GATEWAY_DIAG_START_BLOCKED, 2);
        return false;
    }
    if (!gateway_socket_admit(CONFIG_LWIP_MAX_SOCKETS, active, sockets.open)) {
        strlcpy(m->error, "Socket capacity reserved for USB setup and DNS", sizeof(m->error));
        admission_note(m, TDONGLE_ADMIT_REFUSED_SOCKETS, free_now, largest, active, &sockets);
        gateway_diag_membership(m->id, GATEWAY_DIAG_START_BLOCKED, 3);
        return false;
    }
    admission_note(m, within_budget ? TDONGLE_ADMIT_OK : TDONGLE_ADMIT_OVERRIDE, free_now, largest,
                   active, &sockets);
    tdongle_memory_phase(m->id, TDONGLE_PHASE_START);
    gateway_diag_membership(m->id, GATEWAY_DIAG_START_ATTEMPT, 0);
    microlink_config_t config = {.identity_namespace = m->ns,
                                 .auth_key = m->key,
                                 .device_name = m->hostname,
                                 .enable_derp = true,
                                 .enable_stun = true,
                                 .enable_disco = true,
                                 .max_peers = 8,
                                 .diagnostic_id = m->id};
    m->start_heap_before=heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    m->client = microlink_init(&config);
    if (!m->client) {
        strlcpy(m->error, "Could not allocate or save this identity",
                sizeof(m->error));
        admission_note(m, TDONGLE_ADMIT_START_FAILED, heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                       heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL), active, &sockets);
        admission_failed(m);
        gateway_diag_membership(m->id, GATEWAY_DIAG_START_FAILED, 1);
        return false;
    }
    esp_err_t err = microlink_start(m->client);
    m->start_heap_after=heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (err != ESP_OK) {
        admission_note(m, TDONGLE_ADMIT_START_FAILED, heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                       heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL), active, &sockets);
        admission_failed(m);
        gateway_diag_record(m->client, GATEWAY_DIAG_START_FAILED, err);
        if (!stop_member(m)) {
            m->enabled = false;
            save_members();
            return false;
        }
        snprintf(m->error, sizeof(m->error), "Start failed: %s",
                 esp_err_to_name(err));
        return false;
    }
    m->error[0] = 0;
    return true;   /* started: the control task now owns the token (same key) */
}
bool gateway_display_state(lcd_state *s) {
    s->bridge=!gateway_tailnet_mode();
    s->wifi=online;s->recovery=gateway_boot_needs_attention();
    if(xSemaphoreTake(members_lock,pdMS_TO_TICKS(10))!=pdTRUE)return false;
    s->saved_wifi=wifi_saved.count!=0;
    gateway_dns_domains_refresh();
    for(membership_t *m=members;m;m=m->next){
        s->saved++;if(!m->enabled)continue;s->enabled++;
        microlink_t *c=m->client;
        if(m->error[0] || (c && c->last_error[0]))s->failed++;
        if(c && c->auth_url[0])s->login++;
        if(c && c->wg_netif && c->state==ML_STATE_CONNECTED && !c->key_expired &&
           !c->last_error[0] && c->directory.session_valid)s->ready++;
    }
    xSemaphoreGive(members_lock);return true;
}
static void manager(void *arg) {
    unsigned last_socket_failures = 0;
    bool last_online = !online;
    for (;;) {
        tdongle_temperature_sample();
        tdongle_memory_note(TDONGLE_MEMORY_OP_TICK,0,0);
        wifi_maintain();
        /* Before and outside members_lock: the clock never waits on a membership. */
        if (gw_clock_poll(&sntp_clock, esp_timer_get_time() / 1000, ml_derp_clock_valid(), online) == GW_CLOCK_RESTART) {
            ESP_LOGW("clock", "no time yet from SNTP: retrying with %s (restart %lu)",
                     gw_clock_server_name[sntp_clock.server], (unsigned long)sntp_clock.restarts);
            esp_sntp_stop();
            esp_sntp_setservername(0, gw_clock_server_name[sntp_clock.server]);
            esp_sntp_init();
        }
        if (last_online != online) {
            gateway_diag_membership(0, GATEWAY_DIAG_UPSTREAM, online);
            last_online = online;
        }
        gateway_socket_stats sockets = gateway_sockets_snapshot();
        if (sockets.failures != last_socket_failures) {
            gateway_diag_membership(0, GATEWAY_DIAG_SOCKET_FAILURE, sockets.last_errno);
            last_socket_failures = sockets.failures;
        }
        if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
            for (membership_t *m = members; m; m = m->next) {
                if(m->client && m->client->stop_incomplete && !stop_member(m)) continue;
                start_member(m);
                if (m->client && m->client->state == ML_STATE_CONNECTED &&
                    m->key[0]) {
                    memset(m->key, 0, sizeof(m->key));
                    if (!save_members())
                        strlcpy(m->error,
                                "Connected; provisioning-key cleanup could not "
                                "be saved",
                                sizeof(m->error));
                }
            }
            gateway_dns_domains_refresh();
            xSemaphoreGive(members_lock);
        }
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
/* Runs in the lwIP core-lock holder (tcpip task, WireGuard manager): it must never wait.
 * The frame is copied into the USB transmit ring and a worker hands it to TinyUSB; a full ring
 * drops the frame (counted), which TCP treats as loss. See docs/adr/0015-data-plane-io.md. */
/* The elastic transmit buffer's gate: growth is forbidden, and idle chunks are given back, while any membership holds the
 * negotiation token (a join's allocation peak, and the admission measurement that precedes it). */
static tdongle_pm_burst_t usb_tx_pm;
static void usb_tx_pm_begin(void *ctx) { (void)ctx; tdongle_pm_burst_begin(&usb_tx_pm); }
static void usb_tx_pm_end(void *ctx) { (void)ctx; tdongle_pm_burst_end(&usb_tx_pm); }
static bool usb_tx_gate(void *ctx) { (void)ctx; return ml_neg_busy(ml_rt_negotiation()); }
/* Token changed hands: wake the buffer's worker so it retires idle chunks now rather than at its next housekeeping. */
static void usb_tx_negotiation_changed(void *ctx) { (void)ctx; tinyusb_net_tx_elastic_kick(); }
static esp_err_t usb_tx(void *handle, void *buffer, size_t len) {
    rt_stat(RT_STAT_USB_TX);
    esp_err_t result = len > UINT16_MAX ? ESP_ERR_INVALID_SIZE : tinyusb_net_tx_ring_send(buffer, (uint16_t)len);
    if (result != ESP_OK)
        rt_stat(RT_STAT_USB_TX_ERR);
    return result;
}
static gateway_usb_rx_budget usb_rx_budget;
static void usb_free_rx(void *handle, void *buffer) {
    free(buffer);
    gateway_usb_rx_release(&usb_rx_budget);
}
static esp_err_t usb_rx(void *buffer, uint16_t len, void *ctx) {
    if(!gateway_tailnet_mode())return tdongle_l2_host(buffer,len);   /* TinyUSB task: copies into the bridge's queue and returns (ADR 0023) */
    if (!usb_interface) return ESP_ERR_INVALID_STATE;
    if (!gateway_usb_rx_admit(&usb_rx_budget, len, heap_caps_get_free_size(MALLOC_CAP_INTERNAL)))
        return ESP_ERR_NO_MEM;
    void *copy = malloc(len);
    if (!copy) {
        gateway_usb_rx_release(&usb_rx_budget);
        atomic_fetch_add_explicit(&usb_rx_budget.dropped_nomem, 1, memory_order_relaxed);
        return ESP_ERR_NO_MEM;
    }
    memcpy(copy, buffer, len);
    /* esp_netif frees the copy through usb_free_rx exactly once, on every path including errors. */
    return esp_netif_receive(usb_interface, copy, len, NULL);
}
static void wifi_event(void *arg, esp_event_base_t base, int32_t event,
                       void *data) {
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_START &&
        wifi_config.sta.ssid[0])
        wifi_rescan=true;
    if (base == WIFI_EVENT && event == WIFI_EVENT_STA_DISCONNECTED) {
        online = false;
        wifi_link_event_disconnected((const wifi_event_sta_disconnected_t *)data);
        if(!gateway_tailnet_mode())tdongle_l2_link(false);   /* first: nothing new is submitted, then the driver's cleared queues are accounted */
        wifi_pins_link_changed();
        if(!wifi_scan_pauses_reconnect && wifi_current>=0 && wifi_pinned.slot!=wifi_current)
            wifi_retry_after[wifi_current]=(uint32_t)(esp_timer_get_time()/1000)+60000;
        /* Worker rescans with backoff; never reconnect recursively here. */
    }
    if(base==WIFI_EVENT && event==WIFI_EVENT_STA_CONNECTED)wifi_link_event_connected();
    if(base==WIFI_EVENT && event==WIFI_EVENT_STA_CONNECTED)wifi_pins_link_changed();   /* both modes: the driver cleared its TX queues */
    if(base==WIFI_EVENT && event==WIFI_EVENT_STA_CONNECTED && !gateway_tailnet_mode()){online=true;tdongle_l2_link(true);}
    if (base == IP_EVENT && event == IP_EVENT_STA_GOT_IP) {
        online = true;
        wifi_pins_hook_rx();   /* no-op without a netif (bridge mode) */
    }
}
static esp_err_t json_reply(httpd_req_t *req, cJSON *j) {
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Out of memory");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_sendstr(req, s);
    tdongle_heap_free(TDONGLE_OWNER_MAP, s);
    return err;
}
static esp_err_t failure(httpd_req_t *req, const char *message) {
    cJSON *j = cJSON_CreateObject();
    cJSON_AddBoolToObject(j, "ok", false);
    cJSON_AddStringToObject(j, "error", message);
    httpd_resp_set_status(req, "400 Bad Request");
    return json_reply(req, j);
}
static bool local_request(httpd_req_t *req);
static void wifi_scan_resume(bool was_connected) {
    wifi_scan_pauses_reconnect = false;
    wifi_ap_record_t current = {0};
    if (wifi_config.sta.ssid[0] &&
        (!was_connected || esp_wifi_sta_get_ap_info(&current) != ESP_OK))
        wifi_rescan=true;
}
static esp_err_t wifi_scan(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                                   "USB access required");
    if (!wifi_ready) return failure(req, "Wi-Fi startup failed; saved diagnostics contain the reason");
    if (xSemaphoreTake(wifi_scan_lock, 0) != pdTRUE)
        return failure(req, "A Wi-Fi scan is already running");

    wifi_ap_record_t current = {0};
    bool connected = esp_wifi_sta_get_ap_info(&current) == ESP_OK;
    wifi_scan_pauses_reconnect = true;
    if (!connected) {
        /* Stop a failed saved-network reconnect loop so it cannot starve a scan. */
        esp_wifi_disconnect();
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    wifi_scan_config_t config = {
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .show_hidden = false,
        .scan_time.active = {.min = 100, .max = 250},
    };
    esp_err_t result = esp_wifi_scan_start(&config, true);
    if (result != ESP_OK) {
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return failure(req, result == ESP_ERR_WIFI_STATE
                                ? "Wi-Fi is still connecting. Wait a moment, then scan again."
                                : "The dongle could not scan for Wi-Fi. Try again.");
    }

    uint16_t total = 0;
    if (esp_wifi_scan_get_ap_num(&total) != ESP_OK) {
        esp_wifi_clear_ap_list();
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return failure(req, "The Wi-Fi scan finished without readable results. Try again.");
    }

    enum { WIFI_SCAN_RESULT_LIMIT = 12 };
    uint16_t count = total < WIFI_SCAN_RESULT_LIMIT ? total : WIFI_SCAN_RESULT_LIMIT;
    wifi_ap_record_t *records = count ? calloc(count, sizeof(*records)) : NULL;
    if (count && !records) {
        esp_wifi_clear_ap_list();
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return failure(req, "The dongle is low on memory. Try the scan again.");
    }
    if (count && esp_wifi_scan_get_ap_records(&count, records) != ESP_OK) {
        free(records);
        esp_wifi_clear_ap_list();
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return failure(req, "The Wi-Fi scan finished without readable results. Try again.");
    }
    if (!count)
        esp_wifi_clear_ap_list();

    cJSON *response = cJSON_CreateObject();
    cJSON *networks = cJSON_CreateArray();
    if (!response || !networks) {
        cJSON_Delete(response);
        cJSON_Delete(networks);
        free(records);
        wifi_scan_resume(connected);
        xSemaphoreGive(wifi_scan_lock);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Out of memory returning Wi-Fi scan");
    }
    bool attached = cJSON_AddItemToObject(response, "networks", networks);
    if (!attached) cJSON_Delete(networks);
    bool json_ok = attached && cJSON_AddBoolToObject(response, "ok", true) &&
                   cJSON_AddNumberToObject(response, "count", count) &&
                   cJSON_AddBoolToObject(response, "truncated", total > count);
    for (uint16_t i = 0; i < count; i++) {
        if (!json_ok)
            break;
        cJSON *network = cJSON_CreateObject();
        json_ok = network &&
                  cJSON_AddStringToObject(network, "ssid",
                                          (const char *)records[i].ssid) &&
                  cJSON_AddNumberToObject(network, "rssi", records[i].rssi) &&
                  cJSON_AddBoolToObject(network, "secure",
                                        records[i].authmode != WIFI_AUTH_OPEN) &&
                  cJSON_AddItemToArray(networks, network);
        if (!json_ok)
            cJSON_Delete(network);
    }
    free(records);
    wifi_scan_resume(connected);
    xSemaphoreGive(wifi_scan_lock);
    if (!json_ok) {
        cJSON_Delete(response);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Out of memory returning Wi-Fi scan");
    }
    return json_reply(req, response);
}
static bool usb_peer_address(const struct sockaddr *address, socklen_t length) {
    uint32_t ipv4;
    if (address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        ipv4 = ((const struct sockaddr_in *)address)->sin_addr.s_addr;
    } else if (address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        const uint8_t *bytes = (const uint8_t *)&((const struct sockaddr_in6 *)address)->sin6_addr;
        static const uint8_t mapped_prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (memcmp(bytes, mapped_prefix, sizeof(mapped_prefix))) return false;
        memcpy(&ipv4, bytes + 12, sizeof(ipv4));
    } else return false;
    return (ntohl(ipv4) & 0xffffff00) == 0xc0a84d00;
}
static bool local_request(httpd_req_t *req) {
    /* HTTPD uses a dual-stack socket: IPv4 clients may be IPv4-mapped IPv6. */
    struct sockaddr_storage peer = {0};
    socklen_t n = sizeof(peer);
    if (getpeername(httpd_req_to_sockfd(req), (struct sockaddr *)&peer, &n) != 0 ||
        !usb_peer_address((const struct sockaddr *)&peer, n)) return false;
    char host[64], origin[96];
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK)
        return false;
    if (strcmp(host, "192.168.77.1") && strcmp(host, "192.168.77.1:80"))
        return false;
    if (httpd_req_get_hdr_value_len(req, "Origin")) {
        if (httpd_req_get_hdr_value_str(req, "Origin", origin,
                                        sizeof(origin)) != ESP_OK)
            return false;
        if (strcmp(origin, "http://192.168.77.1") &&
            strcmp(origin, "http://192.168.77.1:80"))
            return false;
    }
    return true;
}
static esp_err_t diagnostics(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "USB access required");
    gateway_diag_ring_t *ring=calloc(1,sizeof(*ring));
    tdongle_memory_note(TDONGLE_MEMORY_OP_JOURNAL,sizeof(*ring),ring==NULL);
    if(!ring)return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"Out of memory reading journal");
    ring->magic=DIAG_RING_MAGIC;
    uint32_t last_read[7]={0};
    bool available = false;
    if (diag_lock && xSemaphoreTake(diag_lock, pdMS_TO_TICKS(100)) == pdTRUE) {
        gateway_diag_load(ring); available = true;
        size_t read_size=sizeof(last_read);
        if(nvs_get_blob(diag_store,"last_read",last_read,&read_size)!=ESP_OK || read_size!=sizeof(last_read))memset(last_read,0,sizeof(last_read));
        xSemaphoreGive(diag_lock);
    }
    httpd_resp_set_type(req, "application/json");
    char prefix[64];
    int prefix_len = snprintf(prefix, sizeof(prefix),
                              "{\"schema\":2,\"available\":%s,\"events\":[",
                              available ? "true" : "false");
    if (prefix_len < 0 || prefix_len >= sizeof(prefix) ||
        httpd_resp_send_chunk(req, prefix, prefix_len) != ESP_OK)
        {free(ring);return ESP_FAIL;}
    char row[1024];
    unsigned first = (ring->next + DIAG_RING_COUNT - ring->count) % DIAG_RING_COUNT;
    for (unsigned i = 0; i < ring->count; i++) {
        gateway_diag_record_t *e = &ring->entries[(first + i) % DIAG_RING_COUNT];
        int n = snprintf(row, sizeof(row),
            "%s{\"uptime_ms\":%lu,\"member_id\":%lu,\"event\":%lu,\"detail\":%lu,\"state\":%lu,\"map_attempts\":%lu,\"map_bytes\":%lu,\"map_error\":%lu,\"h2_error\":%lu,\"h2_stream\":%lu,\"free_memory\":%lu,\"largest_free_block\":%lu,\"control_stage\":%lu,\"noise_error\":%lu,\"noise_frame_bytes\":%lu,\"reset_reason\":%lu,\"wifi\":%lu,\"sockets_open\":%lu,\"sockets_peak\":%lu,\"socket_failures\":%lu,\"socket_errno\":%lu,\"socket_operation\":%lu,\"reason\":\"%s\",\"h2_debug\":\"%s\"}",
            i ? "," : "", (unsigned long)e->uptime_ms,
            (unsigned long)e->member_id, (unsigned long)e->event,
            (unsigned long)e->detail, (unsigned long)e->state,
            (unsigned long)e->map_attempts, (unsigned long)e->map_bytes,
            (unsigned long)e->map_error, (unsigned long)e->h2_error,
            (unsigned long)e->h2_stream, (unsigned long)e->heap_free,
            (unsigned long)e->heap_largest, (unsigned long)e->stage,
            (unsigned long)e->noise_error, (unsigned long)e->noise_frame_bytes,
            (unsigned long)e->reset_reason, (unsigned long)e->wifi,
            (unsigned long)e->sockets_open, (unsigned long)e->sockets_peak,
            (unsigned long)e->socket_failures, (unsigned long)e->socket_errno,
            (unsigned long)e->socket_operation, e->reason, e->h2_debug);
        if (n < 0 || n >= sizeof(row) || httpd_resp_send_chunk(req, row, n) != ESP_OK)
            {free(ring);return ESP_FAIL;}
    }
    free(ring);
    int read_len=snprintf(row,sizeof(row),"],\"last_read_failure\":{\"uptime_ms\":%lu,\"member_id\":%lu,\"expected\":%lu,\"received\":%lu,\"elapsed_ms\":%lu,\"errno\":%lu,\"tls_result\":%ld}}",(unsigned long)last_read[0],(unsigned long)last_read[1],(unsigned long)last_read[2],(unsigned long)last_read[3],(unsigned long)last_read[4],(unsigned long)last_read[5],(long)(int32_t)last_read[6]);
    esp_err_t ret = httpd_resp_send_chunk(req,row,read_len);
    if (ret != ESP_OK) return ret;
    return httpd_resp_send_chunk(req, NULL, 0);
}
static esp_err_t home(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(
            req, HTTPD_403_FORBIDDEN,
            "Open this page through USB Ethernet at 192.168.77.1");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Content-Security-Policy",
                       "default-src 'self'; script-src 'unsafe-inline'; "
                       "style-src 'unsafe-inline'; "
                       "connect-src 'self'; frame-ancestors 'none'");
    return httpd_resp_send(req, setup_html_start,
                           setup_html_end - setup_html_start);
}
/* The Wi-Fi power-save mode in force, for /status (set in start_wifi). -1: not readable. */
static int wifi_ps_mode(void) {
    wifi_ps_type_t t=WIFI_PS_MAX_MODEM;
    return esp_wifi_get_ps(&t)==ESP_OK?(int)t:-1;
}
#include "json_writer.inc"
#include "runtime_status.inc"
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
#include "memory_diagnostics.inc"
#endif
typedef struct {
    uint32_t id, state, vpn_ip;
    size_t start_heap_before, start_heap_after;
    bool enabled, has_client, routing_ready;
    char label[24], error[64], dns[128], login[384], protocol_error[64], h2_debug[49];
    unsigned control_stage;
    uint32_t derp_tls_failures, derp_tls_deferred;
    uint32_t derp_state, derp_stats[6];   /* link state; frames rx/tx, record timeouts, write stalls, drops, connects */
    unsigned control_key_auth;
    uint32_t diagnostics[21], stack_free[5];
    unsigned peers, directory_count, peer_offset, page_start;
    uint32_t jit[5];
    struct {
        char name[64];
        uint32_t address;
    } peer[ML_MAX_PEERS];
} status_member;
static int status_chunk(void *context, const char *bytes, size_t length) {
    return httpd_resp_send_chunk(context, bytes, length) == ESP_OK ? 0 : -1;
}
static esp_err_t status_busy(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Retry-After", "1");
    httpd_resp_set_status(req, "503 Service Unavailable");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(
        req,
        "{\"ok\":false,\"error\":\"Memberships are busy; retry shortly\"}");
}
static esp_err_t status(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                                   "USB access required");
    /* Allocate outside the lock, then re-count to tolerate add/remove races.
     * No member/client pointers escape the lifetime lock. */
    if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(20)) != pdTRUE)
        return status_busy(req);
    size_t capacity = 0;
    for (membership_t *m = members; m; m = m->next)
        capacity++;
    xSemaphoreGive(members_lock);
    if (capacity > SIZE_MAX / sizeof(status_member))
        return status_busy(req);
    status_member *snapshot =
        capacity ? calloc(capacity, sizeof(*snapshot)) : NULL;
    tdongle_memory_note(TDONGLE_MEMORY_OP_STATUS_SNAPSHOT,capacity*sizeof(*snapshot),capacity && !snapshot);
    if (capacity && !snapshot)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Out of memory taking setup snapshot");
    if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(20)) != pdTRUE) {
        free(snapshot);
        return status_busy(req);
    }
    gateway_dns_domains_refresh();
    unsigned peer_offset=0,peer_member=0;char query[64]={0},offset_text[16];
    if(httpd_req_get_url_query_str(req,query,sizeof(query))==ESP_OK &&
       httpd_query_key_value(query,"peer_offset",offset_text,sizeof(offset_text))==ESP_OK)
        peer_offset=strtoul(offset_text,NULL,10);
    if(httpd_query_key_value(query,"peer_member",offset_text,sizeof(offset_text))==ESP_OK)
        peer_member=strtoul(offset_text,NULL,10);
    if(peer_offset>100000)peer_offset=0;
    size_t count = 0;
    for (membership_t *m = members; m; m = m->next) {
        if (count == capacity) {
            xSemaphoreGive(members_lock);
            free(snapshot);
            return status_busy(req);
        }
        status_member *v = &snapshot[count++];
        v->id = m->id;
        v->enabled = m->enabled;
        v->start_heap_before = m->start_heap_before;
        v->start_heap_after = m->start_heap_after;
        strlcpy(v->label, m->label, sizeof(v->label));
        strlcpy(v->error, m->error, sizeof(v->error));
        microlink_t *c = m->client;
        if (!c)
            continue;
        v->has_client = true;
        v->state = c->state;
        v->vpn_ip = c->vpn_ip;
        v->routing_ready = m->enabled && c->wg_netif &&
                           c->state == ML_STATE_CONNECTED && !c->key_expired &&
                           !c->last_error[0] && c->directory.session_valid;
        ml_published_name_get(&c->self_dns_name, v->dns, sizeof(v->dns), NULL);
        strlcpy(v->login, c->auth_url, sizeof(v->login));
        strlcpy(v->protocol_error,
                c->last_error[0] ? c->last_error : c->transport_error,
                sizeof(v->protocol_error));
        strlcpy(v->h2_debug,c->h2_debug,sizeof(v->h2_debug));v->control_stage=c->control_stage;
        v->derp_tls_failures=c->derp.tls_verify_failures;v->derp_tls_deferred=c->derp.tls_deferred;v->control_key_auth=c->ctrl_key_auth;
        v->derp_state=c->derp.link.state;
        v->derp_stats[0]=c->derp.link.stats.frames_rx;v->derp_stats[1]=c->derp.link.stats.frames_tx;
        v->derp_stats[2]=c->derp.link.stats.rx_timeouts;v->derp_stats[3]=c->derp.link.stats.tx_stalls;
        v->derp_stats[4]=c->derp.link.stats.alloc_drops;v->derp_stats[5]=c->derp.link.stats.connects;
        v->diagnostics[0] = c->map_attempts;
        v->diagnostics[1] = c->map_failures;
        v->diagnostics[2] = c->map_error;
        v->diagnostics[3] = c->map_bytes;
        v->diagnostics[4] = c->map_declared_bytes;
        v->diagnostics[5] = c->map_projected_bytes;
        v->diagnostics[6] = c->map_heap_before;
        v->diagnostics[7] = c->map_heap_after;
        v->diagnostics[8] = c->map_largest_before;
        v->diagnostics[9] = c->map_stream_id;
        v->diagnostics[10] = c->map_frame_type;
        v->diagnostics[11] = c->noise_error;
        v->diagnostics[12] = c->noise_frame_bytes;
        v->diagnostics[13] = c->map_generation;
        v->diagnostics[14] = c->map_h2_error;
        v->diagnostics[15] = c->map_h2_last_stream;
        v->diagnostics[16]=c->read_expected;v->diagnostics[17]=c->read_received;
        v->diagnostics[18]=c->read_elapsed_ms;v->diagnostics[19]=c->read_errno;
        v->diagnostics[20]=(uint32_t)c->read_tls_result;
        /* net_io, derp_tx and wg_mgr are the shared tasks (the same headroom for every membership, see
         * shared_runtime.tasks); derp_rx has not existed since the I/O tasks were merged; coord is this one's. */
        bool shared = c->rt_attached;
        const TaskHandle_t none = (TaskHandle_t)0;
        TaskHandle_t tasks[5] = {shared ? ml_rt_task_handle(ML_RT_TASK_NET_IO) : none,
                                 shared ? ml_rt_task_handle(ML_RT_TASK_DERP) : none,
                                 none, c->coord_task,
                                 shared ? ml_rt_task_handle(ML_RT_TASK_WG_MGR) : none};
        for (unsigned t = 0; t < 5; t++) {
            v->stack_free[t]=UINT32_MAX;
            if (tasks[t] && !c->stop_incomplete)
                v->stack_free[t] = uxTaskGetStackHighWaterMark(tasks[t]);
        }
        uint32_t peer_generation=__atomic_load_n(&c->peer_generation,__ATOMIC_ACQUIRE);
        if(peer_generation&1){xSemaphoreGive(members_lock);free(snapshot);return status_busy(req);}
        uint32_t directory_generation=__atomic_load_n(&c->directory.generation,__ATOMIC_ACQUIRE);
        v->jit[0]=c->jit_hits;v->jit[1]=c->jit_misses;v->jit[2]=c->jit_evictions;
        v->jit[3]=c->jit_rejected;v->jit[4]=c->jit_dropped;
        v->directory_count=c->directory.count;v->page_start=peer_member==m->id?peer_offset:0;v->peer_offset=v->page_start;
        for(unsigned i=v->page_start;i<c->directory.count && v->peers<ML_MAX_PEERS;i++) {
            ml_peer_update_t record;
            if(!ml_directory_at(c,i,&record))continue;
            unsigned j=v->peers++;
            strlcpy(v->peer[j].name,record.hostname,sizeof(v->peer[j].name));
            v->peer[j].address=record.vpn_ip;
            v->peer_offset=i+1;
        }
        if(peer_generation!=__atomic_load_n(&c->peer_generation,__ATOMIC_ACQUIRE) || directory_generation!=__atomic_load_n(&c->directory.generation,__ATOMIC_ACQUIRE)){xSemaphoreGive(members_lock);free(snapshot);return status_busy(req);}
        for(unsigned j=0;j<v->peers;j++)v->peer[j].address=gateway_alias(m->id,v->peer[j].address);
    }
    char saved_ssids[8][33];unsigned saved_count=wifi_saved.count;
    for(unsigned i=0;i<saved_count;i++)strlcpy(saved_ssids[i],wifi_saved.profiles[i].ssid,33);
    xSemaphoreGive(members_lock);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    jw_writer writer = {.context = req, .sink = status_chunk};
    jw_writer *w = &writer;
    jw_raw(w, "{");
#define NUM(name, value)                                                       \
    do {                                                                       \
        jw_key(w, name);                                                       \
        jw_number(w, value);                                                   \
        jw_char(w, ',');                                                       \
    } while (0)
#define STR(name, value)                                                       \
    do {                                                                       \
        jw_key(w, name);                                                       \
        jw_string(w, value);                                                   \
        jw_char(w, ',');                                                       \
    } while (0)
#define BOOL(name, value)                                                      \
    do {                                                                       \
        jw_key(w, name);                                                       \
        jw_bool(w, value);                                                     \
        jw_char(w, ',');                                                       \
    } while (0)
    STR("firmware", GATEWAY_VERSION);
    STR("mode",tdongle_mode_name(runtime_mode));
    tdongle_temperature temperature=tdongle_temperature_snapshot();
    jw_raw(w,"\"chip_temperature\":{");
    BOOL("valid",temperature.valid);NUM("current_tenths_c",temperature.current_tenths);NUM("peak_tenths_c",temperature.peak_tenths);NUM("sampled_at_uptime_ms",temperature.sampled_at_ms);
    /* current is re-read every sample and moves in whole-degree steps; age_ms and samples show it is live. */
    NUM("samples",temperature.samples);NUM("changed_at_uptime_ms",temperature.changed_at_ms);NUM("step_tenths_c",TDONGLE_TEMPERATURE_STEP_TENTHS);
    jw_key(w,"age_ms");if(temperature.samples)jw_number(w,temperature.age_ms);else jw_raw(w,"null");jw_char(w,',');
    jw_key(w,"errors");jw_number(w,temperature.errors);jw_raw(w,"},");
    BOOL("recovery", gateway_boot_recovery());
    NUM("membership_start_budget", member_start_budget());
    NUM("membership_context_bytes", sizeof(microlink_t));
    status_shared_runtime(w);
    status_power(w);
    gateway_socket_stats sockets = gateway_sockets_snapshot();
    NUM("socket_limit", CONFIG_LWIP_MAX_SOCKETS);
    NUM("socket_recovery_reserve", GATEWAY_SOCKET_RECOVERY);
    NUM("sockets_open", sockets.open);
    NUM("sockets_peak", sockets.peak);
    NUM("socket_failures", sockets.failures);
    NUM("socket_last_errno", sockets.last_errno);
    NUM("socket_last_operation", sockets.last_operation);
    NUM("socket_last_at_ms", sockets.last_at_ms);
    NUM("reset_reason", esp_reset_reason());
    BOOL("wifi", online);
    {   /* Additive: RSSI, channel, PHY and disconnect counters, with no BSSID or SSID. Omitted whole if it cannot fit. */
        wifi_link_info link = wifi_link_read();
        char link_json[WIFI_LINK_JSON_MAX];
        if (wifi_link_json(link_json, sizeof(link_json), &link, &wifi_link_stats)) {
            jw_key(w, "wifi_link");
            jw_raw(w, link_json);
            jw_char(w, ',');
        }
    }
    {   /* The wall clock gates DERP (certificate validity): a clock that never arrives must be visible. */
        bool clock_valid=ml_derp_clock_valid();
        jw_raw(w,"\"clock\":{");
        STR("state",gw_clock_state(&sntp_clock,clock_valid,online));
        BOOL("valid",clock_valid);NUM("sntp_restarts",sntp_clock.restarts);
        NUM("retry_in_ms",sntp_clock.retry_in_ms);
        jw_key(w,"server");jw_string(w,gw_clock_server_name[sntp_clock.server%GW_CLOCK_SERVERS]);
        jw_raw(w,"},");
    }
    jw_raw(w,"\"saved_wifi\":[");
    for(unsigned i=0;i<saved_count;i++){if(i)jw_char(w,',');jw_string(w,saved_ssids[i]);}
    jw_raw(w,"],");

    BOOL("route_storage_ok", route_storage_ok);
    NUM("free_memory", esp_get_free_heap_size());
    NUM("largest_free_block",
        heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    NUM("minimum_free_memory",
        heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    {   /* ADR 0022: the one elastic floor and what was refused for it (each refusal a dropped packet, never silent). */
        jw_raw(w, "\"heap_budget\":{");
        NUM("floor", ML_HB_FLOOR);NUM("reserve", ML_HB_RESERVE);NUM("pin_buffers", ML_HB_PIN_BUFFERS);
        NUM("refused_usb_rx", atomic_load(&usb_rx_budget.dropped_heap));
        NUM("refused_pending", atomic_load(&ml_hb_refused[ML_HB_JIT]));
        NUM("refused_derp_tx", atomic_load(&ml_hb_refused[ML_HB_DERP_TX]));
        NUM("refused_rx_ctrl", atomic_load(&ml_hb_refused[ML_HB_RX_CTRL]));NUM("refused_derp_rx", atomic_load(&ml_hb_refused[ML_HB_DERP_RX]));
        jw_key(w, "refused_wg_copy");jw_number(w, atomic_load(&ml_hb_refused[ML_HB_WG_COPY]));
        jw_raw(w, "},");
    }
    {   /* ADR 0022 amendment 2: Wi-Fi driver buffers pinned by the data path, counted where they start. tx_stale and tx_unmatched say
         * whether the driver's tx-done callback can be trusted (both ~0); tx_refused_* and rx_dropped are the price of the floor. */
        jw_raw(w, "\"wifi_pins\":{");
        BOOL("installed", wifi_pins_installed);BOOL("tx_done_cb", wifi_pins_tx_done_ok);BOOL("rx_hooked", wifi_pins_rx_hooked);
        NUM("tx_pool", GATEWAY_WIFI_TX_POOL);NUM("band_total", GATEWAY_WIFI_BAND_TOTAL);NUM("tx_band_max", GATEWAY_WIFI_TX_BAND_MAX);NUM("rx_band_max", GATEWAY_WIFI_RX_BAND_MAX);
        NUM("tx_inflight", wifi_pins_tx_outstanding());NUM("tx_high_water", atomic_load(&wifi_pins.tx_high_water));
        NUM("tx_charged", atomic_load(&wifi_pins.tx_charged));NUM("tx_done", atomic_load(&wifi_pins.tx_done));
        NUM("tx_aborted", atomic_load(&wifi_pins.tx_aborted));NUM("tx_flushed", atomic_load(&wifi_pins.tx_flushed));
        NUM("tx_stale", atomic_load(&wifi_pins.tx_stale));NUM("tx_unmatched", atomic_load(&wifi_pins.tx_unmatched));
        NUM("tx_band_admits", atomic_load(&wifi_pins.tx_band));NUM("tx_elastic_admits", atomic_load(&wifi_pins.tx_elastic));
        NUM("tx_refused_pool", atomic_load(&wifi_pins.tx_refused_pool));NUM("tx_refused_heap", atomic_load(&wifi_pins.tx_refused_heap));
        NUM("rx_inflight", wifi_pins_rx_inflight());NUM("rx_high_water", atomic_load(&wifi_pins.rx_high_water));
        NUM("rx_band_admits", atomic_load(&wifi_pins.rx_band));NUM("rx_elastic_admits", atomic_load(&wifi_pins.rx_elastic));
        NUM("rx_released", atomic_load(&wifi_pins.rx_released));NUM("rx_unmatched", atomic_load(&wifi_pins.rx_unmatched));
        jw_key(w, "rx_dropped");jw_number(w, atomic_load(&wifi_pins.rx_dropped));
        jw_raw(w, "},");
    }
    jw_raw(w, "\"members\":[");
    const char *diagnostic_names[] = {
        "map_attempts",      "map_failures",       "map_error",
        "map_bytes",         "map_declared_bytes", "map_projected_bytes",
        "map_heap_before",   "map_heap_after",     "map_largest_before",
        "map_stream_id",     "map_frame_type",     "noise_error",
        "noise_frame_bytes", "map_generation", "h2_error", "h2_last_stream",
        "read_expected", "read_received", "read_elapsed_ms", "read_errno", "read_tls_result"};
    const char *stack_names[] = {"net_io", "derp_tx", "derp_rx", "coord",
                                 "wg_mgr"};
    for (size_t i = 0; i < count && !w->failed; i++) {
        status_member *v = &snapshot[i];
        if (i)
            jw_char(w, ',');
        jw_char(w, '{');
        NUM("id", v->id);
        NUM("start_heap_before", v->start_heap_before);
        NUM("start_heap_after", v->start_heap_after);
        STR("label", v->label);
        BOOL("enabled", v->enabled);
        STR("error", v->error);
        NUM("state", v->state);
        jw_key(w, "routing_ready");
        jw_bool(w, v->routing_ready);
        if (v->has_client) {
            jw_char(w, ',');
            if (v->vpn_ip) {
                char ip[16];
                microlink_ip_to_str(v->vpn_ip, ip);
                STR("tailnet_ip", ip);
            }
            if (v->dns[0])
                STR("tailnet_dns_name", v->dns);
            jw_raw(w, "\"map_diagnostics\":{");
            for (unsigned d = 0; d < sizeof(diagnostic_names) / sizeof(diagnostic_names[0]); d++) {
                if (d)
                    jw_char(w, ',');
                jw_key(w, diagnostic_names[d]);
                if(d==20){char value[24];snprintf(value,sizeof(value),"%ld",(long)(int32_t)v->diagnostics[d]);jw_raw(w,value);}else jw_number(w,v->diagnostics[d]);
            }
            jw_raw(w, "},\"stack_free_bytes\":{");
            for (unsigned t = 0; t < 5; t++) {
                if (t)
                    jw_char(w, ',');
                jw_key(w, stack_names[t]);
                if(v->stack_free[t]==UINT32_MAX)jw_raw(w,"null");else jw_number(w, v->stack_free[t]);
            }
            jw_raw(w, "},");
            STR("login_url", v->login);
            STR("protocol_error", v->protocol_error);
            STR("h2_debug", v->h2_debug);
            NUM("control_stage", v->control_stage);
            NUM("derp_tls_verify_failures",v->derp_tls_failures);NUM("derp_tls_deferred",v->derp_tls_deferred);
            jw_raw(w,"\"derp_link\":{");STR("state",ml_derp_link_state_name((ml_derp_link_state_t)v->derp_state));
            NUM("frames_rx",v->derp_stats[0]);NUM("frames_tx",v->derp_stats[1]);NUM("record_timeouts",v->derp_stats[2]);
            NUM("write_stalls",v->derp_stats[3]);NUM("alloc_drops",v->derp_stats[4]);jw_key(w,"connects");jw_number(w,v->derp_stats[5]);jw_raw(w,"},");
            NUM("control_key_auth",v->control_key_auth);
            NUM("jit_hits",v->jit[0]);NUM("jit_misses",v->jit[1]);NUM("jit_evictions",v->jit[2]);
            NUM("jit_rejected",v->jit[3]);NUM("jit_dropped",v->jit[4]);
            NUM("directory_records",v->directory_count);
            NUM("next_peer_offset",v->peer_offset);NUM("peer_page_start",v->page_start);
            jw_raw(w, "\"peers\":[");
            for (unsigned j = 0; j < v->peers && !w->failed; j++) {
                if (j)
                    jw_char(w, ',');
                jw_char(w, '{');
                STR("name", v->peer[j].name);
                char short_name[64], qualified[128], ip[16];
                strlcpy(short_name, v->peer[j].name, sizeof(short_name));
                char *dot = strchr(short_name, '.');
                if (dot)
                    *dot = 0;
                snprintf(qualified, sizeof(qualified), "%s.%s.tailnet",
                         short_name, v->label);
                STR("qualifiedName", qualified);
                microlink_ip_to_str(v->peer[j].address, ip);
                jw_key(w, "address");
                jw_string(w, ip);
                jw_char(w, '}');
            }
            jw_char(w, ']');
        }
        jw_char(w, '}');
    }
    jw_raw(w, "]}");
    bool ok = jw_flush(w);
    free(snapshot);
#undef NUM
#undef STR
#undef BOOL
    if (!ok)
        return ESP_FAIL;
    return httpd_resp_send_chunk(req, NULL, 0);
}
static esp_err_t command(httpd_req_t *req) {
    if (!local_request(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN,
                                   "USB access required");
    char type[64];
    if (httpd_req_get_hdr_value_str(req, "Content-Type", type, sizeof(type)) !=
            ESP_OK ||
        strcmp(type, "application/json"))
        return failure(req, "JSON required");
    if (req->content_len <= 0 || req->content_len > 1024)
        return failure(req, "Request is too large");
    char body[1025];
    size_t used = 0;
    while (used < req->content_len) {
        int n = httpd_req_recv(req, body + used, req->content_len - used);
        if (n <= 0)
            return failure(req, "Incomplete request");
        used += n;
    }
    body[used] = 0;
    cJSON *j = cJSON_Parse(body);
    if (!j)
        return failure(req, "Invalid JSON");
    const char *action = cJSON_GetStringValue(cJSON_GetObjectItem(j, "action"));
    const char *error = NULL;
    if (xSemaphoreTake(members_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        cJSON_Delete(j);
        return failure(req, "Memberships are busy; retry shortly");
    }
    if (!settings_ok || gateway_boot_recovery()) {
        error = "Recovery mode: settings are preserved. Use Restart services in the app after saving diagnostics.";
    } else if(action && !strcmp(action,"mode")){
        tdongle_mode selected;
        const char *value=cJSON_GetStringValue(cJSON_GetObjectItem(j,"mode"));
        if(!tdongle_mode_parse(value,&selected))error="Choose Wi-Fi bridge or tailnet gateway";
        else if(tdongle_mode_save(store,selected)!=ESP_OK)error="Mode could not be saved; current mode remains active";
        else {extern bool control_submit(const char *line);if(!control_submit("reboot"))error="Mode saved; restart the dongle to apply it";}
    } else if (action && !strcmp(action, "wifi")) {
        if(!wifi_ready){xSemaphoreGive(members_lock);cJSON_Delete(j);return failure(req,"Wi-Fi did not start; restart services after saving diagnostics");}
        const char *ssid = cJSON_GetStringValue(cJSON_GetObjectItem(j, "ssid")),
                   *password =
                       cJSON_GetStringValue(cJSON_GetObjectItem(j, "password"));
        if (!ssid || !password || !strlen(ssid) || strlen(ssid) > 32 ||
            strlen(password) > 63)
            error = "Enter a valid Wi-Fi name and password";
        else {
            if(!wifi_save_profile(ssid,password,false))error="Could not save Wi-Fi; at most eight networks can be saved";
        }
    } else if(action && !strcmp(action,"wifi_remove")) {
        const char *ssid=cJSON_GetStringValue(cJSON_GetObjectItem(j,"ssid"));
        if(!ssid || !wifi_save_profile(ssid,"",true))error="Could not remove that saved network";
    } else if (action && !strcmp(action, "add")) {
        const char *label =
                       cJSON_GetStringValue(cJSON_GetObjectItem(j, "label")),
                   *key = cJSON_GetStringValue(cJSON_GetObjectItem(j, "key"));
        if (!key)
            key = "";
        if (!label || !strlen(label) || strlen(label) > 20 ||
            strlen(key) >= 160)
            error = "Use a short label and valid auth key";
        else {
            for (const char *s = label; *s; s++)
                if (!isalnum((unsigned char)*s) && *s != '-')
                    error = "Labels use letters, numbers and hyphens";
            for (membership_t *m = members; m; m = m->next)
                if (!strcasecmp(m->label, label))
                    error = "That label is already saved";
        }
        if (!error) {
            membership_t *m = calloc(1, sizeof(*m));
            if (!m || !next_id || next_id == UINT32_MAX) {
                free(m);
                error = "Cannot allocate another membership";
            } else {
                m->id = next_id++;
                strlcpy(m->label, label, sizeof(m->label));
                strlcpy(m->key, key, sizeof(m->key));
                m->enabled = true;
                identify(m);
                m->next = members;
                members = m;
                if (!save_members()) {
                    members = m->next;
                    next_id--;
                    free(m);
                    error = "Membership could not be saved";
                }
            }
        }
    } else if (action &&
               (!strcmp(action, "remove") || !strcmp(action, "enable"))) {
        cJSON *id = cJSON_GetObjectItem(j, "id");
        membership_t **link = &members;
        while (*link && (!cJSON_IsNumber(id) || (*link)->id != id->valuedouble))
            link = &(*link)->next;
        membership_t *m = *link;
        if (!m)
            error = "Membership not found";
        else if (!strcmp(action, "enable")) {
            bool old = m->enabled;
            m->enabled = cJSON_IsTrue(cJSON_GetObjectItem(j, "enabled"));
            if (!save_members()) {
                m->enabled = old;
                error = "Change could not be saved";
            } else if (!m->enabled && m->client) {
                if (!stop_member(m))
                    error = "Disconnect is still finishing; retry shortly";
                else
                    m->error[0] = 0;
            }
        } else {
            m->enabled = false;
            if (!stop_member(m)) {
                save_members();
                error = "Removal is waiting for shutdown; retry shortly";
            } else {
                *link = m->next;
                if (!save_members()) {
                    *link = m;
                    error = "Removal could not be saved";
                } else {
                    gateway_forget(m->id);
                    nvs_handle_t identity;
                    esp_err_t erase = nvs_open(m->ns, NVS_READWRITE, &identity);
                    if (erase == ESP_OK) {
                        erase = nvs_erase_all(identity);
                        if (erase == ESP_OK)
                            erase = nvs_commit(identity);
                        nvs_close(identity);
                    }
                    if (erase != ESP_OK)
                        error = "Membership removed, but stored identity "
                                "cleanup failed";
                    memset(m->key, 0, sizeof(m->key));
                    free(m);
                }
            }
        }
    } else
        error = "Unknown action";
    gateway_dns_domains_refresh();
    xSemaphoreGive(members_lock);
    cJSON_Delete(j);
    memset(body, 0, sizeof(body));
    if (error)
        return failure(req, error);
    cJSON *ok = cJSON_CreateObject();
    cJSON_AddBoolToObject(ok, "ok", true);
    return json_reply(req, ok);
}
/* Recovery endpoints never depend on a successful tailnet/Wi-Fi startup. */
static esp_err_t boot_status(httpd_req_t *req) {
    if(!local_request(req))return httpd_resp_send_err(req,HTTPD_403_FORBIDDEN,"USB access required");
    httpd_resp_set_type(req,"application/json");
    httpd_resp_set_hdr(req,"Cache-Control","no-store");
    if(gateway_boot_report(req,status_chunk))return ESP_FAIL;
    return httpd_resp_send_chunk(req,NULL,0);
}
#define START_TRY(call) do {esp_err_t result_=(call);if(result_!=ESP_OK)return result_;}while(0)
static esp_err_t start_usb(void) {
    static char serial[13];
    uint8_t identity_mac[6];
    esp_read_mac(identity_mac, ESP_MAC_WIFI_STA);
    snprintf(serial, sizeof(serial), "%02X%02X%02X%02X%02X%02X",
             identity_mac[0], identity_mac[1], identity_mac[2], identity_mac[3],
             identity_mac[4], identity_mac[5]);
    static const char language[] = {0x09, 0x04};
    static const char *strings[] = {language,
                                    "T-Dongle Adapter Project",
                                    "T-Dongle-S3 tailnet gateway",
                                    serial,
                                    "Management",
                                    "USB network",
                                    ""};
    tinyusb_config_t usb = TINYUSB_DEFAULT_CONFIG();
    usb.task.priority = GATEWAY_TASK_TINYUSB_PRIO;   /* both modes (ADR 0022, 0023): the IN pipe must not wait behind forwarding work */
    usb.event_cb = usb_event;
    usb.descriptor.string = strings;
    usb.descriptor.string_count = sizeof(strings) / sizeof(strings[0]);
    esp_err_t result=tinyusb_driver_install(&usb);
    if(result!=ESP_OK)return result;
    /* No free_tx_buffer: every frame to the host goes through the transmit ring, which copies it and owns the copy. */
    tinyusb_net_config_t net = {.on_recv_callback = usb_rx};
    if(gateway_tailnet_mode()){uint8_t device[6];gateway_usb_macs(identity_mac,device,net.mac_addr);}
    else memcpy(net.mac_addr, identity_mac, 6);
    result=tinyusb_net_init(&net);
    if(result==ESP_OK){
        const bool tailnet=gateway_tailnet_mode();
        const tinyusb_net_tx_config_t tx = {.base_frames = tailnet?GATEWAY_USB_TX_BASE_FRAMES:GATEWAY_BRIDGE_TX_BASE_FRAMES,
                                            .max_chunks = tailnet?GATEWAY_USB_TX_MAX_CHUNKS:GATEWAY_BRIDGE_TX_MAX_CHUNKS,
                                            .priority = GATEWAY_TASK_USB_TX_PRIO, .work_priority = GATEWAY_TASK_USB_TX_WORK_PRIO, .core = GATEWAY_TASK_USB_TX_CORE,
                                            .floor_free = GATEWAY_USB_TX_FLOOR_FREE, .floor_largest = GATEWAY_USB_TX_FLOOR_LARGEST,
                                            .idle_ms = GATEWAY_USB_TX_IDLE_MS, .gate = tailnet?usb_tx_gate:NULL,   /* the bridge has no negotiation to yield to */
                                            .pm_begin = usb_tx_pm_begin, .pm_end = usb_tx_pm_end};
        tdongle_pm_burst_register(&usb_tx_pm, "usb_txq");   /* ADR 0016: one CPU-max hold mechanism, worker-only begin/end */
        /* The shared runtime's state is built on first use; do that here, before the worker (1,536 B of stack) can ask the gate. */
        ml_neg_t *neg=tailnet?ml_rt_negotiation():NULL;
        result=tinyusb_net_tx_ring_start(&tx);
        if(result==ESP_OK && neg)ml_neg_set_observer(neg,usb_tx_negotiation_changed,NULL);
    }
    extern esp_err_t gateway_console_start(void);
    esp_err_t console=gateway_console_start();
    return console!=ESP_OK?console:result;

}
static esp_err_t start_network(void) {
    START_TRY(esp_netif_init());
    START_TRY(esp_event_loop_create_default());
    if(!gateway_tailnet_mode())return ESP_OK;
    esp_netif_ip_info_t ip = {0};
    IP4_ADDR(&ip.ip, 192, 168, 77, 1);
    ip.gw = ip.ip;
    IP4_ADDR(&ip.netmask, 255, 255, 255, 0);
    esp_netif_inherent_config_t base = ESP_NETIF_INHERENT_DEFAULT_ETH();
    base.flags = ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP;
    base.ip_info = &ip;
    base.if_key = "USB";
    base.if_desc = "usb";
    base.route_prio = 0;
    esp_netif_driver_ifconfig_t driver = {.handle = &usb_interface,
                                          .transmit = usb_tx,
                                          .driver_free_rx_buffer = usb_free_rx};
    esp_netif_config_t config = {.base = &base,
                                 .driver = &driver,
                                 .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH};
    usb_interface = esp_netif_new(&config);
    if(!usb_interface)return ESP_ERR_NO_MEM;
    uint8_t station[6], mac[6], host[6];
    START_TRY(esp_read_mac(station, ESP_MAC_WIFI_STA));
    gateway_usb_macs(station, mac, host);
    START_TRY(esp_netif_set_mac(usb_interface, mac));
    esp_netif_dns_info_t dns = {0};
    IP_SET_TYPE_VAL(dns.ip, IPADDR_TYPE_V4);
    IP4_ADDR(ip_2_ip4(&dns.ip), 192, 168, 77, 1);
    START_TRY(
        esp_netif_set_dns_info(usb_interface, ESP_NETIF_DNS_MAIN, &dns));
    uint8_t offer = 1;
    START_TRY(esp_netif_dhcps_option(usb_interface, ESP_NETIF_OP_SET,
                                           ESP_NETIF_DOMAIN_NAME_SERVER, &offer,
                                           sizeof(offer)));
    esp_netif_action_start(usb_interface, NULL, 0, NULL);
    esp_netif_action_connected(usb_interface, NULL, 0, NULL);

    return ESP_OK;
}
static esp_err_t start_http(void) {
    httpd_config_t http = HTTPD_DEFAULT_CONFIG();
    http.stack_size = 6144;
    http.max_uri_handlers = 6;
    http.max_open_sockets = 2;
    http.lru_purge_enable = true;
    http.recv_wait_timeout = http.send_wait_timeout = 2;
    httpd_handle_t server;
    START_TRY(httpd_start(&server, &http));
    httpd_uri_t page = {.uri = "/", .method = HTTP_GET, .handler = home},
                state = {.uri = "/status",
                         .method = HTTP_GET,
                         .handler = status},
                diag = {.uri = "/diagnostics",
                        .method = HTTP_GET,
                        .handler = diagnostics},
                scan = {.uri = "/wifi-scan",
                        .method = HTTP_GET,
                        .handler = wifi_scan},
                api = {
                    .uri = "/command", .method = HTTP_POST, .handler = command};
    httpd_uri_t boot = {.uri="/boot-status",.method=HTTP_GET,.handler=boot_status};
    const httpd_uri_t *handlers[]={&page,&state,&diag,&scan,&api,&boot};
    for(unsigned i=0;i<sizeof(handlers)/sizeof(handlers[0]);i++) {
        esp_err_t result=httpd_register_uri_handler(server,handlers[i]);
        if(result!=ESP_OK){httpd_stop(server);return result;}
    }
    return ESP_OK;

}
static esp_err_t start_settings(void) {
    START_TRY(nvs_flash_init()); /* Never erase identities on a storage error. */
    gateway_boot_storage();
    START_TRY(nvs_open("tn_settings",NVS_READWRITE,&store));
    if(nvs_open("tn_diag",NVS_READWRITE,&diag_store)==ESP_OK)diag_lock=xSemaphoreCreateMutex();
    if(!load_members())return ESP_ERR_INVALID_STATE;
    size_t n=sizeof(wifi_config);
    esp_err_t result=nvs_get_blob(store,"wifi",&wifi_config,&n);
    if(result!=ESP_ERR_NVS_NOT_FOUND && (result!=ESP_OK || n!=sizeof(wifi_config)))return ESP_ERR_INVALID_STATE;
    if(!wifi_load_profiles())return ESP_ERR_INVALID_STATE;
    START_TRY(tdongle_mode_load(store,&runtime_mode));
    settings_ok=true;
    gateway_diag_membership(0,GATEWAY_DIAG_BOOT,esp_reset_reason());
    return ESP_OK;
}
static esp_err_t start_directory(void) {return ml_directory_mount()?ESP_OK:ESP_FAIL;}
static esp_err_t start_routes(void) {
    extern bool gateway_routes_init(void);
    route_storage_ok=gateway_routes_init();return route_storage_ok?ESP_OK:ESP_FAIL;
}
/* No Wi-Fi modem sleep. The IDF default (WIFI_PS_MIN_MODEM) wakes for every DTIM beacon and parks frames at the
 * access point between them: measured on the board 2026-10-05 it added about 80 ms to the median round trip (ping
 * p50 126 ms against 48 ms with power save off) and changed throughput not at all. The original bridge does the
 * same (main/bridge.c). It costs radio idle current, not CPU frequency: DFS and modem sleep are independent here
 * (light sleep is off). Failure is not fatal: the link works, only slower to answer. */
static void wifi_power_save_off(void) {
    esp_err_t e=esp_wifi_set_ps(WIFI_PS_NONE);
    if(e!=ESP_OK)ESP_LOGW("wifi","esp_wifi_set_ps(NONE) failed: %s; modem sleep stays on",esp_err_to_name(e));
}
static esp_err_t start_wifi(void) {
    esp_netif_t *sta=NULL;   /* the transparent bridge has no STA netif: frames go through the bridge, not lwIP */
    if(gateway_tailnet_mode()){
        sta=esp_netif_create_default_wifi_sta();
        if(!sta)return ESP_ERR_NO_MEM;
    }
    wifi_pins_install(sta);   /* ADR 0022 amendment 2, ADR 0023: count and bound the driver TX buffers in both modes (RX too with a netif), before Wi-Fi runs */
    if(!gateway_tailnet_mode()){
        uint8_t mac[6];esp_read_mac(mac,ESP_MAC_WIFI_STA);
        const tdongle_l2_config_t bridge={.wifi_tx=wifi_pins_tx,.task_priority=GATEWAY_TASK_BRIDGE_PRIO,.task_core=GATEWAY_TASK_BRIDGE_CORE,.task_stack=GATEWAY_BRIDGE_TASK_STACK};
        START_TRY(tdongle_l2_start(mac,&bridge));
    }
    wifi_init_config_t w=WIFI_INIT_CONFIG_DEFAULT();
    START_TRY(esp_wifi_init(&w));
    START_TRY(esp_event_handler_register(WIFI_EVENT,ESP_EVENT_ANY_ID,wifi_event,NULL));
    START_TRY(esp_event_handler_register(IP_EVENT,IP_EVENT_STA_GOT_IP,wifi_event,NULL));
    START_TRY(esp_wifi_set_storage(WIFI_STORAGE_RAM)); /* tn_settings owns credentials. */
    START_TRY(esp_wifi_set_mode(WIFI_MODE_STA));
    START_TRY(esp_wifi_set_config(WIFI_IF_STA,&wifi_config));
    START_TRY(esp_wifi_start());
    wifi_pins_start();
    wifi_power_save_off();
    wifi_ready=true;
    wifi_rescan=true;
    if(!gateway_tailnet_mode())return ESP_OK;
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0,gw_clock_server_name[0]);esp_sntp_init();
    return ESP_OK;
}
static esp_err_t start_dns(void) {
    START_TRY(esp_netif_napt_enable(usb_interface));
    extern esp_err_t gateway_dns_start(void);
    return gateway_dns_start();
}
static esp_err_t start_manager(void) {
    return xTaskCreate(manager,"members",4096,NULL,4,NULL)==pdPASS?ESP_OK:ESP_ERR_NO_MEM;
}
static esp_err_t start_display(void){return gateway_display_start();}
static bool start_step(unsigned stage,esp_err_t (*start)(void)) {
    gateway_boot_stage(stage);
    esp_err_t result=start();gateway_boot_result(stage,result);
    if(result!=ESP_OK)ESP_LOGE("startup","stage %u failed: %s; management stays available",stage,esp_err_to_name(result));
    return result==ESP_OK;
}
/* Compiled unchanged by the host fault-injection harness. */
#include "startup_sequence.inc"
void app_main(void) {
    tdongle_memory_diagnostics_init();
#ifdef CONFIG_TDONGLE_MEMORY_DIAGNOSTICS
    heap_low_start();   /* ADR 0022: owner breakdown at every new heap minimum below the elastic floor (`memory low`) */
#endif
    /* Read only before USB descriptors are created; normal settings startup
     * still validates storage and reports failures without erasing anything. */
    nvs_handle_t early;
    if(nvs_flash_init()==ESP_OK && nvs_open("tn_settings",NVS_READONLY,&early)==ESP_OK){tdongle_mode_load(early,&runtime_mode);nvs_close(early);}

    /* Frequency scaling for both modes (ADR 0016, 0023): 240 MHz while forwarding work is pending, 80 MHz when idle. The tailnet's tasks
     * hold CPU-max locks while they have work; the transparent bridge notes forwarding activity in its Wi-Fi and USB callbacks and its
     * transmit ring holds a lock while frames are queued. A failure leaves the fixed boot frequency (240 MHz). */
    tdongle_pm_start();
    members_lock=xSemaphoreCreateMutexStatic(&members_mutex);
    wifi_scan_lock=xSemaphoreCreateMutexStatic(&scan_mutex);
    gateway_startup_sequence();
    gateway_display_tick();
}
