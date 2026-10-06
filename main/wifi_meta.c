// SPDX-License-Identifier: MIT
#include "wifi_meta.h"
#include <string.h>

bool wifi_meta_name_valid(const char *name) {
    size_t n = 0;
    while (n <= WIFI_META_NAME_MAX && name[n]) {
        if ((unsigned char)name[n] < 32 || (unsigned char)name[n] > 126) return false;
        n++;
    }
    return n >= 1 && n <= WIFI_META_NAME_MAX;
}
void wifi_meta_slot_default(wifi_meta_slot *slot, const char *ssid) {
    memset(slot, 0, sizeof(*slot));
    size_t n = 0;
    /* Printable ASCII only: an SSID may be any bytes, and the name is shown on the screen and the serial console. */
    for (; ssid[n] && n < WIFI_META_NAME_MAX; n++)
        slot->name[n] = (unsigned char)ssid[n] >= 32 && (unsigned char)ssid[n] <= 126 ? ssid[n] : '?';
    slot->priority = WIFI_META_PRIORITY_DEFAULT;
}
void wifi_meta_defaults(wifi_meta_set *set, const char *const ssids[], unsigned count) {
    memset(set, 0, sizeof(*set));
    set->preferred = -1;
    for (unsigned i = 0; i < count && i < WIFI_META_SLOTS; i++) wifi_meta_slot_default(&set->slot[i], ssids[i]);
}
void wifi_meta_remove(wifi_meta_set *set, unsigned count, unsigned slot) {
    if (slot >= count || count > WIFI_META_SLOTS) return;
    memmove(&set->slot[slot], &set->slot[slot + 1], (count - slot - 1) * sizeof(set->slot[0]));
    memset(&set->slot[count - 1], 0, sizeof(set->slot[0]));
    if (set->preferred == (int)slot) set->preferred = -1;
    else if (set->preferred > (int)slot) set->preferred--;
}
void wifi_meta_encode(wifi_meta_blob *blob, const char *const ssids[], unsigned count, const wifi_meta_set *set) {
    memset(blob, 0, sizeof(*blob));
    blob->schema = WIFI_META_SCHEMA;
    if (count > WIFI_META_SLOTS) count = WIFI_META_SLOTS;
    blob->count = count;
    for (unsigned i = 0; i < count; i++) {
        strncpy(blob->entry[i].ssid, ssids[i], WIFI_META_SSID_MAX);
        strncpy(blob->entry[i].name, set->slot[i].name, WIFI_META_NAME_MAX);
        blob->entry[i].priority = set->slot[i].priority;
    }
    if (set->preferred >= 0 && (unsigned)set->preferred < count) strncpy(blob->preferred_ssid, ssids[set->preferred], WIFI_META_SSID_MAX);
}
static bool terminated(const char *s, size_t cap) { return memchr(s, 0, cap) != NULL; }
bool wifi_meta_decode(const void *data, size_t length, const char *const ssids[], unsigned count, wifi_meta_set *set) {
    wifi_meta_blob blob;
    if (!data || length != sizeof(blob) || count > WIFI_META_SLOTS) return false;
    memcpy(&blob, data, sizeof(blob));
    if (blob.schema != WIFI_META_SCHEMA || blob.count > WIFI_META_SLOTS || !terminated(blob.preferred_ssid, sizeof(blob.preferred_ssid))) return false;
    for (unsigned i = 0; i < blob.count; i++)
        if (!terminated(blob.entry[i].ssid, sizeof(blob.entry[i].ssid)) || !terminated(blob.entry[i].name, sizeof(blob.entry[i].name)) ||
            blob.entry[i].priority > WIFI_META_PRIORITY_MAX)
            return false;
    wifi_meta_set result;
    wifi_meta_defaults(&result, ssids, count);
    for (unsigned i = 0; i < count; i++) {
        for (unsigned j = 0; j < blob.count; j++) {
            if (strcmp(blob.entry[j].ssid, ssids[i])) continue;
            if (wifi_meta_name_valid(blob.entry[j].name)) strncpy(result.slot[i].name, blob.entry[j].name, WIFI_META_NAME_MAX);
            result.slot[i].priority = blob.entry[j].priority;
            break;
        }
        if (blob.preferred_ssid[0] && !strcmp(blob.preferred_ssid, ssids[i])) result.preferred = (int)i;
    }
    *set = result;
    return true;
}
