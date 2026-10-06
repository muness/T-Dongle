// SPDX-License-Identifier: MIT
#include "legacy_import.h"
#include "core.h"
#include <string.h>

bool legacy_import_decode(const void *blob, size_t length, legacy_import *out) {
    settings_t old;
    if (!blob || length != sizeof(old)) return false;
    memcpy(&old, blob, sizeof(old));
    if (old.version != CFG_VERSION) return false;
    memset(out, 0, sizeof(*out));
    out->preferred = -1;
    int mapped[PROFILE_MAX];   /* old slot -> index in out->net, -1 when the slot was not imported */
    for (unsigned i = 0; i < PROFILE_MAX; i++) {
        mapped[i] = -1;
        const profile_t *p = &old.p[i];
        if (!p->ssid[0] || !memchr(p->ssid, 0, sizeof(p->ssid)) || !memchr(p->pass, 0, sizeof(p->pass)) || strlen(p->pass) > 63) continue;
        int existing = -1;
        for (unsigned j = 0; j < out->count; j++)
            if (!strcmp(out->net[j].ssid, p->ssid)) existing = (int)j;
        if (existing >= 0) { mapped[i] = existing; continue; }   /* the same network again: the first slot's data stands */
        if (out->count == WIFI_META_SLOTS) continue;
        legacy_network *n = &out->net[out->count];
        memcpy(n->ssid, p->ssid, sizeof(n->ssid));
        memcpy(n->password, p->pass, 64);
        n->password[63] = 0;
        wifi_meta_slot_default(&n->meta, n->ssid);
        if (memchr(p->name, 0, sizeof(p->name)) && wifi_meta_name_valid(p->name)) {
            memset(n->meta.name, 0, sizeof(n->meta.name));
            memcpy(n->meta.name, p->name, strlen(p->name));
        }
        if (p->priority <= WIFI_META_PRIORITY_MAX) n->meta.priority = p->priority;
        mapped[i] = (int)out->count++;
    }
    if (old.preferred < PROFILE_MAX) out->preferred = mapped[old.preferred];
    ui_settings display = {.brightness = old.brightness, .rotation = old.rotation, .dim_seconds = old.dim_seconds};
    if (ui_settings_valid(&display)) { out->display = display; out->display_valid = true; }
    return true;
}
