// SPDX-License-Identifier: MIT
#include "cJSON.h"
#include "core.h"
#include <string.h>
static bool integer(const cJSON *o, const char *key, int min, int max, int *out) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!cJSON_IsNumber(v) || v->valuedouble != v->valueint || v->valueint < min ||
        v->valueint > max)
        return false;
    *out = v->valueint;
    return true;
}
static bool string(const cJSON *o, const char *key, char *out, size_t cap) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!cJSON_IsString(v) || strlen(v->valuestring) >= cap)
        return false;
    strcpy(out, v->valuestring);
    return true;
}
bool profile_parse_json(const char *json, int *slot, profile_t *p) {
    if (strlen(json) > 500)
        return false;
    // Avoid cJSON's embedded-NUL truncation. This protocol uses printable ASCII.
    for (size_t i = 0; json[i]; i++)
        if (json[i] == '\\') {
            if (!json[i + 1] || json[i + 1] == 'u')
                return false;
            i++;
        }
    const char *end;
    cJSON *o = cJSON_ParseWithOpts(json, &end, true);
    bool ok = cJSON_IsObject(o);
    const char *keys[] = {"slot", "priority", "name", "ssid", "password"};
    unsigned seen = 0;
    if (ok)
        for (cJSON *v = o->child; v; v = v->next) {
            unsigned i;
            for (i = 0; i < 5; i++)
                if (!strcmp(keys[i], v->string))
                    break;
            if (i == 5 || (seen & (1u << i))) {
                ok = false;
                break;
            }
            seen |= 1u << i;
        }
    int n = 0, priority = 0;
    memset(p, 0, sizeof(*p));
    ok = ok && seen == 31 && integer(o, "slot", 1, 8, &n) &&
         integer(o, "priority", 0, 100, &priority) && string(o, "name", p->name, sizeof(p->name)) &&
         string(o, "ssid", p->ssid, sizeof(p->ssid)) &&
         string(o, "password", p->pass, sizeof(p->pass));
    if (ok) {
        p->priority = priority;
        ok = profile_valid(p);
    }
    cJSON_Delete(o);
    if (ok)
        *slot = n - 1;
    else
        memset(p, 0, sizeof(*p));
    return ok;
}

bool metadata_parse_json(const char *json, metadata_edit_t *edit) {
    memset(edit, 0, sizeof(*edit));
    if (strlen(json) > 500)
        return false;
    for (size_t i = 0; json[i]; i++)
        if (json[i] == '\\') {
            if (!json[i + 1] || json[i + 1] == 'u')
                return false;
            i++;
        }
    const char *end;
    cJSON *o = cJSON_ParseWithOpts(json, &end, true);
    const char *keys[] = {"slot", "expectedName", "expectedSsid", "expectedPriority", "name", "priority", "preferred"};
    unsigned seen = 0;
    bool ok = cJSON_IsObject(o);
    if (ok)
        for (cJSON *v = o->child; v; v = v->next) {
            unsigned i;
            for (i = 0; i < 7; i++)
                if (!strcmp(keys[i], v->string))
                    break;
            if (i == 7 || (seen & (1u << i))) { ok = false; break; }
            seen |= 1u << i;
        }
    int slot = 0;
    const cJSON *preferred = cJSON_GetObjectItemCaseSensitive(o, "preferred");
    ok = ok && seen == 127 && integer(o, "slot", 1, 8, &slot) &&
        integer(o, "expectedPriority", 0, 100, &edit->expected_priority) &&
        integer(o, "priority", 0, 100, &edit->priority) &&
        string(o, "expectedName", edit->expected_name, sizeof(edit->expected_name)) &&
        string(o, "expectedSsid", edit->expected_ssid, sizeof(edit->expected_ssid)) &&
        string(o, "name", edit->name, sizeof(edit->name)) && cJSON_IsBool(preferred);
    if (ok) {
        settings_t check = {0};
        edit->slot = slot - 1;
        edit->preferred = cJSON_IsTrue(preferred);
        strcpy(check.p[edit->slot].name, edit->expected_name);
        strcpy(check.p[edit->slot].ssid, edit->expected_ssid);
        check.p[edit->slot].priority = edit->expected_priority;
        ok = metadata_apply(&check, edit);
    }
    cJSON_Delete(o);
    if (!ok)
        memset(edit, 0, sizeof(*edit));
    return ok;
}
