// SPDX-License-Identifier: MIT
#include "app.h"
#include "nvs.h"
#include <string.h>
static bool store_ok = true;
static void defaults(settings_t *s) {
    memset(s, 0, sizeof(*s));
    s->version = CFG_VERSION;
    s->brightness = 60;
    s->dim_seconds = 60;
}
void settings_load(settings_t *s) {
    defaults(s);
    nvs_handle_t h;
    esp_err_t e = nvs_open("adapter", NVS_READONLY, &h);
    if (e == ESP_ERR_NVS_NOT_FOUND)
        return;
    if (e != ESP_OK) {
        store_ok = false;
        return;
    }
    settings_t tmp;
    size_t n = sizeof(tmp);
    e = nvs_get_blob(h, "config", &tmp, &n);
    nvs_close(h);
    if (e == ESP_OK && n == sizeof(tmp) && settings_valid(&tmp))
        *s = tmp;
    else if (e != ESP_ERR_NVS_NOT_FOUND)
        store_ok = false; /* never silently overwrite damaged/unknown schema */
}
bool settings_store_ok(void) { return store_ok; }
static esp_err_t put(const char *key, const void *data, size_t n) {
    if (!store_ok)
        return ESP_ERR_INVALID_STATE;
    nvs_handle_t h;
    esp_err_t e = nvs_open("adapter", NVS_READWRITE, &h);
    if (e != ESP_OK)
        return e;
    e = nvs_set_blob(h, key, data, n);
    if (e == ESP_OK)
        e = nvs_commit(h);
    nvs_close(h);
    return e;
}
esp_err_t settings_save(const settings_t *s) {
    return settings_valid(s) ? put("config", s, sizeof(*s)) : ESP_ERR_INVALID_ARG;
}
typedef struct {
    uint32_t version;
    int slot;
    profile_t p;
} candidate_t;
esp_err_t settings_stage(int slot, const profile_t *p) {
    if (slot < 0 || slot >= PROFILE_MAX || !profile_valid(p))
        return ESP_ERR_INVALID_ARG;
    candidate_t c = {.version = CFG_VERSION, .slot = slot, .p = *p};
    return put("candidate", &c, sizeof(c));
}
bool settings_take_candidate(int *slot, profile_t *p) {
    nvs_handle_t h;
    if (nvs_open("adapter", NVS_READWRITE, &h) != ESP_OK)
        return false;
    candidate_t c;
    size_t n = sizeof(c);
    bool ok = nvs_get_blob(h, "candidate", &c, &n) == ESP_OK && n == sizeof(c) &&
              c.version == CFG_VERSION && c.slot >= 0 && c.slot < PROFILE_MAX &&
              profile_valid(&c.p);
    /* Consume before trying; a reset during trial always falls back to saved
     * config. */
    esp_err_t e = nvs_erase_key(h, "candidate");
    if (e == ESP_OK)
        e = nvs_commit(h);
    nvs_close(h);
    if (ok && e == ESP_OK) {
        *slot = c.slot;
        *p = c.p;
        return true;
    }
    return false;
}
esp_err_t settings_reset(void) {
    nvs_handle_t h;
    esp_err_t e = nvs_open("adapter", NVS_READWRITE, &h);
    if (e != ESP_OK)
        return e;
    e = nvs_erase_all(h);
    if (e == ESP_OK)
        e = nvs_commit(h);
    nvs_close(h);
    if (e == ESP_OK)
        store_ok = true;
    return e;
}
