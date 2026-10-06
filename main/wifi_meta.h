// SPDX-License-Identifier: MIT
#pragma once
/* Per-network metadata for the saved Wi-Fi list: a display name, a priority (0 to 100) and which network is preferred.
 * v0.1.1 kept these next to each SSID; the unified firmware's `wifi_profiles` blob has only SSID and password, and its format
 * must not change (an older unified build reads that blob and refuses a schema it does not know). The metadata therefore
 * lives in its own blob, keyed by SSID rather than by slot, so reordering, deleting, or an older build editing `wifi_profiles`
 * can never attach a priority to the wrong network: an entry whose SSID is not in the list is ignored, and a network without
 * an entry gets the defaults. Pure C, host tested (tests/test_wifi_meta.c). */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { WIFI_META_SLOTS = 8, WIFI_META_NAME_MAX = 24, WIFI_META_PRIORITY_DEFAULT = 50, WIFI_META_PRIORITY_MAX = 100,
       WIFI_META_SSID_MAX = 32, WIFI_META_SCHEMA = 1 };

typedef struct { char name[WIFI_META_NAME_MAX + 1]; uint8_t priority; } wifi_meta_slot;
typedef struct {
    wifi_meta_slot slot[WIFI_META_SLOTS];   /* parallel to the saved networks, same order */
    int preferred;                          /* slot index, or -1 for none */
} wifi_meta_set;

/* Persisted form (NVS tn_settings key "wifi_meta"). */
typedef struct {
    uint32_t schema, count;
    char preferred_ssid[WIFI_META_SSID_MAX + 1];
    struct { char ssid[WIFI_META_SSID_MAX + 1]; char name[WIFI_META_NAME_MAX + 1]; uint8_t priority; } entry[WIFI_META_SLOTS];
} wifi_meta_blob;

/* A name is 1 to 24 printable ASCII characters (what the v0.1.1 profile JSON accepted). */
bool wifi_meta_name_valid(const char *name);
void wifi_meta_slot_default(wifi_meta_slot *slot, const char *ssid);   /* name = the SSID cut to 24 characters, priority 50 */
void wifi_meta_defaults(wifi_meta_set *set, const char *const ssids[], unsigned count);
/* Remove the entry of saved slot `slot` of `count` (the list shrinks by one): later entries move up; a preferred network that
 * is removed is forgotten, and the index of one that moves is kept pointing at it. */
void wifi_meta_remove(wifi_meta_set *set, unsigned count, unsigned slot);
/* Persisted blob for the current list. */
void wifi_meta_encode(wifi_meta_blob *blob, const char *const ssids[], unsigned count, const wifi_meta_set *set);
/* Lay the blob over what `set` already holds: only the networks the blob has an entry for take its name and priority (the others keep whatever
 * `set` had, typically defaults or the v0.1.x values), and its preferred network, present or "none", is authoritative: a blob exists only
 * because the user acted. Returns false (set untouched) for an invalid blob: wrong size or schema, unterminated strings, a priority above 100.
 * The firmware starts from wifi_meta_defaults (then the v0.1.x values, if any) and overlays the stored blob. */
bool wifi_meta_overlay(const void *data, size_t length, const char *const ssids[], unsigned count, wifi_meta_set *set);
