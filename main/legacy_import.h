// SPDX-License-Identifier: MIT
#pragma once
/* Reading what the v0.1.x bridge firmware left in flash: NVS namespace `adapter`, key `config`, a blob of settings_t
 * (core.h, CFG_VERSION 1). The unified firmware never writes or erases that blob except in a factory reset; it only reads it,
 * every boot until the user's first explicit save moves the data into its own keys (tn_settings/wifi_profiles, wifi_meta,
 * display). Everything the old firmware stored is carried: SSID, password, display name, priority, the preferred slot, and the
 * display settings. Pure C, host tested (tests/test_legacy_import.c). */
#include "ui_settings.h"
#include "wifi_meta.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char ssid[33], password[64];
    wifi_meta_slot meta;
} legacy_network;
typedef struct {
    unsigned count;                 /* usable networks, at most 8, in the old slot order with empty slots skipped */
    legacy_network net[8];
    int preferred;                  /* index into net[] of the old preferred slot, or -1 */
    bool display_valid;             /* the three display settings were in range */
    ui_settings display;
} legacy_import;

/* Decode a v0.1.x settings blob. False when it is not one (wrong size or version): nothing is imported then. A network that
 * cannot be used (unterminated or oversized strings, a password longer than 63) is skipped, and one that repeats an SSID that is
 * already imported is skipped too (the unified store keys networks by SSID), as the first import always did. A bad display name
 * or priority falls back to the SSID or 50 for that network instead of dropping it, and bad display settings only clear
 * display_valid: the user's networks are the part that must never be lost. */
bool legacy_import_decode(const void *blob, size_t length, legacy_import *out);
