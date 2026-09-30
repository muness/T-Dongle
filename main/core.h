// SPDX-License-Identifier: MIT
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define PROFILE_MAX 8
#define ADDRESS_TTL_MS 60000u
#define HISTORY_LEN 32
#define CFG_VERSION 1u

typedef struct {
    char name[25], ssid[33], pass[65];
    uint8_t priority;
} profile_t;
typedef struct {
    uint32_t version;
    profile_t p[PROFILE_MAX];
    uint8_t preferred, brightness, rotation;
    uint16_t dim_seconds;
} settings_t;
bool profile_valid(const profile_t *p);
bool settings_valid(const settings_t *s);
int policy_next(const settings_t *s, uint8_t tried);
uint32_t retry_delay_ms(unsigned failures);

typedef struct {
    uint8_t ip4[4], ip6[16];
    uint64_t seen4, seen6;
    bool valid4, valid6;
} addresses_t;
void observe_packet(addresses_t *a, const uint8_t *f, size_t n, uint64_t now);
bool address_fresh(bool valid, uint64_t seen, uint64_t now);
bool frame_reflected(const uint8_t *f, size_t n, const uint8_t mac[6]);

typedef struct {
    uint64_t down, up, time;
    double down_mbps, up_mbps;
    float history[HISTORY_LEN];
    unsigned cursor;
    bool initialized;
} rates_t;
void rate_update(rates_t *r, uint64_t down, uint64_t up, uint64_t now_us);

typedef enum { BUTTON_NONE, BUTTON_SHORT, BUTTON_HOLD, BUTTON_WAKE } button_event_t;
typedef struct {
    bool raw, stable, fired, suppress;
    uint64_t edge, pressed;
} button_t;
button_event_t button_update(button_t *b, bool down, bool dimmed, uint64_t ms);
/* 30 ms debounce; hold fires once after 1500 ms. Wake consumes whole gesture.
 */

/* Four clipped text lines; pixel placement belongs to renderer. */
void text_clip(char *dst, size_t cap, const char *src, size_t columns);

/* Candidate validation: 0 waiting, 1 commit, -1 timed out. */
int trial_decision(uint64_t now, uint64_t started, uint64_t associated_since, bool associated);
bool profile_parse_json(const char *json, int *slot, profile_t *p);

/* Compare-and-set metadata; no SSID/password mutation and no association change. */
typedef struct {
    int slot, expected_priority, priority;
    char expected_name[25], expected_ssid[33], name[25];
    bool preferred;
} metadata_edit_t;
bool metadata_parse_json(const char *json, metadata_edit_t *edit);
bool metadata_apply(settings_t *settings, const metadata_edit_t *edit);
