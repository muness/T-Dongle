// SPDX-License-Identifier: MIT
#include "core.h"
#include <string.h>
static bool printable(const char *s, size_t max, size_t min) {
    size_t n = 0;
    while (n <= max && s[n]) {
        if ((unsigned char)s[n] < 32 || (unsigned char)s[n] > 126)
            return false;
        n++;
    }
    return n >= min && n <= max;
}
bool profile_valid(const profile_t *p) {
    if (!printable(p->name, 24, 1) || !printable(p->ssid, 32, 1) || p->priority > 100)
        return false;
    size_t n = 0;
    while (n < 65 && p->pass[n])
        n++;
    return (n == 0 || (n >= 8 && n <= 63)) && printable(p->pass, 63, 0);
}
bool settings_valid(const settings_t *s) {
    if (s->version != CFG_VERSION || s->preferred >= PROFILE_MAX || s->brightness < 5 ||
        s->brightness > 100 || s->rotation > 1 || s->dim_seconds < 10 || s->dim_seconds > 3600)
        return false;
    for (int i = 0; i < PROFILE_MAX; i++)
        if (s->p[i].ssid[0] && !profile_valid(&s->p[i]))
            return false;
    return true;
}
int policy_next(const settings_t *s, uint8_t tried) {
    if (s->p[s->preferred].ssid[0] && !(tried & (1u << s->preferred)))
        return s->preferred;
    int best = -1;
    for (int i = 0; i < PROFILE_MAX; i++)
        if (s->p[i].ssid[0] && !(tried & (1u << i)) &&
            (best < 0 || s->p[i].priority > s->p[best].priority))
            best = i;
    return best;
}
uint32_t retry_delay_ms(unsigned failures) { return failures >= 5 ? 30000 : (1000u << failures); }
bool address_fresh(bool v, uint64_t seen, uint64_t now) {
    return v && now >= seen && now - seen < ADDRESS_TTL_MS;
}
bool frame_reflected(const uint8_t *f, size_t n, const uint8_t mac[6]) {
    return n >= 14 && !memcmp(f + 6, mac, 6);
}
void observe_packet(addresses_t *a, const uint8_t *f, size_t n, uint64_t now) {
    if (n < 14)
        return;
    unsigned eth = (f[12] << 8) | f[13];
    const uint8_t *ip = NULL;
    if (eth == 0x0806 && n >= 42 && f[14] == 0 && f[15] == 1 && f[16] == 8 && f[17] == 0 &&
        f[18] == 6 && f[19] == 4 && f[20] == 0 && (f[21] == 1 || f[21] == 2))
        ip = f + 28;
    if (eth == 0x0800 && n >= 34 && (f[14] >> 4) == 4) {
        size_t h = (f[14] & 15) * 4u, total = (f[16] << 8) | f[17];
        if (h >= 20 && total >= h && n >= 14 + total)
            ip = f + 26;
    }
    if (ip && ip[0] != 0 && ip[0] < 224 && ip[0] != 127) {
        memcpy(a->ip4, ip, 4);
        a->valid4 = true;
        a->seen4 = now;
    }
    if (eth == 0x86dd && n >= 54 && (f[14] >> 4) == 6 && n >= 54u + ((f[18] << 8) | f[19])) {
        ip = f + 22;
        bool nonzero = false;
        for (int i = 0; i < 16; i++)
            nonzero |= ip[i] != 0;
        if (nonzero && ip[0] != 255) {
            memcpy(a->ip6, ip, 16);
            a->valid6 = true;
            a->seen6 = now;
        }
    }
}
void rate_update(rates_t *r, uint64_t down, uint64_t up, uint64_t now) {
    if (r->initialized && now > r->time && down >= r->down && up >= r->up) {
        r->down_mbps = (double)(down - r->down) * 8.0 / (double)(now - r->time);
        r->up_mbps = (double)(up - r->up) * 8.0 / (double)(now - r->time);
    } else
        r->down_mbps = r->up_mbps = 0;
    r->history[r->cursor++ % HISTORY_LEN] = (float)(r->down_mbps + r->up_mbps);
    r->down = down;
    r->up = up;
    r->time = now;
    r->initialized = true;
}
button_event_t button_update(button_t *b, bool down, bool dimmed, uint64_t ms) {
    if (down != b->raw) {
        b->raw = down;
        b->edge = ms;
    }
    if (ms - b->edge >= 30 && b->stable != down) {
        b->stable = down;
        if (down) {
            b->pressed = ms;
            b->fired = false;
            b->suppress = dimmed;
            if (dimmed)
                return BUTTON_WAKE;
        } else if (!b->fired && !b->suppress)
            return BUTTON_SHORT;
    }
    if (b->stable && !b->fired && !b->suppress && ms - b->pressed >= 1500) {
        b->fired = true;
        return BUTTON_HOLD;
    }
    return BUTTON_NONE;
}
void text_clip(char *dst, size_t cap, const char *src, size_t cols) {
    if (!cap)
        return;
    size_t n = strlen(src);
    if (cols >= cap)
        cols = cap - 1;
    size_t take = n < cols ? n : cols;
    for (size_t i = 0; i < take; i++)
        dst[i] = (src[i] >= 32 && src[i] <= 126) ? src[i] : '?';
    if (n > cols && take >= 3)
        memcpy(dst + take - 3, "...", 3);
    dst[take] = 0;
}

int trial_decision(uint64_t now, uint64_t started, uint64_t since, bool associated) {
    if (now < started)
        return -1;
    if (associated && since >= started && since <= now && now - since >= 10000 &&
        since - started <= 35000)
        return 1;
    return now - started >= 45000 ? -1 : 0;
}

bool metadata_apply(settings_t *s, const metadata_edit_t *e) {
    if (e->slot < 0 || e->slot >= PROFILE_MAX || e->priority < 0 || e->priority > 100 ||
        !printable(e->name, 24, 1) || strstr(e->name, " ssid=") || !printable(e->expected_name, 24, 1) ||
        !printable(e->expected_ssid, 32, 1))
        return false;
    profile_t *p = &s->p[e->slot];
    if (strcmp(p->name, e->expected_name) || strcmp(p->ssid, e->expected_ssid) ||
        p->priority != e->expected_priority)
        return false;
    memcpy(p->name, e->name, sizeof(p->name));
    p->priority = e->priority;
    if (e->preferred)
        s->preferred = e->slot;
    return true;
}
