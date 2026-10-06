#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#define WIFI_PROFILE_LIMIT 8
/* Saved-network selection. Three things decide which saved network is joined, strongest first:
 *   1. the preferred slot (the one `use N` or the v0.1.1 preferred slot set), if it is usable;
 *   2. the saved network's priority (0 to 100, default 50; v0.1.1 imported it per slot);
 *   3. signal strength, with ties to the lower slot.
 * With every priority at the default and no preferred slot (a fresh install, or any install that never set either) only the
 * third applies and the choice is the strongest network, exactly as before priorities existed.
 *
 * "Usable" is WIFI_USABLE_DBM or stronger: a preferred or high-priority network seen only faintly does not outrank one that
 * can carry traffic. When nothing is usable, everything seen is ranked, so a weak network is still joined if it is all there is.
 * Leaving a working link is deliberately hard (the v0.1.1 rule: never oscillate a healthy link): a connected network stronger
 * than WIFI_HEALTHY_DBM is kept whatever else is in range, and a weaker one is left only for a candidate at least
 * WIFI_HYSTERESIS_DB stronger. */
enum { WIFI_PRIORITY_DEFAULT = 50, WIFI_PRIORITY_MAX = 100, WIFI_USABLE_DBM = -85, WIFI_HEALTHY_DBM = -75, WIFI_HYSTERESIS_DB = 12 };
typedef struct {
    const uint8_t *priority;   /* one entry per saved slot, or NULL: every slot at WIFI_PRIORITY_DEFAULT */
    int preferred;             /* slot (0-based) or -1 */
} wifi_rank;
#define WIFI_RANK_NONE {NULL, -1}
static inline unsigned wifi_rank_priority(const wifi_rank *r, int slot) { return r && r->priority ? r->priority[slot] : (unsigned)WIFI_PRIORITY_DEFAULT; }
/* Is slot a strictly better choice than slot b? Both seen (signal > -127). */
static inline bool wifi_rank_better(const wifi_rank *r, const int16_t signal[WIFI_PROFILE_LIMIT], int a, int b) {
    bool a_usable = signal[a] >= WIFI_USABLE_DBM, b_usable = signal[b] >= WIFI_USABLE_DBM;
    if (a_usable != b_usable) return a_usable;
    bool a_pref = r && r->preferred == a, b_pref = r && r->preferred == b;   /* a usable network always outranks an unusable one, above */
    if (a_pref != b_pref) return a_pref;
    unsigned pa = wifi_rank_priority(r, a), pb = wifi_rank_priority(r, b);
    if (pa != pb) return pa > pb;
    return signal[a] > signal[b];
}
static inline int wifi_pick_ranked(const int16_t signal[WIFI_PROFILE_LIMIT], unsigned count, int current, bool connected, const wifi_rank *r) {
    int best = -1;
    for (unsigned i = 0; i < count; i++) if (signal[i] > -127 && (best < 0 || wifi_rank_better(r, signal, (int)i, best))) best = (int)i;
    if (!connected) return best;
    if (best < 0 || best == current) return -1;
    if (current >= 0 && signal[current] > WIFI_HEALTHY_DBM) return -1;
    if (current >= 0 && signal[best] < signal[current] + WIFI_HYSTERESIS_DB) return -1;
    return best;
}
/* Stable ties, 12 dB hysteresis and a weak-current threshold prevent churn. */
static inline int wifi_pick(const int16_t signal[WIFI_PROFILE_LIMIT],unsigned count,int current,bool connected){
    return wifi_pick_ranked(signal, count, current, connected, NULL);
}
/* The order in which networks that were not seen (hidden SSIDs, or out of range right now) are tried while offline:
 * the preferred slot, then by priority, then by slot. Fills order[] with count slot numbers. */
static inline void wifi_rank_order(const wifi_rank *r, unsigned count, uint8_t order[WIFI_PROFILE_LIMIT]) {
    for (unsigned i = 0; i < count; i++) order[i] = (uint8_t)i;
    for (unsigned i = 1; i < count; i++) {   /* insertion sort: at most eight entries, stable */
        uint8_t slot = order[i];
        unsigned j = i;
        while (j > 0) {
            uint8_t prev = order[j - 1];
            bool slot_pref = r && r->preferred == (int)slot, prev_pref = r && r->preferred == (int)prev;
            bool before = slot_pref != prev_pref ? slot_pref : wifi_rank_priority(r, slot) > wifi_rank_priority(r, prev);
            if (!before) break;
            order[j] = prev;
            j--;
        }
        order[j] = slot;
    }
}
/* A network the user chose with `use N` is pinned: automatic roaming and strongest-signal selection leave it alone
 * until the user changes it, saved networks are edited, or the join fails WIFI_PIN_MAX_ATTEMPTS worker passes in a
 * row (then the pin is dropped, failed_slot says which network, and normal selection resumes). slot is 0-based. */
enum { WIFI_PIN_MAX_ATTEMPTS = 3 };
typedef struct { int slot; unsigned attempts; unsigned failed_slot; /* 1-based, 0 none */ } wifi_pin;
#define WIFI_PIN_INIT {-1, 0, 0}
static inline void wifi_pin_set(wifi_pin *p, int slot) { p->slot = slot; p->attempts = 0; p->failed_slot = 0; }
static inline void wifi_pin_clear(wifi_pin *p) { p->slot = -1; p->attempts = 0; p->failed_slot = 0; }
/* The worker's choice: the slot to connect to, or -1 to stay. Unpinned: wifi_pick. Pinned: stay while connected to the
 * pinned network, otherwise retry it regardless of signal (it may be hidden or briefly unseen) until it gives up. */
static inline int wifi_pin_pick_ranked(wifi_pin *p, const int16_t signal[WIFI_PROFILE_LIMIT], unsigned count, int current, bool connected, const wifi_rank *r) {
    if (p->slot >= (int)count) wifi_pin_clear(p);
    if (p->slot < 0) return wifi_pick_ranked(signal, count, current, connected, r);
    if (connected && current == p->slot) { p->attempts = 0; return -1; }
    if (++p->attempts > WIFI_PIN_MAX_ATTEMPTS) {
        p->failed_slot = (unsigned)p->slot + 1; p->slot = -1; p->attempts = 0;
        return wifi_pick_ranked(signal, count, current, connected, r);
    }
    return p->slot;
}
static inline int wifi_pin_pick(wifi_pin *p, const int16_t signal[WIFI_PROFILE_LIMIT], unsigned count, int current, bool connected) {
    return wifi_pin_pick_ranked(p, signal, count, current, connected, NULL);
}
