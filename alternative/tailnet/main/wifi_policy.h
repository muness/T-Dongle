#pragma once
#include <stdint.h>
#include <stdbool.h>
#define WIFI_PROFILE_LIMIT 8
/* Stable ties, 12 dB hysteresis and a weak-current threshold prevent churn. */
static int wifi_pick(const int16_t signal[WIFI_PROFILE_LIMIT],unsigned count,int current,bool connected){
    int best=-1;
    for(unsigned i=0;i<count;i++)if(signal[i]>-127 && (best<0 || signal[i]>signal[best]))best=i;
    if(!connected)return best;
    if(best<0 || best==current)return -1;
    if(current>=0 && signal[current]>-75)return -1;
    if(current>=0 && signal[best]<signal[current]+12)return -1;
    return best;
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
static inline int wifi_pin_pick(wifi_pin *p, const int16_t signal[WIFI_PROFILE_LIMIT], unsigned count, int current, bool connected) {
    if (p->slot >= (int)count) wifi_pin_clear(p);
    if (p->slot < 0) return wifi_pick(signal, count, current, connected);
    if (connected && current == p->slot) { p->attempts = 0; return -1; }
    if (++p->attempts > WIFI_PIN_MAX_ATTEMPTS) {
        p->failed_slot = (unsigned)p->slot + 1; p->slot = -1; p->attempts = 0;
        return wifi_pick(signal, count, current, connected);
    }
    return p->slot;
}
