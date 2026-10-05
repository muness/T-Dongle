/**
 * @file clock_sync.h
 * @brief Supervision of the SNTP wall clock, kept free of ESP-IDF so the host
 *        tests run it unchanged.
 *
 * TLS certificate validity cannot be judged before the clock is set, so the
 * DERP relay waits for it (ml_derp_clock_valid). That makes a clock that never
 * arrives a visible fault, not a silent one: lwIP's SNTP client retries on its
 * own schedule but reports nothing, and a blocked pool.ntp.org (captive
 * network, DNS filtering) would leave every membership without a relay and
 * nothing to show why.
 *
 * gw_clock_poll() is called from the manager task every few seconds. While the
 * clock is wrong and the uplink is up it asks, on a doubling schedule, for the
 * SNTP client to be restarted against the next server in the list. It never
 * blocks and never gates anything itself: control-plane registration, the
 * other memberships and the setup UI do not wait for the clock.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define GW_CLOCK_SERVERS 3
#define GW_CLOCK_FIRST_RETRY_MS 30000u   /* after the uplink comes up */
#define GW_CLOCK_MAX_RETRY_MS 600000u    /* backoff ceiling */

static const char *const gw_clock_server_name[GW_CLOCK_SERVERS] = {
    "pool.ntp.org", "time.cloudflare.com", "time.google.com"};

typedef struct {
    bool synced;               /* the wall clock has been plausible at least once */
    uint8_t server;            /* index into gw_clock_server_name currently in use */
    uint32_t restarts;         /* SNTP restarts requested because no time arrived */
    uint32_t backoff_ms;       /* delay before the next restart */
    uint64_t next_retry_ms;    /* 0 = not armed (uplink down, or clock set); manager task only */
    uint32_t retry_in_ms;      /* next_retry_ms - now as of the last poll: readable from any task
                                * (a 64-bit value is not read atomically on this CPU) */
} gw_clock_t;

typedef enum {
    GW_CLOCK_NOTHING = 0,
    GW_CLOCK_RESTART = 1,      /* restart SNTP with gw_clock_server_name[c->server] */
} gw_clock_action;

static inline gw_clock_action gw_clock_step(gw_clock_t *c, uint64_t now_ms,
                                            bool clock_valid, bool uplink_up) {
    if (clock_valid) {
        c->synced = true;
        c->backoff_ms = 0;
        c->next_retry_ms = 0;
        return GW_CLOCK_NOTHING;
    }
    if (!uplink_up) {            /* nothing can be asked of a server yet */
        c->next_retry_ms = 0;
        return GW_CLOCK_NOTHING;
    }
    if (!c->next_retry_ms) {     /* the uplink just came up: give the first request time */
        c->backoff_ms = GW_CLOCK_FIRST_RETRY_MS;
        c->next_retry_ms = now_ms + c->backoff_ms;
        return GW_CLOCK_NOTHING;
    }
    if (now_ms < c->next_retry_ms)
        return GW_CLOCK_NOTHING;
    c->restarts++;
    c->server = (uint8_t)((c->server + 1) % GW_CLOCK_SERVERS);
    c->backoff_ms = c->backoff_ms >= GW_CLOCK_MAX_RETRY_MS / 2 ? GW_CLOCK_MAX_RETRY_MS
                                                              : c->backoff_ms * 2;
    c->next_retry_ms = now_ms + c->backoff_ms;
    return GW_CLOCK_RESTART;
}

static inline gw_clock_action gw_clock_poll(gw_clock_t *c, uint64_t now_ms,
                                            bool clock_valid, bool uplink_up) {
    gw_clock_action action = gw_clock_step(c, now_ms, clock_valid, uplink_up);
    c->retry_in_ms = c->next_retry_ms > now_ms ? (uint32_t)(c->next_retry_ms - now_ms) : 0;
    return action;
}

/* One word for /status and the serial console. */
static inline const char *gw_clock_state(const gw_clock_t *c, bool clock_valid, bool uplink_up) {
    if (clock_valid) return "synced";
    if (!uplink_up) return "waiting_for_network";
    return c->restarts ? "failing" : "syncing";
}
