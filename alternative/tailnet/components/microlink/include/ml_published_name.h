/**
 * @file ml_published_name.h
 * @brief A short text value written by one task and read by others, without
 *        a lock and without torn reads.
 *
 * The control task rewrites a membership's MagicDNS name whenever a map
 * arrives; the status page, the LCD and the DNS task read it from other
 * tasks. A plain char array copied with strlcpy() can be observed half
 * rewritten ("dongle.old-tailnet" overwritten in place by "gw.corp.ts.net"
 * reads as "gw.corpold-tailnet"), and the DNS task would then publish a
 * domain that never existed.
 *
 * This is a seqlock. The sequence counter is odd while a write is in
 * progress. A reader copies the text and keeps the copy only if the counter
 * was even and unchanged on both sides of the copy; otherwise it retries.
 * Readers never block the writer and never take a lock, so they are safe in
 * the DNS task, which must not wait on the control task. Their retry count is
 * bounded so a high priority reader cannot spin against a preempted writer.
 *
 * Writers exclude each other by claiming the counter with a compare and
 * swap, so a second writer (today there is only the control task) waits
 * instead of corrupting the counter. Every byte of the text is accessed with
 * relaxed atomic operations, which makes the concurrent copy well defined
 * and clean under ThreadSanitizer; the acquire and release fences on the
 * counter provide the ordering.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ML_PUBLISHED_NAME_MAX 128

typedef struct {
    uint32_t seq;                    /* even = stable, odd = being written */
    char text[ML_PUBLISHED_NAME_MAX];
} ml_published_name_t;

/* Replace the value. Returns false, leaving the old value untouched, when
 * the new one (with its NUL) does not fit. */
static inline bool ml_published_name_set(ml_published_name_t *name,
                                         const char *value) {
    size_t length = 0;
    while (length < ML_PUBLISHED_NAME_MAX && value[length])
        length++;
    if (length == ML_PUBLISHED_NAME_MAX)
        return false;
    uint32_t seq;
    for (;;) {
        seq = __atomic_load_n(&name->seq, __ATOMIC_RELAXED);
        if (!(seq & 1) && __atomic_compare_exchange_n(
                              &name->seq, &seq, seq + 1, false,
                              __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            break;
    }
    /* The counter is odd from here: readers discard what they copy. The fence
     * keeps the text stores from becoming visible before the odd counter. */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    for (size_t i = 0; i <= length; i++)
        __atomic_store_n(&name->text[i], value[i], __ATOMIC_RELAXED);
    __atomic_store_n(&name->seq, seq + 2, __ATOMIC_RELEASE);
    return true;
}

/* Copy a consistent value into out (cap bytes, always NUL terminated,
 * truncated if cap is too small) and store its length in *length when that
 * is not NULL. The retry count is bounded: a reader running at a higher
 * priority than a writer that was preempted mid-write must not spin forever.
 * Returns false, with out set to "", when no consistent copy was obtained;
 * callers treat that as "name unknown right now" and ask again later. */
#define ML_PUBLISHED_NAME_ATTEMPTS 16
#define ML_PUBLISHED_NAME_SPINS 512 /* ~10 us of loads per wait for a running writer */
static inline bool ml_published_name_get(const ml_published_name_t *name,
                                         char *out, size_t cap,
                                         size_t *length) {
    if (length)
        *length = 0;
    if (!cap)
        return false;
    char copy[ML_PUBLISHED_NAME_MAX];
    for (unsigned attempt = 0; attempt < ML_PUBLISHED_NAME_ATTEMPTS; attempt++) {
        uint32_t before = __atomic_load_n(&name->seq, __ATOMIC_ACQUIRE);
        /* The writer's window is ~130 byte stores (about a microsecond); a reader
         * on the other core would burn all its attempts inside it if it merely
         * re-read the counter once per attempt. Wait it out, briefly. A counter
         * still odd after ML_PUBLISHED_NAME_SPINS loads means the writer is not
         * running (preempted by this very task, or killed): give up at once. */
        for (unsigned spin = 0; (before & 1) && spin < ML_PUBLISHED_NAME_SPINS; spin++)
            before = __atomic_load_n(&name->seq, __ATOMIC_ACQUIRE);
        if (before & 1)
            break;
        for (size_t i = 0; i < ML_PUBLISHED_NAME_MAX; i++)
            copy[i] = __atomic_load_n(&name->text[i], __ATOMIC_RELAXED);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&name->seq, __ATOMIC_RELAXED) != before)
            continue;
        copy[ML_PUBLISHED_NAME_MAX - 1] = 0; /* a verified copy is terminated */
        size_t n = 0;
        while (n < cap - 1 && copy[n]) {
            out[n] = copy[n];
            n++;
        }
        out[n] = 0;
        if (length)
            *length = n;
        return true;
    }
    out[0] = 0;
    return false;
}
