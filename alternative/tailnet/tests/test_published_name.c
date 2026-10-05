/* self_dns_name publication: one writer rewriting the name while readers copy
 * it must never observe a mixture of two values. Built with
 * -fsanitize=address,undefined and again with -fsanitize=thread. */
#include "../components/microlink/include/ml_published_name.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Every generated name is `count` copies of one letter followed by ".ts.net",
 * where count is a function of the letter. A torn copy mixes letters or has a
 * length that does not match its letter. */
static void make_name(unsigned k, char *out) {
    char letter = (char)('a' + k % 26);
    unsigned count = 1 + (k % 26) * 4; /* 1..101, plus ".ts.net" fits in 127 */
    memset(out, letter, count);
    strcpy(out + count, ".ts.net");
}
static bool well_formed(const char *s) {
    size_t n = strlen(s);
    if (n < 8 || strcmp(s + n - 7, ".ts.net"))
        return false;
    n -= 7;
    for (size_t i = 1; i < n; i++)
        if (s[i] != s[0])
            return false;
    unsigned letter = (unsigned)(s[0] - 'a');
    return letter < 26 && n == 1 + letter * 4;
}

static ml_published_name_t shared;
static atomic_bool stop;
static atomic_uint writes, total_reads;   /* progress, readable while the threads run */

static void *writer(void *arg) {
    (void)arg;
    char name[ML_PUBLISHED_NAME_MAX];
    for (unsigned k = 0; !atomic_load(&stop); k++) {
        make_name(k, name);
        assert(ml_published_name_set(&shared, name));
        atomic_fetch_add(&writes, 1);
    }
    return NULL;
}
typedef struct { unsigned reads, misses; } reader_result;
static void *reader(void *arg) {
    reader_result *r = arg;
    char out[ML_PUBLISHED_NAME_MAX];
    while (!atomic_load(&stop)) {
        size_t length;
        if (!ml_published_name_get(&shared, out, sizeof(out), &length)) {
            assert(out[0] == 0 && length == 0);
            r->misses++;
            continue;
        }
        assert(length == strlen(out));
        assert(well_formed(out)); /* a torn copy fails here */
        r->reads++;
        atomic_fetch_add(&total_reads, 1);
    }
    return NULL;
}

static void stress(void) {
    make_name(0, shared.text);
    pthread_t w, readers[3];
    reader_result results[3] = {{0}};
    atomic_store(&stop, false);
    pthread_create(&w, NULL, writer, NULL);
    for (int i = 0; i < 3; i++)
        pthread_create(&readers[i], NULL, reader, &results[i]);
    /* At least one second, and until both sides have done real work: on a loaded machine four spinning
     * threads can need much longer than a second to reach the thresholds below (it is not a speed test). */
    struct timespec pause = {.tv_nsec = 50 * 1000 * 1000};
    for (unsigned waited = 0; waited < 20 * 20 && (waited < 20 || atomic_load(&writes) <= 1000 || atomic_load(&total_reads) <= 1000); waited++)
        nanosleep(&pause, NULL);
    atomic_store(&stop, true);
    pthread_join(w, NULL);
    unsigned reads = 0, misses = 0;
    for (int i = 0; i < 3; i++) {
        pthread_join(readers[i], NULL);
        reads += results[i].reads;
        misses += results[i].misses;
    }
    assert(atomic_load(&writes) > 1000 && reads > 1000);
    printf("  stress: %u writes, %u consistent reads, %u bounded-retry misses, 0 torn\n",
           atomic_load(&writes), reads, misses);
}

int main(void) {
    char out[ML_PUBLISHED_NAME_MAX];
    size_t length;
    ml_published_name_t name = {0};

    /* Empty value reads as an empty string. */
    assert(ml_published_name_get(&name, out, sizeof(out), &length) && !length && !out[0]);

    /* A value is replaced whole, including by a shorter one (no stale tail). */
    assert(ml_published_name_set(&name, "dongle.tail1234.ts.net"));
    assert(ml_published_name_get(&name, out, sizeof(out), &length));
    assert(!strcmp(out, "dongle.tail1234.ts.net") && length == 22);
    assert(ml_published_name_set(&name, "gw.corp.ts.net"));
    assert(ml_published_name_get(&name, out, sizeof(out), &length));
    assert(!strcmp(out, "gw.corp.ts.net") && length == 14);
    assert(!(name.seq & 1)); /* stable after every write */

    /* The longest value that fits, and one that does not (rejected untouched). */
    char longest[ML_PUBLISHED_NAME_MAX], toolong[ML_PUBLISHED_NAME_MAX + 1];
    memset(longest, 'x', sizeof(longest) - 1); longest[sizeof(longest) - 1] = 0;
    memset(toolong, 'y', sizeof(toolong) - 1); toolong[sizeof(toolong) - 1] = 0;
    assert(ml_published_name_set(&name, longest));
    assert(!ml_published_name_set(&name, toolong));
    assert(ml_published_name_get(&name, out, sizeof(out), &length));
    assert(!strcmp(out, longest) && length == ML_PUBLISHED_NAME_MAX - 1);

    /* A small destination truncates but stays terminated. */
    char small[8];
    assert(ml_published_name_get(&name, small, sizeof(small), &length));
    assert(length == 7 && !strcmp(small, "xxxxxxx"));
    assert(!ml_published_name_get(&name, small, 0, &length) && length == 0);

    /* A write in progress (odd counter) is never returned, and the reader
     * gives up after a bounded number of attempts instead of spinning. */
    name.seq |= 1;
    memset(out, 'z', sizeof(out));
    assert(!ml_published_name_get(&name, out, sizeof(out), &length));
    assert(out[0] == 0 && length == 0);
    name.seq++;
    assert(ml_published_name_get(&name, out, sizeof(out), &length));

    /* The checker used by the stress run rejects the torn shapes an unlocked
     * strlcpy() produces: letters mixed from two values, or a stale tail. */
    char a[ML_PUBLISHED_NAME_MAX], b[ML_PUBLISHED_NAME_MAX], torn[ML_PUBLISHED_NAME_MAX];
    make_name(3, a); make_name(7, b);
    assert(well_formed(a) && well_formed(b));
    memcpy(torn, a, 5); strcpy(torn + 5, b + 5);      /* head of a, tail of b */
    assert(!well_formed(torn));
    make_name(1, torn); strcat(torn, "tail");          /* stale tail kept */
    assert(!well_formed(torn));

    stress();
    puts("self_dns_name publication: seqlock set/get, truncation, odd-counter retry bound, concurrent writer/readers passed");
    return 0;
}
