// SPDX-License-Identifier: MIT
#include "captive_dns.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t DONGLE[4] = {192, 168, 4, 1};
/* A query for `name` (dotted) of the given type, id 0x1234, recursion desired. */
static size_t query(uint8_t *q, const char *name, unsigned type, unsigned klass) {
    memset(q, 0, 12);
    q[0] = 0x12; q[1] = 0x34; q[2] = 0x01; q[5] = 1;
    size_t n = 12;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        q[n++] = (uint8_t)len;
        memcpy(q + n, p, len); n += len;
        p += len; if (*p == '.') p++;
    }
    q[n++] = 0;
    q[n++] = (uint8_t)(type >> 8); q[n++] = (uint8_t)type; q[n++] = (uint8_t)(klass >> 8); q[n++] = (uint8_t)klass;
    return n;
}
static void a_record(void) {
    uint8_t q[512], r[512];
    size_t n = query(q, "captive.apple.com", 1, 1);
    size_t m = captive_dns_reply(q, n, r, sizeof(r), DONGLE);
    assert(m == n + 16);
    assert(r[0] == 0x12 && r[1] == 0x34);                      /* same id */
    assert((r[2] & 0x80) && !(r[2] & 0x78) && (r[2] & 1) && r[3] == 0x80);   /* response, standard query, RD kept, RA, NOERROR */
    assert(r[4] == 0 && r[5] == 1 && r[6] == 0 && r[7] == 1 && !r[8] && !r[9] && !r[10] && !r[11]);   /* one question, one answer */
    assert(!memcmp(r + 12, q + 12, n - 12));                   /* the question is echoed exactly */
    const uint8_t *a = r + n;
    assert(a[0] == 0xc0 && a[1] == 0x0c && a[2] == 0 && a[3] == 1 && a[4] == 0 && a[5] == 1 && a[6] == 0 && a[7] == 0 && a[8] == 0 && a[9] == 60 && a[10] == 0 && a[11] == 4);
    assert(!memcmp(a + 12, DONGLE, 4));
    /* Names of every shape get the same answer: that is what makes the portal open by itself. */
    const char *names[] = {"connectivitycheck.gstatic.com", "www.msftconnecttest.com", "neverssl.com", "a", "x.y.z.example.org", "detectportal.firefox.com"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        n = query(q, names[i], 1, 1);
        assert(captive_dns_reply(q, n, r, sizeof(r), DONGLE) == n + 16);
    }
}
static void other_types_get_an_empty_answer(void) {
    uint8_t q[512], r[512];
    size_t n = query(q, "captive.apple.com", 28, 1);   /* AAAA */
    size_t m = captive_dns_reply(q, n, r, sizeof(r), DONGLE);
    assert(m == n && r[3] == 0x80 && r[6] == 0 && r[7] == 0);
    n = query(q, "captive.apple.com", 1, 3);           /* class CH */
    assert(captive_dns_reply(q, n, r, sizeof(r), DONGLE) == n && r[7] == 0);
    n = query(q, "captive.apple.com", 65, 1);          /* HTTPS */
    assert(captive_dns_reply(q, n, r, sizeof(r), DONGLE) == n && r[7] == 0);
}
static void things_that_are_ignored(void) {
    uint8_t q[512], r[512];
    size_t n = query(q, "example.com", 1, 1);
    assert(!captive_dns_reply(q, 0, r, sizeof(r), DONGLE) && !captive_dns_reply(q, 11, r, sizeof(r), DONGLE) && !captive_dns_reply(q, 16, r, sizeof(r), DONGLE));
    uint8_t m[512];
    memcpy(m, q, n); m[2] |= 0x80; assert(!captive_dns_reply(m, n, r, sizeof(r), DONGLE));          /* a response: never answer an answer */
    memcpy(m, q, n); m[2] |= 0x08; assert(!captive_dns_reply(m, n, r, sizeof(r), DONGLE));          /* opcode 1 */
    memcpy(m, q, n); m[5] = 2; assert(!captive_dns_reply(m, n, r, sizeof(r), DONGLE));              /* two questions */
    memcpy(m, q, n); m[5] = 0; assert(!captive_dns_reply(m, n, r, sizeof(r), DONGLE));              /* none */
    memcpy(m, q, n); m[12] = 0xc0; assert(!captive_dns_reply(m, n, r, sizeof(r), DONGLE));          /* compression pointer in a question */
    memcpy(m, q, n); m[12] = 64; assert(!captive_dns_reply(m, n, r, sizeof(r), DONGLE));            /* label longer than 63 */
    for (size_t cut = 0; cut < n; cut++) assert(captive_dns_reply(q, cut, r, sizeof(r), DONGLE) == 0 || cut == n);   /* any truncation */
    uint8_t unterminated[40];
    memset(unterminated, 5, sizeof(unterminated)); memset(unterminated, 0, 12); unterminated[5] = 1;
    assert(!captive_dns_reply(unterminated, sizeof(unterminated), r, sizeof(r), DONGLE));           /* a name that runs off the packet */
    assert(!captive_dns_reply(q, n, r, n + 15, DONGLE));                                            /* output too small for the answer */
    assert(captive_dns_reply(q, n, r, n + 16, DONGLE) == n + 16);
}
static void trailing_data_is_not_copied(void) {
    uint8_t q[512], r[512];
    size_t n = query(q, "example.com", 1, 1);
    memset(q + n, 0xee, 100);   /* additional records (EDNS) the question does not need */
    size_t m = captive_dns_reply(q, n + 100, r, sizeof(r), DONGLE);
    assert(m == n + 16);
    for (size_t i = n + 16; i < sizeof(r); i += 37) (void)r[i];
}
int main(void) {
    a_record(); other_types_get_an_empty_answer(); things_that_are_ignored(); trailing_data_is_not_copied();
    puts("Captive DNS: A answered with the dongle, other types empty, responses/compression/truncation/oversize ignored");
    return 0;
}
