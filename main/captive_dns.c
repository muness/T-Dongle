// SPDX-License-Identifier: MIT
#include "captive_dns.h"
#include <stdbool.h>
#include <string.h>

enum { HEADER = 12, TYPE_A = 1, CLASS_IN = 1, ANSWER_BYTES = 16 };

size_t captive_dns_reply(const uint8_t *q, size_t n, uint8_t *out, size_t capacity, const uint8_t answer_ipv4[4]) {
    if (n < HEADER + 5) return 0;
    unsigned flags = (unsigned)(q[2] << 8 | q[3]);
    if (flags & 0x8000) return 0;                          /* a response, not a query */
    if (((flags >> 11) & 15) != 0) return 0;               /* only standard queries */
    if ((q[4] << 8 | q[5]) != 1) return 0;                 /* exactly one question */
    size_t i = HEADER;
    while (i < n && q[i]) {
        if (q[i] > 63) return 0;                            /* a compression pointer or an invalid label in a question */
        i += (size_t)q[i] + 1;
    }
    if (i + 5 > n) return 0;                               /* the name's end, then QTYPE and QCLASS */
    unsigned qtype = (unsigned)(q[i + 1] << 8 | q[i + 2]), qclass = (unsigned)(q[i + 3] << 8 | q[i + 4]);
    size_t question_end = i + 5;
    bool answer = qtype == TYPE_A && qclass == CLASS_IN;
    size_t total = question_end + (answer ? ANSWER_BYTES : 0);
    if (total > capacity) return 0;
    memcpy(out, q, question_end);
    out[2] = (uint8_t)(0x80 | (q[2] & 0x01));              /* QR, standard query, recursion desired as asked */
    out[3] = 0x80;                                          /* recursion available, no error */
    out[6] = 0;
    out[7] = answer ? 1 : 0;
    out[4] = 0; out[5] = 1;
    out[8] = out[9] = out[10] = out[11] = 0;
    if (answer) {
        const uint8_t record[ANSWER_BYTES - 4] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4};
        memcpy(out + question_end, record, sizeof(record));
        memcpy(out + question_end + sizeof(record), answer_ipv4, 4);
    }
    return total;
}
