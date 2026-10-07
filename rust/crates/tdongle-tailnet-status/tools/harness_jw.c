/* Host harness: the REAL json_writer.inc. One line on stdin per run: "<fail_at> <op>..." where op is r<hex> (jw_raw), s<hex> (jw_string), k<hex> (jw_key),
 * n<decimal> (jw_number), b0|b1 (jw_bool), c<hex byte> (jw_char), f (jw_flush). Output: the chunks as hex, then the flush results. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json_writer.inc"
static unsigned fail_at, seen;
static char out[1 << 20]; static size_t out_len; static unsigned sizes[4096], nchunks;
static int sink(void *ctx, const char *b, size_t n) {
    seen++;
    if (fail_at && seen == fail_at) return -1;
    sizes[nchunks++] = n; memcpy(out + out_len, b, n); out_len += n; return 0;
}
static int unhex(const char *h, char *dst) { size_t n = strlen(h) / 2; for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); dst[i] = v; } dst[n] = 0; return n; }
int main(void) {
    static char line[1 << 20];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        char *save, *tok = strtok_r(line, " ", &save);
        fail_at = atoi(tok); seen = 0; out_len = 0; nchunks = 0;
        jw_writer w = {.sink = sink}; w.context = NULL;
        char results[4096]; size_t rn = 0;
        for (tok = strtok_r(NULL, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
            static char buf[1 << 18];
            switch (tok[0]) {
            case 'r': unhex(tok + 1, buf); results[rn++] = jw_raw(&w, buf) ? '1' : '0'; break;
            case 's': unhex(tok + 1, buf); results[rn++] = jw_string(&w, buf) ? '1' : '0'; break;
            case 'k': unhex(tok + 1, buf); results[rn++] = jw_key(&w, buf) ? '1' : '0'; break;
            case 'n': results[rn++] = jw_number(&w, strtoull(tok + 1, NULL, 10)) ? '1' : '0'; break;
            case 'b': results[rn++] = jw_bool(&w, tok[1] == '1') ? '1' : '0'; break;
            case 'c': { unsigned v; sscanf(tok + 1, "%x", &v); results[rn++] = jw_char(&w, (char)v) ? '1' : '0'; break; }
            case 'f': results[rn++] = jw_flush(&w) ? '1' : '0'; break;
            }
        }
        results[rn] = 0;
        printf("%s %d", results, w.failed);
        for (unsigned i = 0; i < nchunks; i++) printf(" %u", sizes[i]);
        printf("\n");
        for (size_t i = 0; i < out_len; i++) printf("%02x", (unsigned char)out[i]);
        printf("\n");
    }
    return 0;
}
