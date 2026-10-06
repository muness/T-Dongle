#ifndef WG_CRYPTO_BENCH_H
#define WG_CRYPTO_BENCH_H
/*
 * ChaCha20-Poly1305 self-test and cycle-accurate micro-benchmark.
 *
 * Firmware: reached from the serial console as the single bounded command
 *     crypto bench
 * (control.c). Host: tests/bench_wg_crypto.c links the same code, timing in ns.
 *
 * It first runs a known-answer self-test (RFC 8439 vectors + seal/open + tag
 * rejection), then times ChaCha20, Poly1305 and combined seal/open at 64, 512 and
 * 1400 bytes (plus a misaligned 1400 B seal, which takes the byte-wise path).
 * Output units are CPU cycles on target (esp_cpu_get_cycle_count) or nanoseconds
 * on the host.
 */
#include <stdbool.h>

/* Called once per output line (already terminated with "\r\n"). */
typedef void (*wg_crypto_bench_write_fn)(const char *line);

/* Known-answer test of the code in refc/. Cheap (microseconds). */
bool wg_crypto_selftest(void);

/* Self-test, then benchmark. Returns 0 on success, nonzero if the self-test failed
 * (benchmark numbers are not printed in that case). Allocates ~3 KB of heap
 * temporarily and uses ~1 KB of stack. */
int wg_crypto_bench_run(wg_crypto_bench_write_fn write);

#endif
