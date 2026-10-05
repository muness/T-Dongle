/* Host benchmark for the WireGuard ChaCha20-Poly1305: same code as the on-target `crypto bench`
 * (wg_crypto_bench.c), timing in ns. Build with -O2/-Os and compare against the legacy
 * implementation by defining CONFIG_WG_CRYPTO_BENCH_BASELINE=1 and linking
 * wg_crypto_legacy.c. See tools/bench-wg-crypto.sh. */
#include <stdio.h>
#include "wg_crypto_bench.h"

static void out(const char *line) { fputs(line, stdout); }

int main(void) {
    return wg_crypto_bench_run(out);
}
