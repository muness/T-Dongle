/* PHASES variant of host_derp_verify.c (membership-bytes research, 2026-10-05).
 * Adds: peak live heap INSIDE esp_crt_verify_callback (bundle lookup + pk parse + signature check) versus
 * the peak outside it, the live heap when the first callback starts, and the ANCHOR=<der> variant that installs a
 * static trust anchor (a pinned Root/intermediate, parsed once with parse_der_nocopy and shared) in front of the
 * bundle. Build and run: see membership-bytes.md section 4.
 *
 * Original header:
 * Live check of the DERP TLS verification (ml_derp_tls.c + the ESP-IDF
 * esp_crt_bundle.c) against real DERP servers, with heap measured per mode.
 *
 *   build: see tools/test-gateway.sh (same flags as tests/test_derp_tls.c), then
 *   python $IDF_PATH/components/mbedtls/esp_crt_bundle/gen_crt_bundle.py \
 *          --input $IDF_PATH/components/mbedtls/esp_crt_bundle/cacrt_all.pem -q   # -> x509_crt_bundle
 *   ./host_derp_verify x509_crt_bundle derp1.tailscale.com derp10.tailscale.com ...
 *
 * For each host: handshake with VERIFY_NONE (the old behaviour) and with
 * verification, printing the peak live heap of each (host, 64-bit, so struct
 * heavy numbers overstate the device), the live heap after, and the verdict. */
#include <stdbool.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "esp_crt_bundle.h"
#include "ml_derp_tls.h"

extern int esp_crt_verify_callback(void *buf, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
const unsigned char stub_start[1] __asm__("_binary_x509_crt_bundle_start") = {0};
const unsigned char stub_end[1] __asm__("_binary_x509_crt_bundle_end") = {0};

static size_t live, peak;
#define MAXA 65536
static void *ptrs[MAXA]; static size_t sizes[MAXA]; static int np; static size_t snap[MAXA]; static int nsnap;
typedef struct { size_t n; size_t pad; } H;
static void *mycalloc(size_t a, size_t b) {
    size_t n = a * b; H *h = calloc(1, n + sizeof(H)); h->n = n; live += n;
    if (np < MAXA) { ptrs[np] = h + 1; sizes[np++] = n; }
    if (live > peak) { peak = live; nsnap = 0; for (int i = 0; i < np; i++) if (ptrs[i]) snap[nsnap++] = sizes[i]; }
    return h + 1;
}
static void myfree(void *p) { if (!p) return; H *h = (H *)p - 1; live -= h->n; for (int i = 0; i < np; i++) if (ptrs[i] == p) { ptrs[i] = 0; break; } free(h); }
static int by_size(const void *a, const void *b) { return *(size_t *)b > *(size_t *)a ? 1 : -1; }
static int fd;
static int rx(void *c, unsigned char *b, size_t l) { ssize_t n = recv(fd, b, l, 0); return n <= 0 ? MBEDTLS_ERR_SSL_CONN_EOF : (int)n; }
static int tx(void *c, const unsigned char *b, size_t l) { ssize_t n = send(fd, b, l, 0); return n <= 0 ? MBEDTLS_ERR_SSL_CONN_EOF : (int)n; }
static int in_cb, cb_calls; static size_t peak_cb, live_first_cb, peak_out_cb; static bool first_cb;
static mbedtls_x509_crt anchor; static bool have_anchor;
/* SPKI=1 variant (option P1): a presented certificate whose subject AND public key equal a bundle entry is that
 * trust anchor (a cross-signed root); accept it without verifying the cross-signature (RSA-4096 here). Bundle
 * entry layout (esp_crt_bundle.c): [u16 name_len][u16 key_len][subject DER][SubjectPublicKeyInfo DER]. */
static const unsigned char *g_bundle; static size_t g_bundle_len;
static bool spki_anchored(const mbedtls_x509_crt *crt) {
    uint32_t n = ((const uint32_t *)g_bundle)[0] / 4;
    for (uint32_t i = 0; i < n; i++) {
        const unsigned char *e = g_bundle + ((const uint32_t *)g_bundle)[i];
        uint16_t nl = e[0] | (e[1] << 8), kl = e[2] | (e[3] << 8);
        if (nl == crt->subject_raw.len && kl == crt->pk_raw.len && !memcmp(e + 4, crt->subject_raw.p, nl) &&
            !memcmp(e + 4 + nl, crt->pk_raw.p, kl)) return true;
    }
    return false;
}
static int wrap_cb(void *c, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    if (getenv("SPKI") && (*flags & ~(uint32_t)MBEDTLS_X509_BADCERT_BAD_MD) == MBEDTLS_X509_BADCERT_NOT_TRUSTED &&
        spki_anchored(crt)) { *flags = 0; return 0; }
    if (!first_cb) { first_cb = true; live_first_cb = live; }
    size_t before = live; in_cb = 1; cb_calls++; size_t pk0 = peak; peak = live;
    int r = esp_crt_verify_callback(c, crt, depth, flags);
    in_cb = 0; if (peak - before > peak_cb) peak_cb = peak - before; if (pk0 > peak) peak = pk0;
    return r;
}
static int bundle_attach(void *conf) {
    int r = esp_crt_bundle_attach(conf) == 0 ? 0 : -1;
    if (r == 0 && have_anchor) mbedtls_ssl_conf_ca_chain(conf, &anchor, NULL);
    return r;
}

static int handshake(const char *host, bool verify, size_t *peak_out, size_t *after_out, char *why, size_t cap) {
    struct addrinfo hints = {.ai_socktype = SOCK_STREAM}, *res;
    if (getaddrinfo(host, "443", &hints, &res)) { snprintf(why, cap, "dns"); return -1; }
    fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (connect(fd, res->ai_addr, res->ai_addrlen)) { snprintf(why, cap, "connect"); freeaddrinfo(res); close(fd); return -1; }
    freeaddrinfo(res);
    mbedtls_ssl_context ssl; mbedtls_ssl_config conf; mbedtls_entropy_context ent; mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf); mbedtls_entropy_init(&ent); mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, NULL, 0);
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    ml_derp_verify_t v; ml_derp_cert_t cert; ml_derp_cert_parse(host, NULL, &cert);
    static const ml_derp_trust_t trust = {bundle_attach, wrap_cb};
    if (verify) { if (ml_derp_tls_configure(&conf, &v, &cert, host, &trust)) { snprintf(why, cap, "setup"); return -1; } }
    else mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_hostname(&ssl, host);
    mbedtls_ssl_set_bio(&ssl, NULL, tx, rx, NULL);
    size_t base = live; peak = live; nsnap = 0; first_cb = false; cb_calls = 0; peak_cb = 0; live_first_cb = 0;
    int r;
    while ((r = mbedtls_ssl_handshake(&ssl)) != 0 && (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)) {}
    if (verify) ml_derp_tls_finish(&conf);
    if (r) ml_derp_tls_describe(&ssl, r, verify ? &v : NULL, why, cap); else snprintf(why, cap, "%s", mbedtls_ssl_get_ciphersuite(&ssl));
    if (getenv("ALLOCS")) { qsort(snap, nsnap, sizeof(size_t), by_size); printf("  %s allocations live at the peak (%d): ", verify ? "verify" : "none", nsnap); for (int k = 0; k < nsnap && k < 16; k++) printf("%zu ", snap[k]); printf("\n"); }
    if (verify) printf("  [phases] callbacks=%d live_at_first_callback=%zu peak_inside_callbacks=%zu\n", cb_calls, live_first_cb ? live_first_cb - base : 0, peak_cb);
    *peak_out = peak - base; *after_out = live >= base ? live - base : 0;
    mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf); mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&ent);
    close(fd);
    return r;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    mbedtls_platform_set_calloc_free(mycalloc, myfree);
    FILE *f = fopen(argv[1], "rb"); fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *bundle = malloc(n); fread(bundle, 1, n, f); fclose(f);
    if (esp_crt_bundle_set(bundle, n)) { puts("bad bundle"); return 2; }
    g_bundle = bundle; g_bundle_len = n;
    if (getenv("ANCHOR")) { FILE *a = fopen(getenv("ANCHOR"), "rb"); static unsigned char der[4096]; size_t dn = fread(der, 1, sizeof der, a); fclose(a);
        mbedtls_x509_crt_init(&anchor); if (mbedtls_x509_crt_parse_der_nocopy(&anchor, der, dn)) { puts("bad anchor"); return 2; } have_anchor = true; }
    int ok = 0, bad = 0;
    size_t worst_delta = 0, best_delta = (size_t)-1, sum_delta = 0;
    for (int i = 2; i < argc; i++) {
        size_t p0, a0, p1, a1; char w0[200], w1[300];
        int r0 = handshake(argv[i], false, &p0, &a0, w0, sizeof(w0));
        int r1 = handshake(argv[i], true, &p1, &a1, w1, sizeof(w1));
        printf("%-28s none: %s peak=%zu after=%zu | verify: %s peak=%zu after=%zu | %s\n", argv[i],
               r0 ? "FAIL" : "ok", p0, a0, r1 ? "FAIL" : "ok", p1, a1, r1 ? w1 : "verified");
        if (!r1) { ok++; size_t d = p1 > p0 ? p1 - p0 : 0; sum_delta += d; if (d > worst_delta) worst_delta = d; if (d < best_delta) best_delta = d; } else bad++;
    }
    printf("verified %d, failed %d; extra peak heap with verification: min %zu avg %zu max %zu bytes (host, 64-bit)\n",
           ok, bad, ok ? best_delta : 0, ok ? sum_delta / ok : 0, worst_delta);
    return bad != 0;
}
