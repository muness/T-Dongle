#define _GNU_SOURCE 1
/* DERP TLS server authentication against real mbedTLS handshakes.
 *
 * ml_derp_tls.c and the ESP-IDF esp_crt_bundle.c (the code the firmware uses as
 * its trust store) are compiled unchanged. A TLS 1.2 mbedTLS server on an
 * in-memory pipe presents certificates from a generated PKI (tests/derp_pki.py);
 * the client is configured exactly as ml_derp_connect() configures it. */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "esp_crt_bundle.h"
#include "ml_derp_tls.h"

extern int esp_crt_verify_callback(void *buf, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
const uint8_t bundle_start_stub[1] __asm__("_binary_x509_crt_bundle_start") = {0};
const uint8_t bundle_end_stub[1] __asm__("_binary_x509_crt_bundle_end") = {0};

static const char *pki;
static char path_buf[512];
static const char *file(const char *name, const char *ext) {
    snprintf(path_buf, sizeof(path_buf), "%s/%s%s", pki, name, ext);
    return path_buf;
}
static uint8_t *slurp(const char *path, size_t *length) {
    FILE *f = fopen(path, "rb");
    assert(f);
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc((size_t)n + 1);
    assert(fread(data, 1, (size_t)n, f) == (size_t)n);
    data[n] = 0;
    fclose(f);
    *length = (size_t)n + 1; /* PEM parsers want the NUL */
    return data;
}

/* ---- in-memory pipe -------------------------------------------------------- */
typedef struct { uint8_t data[1 << 16]; size_t r, w; } pipe_t;
typedef struct { pipe_t *in, *out; } end_t;
static int pipe_send(void *ctx, const unsigned char *buf, size_t len) {
    end_t *e = ctx;
    assert(e->out->w + len <= sizeof(e->out->data));
    memcpy(e->out->data + e->out->w, buf, len);
    e->out->w += len;
    return (int)len;
}
static int pipe_recv(void *ctx, unsigned char *buf, size_t len) {
    end_t *e = ctx;
    size_t have = e->in->w - e->in->r;
    if (!have) return MBEDTLS_ERR_SSL_WANT_READ;
    if (len > have) len = have;
    memcpy(buf, e->in->data + e->in->r, len);
    e->in->r += len;
    return (int)len;
}

/* ---- the trust store the firmware uses ------------------------------------ */
static int bundle_attach(void *conf) { return esp_crt_bundle_attach(conf) == ESP_OK ? 0 : -1; }
static const uint8_t *held;      /* the bundle esp_crt_bundle_attach() trusts */
static size_t held_len;
/* The firmware's is_anchor() (ml_derp.c derp_is_trust_anchor) asks the same question of its embedded bundle. */
static bool bundle_is_anchor(const mbedtls_x509_crt *crt) { return ml_derp_bundle_has_anchor(held, held_len, crt); }
/* One trust store, run with and without the trust-anchor match: every scenario must give the same verdict. */
static ml_derp_trust_t bundle_trust_obj = { .attach = bundle_attach, .trust = esp_crt_verify_callback, .is_anchor = bundle_is_anchor };
#define bundle_trust bundle_trust_obj
static int refusing_attach(void *conf) { (void)conf; return -1; }
static const ml_derp_trust_t broken_trust = { .attach = refusing_attach, .trust = esp_crt_verify_callback };

static void use_bundle(const char *name) {
    size_t n;
    free((void *)held);
    held = slurp(file(name, ""), &n);
    held_len = n - 1;
    assert(esp_crt_bundle_set(held, held_len) == ESP_OK);
}

/* ---- heap accounting of the client handshake ------------------------------ */
/* mbedTLS allocates through these hooks. Blocks allocated while the client's handshake runs are counted; the
 * peak is the most such bytes live at once (the transient the DERP task needs, host 64-bit sizes). */
typedef union { struct { size_t n; int counted; } h; max_align_t align; } mem_hdr_t;
static int mem_scope;
static size_t mem_live, mem_peak;
static void *counting_calloc(size_t a, size_t b) {
    mem_hdr_t *h = calloc(1, sizeof(*h) + a * b);
    if (!h) return NULL;
    h->h.n = a * b; h->h.counted = mem_scope;
    if (mem_scope) { mem_live += h->h.n; if (mem_live > mem_peak) mem_peak = mem_live; }
    return h + 1;
}
static void counting_free(void *p) {
    if (!p) return;
    mem_hdr_t *h = (mem_hdr_t *)p - 1;
    if (h->h.counted) mem_live -= h->h.n;
    free(h);
}

/* ---- one handshake --------------------------------------------------------- */
typedef struct {
    const char *server_pem;     /* file stem: certificate(s) the server presents */
    const char *server_key;     /* file stem: its private key */
    const char *sni;            /* the node's HostName */
    const char *cert_name;      /* the node's CertName, or NULL */
    const ml_derp_trust_t *trust;
} scenario_t;
typedef struct {
    int client_error;           /* 0 = connected */
    uint32_t flags;
    size_t peak;                /* client handshake peak heap (bytes) */
    char sni_seen[64];
    char why[300];
    ml_derp_verify_t verify;
    bool configured;
} outcome_t;

static char server_sni[64];
static int sni_callback(void *p, mbedtls_ssl_context *ssl, const unsigned char *name, size_t len) {
    (void)p; (void)ssl;
    snprintf(server_sni, sizeof(server_sni), "%.*s", (int)len, name);
    return 0;
}

static outcome_t connect_to(const scenario_t *sc) {
    outcome_t out = {0};
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    assert(!mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0));

    /* Server. */
    mbedtls_ssl_config sconf; mbedtls_ssl_context sssl; mbedtls_x509_crt chain; mbedtls_pk_context key;
    mbedtls_ssl_config_init(&sconf); mbedtls_ssl_init(&sssl); mbedtls_x509_crt_init(&chain); mbedtls_pk_init(&key);
    size_t n;
    uint8_t *pem = slurp(file(sc->server_pem, ".pem"), &n);
    assert(!mbedtls_x509_crt_parse(&chain, pem, n));
    free(pem);
    uint8_t *kpem = slurp(file(sc->server_key, ".key"), &n);
    assert(!mbedtls_pk_parse_key(&key, kpem, n, NULL, 0, mbedtls_ctr_drbg_random, &drbg));
    free(kpem);
    assert(!mbedtls_ssl_config_defaults(&sconf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
    mbedtls_ssl_conf_rng(&sconf, mbedtls_ctr_drbg_random, &drbg);
    assert(!mbedtls_ssl_conf_own_cert(&sconf, &chain, &key));
    mbedtls_ssl_conf_sni(&sconf, sni_callback, NULL);
    assert(!mbedtls_ssl_setup(&sssl, &sconf));

    /* Client, set up the way ml_derp_connect() does. */
    mbedtls_ssl_config cconf; mbedtls_ssl_context cssl;
    mbedtls_ssl_config_init(&cconf); mbedtls_ssl_init(&cssl);
    assert(!mbedtls_ssl_config_defaults(&cconf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));
    ml_derp_cert_t cert;
    ml_derp_cert_parse(sc->sni, sc->cert_name, &cert);
    int cfg = ml_derp_tls_configure(&cconf, &out.verify, &cert, sc->sni, sc->trust);
    out.configured = cfg == 0;
    if (cfg != 0) {
        out.client_error = cfg;
        ml_derp_tls_describe(NULL, cfg, NULL, out.why, sizeof(out.why));
    } else {
        mbedtls_ssl_conf_rng(&cconf, mbedtls_ctr_drbg_random, &drbg);
        assert(!mbedtls_ssl_setup(&cssl, &cconf));
        assert(!mbedtls_ssl_set_hostname(&cssl, sc->sni));
        static pipe_t a, b;
        memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b));
        end_t client = { &b, &a }, server = { &a, &b };
        mbedtls_ssl_set_bio(&cssl, &client, pipe_send, pipe_recv, NULL);
        mbedtls_ssl_set_bio(&sssl, &server, pipe_send, pipe_recv, NULL);
        server_sni[0] = 0;
        mem_live = mem_peak = 0;
        int c = 1, s = 1;
        for (int i = 0; i < 2000 && (c || s); i++) {
            if (c) {
                mem_scope = 1;
                c = mbedtls_ssl_handshake(&cssl);
                mem_scope = 0;
                if (c && c != MBEDTLS_ERR_SSL_WANT_READ && c != MBEDTLS_ERR_SSL_WANT_WRITE) { out.client_error = c; break; }
            }
            if (s) {
                s = mbedtls_ssl_handshake(&sssl);
                if (s && s != MBEDTLS_ERR_SSL_WANT_READ && s != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    if (!c) break;
                    /* The server failing on the client's alert is the expected echo of a client rejection. */
                    if (!out.client_error) out.client_error = c;
                }
            }
        }
        if (c && !out.client_error) out.client_error = c;
        out.flags = mbedtls_ssl_get_verify_result(&cssl);
        out.peak = mem_peak;
        ml_derp_tls_finish(&cconf);
        ml_derp_tls_describe(&cssl, out.client_error, &out.verify, out.why, sizeof(out.why));
        snprintf(out.sni_seen, sizeof(out.sni_seen), "%s", server_sni);
    }
    mbedtls_ssl_free(&cssl); mbedtls_ssl_config_free(&cconf);
    mbedtls_ssl_free(&sssl); mbedtls_ssl_config_free(&sconf);
    mbedtls_x509_crt_free(&chain); mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&entropy);
    return out;
}

static unsigned cases;
#define EXPECT_OK(r) do { outcome_t o_ = (r); if (o_.client_error) printf("unexpected failure: %s\n", o_.why); assert(!o_.client_error && o_.configured); cases++; } while (0)
#define EXPECT_FAIL(r, flag) do { outcome_t o_ = (r); if (!o_.client_error) printf("unexpected success at line %d\n", __LINE__); \
    assert(o_.client_error); if (flag) { uint32_t f_ = (flag); if (!((o_.flags | o_.verify.verdict_flags) & f_)) printf("flags %08x, wanted %08x: %s\n", o_.flags | o_.verify.verdict_flags, f_, o_.why); \
    assert((o_.flags | o_.verify.verdict_flags) & f_); } assert(o_.why[0]); cases++; } while (0)

static char pin_text[128];
static const char *pin_of(const char *stem) {
    size_t n;
    uint8_t *hex = slurp(file(stem, ".sha256"), &n);
    snprintf(pin_text, sizeof(pin_text), ML_DERP_PIN_PREFIX "%s", hex);
    free(hex);
    return pin_text;
}

static void parse_cases(void) {
    ml_derp_cert_t c;
    const char *hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    char text[200];
    assert(ml_derp_cert_parse("derp1.example", NULL, &c) && c.kind == ML_DERP_CERT_HOSTNAME);
    assert(ml_derp_cert_parse("derp1.example", "", &c) && c.kind == ML_DERP_CERT_HOSTNAME);
    assert(ml_derp_cert_parse("derp1.example", "DERP1.example.", &c) && c.kind == ML_DERP_CERT_HOSTNAME); /* same name */
    assert(ml_derp_cert_parse("derp1.example", "front.example", &c) && c.kind == ML_DERP_CERT_NAME && !strcmp(c.v.name, "front.example"));
    snprintf(text, sizeof(text), "sha256-raw:%s", hex);
    assert(ml_derp_cert_parse("10.0.0.1", text, &c) && c.kind == ML_DERP_CERT_PIN && c.v.sha256[0] == 0x00 && c.v.sha256[31] == 0xff);
    snprintf(text, sizeof(text), "sha256-raw:%.62s", hex);                       /* short */
    assert(!ml_derp_cert_parse("h", text, &c) && c.kind == ML_DERP_CERT_INVALID);
    snprintf(text, sizeof(text), "sha256-raw:%s00", hex);                        /* long */
    assert(!ml_derp_cert_parse("h", text, &c) && c.kind == ML_DERP_CERT_INVALID);
    snprintf(text, sizeof(text), "sha256-raw:%.63sg", hex);                      /* not hex */
    assert(!ml_derp_cert_parse("h", text, &c) && c.kind == ML_DERP_CERT_INVALID);
    assert(!ml_derp_cert_parse("h", "sha256-raw:", &c) && c.kind == ML_DERP_CERT_INVALID);
    memset(text, 'a', 64); text[64] = 0;                                         /* 64 chars: does not fit with NUL */
    assert(!ml_derp_cert_parse("h", text, &c) && c.kind == ML_DERP_CERT_INVALID);
    assert(!ml_derp_cert_parse("h", "bad name", &c) && c.kind == ML_DERP_CERT_INVALID);
    assert(!ml_derp_cert_parse("h", "evil\r\nname", &c) && c.kind == ML_DERP_CERT_INVALID);
    cases += 12;
}

/* Every pre-existing scenario (valid chain, host names, untrusted, validity, wildcard, IP, CertName, pin, fail-closed
 * setup, repeatability). Run once per trust-anchor mode with identical expectations: matching the store's anchors
 * must not change a single verdict for these chains. */
static void suite(void) {

    /* 1. The normal case: chain to a trusted root, name HostName. */
    use_bundle("bundle_root");
    EXPECT_OK(connect_to(&(scenario_t){ "ok", "ok", "derp1.test.example", NULL, &bundle_trust }));
    EXPECT_OK(connect_to(&(scenario_t){ "ok", "ok", "DERP1.Test.Example", NULL, &bundle_trust }));       /* case-insensitive */
    EXPECT_OK(connect_to(&(scenario_t){ "ok", "ok", "derp1.test.example", "derp1.test.example", &bundle_trust })); /* CertName == HostName */
    /* The intermediate need not be sent only if it is in the bundle; here it is sent. */

    /* 2. Wrong host name. */
    EXPECT_FAIL(connect_to(&(scenario_t){ "other", "other", "derp1.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);
    EXPECT_FAIL(connect_to(&(scenario_t){ "ok", "ok", "derp2.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);
    EXPECT_FAIL(connect_to(&(scenario_t){ "ok", "ok", "xderp1.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);
    EXPECT_FAIL(connect_to(&(scenario_t){ "cn_only", "cn_only", "derp1.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH); /* SAN only */

    /* 3. Untrusted. */
    EXPECT_FAIL(connect_to(&(scenario_t){ "rogue_signed", "rogue_signed", "derp1.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    EXPECT_FAIL(connect_to(&(scenario_t){ "pin", "pin", "pin.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_NOT_TRUSTED);   /* self-signed, no pin */
    EXPECT_FAIL(connect_to(&(scenario_t){ "direct", "direct", "derp1.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_NOT_TRUSTED); /* intermediate absent */
    use_bundle("bundle_rogue");
    EXPECT_FAIL(connect_to(&(scenario_t){ "ok", "ok", "derp1.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    EXPECT_OK(connect_to(&(scenario_t){ "rogue_signed", "rogue_signed", "derp1.test.example", NULL, &bundle_trust })); /* its own bundle trusts it */
    use_bundle("bundle_root");

    /* 4. Validity period. */
    EXPECT_FAIL(connect_to(&(scenario_t){ "expired", "expired", "derp1.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_EXPIRED);
    EXPECT_FAIL(connect_to(&(scenario_t){ "future", "future", "derp1.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_FUTURE);

    /* 5. Wildcards: one label, left-most only. */
    EXPECT_OK(connect_to(&(scenario_t){ "wild", "wild", "a.wild.example", NULL, &bundle_trust }));
    EXPECT_FAIL(connect_to(&(scenario_t){ "wild", "wild", "a.b.wild.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);
    EXPECT_FAIL(connect_to(&(scenario_t){ "wild", "wild", "wild.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);

    /* 6. IP literals (Tailscale verifies the dialled name, an IP SAN satisfies it). */
    EXPECT_OK(connect_to(&(scenario_t){ "ip", "ip", "192.0.2.7", NULL, &bundle_trust }));
    EXPECT_FAIL(connect_to(&(scenario_t){ "ip", "ip", "192.0.2.8", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);
    EXPECT_FAIL(connect_to(&(scenario_t){ "ok", "ok", "192.0.2.7", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);   /* IP-only node, no CertName, name cert: fail closed */

    /* 7. CertName: SNI stays HostName, the certificate must name CertName. */
    outcome_t o = connect_to(&(scenario_t){ "front", "front", "front.example", "derp1.test.example", &bundle_trust });
    assert(!o.client_error && !strcmp(o.sni_seen, "front.example")); cases++;
    EXPECT_FAIL(connect_to(&(scenario_t){ "front", "front", "front.example", "other.example", &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);
    EXPECT_FAIL(connect_to(&(scenario_t){ "front", "front", "derp1.test.example", "other.example", &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH); /* HostName alone no longer enough */
    EXPECT_FAIL(connect_to(&(scenario_t){ "rogue_signed", "rogue_signed", "front.example", "derp1.test.example", &bundle_trust }), MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    EXPECT_FAIL(connect_to(&(scenario_t){ "direct", "direct", "front.example", "derp1.test.example", &bundle_trust }), MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    EXPECT_FAIL(connect_to(&(scenario_t){ "expired", "expired", "front.example", "derp1.test.example", &bundle_trust }), MBEDTLS_X509_BADCERT_EXPIRED);

    /* 8. sha256-raw pin: no chain, exact certificate, still named and in date. */
    char pin[96];
    snprintf(pin, sizeof(pin), "%s", pin_of("pin"));
    EXPECT_OK(connect_to(&(scenario_t){ "pin", "pin", "pin.example", pin, &bundle_trust }));
    EXPECT_OK(connect_to(&(scenario_t){ "pin", "pin", "127.0.0.1", pin, &bundle_trust }));            /* IP-literal HostName */
    EXPECT_OK(connect_to(&(scenario_t){ "pin", "pin", "pin.example", pin, NULL }));                   /* needs no trust store */
    EXPECT_FAIL(connect_to(&(scenario_t){ "pin_other", "pin_other", "pin.example", pin, &bundle_trust }), MBEDTLS_X509_BADCERT_NOT_TRUSTED); /* different cert, same name */
    EXPECT_FAIL(connect_to(&(scenario_t){ "ok", "ok", "derp1.test.example", pin, &bundle_trust }), MBEDTLS_X509_BADCERT_NOT_TRUSTED);      /* a CA-valid cert is not the pinned one */
    EXPECT_FAIL(connect_to(&(scenario_t){ "pin", "pin", "other.example", pin, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);          /* pinned, wrong name */
    snprintf(pin, sizeof(pin), "%s", pin_of("pin_expired"));
    EXPECT_FAIL(connect_to(&(scenario_t){ "pin_expired", "pin_expired", "pin.example", pin, &bundle_trust }), MBEDTLS_X509_BADCERT_EXPIRED);
    snprintf(pin, sizeof(pin), "%s", pin_of("pin_wrong_name"));
    EXPECT_FAIL(connect_to(&(scenario_t){ "pin_wrong_name", "pin_wrong_name", "pin.example", pin, &bundle_trust }), MBEDTLS_X509_BADCERT_CN_MISMATCH);
    snprintf(pin, sizeof(pin), "%s", pin_of("pin"));
    EXPECT_FAIL(connect_to(&(scenario_t){ "pin_plus_extra", "pin_plus_extra", "pin.example", pin, &bundle_trust }), 0);   /* two certificates presented */

    /* 9. Fail closed when verification cannot be set up. */
    outcome_t bad = connect_to(&(scenario_t){ "ok", "ok", "derp1.test.example", NULL, &broken_trust });
    assert(!bad.configured && bad.client_error); cases++;
    bad = connect_to(&(scenario_t){ "ok", "ok", "derp1.test.example", NULL, NULL });
    assert(!bad.configured && bad.client_error); cases++;
    bad = connect_to(&(scenario_t){ "ok", "ok", "derp1.test.example", "sha256-raw:00", &bundle_trust }); /* malformed pin => INVALID => refused */
    assert(!bad.configured && bad.client_error); cases++;
    bad = connect_to(&(scenario_t){ "ok", "ok", "derp1.test.example", "bad name", &bundle_trust });
    assert(!bad.configured); cases++;

    /* 10. Failure is clean and repeatable: no leak, no crash, the next connect works (ASan checks the rest). */
    for (int i = 0; i < 25; i++) {
        EXPECT_FAIL(connect_to(&(scenario_t){ "rogue_signed", "rogue_signed", "derp1.test.example", NULL, &bundle_trust }), MBEDTLS_X509_BADCERT_NOT_TRUSTED);
        EXPECT_OK(connect_to(&(scenario_t){ "ok", "ok", "derp1.test.example", NULL, &bundle_trust }));
    }
    char text[300];
    o = connect_to(&(scenario_t){ "other", "other", "derp1.test.example", NULL, &bundle_trust });
    snprintf(text, sizeof(text), "%s", o.why);
    assert(strstr(text, "X509") && strstr(text, "does not match") != NULL);

}

/* ---- trust-anchor match: cross-signed root ----------------------------------------------------------------- */
/* DERP presents  leaf <- intermediate <- "X2" (cross-certificate signed by the RSA-4096 "X1").  X1 and X2 are both
 * in the bundle. The match must (a) accept the presented X2 as the anchor it is, with a smaller peak because the
 * RSA-4096 signature is never verified, and (b) accept nothing else. */
static outcome_t cross(const char *stem, const char *sni, const char *cert_name, const char *bundle, bool anchor) {
    use_bundle(bundle);
    bundle_trust_obj.is_anchor = anchor ? bundle_is_anchor : NULL;
    return connect_to(&(scenario_t){ stem, stem, sni, cert_name, &bundle_trust });
}
#define HOST "derp1.test.example"
/* The same verdict with the anchor match on and off; returns the "on" outcome. */
static outcome_t both_fail(const char *stem, const char *sni, const char *cert_name, const char *bundle, uint32_t flag) {
    outcome_t off = cross(stem, sni, cert_name, bundle, false);
    EXPECT_FAIL(off, flag);
    assert(off.verify.anchor_hits == 0);
    outcome_t on = cross(stem, sni, cert_name, bundle, true);
    EXPECT_FAIL(on, flag);
    return on;
}

static void cross_cases(void) {
    outcome_t on, off;

    /* a. The real shape: X1 and X2 both in the store. */
    off = cross("xok", HOST, NULL, "bundle_cross", false);
    EXPECT_OK(off); assert(off.verify.anchor_hits == 0);                     /* verified through X1 (RSA) */
    on = cross("xok", HOST, NULL, "bundle_cross", true);
    EXPECT_OK(on); assert(on.verify.anchor_hits == 1);                       /* X2 taken as the anchor itself */
    printf("cross-signed root, host heap peak of the client handshake: %zu B verifying the RSA-4096 cross-signature, "
           "%zu B matching the anchor (-%zu B)\n", off.peak, on.peak, off.peak - on.peak);
    assert(on.peak + 2500 <= off.peak);                                      /* three RSA-4096 integers and their work area */
    /* b. X1 is not needed once X2 is the anchor; without the match it is (the match is what trusts X2 here). */
    on = cross("xok", HOST, NULL, "bundle_x2", true);
    EXPECT_OK(on); assert(on.verify.anchor_hits == 1);
    off = cross("xok", HOST, NULL, "bundle_x2", false);
    EXPECT_FAIL(off, MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    /* c. Only X1 in the store: X2 is not an anchor, the RSA path still works and the match is never claimed. */
    on = cross("xok", HOST, NULL, "bundle_x1", true);
    EXPECT_OK(on); assert(on.verify.anchor_hits == 0);
    /* d. A store that trusts neither. */
    on = both_fail("xok", HOST, NULL, "bundle_rogue", MBEDTLS_X509_BADCERT_NOT_TRUSTED);
    assert(on.verify.anchor_hits == 0);

    /* e. Everything below the anchor is still verified: host name, CertName, validity of leaf, intermediate and the
     *    presented certificate itself, in both modes and in the store where the match is the only way in. */
    static const char *const stores[] = { "bundle_cross", "bundle_x2" };
    for (unsigned i = 0; i < 2; i++) {
        const char *b = stores[i];
        both_fail("xother", HOST, NULL, b, MBEDTLS_X509_BADCERT_CN_MISMATCH);                  /* wrong host */
        both_fail("xok", "derp2.test.example", NULL, b, MBEDTLS_X509_BADCERT_CN_MISMATCH);
        both_fail("xleaf_expired", HOST, NULL, b, MBEDTLS_X509_BADCERT_EXPIRED);               /* expired leaf */
        both_fail("xinter_expired", HOST, NULL, b, MBEDTLS_X509_BADCERT_EXPIRED);              /* expired intermediate */
        both_fail("xanchor_expired", HOST, NULL, b, MBEDTLS_X509_BADCERT_EXPIRED);             /* expired presented anchor */
        both_fail("xanchor_future", HOST, NULL, b, MBEDTLS_X509_BADCERT_FUTURE);               /* not yet valid anchor */
        /* CertName: the SNI stays HostName, the chain must name CertName. */
        on = cross("xfront", "front.example", HOST, b, true);
        assert(!on.client_error && !strcmp(on.sni_seen, "front.example") && on.verify.anchor_hits == 1); cases++;
        both_fail("xfront", "front.example", "other.example", b, MBEDTLS_X509_BADCERT_CN_MISMATCH);
        /* Same subject DN, different key; a cross-certificate signed by an impostor carrying X1's name; the right
         * key under another subject DN: none is the anchor, none verifies. */
        on = both_fail("xfake_self", HOST, NULL, b, MBEDTLS_X509_BADCERT_NOT_TRUSTED); assert(on.verify.anchor_hits == 0);
        on = both_fail("xfake_cross", HOST, NULL, b, MBEDTLS_X509_BADCERT_NOT_TRUSTED); assert(on.verify.anchor_hits == 0);
        on = both_fail("xrenamed", HOST, NULL, b, MBEDTLS_X509_BADCERT_NOT_TRUSTED); assert(on.verify.anchor_hits == 0);
        /* The anchor's own certificate as the server's certificate: the leaf is never taken as an anchor (no SAN, so
         * the host name fails; the anchor counter stays at zero). */
        on = both_fail("x2", HOST, NULL, b, MBEDTLS_X509_BADCERT_CN_MISMATCH); assert(on.verify.anchor_hits == 0);
    }
    bundle_trust_obj.is_anchor = bundle_is_anchor;
}

/* ml_derp_bundle_has_anchor on its own: subject AND key, and no crash on a damaged bundle. */
static void bundle_cases(void) {
    use_bundle("bundle_cross");
    mbedtls_x509_crt x1, x2, x2c, fake, renamed, root;
    mbedtls_x509_crt_init(&x1); mbedtls_x509_crt_init(&x2); mbedtls_x509_crt_init(&x2c);
    mbedtls_x509_crt_init(&fake); mbedtls_x509_crt_init(&renamed); mbedtls_x509_crt_init(&root);
    const struct { const char *stem; mbedtls_x509_crt *crt; } load[] = {
        { "x1", &x1 }, { "x2", &x2 }, { "x2_cross", &x2c }, { "fake_x2", &fake }, { "renamed_x2", &renamed }, { "root", &root } };
    for (unsigned i = 0; i < sizeof(load) / sizeof(load[0]); i++) {
        size_t n;
        uint8_t *pem = slurp(file(load[i].stem, ".pem"), &n);
        assert(!mbedtls_x509_crt_parse(load[i].crt, pem, n));
        free(pem);
    }
    assert(ml_derp_bundle_has_anchor(held, held_len, &x1));
    assert(ml_derp_bundle_has_anchor(held, held_len, &x2));
    assert(ml_derp_bundle_has_anchor(held, held_len, &x2c));      /* the cross-certificate has X2's subject and key */
    assert(!ml_derp_bundle_has_anchor(held, held_len, &fake));    /* same subject DN, other key */
    assert(!ml_derp_bundle_has_anchor(held, held_len, &renamed)); /* same key, other subject DN */
    assert(!ml_derp_bundle_has_anchor(held, held_len, &root));
    assert(!ml_derp_bundle_has_anchor(NULL, held_len, &x2) && !ml_derp_bundle_has_anchor(held, 0, &x2) &&
           !ml_derp_bundle_has_anchor(held, held_len, NULL));
    mbedtls_x509_crt empty; mbedtls_x509_crt_init(&empty);
    assert(!ml_derp_bundle_has_anchor(held, held_len, &empty));
    cases += 11;

    /* One changed byte in the stored key, or in the stored subject, of the X2 entry: no longer a match, and X1 is
     * unaffected. */
    uint8_t *copy = malloc(held_len + 1);
    for (int field = 0; field < 2; field++) {
        const mbedtls_x509_buf *want = field ? &x2.subject_raw : &x2.pk_raw;
        memcpy(copy, held, held_len);
        uint8_t *at = memmem(copy, held_len, want->p, want->len);
        assert(at);
        at[want->len - 1] ^= 1;
        assert(!ml_derp_bundle_has_anchor(copy, held_len, &x2));
        assert(ml_derp_bundle_has_anchor(copy, held_len, &x1));
        cases += 2;
    }

    /* A damaged bundle matches nothing it should not and never reads outside the buffer (ASan): every truncation, and
     * every single-bit change of the offset table and of each entry's length header. A prefix can only lose matches. */
    uint8_t *exact = malloc(held_len);                               /* exact size: an over-read is a heap overflow */
    for (size_t len = 0; len <= held_len; len++) {
        memcpy(exact = realloc(exact, len ? len : 1), held, len);
        bool a = ml_derp_bundle_has_anchor(exact, len, &x2), b = ml_derp_bundle_has_anchor(exact, len, &x1);
        if (len < 8) assert(!a && !b);
        if (a) assert(ml_derp_bundle_has_anchor(held, held_len, &x2));
    }
    uint32_t first;
    memcpy(&first, held, 4);
    size_t table = first;
    for (size_t bit = 0; bit < table * 8; bit++) {                    /* the offset table */
        exact = realloc(exact, held_len);
        memcpy(exact, held, held_len);
        exact[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        (void)ml_derp_bundle_has_anchor(exact, held_len, &x2);
        (void)ml_derp_bundle_has_anchor(exact, held_len, &x1);
    }
    for (uint32_t i = 0; i < first / 4; i++) {                        /* each entry's two length fields */
        uint32_t off;
        memcpy(&off, held + 4 * i, 4);
        for (size_t bit = 0; bit < 32; bit++) {
            memcpy(exact, held, held_len);
            exact[off + bit / 8] ^= (uint8_t)(1u << (bit % 8));
            (void)ml_derp_bundle_has_anchor(exact, held_len, &x2);
            (void)ml_derp_bundle_has_anchor(exact, held_len, &x1);
        }
    }
    free(exact); free(copy);
    cases += 2;
    mbedtls_x509_crt_free(&x1); mbedtls_x509_crt_free(&x2); mbedtls_x509_crt_free(&x2c);
    mbedtls_x509_crt_free(&fake); mbedtls_x509_crt_free(&renamed); mbedtls_x509_crt_free(&root);
    mbedtls_x509_crt_free(&empty);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    pki = argv[1];
    mbedtls_platform_set_calloc_free(counting_calloc, counting_free);
    parse_cases();
    mbedtls_ssl_config probe; mbedtls_ssl_config_init(&probe);

    /* The pre-existing scenarios, once with the store's anchors matched (the firmware) and once without. */
    unsigned before = cases;
    bundle_trust_obj.is_anchor = bundle_is_anchor;
    suite();
    unsigned per_mode = cases - before;
    bundle_trust_obj.is_anchor = NULL;
    suite();
    bundle_trust_obj.is_anchor = bundle_is_anchor;
    unsigned legacy = cases;

    cross_cases();
    bundle_cases();
    mbedtls_ssl_config_free(&probe);
    printf("DERP TLS: %u verification cases (%u existing scenarios x 2 anchor modes, then %u trust-anchor-match cases: "
           "cross-signed root accepted with a smaller peak, same subject with another key, same key with another subject, "
           "impostor cross-signer, expired/not-yet-valid anchor, expired leaf/intermediate, wrong host, CertName, damaged bundles) passed\n",
           cases, per_mode, cases - legacy);
    return 0;
}
