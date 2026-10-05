/**
 * @file ml_derp_tls.c
 * @brief DERP TLS server authentication (see ml_derp_tls.h).
 *
 * Compiled unchanged by the host tests, so it includes only mbedTLS and libc.
 */
#include "ml_derp_tls.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "mbedtls/error.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"

/* A non-NULL, empty trust chain: "verify, trusting nothing of your own". */
static const mbedtls_x509_crt s_no_anchor;

static size_t trimmed_length(const char *s) {
    size_t n = strlen(s);
    return (n && s[n - 1] == '.') ? n - 1 : n;
}

/* pattern is a dNSName from a certificate (not NUL terminated). */
static bool dns_pattern_matches(const unsigned char *pattern, size_t plen, const char *host) {
    size_t hlen = trimmed_length(host);
    if (plen && pattern[plen - 1] == '.') plen--;
    if (!plen || !hlen) return false;
    const unsigned char *p = pattern;
    if (plen > 2 && p[0] == '*' && p[1] == '.') {
        /* The wildcard is the whole left-most label and covers exactly one label. */
        const char *dot = memchr(host, '.', hlen);
        if (!dot || dot == host) return false;
        size_t rest = hlen - (size_t)(dot - host);        /* ".example.com" */
        if (rest != plen - 1) return false;
        for (size_t i = 0; i < rest; i++)
            if (tolower((unsigned char)dot[i]) != tolower(p[1 + i])) return false;
        return memchr(p + 2, '*', plen - 2) == NULL;
    }
    if (plen != hlen) return false;
    for (size_t i = 0; i < plen; i++) {
        if (p[i] == '*') return false;
        if (tolower(p[i]) != tolower((unsigned char)host[i])) return false;
    }
    return true;
}

bool ml_derp_cert_names(const mbedtls_x509_crt *crt, const char *name) {
    uint32_t ip[4];
    size_t ip_len = mbedtls_x509_crt_parse_cn_inet_pton(name, ip); /* 0 = not an IP literal */
    for (const mbedtls_x509_sequence *san = &crt->subject_alt_names; san; san = san->next) {
        if (!san->buf.p) continue;
        unsigned tag = (unsigned char)san->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK;
        if (!ip_len && tag == MBEDTLS_X509_SAN_DNS_NAME &&
            dns_pattern_matches(san->buf.p, san->buf.len, name))
            return true;
        if (ip_len && tag == MBEDTLS_X509_SAN_IP_ADDRESS && san->buf.len == ip_len &&
            !memcmp(san->buf.p, ip, ip_len))
            return true;
    }
    return false;
}

static bool equal_bytes(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* ---- Trust anchor match ------------------------------------------------------
 *
 * What DERP presents. Let's Encrypt chains are  leaf <- YE2 <- Root YE <- ISRG Root X2, and the server
 * also sends "ISRG Root X2" as a cross-certificate signed by ISRG Root X1 (RSA-4096), so that older clients
 * that only trust X1 can still build a path. mbedTLS parses every presented certificate and verifies each link
 * with the already parsed key of the one above (P-384, one ECDSA at a time). The presented X2 has no parent in
 * the chain and no configured trust anchor, so it is flagged NOT_TRUSTED, and the ESP-IDF bundle callback then
 * parses X1's 4096-bit RSA key from the bundle and verifies the cross-signature: about 5.8 KB of transient heap on
 * the host (docs/research/membership-bytes.md section 4), the largest block of the whole handshake.
 *
 * Why skipping that check is sound. The bundle already contains X2 itself as a trust anchor. RFC 5280
 * section 6.1.1(d) takes the trust anchor as input, established out of band, as a name, a public key and its
 * algorithm, and section 6.1 starts every path at such an anchor; a trust anchor is not defined by a certificate
 * or by the signature on one. The signature a certificate carries only proves who issued that copy; if the key
 * and the name are already trusted, a copy issued by anybody (X1 for the cross-certificate) says nothing more
 * about trust. So a presented certificate whose subject DN and SubjectPublicKeyInfo equal a bundle entry is that
 * anchor, and the path below it was verified by mbedTLS against exactly that key: forging it needs the X2 private
 * key, the same as with the cross-signature.
 *
 * Constraints that keep it from widening trust:
 *  - BOTH the full subject DN (raw DER bytes) AND the full SubjectPublicKeyInfo (raw DER bytes) must be equal.
 *    A name alone never matches; a different key under the same name falls through to the bundle callback,
 *    which looks up the issuer by name and fails the signature. Byte equality is stricter than RFC 5280
 *    section 7.1 name matching (no case or whitespace folding), so it can only miss a match, never add one.
 *  - Only a certificate that mbedTLS flagged with exactly NOT_TRUSTED (the weak-hash flag aside, like the bundle
 *    callback). EXPIRED, FUTURE, BAD_KEY, BAD_PK or anything else on the certificate stays and fails the
 *    handshake: validity of the presented certificate is still enforced, stricter than an anchor needs.
 *  - Never the leaf (depth 0): the certificate that names the server must be issued by a CA. Everything below
 *    the anchor is verified by mbedTLS as before: signatures, validity of every intermediate and the leaf,
 *    basicConstraints/keyUsage/path length of the CA links, and the SAN-only host name check below.
 *  - The pin (sha256-raw) path never gets here, VERIFY_REQUIRED is unchanged, and a chain that does not match
 *    goes to the bundle callback exactly as before. No flag is ever cleared for a non-matching certificate.
 */
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

bool ml_derp_bundle_has_anchor(const uint8_t *bundle, size_t length, const mbedtls_x509_crt *crt) {
    if (!bundle || !crt || length < 8) return false;
    if (!crt->subject_raw.p || !crt->subject_raw.len || !crt->pk_raw.p || !crt->pk_raw.len) return false;
    /* [u32 offset] x n, then entries [u16 name_len][u16 key_len][subject DER][SubjectPublicKeyInfo DER] */
    uint32_t first = rd32(bundle);
    if (first < 4 || (first & 3) || first >= length) return false;
    uint32_t count = first / 4;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t off = rd32(bundle + 4 * (size_t)i);
        if (off < first || off > length - 4) continue;       /* length >= 8: no overflow, also with a 32-bit size_t */
        size_t name_len = (size_t)bundle[off] | (size_t)bundle[off + 1] << 8;
        size_t key_len = (size_t)bundle[off + 2] | (size_t)bundle[off + 3] << 8;
        if (name_len != crt->subject_raw.len || key_len != crt->pk_raw.len) continue;
        if (name_len + key_len > length - off - 4) continue;
        const uint8_t *name = bundle + off + 4;
        if (equal_bytes(name, crt->subject_raw.p, name_len) &&
            equal_bytes(name + name_len, crt->pk_raw.p, key_len))
            return true;
    }
    return false;
}

/* mbedTLS calls this for every certificate of the chain, the top one first and
 * the leaf (depth 0) last, after it has set the flags for that certificate.
 * A non-zero return aborts the handshake. mbedTLS's own host name judgement
 * (CN_MISMATCH, which accepts a CommonName when there is no SAN) is discarded
 * for the leaf and replaced by ml_derp_cert_names(). */
static int verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    ml_derp_verify_t *v = ctx;

    if (v->cert.kind == ML_DERP_CERT_PIN) {
        /* Tailscale: exactly one certificate besides the "derpkey" meta
         * certificate its derper appends (common name prefix derpconst.
         * MetaCertCommonNamePrefix). mbedTLS cannot parse that Ed25519 certificate and
         * its handshake skips it, so it never reaches this callback. */
        if (depth > 0 || (crt->next && crt->next->version)) {
            /* Not only a chain: any second certificate in the server's list. */
            *flags |= MBEDTLS_X509_BADCERT_OTHER;
            return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        }
        if (mbedtls_sha256(crt->raw.p, crt->raw.len, v->leaf_sha256, 0) != 0)
            return MBEDTLS_ERR_X509_FATAL_ERROR;
        v->pin_matched = equal_bytes(v->leaf_sha256, v->cert.v.sha256, 32);
        if (v->pin_matched) {
            /* The pin replaces chain building: a self-signed certificate is
             * trusted because it is the one named. Expiry and the host name
             * still count, as in Tailscale. */
            *flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_NOT_TRUSTED |
                                  MBEDTLS_X509_BADCERT_BAD_MD |
                                  MBEDTLS_X509_BADCERT_BAD_PK);
        } else {
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        }
    } else {
        /* Clear first: the chain's trust callback only acts on a certificate
         * whose single problem is NOT_TRUSTED. */
        if (depth == 0)
            *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH;
        int r;
        if (depth > 0 && v->is_anchor && (*flags & ~(uint32_t)MBEDTLS_X509_BADCERT_BAD_MD) == MBEDTLS_X509_BADCERT_NOT_TRUSTED &&
            v->is_anchor(crt)) {
            /* The store's own anchor (see "Trust anchor match"): no signature to verify. */
            *flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_BAD_MD);
            if (v->anchor_hits < UINT8_MAX) v->anchor_hits++;
            r = 0;
        } else {
            r = v->trust ? v->trust(NULL, crt, depth, flags) : MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        }
        if (r != 0) {
            if (depth == 0) {
                v->leaf_seen = true;
                v->verdict_flags = *flags;
            }
            return r;
        }
    }

    if (depth == 0) {
        *flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_CN_MISMATCH;
        if (!ml_derp_cert_names(crt, v->name))
            *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
        v->leaf_seen = true;
        v->verdict_flags = *flags;
    }
    return 0;
}

int ml_derp_tls_configure(mbedtls_ssl_config *conf, ml_derp_verify_t *state,
                          const ml_derp_cert_t *cert, const char *hostname,
                          const ml_derp_trust_t *trust) {
    if (!conf || !state || !cert || !hostname || cert->kind >= ML_DERP_CERT_INVALID ||
        !ml_derp_name_plausible(hostname, strlen(hostname)))
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    memset(state, 0, sizeof(*state));
    state->cert = *cert;
    strcpy(state->name, cert->kind == ML_DERP_CERT_NAME ? cert->v.name : hostname);
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    if (cert->kind == ML_DERP_CERT_PIN) {
        /* A non-NULL, empty chain: mbedTLS verifies (and calls us) rather than
         * refusing for lack of trust anchors; our callback supplies the trust. */
        mbedtls_ssl_conf_ca_chain(conf, (mbedtls_x509_crt *)&s_no_anchor, NULL);
    } else {
        if (!trust || !trust->attach || !trust->trust || trust->attach(conf) != 0)
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        state->trust = trust->trust;
        state->is_anchor = trust->is_anchor;
    }
    mbedtls_ssl_conf_verify(conf, verify_cb, state);
    return 0;
}

void ml_derp_tls_finish(mbedtls_ssl_config *conf) {
    mbedtls_ssl_conf_verify(conf, NULL, NULL);
}

void ml_derp_tls_describe(const mbedtls_ssl_context *ssl, int error,
                          const ml_derp_verify_t *state, char *out, size_t cap) {
    if (!cap) return;
    char reason[96];
    mbedtls_strerror(error, reason, sizeof(reason));
    uint32_t flags = ssl ? mbedtls_ssl_get_verify_result(ssl) : 0;
    if (state && state->verdict_flags) flags |= state->verdict_flags;
    char detail[128] = "";
    if (flags && flags != 0xFFFFFFFFu)
        mbedtls_x509_crt_verify_info(detail, sizeof(detail), "", flags);
    for (char *c = detail; *c; c++) if (*c == '\n') *c = ';';
    snprintf(out, cap, "%s (-0x%04x)%s%s", reason, (unsigned)-error, detail[0] ? " " : "", detail);
}

bool ml_derp_clock_valid(void) {
    return time(NULL) > 1700000000; /* Nov 2023: later than any firmware build */
}
