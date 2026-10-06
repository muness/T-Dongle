/**
 * @file ml_derp_tls.h
 * @brief Server authentication for the DERP TLS connection.
 *
 * Mirrors the Tailscale client (derp/derphttp/derphttp_client.go tlsClient,
 * net/tlsdial, tailcfg.DERPNode.CertName):
 *
 *  - the TLS server name (SNI) is the node's HostName;
 *  - by default the certificate chain must verify to a trusted root and name
 *    HostName;
 *  - a CertName on the node names the certificate instead: the SNI stays
 *    HostName but the chain must name CertName (domain fronting);
 *  - CertName "sha256-raw:<64 hex>" pins the leaf certificate by the SHA-256 of
 *    its DER encoding (self-signed DERP servers). No chain is built, exactly one
 *    certificate must be presented, it must still be inside its validity period
 *    and still name HostName. Tailscale's "derpkey" meta certificate is not
 *    understood by mbedTLS and is skipped by its parser, as Tailscale skips it;
 *  - a presented certificate that IS a trust anchor of the store (same subject DN
 *    bytes and same SubjectPublicKeyInfo bytes as a bundle entry) is trusted as
 *    that anchor and its own signature is not verified. This is how the cross-signed
 *    "ISRG Root X2" that DERP serves (signed by the RSA-4096 "ISRG Root X1") is
 *    accepted without parsing a 4096-bit RSA key. See "Trust anchor match" in
 *    ml_derp_tls.c for the rationale (RFC 5280 section 6.1.1(d));
 *  - DERPNode.InsecureForTests is NOT honoured. Nothing a control server sends
 *    can turn verification off.
 *
 * Anything this module cannot positively verify fails the handshake. mbedTLS is
 * configured VERIFY_REQUIRED, so a failure is a clean handshake error that the
 * DERP task reports and retries on its backoff ladder.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "ml_derp_cert.h"

/* Does a certificate name the DNS name or IP literal `name`? Go's
 * x509.Certificate.VerifyHostname rules: subjectAltName only (no CommonName
 * fallback), a wildcard only as the whole left-most label, one label deep. */
bool ml_derp_cert_names(const mbedtls_x509_crt *crt, const char *name);

typedef int (*ml_derp_verify_fn)(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags);

/* Where trust anchors come from. In the firmware this is the ESP-IDF
 * certificate bundle (esp_crt_bundle_attach / esp_crt_verify_callback); tests
 * install their own bundle behind the same functions. */
typedef bool (*ml_derp_anchor_fn)(const mbedtls_x509_crt *crt);

typedef struct {
    int (*attach)(void *ssl_conf);  /* installs trust; returns 0 on success */
    ml_derp_verify_fn trust;        /* the callback attach() installs, chained to */
    ml_derp_anchor_fn is_anchor;    /* optional: is `crt` itself one of the store's trust anchors (subject DN and
                                       SubjectPublicKeyInfo both equal)? NULL = never, every chain is verified up
                                       to a certificate that `trust` can sign-check */
} ml_derp_trust_t;

/* is_anchor() for a bundle in the ESP-IDF format (esp_crt_bundle.c): true when an entry has exactly the same
 * subject DN bytes and exactly the same SubjectPublicKeyInfo bytes as `crt`. Names alone never match. A malformed
 * entry is skipped, a malformed bundle matches nothing. `bundle` is read-only and need not be aligned. */
bool ml_derp_bundle_has_anchor(const uint8_t *bundle, size_t length, const mbedtls_x509_crt *crt);

/* Per-handshake verifier state. Lives at least until the handshake returns;
 * ml_derp_tls_finish() detaches it. */
typedef struct {
    ml_derp_cert_t cert;
    char name[ML_DERP_CERT_NAME_MAX]; /* the name the certificate must carry */
    ml_derp_verify_fn trust;
    ml_derp_anchor_fn is_anchor;
    uint8_t anchor_hits;    /* certificates accepted as the trust anchor itself in this handshake */
    uint32_t verdict_flags; /* final flags of the leaf, for the failure report */
    bool pin_matched;
    uint8_t leaf_sha256[32];
    bool leaf_seen;
} ml_derp_verify_t;

/* Configure conf to require a verified server. `hostname` is the node's
 * HostName; the caller sets the same name as the SNI with
 * mbedtls_ssl_set_hostname(). The certificate must carry hostname, or CertName
 * when the node has one (SAN only, decided here rather than by mbedTLS, which
 * also falls back to the CommonName). Returns 0, or an mbedTLS error (the
 * caller must not connect). */
int ml_derp_tls_configure(mbedtls_ssl_config *conf, ml_derp_verify_t *state,
                          const ml_derp_cert_t *cert, const char *hostname,
                          const ml_derp_trust_t *trust);

/* After the handshake (success or failure): drop the pointer to `state`. */
void ml_derp_tls_finish(mbedtls_ssl_config *conf);

/* Human readable reason for a failed handshake: the mbedTLS error plus the
 * certificate verification flags. */
void ml_derp_tls_describe(const mbedtls_ssl_context *ssl, int error,
                          const ml_derp_verify_t *state, char *out, size_t cap);

/* True when the wall clock is plausibly set. Certificate validity cannot be
 * checked before SNTP has run; connecting earlier would fail every handshake. */
bool ml_derp_clock_valid(void);
