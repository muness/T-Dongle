/**
 * @file ml_derp_cert.h
 * @brief How a DERP node's TLS server is authenticated, from DERPNode.CertName.
 *
 * Plain data and a parser with no TLS dependency, so the DERP map decoder and
 * its host tests can use it. See ml_derp_tls.h for the semantics.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ML_DERP_CERT_HOSTNAME 0 /* verify against HostName (no CertName) */
#define ML_DERP_CERT_NAME     1 /* verify against CertName, SNI stays HostName */
#define ML_DERP_CERT_PIN      2 /* leaf pinned by SHA-256 of its DER */
#define ML_DERP_CERT_INVALID  3 /* CertName present but unusable: never connect */

#define ML_DERP_CERT_NAME_MAX 64 /* including the terminating NUL */
#define ML_DERP_PIN_PREFIX "sha256-raw:"

typedef struct {
    uint8_t kind; /* ML_DERP_CERT_* */
    union {
        char name[ML_DERP_CERT_NAME_MAX]; /* ML_DERP_CERT_NAME */
        uint8_t sha256[32];               /* ML_DERP_CERT_PIN */
    } v;
} ml_derp_cert_t;

/* Interpret a DERPNode's CertName. cert_name may be NULL or empty (default).
 * A name equal to hostname (ignoring case and a trailing dot) is the default.
 * Returns false and sets kind to ML_DERP_CERT_INVALID when CertName is present
 * but malformed (bad pin, too long, not a hostname); such a node is unusable. */
bool ml_derp_cert_parse(const char *hostname, const char *cert_name, ml_derp_cert_t *out);

/* A DNS name or IP literal this module is willing to compare certificates with. */
bool ml_derp_name_plausible(const char *name, size_t length);
