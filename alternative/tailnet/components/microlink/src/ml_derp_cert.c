/**
 * @file ml_derp_cert.c
 * @brief DERPNode.CertName parsing (see ml_derp_cert.h).
 */
#include "ml_derp_cert.h"

#include <ctype.h>
#include <string.h>

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t trimmed_length(const char *s) {
    size_t n = strlen(s);
    return (n && s[n - 1] == '.') ? n - 1 : n;
}

static bool same_name(const char *a, const char *b) {
    size_t la = trimmed_length(a), lb = trimmed_length(b);
    if (la != lb) return false;
    for (size_t i = 0; i < la; i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return false;
    return true;
}

bool ml_derp_name_plausible(const char *s, size_t n) {
    if (!n || n >= ML_DERP_CERT_NAME_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_' || c == ':')) /* no '*': Go's VerifyHostname refuses a wildcard host name */
            return false;
    }
    return true;
}

bool ml_derp_cert_parse(const char *hostname, const char *cert_name, ml_derp_cert_t *out) {
    memset(out, 0, sizeof(*out));
    out->kind = ML_DERP_CERT_HOSTNAME;
    if (!cert_name || !*cert_name) return true;
    size_t prefix = strlen(ML_DERP_PIN_PREFIX);
    if (!strncmp(cert_name, ML_DERP_PIN_PREFIX, prefix)) {
        const char *hex = cert_name + prefix;
        if (strlen(hex) != 64) goto invalid;
        for (int i = 0; i < 32; i++) {
            int hi = hex_value(hex[2 * i]), lo = hex_value(hex[2 * i + 1]);
            if (hi < 0 || lo < 0) goto invalid;
            out->v.sha256[i] = (uint8_t)(hi << 4 | lo);
        }
        out->kind = ML_DERP_CERT_PIN;
        return true;
    }
    if (hostname && same_name(hostname, cert_name)) return true;
    size_t n = strlen(cert_name);
    if (!ml_derp_name_plausible(cert_name, n)) goto invalid;
    memcpy(out->v.name, cert_name, n);
    out->kind = ML_DERP_CERT_NAME;
    return true;
invalid:
    memset(out, 0, sizeof(*out));
    out->kind = ML_DERP_CERT_INVALID;
    return false;
}

