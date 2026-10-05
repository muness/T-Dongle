#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "ssl_misc.h"
const unsigned sz_ssl_context=sizeof(mbedtls_ssl_context);
const unsigned sz_ssl_config=sizeof(mbedtls_ssl_config);
const unsigned sz_x509_crt=sizeof(mbedtls_x509_crt);
const unsigned sz_handshake=sizeof(mbedtls_ssl_handshake_params);
const unsigned sz_session=sizeof(mbedtls_ssl_session);
const unsigned sz_transform=sizeof(mbedtls_ssl_transform);
const unsigned sz_ctr_drbg=sizeof(mbedtls_ctr_drbg_context);
const unsigned sz_entropy=sizeof(mbedtls_entropy_context);
const unsigned sz_in_buflen=MBEDTLS_SSL_IN_BUFFER_LEN;
const unsigned sz_out_buflen=MBEDTLS_SSL_OUT_BUFFER_LEN;
const unsigned sz_hdr=sizeof(void*);
