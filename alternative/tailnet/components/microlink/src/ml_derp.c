/**
 * @file ml_derp.c
 * @brief DERP relay: the platform side of the shared DERP task
 *
 * ADR 0013 stage 1: ONE task serves the DERP connection of every membership. The relay protocol itself
 * (HTTP upgrade, ServerKey/ClientInfo/ServerInfo, frames in both directions, deadlines, reconnect pacing)
 * is ml_derp_link.c, a non-blocking state machine that is tested on the host against scripted servers that
 * stall, go deaf or hang the handshake. This file supplies what that machine needs from the platform:
 *
 *   - transport bring-up in bounded steps: DNS through the lwIP resolver callback (no blocking
 *     getaddrinfo), a non-blocking TCP connect, and the TLS handshake one mbedtls_ssl_handshake() call at
 *     a time, with server authentication (ml_derp_tls.c) exactly as before;
 *   - established-connection I/O over mbedtls_ssl_read/write on a non-blocking socket;
 *   - the packet queue, the packet owner tags, the negotiation token and the event bits other tasks use.
 *
 * Nothing in here waits on a server. The one remaining blocking path is the cellular AT-socket bridge
 * (ml_at_socket_is_ready), which has no non-blocking resolver or connect; that mode is not a gateway
 * configuration and keeps its old behaviour for that single step.
 *
 * Reference: tailscale/wgengine/magicsock/derp.go (runDerpWriter)
 *            tailscale/derp/derphttp/derphttp_client.go
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/tcpip.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "nacl_box.h"
#include "esp_crt_bundle.h"
#include "ml_runtime.h"
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static const char *TAG = "ml_derp";

/* Trust anchors: the ESP-IDF certificate bundle (Mozilla roots, flash resident). */
/* Public in the library, not declared by esp_crt_bundle.h: the callback that
 * esp_crt_bundle_attach() installs and that ml_derp_tls.c chains to. */
extern int esp_crt_verify_callback(void *buf, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
static int derp_trust_attach(void *conf) { return esp_crt_bundle_attach(conf) == ESP_OK ? 0 : -1; }

/* DISCO magic bytes: "TS" + sparkles emoji UTF-8 */
static const uint8_t DISCO_MAGIC[6] = { 'T', 'S', 0xf0, 0x9f, 0x92, 0xac };

/* ============================================================================
 * Established-connection I/O (mbedTLS over a non-blocking socket)
 * ========================================================================== */

/* BIO callbacks route through ml_read_sock/ml_write_sock, which support both lwIP and AT sockets. */
static int bio_recv(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    int ret = (int)ml_read_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_READ;
        if (errno == EPIPE || errno == ECONNRESET) return MBEDTLS_ERR_NET_CONN_RESET;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return ret;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    if (fd < 0) return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    int ret = (int)ml_write_sock(fd, buf, len);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return MBEDTLS_ERR_SSL_WANT_WRITE;
        if (errno == EPIPE || errno == ECONNRESET) return MBEDTLS_ERR_NET_CONN_RESET;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}

static bool tls_would_block(int ret) {
    return ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
           ret == MBEDTLS_ERR_SSL_TIMEOUT || ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS;
}

static int op_io_read(void *user, uint8_t *buf, size_t len) {
    microlink_t *ml = user;
    int ret = mbedtls_ssl_read(&ml->derp.ssl, buf, len);
    if (ret > 0) return ret;
    if (ret < 0 && tls_would_block(ret)) return 0;
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) ESP_LOGW(TAG, "DERP server closed the connection");
    else ESP_LOGE(TAG, "TLS read failed: -0x%04x", -ret);
    return -1;
}

static int op_io_write(void *user, const uint8_t *buf, size_t len) {
    microlink_t *ml = user;
    int ret = mbedtls_ssl_write(&ml->derp.ssl, buf, len);
    if (ret > 0) return ret;
    if (ret == 0 || tls_would_block(ret)) return 0;
    ESP_LOGE(TAG, "TLS write failed: -0x%04x", -ret);
    return -1;
}

/* ============================================================================
 * Transport bring-up: DNS -> TCP -> TLS, one bounded step per call
 * ========================================================================== */

/* Resolver results arrive on the lwIP thread through a callback that cannot be cancelled. Each pending
 * lookup owns a slot of a static table, and the callback argument carries the slot's generation, so a late
 * answer for an attempt that was torn down (or whose slot another attempt has since taken) is ignored. */
enum { DNS_FREE = 0, DNS_PENDING, DNS_OK, DNS_FAILED };
typedef struct {
    volatile uint8_t state;
    volatile uint16_t generation;
    ip_addr_t addr;
} dns_slot_t;
static dns_slot_t dns_slots[ML_MUX_MAX];

static void dns_found(const char *name, const ip_addr_t *ip, void *arg) {
    (void)name;
    uintptr_t token = (uintptr_t)arg;
    unsigned index = (unsigned)(token >> 16);
    uint16_t generation = (uint16_t)(token & 0xffff);
    if (index >= ML_MUX_MAX) return;
    dns_slot_t *slot = &dns_slots[index];
    if (slot->generation != generation || slot->state != DNS_PENDING) return;
    if (ip) {
        slot->addr = *ip;
        __atomic_store_n(&slot->state, DNS_OK, __ATOMIC_RELEASE);
    } else {
        __atomic_store_n(&slot->state, DNS_FAILED, __ATOMIC_RELEASE);
    }
}

typedef enum { XP_RESOLVE, XP_RESOLVING, XP_CONNECT, XP_CONNECTING, XP_TLS_SETUP, XP_HANDSHAKE } xp_phase_t;

/* State of the connection attempt in flight; heap, tagged TLS, freed once the relay is up. */
struct derp_xport {
    xp_phase_t phase;
    ml_derp_verify_t verify;        /* must outlive the handshake (ml_derp_tls.h) */
    ml_derp_cert_t cert;
    char host[sizeof(((ml_derp_node_t *)0)->hostname)];
    uint16_t port;
    int region;
    int dns_slot;                   /* -1 when none held */
    uint16_t dns_generation;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int family;
    int64_t t_start, t_dns, t_tcp;
};

static void xport_release_dns(struct derp_xport *xp) {
    if (xp->dns_slot < 0) return;
    dns_slot_t *slot = &dns_slots[xp->dns_slot];
    /* dns_found runs on the lwIP thread with the core lock held and checks generation and state, then writes the answer:
     * releasing under the same lock makes that check-then-write atomic against this release, so a late answer can never
     * land in a slot another attempt has taken in between. (Callers hold no lwIP lock; the core lock is recursive.) */
    LOCK_TCPIP_CORE();
    slot->generation++;
    __atomic_store_n(&slot->state, DNS_FREE, __ATOMIC_RELEASE);
    UNLOCK_TCPIP_CORE();
    xp->dns_slot = -1;
}

static int xport_take_dns(struct derp_xport *xp) {
    for (unsigned i = 0; i < ML_MUX_MAX; i++) {
        uint8_t expected = DNS_FREE;
        if (__atomic_compare_exchange_n(&dns_slots[i].state, &expected, DNS_PENDING, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            xp->dns_slot = (int)i;
            xp->dns_generation = dns_slots[i].generation;
            return 0;
        }
    }
    return -1;
}

static void ip_to_sockaddr(const ip_addr_t *ip, uint16_t port, struct sockaddr_storage *ss,
                           socklen_t *len, int *family) {
    memset(ss, 0, sizeof(*ss));
#if LWIP_IPV6
    if (IP_IS_V6(ip)) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        memcpy(&a->sin6_addr, ip_2_ip6(ip)->addr, sizeof(a->sin6_addr));
        *len = sizeof(*a);
        *family = AF_INET6;
        return;
    }
#endif
    struct sockaddr_in *a = (struct sockaddr_in *)ss;
    a->sin_family = AF_INET;
    a->sin_port = htons(port);
    a->sin_addr.s_addr = ip_2_ip4(ip)->addr;
    *len = sizeof(*a);
    *family = AF_INET;
}

/* Pick the server from the DERPMap. Always start from the first usable node of the home region; only a
 * successful connection that later drops rotates, never a failed attempt (so it does not bounce between nodes). */
static void derp_pick_server(microlink_t *ml, struct derp_xport *xp) {
    const char *derp_host = ML_DERP_HOST;
    int derp_port = ML_DERP_PORT;
    bool region_in_map = false;
    ml_derp_cert_t derp_cert = { .kind = ML_DERP_CERT_HOSTNAME };

    if (ml->derp_region_count > 0 && ml->derp_home_region > 0) {
        for (int i = 0; i < ml->derp_region_count; i++) {
            if (ml->derp_regions[i].region_id == ml->derp_home_region) {
                for (int attempt = 0; attempt < ml->derp_regions[i].node_count; attempt++) {
                    if (!ml->derp_regions[i].nodes[attempt].stun_only &&
                        ml->derp_regions[i].nodes[attempt].hostname[0] &&
                        ml->derp_regions[i].nodes[attempt].cert.kind != ML_DERP_CERT_INVALID) {
                        derp_host = ml->derp_regions[i].nodes[attempt].hostname;
                        derp_cert = ml->derp_regions[i].nodes[attempt].cert;
                        if (ml->derp_regions[i].nodes[attempt].derp_port > 0)
                            derp_port = ml->derp_regions[i].nodes[attempt].derp_port;
                        region_in_map = true;
                        break;
                    }
                }
                break;
            }
        }
    }

    /* Home region absent from this tailnet's DERPMap — typical on self-hosted Headscale where only the
     * embedded region (999) exists while our default is a public Tailscale region. Dialing the hardcoded
     * public fallback would connect us to infrastructure none of our peers use, so pick the map's first
     * usable region instead and make it home (peers on such tailnets live in that region too). */
    if (!region_in_map && ml->derp_region_count > 0) {
        for (int i = 0; i < ml->derp_region_count && !region_in_map; i++) {
            for (int j = 0; j < ml->derp_regions[i].node_count; j++) {
                if (!ml->derp_regions[i].nodes[j].stun_only &&
                    ml->derp_regions[i].nodes[j].hostname[0] &&
                    ml->derp_regions[i].nodes[j].cert.kind != ML_DERP_CERT_INVALID) {
                    derp_host = ml->derp_regions[i].nodes[j].hostname;
                    derp_cert = ml->derp_regions[i].nodes[j].cert;
                    if (ml->derp_regions[i].nodes[j].derp_port > 0)
                        derp_port = ml->derp_regions[i].nodes[j].derp_port;
                    ESP_LOGW(TAG, "Home DERP region %u not in DERPMap — using region %u (%s)",
                             ml->derp_home_region, ml->derp_regions[i].region_id, derp_host);
                    ml->derp_home_region = ml->derp_regions[i].region_id;
                    region_in_map = true;
                    break;
                }
            }
        }
    }
    /* The map is rewritten by the control task at any time: keep a private copy of the name the TLS
     * policy is judged against. */
    strlcpy(xp->host, derp_host, sizeof(xp->host));
    xp->port = (uint16_t)derp_port;
    xp->cert = derp_cert;
    xp->region = ml->derp_home_region ? ml->derp_home_region : ML_DERP_REGION;
}

/* Tear down everything a connection attempt or an established connection held. Idempotent. */
static void tls_teardown(microlink_t *ml, bool graceful) {
    if (ml->derp.tls_up) {
        if (graceful) mbedtls_ssl_close_notify(&ml->derp.ssl);   /* best effort: never waits on a non-blocking socket */
        mbedtls_ssl_free(&ml->derp.ssl);
        mbedtls_ssl_config_free(&ml->derp.ssl_conf);
        ml_rng_release();
        ml->derp.tls_up = false;
    }
    if (ml->derp.sockfd >= 0) {
        ml_close_sock(ml->derp.sockfd);
        ml->derp.sockfd = -1;
    }
    if (ml->derp.xport) {
        xport_release_dns(ml->derp.xport);
        tdongle_heap_free(TDONGLE_OWNER_TLS, ml->derp.xport);
        ml->derp.xport = NULL;
    }
}

static int op_transport_open(void *user) {
    microlink_t *ml = user;
    /* Certificates cannot be judged before the wall clock is set (SNTP): a handshake now would fail on "not yet
     * valid" and burn a TLS attempt's memory and time. The link does not even ask for the token until the
     * clock is valid; this is the same rule at the last moment. */
    if (!ml_derp_clock_valid()) {
        ml->derp.tls_deferred++;
        return -1;
    }
    struct derp_xport *xp = tdongle_heap_tag(TDONGLE_OWNER_TLS, calloc(1, sizeof(*xp)));
    if (!xp) return -1;
    xp->dns_slot = -1;
    xp->t_start = esp_timer_get_time();
    derp_pick_server(ml, xp);
    ESP_LOGI(TAG, "Connecting to DERP %s:%d (region %d)", xp->host, xp->port, xp->region);
    ml->derp.xport = xp;
    ml->derp.sockfd = -1;
    ml->derp.connect_started_ms = ml_get_time_ms();
    return 0;
}

static int xport_resolve(microlink_t *ml, struct derp_xport *xp) {
    ip_addr_t ip;
    if (ml_at_socket_is_ready()) {
        /* The cellular AT bridge has no asynchronous resolver: this one step may block (not a gateway mode). */
        struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
        struct addrinfo *res = NULL;
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%d", xp->port);
        if (ml_getaddrinfo(xp->host, port_str, &hints, &res) != 0 || !res) {
            ESP_LOGE(TAG, "DNS resolve failed for %s", xp->host);
            return ML_DERP_T_FAIL;
        }
        memcpy(&xp->addr, res->ai_addr, res->ai_addrlen);
        xp->addr_len = res->ai_addrlen;
        xp->family = res->ai_family;
        ml_freeaddrinfo(res);
        xp->phase = XP_CONNECT;
        return ML_DERP_T_PENDING;
    }
    if (xport_take_dns(xp) < 0) return ML_DERP_T_PENDING;   /* all slots in use: retry next step */
    uintptr_t token = ((uintptr_t)xp->dns_slot << 16) | xp->dns_generation;
    LOCK_TCPIP_CORE();
    err_t err = dns_gethostbyname_addrtype(xp->host, &ip, dns_found, (void *)token, LWIP_DNS_ADDRTYPE_IPV4_IPV6);
    UNLOCK_TCPIP_CORE();
    if (err == ERR_OK) {
        ip_to_sockaddr(&ip, xp->port, &xp->addr, &xp->addr_len, &xp->family);
        xport_release_dns(xp);
        xp->phase = XP_CONNECT;
        return ML_DERP_T_PENDING;
    }
    if (err == ERR_INPROGRESS) {
        xp->phase = XP_RESOLVING;
        return ML_DERP_T_PENDING;
    }
    ESP_LOGE(TAG, "DNS resolve failed for %s (err %d)", xp->host, (int)err);
    return ML_DERP_T_FAIL;
}

static int xport_start_connect(microlink_t *ml, struct derp_xport *xp) {
    int sock = ml_socket(xp->family, SOCK_STREAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed: %d", errno);
        return ML_DERP_T_FAIL;
    }
    ml->derp.sockfd = sock;
    /* Keep the DERP socket off the exit-node tunnel (self-origin must use the physical uplink, not the WG
     * default route — see ml_bind_sock_to_upstream). */
    ml_bind_sock_to_upstream(ml, sock);
    if (ml_at_socket_is_at_fd(sock)) {
        /* AT sockets connect synchronously (cellular bridge only). */
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        ml_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        ml_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (ml_connect(sock, (struct sockaddr *)&xp->addr, xp->addr_len) < 0) {
            ESP_LOGE(TAG, "TCP connect failed: %d", errno);
            return ML_DERP_T_FAIL;
        }
        xp->phase = XP_TLS_SETUP;
        return ML_DERP_T_PENDING;
    }
    int flags = ml_fcntl(sock, F_GETFL, 0);
    if (flags >= 0) ml_fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    if (ml_connect(sock, (struct sockaddr *)&xp->addr, xp->addr_len) == 0) {
        xp->phase = XP_TLS_SETUP;
    } else if (errno == EINPROGRESS || errno == EALREADY) {
        xp->phase = XP_CONNECTING;
    } else {
        ESP_LOGE(TAG, "TCP connect failed: %d", errno);
        return ML_DERP_T_FAIL;
    }
    return ML_DERP_T_PENDING;
}

static int xport_poll_connect(microlink_t *ml, struct derp_xport *xp) {
    fd_set wr;
    FD_ZERO(&wr);
    FD_SET(ml->derp.sockfd, &wr);
    struct timeval tv = { 0, 0 };
    int r = ml_select_fds(ml->derp.sockfd + 1, NULL, &wr, NULL, &tv);
    if (r < 0) return errno == EINTR ? ML_DERP_T_PENDING : ML_DERP_T_FAIL;
    if (r == 0) return ML_DERP_T_PENDING;
    int so_error = 0;
    socklen_t so_len = sizeof(so_error);
    if (getsockopt(ml->derp.sockfd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) < 0 || so_error != 0) {
        ESP_LOGE(TAG, "TCP connect failed: %d", so_error ? so_error : errno);
        return ML_DERP_T_FAIL;
    }
    xp->t_tcp = esp_timer_get_time();
    xp->phase = XP_TLS_SETUP;
    return ML_DERP_T_PENDING;
}

static int xport_tls_setup(microlink_t *ml, struct derp_xport *xp) {
    xp->t_tcp = xp->t_tcp ? xp->t_tcp : esp_timer_get_time();
    mbedtls_ssl_init(&ml->derp.ssl);
    mbedtls_ssl_config_init(&ml->derp.ssl_conf);
    if (ml_rng_acquire() != 0) {
        ESP_LOGE(TAG, "no random number generator (out of memory?)");
        mbedtls_ssl_free(&ml->derp.ssl);
        mbedtls_ssl_config_free(&ml->derp.ssl_conf);
        return ML_DERP_T_FAIL;
    }
    ml->derp.tls_up = true;     /* from here tls_teardown frees the context and drops the RNG reference */

    mbedtls_ssl_config_defaults(&ml->derp.ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    /* The server must prove it is the DERP node named in the map (see ml_derp_tls.h). A configuration
     * failure means no connection at all. */
    static const ml_derp_trust_t trust = { .attach = derp_trust_attach, .trust = esp_crt_verify_callback };
    int cfg_ret = ml_derp_tls_configure(&ml->derp.ssl_conf, &xp->verify, &xp->cert, xp->host, &trust);
    if (cfg_ret != 0) {
        char why[160];
        ml_derp_tls_describe(NULL, cfg_ret, NULL, why, sizeof(why));
        ESP_LOGE(TAG, "DERP TLS verification setup failed for %s: %s", xp->host, why);
        ml->derp.tls_verify_failures++;
        return ML_DERP_T_FAIL;
    }
    mbedtls_ssl_conf_rng(&ml->derp.ssl_conf, ml_rng, NULL);
    if (mbedtls_ssl_setup(&ml->derp.ssl, &ml->derp.ssl_conf) != 0) {
        /* Typically alloc failure — without this check the handshake below dies with SSL_BAD_INPUT_DATA
         * and the real cause stays hidden. */
        ESP_LOGE(TAG, "mbedtls_ssl_setup failed (out of memory?)");
        ml_derp_tls_finish(&ml->derp.ssl_conf);
        return ML_DERP_T_FAIL;
    }
    /* SNI is the HostName, except for an IP literal: Go's crypto/tls (Tailscale's client) sends none for one,
     * and RFC 6066 forbids literal addresses. The name the certificate must carry is checked by
     * ml_derp_tls.c either way. */
    {
        uint32_t literal[4];
        if (mbedtls_x509_crt_parse_cn_inet_pton(xp->host, literal) == 0)
            mbedtls_ssl_set_hostname(&ml->derp.ssl, xp->host);
    }
    mbedtls_ssl_set_bio(&ml->derp.ssl, &ml->derp.sockfd, bio_send, bio_recv, NULL);
    xp->phase = XP_HANDSHAKE;
    return ML_DERP_T_PENDING;
}

static int xport_handshake(microlink_t *ml, struct derp_xport *xp) {
    int ret = mbedtls_ssl_handshake(&ml->derp.ssl);
    if (ret == 0) {
        ml_derp_tls_finish(&ml->derp.ssl_conf);   /* the verifier state is about to go away */
        /* TCP_NODELAY — CRITICAL for a relay carrying many ~1.3KB packets. Without it Nagle's algorithm holds
         * partial segments until the prior segment is ACKed, and Nagle x delayed-ACK stalls each packet
         * ~40-200ms -> the classic small-packet throughput collapse. The canonical Tailscale DERP client sets
         * NODELAY. */
        int nodelay = 1;
        ml_setsockopt(ml->derp.sockfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
        ESP_LOGI(TAG, "[TIMING] DERP DNS+TCP: %lld ms, TLS handshake: %lld ms",
                 (long long)((xp->t_tcp - xp->t_start) / 1000),
                 (long long)((esp_timer_get_time() - xp->t_tcp) / 1000));
        return ML_DERP_T_DONE;
    }
    if (tls_would_block(ret)) return ML_DERP_T_PENDING;
    char why[200];
    ml_derp_tls_describe(&ml->derp.ssl, ret, &xp->verify, why, sizeof(why));
    if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED || xp->verify.verdict_flags) {
        ESP_LOGE(TAG, "DERP %s failed certificate verification (%s): %s", xp->host,
                 xp->cert.kind == ML_DERP_CERT_PIN ? "pinned" :
                 xp->cert.kind == ML_DERP_CERT_NAME ? "CertName" : "HostName", why);
        ml->derp.tls_verify_failures++;
    } else {
        ESP_LOGE(TAG, "TLS handshake to %s failed: %s", xp->host, why);
    }
    ml_derp_tls_finish(&ml->derp.ssl_conf);
    return ML_DERP_T_FAIL;
}

static int op_transport_step(void *user, uint64_t now_ms) {
    (void)now_ms;
    microlink_t *ml = user;
    struct derp_xport *xp = ml->derp.xport;
    if (!xp) return ML_DERP_T_FAIL;
    /* A few phases complete without waiting; run them back to back, but return as soon as one waits. */
    for (unsigned guard = 0; guard < 6; guard++) {
        xp_phase_t before = xp->phase;
        int r = ML_DERP_T_PENDING;
        switch (xp->phase) {
        case XP_RESOLVE: r = xport_resolve(ml, xp); break;
        case XP_RESOLVING: {
            dns_slot_t *slot = &dns_slots[xp->dns_slot];
            uint8_t st = __atomic_load_n(&slot->state, __ATOMIC_ACQUIRE);
            if (st == DNS_OK) {
                ip_to_sockaddr(&slot->addr, xp->port, &xp->addr, &xp->addr_len, &xp->family);
                xport_release_dns(xp);
                xp->phase = XP_CONNECT;
            } else if (st == DNS_FAILED) {
                ESP_LOGE(TAG, "DNS resolve failed for %s", xp->host);
                r = ML_DERP_T_FAIL;
            }
            break;
        }
        case XP_CONNECT: r = xport_start_connect(ml, xp); break;
        case XP_CONNECTING: r = xport_poll_connect(ml, xp); break;
        case XP_TLS_SETUP: r = xport_tls_setup(ml, xp); break;
        case XP_HANDSHAKE: return xport_handshake(ml, xp);
        }
        if (r != ML_DERP_T_PENDING) return r;
        if (xp->phase == before) return ML_DERP_T_PENDING;   /* waiting on the network */
    }
    return ML_DERP_T_PENDING;
}

static void op_transport_close(void *user) {
    microlink_t *ml = user;
    /* Say goodbye only on a connection that completed its handshake. */
    bool established = ml->derp.link.state >= ML_DERP_UPGRADE_TX;
    tls_teardown(ml, established);
}

static bool op_clock_valid(void *user) {
    (void)user;
    return ml_derp_clock_valid();
}

/* ============================================================================
 * DERP protocol glue
 * ========================================================================== */

static size_t op_upgrade_request(void *user, uint8_t *out, size_t cap) {
    microlink_t *ml = user;
    if (!ml->derp.xport) return 0;
    int n = snprintf((char *)out, cap,
                     "GET /derp HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Connection: Upgrade\r\n"
                     "Upgrade: DERP\r\n"
                     "\r\n",
                     ml->derp.xport->host);
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

/* ClientInfo payload: [our_nodekey(32)][nonce(24)][nacl_box(JSON)] */
static bool op_client_info(void *user, const uint8_t derp_server_key[32], uint8_t *out, size_t cap, size_t *len) {
    microlink_t *ml = user;
    static const char *client_info_json = "{\"Version\":2,\"CanAckPings\":true,\"IsProber\":false}";
    size_t json_len = strlen(client_info_json);
    size_t ciphertext_len = json_len + NACL_BOX_MACBYTES;
    size_t total = 32 + NACL_BOX_NONCEBYTES + ciphertext_len;
    if (total > cap) return false;

    uint8_t nonce[NACL_BOX_NONCEBYTES];
    esp_fill_random(nonce, NACL_BOX_NONCEBYTES);
    memcpy(out, ml->wg_public_key, 32);
    memcpy(out + 32, nonce, NACL_BOX_NONCEBYTES);
    /* Encrypt JSON with NaCl box: our WG private key -> DERP server public key */
    if (nacl_box(out + 32 + NACL_BOX_NONCEBYTES, (const uint8_t *)client_info_json, json_len, nonce,
                 derp_server_key,       /* recipient: DERP server */
                 ml->wg_private_key     /* sender: our WG node key */
                 ) != 0) {
        ESP_LOGE(TAG, "NaCl box encrypt failed");
        return false;
    }
    ESP_LOGI(TAG, "DERP ClientInfo node_key=%02x%02x%02x%02x%02x%02x%02x%02x",
             ml->wg_public_key[0], ml->wg_public_key[1], ml->wg_public_key[2], ml->wg_public_key[3],
             ml->wg_public_key[4], ml->wg_public_key[5], ml->wg_public_key[6], ml->wg_public_key[7]);
    *len = total;
    return true;
}

/* Packet classification */
typedef enum {
    PKT_DISCO,
    PKT_STUN,
    PKT_WIREGUARD,
    PKT_UNKNOWN,
} pkt_type_t;

static pkt_type_t classify_packet(const uint8_t *data, size_t len) {
    if (len >= 20 && (data[0] == 0x00 || data[0] == 0x01) && data[1] == 0x01) return PKT_STUN;
    if (len >= 62 && memcmp(data, DISCO_MAGIC, 6) == 0) return PKT_DISCO;
    if (len >= 4) return PKT_WIREGUARD;
    return PKT_UNKNOWN;
}

static void op_deliver(void *user, const uint8_t *src_pubkey, uint8_t *data, size_t len) {
    microlink_t *ml = user;
    pkt_type_t type = classify_packet(data, len);

    ml_rx_packet_t pkt = {
        .data = data,
        .len = len,
        .via_derp = true,
    };
    memcpy(pkt.src_pubkey, src_pubkey, 32);

    QueueHandle_t target = (type == PKT_DISCO) ? ml->disco_rx_queue : ml->wg_rx_queue;
    if (xQueueSend(target, &pkt, 0) != pdTRUE) {
        /* Download-direction RX drop: frames arrive faster than the consumer (wg_rx_queue depth) can
         * decrypt/forward. Rate-limited so a flood doesn't itself spam the SD recorder. */
        static uint32_t derp_rx_drops = 0;
        if ((++derp_rx_drops & 0x1F) == 1)
            ESP_LOGW(TAG, "DERP-RX queue full: dropped %lu (type=%d)", (unsigned long)derp_rx_drops, (int)type);
        tdongle_memory_drop(TDONGLE_DROP_DERP_RX_FULL);
        tdongle_heap_free(TDONGLE_OWNER_PACKET, data);
    } else {
        ml_rt_wake(ML_RT_TASK_WG_MGR);
    }
}

static bool op_tx_pop(void *user, ml_derp_out_t *out) {
    microlink_t *ml = user;
    ml_derp_tx_item_t item;
    if (xQueueReceive(ml->derp_tx_queue, &item, 0) != pdTRUE) return false;
    memcpy(out->dest, item.dest_pubkey, 32);
    out->data = item.data;
    out->len = item.len;
    out->frame_type = item.frame_type;
    return true;
}

static void drain_tx_queue(microlink_t *ml) {
    ml_derp_tx_item_t item;
    while (xQueueReceive(ml->derp_tx_queue, &item, 0) == pdTRUE) tdongle_heap_free(TDONGLE_OWNER_PACKET, item.data);
}

static void op_event(void *user, ml_derp_event_t ev) {
    microlink_t *ml = user;
    switch (ev) {
    case ML_DERP_EV_CONNECTED:
        ml->derp.connected = true;
        ml->derp.last_recv_ms = ml_get_time_ms();
        if (ml->derp.xport) {                      /* the attempt is over: its scratch goes */
            xport_release_dns(ml->derp.xport);
            tdongle_heap_free(TDONGLE_OWNER_TLS, ml->derp.xport);
            ml->derp.xport = NULL;
        }
        tdongle_memory_phase(ml->config.diagnostic_id, TDONGLE_PHASE_DERP);
        xEventGroupSetBits(ml->events, ML_EVT_DERP_CONNECTED);
        ESP_LOGI(TAG, "DERP handshake complete, connected (%lu ms)",
                 (unsigned long)(ml_get_time_ms() - ml->derp.connect_started_ms));
        break;
    case ML_DERP_EV_DISCONNECTED:
        ml->derp.connected = false;
        xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECTED);
        drain_tx_queue(ml);
        ESP_LOGI(TAG, "DERP disconnected");
        break;
    case ML_DERP_EV_CONNECT_FAILED:
        ml->rc_derp_retry++;
        ESP_LOGW(TAG, "DERP connect attempt failed (state %s)", ml_derp_link_state_name(ml->derp.link.state));
        break;
    case ML_DERP_EV_RX_STALE:
        ml->rc_derp_rx_wd++;
        ESP_LOGW(TAG, "DERP RX silent for %lu s — relay presumed dead, reconnecting",
                 (unsigned long)((ml_get_time_ms() - ml->derp.link.last_recv_ms) / 1000));
        break;
    case ML_DERP_EV_CLOCK_DEFERRED:
        ml->derp.tls_deferred++;
        ESP_LOGW(TAG, "DERP connect held back: wall clock not set (SNTP), certificates cannot be verified");
        break;
    }
}

/* ---- allocation and the negotiation token ---- */

static void *op_alloc(void *user, size_t bytes) {
    (void)user;
    /* Relay buffers go to SPIRAM when there is any (not DMA, not latency-critical); without it this is the
     * internal heap, which is why the owner tag matters. Freed with plain free() (heap_caps). */
    return tdongle_heap_tag(TDONGLE_OWNER_PACKET, ml_psram_malloc(bytes));
}
static void op_release(void *user, void *block) {
    (void)user;
    tdongle_heap_free(TDONGLE_OWNER_PACKET, block);
}
static uint64_t op_now(void *user) {
    (void)user;
    return ml_get_time_ms();
}
static bool op_token_try(void *user) {
    microlink_t *ml = user;
    /* A membership without a relay outranks one that is still joining: finishing a join beats starting one. */
    return ml_neg_request(ml_rt_negotiation(), ml_neg_key(ml->config.diagnostic_id, ML_NEG_PHASE_DERP),
                          ML_NEG_PRIO_RELAY, ML_NEG_PHASE_DERP) == ML_NEG_GRANTED;
}
static void op_token_release(void *user) {
    microlink_t *ml = user;
    ml_neg_release(ml_rt_negotiation(), ml_neg_key(ml->config.diagnostic_id, ML_NEG_PHASE_DERP));
}

static const ml_derp_link_ops_t derp_ops = {
    .now_ms = op_now,
    .alloc = op_alloc,
    .release = op_release,
    .io_read = op_io_read,
    .io_write = op_io_write,
    .transport_open = op_transport_open,
    .transport_step = op_transport_step,
    .transport_close = op_transport_close,
    .clock_valid = op_clock_valid,
    .make_upgrade_request = op_upgrade_request,
    .make_client_info = op_client_info,
    .tx_pop = op_tx_pop,
    .deliver = op_deliver,
    .event = op_event,
    .token_try = op_token_try,
    .token_release = op_token_release,
};

void ml_derp_member_init(microlink_t *ml) {
    ml->derp.sockfd = -1;
    ml_derp_link_init(&ml->derp.link, &derp_ops, ml);
}

/* ============================================================================
 * TX queue: relay packets from every other task
 * ========================================================================== */

/* Queue a packet for DERP TX with backpressure */
esp_err_t ml_derp_queue_send(microlink_t *ml, const uint8_t *dest_key,
                              const uint8_t *data, size_t len) {
    if (!ml || !dest_key || !data || len == 0) return ESP_ERR_INVALID_ARG;

    /* Relay buffer goes to SPIRAM (not DMA, not latency-critical): with a deeper TX queue this can hold
     * ~64 x ~1.3KB in-flight — keep it off the chronically-tight internal DRAM. */
    uint8_t *pkt_data = tdongle_heap_tag(TDONGLE_OWNER_PACKET, ml_psram_malloc(len));
    if (!pkt_data) return ESP_ERR_NO_MEM;
    memcpy(pkt_data, data, len);

    ml_derp_tx_item_t item = {
        .data = pkt_data,
        .len = len,
        .frame_type = ML_DERP_FRAME_SEND_PACKET,
    };
    memcpy(item.dest_pubkey, dest_key, 32);

    /* WG handshake packets (type 1=init, 2=response) get priority — front of queue.
     * This ensures handshake responses aren't delayed behind DISCO pings. */
    bool is_wg_handshake = (len >= 4 && (data[0] == 0x01 || data[0] == 0x02));

    /* Try to send to queue */
    if ((is_wg_handshake ? xQueueSendToFront(ml->derp_tx_queue, &item, 0)
                         : xQueueSend(ml->derp_tx_queue, &item, 0)) == pdTRUE) {
        ml_rt_wake(ML_RT_TASK_DERP);   /* event driven: the relay writes it now, not at the next poll */
        return ESP_OK;
    }

    /* Queue full - backpressure: drop oldest, retry up to 3 times */
    for (int i = 0; i < 3; i++) {
        ml_derp_tx_item_t dropped;
        if (xQueueReceive(ml->derp_tx_queue, &dropped, 0) == pdTRUE) {
            tdongle_memory_drop(TDONGLE_DROP_DERP_TX_EVICT);
            tdongle_heap_free(TDONGLE_OWNER_PACKET, dropped.data);  /* Drop oldest */
        }
        if (xQueueSend(ml->derp_tx_queue, &item, 0) == pdTRUE) {
            ml_rt_wake(ML_RT_TASK_DERP);
            return ESP_OK;
        }
    }

    /* Still full after 3 attempts, drop new packet (upload-direction loss: forwarded packets enqueued
     * faster than the DERP task can TLS-write). */
    static uint32_t derp_tx_drops = 0;
    if ((++derp_tx_drops & 0x1F) == 1)
        ESP_LOGW(TAG, "DERP-TX queue full: dropped %lu", (unsigned long)derp_tx_drops);
    tdongle_memory_drop(TDONGLE_DROP_DERP_TX_FULL);
    tdongle_heap_free(TDONGLE_OWNER_PACKET, pkt_data);
    return ESP_ERR_TIMEOUT;
}

/* ============================================================================
 * The shared task's per-membership slice
 * ========================================================================== */

static void member_service(void *ctx, void *shared) {
    microlink_t *ml = ctx;
    uint64_t now = ml_get_time_ms();

    /* Liveness stamp for external diagnostics: refreshed on every visit, so the age stays small while the
     * task runs and climbs without bound the instant it blocks in a call. */
    ml->derp_last_heartbeat_ms = now;

    EventBits_t bits = xEventGroupGetBits(ml->events);
    if (bits & ML_EVT_SHUTDOWN_REQUEST) {
        ml_derp_link_close(&ml->derp.link);
        return;
    }
    if (bits & ML_EVT_DERP_RECONNECT) {
        xEventGroupClearBits(ml->events, ML_EVT_DERP_RECONNECT);
        ESP_LOGW(TAG, "DERP reconnect requested (was %s)", ml->derp.connected ? "connected" : "disconnected");
        ml_derp_link_reconnect(&ml->derp.link);
    }
    if ((bits & ML_EVT_DERP_CONNECT_REQ) && !ml->derp.connected) {
        xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECT_REQ);
        ESP_LOGI(TAG, "DERP connect requested");
        ml_derp_link_connect(&ml->derp.link);
    }

    uint32_t frames_before = ml->derp.link.stats.frames_rx + ml->derp.link.stats.frames_tx;
    ml_derp_link_service(&ml->derp.link);
    if (shared && ml_derp_link_busy(&ml->derp.link, frames_before)) ((ml_derp_pass_t *)shared)->active = true;
    ml->derp.last_recv_ms = ml->derp.link.last_recv_ms;
    {   /* when this link next needs the task: the shared loop sleeps until the earliest of them */
        ml_derp_pass_t *pass = shared;
        uint32_t wait = ml_derp_link_wait_ms(&ml->derp.link);
        if (pass && wait < pass->wait_ms) pass->wait_ms = wait;
    }

    static uint64_t last_status_ms;   /* one line per 10 s across all memberships is plenty */
    if (now - last_status_ms > 10000) {
        last_status_ms = now;
        ESP_LOGI(TAG, "DERP[%lu] %s rx=%lu tx=%lu timeouts=%lu/%lu drops=%lu",
                 (unsigned long)ml->config.diagnostic_id, ml_derp_link_state_name(ml->derp.link.state),
                 (unsigned long)ml->derp.link.stats.frames_rx, (unsigned long)ml->derp.link.stats.frames_tx,
                 (unsigned long)ml->derp.link.stats.rx_timeouts, (unsigned long)ml->derp.link.stats.tx_stalls,
                 (unsigned long)ml->derp.link.stats.alloc_drops);
    }
}

/* Runs under the DERP mux lock after the membership left the table: the TLS context, the socket and the
 * packet queue are released while the shared task cannot be using them. */
static void member_teardown(void *ctx, void *shared) {
    (void)shared;
    microlink_t *ml = ctx;
    ml_derp_link_close(&ml->derp.link);    /* closes the transport, frees buffers, releases the token */
    tls_teardown(ml, false);               /* defensive: a link that never opened anything holds nothing */
    drain_tx_queue(ml);
}

const ml_mux_ops_t ml_derp_mux_ops = {
    .service = member_service,
    .teardown = member_teardown,
};
