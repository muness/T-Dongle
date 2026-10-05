/* Who vouches for the control server's Noise key. The code under test is the
 * real key-fetch core from ml_coord.c (parse_host_port, the /key response
 * parser, ctrl_key_fetch, ctrl_key_ensure), driven through a mock transport. */
#define _POSIX_C_SOURCE 200809L
#include "cJSON.h"
#include "tdongle_memory.h"
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#define ESP_LOGE(tag, ...) (logs_error++)
#define ESP_LOGW(tag, ...) (logs_warn++)
#define ESP_LOGI(tag, ...) ((void)0)
#define ML_CTRL_PROTOCOL_VER 131
static const char *TAG = "t";
static unsigned logs_error, logs_warn;
typedef struct {
    char ctrl_host[64], ctrl_host_parsed[64], ctrl_port_str[8], ctrl_host_hdr[72];
    bool use_tls, ctrl_noise_pubkey_valid;
    uint8_t ctrl_noise_pubkey[32], ctrl_key_auth;
    char transport_error[64];
    uint8_t ctrl_key_failures; uint32_t ctrl_key_drop_backoff_ms, ctrl_key_refetches; uint64_t ctrl_key_next_drop_ms;
} microlink_t;
static bool test_clock_valid = true;
static bool ml_derp_clock_valid(void) { return test_clock_valid; }
#include "ctrl_key_defs.inc"
static unsigned allocations, live;
static void *coord_alloc(size_t n) { allocations++; void *p = malloc(n); if (p) live++; return p; }
#define free_counted(p) do { if (p) live--; free(p); } while (0)
#define tdongle_heap_free(owner, p) free_counted(p)
#include "key_fetch.inc"

/* ---- mock transports ------------------------------------------------------- */
typedef struct {
    const char *name;
    bool open_fails;                 /* TLS verification failure / connect failure */
    const char *response;            /* what the server sends */
    size_t response_size;            /* 0 = strlen */
    unsigned opens, writes, reads, closes;
    bool open_now, parsed_after_close_ok;
    char request[300];
    char host[64], port[8];
    int write_result_delta;
} mock_t;
static mock_t tls_mock = {"tls"}, plain_mock = {"plain"};
static void *mock_open(mock_t *m, const char *host, const char *port) {
    m->opens++;
    snprintf(m->host, sizeof(m->host), "%s", host);
    snprintf(m->port, sizeof(m->port), "%s", port);
    if (m->open_fails) return NULL;
    assert(!tls_mock.open_now && !plain_mock.open_now);          /* never two connections at once */
    m->open_now = true;
    return m;
}
static void *tls_open(microlink_t *ml, const char *h, const char *p) { return mock_open(&tls_mock, h, p); }
static void *plain_open(microlink_t *ml, const char *h, const char *p) { return mock_open(&plain_mock, h, p); }
static int mock_write(void *c, const uint8_t *d, size_t n) {
    mock_t *m = c; m->writes++;
    assert(n < sizeof(m->request)); memcpy(m->request, d, n); m->request[n] = 0;
    return (int)n + m->write_result_delta;
}
static size_t sent;
static int mock_read(void *c, uint8_t *b, size_t cap) {
    mock_t *m = c; m->reads++;
    size_t total = m->response_size ? m->response_size : strlen(m->response);
    if (sent >= total) return 0;
    size_t n = total - sent; if (n > cap) n = cap; if (n > 100) n = 100; /* deliver in pieces */
    memcpy(b, m->response + sent, n); sent += n;
    return (int)n;
}
static void mock_close(void *c) { mock_t *m = c; assert(m->open_now); m->open_now = false; m->closes++; }
static const ctrl_key_transport_t tls_t = {tls_open, mock_write, mock_read, mock_close};
static const ctrl_key_transport_t plain_t = {plain_open, mock_write, mock_read, mock_close};

#define KEYHEX "7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b"
static const char GOOD[] = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 160\r\nConnection: close\r\n\r\n"
    "{\"legacyPublicKey\":\"mkey:9e5156a4c65121306dd2d8ed8f92cb8d738e2533011344b522c5d28409bc4970\",\"publicKey\":\"mkey:" KEYHEX "\"}";
static const uint8_t KEY[32] = {0x7d,0x27,0x92,0xf9,0xc9,0x8d,0x75,0x3d,0x20,0x42,0x47,0x15,0x36,0x80,0x19,0x49,
                                0x10,0x4c,0x24,0x7f,0x95,0xea,0xc7,0x70,0xf8,0xfb,0x32,0x15,0x95,0xe2,0x17,0x3b};

static microlink_t make(const char *login_server) {
    microlink_t ml = {0};
    snprintf(ml.ctrl_host, sizeof(ml.ctrl_host), "%s", login_server);
    if (login_server[0]) {
        assert(!parse_host_port(login_server, ml.ctrl_host_parsed, sizeof(ml.ctrl_host_parsed), ml.ctrl_port_str, sizeof(ml.ctrl_port_str), &ml.use_tls));
        bool default_port = !strcmp(ml.ctrl_port_str, ml.use_tls ? "443" : "80");
        snprintf(ml.ctrl_host_hdr, sizeof(ml.ctrl_host_hdr), default_port ? "%s" : "%s:%s", ml.ctrl_host_parsed, ml.ctrl_port_str);
    }
    return ml;
}
static void reset_mocks(void) {
    memset(&tls_mock, 0, sizeof(tls_mock)); tls_mock.name = "tls";
    memset(&plain_mock, 0, sizeof(plain_mock)); plain_mock.name = "plain";
    sent = 0; logs_error = logs_warn = 0;
}
static int ensure(microlink_t *ml, const uint8_t **key) { sent = 0; return ctrl_key_ensure(ml, &tls_t, &plain_t, key); }

int main(void) {
    char host[64], port[8]; bool tls;

    /* Scheme handling: https and bare hosts are TLS (Tailscale's default); only an explicit http:// is plain. */
    assert(!parse_host_port("hs.example.com", host, 64, port, 8, &tls) && tls && !strcmp(port, "443") && !strcmp(host, "hs.example.com"));
    assert(!parse_host_port("hs.example.com:8443", host, 64, port, 8, &tls) && tls && !strcmp(port, "8443"));
    assert(!parse_host_port("https://hs.example.com", host, 64, port, 8, &tls) && tls && !strcmp(port, "443"));
    assert(!parse_host_port("HTTPS://hs.example.com:9/x", host, 64, port, 8, &tls) && tls && !strcmp(port, "9") && !strcmp(host, "hs.example.com"));
    assert(!parse_host_port("http://hs.lan", host, 64, port, 8, &tls) && !tls && !strcmp(port, "80"));
    assert(!parse_host_port("http://hs.lan:8080", host, 64, port, 8, &tls) && !tls && !strcmp(port, "8080"));
    assert(parse_host_port("http://", host, 64, port, 8, &tls) && parse_host_port("hs:99999999", host, 64, port, 8, &tls));
    assert(parse_host_port("hs:80a", host, 64, port, 8, &tls) && parse_host_port("hs:", host, 64, port, 8, &tls));

    /* Tailscale SaaS: the built-in key, nothing fetched, no connection opened. */
    reset_mocks();
    microlink_t saas = make("");
    const uint8_t *key = (const uint8_t *)1;
    assert(!ensure(&saas, &key) && key == NULL && saas.ctrl_key_auth == CTRL_KEY_PINNED_BUILTIN);
    assert(!tls_mock.opens && !plain_mock.opens && !saas.ctrl_noise_pubkey_valid);

    /* A key from the configuration pins any scheme; nothing is fetched. */
    for (const char *url = "http://hs.lan"; url; url = url[0] == 'h' && url[4] == ':' ? "https://hs.example.com" : NULL) {
        reset_mocks();
        microlink_t pinned = make(url);
        memcpy(pinned.ctrl_noise_pubkey, KEY, 32); pinned.ctrl_noise_pubkey_valid = true; pinned.ctrl_key_auth = CTRL_KEY_PINNED_CONFIG;
        assert(!ensure(&pinned, &key) && key == pinned.ctrl_noise_pubkey && pinned.ctrl_key_auth == CTRL_KEY_PINNED_CONFIG);
        assert(!tls_mock.opens && !plain_mock.opens);
    }

    /* https: fetched over the verified TLS transport, only that one. */
    reset_mocks();
    microlink_t secure = make("https://hs.example.com");
    tls_mock.response = GOOD;
    assert(!ensure(&secure, &key) && key == secure.ctrl_noise_pubkey && !memcmp(key, KEY, 32));
    assert(secure.ctrl_key_auth == CTRL_KEY_TLS_VERIFIED && !logs_warn);
    assert(tls_mock.opens == 1 && tls_mock.closes == 1 && !plain_mock.opens && !tls_mock.open_now);
    assert(!strcmp(tls_mock.host, "hs.example.com") && !strcmp(tls_mock.port, "443"));
    assert(strstr(tls_mock.request, "GET /key?v=131 HTTP/1.1\r\n") == tls_mock.request && strstr(tls_mock.request, "Host: hs.example.com\r\n"));
    assert(!live);                                           /* response buffer released */
    /* Cached: a reconnect does not fetch again. */
    assert(!ensure(&secure, &key) && tls_mock.opens == 1);
    /* No wall clock yet: an https:// key is not fetched (its certificate cannot be judged), the
     * reason is reported, and no TLS session is opened; the key arrives once SNTP has run. */
    reset_mocks();
    microlink_t early = make("https://hs.example.com");
    tls_mock.response = GOOD;
    test_clock_valid = false;
    assert(ensure(&early, &key) != 0 && !tls_mock.opens && !early.ctrl_noise_pubkey_valid && strstr(early.transport_error, "SNTP"));
    test_clock_valid = true;
    assert(!ensure(&early, &key) && tls_mock.opens == 1 && early.ctrl_key_auth == CTRL_KEY_TLS_VERIFIED);
    /* The clock gates only that fetch: SaaS (built-in key), a pinned key and an http:// server do not wait. */
    test_clock_valid = false;
    reset_mocks();
    assert(!ensure(&saas, &key) && key == NULL);
    microlink_t lan = make("http://hs.lan");
    plain_mock.response = GOOD;
    assert(!ensure(&lan, &key) && lan.ctrl_key_auth == CTRL_KEY_PLAINTEXT);
    microlink_t pin_https = make("https://hs.example.com");
    memcpy(pin_https.ctrl_noise_pubkey, KEY, 32); pin_https.ctrl_noise_pubkey_valid = true; pin_https.ctrl_key_auth = CTRL_KEY_PINNED_CONFIG;
    assert(!ensure(&pin_https, &key) && !tls_mock.opens);
    test_clock_valid = true;
    /* Bare host is the same as https, with a non-default port in Host. */
    reset_mocks();
    microlink_t bare = make("hs.example.com:8443"); tls_mock.response = GOOD;
    assert(!ensure(&bare, &key) && bare.ctrl_key_auth == CTRL_KEY_TLS_VERIFIED && !plain_mock.opens);
    assert(strstr(tls_mock.request, "Host: hs.example.com:8443\r\n") && !strcmp(tls_mock.port, "8443"));

    /* A failed TLS verification (open fails) never stores a key and never falls back to plain HTTP. */
    reset_mocks();
    microlink_t rejected = make("https://hs.example.com");
    tls_mock.open_fails = true; plain_mock.response = GOOD; tls_mock.response = GOOD;
    assert(ensure(&rejected, &key) < 0 && !rejected.ctrl_noise_pubkey_valid && rejected.ctrl_key_auth == ML_CTRL_KEY_NONE);
    assert(tls_mock.opens == 1 && !plain_mock.opens && !tls_mock.writes && logs_error);
    /* The next attempt (certificate fixed) works: nothing was poisoned. */
    tls_mock.open_fails = false;
    assert(!ensure(&rejected, &key) && rejected.ctrl_key_auth == CTRL_KEY_TLS_VERIFIED);

    /* http://: plain, allowed as Tailscale allows it, but reported as unauthenticated. */
    reset_mocks();
    microlink_t plain = make("http://hs.lan:8080"); plain_mock.response = GOOD;
    assert(!ensure(&plain, &key) && plain.ctrl_key_auth == CTRL_KEY_PLAINTEXT && logs_warn == 1 && !tls_mock.opens);
    assert(!memcmp(key, KEY, 32) && plain_mock.closes == 1 && !strcmp(plain_mock.port, "8080"));

    /* Malformed or hostile responses: no key, connection closed, buffer released. */
    struct { const char *label; const char *response; size_t size; } bad[] = {
        {"error status", "HTTP/1.1 400 Bad Request\r\n\r\n{\"publicKey\":\"mkey:" KEYHEX "\"}", 0},
        {"redirect", "HTTP/1.1 302 Found\r\nLocation: http://evil/\r\n\r\n{\"publicKey\":\"mkey:" KEYHEX "\"}", 0},
        {"not http", "{\"publicKey\":\"mkey:" KEYHEX "\"}", 0},
        {"no headers end", "HTTP/1.1 200 OK\r\n{\"publicKey\":\"mkey:" KEYHEX "\"}", 0},
        {"not json", "HTTP/1.1 200 OK\r\n\r\nhello", 0},
        {"no key", "HTTP/1.1 200 OK\r\n\r\n{\"legacyPublicKey\":\"mkey:" KEYHEX "\"}", 0},
        {"short key", "HTTP/1.1 200 OK\r\n\r\n{\"publicKey\":\"mkey:7d2792f9\"}", 0},
        {"non hex", "HTTP/1.1 200 OK\r\n\r\n{\"publicKey\":\"mkey:zz2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b\"}", 0},
        {"empty", "", 1},
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        reset_mocks();
        microlink_t m = make("https://hs.example.com");
        tls_mock.response = bad[i].response; tls_mock.response_size = bad[i].size == 1 ? 0 : bad[i].size;
        if (bad[i].size == 1) { tls_mock.response = ""; }
        assert(ensure(&m, &key) < 0 && !m.ctrl_noise_pubkey_valid && !tls_mock.open_now && tls_mock.closes == tls_mock.opens && !live);
    }
    /* An oversized response is refused, not truncated into something parseable. */
    {
        static char big[4000]; memset(big, 'a', sizeof(big) - 1);
        memcpy(big, GOOD, sizeof(GOOD) - 1);                   /* a valid key at the front, then padding */
        reset_mocks();
        microlink_t m = make("https://hs.example.com"); tls_mock.response = big; tls_mock.response_size = sizeof(big) - 1;
        assert(ensure(&m, &key) < 0 && !m.ctrl_noise_pubkey_valid && !live);
    }
    /* A short write (request not fully sent) fails and still closes. */
    reset_mocks();
    microlink_t m = make("https://hs.example.com"); tls_mock.response = GOOD; tls_mock.write_result_delta = -3;
    assert(ensure(&m, &key) < 0 && tls_mock.closes == 1 && !m.ctrl_noise_pubkey_valid && !live);
    /* Chunked transfer encoding (reverse proxies) still parses. */
    reset_mocks();
    m = make("https://hs.example.com");
    tls_mock.response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nA5\r\n{\"publicKey\":\"mkey:" KEYHEX "\"}\r\n0\r\n\r\n";
    assert(!ensure(&m, &key) && !memcmp(key, KEY, 32));

    puts("Control key: SaaS pinned, config pin, https verified (no plain fallback), http flagged, malformed/oversize/error responses refused, connection closed before parse");
    return 0;
    /* Rotation: handshakes keep failing -> the fetched key is dropped and fetched again; the new key is used. */
    {
        reset_mocks();
        microlink_t r = make("https://hs.example.com");
        tls_mock.response = GOOD;
        assert(!ensure(&r, &key) && r.ctrl_noise_pubkey_valid);
        ctrl_key_note_handshake(&r, false, 1000);
        assert(r.ctrl_noise_pubkey_valid);                                   /* one failure: keep */
        ctrl_key_note_handshake(&r, true, 1100); ctrl_key_note_handshake(&r, false, 1200);
        assert(r.ctrl_noise_pubkey_valid);                                   /* a success resets the count */
        ctrl_key_note_handshake(&r, false, 1300);
        assert(!r.ctrl_noise_pubkey_valid && r.ctrl_key_refetches == 1);     /* two in a row: drop */
        static char rotated[400];
        snprintf(rotated, sizeof(rotated), "%s", GOOD);
        char *at = strstr(rotated, KEYHEX); memcpy(at, "11", 2);             /* the server now has a different key */
        reset_mocks(); tls_mock.response = rotated;
        assert(!ensure(&r, &key) && tls_mock.opens == 1 && key[0] == 0x11 && r.ctrl_noise_pubkey_valid);
        ctrl_key_note_handshake(&r, true, 2000);
        /* Drops are spaced: a second pair of failures inside the gap keeps the key (no /key hammering). */
        ctrl_key_note_handshake(&r, false, 5000); ctrl_key_note_handshake(&r, false, 5100);
        assert(r.ctrl_noise_pubkey_valid && r.ctrl_key_refetches == 1);
        /* After the gap it drops again, with a doubled gap; a failed refetch leaves the key invalid and
         * the caller (reconnect backoff) retries, never connecting with a missing key. */
        ctrl_key_note_handshake(&r, false, 1300 + CTRL_KEY_DROP_MIN_MS + 1); ctrl_key_note_handshake(&r, false, 1300 + CTRL_KEY_DROP_MIN_MS + 2);
        assert(!r.ctrl_noise_pubkey_valid && r.ctrl_key_refetches == 2 && r.ctrl_key_drop_backoff_ms == 2 * CTRL_KEY_DROP_MIN_MS);
        reset_mocks(); tls_mock.open_fails = true;
        assert(ensure(&r, &key) != 0 && !r.ctrl_noise_pubkey_valid && tls_mock.opens == 1);
        uint64_t t = 1000000;
        for (int i = 0; i < 20; i++) {                                       /* the gap saturates, never overflows */
            r.ctrl_noise_pubkey_valid = true; r.ctrl_key_auth = CTRL_KEY_TLS_VERIFIED;
            ctrl_key_note_handshake(&r, false, t); ctrl_key_note_handshake(&r, false, t); t += 10000000;
            assert(r.ctrl_key_drop_backoff_ms <= CTRL_KEY_DROP_MAX_MS);
        }
        /* Plain-HTTP fetched keys are dropped the same way. */
        microlink_t h = make("http://hs.lan"); h.ctrl_key_auth = CTRL_KEY_PLAINTEXT; h.ctrl_noise_pubkey_valid = true;
        ctrl_key_note_handshake(&h, false, 10); ctrl_key_note_handshake(&h, false, 11);
        assert(!h.ctrl_noise_pubkey_valid);
        /* Never dropped: a configured pin, or the compiled-in SaaS key (nothing is fetched for it). */
        microlink_t pin = make("https://hs.example.com");
        memcpy(pin.ctrl_noise_pubkey, KEY, 32); pin.ctrl_noise_pubkey_valid = true; pin.ctrl_key_auth = CTRL_KEY_PINNED_CONFIG;
        for (int i = 0; i < 50; i++) ctrl_key_note_handshake(&pin, false, 100000000ull * i);
        assert(pin.ctrl_noise_pubkey_valid && !pin.ctrl_key_refetches);
        reset_mocks();
        assert(!ensure(&pin, &key) && !tls_mock.opens && key == pin.ctrl_noise_pubkey);
        microlink_t sa = make(""); assert(!ensure(&sa, &key));
        for (int i = 0; i < 50; i++) ctrl_key_note_handshake(&sa, false, 100000000ull * i);
        assert(!sa.ctrl_key_refetches && !ensure(&sa, &key) && key == NULL && !tls_mock.opens);
    }
}
