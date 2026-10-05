/**
 * @file microlink.c
 * @brief MicroLink v2 - Public API and Task Orchestration
 *
 * Creates all FreeRTOS tasks, queues, and event groups.
 * Provides the public API that the application calls.
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "cJSON.h"
#include "esp_tls.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include "lwip/sockets.h"
#include "wireguard-platform.h"
#include "ml_runtime.h"

#ifdef CONFIG_ML_ENABLE_CELLULAR
#include "ml_cellular.h"
#endif

static const char *TAG = "microlink";

/* NVS keys */
#define NVS_NAMESPACE       "microlink"
#define NVS_KEY_MACHINE_PRI "machine_pri"
#define NVS_KEY_MACHINE_PUB "machine_pub"
#define NVS_KEY_WG_PRI      "wg_private"
#define NVS_KEY_WG_PUB      "wg_public"
#define NVS_KEY_DISCO_PRI   "disco_pri"
#define NVS_KEY_DISCO_PUB   "disco_pub"

/* X25519 from ml_x25519.h */
#include "ml_x25519.h"

/* ============================================================================
 * Key Management (loaded once at init, read-only after)
 * ========================================================================== */

static void generate_keypair(uint8_t *private_key, uint8_t *public_key) {
    esp_fill_random(private_key, 32);
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    ml_x25519_base(public_key, private_key, 1);
}

static esp_err_t load_or_generate_keys(microlink_t *ml) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(ml->identity_namespace, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    uint8_t keys[96]; size_t len = sizeof(keys);
    err = nvs_get_blob(nvs, "identity_v1", keys, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        uint8_t pub[32];
        for (int i = 0; i < 3; i++) generate_keypair(keys + 32*i, pub);
        err = nvs_set_blob(nvs, "identity_v1", keys, sizeof(keys));
        if (err == ESP_OK) err = nvs_commit(nvs);
    } else if (err == ESP_OK && len != sizeof(keys)) err = ESP_ERR_INVALID_SIZE;
    nvs_close(nvs);
    if (err == ESP_OK) {
        memcpy(ml->machine_private_key, keys, 32);
        memcpy(ml->wg_private_key, keys + 32, 32);
        memcpy(ml->disco_private_key, keys + 64, 32);
        ml_x25519_base(ml->machine_public_key, ml->machine_private_key, 1);
        ml_x25519_base(ml->wg_public_key, ml->wg_private_key, 1);
        ml_x25519_base(ml->disco_public_key, ml->disco_private_key, 1);
        ml->identity_persistent = true;
    }
    memset(keys, 0, sizeof(keys));
    return err;
}

/* ============================================================================
 * cJSON PSRAM Hooks
 * ========================================================================== */

static void *cjson_psram_malloc(size_t size) {
    return tdongle_heap_tag(TDONGLE_OWNER_MAP, ml_psram_malloc(size));
}

static void cjson_free(void *block) {
    tdongle_heap_free(TDONGLE_OWNER_MAP, block);
}

/* ============================================================================
 * Factory Reset
 * ========================================================================== */

esp_err_t microlink_factory_reset(void) {
    esp_err_t err;

    /* Erase key namespace */
    nvs_handle_t nvs;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
        ESP_LOGI(TAG, "Factory reset: keys erased");
    }

    /* Erase cached peers */
    /* Global peer cache disabled in multi-instance firmware. */



    ESP_LOGI(TAG, "Factory reset complete");
    return ESP_OK;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

/* "mkey:<64 hex>" or "<64 hex>" -> 32 bytes. */
static bool ml_parse_noise_key(const char *text, uint8_t out[32]) {
    if (strncmp(text, "mkey:", 5) == 0) text += 5;
    if (strlen(text) != 64) return false;
    for (int i = 0; i < 32; i++) {
        int v[2];
        for (int j = 0; j < 2; j++) {
            char c = text[2 * i + j];
            v[j] = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                   (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
            if (v[j] < 0) return false;
        }
        out[i] = (uint8_t)(v[0] << 4 | v[1]);
    }
    return true;
}

microlink_t *microlink_init(const microlink_config_t *config) {
    if (!config || !config->auth_key) {
        ESP_LOGE(TAG, "Invalid config: auth_key required");
        return NULL;
    }

    /* Route cJSON to PSRAM */
    cJSON_Hooks hooks = {
        .malloc_fn = cjson_psram_malloc,
        .free_fn = cjson_free
    };
    cJSON_InitHooks(&hooks);

    /* Allocate context from PSRAM */
    microlink_t *ml = tdongle_heap_tag(TDONGLE_OWNER_CONTEXT, ml_psram_calloc(1, sizeof(microlink_t)));
    if (!ml) {
        ESP_LOGE(TAG, "Failed to allocate context");
        return NULL;
    }

    if (!config->identity_namespace || !config->identity_namespace[0] || strlen(config->identity_namespace) > 15) {
        tdongle_heap_free(TDONGLE_OWNER_CONTEXT, ml); return NULL;
    }
    snprintf(ml->identity_namespace, sizeof(ml->identity_namespace), "%s", config->identity_namespace);
    /* Copy config */
    ml->config = *config;
    if (ml->config.max_peers == 0) ml->config.max_peers = ML_MAX_PEERS;
    if (ml->config.max_peers > ML_MAX_PEERS) ml->config.max_peers = ML_MAX_PEERS;
    ml->config.enable_derp = true;  /* Always need DERP for relay */

    /* An operator supplied control-server key pins it for any scheme. A key
     * that does not parse is refused rather than ignored: ignoring it would
     * quietly turn a pinned deployment into an unauthenticated key fetch. */
    if (config->ctrl_noise_key && config->ctrl_noise_key[0]) {
        if (!ml_parse_noise_key(config->ctrl_noise_key, ml->ctrl_noise_pubkey)) {
            ESP_LOGE(TAG, "ctrl_noise_key must be 64 hex digits, optionally prefixed mkey:");
            tdongle_heap_free(TDONGLE_OWNER_CONTEXT, ml); return NULL;
        }
        ml->ctrl_noise_pubkey_valid = true;
        ml->ctrl_key_auth = ML_CTRL_KEY_PINNED_CONFIG;
    }
    ml->config.ctrl_noise_key = NULL; /* the caller's string is not retained */

    /* Seed derp_region_default from config so MapRequest.PreferredDERP and
     * the GUI marker have a value before the first MapResponse arrives. */
    ml->derp_region_default = ml->config.preferred_derp_region
                              ? ml->config.preferred_derp_region
                              : ML_DERP_REGION;

    ml->state = ML_STATE_IDLE;
    ml->register_user_id = -1;        /* "no RegisterResponse yet" */
    ml->register_user_name[0] = '\0';
    ml->coord_sock = -1;
    ml->use_tls    = false;
    ml->coord_tls  = NULL;
    ml->disco_sock4 = -1;
    ml->disco_sock6 = -1;
    ml->stun_sock = -1;
    ml->stun_sock6 = -1;
    ml_derp_member_init(ml);

    /* Resolve timing (0 = use defaults from #defines) */
    ml->t_disco_heartbeat_ms = ml->config.disco_heartbeat_ms ? ml->config.disco_heartbeat_ms : ML_DISCO_HEARTBEAT_MS;
    ml->t_stun_interval_ms = ml->config.stun_interval_ms ? ml->config.stun_interval_ms : ML_STUN_RESTUN_INTERVAL_MS;
    ml->t_ctrl_watchdog_ms = ml->config.ctrl_watchdog_ms ? ml->config.ctrl_watchdog_ms : ML_CTRL_WATCHDOG_MS;

    /* Apply Kconfig priority peer if set and app didn't provide one */
    if (ml->config.priority_peer_ip == 0 && strlen(CONFIG_ML_PRIORITY_PEER_IP) > 0) {
        ml->config.priority_peer_ip = microlink_parse_ip(CONFIG_ML_PRIORITY_PEER_IP);
        if (ml->config.priority_peer_ip) {
            ESP_LOGI(TAG, "Priority peer from Kconfig: %s", CONFIG_ML_PRIORITY_PEER_IP);
        }
    }

    /* Load or generate persistent keys */
    if (load_or_generate_keys(ml) != ESP_OK) {
        tdongle_heap_free(TDONGLE_OWNER_CONTEXT, ml);
        return NULL;
    }

    /* Initialize the TAI64N timestamp base used by wireguard-lwip handshake
     * inits. Peers reject any init timestamp <= the one we sent in our
     * previous boot (replay-attack guard in the WireGuard spec). We persist
     * a per-boot counter in NVS so this boot's base + uptime is always
     * strictly greater than the previous boot's max-emitted timestamp.
     * If real wall-clock has synced (SNTP), prefer that. */
    {
        uint64_t base_seconds = 0;
        time_t wallclock = 0;
        time(&wallclock);
        if (wallclock > 1700000000) {
            base_seconds = (uint64_t)wallclock;
        } else {
            nvs_handle_t h;
            if (nvs_open(ml->identity_namespace, NVS_READWRITE, &h) == ESP_OK) {
                uint64_t prev = 0;
                size_t sz = sizeof(prev);
                nvs_get_blob(h, "wg_tai_base", &prev, &sz);
                base_seconds = prev + 86400ULL; /* +1 day per boot */
                nvs_set_blob(h, "wg_tai_base", &base_seconds, sizeof(base_seconds));
                nvs_commit(h);
                nvs_close(h);
            }
        }
        wireguard_set_tai64n_base_seconds(base_seconds);
        ESP_LOGI(TAG, "TAI64N base seconds set to %llu (wallclock=%lld)",
                 (unsigned long long)base_seconds, (long long)wallclock);
    }

    /* Initialize peer NVS cache */
    /* Global peer cache disabled in multi-instance firmware. */

    /* Initialize HTTP config server (loads NVS peer allowlist + settings) */
    ml->config_httpd = NULL;

    /* Override config with NVS-saved settings (web UI save → restart flow).
     * NVS settings take priority over Kconfig defaults.  Strings are copied
     * into ml->nvs_* buffers so the const char* pointers remain valid. */
    if (ml->config_httpd) {
        const char *nvs_auth = ml_config_get_auth_key(ml->config_httpd);
        if (nvs_auth) {
            strncpy(ml->nvs_auth_key, nvs_auth, sizeof(ml->nvs_auth_key) - 1);
            ml->config.auth_key = ml->nvs_auth_key;
            ESP_LOGI(TAG, "Auth key overridden from NVS (len=%d)", (int)strlen(nvs_auth));
        }
        /* Device name: full name takes priority, then prefix+MAC, then Kconfig */
        const char *nvs_full_name = ml_config_get_device_name_full(ml->config_httpd);
        if (nvs_full_name) {
            /* Full custom hostname (e.g. "sensor-tailscale") */
            strncpy(ml->nvs_device_name, nvs_full_name, sizeof(ml->nvs_device_name) - 1);
            ml->config.device_name = ml->nvs_device_name;
            ESP_LOGI(TAG, "Device name from NVS (full): %s", ml->nvs_device_name);
        } else {
            const char *nvs_prefix = ml_config_get_device_prefix(ml->config_httpd);
            if (nvs_prefix) {
                /* Device name = prefix + MAC suffix (e.g. "sensor-a1b2c3") */
                uint8_t mac[6];
                esp_read_mac(mac, ESP_MAC_WIFI_STA);
                snprintf(ml->nvs_device_name, sizeof(ml->nvs_device_name),
                         "%s-%02x%02x%02x", nvs_prefix, mac[3], mac[4], mac[5]);
                ml->config.device_name = ml->nvs_device_name;
                ESP_LOGI(TAG, "Device name from NVS (prefix): %s", ml->nvs_device_name);
            }
        }

        /* v2 overrides */
        uint8_t nvs_max = ml_config_get_max_peers(ml->config_httpd);
        if (nvs_max > 0 && nvs_max <= ML_MAX_PEERS) {
            ml->config.max_peers = nvs_max;
            ESP_LOGI(TAG, "Max peers overridden from NVS: %d", nvs_max);
        }
        uint16_t nvs_hb = ml_config_get_disco_heartbeat_ms(ml->config_httpd);
        if (nvs_hb > 0 && nvs_hb <= 60000) {
            ml->config.disco_heartbeat_ms = nvs_hb;
            ml->t_disco_heartbeat_ms = nvs_hb;
            ESP_LOGI(TAG, "DISCO heartbeat overridden from NVS: %dms", nvs_hb);
        }
        uint32_t nvs_pip = ml_config_get_priority_peer_ip(ml->config_httpd);
        if (nvs_pip > 0) {
            ml->config.priority_peer_ip = nvs_pip;
            char pip_str[16];
            microlink_ip_to_str(nvs_pip, pip_str);
            ESP_LOGI(TAG, "Priority peer overridden from NVS: %s", pip_str);
        }
        const char *nvs_ctrl = ml_config_get_ctrl_host(ml->config_httpd);
        if (nvs_ctrl) {
            strncpy(ml->ctrl_host, nvs_ctrl, sizeof(ml->ctrl_host) - 1);
            ESP_LOGI(TAG, "Control plane overridden from NVS: %s", ml->ctrl_host);
        }
        ml->debug_flags = ml_config_get_debug_flags(ml->config_httpd);
        if (ml->debug_flags) {
            ESP_LOGI(TAG, "Debug flags from NVS: 0x%02x", ml->debug_flags);
        }
    }

    /* Public-config plumbing for ctrl_host / advertise_routes — these mirror
     * the NVS-override semantics above but apply even when the HTTP config
     * server is disabled (CONFIG_ML_ENABLE_CONFIG_HTTPD=n). They give an
     * embedding host (e.g. an integrating component) a way to drive the
     * coordinator URL and subnet routes directly through microlink_config_t,
     * without having to write to microlink's internal NVS namespace. */
    if (ml->config.ctrl_host && ml->config.ctrl_host[0]) {
        strncpy(ml->ctrl_host, ml->config.ctrl_host, sizeof(ml->ctrl_host) - 1);
        ml->ctrl_host[sizeof(ml->ctrl_host) - 1] = '\0';
        ESP_LOGI(TAG, "Control plane from config: %s", ml->ctrl_host);
    }
    if (ml->config.advertise_routes && ml->config.advertise_routes[0]) {
        strncpy(ml->advertise_routes, ml->config.advertise_routes,
                sizeof(ml->advertise_routes) - 1);
        ml->advertise_routes[sizeof(ml->advertise_routes) - 1] = '\0';
        ESP_LOGI(TAG, "Advertised routes from config: %s", ml->advertise_routes);
    }

    /* Create event group */
    ml->events = xEventGroupCreate();
    if (!ml->events) {
        ESP_LOGE(TAG, "Failed to create event group");
        tdongle_heap_free(TDONGLE_OWNER_CONTEXT, ml);
        return NULL;
    }

    /* Create queues */
    ml->derp_tx_queue = xQueueCreate(ML_DERP_TX_QUEUE_DEPTH, sizeof(ml_derp_tx_item_t));
    ml->disco_rx_queue = xQueueCreate(ML_DISCO_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->wg_rx_queue = xQueueCreate(ML_WG_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->stun_rx_queue = xQueueCreate(ML_STUN_RX_QUEUE_DEPTH, sizeof(ml_rx_packet_t));
    ml->coord_cmd_queue = xQueueCreate(ML_COORD_CMD_QUEUE_DEPTH, sizeof(ml_coord_cmd_t));
    ml->peer_update_queue = xQueueCreate(ML_PEER_UPDATE_QUEUE_DEPTH, sizeof(ml_peer_update_t *));

    if (!ml->derp_tx_queue || !ml->disco_rx_queue || !ml->wg_rx_queue ||
        !ml->stun_rx_queue || !ml->coord_cmd_queue || !ml->peer_update_queue) {
        ESP_LOGE(TAG, "Failed to create queues");
        microlink_destroy(ml);
        return NULL;
    }

    ESP_LOGI(TAG, "MicroLink v2 initialized (max_peers=%d)", ml->config.max_peers);
    return ml;
}

esp_err_t microlink_start(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    if (ml->state != ML_STATE_IDLE) {
        ESP_LOGW(TAG, "Already started (state=%d)", ml->state);
        return ESP_ERR_INVALID_STATE;
    }

    /* Diagnostics guard (always true in a release build): decide before any state change, socket or
     * task exists, so a refusal leaves the instance idle and a later microlink_start can retry. The shared
     * tasks' stacks are charged to the first membership only. */
    if (!tdongle_memory_start_allowed(ML_TASK_COORD_STACK + ml_rt_start_bytes())) {
        ESP_LOGE(TAG, "Not enough heap above the diagnostics guard floor for the membership tasks");
        return ESP_ERR_NO_MEM;
    }

    ml->state = ML_STATE_WIFI_WAIT;

    /* Set WiFi TX power if configured */
    if (ml->config.wifi_tx_power_dbm > 0) {
        int8_t power_quarter_dbm = ml->config.wifi_tx_power_dbm * 4;
        esp_wifi_set_max_tx_power(power_quarter_dbm);
        ESP_LOGI(TAG, "WiFi TX power set to %d dBm", ml->config.wifi_tx_power_dbm);
    }

#ifdef CONFIG_ML_ZERO_COPY_WG
    /* Zero-copy mode: raw lwIP PCB replaces BSD socket for DISCO/WG UDP.
     * WG packets go directly to wireguardif_network_rx() from tcpip_thread.
     * DISCO packets go to SPSC ring buffer, STUN to existing queue. */
    if (ml_zerocopy_init(ml) != ESP_OK) {
        ESP_LOGE(TAG, "Zero-copy init failed, falling back to BSD socket");
        goto bsd_socket_fallback;
    }
    ESP_LOGI(TAG, "Zero-copy WG mode active (high-throughput)");
    goto skip_bsd_socket;

bsd_socket_fallback:
#endif
    /* Create DISCO/magicsock UDP socket (port 51820 = WireGuard standard)
     * This is the single socket for ALL direct UDP traffic: DISCO pings/pongs,
     * CallMeMaybe probes, and WireGuard encrypted data.
     * Matches v1 microlink_disco_init() and tailscale's pconn4. */
    ml->disco_sock4 = ml_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ml->disco_sock4 >= 0) {
        struct sockaddr_in bind_addr = {
            .sin_family = AF_INET,
            .sin_port = 0,
            .sin_addr.s_addr = INADDR_ANY,
        };
        if (ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            ESP_LOGW(TAG, "Failed to bind port 51820 (errno=%d), trying ephemeral", errno);
            bind_addr.sin_port = 0;
            ml_bind(ml->disco_sock4, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
        }

        /* Mark packets as DSCP 46 (Expedited Forwarding) → WMM AC_VO.
         * WiFi APs with WMM use shorter contention windows for voice-priority
         * traffic, reducing jitter on WireGuard/DISCO UDP packets. */
        int tos = 0xB8;  /* DSCP 46 = EF, TOS byte = 46 << 2 = 184 */
        setsockopt(ml->disco_sock4, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

        /* Set non-blocking for select() in net_io */
        int flags = ml_fcntl(ml->disco_sock4, F_GETFL, 0);
        ml_fcntl(ml->disco_sock4, F_SETFL, flags | O_NONBLOCK);

        /* Record the actual bound port (getsockname not wrapped — AT sockets use stored port) */
        struct sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        getsockname(ml->disco_sock4, (struct sockaddr *)&local_addr, &addr_len);
        ml->disco_local_port = ntohs(local_addr.sin_port);
        ESP_LOGI(TAG, "DISCO/magicsock UDP socket bound to port %d", ml->disco_local_port);
    } else {
        ESP_LOGE(TAG, "Failed to create DISCO socket: errno=%d", errno);
    }
#ifdef CONFIG_ML_ZERO_COPY_WG
skip_bsd_socket:
    ;
#endif

    /* Join the shared net_io / derp / wg_mgr tasks (started by the first membership), then create the one
     * task a membership keeps for itself: the control plane. */
    esp_err_t rt_err = ml_rt_attach(ml);
    if (rt_err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to join the shared runtime: %s", esp_err_to_name(rt_err));
        goto start_failed;
    }

    __atomic_add_fetch(&ml->tasks_alive, 1, __ATOMIC_SEQ_CST);
    if (xTaskCreatePinnedToCore(ml_coord_task, "ml_coord", ML_TASK_COORD_STACK,
                                ml, ML_TASK_COORD_PRIO, &ml->coord_task, ML_TASK_COORD_CORE) != pdPASS) {
        __atomic_sub_fetch(&ml->tasks_alive, 1, __ATOMIC_SEQ_CST);
        ESP_LOGE(TAG, "Failed to create coord task");
        rt_err = ESP_ERR_NO_MEM;
        goto start_failed;
    }

    /* WiFi is expected to be connected before microlink_start() is called.
     * Signal the event so coord/wg_mgr tasks proceed immediately. */
    xEventGroupSetBits(ml->events, ML_EVT_WIFI_CONNECTED);

    /* Signal coord task to start connecting */
    ml_coord_cmd_t cmd = ML_CMD_CONNECT;
    xQueueSend(ml->coord_cmd_queue, &cmd, 0);

    /* Start HTTP config server (binds port 80, serves config page + REST API) */
    if (ml->config_httpd) {
        ml_config_httpd_start(ml->config_httpd, ml);
    }

    ESP_LOGI(TAG, "All tasks started");
    return ESP_OK;

start_failed:
    /* Nothing keeps running for a start that did not complete: leave the shared tasks (their detach stops them
     * if this was the only membership), close what start opened, and report so a later start can retry. */
    ml->state = ML_STATE_IDLE;
    if (!ml_rt_detach(ml)) ml->stop_incomplete = true;
    return ESP_FAIL;
}

esp_err_t microlink_stop(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;

    ESP_LOGI(TAG, "Stopping...");
    xEventGroupSetBits(ml->events, ML_EVT_SHUTDOWN_REQUEST);

    /* Unblock the control task if it is parked in a blocking socket call so it can observe the shutdown bit
     * and self-delete BEFORE microlink_destroy() frees ml below. Without this a coord task in coord_recv
     * stays blocked past the wait, and the free() races the still-running task -> use-after-free panic
     * (observed 2026-05-26 on a WiFi-uplink bounce that re-triggered the connect/teardown path). shutdown() --
     * not close() -- wakes the recv without invalidating the fd, so the task still closes its own socket in its
     * normal error path and there is no double-close / fd-reuse race. The shared DERP, WireGuard and net_io
     * tasks never block on a membership's socket (they are non-blocking by construction), so they need no
     * such nudge: the detach below is what ends their use of this instance. */
    if (ml->coord_sock >= 0)  shutdown(ml->coord_sock,  SHUT_RDWR);
    /* TLS control-plane connection: coord_sock is -1 and the fd lives inside
     * the esp_tls handle — shut that down too so a blocked esp_tls_conn_read
     * in the coord task wakes up the same way the plain path does. The coord
     * task still owns and destroys the TLS handle in its own teardown path. */
    if (ml->coord_tls) {
        int tls_fd = -1;
        if (esp_tls_get_conn_sockfd(ml->coord_tls, &tls_fd) == ESP_OK && tls_fd >= 0)
            shutdown(tls_fd, SHUT_RDWR);
    }
    /* The coord task may be parked in its reconnect backoff (xQueueReceive on
     * coord_cmd_queue, up to a multi-second timeout) rather than in recv. Poke
     * the queue so it returns to the loop top and sees the shutdown bit
     * instead of sleeping the backoff out while we delete the queue. */
    if (ml->coord_cmd_queue) {
        ml_coord_cmd_t stop_cmd = ML_CMD_DISCONNECT;
        xQueueSend(ml->coord_cmd_queue, &stop_cmd, 0);
    }

    /* Wait for the control task to exit (it checks ML_EVT_SHUTDOWN_REQUEST).
     * Tasks call vTaskDelete(NULL) to self-delete, so we must NOT call
     * vTaskDelete() on them again — that causes a crash in uxListRemove
     * because the task's list node is already invalid. Wait for them to
     * sign off (ml_task_exiting) -- bounded, but NOT a fixed delay: a
     * coord task still inside poll_map_update() after the old 3 s sleep
     * met microlink_destroy()'s free() and died in the freed instance
     * (PANIC, reference router, three connect requests in a row). The
     * longest legitimate holdout is a blocking DNS lookup or a TLS
     * handshake that shutdown() cannot interrupt, well inside 15 s. */
    {
        const int max_wait_ms = 15000;
        int waited = 0;
        while (__atomic_load_n(&ml->tasks_alive, __ATOMIC_SEQ_CST) > 0 && waited < max_wait_ms) {
            vTaskDelay(pdMS_TO_TICKS(50));
            waited += 50;
        }
        int left = __atomic_load_n(&ml->tasks_alive, __ATOMIC_SEQ_CST);
        if (left > 0) {
            ESP_LOGE(TAG, "%d task(s) still running %d ms after the stop request -- "
                          "the instance will be leaked rather than freed under them", left, waited);
            ml->stop_incomplete = true;
        } else {
            ESP_LOGI(TAG, "All tasks exited (%d ms)", waited);
        }
    }

    ml->coord_task = NULL;

    /* Leave the shared tasks. Detach waits for the slice they may be running for this membership, tears down
     * its DERP connection and WireGuard interface under their locks, and returns only when no shared task can
     * touch ml again. If one cannot let go in time the membership stays attached and must not be freed. */
    if (!ml_rt_detach(ml)) {
        ESP_LOGE(TAG, "a shared task still holds this membership -- the instance will be leaked rather than freed under it");
        ml->stop_incomplete = true;
    }

    /* A membership that is gone never keeps the negotiation token, whatever path it was on when it was stopped
     * (the control task and the DERP link release it themselves; this is the backstop for every other way out). */
    {
        ml_neg_t *neg = ml_rt_negotiation();
        ml_neg_release(neg, ml_neg_key(ml->config.diagnostic_id, ML_NEG_PHASE_CONTROL));
        ml_neg_release(neg, ml_neg_key(ml->config.diagnostic_id, ML_NEG_PHASE_DERP));
    }

    /* Stop HTTP config server */
    if (ml->config_httpd) {
        ml_config_httpd_stop(ml->config_httpd);
    }

    /* Clean up zero-copy PCB if active */
#ifdef CONFIG_ML_ZERO_COPY_WG
    ml_zerocopy_deinit(ml);
#endif

    /* Close sockets */
    if (ml->disco_sock4 >= 0) { ml_close_sock(ml->disco_sock4); ml->disco_sock4 = -1; }
    if (ml->stun_sock >= 0) { ml_close_sock(ml->stun_sock); ml->stun_sock = -1; }
    if (ml->stun_sock6 >= 0) { ml_close_sock(ml->stun_sock6); ml->stun_sock6 = -1; }

    ml->state = ML_STATE_IDLE;
    ESP_LOGI(TAG, "Stopped");
    return ESP_OK;
}

void microlink_destroy(microlink_t *ml) {
    if (!ml) return;

    microlink_stop(ml);
    if (ml->stop_incomplete) {
        /* A task is still executing on this instance. Freeing it now is the
         * use-after-free we are here to avoid; a leaked instance is the
         * lesser evil and is loud in the log. */
        ESP_LOGE(TAG, "Destroy skipped: a task still runs on this instance (leaked on purpose)");
        return;
    }
    /* Only now is everything the tasks owned quiescent. The DERP TLS state
     * and the long-poll accumulators (two PSRAM buffers of
     * ML_JSON_BUFFER_SIZE) were never released here before: every
     * stop/start cycle lost ~650 KB on the reference router. */
    ml_directory_abort(ml);
    for(unsigned i=0;i<4;i++)tdongle_heap_free(TDONGLE_OWNER_WG, ml->jit_pending[i].packet);
    /* The DERP link was closed and its TLS state released by ml_rt_detach() (under the DERP task's lock); the
     * packets still queued for it are freed with the queues below. */
    if (ml->h2_acc) { tdongle_heap_free(TDONGLE_OWNER_CONTROL, ml->h2_acc); ml->h2_acc = NULL; ml->h2_acc_len = 0; }
    if (ml->lp_acc) { free(ml->lp_acc); ml->lp_acc = NULL; ml->lp_acc_len = 0; }

    extern void ml_gateway_release_netif(microlink_t *);
    ml_gateway_release_netif(ml);

    /* Deinitialize peer NVS */


    /* Deinitialize HTTP config server */
    if (ml->config_httpd) {
        ml_config_httpd_deinit(ml->config_httpd);
        ml->config_httpd = NULL;
    }

    /* Whatever is still queued owns heap memory: packets the disco / wg /
     * stun consumers never got to (data), peer updates the wg_mgr never
     * applied (the update itself). Free them before the queues go. The DERP
     * TX queue is drained here too: it may hold packets queued after the link closed. */
    {
        ml_rx_packet_t pkt;
        QueueHandle_t rxq[] = { ml->disco_rx_queue, ml->wg_rx_queue, ml->stun_rx_queue };
        for (size_t i = 0; i < sizeof(rxq) / sizeof(rxq[0]); i++) {
            if (!rxq[i]) continue;
            while (xQueueReceive(rxq[i], &pkt, 0) == pdTRUE) tdongle_heap_free(TDONGLE_OWNER_PACKET, pkt.data);
        }
        ml_derp_tx_item_t tx;
        if (ml->derp_tx_queue) {
            while (xQueueReceive(ml->derp_tx_queue, &tx, 0) == pdTRUE) tdongle_heap_free(TDONGLE_OWNER_PACKET, tx.data);
        }
        ml_peer_update_t *upd;
        if (ml->peer_update_queue) {
            while (xQueueReceive(ml->peer_update_queue, &upd, 0) == pdTRUE) tdongle_heap_free(ml_peer_update_owner(upd), upd);
        }
    }

    /* Delete queues */
    if (ml->derp_tx_queue) vQueueDelete(ml->derp_tx_queue);
    if (ml->disco_rx_queue) vQueueDelete(ml->disco_rx_queue);
    if (ml->wg_rx_queue) vQueueDelete(ml->wg_rx_queue);
    if (ml->stun_rx_queue) vQueueDelete(ml->stun_rx_queue);
    if (ml->coord_cmd_queue) vQueueDelete(ml->coord_cmd_queue);
    if (ml->peer_update_queue) vQueueDelete(ml->peer_update_queue);

    /* Delete event group */
    if (ml->events) vEventGroupDelete(ml->events);

    /* Clear keys from memory */
    memset(ml->machine_private_key, 0, 32);
    memset(ml->wg_private_key, 0, 32);
    memset(ml->disco_private_key, 0, 32);

    tdongle_heap_free(TDONGLE_OWNER_CONTEXT, ml);
    ESP_LOGI(TAG, "Destroyed");
}

/* ============================================================================
 * State Queries
 * ========================================================================== */

void ml_task_exiting(microlink_t *ml) {
    if (ml) __atomic_sub_fetch(&ml->tasks_alive, 1, __ATOMIC_SEQ_CST);
}

microlink_state_t microlink_get_state(const microlink_t *ml) {
    return ml ? ml->state : ML_STATE_IDLE;
}

bool microlink_is_connected(const microlink_t *ml) {
    return ml && ml->state == ML_STATE_CONNECTED;
}

uint32_t microlink_get_vpn_ip(const microlink_t *ml) {
    return ml ? ml->vpn_ip : 0;
}

int64_t microlink_get_key_expiry(const microlink_t *ml) {
    return ml ? ml->key_expiry_epoch : 0;
}

esp_err_t microlink_rebind(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;
    if (ml->state == ML_STATE_IDLE) return ESP_ERR_INVALID_STATE;

    ESP_LOGI(TAG, "=== Rebind: forcing coord + DERP reconnect ===");

    /* Signal the coord task to reconnect. Its ML_CMD_FORCE_RECONNECT path
     * (COORD_RECONNECTING) tears down and re-runs the full
     * STUN -> DNS -> TCP -> Noise -> Register -> MapRequest flow, rebuilding
     * its own sockets; peers and WG state are preserved. */
    xEventGroupClearBits(ml->events, ML_EVT_COORD_REGISTERED);
    ml_coord_cmd_t cmd = ML_CMD_FORCE_RECONNECT;
    xQueueSend(ml->coord_cmd_queue, &cmd, pdMS_TO_TICKS(100));

    /* Signal the DERP I/O task to drop its TLS session and reconnect with a
     * fresh handshake (it watches ML_EVT_DERP_RECONNECT directly). */
    xEventGroupClearBits(ml->events, ML_EVT_DERP_CONNECTED);
    xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);

    return ESP_OK;
}

int microlink_get_peer_count(const microlink_t *ml) {
    return ml ? ml->peer_count : 0;
}

uint64_t microlink_get_last_derp_heartbeat_ms(const microlink_t *ml) {
    return ml ? ml->derp_last_heartbeat_ms : 0;
}

uint64_t microlink_get_ctrl_last_rx_ms(const microlink_t *ml) {
    return ml ? ml->ctrl_last_rx_ms : 0;
}

void microlink_get_task_states(const microlink_t *ml, microlink_task_states_t *out) {
    if (!out) return;
    /* net_io, derp and wg_mgr are shared by every attached membership; coord is this membership's own. */
    TaskHandle_t net_io = (ml && ml->rt_attached) ? ml_rt_task_handle(ML_RT_TASK_NET_IO) : NULL;
    TaskHandle_t derp   = (ml && ml->rt_attached) ? ml_rt_task_handle(ML_RT_TASK_DERP) : NULL;
    TaskHandle_t wg_mgr = (ml && ml->rt_attached) ? ml_rt_task_handle(ML_RT_TASK_WG_MGR) : NULL;
    out->net_io  = net_io ? (int)eTaskGetState(net_io) : -1;
    out->derp_tx = derp   ? (int)eTaskGetState(derp)   : -1;
    out->coord   = (ml && ml->coord_task) ? (int)eTaskGetState(ml->coord_task) : -1;
    out->wg_mgr  = wg_mgr ? (int)eTaskGetState(wg_mgr) : -1;
}

esp_err_t microlink_get_peer_info(const microlink_t *ml, int index, microlink_peer_info_t *info) {
    if (!ml || !info || index < 0 || index >= ml->peer_count) {
        return ESP_ERR_INVALID_ARG;
    }
    const ml_peer_t *p = &ml->peers[index];
    info->vpn_ip = p->vpn_ip;
    strncpy(info->hostname, p->hostname, sizeof(info->hostname) - 1);
    memcpy(info->public_key, p->public_key, 32);
    /* Report Tailscale netmap liveness rather than the microlink slot-active
     * flag — `p->active` only means "the peer occupies a slot", not that the
     * remote device is currently reachable on the tailnet. */
    info->online = p->online && p->active;
    info->direct_path = p->has_direct_path;
    info->is_exit_node = p->is_exit_node;
    info->derp_region = p->derp_region;
    info->subnet_route_count = p->subnet_route_count;
    if (info->subnet_route_count > MICROLINK_MAX_PEER_ROUTES) {
        info->subnet_route_count = MICROLINK_MAX_PEER_ROUTES;
    }
    for (int r = 0; r < info->subnet_route_count; r++) {
        info->subnet_routes[r] = p->subnet_routes[r];
    }
    return ESP_OK;
}

esp_err_t microlink_get_diag(const microlink_t *ml, microlink_diag_t *out) {
    if (!ml || !out) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    out->state = ml->state;
    out->connected = (ml->state == ML_STATE_CONNECTED);
    out->vpn_ip = ml->vpn_ip;
    out->wan_public_ip = ml->stun_public_ip;
    out->derp_home_region = ml->derp_home_region;
    out->derp_region_default = ml->derp_region_default;
    out->peer_count = ml->peer_count;
    int online = 0;
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].active && ml->peers[i].online) online++;
    }
    out->peer_online = online;
    if (ml->state == ML_STATE_CONNECTED && ml->connected_at_ms > 0) {
        uint64_t now_ms = ml_get_time_ms();
        if (now_ms > ml->connected_at_ms) {
            out->uptime_sec = (uint32_t)((now_ms - ml->connected_at_ms) / 1000ULL);
        }
    }
    out->register_user_id = ml->register_user_id;
    strlcpy(out->register_user_name, ml->register_user_name,
            sizeof out->register_user_name);
    out->identity_persistent = ml->identity_persistent;
    out->rc_coord_stream_wd = ml->rc_coord_stream_wd;
    out->rc_coord_transport = ml->rc_coord_transport;
    out->rc_derp_rx_wd      = ml->rc_derp_rx_wd;
    out->rc_derp_retry      = ml->rc_derp_retry;
    out->derp_tls_verify_failures = ml->derp.tls_verify_failures;
    out->derp_tls_deferred  = ml->derp.tls_deferred;
    out->ctrl_key_auth      = ml->ctrl_key_auth;
    /* First 16 hex chars of the WG public key (= 8 bytes). Enough to
     * eyeball-match against `headscale nodes list` output. */
    for (int i = 0; i < 8; i++) {
        snprintf(out->identity_pubkey_prefix + i * 2, 3,
                 "%02x", ml->wg_public_key[i]);
    }
    out->identity_pubkey_prefix[16] = '\0';
    return ESP_OK;
}

const char *microlink_get_derp_region_name(const microlink_t *ml, uint16_t region_id) {
    if (!ml || region_id == 0) return NULL;
    for (int i = 0; i < ml->derp_region_count; i++) {
        if (ml->derp_regions[i].region_id == region_id && ml->derp_regions[i].name[0]) {
            return ml->derp_regions[i].name;
        }
    }
    return NULL;
}

int microlink_get_derp_rtts(const microlink_t *ml, microlink_derp_rtt_t *out, int max) {
    if (!ml || !out || max <= 0) return 0;
    int count = 0;
    for (int i = 0; i < ml->derp_region_count && count < max; i++) {
        uint16_t rtt = ml->derp_rtt_ms[i];
        uint16_t rid = ml->derp_regions[i].region_id;
        if (rid == 0) continue;
        out[count].region_id = rid;
        out[count].rtt_ms = rtt;
        count++;
    }
    /* Insertion sort by rtt_ms ascending; zero-RTT (timeout) goes to the end. */
    for (int i = 1; i < count; i++) {
        microlink_derp_rtt_t cur = out[i];
        uint16_t cur_key = cur.rtt_ms ? cur.rtt_ms : 0xFFFF;
        int j = i - 1;
        while (j >= 0) {
            uint16_t prev_key = out[j].rtt_ms ? out[j].rtt_ms : 0xFFFF;
            if (prev_key <= cur_key) break;
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = cur;
    }
    return count;
}

/* ============================================================================
 * Send API
 * ========================================================================== */

esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                          const uint8_t *data, size_t len) {
    if (!ml || !data || len == 0 || len > 1400) return ESP_ERR_INVALID_ARG;
    if (ml->state != ML_STATE_CONNECTED) return ESP_ERR_INVALID_STATE;

    /* Find peer by VPN IP */
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].vpn_ip == dest_vpn_ip && ml->peers[i].active) {
            /* TODO: Route through WireGuard tunnel */
            /* For now, queue via DERP as fallback */
            return ml_derp_queue_send(ml, ml->peers[i].public_key, data, len);
        }
    }
    return ESP_ERR_NOT_FOUND;
}

/* ============================================================================
 * Callbacks
 * ========================================================================== */

void microlink_set_state_callback(microlink_t *ml, microlink_state_cb_t cb, void *user_data) {
    if (ml) { ml->state_cb = cb; ml->state_cb_data = user_data; }
}

void microlink_set_peer_callback(microlink_t *ml, microlink_peer_cb_t cb, void *user_data) {
    if (ml) { ml->peer_cb = cb; ml->peer_cb_data = user_data; }
}

void microlink_set_data_callback(microlink_t *ml, microlink_data_cb_t cb, void *user_data) {
    if (ml) { ml->data_cb = cb; ml->data_cb_data = user_data; }
}

/* ============================================================================
 * Utilities
 * ========================================================================== */

void microlink_ip_to_str(uint32_t ip, char *buf) {
    snprintf(buf, 16, "%lu.%lu.%lu.%lu",
             (unsigned long)((ip >> 24) & 0xFF),
             (unsigned long)((ip >> 16) & 0xFF),
             (unsigned long)((ip >> 8) & 0xFF),
             (unsigned long)(ip & 0xFF));
}

uint32_t microlink_parse_ip(const char *ip_str) {
    if (!ip_str) return 0;
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return (a << 24) | (b << 16) | (c << 8) | d;
}

const char *microlink_default_device_name(void) {
    static char name[48] = {0};
    if (name[0] == 0) {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);

        /* Use ML_DEVICE_NAME as prefix if configured, otherwise "esp32" */
        const char *prefix = CONFIG_ML_DEVICE_NAME;
        if (!prefix || !prefix[0]) prefix = "esp32";
        snprintf(name, sizeof(name), "%s-%02x%02x%02x", prefix, mac[3], mac[4], mac[5]);
    }
    return name;
}

const char *microlink_imei_device_name(void) {
#ifdef CONFIG_ML_ENABLE_CELLULAR
    static char name[48] = {0};  /* prefix + "-" + 15-digit IMEI + null */
    const char *imei = ml_cellular_get_imei();
    if (imei && imei[0]) {
        const char *prefix = CONFIG_ML_DEVICE_NAME;
        if (!prefix || !prefix[0]) prefix = "esp32";
        snprintf(name, sizeof(name), "%s-%s", prefix, imei);
        return name;
    }
#endif
    return NULL;
}

uint64_t ml_get_time_ms(void) {
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

/* ============================================================================
 * MagicDNS — Resolve tailnet hostnames against peer list
 * ========================================================================== */

/* Case-insensitive string compare (limited to len bytes) */
static int strncasecmp_local(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca - cb;
        if (ca == '\0') return 0;
    }
    return 0;
}

uint32_t microlink_resolve(const microlink_t *ml, const char *hostname) {
    if (!ml || !hostname || hostname[0] == '\0') return 0;

    size_t query_len = strlen(hostname);

    for (int i = 0; i < ml->peer_count; i++) {
        const ml_peer_t *p = &ml->peers[i];
        if (!p->active || p->hostname[0] == '\0') continue;

        /* 1. Exact match (case-insensitive) */
        if (strncasecmp_local(p->hostname, hostname, sizeof(p->hostname)) == 0) {
            return p->vpn_ip;
        }

        /* 2. Prefix match: query "npc1" matches peer "npc1.tail12345.ts.net"
         * The query must match up to the first '.' in the peer hostname. */
        const char *dot = strchr(p->hostname, '.');
        if (dot) {
            size_t short_len = (size_t)(dot - p->hostname);
            if (query_len == short_len &&
                strncasecmp_local(p->hostname, hostname, short_len) == 0) {
                return p->vpn_ip;
            }
        }
    }

    return 0;  /* Not found */
}
