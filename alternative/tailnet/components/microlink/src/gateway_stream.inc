/* A single bounded control-plane workspace, serialized across memberships.
 * Dataplane tasks and per-membership identities remain independent. */
static uint8_t gateway_plain[20480];
static uint8_t gateway_json[49152];
static StaticSemaphore_t gateway_lock_storage;
static SemaphoreHandle_t gateway_lock;
static portMUX_TYPE gateway_init_lock = portMUX_INITIALIZER_UNLOCKED;
static int gateway_read_map(microlink_t *ml, ml_noise_state_t *noise, uint32_t wanted,
                            bool initial) {
    portENTER_CRITICAL(&gateway_init_lock);
    if (!gateway_lock)
        gateway_lock = xSemaphoreCreateMutexStatic(&gateway_lock_storage);
    portEXIT_CRITICAL(&gateway_init_lock);
    if (xSemaphoreTake(gateway_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return initial ? -1 : 0;
    size_t used = 0, expected = 0;
    int result = 0;
    bool applied = false;
    uint64_t deadline = ml_get_time_ms() + (initial ? 15000 : 4000);
    do {
        int n = noise_recv(ml, noise, gateway_plain, sizeof(gateway_plain));
        if (n < 0) {
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && !used && !initial)
                break;
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && ml_get_time_ms() < deadline)
                continue;
            result = -1;
            break;
        }
        if (!n) {
            result = -1;
            break;
        }
        ml->ctrl_last_rx_ms = ml_get_time_ms();
        for (int i = 0; i < n; i++) {
            uint8_t b = gateway_plain[i];
            if (ml->stream_header_used < 9) {
                ml->stream_header[ml->stream_header_used++] = b;
                if (ml->stream_header_used != 9)
                    continue;
                uint8_t *h = ml->stream_header;
                ml->stream_remaining = ((uint32_t)h[0] << 16) | ((uint32_t)h[1] << 8) | h[2];
                ml->stream_type = h[3];
                ml->stream_flags = h[4];
                ml->stream_id = ((uint32_t)(h[5] & 127) << 24) | ((uint32_t)h[6] << 16) |
                                ((uint32_t)h[7] << 8) | h[8];
                ml->stream_special_used = 0;
                if (ml->stream_type == 0 && (ml->stream_flags & 8)) {
                    result = -1;
                    goto done;
                }
                if (!ml->stream_remaining) {
                    ml->stream_header_used = 0;
                    if (ml->stream_type == 4 && !(ml->stream_flags & 1)) {
                        uint8_t ack[9] = {0, 0, 0, 4, 1, 0, 0, 0, 0};
                        if (noise_send(ml, noise, ack, sizeof(ack)) < 0) {
                            result = -1;
                            goto done;
                        }
                    }
                    if (initial && ml->stream_id == wanted && (ml->stream_flags & 1) &&
                        (ml->stream_type == 0 || ml->stream_type == 1)) {
                        result = applied ? 0 : 1;
                        goto done;
                    }
                    continue;
                }
                continue;
            }
            if (ml->stream_type == 0 && ml->stream_id == wanted) {
                if (used >= sizeof(gateway_json)) {
                    result = -1;
                    goto done;
                }
                gateway_json[used++] = b;
                if (used == 4) {
                    expected =
                        4 + ((uint32_t)gateway_json[0] | ((uint32_t)gateway_json[1] << 8) |
                             ((uint32_t)gateway_json[2] << 16) | ((uint32_t)gateway_json[3] << 24));
                    if (expected <= 4 || expected >= sizeof(gateway_json)) {
                        result = -1;
                        goto done;
                    }
                }
                if (expected && used == expected) {
                    gateway_json[used] = 0;
                    cJSON *map = cJSON_ParseWithLength((char *)gateway_json + 4, used - 3);
                    if (!map || !cJSON_IsObject(map)) {
                        cJSON_Delete(map);
                        result = -1;
                        goto done;
                    }
                    apply_long_poll_map(ml, map);
                    cJSON_Delete(map);
                    ml->ctrl_stream_rx_ms = ml_get_time_ms();
                    applied = true;
                    used = expected = 0;
                }
            } else if (ml->stream_type == 6 && ml->stream_special_used < 8) {
                ml->stream_special[ml->stream_special_used++] = b;
            }
            if (--ml->stream_remaining == 0) {
                uint8_t reply[26];
                int rlen = 0;
                if (ml->stream_type == 0) {
                    uint32_t count = ((uint32_t)ml->stream_header[0] << 16) |
                                     ((uint32_t)ml->stream_header[1] << 8) | ml->stream_header[2];
                    if (count) {
                        rlen = ml_h2_build_window_update(reply, sizeof(reply), 0, count);
                        int second = ml_h2_build_window_update(reply + rlen, sizeof(reply) - rlen,
                                                               ml->stream_id, count);
                        if (second > 0)
                            rlen += second;
                    }
                } else if (ml->stream_type == 4 && !(ml->stream_flags & 1)) {
                    memset(reply, 0, 9);
                    reply[3] = 4;
                    reply[4] = 1;
                    rlen = 9;
                } else if (ml->stream_type == 6 && !(ml->stream_flags & 1) &&
                           ml->stream_special_used == 8) {
                    memset(reply, 0, 9);
                    reply[2] = 8;
                    reply[3] = 6;
                    reply[4] = 1;
                    memcpy(reply + 9, ml->stream_special, 8);
                    rlen = 17;
                } else if (initial && ml->stream_type == 1 && ml->stream_id == wanted &&
                           (ml->stream_flags & 1) && !applied) {
                    result = 1;
                    goto done;
                } else if (ml->stream_type == 7 ||
                           (ml->stream_type == 3 && ml->stream_id == wanted)) {
                    result = -1;
                    goto done;
                }
                ml->stream_header_used = 0;
                if (rlen > 0 && noise_send(ml, noise, reply, rlen) < 0) {
                    result = -1;
                    goto done;
                }
                if (initial && ml->stream_type == 0 && ml->stream_id == wanted &&
                    (ml->stream_flags & 1) && !applied) {
                    result = 1;
                    goto done;
                }
            }
        }
        if (applied && !used)
            break;
    } while (ml_get_time_ms() < deadline);
    if (used || (initial && !applied && result != 1))
        result = -1;
done:
    if (result < 0) {
        ml->stream_header_used = 0;
        ml->stream_remaining = 0;
    }
    xSemaphoreGive(gateway_lock);
    return result;
}
static int poll_map_update(microlink_t *ml, ml_noise_state_t *noise) {
    return gateway_read_map(ml, noise, 5, false);
}
