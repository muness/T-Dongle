/* A single bounded control-plane workspace, serialized across memberships.
 * Dataplane tasks and per-membership identities remain independent. */
#include "gateway_project_stream.inc"
static gs_parser gateway_projection;
static int gateway_map_fail(microlink_t *ml, unsigned code,
                            const char *message) {
    ml->map_error = code;
    ml->map_failures++;
    snprintf(ml->transport_error, sizeof(ml->transport_error), "%s", message);
    return -1;
}
static int gateway_read_map(microlink_t *ml, ml_noise_state_t *noise,
                            uint32_t wanted, bool initial) {
    ml->map_attempts++;
    if (initial) {
        ml->map_bytes = ml->map_declared_bytes = ml->map_projected_bytes = 0;
        ml->map_error = 0;
        ml->transport_error[0] = 0;
    }
    portENTER_CRITICAL(&gateway_init_lock);
    if (!gateway_lock)
        gateway_lock = xSemaphoreCreateMutexStatic(&gateway_lock_storage);
    portEXIT_CRITICAL(&gateway_init_lock);
    if (xSemaphoreTake(gateway_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return initial ? gateway_map_fail(ml, 1, "Map workspace busy; retrying")
                       : 0;
    size_t used = 0, expected = 0;
    uint8_t prefix[4];
#ifdef GATEWAY_SEMANTIC_MAP
    gateway_stage_init(&gateway_projection, ml);
#else
    gs_init(&gateway_projection, (char *)gateway_json, sizeof(gateway_json));
    gateway_projection.home = ml->derp_region_default;
#endif
    int result = 0;
    bool applied = false;
    uint64_t deadline = ml_get_time_ms() + (initial ? 15000 : 4000);
    do {
        int n =
            noise_recv_inplace(ml, noise, gateway_plain, sizeof(gateway_plain));
        if (n < 0) {
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && !used && !initial)
                break;
            if ((errno == EAGAIN || errno == EWOULDBLOCK) &&
                ml_get_time_ms() < deadline)
                continue;
            result = gateway_map_fail(
                ml, 2,
                ml->noise_error == 3   ? "Noise frame exceeds receive capacity"
                : ml->noise_error == 4 ? "Not enough memory for Noise frame"
                : ml->noise_error == 6 ? "Noise authentication failed"
                : ml->noise_error == 5
                    ? "Noise payload read failed"
                    : "Map receive timed out or connection closed");
            break;
        }
        if (!n) {
            result = gateway_map_fail(ml, 3, "Map connection returned no data");
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
                ml->stream_remaining =
                    ((uint32_t)h[0] << 16) | ((uint32_t)h[1] << 8) | h[2];
                ml->stream_type = h[3];
                ml->stream_flags = h[4];
                ml->stream_id = ((uint32_t)(h[5] & 127) << 24) |
                                ((uint32_t)h[6] << 16) | ((uint32_t)h[7] << 8) |
                                h[8];
                ml->stream_special_used = 0;
                ml->map_stream_id = ml->stream_id;
                ml->map_frame_type = ml->stream_type;
                ml->stream_padding = 0;
                ml->stream_padding_pending =
                    ml->stream_type == 0 && (ml->stream_flags & 8);
                if (ml->stream_padding_pending && !ml->stream_remaining) {
                    result =
                        gateway_map_fail(ml, 4, "Invalid HTTP/2 DATA padding");
                    goto done;
                }
                if (!ml->stream_remaining) {
                    ml->stream_header_used = 0;
                    if (ml->stream_type == 4 && !(ml->stream_flags & 1)) {
                        uint8_t ack[9] = {0, 0, 0, 4, 1, 0, 0, 0, 0};
                        if (noise_send(ml, noise, ack, sizeof(ack)) < 0) {
                            result = gateway_map_fail(
                                ml, 5,
                                "HTTP/2 settings acknowledgement failed");
                            goto done;
                        }
                    }
                    if (initial && ml->stream_id == wanted &&
                        (ml->stream_flags & 1) &&
                        (ml->stream_type == 0 || ml->stream_type == 1)) {
                        if (used) {
                            result = gateway_map_fail(
                                ml, 12, "Map stream ended during a message");
                            goto done;
                        }
                        result = applied ? 0 : 1;
                        goto done;
                    }
                    continue;
                }
                continue;
            }
            if (ml->stream_padding_pending) {
                ml->stream_padding_pending = false;
                ml->stream_padding = b;
                if (b >= ml->stream_remaining) {
                    result =
                        gateway_map_fail(ml, 4, "Invalid HTTP/2 DATA padding");
                    goto done;
                }
            } else if (ml->stream_type == 0 && ml->stream_id == wanted &&
                       ml->stream_remaining > ml->stream_padding) {
                ml->map_bytes++;
                if (used < 4)
                    prefix[used] = b;
                else if (ml->config.map_callback) {
                    if (used - 4 >= sizeof(gateway_json) - 1) {
                        result = gateway_map_fail(
                            ml, 6, "Raw callback map exceeds capacity");
                        goto done;
                    }
                    gateway_json[used - 4] = b;
                } else if (!gs_byte(&gateway_projection, b)) {
                    const char *message =
                        gateway_projection.overflow
                            ? "Retained map exceeds capacity"
                            : "Map JSON exceeds parser bounds or is malformed";
#ifdef GATEWAY_SEMANTIC_MAP
                    gateway_stage *stage = gateway_projection.context;
                    if (stage->failure)
                        message = stage->failure;
#endif
                    result = gateway_map_fail(
                        ml, gateway_projection.overflow ? 6 : 8, message);
                    goto done;
                }
                used++;
                if (used == 4) {
                    uint32_t length = (uint32_t)prefix[0] |
                                      ((uint32_t)prefix[1] << 8) |
                                      ((uint32_t)prefix[2] << 16) |
                                      ((uint32_t)prefix[3] << 24);
                    ml->map_declared_bytes = length;
                    if (!length || length > 1024 * 1024) {
                        result = gateway_map_fail(ml, 7,
                                                  "Invalid map length or raw "
                                                  "map exceeds 1 MiB limit");
                        goto done;
                    }
                    expected = 4 + (size_t)length;
                }
                if (expected && used == expected) {
#ifdef GATEWAY_SEMANTIC_MAP
                    if (!ml->config.map_callback) {
                        if (!gs_finish(&gateway_projection)) {
                            result = gateway_map_fail(
                                ml, 8,
                                "Incomplete or unsupported semantic map");
                            goto done;
                        }
                        ml->map_projected_bytes =
                            ((gateway_stage *)gateway_projection.context)
                                ->total;
                        ml->map_heap_before =
                            heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
                        ml->map_largest_before =
                            heap_caps_get_largest_free_block(
                                MALLOC_CAP_INTERNAL);
                        if (!gateway_stage_commit(ml, &gateway_projection)) {
                            result = gateway_map_fail(
                                ml, 9,
                                ((gateway_stage *)gateway_projection.context)
                                        ->failure
                                    ? ((gateway_stage *)
                                           gateway_projection.context)
                                          ->failure
                                    : "Map batch admission failed; no map "
                                      "applied");
                            goto done;
                        }
                        ml->map_heap_after =
                            heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
                    } else
#endif
                    {
                        size_t json_len = used - 4;
                        if (!ml->config.map_callback) {
                            if (!gs_finish(&gateway_projection)) {
                                result = gateway_map_fail(
                                    ml, 8,
                                    "Incomplete or malformed projected JSON");
                                goto done;
                            }
                            json_len = gateway_projection.used;
                        }
                        gateway_json[json_len] = 0;
                        ml->map_projected_bytes = json_len;
                        if (!json_len) {
                            result = gateway_map_fail(
                                ml, 8,
                                "Map JSON is malformed or nesting exceeds 32");
                            goto done;
                        }
                        ml->map_heap_before =
                            heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
                        ml->map_largest_before =
                            heap_caps_get_largest_free_block(
                                MALLOC_CAP_INTERNAL);
                        cJSON *map = cJSON_ParseWithLength((char *)gateway_json,
                                                           json_len + 1);
                        ml->map_heap_after =
                            heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
                        if (!map || !cJSON_IsObject(map)) {
                            cJSON_Delete(map);
                            result = gateway_map_fail(
                                ml, 9,
                                "Map object allocation or JSON parsing failed");
                            goto done;
                        }
                        apply_long_poll_map(ml, map);
                        cJSON_Delete(map);
                    }
                    ml->ctrl_stream_rx_ms = ml_get_time_ms();
                    applied = true;
                    used = expected = 0;
#ifdef GATEWAY_SEMANTIC_MAP
                    gateway_stage_init(&gateway_projection, ml);
#else
                    gs_init(&gateway_projection, (char *)gateway_json,
                            sizeof(gateway_json));
                    gateway_projection.home = ml->derp_region_default;
#endif
                }
            } else if ((ml->stream_type == 6 || ml->stream_type == 7 || ml->stream_type == 3) && ml->stream_special_used < 8) {
                ml->stream_special[ml->stream_special_used++] = b;
            }
            if (--ml->stream_remaining == 0) {
                uint8_t reply[26];
                int rlen = 0;
                if (ml->stream_type == 0) {
                    uint32_t count = ((uint32_t)ml->stream_header[0] << 16) |
                                     ((uint32_t)ml->stream_header[1] << 8) |
                                     ml->stream_header[2];
                    if (count) {
                        rlen = ml_h2_build_window_update(reply, sizeof(reply),
                                                         0, count);
                        int second = ml_h2_build_window_update(
                            reply + rlen, sizeof(reply) - rlen, ml->stream_id,
                            count);
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
                } else if (initial && ml->stream_type == 1 &&
                           ml->stream_id == wanted && (ml->stream_flags & 1) &&
                           !applied) {
                    if (used) {
                        result = gateway_map_fail(
                            ml, 12, "Map stream ended during a message");
                        goto done;
                    }
                    result = 1;
                    goto done;
                } else if (ml->stream_type == 7 ||
                           (ml->stream_type == 3 && ml->stream_id == wanted)) {
                    char reason[64];
                    size_t e = ml->stream_type == 7 ? 4 : 0;
                    if (ml->stream_special_used >= e + 4) {
                        const uint8_t *p = ml->stream_special + e;
                        uint32_t code = ((uint32_t)p[0] << 24) |
                            ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
                        ml->map_h2_error = code;
                        ml->map_h2_last_stream = ml->stream_type == 7 ?
                            (((uint32_t)ml->stream_special[0] << 24) |
                             ((uint32_t)ml->stream_special[1] << 16) |
                             ((uint32_t)ml->stream_special[2] << 8) |
                             ml->stream_special[3]) : ml->stream_id;
                        snprintf(reason, sizeof(reason), "HTTP/2 %s error=%lu",
                            ml->stream_type == 7 ? "GOAWAY" : "RST_STREAM",
                            (unsigned long)code);
                    } else {
                        snprintf(reason, sizeof(reason), "Truncated HTTP/2 close frame");
                    }
                    result = gateway_map_fail(ml, 10, reason);
                    goto done;
                }
                ml->stream_header_used = 0;
                if (rlen > 0 && noise_send(ml, noise, reply, rlen) < 0) {
                    result = gateway_map_fail(
                        ml, 11, "HTTP/2 flow-control acknowledgement failed");
                    goto done;
                }
                if (initial && ml->stream_type == 0 &&
                    ml->stream_id == wanted && (ml->stream_flags & 1) &&
                    !applied) {
                    if (used) {
                        result = gateway_map_fail(
                            ml, 12, "Map stream ended during a message");
                        goto done;
                    }
                    result = 1;
                    goto done;
                }
            }
        }
        if (applied && !used)
            break;
    } while (ml_get_time_ms() < deadline);
    if (result >= 0 && (used || (initial && !applied && result != 1)))
        result = gateway_map_fail(
            ml, 12, "Map ended before a complete message arrived");
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
