/* Caller holds gateway_lock. No transient receive allocation. */
static int gateway_read_registration(microlink_t *ml, ml_noise_state_t *noise) {
    uint8_t *h2_resp = gateway_json;
    size_t h2_resp_len = ml->h2_acc_len;
    if (h2_resp_len >= sizeof(gateway_json)) return -1;
    if (h2_resp_len) memcpy(h2_resp, ml->h2_acc, h2_resp_len);
    free(ml->h2_acc);
    ml->h2_acc = NULL;
    ml->h2_acc_len = 0;

    uint8_t *resp_buf = h2_resp;
    size_t resp_total = 0;

    /* Accumulate Noise frames into H2 buffer.
     * Scan each frame for H2 END_STREAM on stream 1 to break early
     * instead of blocking 60s waiting for more data that won't come. */
    bool got_register_end = false;
    int scan = 0;
    for (int frame_count = 0; frame_count < 128 && !got_register_end;
         frame_count++) {
        /* Scan accumulated buffer for H2 END_STREAM on stream 1 */
        while (scan + 9 <= (int)h2_resp_len) {
            uint32_t fl = (h2_resp[scan] << 16) | (h2_resp[scan + 1] << 8) |
                          h2_resp[scan + 2];
            uint8_t ft = h2_resp[scan + 3];
            uint8_t ff = h2_resp[scan + 4];
            uint32_t fs = ((h2_resp[scan + 5] & 0x7F) << 24) |
                          (h2_resp[scan + 6] << 16) | (h2_resp[scan + 7] << 8) |
                          h2_resp[scan + 8];
            if (fl > 1000000 || scan + 9 + (int)fl > (int)h2_resp_len)
                break;
            if (ft == 4 && fs == 0 && !(ff & 1)) {
                uint8_t ack[9] = {0, 0, 0, 4, 1, 0, 0, 0, 0};
                if (noise_send(ml, noise, ack, sizeof(ack)) < 0)
                    return -1;
            }
            if (ft == 6 && fs == 0 && fl == 8 && !(ff & 1)) {
                uint8_t ack[17] = {0, 0, 8, 6, 1, 0, 0, 0, 0};
                memcpy(ack + 9, h2_resp + scan + 9, 8);
                if (noise_send(ml, noise, ack, sizeof(ack)) < 0)
                    return -1;
            }
            if (ft == 7 || (ft == 3 && fs == 1)) {
                const uint8_t *payload = h2_resp + scan + 9;
                size_t e = ft == 7 ? 4 : 0;
                if (fl >= e + 4) {
                    uint32_t code = ((uint32_t)payload[e] << 24) |
                        ((uint32_t)payload[e+1] << 16) |
                        ((uint32_t)payload[e+2] << 8) | payload[e+3];
                    snprintf(ml->transport_error, sizeof(ml->transport_error),
                        "HTTP/2 %s error=%lu during registration",
                        ft == 7 ? "GOAWAY" : "RST_STREAM", (unsigned long)code);
                }
                return -1;
            }
            /* END_STREAM (0x01) on stream 1 in DATA(0x00) or HEADERS(0x01)
             * frame */
            if (fs == 1 && (ft == 0x00 || ft == 0x01) && (ff & 0x01)) {
                got_register_end = true;
                break;
            }
            scan += 9 + fl;
        }
        if (got_register_end) break;
        uint8_t *frame_buf = gateway_plain;
        int frame_len =
            noise_recv_inplace(ml, noise, frame_buf, sizeof(gateway_plain));
        if (frame_len <= 0) {

            break;
        }

        if (h2_resp_len + frame_len < sizeof(gateway_json)) {
            memcpy(h2_resp + h2_resp_len, frame_buf, frame_len);
            h2_resp_len += frame_len;
        } else {
            return -1;
        }

    }

    if (!got_register_end)
        return -1;
    /* Parse H2 frames from accumulated buffer */
    int fpos = 0;
    while (fpos + 9 <= (int)h2_resp_len) {
        uint32_t f_len = (h2_resp[fpos] << 16) | (h2_resp[fpos + 1] << 8) |
                         h2_resp[fpos + 2];
        uint8_t f_type = h2_resp[fpos + 3];
        uint8_t f_flags = h2_resp[fpos + 4];
        uint32_t f_stream = ((h2_resp[fpos + 5] & 0x7F) << 24) |
                            (h2_resp[fpos + 6] << 16) |
                            (h2_resp[fpos + 7] << 8) | h2_resp[fpos + 8];
        fpos += 9;

        ESP_LOGD(
            TAG, "  Register H2 frame: type=%d flags=0x%02x len=%lu stream=%lu",
            f_type, f_flags, (unsigned long)f_len, (unsigned long)f_stream);

        if (f_len > 1000000 || fpos + (int)f_len > (int)h2_resp_len) {
            ESP_LOGW(TAG, "  Invalid H2 frame length %lu at pos %d, stopping",
                     (unsigned long)f_len, fpos - 9);
            break;
        }

        /* Only process frames on stream 1 (our RegisterResponse).
         * Stream 0 = connection-level (SETTINGS, WINDOW_UPDATE, PING) */
        if (f_stream == 1) {
            if (f_type == 0x00 && f_len > 0) { /* DATA frame */
                size_t offset = 0, count = f_len;
                if (f_flags & 8) {
                    if (!count || h2_resp[fpos] >= count)
                        return -1;
                    offset = 1;
                    count -= 1 + h2_resp[fpos];
                }
                if (resp_total + count >= sizeof(gateway_json))
                    return -1;
                memmove(resp_buf + resp_total, h2_resp + fpos + offset, count);
                resp_total += count;
            }
        }

        fpos += f_len;
    }

    /* Send connection-level WINDOW_UPDATE for RegisterResponse.
     * Stream 1 is closed (END_STREAM received), only update connection level.
     */
    if (resp_total > 0) {
        uint8_t wu_buf[13];
        int wu_len =
            ml_h2_build_window_update(wu_buf, 13, 0, (uint32_t)resp_total);
        noise_send(ml, noise, wu_buf, wu_len);
    }

    ESP_LOGI(TAG, "RegisterResponse: %d bytes total data", (int)resp_total);

    if (resp_total == 0) {
        ESP_LOGW(TAG, "No DATA frame in RegisterResponse");

        return -1;
    }

    resp_buf[resp_total] = 0;
    return (int)resp_total;
}
