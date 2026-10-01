/* Read only through the terminator: TCP segmentation/coalescing never consumes
 * the beginning of msg2. Header storage is bounded and released before Noise. */
static int gateway_read_upgrade(microlink_t *ml) {
    char *headers = ml_psram_malloc(2049);
    if (!headers) { errno = ENOMEM; return -1; }
    size_t used = 0;
    int result = -1;
    int64_t deadline = esp_timer_get_time() + 10000000;
    while (used < 2048 && esp_timer_get_time() < deadline) {
        if (coord_recv_committed(ml, (uint8_t *)headers + used, 1) < 0) goto done;
        used++;
        if (used >= 4 && !memcmp(headers + used - 4, "\r\n\r\n", 4)) {
            headers[used] = 0;
            if (used >= 13 && (!memcmp(headers, "HTTP/1.1 101 ", 13) ||
                               !memcmp(headers, "HTTP/1.0 101 ", 13))) result = 0;
            else errno = EPROTO;
            goto done;
        }
    }
    errno = used == 2048 ? EMSGSIZE : ETIMEDOUT;
done:
    free(headers);
    return result;
}

static int gateway_read_msg2(microlink_t *ml, ml_noise_state_t *noise) {
    uint8_t msg2[51]; /* IK response: ephemeral key + authentication tag. */
    if (coord_recv_committed(ml, msg2, 3) < 0) return -1;
    if (msg2[0] != 2 || msg2[1] != 0 || msg2[2] != 48) {
        errno = EPROTO; return -1;
    }
    if (coord_recv_committed(ml, msg2 + 3, 48) < 0) return -1;
    if (ml_noise_read_msg2(noise, msg2 + 3, 48) != ESP_OK) {
        errno = EBADMSG; return -1;
    }
    return 0;
}

/* A small, per-attempt plaintext cursor; never share pending bytes or nonces
 * across identities. Only the unconsumed tail is retained for registration. */
typedef struct {
    uint8_t frame[4096];
    size_t used, length;
} gateway_early_cursor;
static int gateway_early_exact(microlink_t *ml, ml_noise_state_t *noise,
                               gateway_early_cursor *c, uint8_t *out, size_t n) {
    int64_t deadline = esp_timer_get_time() + 10000000;
    while (n) {
        if (esp_timer_get_time() >= deadline) { errno = ETIMEDOUT; return -1; }
        if (c->used == c->length) {
            int length = noise_recv_inplace(ml, noise, c->frame, sizeof(c->frame));
            if (length < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
                vTaskDelay(pdMS_TO_TICKS(10)); continue;
            }
            c->used = 0; c->length = length;
            if (!length) continue;
        }
        size_t take = c->length - c->used;
        if (take > n) take = n;
        memcpy(out, c->frame + c->used, take);
        c->used += take; out += take; n -= take;
    }
    return 0;
}
static int gateway_read_early(microlink_t *ml, ml_noise_state_t *noise) {
    ml->has_node_key_challenge = false;
    gateway_early_cursor *c = ml_psram_malloc(sizeof(*c));
    if (!c) { errno = ENOMEM; return -1; }
    c->used = c->length = 0;
    uint8_t header[9];
    int result = -1;
    char *json = NULL;
    if (gateway_early_exact(ml, noise, c, header, sizeof(header)) < 0) goto done;
    bool early = !memcmp(header, "\xff\xff\xffTS", 5);
    if (early) {
        uint32_t length = ((uint32_t)header[5] << 24) |
                          ((uint32_t)header[6] << 16) |
                          ((uint32_t)header[7] << 8) | header[8];
        if (!length || length > 1024) { errno = EMSGSIZE; goto done; }
        json = ml_psram_malloc(length + 1);
        if (!json) { errno = ENOMEM; goto done; }
        if (gateway_early_exact(ml, noise, c, (uint8_t *)json, length) < 0) goto done;
        json[length] = 0;
        const char *end = NULL;
        cJSON *root = cJSON_ParseWithLengthOpts(json, length + 1, &end, true);
        if (!root) { errno = EPROTO; goto done; }
        cJSON *challenge = cJSON_GetObjectItemCaseSensitive(root, "nodeKeyChallenge");
        if (challenge) {
            const char *v = cJSON_IsString(challenge) ? challenge->valuestring : NULL;
            bool valid = v && strlen(v) == 72 && !memcmp(v, "chalpub:", 8);
            for (unsigned i = 8; valid && i < 72; i++)
                valid = (v[i] >= '0' && v[i] <= '9') || (v[i] >= 'a' && v[i] <= 'f') ||
                        (v[i] >= 'A' && v[i] <= 'F');
            if (!valid) { cJSON_Delete(root); errno = EPROTO; goto done; }
            hex_to_bytes(v + 8, ml->node_key_challenge, 32);
            ml->has_node_key_challenge = true;
        }
        cJSON_Delete(root);
    }
    size_t tail = c->length - c->used, prefix = early ? 0 : sizeof(header);
    free(ml->h2_acc); ml->h2_acc = NULL; ml->h2_acc_len = 0;
    if (tail + prefix) {
        ml->h2_acc = ml_psram_malloc(tail + prefix);
        if (!ml->h2_acc) { errno = ENOMEM; goto done; }
        if (prefix) memcpy(ml->h2_acc, header, prefix);
        memcpy(ml->h2_acc + prefix, c->frame + c->used, tail);
        ml->h2_acc_len = tail + prefix;
    }
    result = 0;
done:
    free(json); free(c);
    return result;
}
