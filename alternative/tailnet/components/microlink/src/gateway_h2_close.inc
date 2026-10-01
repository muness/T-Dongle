/* Only retain bounded noncredential debug prose. Never retain arbitrary
 * binary, URLs, key/token-like identifiers or server response bodies. */
static void gateway_h2_close(microlink_t *ml, uint8_t type, uint32_t stream,
                              const uint8_t *payload, size_t length) {
    size_t offset = type == 7 ? 4 : 0;
    ml->h2_debug[0] = 0;
    if (length < offset + 4) return;
    const uint8_t *p = payload + offset;
    ml->map_h2_error = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                       ((uint32_t)p[2] << 8) | p[3];
    ml->map_h2_last_stream = type == 7 ?
        (((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
         ((uint32_t)payload[2] << 8) | payload[3]) & 0x7fffffff : stream;
    if (type != 7 || length <= 8) return;
    size_t n = length - 8;
    if (n >= sizeof(ml->h2_debug)) n = sizeof(ml->h2_debug) - 1;
    char lower[sizeof(ml->h2_debug)];
    bool safe = true;
    for (size_t i = 0; i < n; i++) {
        char c = payload[8+i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              c == ' ' || c == '.' || c == '-' || c == '_')) safe = false;
        ml->h2_debug[i] = c; lower[i] = c >= 'A' && c <= 'Z' ? c + ('a'-'A') : c;
    }
    ml->h2_debug[n] = lower[n] = 0;
    if (!safe || strstr(lower,"key") || strstr(lower,"token") ||
        strstr(lower,"password") || strstr(lower,"auth")) ml->h2_debug[0] = 0;
}
