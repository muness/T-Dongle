/* Bounded serializer: caller sink reports failures; no allocations or locks. */
typedef struct {
    char bytes[256];
    size_t used;
    bool failed;
    void *context;
    int (*sink)(void *, const char *, size_t);
} jw_writer;
static bool jw_flush(jw_writer *w) {
    if (w->failed)
        return false;
    if (w->used && w->sink(w->context, w->bytes, w->used) < 0) {
        w->failed = true;
        return false;
    }
    w->used = 0;
    return true;
}
static bool jw_char(jw_writer *w, char c) {
    if (w->failed)
        return false;
    if (w->used == sizeof(w->bytes) && !jw_flush(w))
        return false;
    w->bytes[w->used++] = c;
    return true;
}
static bool jw_raw(jw_writer *w, const char *s) {
    while (*s)
        if (!jw_char(w, *s++))
            return false;
    return true;
}
static bool jw_string(jw_writer *w, const char *s) {
    if (!jw_char(w, '"'))
        return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') {
            if (!jw_char(w, '\\') || !jw_char(w, c))
                return false;
        } else if (c < 32) {
            char escaped[7];
            snprintf(escaped, sizeof(escaped), "\\u%04x", c);
            if (!jw_raw(w, escaped))
                return false;
        } else if (!jw_char(w, c))
            return false;
    }
    return jw_char(w, '"');
}
static bool jw_key(jw_writer *w, const char *name) {
    return jw_string(w, name) && jw_char(w, ':');
}
static bool jw_number(jw_writer *w, uint64_t value) {
    char text[24];
    snprintf(text, sizeof(text), "%llu", (unsigned long long)value);
    return jw_raw(w, text);
}
static bool jw_bool(jw_writer *w, bool value) {
    return jw_raw(w, value ? "true" : "false");
}
