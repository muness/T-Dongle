/* A bounded, allocation-free view of ONE validated projected record. The full
 * map never becomes a JSON tree. Nodes/strings live only until semantic
 * staging. */
typedef struct {
    cJSON nodes[128];
    char strings[4096];
    unsigned nodes_used;
    size_t strings_used;
    const char *cursor;
    unsigned depth;
} gr_reader;
static void gr_space(gr_reader *r) {
    while (*r->cursor == ' ' || *r->cursor == '\t' || *r->cursor == '\r' ||
           *r->cursor == '\n')
        r->cursor++;
}
static bool gr_put(gr_reader *r, unsigned char c) {
    if (r->strings_used == sizeof(r->strings))
        return false;
    r->strings[r->strings_used++] = c;
    return true;
}
static unsigned gr_hex(const char *s) {
    unsigned n = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char c = s[i];
        n = n * 16 + (c <= '9' ? c - '0' : tolower(c) - 'a' + 10);
    }
    return n;
}
static char *gr_string(gr_reader *r) {
    if (*r->cursor++ != '"')
        return NULL;
    size_t start = r->strings_used;
    while (*r->cursor && *r->cursor != '"') {
        unsigned char c = *r->cursor++;
        if (c == '\\') {
            c = *r->cursor++;
            if (c == 'u') {
                unsigned n = gr_hex(r->cursor);
                r->cursor += 4;
                if (n >= 0xd800 && n <= 0xdbff) {
                    if (r->cursor[0] != '\\' || r->cursor[1] != 'u')
                        return NULL;
                    unsigned low = gr_hex(r->cursor + 2);
                    if (low < 0xdc00 || low > 0xdfff)
                        return NULL;
                    r->cursor += 6;
                    n = 0x10000 + ((n - 0xd800) << 10) + (low - 0xdc00);
                } else if (n >= 0xdc00 && n <= 0xdfff)
                    return NULL;
                if (!n)
                    return NULL; /* embedded NUL cannot represent an
                                    identity/key */
                if (n < 0x80) {
                    if (!gr_put(r, n))
                        return NULL;
                } else if (n < 0x800) {
                    if (!gr_put(r, 0xc0 | (n >> 6)) ||
                        !gr_put(r, 0x80 | (n & 63)))
                        return NULL;
                } else if (n < 0x10000) {
                    if (!gr_put(r, 0xe0 | (n >> 12)) ||
                        !gr_put(r, 0x80 | ((n >> 6) & 63)) ||
                        !gr_put(r, 0x80 | (n & 63)))
                        return NULL;
                } else if (!gr_put(r, 0xf0 | (n >> 18)) ||
                           !gr_put(r, 0x80 | ((n >> 12) & 63)) ||
                           !gr_put(r, 0x80 | ((n >> 6) & 63)) ||
                           !gr_put(r, 0x80 | (n & 63)))
                    return NULL;
                continue;
            }
            const char *escaped = "\"\\/bfnrt", *decoded = "\"\\/\b\f\n\r\t";
            const char *p = strchr(escaped, c);
            if (!p)
                return NULL;
            c = decoded[p - escaped];
        }
        if (!gr_put(r, c))
            return NULL;
    }
    if (*r->cursor++ != '"' || !gr_put(r, 0))
        return NULL;
    return r->strings + start;
}
static cJSON *gr_value(gr_reader *r) {
    gr_space(r);
    if (r->nodes_used == 128 || r->depth++ == 32)
        return NULL;
    cJSON *n = &r->nodes[r->nodes_used++];
    memset(n, 0, sizeof(*n));
    char c = *r->cursor;
    if (c == '{' || c == '[') {
        r->cursor++;
        n->type = c == '{' ? cJSON_Object : cJSON_Array;
        gr_space(r);
        char end = c == '{' ? '}' : ']';
        cJSON *last = NULL;
        while (*r->cursor != end) {
            char *key = NULL;
            if (c == '{') {
                key = gr_string(r);
                if (!key)
                    return NULL;
                gr_space(r);
                if (*r->cursor++ != ':')
                    return NULL;
            }
            cJSON *child = gr_value(r);
            if (!child)
                return NULL;
            child->string = key;
            if (last) {
                last->next = child;
                child->prev = last;
            } else
                n->child = child;
            last = child;
            gr_space(r);
            if (*r->cursor == end)
                break;
            if (*r->cursor++ != ',')
                return NULL;
            gr_space(r);
        }
        r->cursor++;
    } else if (c == '"') {
        n->type = cJSON_String;
        n->valuestring = gr_string(r);
        if (!n->valuestring)
            return NULL;
    } else if (c == 't') {
        n->type = cJSON_True;
        r->cursor += 4;
    } else if (c == 'f') {
        n->type = cJSON_False;
        r->cursor += 5;
    } else if (c == 'n') {
        n->type = cJSON_NULL;
        r->cursor += 4;
    } else {
        char *end;
        n->valuedouble = strtod(r->cursor, &end);
        if (end == r->cursor)
            return NULL;
        r->cursor = end;
        n->type = cJSON_Number;
        n->valueint = n->valuedouble >= INT_MAX   ? INT_MAX
                      : n->valuedouble <= INT_MIN ? INT_MIN
                                                  : (int)n->valuedouble;
    }
    r->depth--;
    return n;
}
static cJSON *gr_parse(gr_reader *r, const char *json) {
    memset(r, 0, sizeof(*r));
    r->cursor = json;
    cJSON *root = gr_value(r);
    gr_space(r);
    return root && !*r->cursor ? root : NULL;
}
