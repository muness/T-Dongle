/* Incremental JSON validation/projection. Raw bytes never accumulate: only
 * retained fields enter the bounded output. State is shared under gateway_lock.
 */
typedef struct {
    gp_scope scope, child;
    unsigned phase, regions;
    bool object, first;
    char key[128];
    size_t key_length;
} gs_frame;
typedef struct {
    gs_frame frames[32];
    unsigned depth, lex, unicode, home;
    bool escaped, key, keep, started, complete, overflow;
    char scalar[96];
    size_t scalar_length, used, capacity;
    char *out;
} gs_parser;
static bool gs_emit(gs_parser *p, char c) {
    if (p->used + 1 >= p->capacity) {
        p->overflow = true;
        return false;
    }
    p->out[p->used++] = c;
    return true;
}
static void gs_init(gs_parser *p, char *out, size_t capacity) {
    memset(p, 0, sizeof(*p));
    p->out = out;
    p->capacity = capacity;
}
static bool gs_start_value(gs_parser *p, gp_scope *scope) {
    if (!p->depth) {
        if (p->started)
            return false;
        p->started = true;
        *scope = GP_ROOT;
        return true;
    }
    gs_frame *f = &p->frames[p->depth - 1];
    if (f->phase != 3 && !(f->phase == 0 && !f->object))
        return false;
    *scope = f->object ? f->child : f->scope;
    if (*scope != GP_DROP) {
        if (!f->first && !gs_emit(p, ','))
            return false;
        if (f->object) {
            for (size_t i = 0; i < f->key_length; i++)
                if (!gs_emit(p, f->key[i]))
                    return false;
            if (!gs_emit(p, ':'))
                return false;
        }
        f->first = false;
    }
    f->phase = 4;
    return true;
}
static bool gs_finish_scalar(gs_parser *p) {
    p->scalar[p->scalar_length] = 0;
    gp_reader r = {.b = p->scalar, .n = p->scalar_length};
    if (!gp_value(&r, GP_DROP) || r.r != r.n)
        return false;
    if (p->keep)
        for (size_t i = 0; i < p->scalar_length; i++)
            if (!gs_emit(p, p->scalar[i]))
                return false;
    p->lex = 0;
    if (!p->depth)
        p->complete = true;
    return true;
}
static bool gs_byte(gs_parser *p, unsigned char c) {
again:
    if (p->lex == 2) {
        if (c == ',' || c == ']' || c == '}' || c == ' ' || c == '\r' ||
            c == '\n' || c == '\t') {
            if (!gs_finish_scalar(p))
                return false;
            goto again;
        }
        if (p->scalar_length + 1 >= sizeof(p->scalar))
            return false;
        p->scalar[p->scalar_length++] = c;
        return true;
    }
    if (p->lex == 1) {
        gs_frame *f = p->depth ? &p->frames[p->depth - 1] : NULL;
        if (p->key) {
            if (f->key_length == sizeof(f->key))
                return false;
            f->key[f->key_length++] = c;
        } else if (p->keep && !gs_emit(p, c))
            return false;
        if (p->unicode) {
            if (!isxdigit(c))
                return false;
            p->unicode--;
            return true;
        }
        if (p->escaped) {
            p->escaped = false;
            if (c == 'u')
                p->unicode = 4;
            else if (!c || !strchr("\"\\/bfnrt", c))
                return false;
            return true;
        }
        if (c < 32)
            return false;
        if (c == '\\') {
            p->escaped = true;
            return true;
        }
        if (c == '"') {
            p->lex = 0;
            if (p->key) {
                gp_reader r = {.b = f->key, .n = f->key_length};
                f->child = gp_field(&r, f->scope, 0, f->key_length);
                if (f->scope == GP_REGIONS) {
                    char home[16];
                    snprintf(home, sizeof(home), "%u", p->home);
                    if (f->regions >= ML_MAX_DERP_REGIONS &&
                        !gp_key(&r, 0, f->key_length, home))
                        f->child = GP_DROP;
                    if (f->child != GP_DROP)
                        f->regions++;
                }
                f->phase = 2;
            } else if (!p->depth)
                p->complete = true;
        }
        return true;
    }
    if (c == ' ' || c == '\r' || c == '\n' || c == '\t')
        return true;
    if (p->complete)
        return false;
    gs_frame *f = p->depth ? &p->frames[p->depth - 1] : NULL;
    if (f) {
        if (c == '}' || c == ']') {
            if (c != (f->object ? '}' : ']') ||
                (f->phase != 0 && f->phase != 4))
                return false;
            if (f->scope != GP_DROP && !gs_emit(p, c))
                return false;
            if (!--p->depth)
                p->complete = true;
            return true;
        }
        if (f->phase == 4) {
            if (c != ',')
                return false;
            f->phase = f->object ? 1 : 3;
            return true;
        }
        if (f->object && (f->phase == 0 || f->phase == 1)) {
            if (c != '"')
                return false;
            f->key_length = 1;
            f->key[0] = '"';
            p->lex = 1;
            p->key = true;
            p->escaped = false;
            p->unicode = 0;
            return true;
        }
        if (f->phase == 2) {
            if (c != ':')
                return false;
            f->phase = 3;
            return true;
        }
    } else if (!p->started && c != '{')
        return false;
    gp_scope scope;
    if (!gs_start_value(p, &scope))
        return false;
    p->keep = scope != GP_DROP;
    p->key = false;
    if (c == '{' || c == '[') {
        if (p->depth == 32)
            return false;
        if (p->keep && !gs_emit(p, c))
            return false;
        gs_frame *next = &p->frames[p->depth++];
        memset(next, 0, sizeof(*next));
        next->scope = scope;
        next->object = c == '{';
        next->first = true;
        return true;
    }
    if (c == '"') {
        p->lex = 1;
        p->escaped = false;
        p->unicode = 0;
        return !p->keep || gs_emit(p, c);
    }
    if (c == '-' || (c >= '0' && c <= '9') || c == 't' || c == 'f' ||
        c == 'n') {
        p->lex = 2;
        p->scalar_length = 1;
        p->scalar[0] = c;
        return true;
    }
    return false;
}
static bool gs_finish(gs_parser *p) {
    if (p->lex == 2 && !gs_finish_scalar(p))
        return false;
    if (!p->complete || p->depth || p->lex)
        return false;
    p->out[p->used] = 0;
    return true;
}
