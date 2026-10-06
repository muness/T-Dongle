/* Allocation-free, in-place JSON projection. Validate even discarded values;
 * never build a DOM for metadata this gateway does not consume. Output cannot
 * exceed input. Callback users retain the full map through the caller. */
typedef enum {
    GP_DROP,
    GP_ANY,
    GP_ROOT,
    GP_NODE,
    GP_DERP,
    GP_REGIONS,
    GP_REGION,
    GP_DNODE
} gp_scope;
typedef struct {
    char *b;
    size_t n, r, w;
    unsigned depth, home;
} gp_reader;
static void gp_space(gp_reader *p) {
    while (p->r < p->n && (p->b[p->r] == ' ' || p->b[p->r] == '\r' ||
                           p->b[p->r] == '\n' || p->b[p->r] == '\t'))
        p->r++;
}
static bool gp_string(gp_reader *p) {
    if (p->r >= p->n || p->b[p->r++] != '"')
        return false;
    while (p->r < p->n) {
        unsigned char c = p->b[p->r++];
        if (c == '"')
            return true;
        if (c < 32)
            return false;
        if (c == '\\') {
            if (p->r == p->n)
                return false;
            char e = p->b[p->r++];
            if (e == 'u') {
                for (int i = 0; i < 4; i++) {
                    if (p->r == p->n || !isxdigit((unsigned char)p->b[p->r++]))
                        return false;
                }
            } else if (!e || !strchr("\"\\/bfnrt", e))
                return false;
        }
    }
    return false;
}
static bool gp_key(gp_reader *p, size_t a, size_t z, const char *key) {
    size_t k = 0;
    for (size_t i = a + 1; i < z - 1; i++) {
        unsigned char c = p->b[i];
        if (c == '\\') {
            if (++i >= z - 1)
                return false;
            if (p->b[i] == 'u') {
                unsigned value = 0;
                for (int j = 0; j < 4; j++) {
                    unsigned char h = p->b[++i];
                    value = value * 16 +
                            (h <= '9' ? h - '0' : tolower(h) - 'a' + 10);
                }
                if (value > 127)
                    return false;
                c = (unsigned char)value;
            } else
                c = p->b[i];
        }
        if (!key[k] || tolower(c) != tolower((unsigned char)key[k++]))
            return false;
    }
    return key[k] == 0;
}
static gp_scope gp_field(gp_reader *p, gp_scope parent, size_t a, size_t z) {
#define K(s) gp_key(p, a, z, s)
    if (parent == GP_ANY)
        return GP_ANY;
    if (parent == GP_ROOT) {
        if (K("Node") || K("Peers") || K("peers") || K("PeersChanged") ||
            K("PeersChangedPatch"))
            return GP_NODE;
        if (K("PeersRemoved"))
            return GP_ANY;
        if (K("DERPMap"))
            return GP_DERP;
    } else if (parent == GP_NODE) {
        if (K("ID") || K("NodeID") || K("Name") || K("Key") || K("DiscoKey") ||
            K("Addresses") || K("AllowedIPs") || K("HomeDERP") || K("DERP") ||
            K("DERPRegion") || K("Endpoints") || K("Online") || K("Expired"))
            return GP_ANY;
    } else if (parent == GP_DERP) {
        if (K("Regions"))
            return GP_REGIONS;
    } else if (parent == GP_REGIONS)
        return GP_REGION;
    else if (parent == GP_REGION) {
        if (K("Nodes"))
            return GP_DNODE;
        if (K("RegionID") || K("RegionCode") || K("RegionName") || K("Avoid"))
            return GP_ANY;
    } else if (parent == GP_DNODE) {
        if (K("HostName") || K("IPv4") || K("IPv6") || K("STUNPort") ||
            K("DERPPort") || K("STUNOnly") || K("CertName"))
            return GP_ANY;
    }
    return GP_DROP;
#undef K
}
static bool gp_value(gp_reader *p, gp_scope scope);
static bool gp_container(gp_reader *p, gp_scope scope, bool object) {
    char close = object ? '}' : ']';
    bool keep = scope != GP_DROP, first = true;
    unsigned retained_regions = 0;
    p->r++;
    if (keep)
        p->b[p->w++] = object ? '{' : '[';
    gp_space(p);
    if (p->r < p->n && p->b[p->r] == close) {
        p->r++;
        if (keep)
            p->b[p->w++] = close;
        return true;
    }
    for (;;) {
        gp_scope child = scope;
        size_t a = 0, z = 0;
        if (object) {
            a = p->r;
            if (!gp_string(p))
                return false;
            z = p->r;
            child = gp_field(p, scope, a, z);
            if (scope == GP_REGIONS) {
                char home[16];
                snprintf(home, sizeof(home), "%u", p->home);
                if (retained_regions >= ML_MAX_DERP_REGIONS &&
                    !gp_key(p, a, z, home))
                    child = GP_DROP;
                if (child != GP_DROP)
                    retained_regions++;
            }
            gp_space(p);
            if (p->r == p->n || p->b[p->r++] != ':')
                return false;
            gp_space(p);
        }
        if (keep && child != GP_DROP) {
            if (!first)
                p->b[p->w++] = ',';
            first = false;
            if (object) {
                memmove(p->b + p->w, p->b + a, z - a);
                p->w += z - a;
                p->b[p->w++] = ':';
            }
        }
        if (!gp_value(p, child))
            return false;
        gp_space(p);
        if (p->r == p->n)
            return false;
        char c = p->b[p->r++];
        if (c == close) {
            if (keep)
                p->b[p->w++] = close;
            return true;
        }
        if (c != ',')
            return false;
        gp_space(p);
    }
}
static bool gp_value(gp_reader *p, gp_scope scope) {
    gp_space(p);
    if (p->r == p->n || ++p->depth > 32)
        return false;
    size_t a = p->r;
    char c = p->b[p->r];
    bool ok = true;
    if (c == '{' || c == '[')
        ok = gp_container(p, scope, c == '{');
    else {
        if (c == '"')
            ok = gp_string(p);
        else if (c == 't' || c == 'f' || c == 'n') {
            const char *word = c == 't' ? "true" : c == 'f' ? "false" : "null";
            size_t len = strlen(word);
            ok = p->n - p->r >= len && !memcmp(p->b + p->r, word, len);
            if (ok)
                p->r += len;
        } else {
            if (c == '-')
                p->r++;
            if (p->r == p->n)
                ok = false;
            else if (p->b[p->r] == '0')
                p->r++;
            else if (p->b[p->r] >= '1' && p->b[p->r] <= '9') {
                while (p->r < p->n && isdigit((unsigned char)p->b[p->r]))
                    p->r++;
            } else
                ok = false;
            if (ok && p->r < p->n && p->b[p->r] == '.') {
                size_t start = ++p->r;
                while (p->r < p->n && isdigit((unsigned char)p->b[p->r]))
                    p->r++;
                ok = p->r > start;
            }
            if (ok && p->r < p->n && (p->b[p->r] == 'e' || p->b[p->r] == 'E')) {
                p->r++;
                if (p->r < p->n && (p->b[p->r] == '+' || p->b[p->r] == '-'))
                    p->r++;
                size_t start = p->r;
                while (p->r < p->n && isdigit((unsigned char)p->b[p->r]))
                    p->r++;
                ok = p->r > start;
            }
        }
        if (ok && scope != GP_DROP) {
            memmove(p->b + p->w, p->b + a, p->r - a);
            p->w += p->r - a;
        }
    }
    p->depth--;
    return ok;
}
static size_t gateway_project(char *bytes, size_t length, unsigned home) {
    gp_reader p = {.b = bytes, .n = length, .home = home};
    gp_space(&p);
    if (p.r == p.n || bytes[p.r] != '{' || !gp_value(&p, GP_ROOT))
        return 0;
    gp_space(&p);
    if (p.r != p.n)
        return 0;
    bytes[p.w] = 0;
    return p.w;
}
