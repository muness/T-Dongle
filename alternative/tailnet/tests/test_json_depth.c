/* cJSON recurses once per nesting level. The firmware compiles cJSON with
 * CJSON_NESTING_LIMIT (CMakeLists.txt, TDONGLE_CJSON_NESTING_LIMIT) so a hostile
 * document from the network cannot run a task out of stack. This compiles the
 * same cJSON.c with the same value and shows: a 5,000-deep document is refused
 * after at most LIMIT levels of recursion (measured as the stack the parser
 * used, through its allocation hook), documents as deep as Tailscale's real
 * ones still parse, and the recorded fixtures stay under the limit. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

#ifndef CJSON_NESTING_LIMIT
#error build with -DCJSON_NESTING_LIMIT=<TDONGLE_CJSON_NESTING_LIMIT>
#endif

static char *stack_base;
static size_t deepest;       /* deepest stack offset seen at an allocation */
static unsigned allocations;
static void *probe_malloc(size_t n) {
    char here;
    size_t used = (size_t)(stack_base - &here);
    if (used > deepest) deepest = used;
    allocations++;
    return malloc(n);
}
static void probe_reset(void) { deepest = 0; allocations = 0; }

static char *nested(size_t depth, int objects, const char *leaf) {
    size_t per = objects ? 5 : 1, tail = 1;
    char *s = malloc(depth * (per + tail) + strlen(leaf) + 8), *w = s;
    for (size_t i = 0; i < depth; i++) { if (objects) { memcpy(w, "{\"a\":", 5); w += 5; } else *w++ = '['; }
    strcpy(w, leaf); w += strlen(leaf);
    for (size_t i = 0; i < depth; i++) *w++ = objects ? '}' : ']';
    *w = 0;
    return s;
}
static unsigned depth_of(const cJSON *n) {
    unsigned d = 0;
    for (const cJSON *c = n->child; c; c = c->next) { unsigned e = depth_of(c); if (e > d) d = e; }
    return (cJSON_IsArray(n) || cJSON_IsObject(n)) ? d + 1 : d;
}
static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
    char *b = malloc(n + 1); assert(fread(b, 1, n, f) == (size_t)n); b[n] = 0; fclose(f);
    return b;
}

int main(void) {
    char base;
    stack_base = &base;
    cJSON_Hooks hooks = {probe_malloc, free};
    cJSON_InitHooks(&hooks);

    /* Hostile: 5,000 levels of arrays and of objects, with every parse entry the firmware uses. */
    for (int objects = 0; objects < 2; objects++) {
        char *bomb = nested(5000, objects, "1");
        probe_reset();
        assert(cJSON_Parse(bomb) == NULL);
        size_t refused_stack = deepest;
        assert(allocations <= (objects ? 2 : 1) * (CJSON_NESTING_LIMIT + 1)); /* never recursed past the limit (objects also allocate a key) */
        probe_reset();
        assert(cJSON_ParseWithLength(bomb, strlen(bomb)) == NULL);
        assert(cJSON_ParseWithLengthOpts(bomb, strlen(bomb) + 1, NULL, 1) == NULL);
        assert(cJSON_ParseWithOpts(bomb, NULL, 1) == NULL);
        assert(allocations <= 6 * (CJSON_NESTING_LIMIT + 1));
        printf("%s x5000: refused; the parser used %zu bytes of host stack (about %zu per level, "
               "limit %d levels)\n", objects ? "objects" : "arrays", refused_stack,
               refused_stack / CJSON_NESTING_LIMIT, CJSON_NESTING_LIMIT);
        free(bomb);
    }

    /* The boundary: exactly LIMIT levels parse, one more does not. */
    for (int objects = 0; objects < 2; objects++) {
        char *ok = nested(CJSON_NESTING_LIMIT, objects, "1"), *over = nested(CJSON_NESTING_LIMIT + 1, objects, "1");
        cJSON *j = cJSON_Parse(ok);
        assert(j && depth_of(j) == CJSON_NESTING_LIMIT);
        cJSON_Delete(j);
        assert(!cJSON_Parse(over));
        free(ok); free(over);
    }

    /* Tailscale's documents are shallow. The deepest realistic shape is a node capability map:
     * Node > CapMap > capability > [grant] > attribute list > object > list. */
    const char *cap_map =
        "{\"Node\":{\"CapMap\":{\"https://tailscale.com/cap/app-connectors\":[{\"name\":\"a\","
        "\"domains\":[\"x\"],\"routes\":[\"10.0.0.0/8\"],\"extra\":{\"k\":[{\"v\":[1]}]}}]}},"
        "\"PacketFilters\":{\"base\":[{\"SrcIPs\":[\"*\"],\"CapGrant\":[{\"Dsts\":[\"*\"],"
        "\"CapMap\":{\"cap\":[{\"o\":{\"p\":[1]}}]}}]}]},\"DERPMap\":{\"Regions\":{\"1\":{\"Nodes\":[{\"HostName\":\"d\"}]}}}}";
    cJSON *j = cJSON_Parse(cap_map);
    assert(j);
    unsigned real = depth_of(j);
    cJSON_Delete(j);
    assert(real <= 12 && real * 2 < CJSON_NESTING_LIMIT);
    printf("deepest realistic Tailscale document: %u levels (limit %d)\n", real, CJSON_NESTING_LIMIT);

    /* The recorded DERP map (the largest real document in the repository). */
    char *fixture = read_file("tests/fixtures/derp-map-2026-10-01.json");
    assert(fixture);
    j = cJSON_Parse(fixture);
    assert(j && depth_of(j) < CJSON_NESTING_LIMIT / 2);
    printf("derp map fixture depth: %u\n", depth_of(j));
    cJSON_Delete(j);
    free(fixture);

    /* Deleting a parsed document recurses as deep as it was parsed: bounded too. */
    char *deep = nested(CJSON_NESTING_LIMIT, 0, "1");
    j = cJSON_Parse(deep);
    assert(j);
    cJSON_Delete(j);
    free(deep);
    puts("json_depth ok");
    return 0;
}
