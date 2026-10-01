#include "cJSON.h"
#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ML_MAX_DERP_REGIONS 4
#include "../components/microlink/src/gateway_project.inc"
#include "../components/microlink/src/gateway_project_stream.inc"
static void compare(const char *input, unsigned home) {
    size_t n = strlen(input);
    char *original = malloc(n + 1);
    strcpy(original, input);
    size_t expected = gateway_project(original, n, home);
    assert(expected);
    char output[24576];
    gs_parser p;
    gs_init(&p, output, sizeof(output));
    p.home = home;
    for (size_t i = 0; i < n; i++)
        assert(gs_byte(&p, (unsigned char)input[i]));
    assert(gs_finish(&p));
    assert(p.used == expected);
    assert(!strcmp(output, original));
    free(original);
}
int main(void) {
    compare("{\"Node\":{\"Name\":\"dongle.example.ts.net\",\"Addresses\":["
            "\"100.90.1.1/"
            "32\"],\"Expired\":false},\"PeersChanged\":[{\"ID\":123,\"Name\":"
            "\"peer\",\"Online\":true}],\"PeersRemoved\":[42],"
            "\"PeersChangedPatch\":[{\"NodeID\":123,\"Endpoints\":[\"1.2.3.4:"
            "5\"]}],\"Ignored\":{\"escaped\":\"a\\u0030\\\\b\"}}",
            4);
    compare("{\"Peers\":[{\"ID\":1,\"Name\":\"a.ts.net\",\"Addresses\":[\"100."
            "1.2.3/32\"],\"Key\":\"nodekey:test\"}],\"PeersRemoved\":[1]}",
            4);
    compare(
        "{\"DERPMap\":{\"Regions\":{\"1\":{},\"2\":{},\"3\":{},\"5\":{},\"6\":{"
        "},\"4\":{\"Nodes\":[{\"HostName\":\"derp\",\"IPv4\":\"1.2.3.4\"}]}}}}",
        4);
    compare("{\"\\u004eode\":{\"ID\":-12.34e+2},\"Dropped\":[null,false,true,{}"
            ",[]]}",
            4);
    char *large = malloc(400000);
    strcpy(large, "{\"Unused\":\"");
    size_t a = strlen(large);
    memset(large + a, 'x', 300000);
    strcpy(large + a + 300000,
           "\",\"Node\":{\"Name\":\"kept\",\"Addresses\":[\"100.1.2.3/32\"]}}");
    compare(large, 4);
    free(large);
    const char *bad[] = {"{\"Unused\":\"bad\\q\"}", "{\"Unused\":[1,]}",
                         "{\"Unused\":01}",         "{\"Unused\":truee}",
                         "{\"Unused\":{\"x\":}}",   "{}{}"};
    for (size_t k = 0; k < sizeof(bad) / sizeof(*bad); k++) {
        char out[100];
        gs_parser p;
        gs_init(&p, out, sizeof(out));
        bool ok = true;
        for (size_t i = 0; i < strlen(bad[k]) && ok; i++)
            ok = gs_byte(&p, bad[k][i]);
        assert(!ok || !gs_finish(&p));
    }
    char out[16];
    gs_parser p;
    gs_init(&p, out, sizeof(out));
    const char *retained =
        "{\"Node\":{\"Name\":\"a retained value larger than output\"}}";
    bool ok = true;
    for (size_t i = 0; i < strlen(retained) && ok; i++)
        ok = gs_byte(&p, retained[i]);
    assert(!ok && p.overflow);
    char nested[200];
    size_t pos = 0;
    memcpy(nested, "{\"Unused\":", 10);
    pos = 10;
    for (int i = 0; i < 32; i++)
        nested[pos++] = '[';
    for (int i = 0; i < 32; i++)
        nested[pos++] = ']';
    nested[pos++] = '}';
    nested[pos] = 0;
    gs_init(&p, out, sizeof(out));
    ok = true;
    for (size_t i = 0; i < pos && ok; i++)
        ok = gs_byte(&p, nested[i]);
    assert(!ok);
    puts("Streaming projection: 300 KB raw input, semantic equivalence, "
         "discarded syntax validation, and explicit retained-capacity failure "
         "passed.");
}
