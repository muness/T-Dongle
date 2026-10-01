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
static size_t allocated, peak;
static void *tracked_alloc(size_t n) {
    size_t *p = malloc(n + sizeof(size_t));
    if (!p)
        return NULL;
    *p = n;
    allocated += n;
    if (allocated > peak)
        peak = allocated;
    return p + 1;
}
static void tracked_free(void *p) {
    if (p) {
        size_t *q = (size_t *)p - 1;
        allocated -= *q;
        free(q);
    }
}
static void invalid(const char *input) {
    char buf[1024];
    strcpy(buf, input);
    assert(gateway_project(buf, strlen(buf), 99) == 0);
}
int main(void) {
    const char *fixture =
        " {\"Node\":{\"Addresses\":[\"100.64.0.1/"
        "32\"],\"Expired\":false,\"Hostinfo\":{\"large\":[1,2,3]}},\"Peers\":[{"
        "\"ID\":3,\"Key\":\"nodekey:a\",\"Name\":"
        "\"quote\\\"slash\\\\unicode\\u1234\",\"AllowedIPs\":[\"10.0.0.0/"
        "8\"],\"Hostinfo\":{\"unused\":true}}],\"PeersChangedPatch\":[{"
        "\"NodeID\":3,\"Online\":false}],\"PeersRemoved\":[4],\"PacketFilter\":"
        "[{\"unused\":null}]} ";
    char buf[50000];
    strcpy(buf, fixture);
    size_t len = gateway_project(buf, strlen(buf), 99);
    assert(len && len < strlen(fixture));
    cJSON *map = cJSON_Parse(buf);
    assert(map);
    assert(!cJSON_GetObjectItem(map, "PacketFilter"));
    assert(!cJSON_GetObjectItem(cJSON_GetObjectItem(map, "Node"), "Hostinfo"));
    assert(cJSON_GetArraySize(cJSON_GetObjectItem(map, "Peers")) == 1);
    assert(cJSON_GetObjectItem(cJSON_GetObjectItem(map, "Node"), "Addresses"));
    assert(cJSON_GetObjectItem(map, "PeersRemoved"));
    assert(cJSON_GetObjectItem(map, "PeersChangedPatch"));
    cJSON_Delete(map);
    const char *bad[] = {"{\"ignored\":01}",
                         "{\"ignored\":1.}",
                         "{\"ignored\":1e+}",
                         "{\"ignored\":tru}",
                         "{\"ignored\":\"\\x\"}",
                         "{\"ignored\":[1,]}",
                         "{\"ignored\":{\"a\":1,}}",
                         "{} garbage",
                         "[]",
                         "{\"Node\":{\"Addresses\":[1]"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        invalid(bad[i]);
    strcpy(buf, "{\"DERPMap\":{\"Regions\":{");
    for (int i = 1; i <= 80; i++) {
        char region[400];
        snprintf(
            region, sizeof(region),
            "%s\"%d\":{\"RegionID\":%d,\"RegionCode\":\"r%d\",\"Nodes\":[{"
            "\"HostName\":\"derp.example.com\",\"IPv4\":\"1.2.3.4\",\"IPv6\":"
            "\"::1\",\"DERPPort\":443,\"STUNPort\":3478,\"STUNOnly\":false,"
            "\"unused\":{\"many\":[1,2,3,4,5,6,7,8,9]}}]}",
            i == 1 ? "" : ",", i, i, i);
        strcat(buf, region);
    }
    strcat(buf, "}}}");
    cJSON_Hooks hooks = {tracked_alloc, tracked_free};
    cJSON_InitHooks(&hooks);
    map = cJSON_Parse(buf);
    assert(map);
    size_t full_peak = peak;
    cJSON_Delete(map);
    assert(!allocated);
    peak = 0;
    size_t original = strlen(buf);
    len = gateway_project(buf, original, 79);
    assert(len && len < original / 5);
    map = cJSON_Parse(buf);
    assert(map);
    size_t projected_peak = peak;
    cJSON *regions =
        cJSON_GetObjectItem(cJSON_GetObjectItem(map, "DERPMap"), "Regions");
    assert(cJSON_GetArraySize(regions) == 5);
    assert(cJSON_GetObjectItem(regions, "79"));
    assert(!cJSON_GetObjectItem(regions, "80"));
    assert(projected_peak < full_peak / 5);
    printf("Map DOM peak: %zu -> %zu bytes; JSON %zu -> %zu bytes\n", full_peak,
           projected_peak, original, len);
    cJSON_Delete(map);
    assert(!allocated);
    cJSON_InitHooks(NULL);
    // Excessive nesting fails even inside discarded metadata.
    strcpy(buf, "{\"unused\":");
    for (int i = 0; i < 40; i++)
        strcat(buf, "[");
    strcat(buf, "0");
    for (int i = 0; i < 40; i++)
        strcat(buf, "]");
    strcat(buf, "}");
    assert(!gateway_project(buf, strlen(buf), 99));
    // Snapshot of the public Tailscale relay map, not a private tailnet map.
    FILE *f = fopen("tests/fixtures/derp-map-2026-10-01.json", "rb");
    assert(f);
    strcpy(buf, "{\"DERPMap\":");
    size_t start = strlen(buf);
    size_t read = fread(buf + start, 1, sizeof(buf) - start - 2, f);
    assert(!ferror(f) && feof(f));
    fclose(f);
    buf[start + read] = '}';
    buf[start + read + 1] = 0;
    cJSON_InitHooks(&hooks);
    peak = 0;
    map = cJSON_Parse(buf);
    assert(map);
    size_t public_full_peak = peak;
    cJSON_Delete(map);
    assert(!allocated);
    peak = 0;
    size_t public_bytes = strlen(buf);
    len = gateway_project(buf, public_bytes, 4);
    assert(len);
    map = cJSON_Parse(buf);
    assert(map);
    regions =
        cJSON_GetObjectItem(cJSON_GetObjectItem(map, "DERPMap"), "Regions");
    assert(cJSON_GetObjectItem(regions, "4"));
    assert(cJSON_GetArraySize(regions) <= 5);
    printf(
        "Public DERP map DOM peak: %zu -> %zu bytes; JSON %zu -> %zu bytes\n",
        public_full_peak, peak, public_bytes, len);
    assert(peak < public_full_peak / 3);
    cJSON_Delete(map);
    assert(!allocated);
    cJSON_InitHooks(NULL);
    strcpy(buf, "{\"\\u004eode\":{\"Addresses\":[\"100.64.0.1/32\"]}}");
    assert(gateway_project(buf, strlen(buf), 4));
    map = cJSON_Parse(buf);
    assert(map && cJSON_GetObjectItem(map, "Node"));
    cJSON_Delete(map);
    return 0;
}
