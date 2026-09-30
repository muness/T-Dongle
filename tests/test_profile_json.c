// SPDX-License-Identifier: MIT
#include "core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    profile_t p;
    int slot;
    const char *valid = "{\"slot\":8,\"priority\":100,\"name\":\"Home\",\"ssid\":"
                        "\"Network\",\"password\":\"12345678\"}";
    assert(profile_parse_json(valid, &slot, &p) && slot == 7 && !strcmp(p.pass, "12345678"));
    const char *bad[] = {"",
                         "{}",
                         "[]",
                         "null",
                         "{",
                         "{\"slot\":1}",
                         "{\"slot\":1,\"slot\":2,\"priority\":1,\"name\":\"x\","
                         "\"ssid\":\"x\",\"password\":\"\"}",
                         "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":"
                         "\"x\",\"password\":\"\\u0000hidden\"}",
                         "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":"
                         "\"x\",\"password\":\"short\"}",
                         "{\"slot\":1.5,\"priority\":1,\"name\":\"x\",\"ssid\":"
                         "\"x\",\"password\":\"\"}",
                         "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":"
                         "\"x\",\"password\":\"\",\"extra\":0}",
                         "{\"slot\":1,\"priority\":1,\"name\":\"x\",\"ssid\":"
                         "\"x\\n\",\"password\":\"\"}"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++)
        assert(!profile_parse_json(bad[i], &slot, &p));
    char extra[512];
    snprintf(extra, sizeof(extra), "%s trailing", valid);
    assert(!profile_parse_json(extra, &slot, &p));
    metadata_edit_t edit;
    const char *metadata = "{\"slot\":1,\"expectedName\":\"Home\",\"expectedSsid\":\"WiFi\",\"expectedPriority\":50,\"name\":\"Renamed\",\"priority\":80,\"preferred\":true}";
    assert(metadata_parse_json(metadata, &edit));
    settings_t settings = {.version=CFG_VERSION, .brightness=60, .dim_seconds=60};
    strcpy(settings.p[0].name, "Home"); strcpy(settings.p[0].ssid, "WiFi"); strcpy(settings.p[0].pass, "secret-password"); settings.p[0].priority=50;
    char original_password[65]; memcpy(original_password, settings.p[0].pass, 65);
    assert(metadata_apply(&settings, &edit));
    assert(!memcmp(original_password, settings.p[0].pass, 65)); assert(!strcmp(settings.p[0].ssid, "WiFi"));
    settings_t saved=settings;
    assert(!metadata_apply(&settings, &edit)); assert(!memcmp(&saved,&settings,sizeof(settings)));
    assert(!metadata_parse_json("{}", &edit));
    assert(!metadata_parse_json("{\"slot\":1,\"slot\":2}", &edit));
    assert(!metadata_parse_json("{\"name\":\"bad\\u0000name\"}", &edit));
    puts("PASS: shared browser/serial profile parser malformed, duplicate, "
         "escaped-NUL, numeric and credential validation");
}
