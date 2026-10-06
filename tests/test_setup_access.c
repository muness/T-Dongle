// SPDX-License-Identifier: MIT
#include "setup_access.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
static access_origin classify(uint32_t peer, bool setup, const char *host, const char *origin) { return access_classify(true, peer, setup, host, origin); }

static void usb_origin_is_unchanged(void) {
    /* The rule the handlers always applied (gateway_main.c local_request): USB subnet peer, canonical Host, canonical or absent Origin. */
    assert(classify(IP(192, 168, 77, 2), false, "192.168.77.1", NULL) == ACCESS_USB);
    assert(classify(IP(192, 168, 77, 2), false, "192.168.77.1:80", "http://192.168.77.1") == ACCESS_USB);
    assert(classify(IP(192, 168, 77, 254), true, "192.168.77.1", "http://192.168.77.1:80") == ACCESS_USB);
    assert(classify(IP(192, 168, 77, 2), false, "evil.example", NULL) == ACCESS_DENIED);
    assert(classify(IP(192, 168, 77, 2), false, NULL, NULL) == ACCESS_DENIED);
    assert(classify(IP(192, 168, 77, 2), false, "192.168.77.1", "http://evil.example") == ACCESS_DENIED);
    assert(classify(IP(192, 168, 77, 2), false, "192.168.77.1:8080", NULL) == ACCESS_DENIED);
    assert(!access_classify(false, IP(192, 168, 77, 2), false, "192.168.77.1", NULL));
    assert(classify(IP(192, 168, 78, 2), false, "192.168.77.1", NULL) == ACCESS_DENIED && classify(IP(10, 0, 0, 2), false, "192.168.77.1", NULL) == ACCESS_DENIED);
}
static void setup_access_point_origin(void) {
    assert(classify(IP(192, 168, 4, 2), true, "192.168.4.1", NULL) == ACCESS_SETUP_AP);
    assert(classify(IP(192, 168, 4, 2), true, "192.168.4.1:80", "http://192.168.4.1") == ACCESS_SETUP_AP);
    /* Only during a setup boot, and only for the canonical name: the captive-portal DNS hijack makes a phone send arbitrary Host
     * names, which is exactly what DNS rebinding looks like, so they are redirected to the canonical address instead of served. */
    assert(classify(IP(192, 168, 4, 2), false, "192.168.4.1", NULL) == ACCESS_DENIED);
    assert(classify(IP(192, 168, 4, 2), true, "captive.apple.com", NULL) == ACCESS_DENIED);
    assert(classify(IP(192, 168, 4, 2), true, "192.168.4.1", "http://captive.apple.com") == ACCESS_DENIED);
    assert(classify(IP(192, 168, 4, 2), true, NULL, NULL) == ACCESS_DENIED);
    assert(access_in_setup_subnet(IP(192, 168, 4, 77)) && !access_in_setup_subnet(IP(192, 168, 5, 1)) && !access_in_setup_subnet(IP(192, 168, 77, 2)));
    /* The two subnets never lend each other their trust. */
    assert(classify(IP(192, 168, 4, 2), true, "192.168.77.1", NULL) == ACCESS_DENIED && classify(IP(192, 168, 77, 2), true, "192.168.4.1", NULL) == ACCESS_DENIED);
}
static void what_each_origin_may_ask_for(void) {
    for (int e = EP_HOME; e <= EP_BOOT_STATUS; e++) assert(access_endpoint_allowed(ACCESS_USB, (access_endpoint)e) && !access_endpoint_allowed(ACCESS_DENIED, (access_endpoint)e));
    /* The open setup access point reaches the Wi-Fi pages and nothing else. */
    assert(access_endpoint_allowed(ACCESS_SETUP_AP, EP_HOME) && access_endpoint_allowed(ACCESS_SETUP_AP, EP_WIFI_SCAN) &&
           access_endpoint_allowed(ACCESS_SETUP_AP, EP_WIFI_SAVED) && access_endpoint_allowed(ACCESS_SETUP_AP, EP_COMMAND));
    assert(!access_endpoint_allowed(ACCESS_SETUP_AP, EP_STATUS) && !access_endpoint_allowed(ACCESS_SETUP_AP, EP_DIAGNOSTICS) && !access_endpoint_allowed(ACCESS_SETUP_AP, EP_BOOT_STATUS));
    for (int a = ACTION_MODE; a < ACTION_UNKNOWN; a++) assert(access_action_allowed(ACCESS_USB, (access_action)a) && !access_action_allowed(ACCESS_DENIED, (access_action)a));
    assert(access_action_allowed(ACCESS_SETUP_AP, ACTION_WIFI) && access_action_allowed(ACCESS_SETUP_AP, ACTION_WIFI_REMOVE) && access_action_allowed(ACCESS_SETUP_AP, ACTION_SETUP_DONE));
    /* From the open AP: no tailnet memberships (their sign-in keys), no routing-mode switch. */
    assert(!access_action_allowed(ACCESS_SETUP_AP, ACTION_MODE) && !access_action_allowed(ACCESS_SETUP_AP, ACTION_ADD) &&
           !access_action_allowed(ACCESS_SETUP_AP, ACTION_REMOVE) && !access_action_allowed(ACCESS_SETUP_AP, ACTION_ENABLE));
    assert(!access_action_allowed(ACCESS_USB, ACTION_UNKNOWN) && !access_action_allowed(ACCESS_SETUP_AP, ACTION_UNKNOWN));
}
static void actions_parse(void) {
    assert(access_action_parse("mode") == ACTION_MODE && access_action_parse("wifi") == ACTION_WIFI && access_action_parse("wifi_remove") == ACTION_WIFI_REMOVE &&
           access_action_parse("add") == ACTION_ADD && access_action_parse("remove") == ACTION_REMOVE && access_action_parse("enable") == ACTION_ENABLE &&
           access_action_parse("setup_done") == ACTION_SETUP_DONE);
    assert(access_action_parse("") == ACTION_UNKNOWN && access_action_parse("WIFI") == ACTION_UNKNOWN && access_action_parse("wifi ") == ACTION_UNKNOWN && access_action_parse(NULL) == ACTION_UNKNOWN);
}
static void tokens(void) {
    const uint8_t random[16] = {0x00, 0x01, 0x0a, 0x0f, 0x10, 0xa5, 0xff, 0x80, 1, 2, 3, 4, 5, 6, 7, 8};
    char token[ACCESS_TOKEN_LENGTH + 1];
    access_token_format(token, random);
    assert(!strcmp(token, "00010a0f10a5ff80" "0102030405060708") && strlen(token) == 32);
    assert(access_token_equal(token, token));
    char other[33]; strcpy(other, token);
    for (unsigned i = 0; i < 32; i++) { other[i] ^= 1; assert(!access_token_equal(other, token)); other[i] ^= 1; }
    assert(!access_token_equal("", token) && !access_token_equal(NULL, token) && !access_token_equal(token, "") && !access_token_equal(token, NULL) && !access_token_equal("", ""));
    assert(!access_token_equal("0001", token) && !access_token_equal("00010a0f10a5ff800102030405060708x", token));
}
int main(void) {
    usb_origin_is_unchanged(); setup_access_point_origin(); what_each_origin_may_ask_for(); actions_parse(); tokens();
    puts("Setup access: USB rule unchanged, open AP reaches only the Wi-Fi pages, canonical Host required, tokens constant-time");
    return 0;
}
