// SPDX-License-Identifier: MIT
#include "setup_access.h"
#include <string.h>

#define USB_SUBNET 0xc0a84d00u   /* 192.168.77.0 */
#define AP_SUBNET 0xc0a80400u    /* 192.168.4.0 */

static bool one_of(const char *value, const char *a, const char *b) { return value && (!strcmp(value, a) || !strcmp(value, b)); }

access_origin access_classify(bool peer_known, uint32_t peer_ipv4, bool setup_active, const char *host, const char *origin) {
    if (!peer_known) return ACCESS_DENIED;
    if ((peer_ipv4 & 0xffffff00u) == USB_SUBNET) {
        if (!one_of(host, "192.168.77.1", "192.168.77.1:80")) return ACCESS_DENIED;
        if (origin && !one_of(origin, "http://192.168.77.1", "http://192.168.77.1:80")) return ACCESS_DENIED;
        return ACCESS_USB;
    }
    if (setup_active && (peer_ipv4 & 0xffffff00u) == AP_SUBNET) {
        if (!one_of(host, "192.168.4.1", "192.168.4.1:80")) return ACCESS_DENIED;
        if (origin && !one_of(origin, "http://192.168.4.1", "http://192.168.4.1:80")) return ACCESS_DENIED;
        return ACCESS_SETUP_AP;
    }
    return ACCESS_DENIED;
}
bool access_in_setup_subnet(uint32_t peer_ipv4) { return (peer_ipv4 & 0xffffff00u) == AP_SUBNET; }
bool access_endpoint_allowed(access_origin origin, access_endpoint endpoint) {
    if (origin == ACCESS_USB) return true;
    if (origin != ACCESS_SETUP_AP) return false;
    return endpoint == EP_HOME || endpoint == EP_WIFI_SCAN || endpoint == EP_WIFI_SAVED || endpoint == EP_COMMAND;
}
bool access_action_allowed(access_origin origin, access_action action) {
    if (action == ACTION_UNKNOWN) return false;
    if (origin == ACCESS_USB) return true;
    if (origin != ACCESS_SETUP_AP) return false;
    return action == ACTION_WIFI || action == ACTION_WIFI_REMOVE || action == ACTION_SETUP_DONE;
}
access_action access_action_parse(const char *name) {
    static const struct { const char *name; access_action action; } table[] = {
        {"mode", ACTION_MODE}, {"wifi", ACTION_WIFI}, {"wifi_remove", ACTION_WIFI_REMOVE}, {"add", ACTION_ADD},
        {"remove", ACTION_REMOVE}, {"enable", ACTION_ENABLE}, {"setup_done", ACTION_SETUP_DONE}};
    if (!name) return ACTION_UNKNOWN;
    for (unsigned i = 0; i < sizeof(table) / sizeof(table[0]); i++)
        if (!strcmp(name, table[i].name)) return table[i].action;
    return ACTION_UNKNOWN;
}
bool access_token_equal(const char *supplied, const char *expected) {
    size_t n = expected ? strlen(expected) : 0;
    if (!supplied || !n || strlen(supplied) != n) return false;
    unsigned char difference = 0;
    for (size_t i = 0; i < n; i++) difference |= (unsigned char)(supplied[i] ^ expected[i]);
    return difference == 0;
}
void access_token_format(char token[ACCESS_TOKEN_LENGTH + 1], const uint8_t random[16]) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 16; i++) {
        token[2 * i] = hex[random[i] >> 4];
        token[2 * i + 1] = hex[random[i] & 15];
    }
    token[ACCESS_TOKEN_LENGTH] = 0;
}
