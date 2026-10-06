// SPDX-License-Identifier: MIT
#pragma once
/* Who may ask the setup HTTP server for what.
 *
 * The one HTTP server (alternative/tailnet/main/gateway_main.c) answers two kinds of client:
 *   USB       the host on the USB Ethernet link, 192.168.77.1 (tailnet gateway mode): everything, as before;
 *   SETUP_AP  a phone or laptop on the setup access point, 192.168.4.0/24, only while a setup boot is running: the Wi-Fi
 *             network pages and nothing else. The access point is open (owner decision, Kconfig TDONGLE_SETUP_AP_OPEN), so
 *             this client is untrusted: it can never read tailnet memberships or sign-in links, switch the routing mode, add
 *             or remove a tailnet, or read diagnostics.
 * The decision is made from facts the handler reads (peer address, Host and Origin headers) so it can be tested without a
 * network (tests/test_setup_access.c). A request that is neither is DENIED. Pure C. */
#include <stdbool.h>
#include <stdint.h>

typedef enum { ACCESS_DENIED = 0, ACCESS_USB, ACCESS_SETUP_AP } access_origin;
typedef enum { EP_HOME, EP_STATUS, EP_DIAGNOSTICS, EP_WIFI_SCAN, EP_WIFI_SAVED, EP_COMMAND, EP_BOOT_STATUS } access_endpoint;
typedef enum { ACTION_MODE, ACTION_WIFI, ACTION_WIFI_REMOVE, ACTION_ADD, ACTION_REMOVE, ACTION_ENABLE, ACTION_SETUP_DONE, ACTION_UNKNOWN } access_action;

enum { ACCESS_TOKEN_LENGTH = 32 };

/* peer_ipv4 is the client's IPv4 address in host byte order (an IPv4-mapped IPv6 peer is converted by the caller);
 * peer_known is false when the address could not be read. host and origin are the header values, origin NULL when absent. */
access_origin access_classify(bool peer_known, uint32_t peer_ipv4, bool setup_active, const char *host, const char *origin);
/* A client on the setup access point's subnet, whatever it asked for: the handler uses it to send captive-portal probes (any Host
 * name the DNS hijack made it use) to http://192.168.4.1/ instead of answering 403. */
bool access_in_setup_subnet(uint32_t peer_ipv4);
bool access_endpoint_allowed(access_origin origin, access_endpoint endpoint);
bool access_action_allowed(access_origin origin, access_action action);
access_action access_action_parse(const char *name);
/* Setup-AP requests carry a per-boot random token (X-Setup-Token). Constant time over the expected length; an empty expected
 * token matches nothing. */
bool access_token_equal(const char *supplied, const char *expected);
/* Fill token with ACCESS_TOKEN_LENGTH lowercase hex digits and a NUL from 16 random bytes. */
void access_token_format(char token[ACCESS_TOKEN_LENGTH + 1], const uint8_t random[16]);
