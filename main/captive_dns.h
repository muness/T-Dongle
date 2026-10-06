// SPDX-License-Identifier: MIT
#pragma once
/* The setup access point's DNS hijack: every name resolves to the dongle (192.168.4.1) so that a phone's captive-portal probe
 * (captive.apple.com, connectivitycheck.gstatic.com, www.msftconnecttest.com, ...) lands on the setup page and the operating
 * system opens it by itself. Pure packet handling, no sockets (alternative/tailnet/main/setup_ap.inc owns the socket); host tested
 * (tests/test_captive_dns.c).
 *
 * Only a plain single-question query is answered: an A query gets one A record (TTL 60), any other type gets an empty NOERROR
 * answer (so a phone's AAAA query does not stall waiting for a record that will not come). Responses, other opcodes, multiple or
 * compressed questions, and anything malformed are ignored, so the server can neither be used to reflect traffic nor be
 * confused by an oversized packet. The answer never copies more than the question it was asked. */
#include <stddef.h>
#include <stdint.h>

/* Build the reply to query[0..length) in out[0..capacity). Returns the reply length, or 0 to send nothing.
 * answer_ipv4 is the four address bytes in network order. out must not overlap query. */
size_t captive_dns_reply(const uint8_t *query, size_t length, uint8_t *out, size_t capacity, const uint8_t answer_ipv4[4]);
