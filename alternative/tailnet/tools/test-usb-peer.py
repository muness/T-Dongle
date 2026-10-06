#!/usr/bin/env python3
"""Check the actual HTTP peer-address reader (gateway_main.c peer_ipv4) against dual-stack client addresses, and what the access rules
(main/setup_access.c) then make of each: USB host, setup access point client, or nobody."""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parent.parent
source = (root / 'main/gateway_main.c').read_text()
guard = source[source.index('static bool peer_ipv4('):source.index('static bool request_peer(')]
headers = '#include <sys/socket.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>\n#include <stdint.h>\n#include <string.h>\n#include <assert.h>\n#include <stdbool.h>\n#include "setup_access.h"\n'
tests = r'''
static access_origin classify(const struct sockaddr *a, socklen_t n, bool setup, const char *host) {
    uint32_t ip = 0;
    bool known = peer_ipv4(a, n, &ip);
    return access_classify(known, ip, setup, host, NULL);
}
int main(void) {
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    uint32_t ip;
    inet_pton(AF_INET, "192.168.77.2", &a.sin_addr);
    assert(peer_ipv4((void *)&a, sizeof a, &ip) && ip == 0xc0a84d02u);
    assert(classify((void *)&a, sizeof a, false, "192.168.77.1") == ACCESS_USB);
    inet_pton(AF_INET, "192.168.1.141", &a.sin_addr);
    assert(classify((void *)&a, sizeof a, true, "192.168.77.1") == ACCESS_DENIED);
    inet_pton(AF_INET, "192.168.4.2", &a.sin_addr);   /* a phone on the setup access point */
    assert(classify((void *)&a, sizeof a, true, "192.168.4.1") == ACCESS_SETUP_AP);
    assert(classify((void *)&a, sizeof a, false, "192.168.4.1") == ACCESS_DENIED);   /* only during a setup boot */
    struct sockaddr_in6 b = {0};
    b.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::ffff:192.168.77.2", &b.sin6_addr);
    assert(classify((void *)&b, sizeof b, false, "192.168.77.1") == ACCESS_USB);
    assert(!peer_ipv4((void *)&b, 16, &ip));   /* truncated */
    inet_pton(AF_INET6, "::ffff:192.168.4.2", &b.sin6_addr);
    assert(classify((void *)&b, sizeof b, true, "192.168.4.1") == ACCESS_SETUP_AP);
    inet_pton(AF_INET6, "::ffff:192.168.1.141", &b.sin6_addr);
    assert(classify((void *)&b, sizeof b, true, "192.168.4.1") == ACCESS_DENIED);
    inet_pton(AF_INET6, "::1", &b.sin6_addr);
    assert(!peer_ipv4((void *)&b, sizeof b, &ip));
    inet_pton(AF_INET6, "fe80::1", &b.sin6_addr);
    assert(classify((void *)&b, sizeof b, true, "192.168.4.1") == ACCESS_DENIED);   /* native IPv6 is never served */
    struct sockaddr other;
    memset(&other, 0, sizeof other);
    other.sa_family = AF_UNSPEC;
    assert(!peer_ipv4(&other, sizeof other, &ip));   /* neither IPv4 nor IPv6 */
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='tdongle-usb-peer-') as folder:
    c = Path(folder) / 'test.c'
    binary = Path(folder) / 'test'
    c.write_text(headers + guard + tests)
    subprocess.run(['cc', '-fsanitize=address,undefined', '-I', str(root.parent.parent / 'main'), str(c), str(root.parent.parent / 'main/setup_access.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('HTTP peer checks passed: native/mapped IPv4 classified as USB host or setup access point client; other networks, native IPv6 and truncated addresses refused.')
