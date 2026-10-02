#!/usr/bin/env python3
"""Check the actual HTTP USB peer guard against dual-stack client addresses."""
from pathlib import Path
import subprocess
import tempfile
source = (Path(__file__).resolve().parent.parent / 'main/gateway_main.c').read_text()
guard = source[source.index('static bool usb_peer_address'):source.index('static bool local_request(httpd_req_t *req) {')]
headers = '#include <sys/socket.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>\n#include <stdint.h>\n#include <string.h>\n#include <assert.h>\n#include <stdbool.h>\n'
tests = 'int main(void){struct sockaddr_in a={0};a.sin_family=AF_INET;inet_pton(AF_INET,"192.168.77.2",&a.sin_addr);assert(usb_peer_address((void*)&a,sizeof a));inet_pton(AF_INET,"192.168.1.141",&a.sin_addr);assert(!usb_peer_address((void*)&a,sizeof a));struct sockaddr_in6 b={0};b.sin6_family=AF_INET6;inet_pton(AF_INET6,"::ffff:192.168.77.2",&b.sin6_addr);assert(usb_peer_address((void*)&b,sizeof b));assert(!usb_peer_address((void*)&b,16));inet_pton(AF_INET6,"::ffff:192.168.1.141",&b.sin6_addr);assert(!usb_peer_address((void*)&b,sizeof b));inet_pton(AF_INET6,"::1",&b.sin6_addr);assert(!usb_peer_address((void*)&b,sizeof b));}\n'
with tempfile.TemporaryDirectory(prefix='tdongle-usb-peer-') as folder:
    c = Path(folder) / 'test.c'
    binary = Path(folder) / 'test'
    c.write_text(headers + guard + tests)
    subprocess.run(['cc', '-fsanitize=address,undefined', str(c), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('USB HTTP guard checks passed: native/mapped IPv4 allowed; other networks, native IPv6 and truncated addresses rejected.')
