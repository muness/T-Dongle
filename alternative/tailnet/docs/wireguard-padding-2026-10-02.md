# HTTP requests arrive, but responses stall

## Evidence

The Mac peer probe received Android HTTP requests from the dongle's assigned tailnet IP. After adding response-delivery logging, a further request arrived and the server wrote 618 HTTP response bytes. After 9.25 seconds all 618 bytes remained unacknowledged, with repeated retransmissions. Android reported continued loading/timeouts. This proves an outbound HTTP request reached the peer; it does not prove page delivery. The original probe logged only request arrival, which was insufficient to distinguish these outcomes. The probe now saves TCP delivery counters and a browser callback when the page executes.

The actual decryptor in `wireguardif.c` authenticates and decrypts into a padded pbuf, checks that the inner IP length does not exceed it, then calls the custom gateway input without trimming the padding. Ordinary lwIP IP input normally handles the inner length. Our custom `gateway_tunnel_input` instead required the IP length to equal the complete buffer length. [WireGuard's protocol](https://www.wireguard.com/protocol/) specifies padding to a 16-byte boundary. The old gateway therefore discarded otherwise valid replies unless their lengths happened to align. This explains how a handshake could complete while data or ACK-only packets vanished; the captured server counters do not themselves reveal the decrypted bytes.

## Fix and adversarial checks

Firmware 0.2.16 bounds the inner IPv4 length against the authenticated decrypted buffer, then validates and translates only that inner packet. USB ingress retains its strict packet-length checks. Identity, peer, port, protocol and USB-generation flow matching remain unchanged. No new allocation, task, queue or persistent memory is added.

`tests/test_router.c` drives the actual return-path function with TCP and UDP packets for payload lengths 0–63, covering every WireGuard padding remainder, including ACK-only TCP. The old routine fails its first unaligned reply. The fixed routine forwards the exact inner length, preserves payload, rewrites the expected addresses and ports, and produces correct IP/transport checksums. Each case also rejects a wrong membership, a truncated packet and padded USB ingress. These checks reject the tempting shortcut of merely loosening the shared validator, which would accept padded host packets or accidentally checksum/forward padding.

Review: the aim remains a working Android-to-peer connection. Evidence identifies a concrete protocol-boundary defect consistent with the observed one-way HTTP failure. Full gateway, recovery, DNS, USB ownership and LCD checks run for the package; real-board response delivery and sustained routing remain hardware acceptance checks. No physical flash or erase is performed by the agent. Prior settings, partition layout and crash evidence remain preserved.
